use api::grpc::qdrant::raft_server::Raft;
use api::grpc::qdrant::{
    AddPeerToKnownMessage, AllPeers, Peer, PeerId, RaftMessage as RaftMessageBytes, Uri as UriStr,
};
use itertools::Itertools;
use raft::eraftpb::Message as RaftMessage;
use storage::content_manager::consensus_manager::{ConsensusProposalOutcome, ConsensusStateRef};
use storage::content_manager::consensus_ops::ConsensusOperations;
use tokio::sync::mpsc::Sender;
use tonic::transport::Uri;
use tonic::{Request, Response, Status, async_trait};

use super::validate;
use crate::consensus;

pub struct RaftService {
    message_sender: Sender<consensus::Message>,
    consensus_state: ConsensusStateRef,
    use_tls: bool,
}

impl RaftService {
    pub fn new(
        sender: Sender<consensus::Message>,
        consensus_state: ConsensusStateRef,
        use_tls: bool,
    ) -> Self {
        Self {
            message_sender: sender,
            consensus_state,
            use_tls,
        }
    }
}

fn decode_raft_message(bytes: &[u8]) -> Result<RaftMessage, Status> {
    <RaftMessage as prost_for_raft::Message>::decode(bytes)
        .map_err(|_| Status::invalid_argument("Failed to parse raft message"))
}

fn parse_peer_uri(uri: &str) -> Result<Uri, Status> {
    uri.parse()
        .map_err(|_| Status::internal("Failed to parse uri"))
}

#[async_trait]
impl Raft for RaftService {
    async fn send(&self, mut request: Request<RaftMessageBytes>) -> Result<Response<()>, Status> {
        let message = decode_raft_message(&request.get_mut().message[..])?;
        self.message_sender
            .send(consensus::Message::FromPeer(Box::new(message)))
            .await
            .map_err(|_| Status::internal("Can't send Raft message over channel"))?;
        Ok(Response::new(()))
    }

    async fn who_is(
        &self,
        request: tonic::Request<PeerId>,
    ) -> Result<tonic::Response<UriStr>, tonic::Status> {
        let addresses = self.consensus_state.peer_address_by_id();
        let uri = addresses
            .get(&request.get_ref().id)
            .ok_or_else(|| Status::internal("Peer not found"))?;
        Ok(Response::new(UriStr {
            uri: uri.to_string(),
        }))
    }

    async fn add_peer_to_known(
        &self,
        request: tonic::Request<AddPeerToKnownMessage>,
    ) -> Result<tonic::Response<AllPeers>, tonic::Status> {
        validate(request.get_ref())?;
        let peer = request.get_ref();
        let uri_string = if let Some(uri) = &peer.uri {
            uri.clone()
        } else {
            let ip = request
                .remote_addr()
                .ok_or_else(|| {
                    Status::failed_precondition("Remote address unavailable due to the used IO")
                })?
                .ip();
            let port = peer
                .port
                .ok_or_else(|| Status::invalid_argument("URI or port should be supplied"))?;
            if self.use_tls {
                format!("https://{ip}:{port}")
            } else {
                format!("http://{ip}:{port}")
            }
        };
        let uri = parse_peer_uri(&uri_string)?;
        let peer = request.into_inner();

        // If this URI is already registered by a different peer that has no
        // shards, remove the old peer first so the new one can take its place.
        let existing_peer_id = self
            .consensus_state
            .peer_address_by_id()
            .into_iter()
            .find(|(id, peer_uri)| *peer_uri == uri && *id != peer.id)
            .map(|(id, _)| id);

        if let Some(old_peer_id) = existing_peer_id {
            let consensus_state = self.consensus_state.clone();
            let has_shards = tokio::task::spawn_blocking(move || {
                // Must use spawn_blocking for peer_has_shards
                consensus_state.peer_has_shards(old_peer_id)
            })
            .await
            .map_err(|err| Status::internal(format!("Failed to check shards: {err}")))?;

            if has_shards {
                return Err(Status::failed_precondition(format!(
                    "peer URI {uri} already used by peer {old_peer_id} which still has shards, \
                     remove its shards first or use a different URI",
                )));
            }

            log::info!(
                "Peer {} is replacing peer {old_peer_id} which has no shards ({uri})",
                peer.id,
            );

            self.consensus_state
                .propose_consensus_op_with_await(ConsensusOperations::RemovePeer(old_peer_id), None)
                .await
                .map_err(|err| {
                    Status::internal(format!("Failed to remove old peer {old_peer_id}: {err}"))
                })?;
        }

        // A timed-out proposal can already be applied by the time bootstrap retries. Preserve
        // its current voter/learner role instead of proposing AddLearnerNode again.
        if !self
            .consensus_state
            .complete_registered_peer_add(peer.id, &uri)
        {
            match self
                .consensus_state
                .propose_consensus_op_with_outcome(
                    ConsensusOperations::AddPeer {
                        peer_id: peer.id,
                        uri: uri.to_string(),
                    },
                    None,
                )
                .await
            {
                ConsensusProposalOutcome::Applied(_) => {}
                ConsensusProposalOutcome::Indeterminate(error) => {
                    if !self
                        .consensus_state
                        .complete_registered_peer_add(peer.id, &uri)
                    {
                        // This includes proposals declined while the local Raft log catches up.
                        // Only the bootstrap client retries this transient status, under its
                        // existing overall deadline; permanent URI refusals remain immediate.
                        return Err(Status::unavailable(format!("Failed to add peer: {error}")));
                    }
                }
                ConsensusProposalOutcome::NotSubmitted(error)
                | ConsensusProposalOutcome::Failed(error) => {
                    return Err(Status::internal(format!("Failed to add peer: {error}")));
                }
            }
        }

        let mut addresses = self.consensus_state.peer_address_by_id();

        // Make sure that the new peer is now present in the known addresses
        if !addresses.values().contains(&uri) {
            return Err(Status::internal(format!(
                "Failed to add peer after consensus: {uri}"
            )));
        }

        let first_peer_id = self.consensus_state.first_voter();

        // If `first_peer_id` is not present in the list of peers, it means it was removed from
        // cluster at some point.
        //
        // Before Qdrant version 1.11.6 origin peer was not committed to consensus, so if it was
        // removed from cluster, any node added to the cluster after this would not recognize it as
        // being part of the cluster in the past and will end up with a broken consensus state.
        //
        // To prevent this, we add `first_peer_id` (with a fake URI) to the list of peers.
        //
        // `add_peer_to_known` is used to add new peers to the cluster, and so `first_peer_id` (and
        // its fake URI) would be removed from new peer's state shortly, while it will be synchronizing
        // and applying past Raft log.
        addresses.entry(first_peer_id).or_default();

        Ok(Response::new(AllPeers {
            all_peers: addresses
                .into_iter()
                .map(|(id, uri)| Peer {
                    id,
                    uri: uri.to_string(),
                })
                .collect(),
            first_peer_id,
        }))
    }

    // Left for compatibility - does nothing
    async fn add_peer_as_participant(
        &self,
        _request: tonic::Request<PeerId>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_peer_bootstrap_preserves_voters_and_learners_without_proposal() {
        use collection::operations::types::PeerMetadata;
        use collection::operations::verification::new_unchecked_verification_pass;
        use storage::content_manager::consensus::operation_sender::OperationSender;
        use storage::content_manager::consensus::persistent::Persistent;
        use storage::content_manager::consensus_manager::ConsensusManager;
        use storage::rbac::{Access, Auth};

        let (temp, dispatcher) = crate::common::private_hnsw_wire_fixture::test_dispatcher();
        let toc = dispatcher
            .toc(
                &Auth::new_internal(Access::full("registered peer bootstrap test")),
                &new_unchecked_verification_pass(),
            )
            .clone();
        let persistent = Persistent::load_or_init(temp.path(), true, false, Some(11)).unwrap();
        let (proposal_sender, proposal_receiver) = std::sync::mpsc::channel();
        let state: ConsensusStateRef = ConsensusManager::new(
            persistent,
            toc,
            OperationSender::new(proposal_sender),
            temp.path(),
            PeerMetadata::current(),
        )
        .unwrap()
        .into();
        state
            .add_peer(11, "http://voter:6335".parse().unwrap())
            .unwrap();
        state
            .add_peer(12, "http://learner:6335".parse().unwrap())
            .unwrap();
        state
            .set_conf_state(raft::eraftpb::ConfState {
                voters: vec![11],
                learners: vec![12],
                ..Default::default()
            })
            .unwrap();
        let before = state.conf_state();
        let (message_sender, _message_receiver) = tokio::sync::mpsc::channel(1);
        let service = RaftService::new(message_sender, state.clone(), false);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for (id, uri) in [(11, "http://voter:6335"), (12, "http://learner:6335")] {
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    service.add_peer_to_known(Request::new(AddPeerToKnownMessage {
                        id,
                        uri: Some(uri.to_string()),
                        port: None,
                    })),
                )
                .await
                .unwrap()
                .unwrap()
                .into_inner();
                assert!(
                    response
                        .all_peers
                        .iter()
                        .any(|peer| peer.id == id && peer.uri == uri)
                );
                assert_eq!(state.conf_state(), before);
                assert!(matches!(
                    proposal_receiver.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ));
            }
        });
    }

    #[test]
    fn raft_message_parse_error_does_not_reflect_payload_or_decoder_detail() {
        let payload = b"raft-message-secret-sentinel";
        let err = decode_raft_message(payload).unwrap_err();

        assert_eq!(err.message(), "Failed to parse raft message");
        assert!(!err.message().contains("raft-message-secret-sentinel"));
        assert!(!err.message().contains("invalid wire type"));
        assert!(!err.message().contains("buffer"));
    }

    #[test]
    fn raft_peer_uri_parse_error_does_not_reflect_uri_or_parser_detail() {
        let uri = "http://raft-user:raft-password@exa mple.com/raft-secret-token";
        let err = parse_peer_uri(uri).unwrap_err();

        assert_eq!(err.message(), "Failed to parse uri");
        assert!(!err.message().contains("raft-user"));
        assert!(!err.message().contains("raft-password"));
        assert!(!err.message().contains("raft-secret-token"));
        assert!(!err.message().contains("invalid"));
    }
}

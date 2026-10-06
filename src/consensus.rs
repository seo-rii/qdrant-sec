use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{cmp, fmt, thread};

use anyhow::{Context as _, anyhow};
use api::grpc::dynamic_channel_pool::make_grpc_channel;
use api::grpc::qdrant::raft_client::RaftClient;
use api::grpc::qdrant::{AllPeers, PeerId as GrpcPeerId, RaftMessage as GrpcRaftMessage};
use api::grpc::transport_channel_pool::TransportChannelPool;
use collection::shards::channel_service::ChannelService;
use collection::shards::shard::PeerId;
#[cfg(target_os = "linux")]
use common::cpu::linux_high_thread_priority;
use raft::eraftpb::Message as RaftMessage;
use raft::prelude::*;
use raft::{INVALID_ID, SoftState, StateRole};
use storage::content_manager::consensus_manager::{ConsensusStateRef, raft_conf_change_pending};
use storage::content_manager::consensus_ops::{ConsensusOperations, SnapshotStatus};
use storage::content_manager::toc::TableOfContent;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;
use tokio::time::sleep;
use tonic::transport::{ClientTlsConfig, Uri};

use crate::common::helpers;
use crate::common::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use crate::common::telemetry::TelemetryCollector;
use crate::common::telemetry_ops::requests_telemetry::TonicTelemetryCollector;
use crate::settings::{ConsensusConfig, Settings};
use crate::tonic::init_internal;

type Node = RawNode<ConsensusStateRef>;

const RECOVERY_RETRY_TIMEOUT: Duration = Duration::from_secs(1);
const RECOVERY_MAX_RETRY_COUNT: usize = 3;

pub enum Message {
    FromClient(ConsensusOperations),
    FromPeer(Box<RaftMessage>),
}

/// Aka Consensus Thread
/// Manages proposed changes to consensus state, ensures that everything is ordered properly
/// Kind of Raft membership change proposed through the private ORAM topology gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TopologyChange {
    AddPeer,
    RemovePeer,
}

pub struct Consensus {
    /// Raft structure which handles raft-related state
    node: Node,
    /// Receives proposals from peers and client for applying in consensus
    receiver: Receiver<Message>,
    /// Runtime for async message sending
    runtime: Handle,
    /// Uri to some other known peer, used to join the consensus
    /// ToDo: Make if many
    config: ConsensusConfig,
    broker: RaftMessageBroker,
    raft_config: Config,
}

impl Consensus {
    /// Create and run consensus node
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        logger: &slog::Logger,
        state_ref: ConsensusStateRef,
        bootstrap_peer: Option<Uri>,
        uri: Option<String>,
        settings: Settings,
        channel_service: ChannelService,
        propose_receiver: mpsc::Receiver<ConsensusOperations>,
        telemetry_collector: Arc<tokio::sync::Mutex<TelemetryCollector>>,
        tonic_telemetry_collector: Arc<parking_lot::Mutex<TonicTelemetryCollector>>,
        toc: Arc<TableOfContent>,
        private_oram_peer_identity: Option<Arc<PrivateOramPeerRecoveryIdentity>>,
        runtime: Handle,
        reinit: bool,
    ) -> anyhow::Result<JoinHandle<std::io::Result<()>>> {
        let tls_client_config = helpers::load_tls_client_config(&settings)?;

        let p2p_host = settings.service.host.clone();
        let p2p_port = settings
            .cluster
            .p2p
            .port
            .ok_or_else(|| anyhow::anyhow!("P2P port is not set"))?;
        let config = settings.cluster.consensus.clone();

        let (mut consensus, message_sender) = Self::new(
            logger,
            state_ref.clone(),
            bootstrap_peer,
            uri,
            p2p_port,
            config,
            tls_client_config,
            channel_service,
            runtime.clone(),
            reinit,
        )?;

        let state_ref_clone = state_ref.clone();
        thread::Builder::new()
            .name("consensus".to_string())
            .spawn(move || {
                // On Linux, try to use high thread priority because consensus is important
                // Likely fails as we cannot set a higher priority by default due to permissions
                #[cfg(target_os = "linux")]
                if let Err(err) = linux_high_thread_priority() {
                    log::debug!(
                        "Failed to set high thread priority for consensus, ignoring: {err}"
                    );
                }

                if let Err(err) = consensus.start() {
                    log::error!("Consensus stopped with error: {err:#}");
                    state_ref_clone.on_consensus_thread_err(err);
                } else {
                    log::info!("Consensus stopped");
                    state_ref_clone.on_consensus_stopped();
                }
            })?;

        let message_sender_moved = message_sender.clone();
        thread::Builder::new()
            .name("forward-proposals".to_string())
            .spawn(move || {
                // On Linux, try to use high thread priority because consensus is important
                // Likely fails as we cannot set a higher priority by default due to permissions
                #[cfg(target_os = "linux")]
                if let Err(err) = linux_high_thread_priority() {
                    log::debug!(
                        "Failed to set high thread priority for consensus, ignoring: {err}"
                    );
                }

                while let Ok(entry) = propose_receiver.recv() {
                    if message_sender_moved
                        .blocking_send(Message::FromClient(entry))
                        .is_err()
                    {
                        log::error!("Can not forward new entry to consensus as it was stopped.");
                        break;
                    }
                }
            })?;

        let server_tls = if settings.cluster.p2p.enable_tls {
            let tls_config = settings
                .tls
                .clone()
                .ok_or_else(Settings::tls_config_is_undefined_error)?;

            Some(helpers::load_tls_internal_server_config(&tls_config)?)
        } else {
            None
        };

        let handle = thread::Builder::new()
            .name("grpc_internal".to_string())
            .spawn(move || {
                init_internal(
                    toc,
                    state_ref,
                    telemetry_collector,
                    tonic_telemetry_collector,
                    settings,
                    private_oram_peer_identity,
                    p2p_host,
                    p2p_port,
                    server_tls,
                    message_sender,
                    runtime,
                )
            })?;

        Ok(handle)
    }

    /// If `bootstrap_peer` peer is supplied, then either `uri` or `p2p_port` should be also supplied
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logger: &slog::Logger,
        state_ref: ConsensusStateRef,
        bootstrap_peer: Option<Uri>,
        uri: Option<String>,
        p2p_port: u16,
        config: ConsensusConfig,
        tls_config: Option<ClientTlsConfig>,
        channel_service: ChannelService,
        runtime: Handle,
        reinit: bool,
    ) -> anyhow::Result<(Self, Sender<Message>)> {
        // If we want to re-initialize consensus, we need to prevent other peers
        // from re-playing consensus WAL operations, as they should already have them applied.
        // Do ensure that we are forcing compacting WAL on the first re-initialized peer,
        // which should trigger snapshot transferring instead of replaying WAL.
        let force_compact_wal = reinit && bootstrap_peer.is_none();

        // On the bootstrap-ed peers during reinit of the consensus
        // we want to make sure only the bootstrap peer will hold the true state
        // Therefore we clear the WAL on the bootstrap peer to force it to request a snapshot
        let clear_wal = reinit && bootstrap_peer.is_some();

        if clear_wal {
            log::debug!("Clearing WAL on the bootstrap peer to force snapshot transfer");
            state_ref.clear_wal()?;
        }

        // raft will not return entries to the application smaller or equal to `applied`
        let last_applied = state_ref.last_applied_entry().unwrap_or_default();
        let raft_config = Config {
            id: state_ref.this_peer_id(),
            applied: last_applied,
            ..Default::default()
        };
        raft_config.validate()?;
        // bounded channel for backpressure
        let (sender, receiver) = tokio::sync::mpsc::channel(config.max_message_queue_size);
        // State might be initialized but the node might be shutdown without actually syncing or committing anything.
        if state_ref.is_new_deployment() || reinit {
            let leader_established_in_ms =
                config.tick_period_ms * raft_config.max_election_tick() as u64;
            Self::init(
                &state_ref,
                bootstrap_peer.clone(),
                uri,
                p2p_port,
                &config,
                tls_config.clone(),
                &runtime,
                leader_established_in_ms,
            )
            .context("Failed to initialize Consensus for new Raft state")?;
        } else {
            runtime
                .block_on(Self::recover(
                    &state_ref,
                    uri.clone(),
                    p2p_port,
                    &config,
                    tls_config.clone(),
                ))
                .context("Failed to recover Consensus from existing Raft state")?;

            if bootstrap_peer.is_some() || uri.is_some() {
                log::debug!("Local raft state found - bootstrap and uri cli arguments were ignored")
            }
            log::debug!("Local raft state found - skipping initialization");
        };

        let mut node = Node::new(&raft_config, state_ref.clone(), logger)?;
        node.set_batch_append(true);

        // Before consensus has started apply any unapplied committed entries
        // They might have not been applied due to unplanned Qdrant shutdown
        let _stop_consensus = state_ref.apply_entries(&mut node)?;

        if force_compact_wal {
            // Making sure that the WAL will be compacted on start
            state_ref.compact_wal(1)?;
        } else {
            state_ref.compact_wal(config.compact_wal_entries)?;
        }

        let broker = RaftMessageBroker::new(
            runtime.clone(),
            bootstrap_peer,
            tls_config,
            config.clone(),
            node.store().clone(),
            channel_service.channel_pool,
        );

        let consensus = Self {
            node,
            receiver,
            runtime,
            config,
            broker,
            raft_config,
        };

        if !state_ref.is_new_deployment() {
            state_ref.recover_first_voter()?;
        }

        Ok((consensus, sender))
    }

    #[allow(clippy::too_many_arguments)]
    fn init(
        state_ref: &ConsensusStateRef,
        bootstrap_peer: Option<Uri>,
        uri: Option<String>,
        p2p_port: u16,
        config: &ConsensusConfig,
        tls_config: Option<ClientTlsConfig>,
        runtime: &Handle,
        leader_established_in_ms: u64,
    ) -> anyhow::Result<()> {
        if let Some(bootstrap_peer) = bootstrap_peer {
            log::debug!("Bootstrapping from peer with address: {bootstrap_peer}");
            runtime.block_on(Self::bootstrap(
                state_ref,
                bootstrap_peer,
                uri,
                p2p_port,
                config,
                tls_config,
            ))?;
            Ok(())
        } else {
            log::debug!(
                "Bootstrapping is disabled. Assuming this peer is the first in the network"
            );
            let tick_period = config.tick_period_ms;
            log::info!(
                "With current tick period of {tick_period}ms, leader will be established in approximately {leader_established_in_ms}ms. To avoid rejected operations - add peers and submit operations only after this period.",
            );
            // First peer needs to add its own address
            state_ref.add_peer(
                state_ref.this_peer_id(),
                uri.ok_or_else(|| anyhow::anyhow!("First peer should specify its uri."))?
                    .parse()?,
            )?;
            Ok(())
        }
    }

    async fn add_peer_to_known_for(
        this_peer_id: PeerId,
        cluster_uri: Uri,
        current_uri: Option<String>,
        p2p_port: u16,
        config: &ConsensusConfig,
        tls_config: Option<ClientTlsConfig>,
    ) -> anyhow::Result<AllPeers> {
        // Use dedicated transport channel for bootstrapping because of specific timeout
        let channel = make_grpc_channel(
            Duration::from_secs(config.bootstrap_timeout_sec),
            Duration::from_secs(config.bootstrap_timeout_sec),
            cluster_uri,
            tls_config,
        )
        .await
        .context("Failed to create timeout channel")?;
        let mut client = RaftClient::new(channel);
        let all_peers = client
            .add_peer_to_known(tonic::Request::new(
                api::grpc::qdrant::AddPeerToKnownMessage {
                    uri: current_uri,
                    port: Some(u32::from(p2p_port)),
                    id: this_peer_id,
                },
            ))
            .await
            .context("Failed to add peer to known")?
            .into_inner();
        Ok(all_peers)
    }

    // Re-attach peer to the consensus:
    // Notifies the cluster(any node) that this node changed its address
    async fn recover(
        state_ref: &ConsensusStateRef,
        uri: Option<String>,
        p2p_port: u16,
        config: &ConsensusConfig,
        tls_config: Option<ClientTlsConfig>,
    ) -> anyhow::Result<()> {
        let this_peer_id = state_ref.this_peer_id();
        let mut peer_to_uri = state_ref
            .persistent
            .read()
            .peer_address_by_id
            .read()
            .clone();
        let this_peer_url = peer_to_uri.remove(&this_peer_id);
        // Recover url if a different one is provided
        let do_recover = match (&this_peer_url, &uri) {
            (Some(this_peer_url), Some(uri)) => this_peer_url != &Uri::from_str(uri)?,
            _ => false,
        };

        if do_recover {
            let mut tries = RECOVERY_MAX_RETRY_COUNT;
            while tries > 0 {
                // Try to inform any peer about the change of address
                for (peer_id, peer_uri) in &peer_to_uri {
                    let res = Self::add_peer_to_known_for(
                        this_peer_id,
                        peer_uri.clone(),
                        uri.clone(),
                        p2p_port,
                        config,
                        tls_config.clone(),
                    )
                    .await;
                    if res.is_err() {
                        log::warn!(
                            "Failed to recover from peer with id {peer_id} at {peer_uri} with error {res:?}, trying others"
                        );
                    } else {
                        log::debug!(
                            "Successfully recovered from peer with id {peer_id} at {peer_uri}"
                        );
                        return Ok(());
                    }
                }
                tries -= 1;
                log::warn!(
                    "Retrying recovering from known peers (retry {})",
                    RECOVERY_MAX_RETRY_COUNT - tries
                );
                let exp_timeout =
                    RECOVERY_RETRY_TIMEOUT * (RECOVERY_MAX_RETRY_COUNT - tries) as u32;
                sleep(exp_timeout).await;
            }
            return Err(anyhow::anyhow!("Failed to recover from any known peers"));
        }

        Ok(())
    }

    /// Add node sequence:
    ///
    /// 1. Add current node as a learner
    /// 2. Start applying entries from consensus
    /// 3. Eventually leader submits the promotion proposal
    /// 4. Learners become voters once they read about the promotion from consensus log
    async fn bootstrap(
        state_ref: &ConsensusStateRef,
        bootstrap_peer: Uri,
        uri: Option<String>,
        p2p_port: u16,
        config: &ConsensusConfig,
        tls_config: Option<ClientTlsConfig>,
    ) -> anyhow::Result<()> {
        let this_peer_id = state_ref.this_peer_id();
        let all_peers = Self::add_peer_to_known_for(
            this_peer_id,
            bootstrap_peer,
            uri.clone(),
            p2p_port,
            config,
            tls_config,
        )
        .await?;

        // Although peer addresses are synchronized with consensus, addresses need to be pre-fetched in the case of a new peer
        // or it will not know how to answer the Raft leader
        for peer in all_peers.all_peers {
            state_ref
                .add_peer(
                    peer.id,
                    peer.uri
                        .parse()
                        .context(format!("Failed to parse peer URI: {}", peer.uri))?,
                )
                .context("Failed to add peer")?
        }
        // Only first peer has itself as a voter in the initial conf state.
        // This needs to be propagated manually to other peers as it is not contained in any log entry.
        // So we skip the learner phase for the first peer.
        state_ref.set_first_voter(all_peers.first_peer_id)?;
        state_ref.set_conf_state(ConfState::from((vec![all_peers.first_peer_id], vec![])))?;
        Ok(())
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        // If this is the only peer in the cluster, tick Raft node a few times to instantly
        // self-elect itself as Raft leader
        if self.node.store().peer_count() == 1 {
            while !self.node.has_ready() {
                self.node.tick();
            }
        }

        // If this is the origin peer of the cluster, try to add origin peer to consensus
        if let Err(err) = self.try_add_origin() {
            log::error!("Failed to add origin peer to consensus: {err}");
        }

        let tick_period = Duration::from_millis(self.config.tick_period_ms);
        let mut previous_tick = Instant::now();
        let mut idle_cycles = 0_usize;

        loop {
            // Wait (for up to `tick_period`) for incoming client requests and Raft messages
            let raft_messages = self.advance_node(tick_period)?;

            // Calculate how many ticks passed since the last one
            let elapsed_ticks = previous_tick.elapsed().div_duration_f32(tick_period) as u32;

            // Update previous tick timestamp
            previous_tick += tick_period * elapsed_ticks;

            // Calculate how many ticks we should *report* to Raft node.
            //
            // If last iteration of the loop took too long to complete, and we report all elapsed
            // ticks to Raft node, it might trigger unnecessary leader election.
            //
            // To prevent this, we check if we received new Raft messages (i.e., we are still
            // connected to Raft leader), and cap how many ticks we report to Raft node.
            //
            // By default, election is triggered if no Raft messages were received for 20 ticks,
            // so we report at most 15 ticks.
            //
            // See https://docs.rs/raft/latest/raft/struct.Config.html#structfield.election_tick.
            let report_ticks = if raft_messages > 0 {
                // Default `election_tick` is 20, so expected value here is 15
                let max_elapsed_ticks =
                    cmp::max(1, self.raft_config.election_tick.saturating_sub(5));

                cmp::min(elapsed_ticks, max_elapsed_ticks as u32)
            } else {
                elapsed_ticks
            };

            // Report elapsed ticks to Raft node
            for _ in 0..report_ticks {
                self.node.tick();
            }

            // Append new entries to the WAL, apply committed entries, etc...
            let (stop_consensus, is_idle) = self.on_ready()?;

            if stop_consensus {
                return Ok(());
            }

            // If we only sent outgoing Raft messages, but did not change any state during `on_ready`,
            // we consider Raft node to be "idle"
            if is_idle {
                // If current node is the only peer in the cluster, or if we received new Raft messages
                // (i.e., we are still connected to Raft leader/peers), and Raft node is idle,
                // count "idle cycle"
                if raft_messages > 0 || (self.is_single_peer() && self.is_leader()) {
                    idle_cycles += 1;
                }
            } else {
                // If Raft state was updated, reset idle cycle counter
                idle_cycles = 0;
            }

            // If Raft node was idle for 3 cycles, try to sync local state to consensus
            if idle_cycles >= 3 {
                self.try_sync_local_state()?;
            }
        }
    }

    fn advance_node(&mut self, tick_period: Duration) -> anyhow::Result<usize> {
        if self
            .try_promote_learner()
            .context("failed to promote learner")?
        {
            return Ok(0);
        }

        // This method propagates incoming client requests and Raft messages to Raft node

        // It's more efficient to process multiple events, so we propagate up to 128 events at a time
        const RAFT_BATCH_SIZE: usize = 128;

        // We have to tick Raft node periodically, so we can wait for new events for up to `tick_period`
        let hard_timeout_at = Instant::now() + tick_period;

        // We also want to react to new events as quickly as possible, so we only wait for `tick_period / 10`
        // for any consecutive events after the first one
        let consecutive_message_timeout = tick_period / 10;

        // Timeout to wait for the *next* event
        let mut timeout_at = hard_timeout_at;

        // Track how many *events* we received...
        let mut events = 0;
        // ...and how many of these events were *Raft messages*
        let mut raft_messages = 0;

        loop {
            let Ok(message) = self.recv_update(timeout_at) else {
                break;
            };

            // When we discover conf-change request, we have to break early and process it ASAP,
            // because Raft node allows to process single conf-change request at a time.
            //
            // E.g., without this condition, if two nodes try to join cluster at the same time and
            // both conf-change requests are processed in the same batch, the second request would
            // be ignored and the node would fail to join.
            let is_serialization_barrier = matches!(
                message,
                Message::FromClient(
                    ConsensusOperations::AddPeer { .. }
                        | ConsensusOperations::RemovePeer(_)
                        | ConsensusOperations::ActivatePrivateOramMutationV2(_)
                ),
            );

            let is_raft_message = matches!(message, Message::FromPeer(_));

            if let Err(err) = self.advance_node_impl(message) {
                log::warn!("{err}");
                continue;
            }

            timeout_at = cmp::min(
                hard_timeout_at,
                Instant::now() + consecutive_message_timeout,
            );

            events += 1;
            raft_messages += usize::from(is_raft_message);

            if events >= RAFT_BATCH_SIZE || is_serialization_barrier {
                break;
            }
        }

        Ok(raft_messages)
    }

    fn recv_update(&mut self, timeout_at: Instant) -> Result<Message, TryRecvUpdateError> {
        self.runtime.block_on(async {
            tokio::select! {
                biased;
                message = self.receiver.recv() => message.ok_or(TryRecvUpdateError::Closed),
                _ = tokio::time::sleep_until(timeout_at.into()) => Err(TryRecvUpdateError::Timeout),
            }
        })
    }

    fn advance_node_impl(&mut self, message: Message) -> anyhow::Result<()> {
        match message {
            Message::FromClient(ConsensusOperations::AddPeer { peer_id, uri }) => {
                self.ensure_private_oram_topology_proposal_allowed(TopologyChange::AddPeer)?;
                let existing_uris = self
                    .broker
                    .consensus_state
                    .peer_address_by_id()
                    .into_iter()
                    .map(|(peer_id, url)| (url, peer_id))
                    .collect::<HashMap<_, _>>();

                // Don't allow a peer URI to join if already in consensus
                // - new URIs can always join
                // - existing URIs can re-join with the same peer ID
                // See: <https://github.com/qdrant/qdrant/pull/7375>
                if let Some(registered_peer_id) =
                    existing_uris.get(&uri.parse::<Uri>().context("peer URI is not a valid URI")?)
                    && registered_peer_id != &peer_id
                {
                    log::warn!(
                        "Rejected peer {peer_id} to join consensus, URI is already registered by peer {registered_peer_id} ({uri})",
                    );
                    return Err(anyhow!(
                        "peer URI {uri} already used by peer {registered_peer_id}, remove it first or use a different URI",
                    ));
                }

                let mut change = ConfChangeV2::default();

                change.set_changes(vec![raft_proto::new_conf_change_single(
                    peer_id,
                    ConfChangeType::AddLearnerNode,
                )]);

                log::debug!("Proposing network configuration change: {change:?}");
                self.node
                    .propose_conf_change(uri.into_bytes(), change)
                    .context("failed to propose conf change")?;
            }

            Message::FromClient(ConsensusOperations::RemovePeer(peer_id)) => {
                self.ensure_private_oram_topology_proposal_allowed(TopologyChange::RemovePeer)?;
                let mut change = ConfChangeV2::default();

                change.set_changes(vec![raft_proto::new_conf_change_single(
                    peer_id,
                    ConfChangeType::RemoveNode,
                )]);

                log::debug!("Proposing network configuration change: {change:?}");
                self.node
                    .propose_conf_change(vec![], change)
                    .context("failed to propose conf change")?;
            }

            Message::FromClient(ConsensusOperations::RequestSnapshot) => {
                self.ensure_private_oram_activation_transition_allows_general_proposal()?;
                self.node
                    .request_snapshot()
                    .context("failed to request snapshot")?;
            }

            Message::FromClient(ConsensusOperations::ReportSnapshot { peer_id, status }) => {
                self.node.report_snapshot(peer_id, status.into());
            }

            Message::FromClient(ConsensusOperations::ActivatePrivateOramMutationV2(operation)) => {
                let current_term = self.node.raft.term;
                let last_log_index = self.node.store().last_index()?;
                let last_applied_index = self.node.raft.raft_log.applied;
                let pending_conf_index = self.node.raft.pending_conf_index;
                self.broker
                    .consensus_state
                    .validate_private_oram_mutation_activation_proposal(
                        &operation,
                        current_term,
                        last_log_index,
                        last_applied_index,
                        pending_conf_index,
                    )?;
                let consensus_operation =
                    ConsensusOperations::ActivatePrivateOramMutationV2(operation);
                let data = serde_cbor::to_vec(&consensus_operation)
                    .context("failed to serialize private ORAM activation barrier")?;
                self.node
                    .propose(vec![], data)
                    .context("failed to propose private ORAM activation barrier")?;
            }

            Message::FromClient(operation) => {
                self.ensure_private_oram_activation_transition_allows_general_proposal()?;
                let data =
                    serde_cbor::to_vec(&operation).context("failed to serialize operation")?;

                log::trace!("Proposing entry from client with length: {}", data.len());
                self.node
                    .propose(vec![], data)
                    .context("failed to propose entry")?;
            }

            Message::FromPeer(message) => {
                let is_heartbeat = matches!(
                    message.get_msg_type(),
                    MessageType::MsgHeartbeat | MessageType::MsgHeartbeatResponse,
                );

                if !is_heartbeat {
                    log::trace!(
                        "Received a message from peer with progress: {:?}. Message: {:?}",
                        self.node.raft.prs().get(message.from),
                        redacted_raft_message(&message),
                    );
                }

                if message.get_msg_type() == MessageType::MsgPropose
                    && self.is_leader()
                    && let Err(error) = self.validate_forwarded_proposal(&message)
                {
                    // Dropping a proposal is safe: the proposer's wait times out.
                    log::warn!(
                        "Dropped a proposal forwarded by peer {}: {error:#}",
                        message.from
                    );
                    return Ok(());
                }

                self.node.step(*message).context("failed to step message")?;
            }
        }

        Ok(())
    }

    fn ensure_private_oram_activation_transition_allows_general_proposal(
        &self,
    ) -> anyhow::Result<()> {
        let last_log_index = self.node.store().last_index()?;
        if self
            .broker
            .consensus_state
            .private_oram_mutation_activation_transition_pending(
                self.node.raft.raft_log.applied,
                last_log_index,
            )?
        {
            return Err(anyhow!(
                "ordinary consensus proposals are disabled while private ORAM mutation activation is in progress"
            ));
        }
        Ok(())
    }

    fn ensure_private_oram_topology_proposal_allowed(
        &self,
        change: TopologyChange,
    ) -> anyhow::Result<()> {
        self.ensure_private_oram_topology_floor_allows(change)?;
        let commit = self.node.store().hard_state().commit;
        let last_log_index = self.node.store().last_index()?;
        let applied = self.node.raft.raft_log.applied;
        if commit != last_log_index
            || applied != commit
            || raft_conf_change_pending(self.node.raft.pending_conf_index, applied)
        {
            return Err(anyhow!(
                "cluster topology change requires a fully applied stable Raft log"
            ));
        }
        Ok(())
    }

    fn ensure_private_oram_topology_floor_allows(
        &self,
        change: TopologyChange,
    ) -> anyhow::Result<()> {
        if self
            .broker
            .consensus_state
            .private_oram_mutation_format_floor_installed()
        {
            match change {
                // Dropping a dead peer never adds a participant outside the activation-time
                // private ORAM roster, and without it a degraded cluster could never recover
                // quorum. Adding peers still requires the roster to be re-established first.
                TopologyChange::RemovePeer => log::warn!(
                    "removing a peer after private ORAM mutation activation; the private ORAM                      roster stays bound to the activation-time membership"
                ),
                TopologyChange::AddPeer => {
                    return Err(anyhow!(
                        "adding peers is disabled after private ORAM mutation activation until the private ORAM roster is re-established"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Re-applies the private ORAM proposal gates to a proposal a follower forwarded to this
    /// leader. The gates run on the proposing node against its own state, and a follower that has
    /// not yet applied an activation forwards proposals the leader would refuse (a learner added
    /// after activation blocks every peer-recovery signer pin). The leader's own Raft-log
    /// quiescence is not required here; raft itself refuses a second pending conf change.
    fn validate_forwarded_proposal(&self, message: &RaftMessage) -> anyhow::Result<()> {
        for entry in &message.entries {
            match entry.get_entry_type() {
                EntryType::EntryConfChangeV2 => {
                    let change: ConfChangeV2 = prost_for_raft::Message::decode(entry.get_data())
                        .context("forwarded configuration change is malformed")?;
                    for single in &change.changes {
                        self.ensure_private_oram_topology_floor_allows(
                            match single.change_type() {
                                ConfChangeType::RemoveNode => TopologyChange::RemovePeer,
                                _ => TopologyChange::AddPeer,
                            },
                        )?;
                    }
                }
                EntryType::EntryConfChange => {
                    let change: ConfChange = prost_for_raft::Message::decode(entry.get_data())
                        .context("forwarded configuration change is malformed")?;
                    self.ensure_private_oram_topology_floor_allows(match change.change_type() {
                        ConfChangeType::RemoveNode => TopologyChange::RemovePeer,
                        _ => TopologyChange::AddPeer,
                    })?;
                }
                EntryType::EntryNormal => {
                    if entry.get_data().is_empty() {
                        continue;
                    }
                    let operation = ConsensusOperations::try_from(entry)
                        .context("forwarded proposal is malformed")?;
                    if let ConsensusOperations::ActivatePrivateOramMutationV2(operation) = operation
                    {
                        self.broker
                            .consensus_state
                            .validate_private_oram_mutation_activation_proposal(
                                &operation,
                                self.node.raft.term,
                                self.node.store().last_index()?,
                                self.node.raft.raft_log.applied,
                                self.node.raft.pending_conf_index,
                            )?;
                    } else {
                        self.ensure_private_oram_activation_transition_allows_general_proposal()?;
                    }
                }
            }
        }
        Ok(())
    }

    fn is_single_peer(&self) -> bool {
        self.node.store().peer_count() == 1
    }

    fn is_leader(&self) -> bool {
        self.node.status().ss.raft_state == StateRole::Leader
    }

    fn try_sync_local_state(&self) -> anyhow::Result<()> {
        if !self.node.has_ready() {
            // No updates to process
            let store = self.node.store();
            let pending_operations = store.persistent.read().unapplied_entities_count();
            if pending_operations == 0 && store.is_leader_established.check_ready() {
                // If leader is established and there is nothing else to do on this iteration,
                // then we can check if there are any un-synchronized local state left.
                store.sync_local_state()?;
            }
        }
        Ok(())
    }

    /// Tries to propose "origin peer" (the very first peer, that starts new cluster) to consensus
    fn try_add_origin(&mut self) -> Result<bool, TryAddOriginError> {
        // We can determine origin peer from consensus state:
        // - it should be the only peer in the cluster
        // - and its commit index should be at 0 or 1
        //
        // When we add a new node to existing cluster, we have to bootstrap it from existing cluster
        // node, and during bootstrap we explicitly add all current peers to consensus state. So,
        // *all* peers added to the cluster after the origin will always have at least two peers.
        //
        // When origin peer starts new cluster, it self-elects itself as a leader and commits empty
        // operation with index 1. It is impossible to commit anything to consensus before this
        // operation is committed. And to add another (second/third/etc) peer to the cluster, we
        // have to commit a conf-change operation. Which means that only origin peer can ever be at
        // commit index 0 or 1.

        // Check that we are the only peer in the cluster
        if self.node.store().peer_count() > 1 {
            return Ok(false);
        }

        let status = self.node.status();

        // Check that we are at index 0 or 1
        if status.hs.commit > 1 {
            return Ok(false);
        }

        // If we reached this point, we are the origin peer, but it's impossible to propose anything
        // to consensus, before leader is elected (`propose_conf_change` will return an error),
        // so we have to wait for a few ticks for self-election
        if !self.is_leader() {
            return Err(TryAddOriginError::NotLeader);
        }

        // Propose origin peer to consensus
        let mut change = ConfChangeV2::default();

        change.set_changes(vec![raft_proto::new_conf_change_single(
            status.id,
            ConfChangeType::AddNode,
        )]);

        let peer_uri = self
            .node
            .store()
            .persistent
            .read()
            .peer_address_by_id
            .read()
            .get(&status.id)
            .ok_or_else(|| TryAddOriginError::UriNotFound)?
            .to_string();

        self.node.propose_conf_change(peer_uri.into(), change)?;

        Ok(true)
    }

    /// Returns `true` if learner promotion was proposed, `false` otherwise.
    /// Learner node does not vote on elections, cause it might not have a big picture yet.
    /// So consensus should guarantee that learners are promoted one-by-one.
    /// Promotions are done by leader and only after it has no pending entries,
    /// that guarantees that learner will start voting only after it applies all the changes in the log
    fn try_promote_learner(&mut self) -> anyhow::Result<bool> {
        // Promote only if leader
        if !self.is_leader() {
            return Ok(false);
        }

        // Promote only when there are no uncommitted changes.
        let store = self.node.store();
        let commit = store.hard_state().commit;
        let last_log_entry = store.last_index()?;

        if self
            .broker
            .consensus_state
            .private_oram_mutation_activation_transition_pending(
                self.node.raft.raft_log.applied,
                last_log_entry,
            )?
            || self
                .broker
                .consensus_state
                .private_oram_mutation_format_floor_installed()
        {
            return Ok(false);
        }

        let applied = self.node.raft.raft_log.applied;
        if commit != last_log_entry
            || applied != commit
            || raft_conf_change_pending(self.node.raft.pending_conf_index, applied)
        {
            return Ok(false);
        }

        let Some(learner) = self.find_learner_to_promote() else {
            return Ok(false);
        };

        log::debug!("Proposing promotion for learner {learner} to voter");

        let mut change = ConfChangeV2::default();

        change.set_changes(vec![raft_proto::new_conf_change_single(
            learner,
            ConfChangeType::AddNode,
        )]);

        self.node.propose_conf_change(vec![], change)?;

        Ok(true)
    }

    fn find_learner_to_promote(&self) -> Option<u64> {
        let commit = self.node.store().hard_state().commit;
        let learners: HashSet<_> = self
            .node
            .store()
            .conf_state()
            .learners
            .into_iter()
            .collect();
        let status = self.node.status();
        status
            .progress?
            .iter()
            .find(|(id, progress)| learners.contains(id) && progress.matched == commit)
            .map(|(id, _)| *id)
    }

    /// Returns two boolean flags: `stop_consensus` and `is_idle`.
    /// If `stop_consensus` is true, then we should exit consensus loop and stop consensus.
    /// If `is_idle` is true, it means that no on-disk state was updated during this `on_ready` call.
    fn on_ready(&mut self) -> anyhow::Result<(bool, bool)> {
        if !self.node.has_ready() {
            // No updates to process
            return Ok((false, true));
        }

        self.store().record_consensus_working();

        // Get the `Ready` with `RawNode::ready` interface.
        let ready = self.node.ready();

        let (Some(light_ready), role_change, is_idle_ready) = self.process_ready(ready)? else {
            // No light ready, so we need to stop consensus.
            return Ok((true, false));
        };

        let (stop_consensus, is_idle_light_ready) = self.process_light_ready(light_ready)?;

        if let Some(role_change) = role_change {
            self.process_role_change(role_change);
        }

        self.store().compact_wal(self.config.compact_wal_entries)?;

        Ok((stop_consensus, is_idle_ready && is_idle_light_ready))
    }

    fn process_role_change(&self, role_change: StateRole) {
        // Explicit match here for better readability
        match role_change {
            StateRole::Candidate | StateRole::PreCandidate => {
                self.store().is_leader_established.make_not_ready()
            }
            StateRole::Leader | StateRole::Follower => {
                if self.node.raft.leader_id != INVALID_ID {
                    self.store().is_leader_established.make_ready()
                } else {
                    self.store().is_leader_established.make_not_ready()
                }
            }
        }
    }

    /// Tries to process raft's ready state. Happens on each tick.
    ///
    /// The order of operations in this functions is critical, changing it might lead to bugs.
    ///
    /// Returns with err on failure to apply the state.
    /// If it receives message to stop the consensus - returns None instead of LightReady.
    fn process_ready(
        &mut self,
        mut ready: raft::Ready,
    ) -> anyhow::Result<(Option<raft::LightReady>, Option<StateRole>, bool)> {
        let store = self.store();

        // We consider Raft node to be idle if we don't change Raft state during `process_ready`.
        //
        // E.g.:
        // - sending messages does not change Raft state, so it's considered idle
        // - but anything else does, and so is not idle
        let mut is_idle = true;

        if !ready.messages().is_empty() {
            log::trace!("Handling {} messages", ready.messages().len());
            self.send_messages(ready.take_messages());
        }

        if !ready.snapshot().is_empty() {
            // This is a snapshot, we need to apply the snapshot at first.
            let snapshot = ready.snapshot().clone();
            log::debug!("Applying snapshot {:?}", snapshot.get_metadata());
            is_idle = false;

            if let Err(err) = store.apply_snapshot(&snapshot)? {
                log::error!("Failed to apply snapshot: {err}");
            }
        }

        if !ready.entries().is_empty() {
            // Append entries to the Raft log.
            log::debug!("Appending {} entries to raft log", ready.entries().len());
            is_idle = false;

            store
                .append_entries(ready.take_entries())
                .context("Failed to append entries")?
        }

        if let Some(hs) = ready.hs() {
            // Raft HardState changed, and we need to persist it.
            log::debug!("Changing hard state. New hard state: {hs:?}");
            is_idle = false;

            store
                .set_hard_state(hs.clone())
                .context("Failed to set hard state")?
        }

        let role_change = ready.ss().map(|ss| ss.raft_state);

        if let Some(ss) = ready.ss() {
            log::debug!("Changing soft state. New soft state: {ss:?}");
            is_idle = false;

            self.handle_soft_state(ss);
        }

        if !ready.persisted_messages().is_empty() {
            log::trace!(
                "Handling {} persisted messages",
                ready.persisted_messages().len()
            );

            self.send_messages(ready.take_persisted_messages());
        }

        let committed_entries = ready.take_committed_entries();
        is_idle &= committed_entries.is_empty();

        // Should be done after Hard State is saved, so that `applied` index is never bigger than `commit`.
        let stop_consensus = handle_committed_entries(&committed_entries, &store, &mut self.node)
            .context("Failed to handle committed entries")?;

        if stop_consensus {
            return Ok((None, None, false));
        }

        // Advance the Raft.
        let light_rd = self.node.advance(ready);
        Ok((Some(light_rd), role_change, is_idle))
    }

    /// Tries to process raft's light ready state.
    ///
    /// The order of operations in this functions is critical, changing it might lead to bugs.
    ///
    /// Returns with err on failure to apply the state.
    /// If it receives message to stop the consensus - returns `true`, otherwise `false`.
    fn process_light_ready(
        &mut self,
        mut light_rd: raft::LightReady,
    ) -> anyhow::Result<(bool, bool)> {
        let store = self.store();

        // We consider Raft node to be idle, if we don't change Raft state during `process_light_ready`.
        //
        // E.g.:
        // - sending messages does not change Raft state, so it's considered idle
        // - but anything else does, and so is not idle
        let mut is_idle = true;

        // Update commit index.
        if let Some(commit) = light_rd.commit_index() {
            log::debug!("Updating commit index to {commit}");
            is_idle = false;

            store
                .set_commit_index(commit)
                .context("Failed to set commit index")?;
        }

        self.send_messages(light_rd.take_messages());

        let committed_entries = light_rd.take_committed_entries();
        is_idle &= committed_entries.is_empty();

        // Apply all committed entries.
        let stop_consensus = handle_committed_entries(&committed_entries, &store, &mut self.node)
            .context("Failed to apply committed entries")?;

        // Advance the apply index.
        self.node.advance_apply();
        Ok((stop_consensus, is_idle))
    }

    fn store(&self) -> ConsensusStateRef {
        self.node.store().clone()
    }

    fn handle_soft_state(&self, state: &SoftState) {
        let store = self.node.store();
        store.set_raft_soft_state(state);
    }

    fn send_messages(&mut self, messages: Vec<RaftMessage>) {
        self.broker.send(messages);
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
enum TryRecvUpdateError {
    #[error("timeout elapsed")]
    Timeout,

    #[error("channel closed")]
    Closed,
}

#[derive(Debug, thiserror::Error)]
enum TryAddOriginError {
    #[error("origin peer is not a leader")]
    NotLeader,

    #[error("origin peer URI not found")]
    UriNotFound,

    #[error("failed to propose origin peer URI to consensus: {0}")]
    RaftError(#[from] raft::Error),
}

/// This function actually applies the committed entries to the state machine.
/// Return `true` if consensus should be stopped.
/// `false` otherwise.
fn handle_committed_entries(
    entries: &[Entry],
    state: &ConsensusStateRef,
    raw_node: &mut RawNode<ConsensusStateRef>,
) -> anyhow::Result<bool> {
    let mut stop_consensus = false;
    if let (Some(first), Some(last)) = (entries.first(), entries.last()) {
        state.set_unapplied_entries(first.index, last.index)?;
        stop_consensus = state.apply_entries(raw_node)?;
    }
    Ok(stop_consensus)
}

struct RaftMessageBroker {
    senders: HashMap<PeerId, RaftMessageSenderHandle>,
    runtime: Handle,
    bootstrap_uri: Option<Uri>,
    tls_config: Option<ClientTlsConfig>,
    consensus_config: Arc<ConsensusConfig>,
    consensus_state: ConsensusStateRef,
    transport_channel_pool: Arc<TransportChannelPool>,
}

impl RaftMessageBroker {
    pub fn new(
        runtime: Handle,
        bootstrap_uri: Option<Uri>,
        tls_config: Option<ClientTlsConfig>,
        consensus_config: ConsensusConfig,
        consensus_state: ConsensusStateRef,
        transport_channel_pool: Arc<TransportChannelPool>,
    ) -> Self {
        Self {
            senders: HashMap::new(),
            runtime,
            bootstrap_uri,
            tls_config,
            consensus_config: consensus_config.into(),
            consensus_state,
            transport_channel_pool,
        }
    }

    pub fn send(&mut self, messages: impl IntoIterator<Item = RaftMessage>) {
        let mut messages = messages.into_iter();
        let mut retry = None;

        while let Some(message) = retry.take().or_else(|| messages.next()) {
            let peer_id = message.to;

            let sender = match self.senders.get_mut(&peer_id) {
                Some(sender) => sender,
                None => {
                    log::debug!("Spawning message sender task for peer {peer_id}...");

                    let (task, handle) = self.message_sender();
                    let future = self.runtime.spawn(task.exec());
                    drop(future); // drop `JoinFuture` explicitly to make clippy happy

                    self.senders.insert(peer_id, handle);

                    let Some(sender) = self.senders.get_mut(&peer_id) else {
                        log::error!("Failed to register message sender task for peer {peer_id}");
                        continue;
                    };
                    sender
                }
            };

            let failed_to_forward = |message: &RaftMessage, description: &str| {
                let peer_id = message.to;

                if log::max_level() >= log::Level::Debug {
                    log::error!(
                        "Failed to forward message {:?} to message sender task {peer_id}: \
                         {description}",
                        redacted_raft_message(message),
                    );
                } else {
                    log::error!(
                        "Failed to forward message to message sender task {peer_id}: {description}"
                    );
                }
            };

            match sender.send(message).map_err(|err| *err) {
                Ok(()) => (),

                Err(tokio::sync::mpsc::error::TrySendError::Full((_, message))) => {
                    failed_to_forward(
                        &message,
                        "message sender task queue is full. Message will be dropped.",
                    );
                }

                Err(tokio::sync::mpsc::error::TrySendError::Closed((_, message))) => {
                    failed_to_forward(
                        &message,
                        "message sender task queue is closed. \
                         Message sender task will be restarted and message will be retried.",
                    );

                    self.senders.remove(&peer_id);
                    retry = Some(message);
                }
            }
        }
    }

    fn message_sender(&self) -> (RaftMessageSender, RaftMessageSenderHandle) {
        let (messages_tx, messages_rx) = tokio::sync::mpsc::channel(128);
        let (heartbeat_tx, heartbeat_rx) = tokio::sync::watch::channel(Default::default());

        let task = RaftMessageSender {
            messages: messages_rx,
            heartbeat: heartbeat_rx,
            bootstrap_uri: self.bootstrap_uri.clone(),
            tls_config: self.tls_config.clone(),
            consensus_config: self.consensus_config.clone(),
            consensus_state: self.consensus_state.clone(),
            transport_channel_pool: self.transport_channel_pool.clone(),
        };

        let handle = RaftMessageSenderHandle {
            messages: messages_tx,
            heartbeat: heartbeat_tx,
            index: 0,
        };

        (task, handle)
    }
}

#[derive(Debug)]
struct RaftMessageSenderHandle {
    messages: Sender<(usize, RaftMessage)>,
    heartbeat: watch::Sender<(usize, RaftMessage)>,
    index: usize,
}

impl RaftMessageSenderHandle {
    fn send(&mut self, message: RaftMessage) -> RaftMessageSenderResult<()> {
        if !is_heartbeat(&message) {
            self.messages
                .try_send((self.index, message))
                .map_err(Box::new)?;
        } else {
            self.heartbeat.send((self.index, message)).map_err(
                |watch::error::SendError(message)| {
                    Box::new(tokio::sync::mpsc::error::TrySendError::Closed(message))
                },
            )?;
        }

        self.index += 1;

        Ok(())
    }
}

type RaftMessageSenderResult<T, E = RaftMessageSenderError> = Result<T, E>;
type RaftMessageSenderError = Box<tokio::sync::mpsc::error::TrySendError<(usize, RaftMessage)>>;

struct RaftMessageSender {
    messages: Receiver<(usize, RaftMessage)>,
    heartbeat: watch::Receiver<(usize, RaftMessage)>,
    bootstrap_uri: Option<Uri>,
    tls_config: Option<ClientTlsConfig>,
    consensus_config: Arc<ConsensusConfig>,
    consensus_state: ConsensusStateRef,
    transport_channel_pool: Arc<TransportChannelPool>,
}

impl RaftMessageSender {
    pub async fn exec(mut self) {
        // Imagine that `raft` crate put four messages to be sent to some other Raft node into
        // `RaftMessageSender`'s queue:
        //
        // | 4: AppendLog | 3: Heartbeat | 2: Heartbeat | 1: AppendLog |
        //
        // Heartbeat is the most basic message type in Raft. It only carries common "metadata"
        // without any additional "payload". And all other message types in Raft also carry
        // the same basic metadata as the heartbeat message.
        //
        // This way, message `3` instantly "outdates" message `2`: they both carry the same data
        // fields, but message `3` was produced more recently, and so it might contain newer values
        // of these data fields.
        //
        // And because all messages carry the same basic data as the heartbeat message, message `4`
        // instantly "outdates" both message `2` and `3`.
        //
        // This way, if there are more than one message queued for the `RaftMessageSender`,
        // we can optimize delivery a bit and skip any heartbeat message if there's a more
        // recent message scheduled later in the queue.
        //
        // `RaftMessageSender` have two separate "queues":
        // - `messages` queue for non-heartbeat messages
        // - and `heartbeat` "watch" channel for heartbeat messages
        //   - "watch" is a special channel in Tokio, that only retains the *last* sent value
        //   - so any heartbeat received from the `heartbeat` channel is always the *most recent* one
        //
        // We are using `tokio::select` to "simultaneously" check both queues for new messages...
        // but we are using `tokio::select` in a "biased" mode!
        //
        // - in this mode select always polls `messages.recv()` future first
        // - so even if there are new messages in both queues, it will always return a non-heartbeat
        //   message from `messages` queue first
        // - and it will only return a heartbeat message from `heartbeat` channel if there's no
        //   messages left in the `messages` queue
        //
        // There's one special case that we should be careful about with our two queues:
        //
        // If we return to the diagram above, and imagine four messages were sent in the same order
        // into our two queues, then `RaftMessageSender` might pull them from the queues in the
        // `1`, `4`, `3` order.
        //
        // E.g., we pull non-heartbeat messages `1` and `4` first, heartbeat `2` was overwritten
        // by heartbeat `3` (because of the "watch" channel), so once `messages` queue is empty
        // we receive heartbeat `3`, which is now out-of-order.
        //
        // To handle this we explicitly enumerate each message and only send a message if its index
        // is higher-or-equal than the index of a previous one. (This check can be expressed with
        // both strict "higher" or "higher-or-equal" conditional, I just like the "or-equal" version
        // a bit better.)
        //
        // If either `messages` queue or `heartbeat` channel is closed (e.g., `messages.recv()`
        // returns `None` or `heartbeat.changed()` returns an error), we assume that
        // `RaftMessageSenderHandle` has been dropped, and treat it as a "shutdown"/"cancellation"
        // signal (and break from the loop).

        let mut prev_index = 0;

        loop {
            let (index, message) = tokio::select! {
                biased;
                Some(message) = self.messages.recv() => message,
                Ok(()) = self.heartbeat.changed() => self.heartbeat.borrow_and_update().clone(),
                else => break,
            };

            if prev_index <= index {
                self.send(&message).await;
                prev_index = index;
            }
        }
    }

    async fn send(&self, message: &RaftMessage) {
        if let Err(err) = self.try_send(message).await {
            let peer_id = message.to;

            if log::max_level() >= log::Level::Debug {
                log::error!(
                    "Failed to send Raft message {:?} to peer {peer_id}: {err}",
                    redacted_raft_message(message),
                );
            } else {
                log::error!("Failed to send Raft message to peer {peer_id}: {err}");
            }
        }
    }

    async fn try_send(&self, message: &RaftMessage) -> anyhow::Result<()> {
        let peer_id = message.to;

        let uri = self.uri(peer_id).await?;
        let bytes = <RaftMessage as prost_for_raft::Message>::encode_to_vec(message);
        let grpc_message = GrpcRaftMessage { message: bytes };

        let timeout = Duration::from_millis(
            self.consensus_config.message_timeout_ticks * self.consensus_config.tick_period_ms,
        );

        let res = self
            .transport_channel_pool
            .with_channel_timeout(
                &uri,
                |channel| async {
                    let mut client = RaftClient::new(channel);
                    let mut request = tonic::Request::new(grpc_message.clone());
                    request.set_timeout(timeout);
                    client.send(request).await
                },
                Some(timeout),
                0,
            )
            .await;

        if message.msg_type == raft::eraftpb::MessageType::MsgSnapshot as i32 {
            let res = self.consensus_state.report_snapshot(
                peer_id,
                if res.is_ok() {
                    SnapshotStatus::Finish
                } else {
                    SnapshotStatus::Failure
                },
            );

            // Should we ignore the error? Seems like it will only produce noise.
            //
            // - `send_message` is only called by the sub-task spawned by the consensus thread.
            // - `report_snapshot` sends a message back to the consensus thread.
            // - It can only fail, if the "receiver" end of the channel is closed.
            // - Which means consensus thread either resolved successfully, or failed.
            // - So, if the consensus thread is shutting down, no need to log a misleading error...
            // - ...or, if the consensus thread failed, then we should already have an error,
            //   and it will only produce more noise.

            if let Err(err) = res {
                log::error!("{err}");
            }
        }

        match res {
            Ok(_) => self.consensus_state.record_message_send_success(&uri),
            Err(err) => self.consensus_state.record_message_send_failure(&uri, err),
        }

        Ok(())
    }

    async fn uri(&self, peer_id: PeerId) -> anyhow::Result<Uri> {
        let uri = self
            .consensus_state
            .peer_address_by_id()
            .get(&peer_id)
            .cloned();

        match uri {
            Some(uri) => Ok(uri),
            None => self.who_is(peer_id).await,
        }
    }

    async fn who_is(&self, peer_id: PeerId) -> anyhow::Result<Uri> {
        let bootstrap_uri = self
            .bootstrap_uri
            .clone()
            .ok_or_else(|| anyhow::format_err!("No bootstrap URI provided"))?;

        let bootstrap_timeout = Duration::from_secs(self.consensus_config.bootstrap_timeout_sec);

        // Use dedicated transport channel for who_is because of specific timeout
        let channel = make_grpc_channel(
            bootstrap_timeout,
            bootstrap_timeout,
            bootstrap_uri,
            self.tls_config.clone(),
        )
        .await
        .context("Failed to create who-is channel")?;

        let uri = RaftClient::new(channel)
            .who_is(tonic::Request::new(GrpcPeerId { id: peer_id }))
            .await?
            .into_inner()
            .uri
            .parse()?;

        Ok(uri)
    }
}

fn redacted_raft_message(message: &RaftMessage) -> RedactedRaftMessage<'_> {
    RedactedRaftMessage(message)
}

struct RedactedRaftMessage<'a>(&'a RaftMessage);

impl fmt::Debug for RedactedRaftMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = self.0;
        let entry_data_bytes = message
            .entries
            .iter()
            .map(|entry| entry.data.len())
            .sum::<usize>();
        let entry_context_bytes = message
            .entries
            .iter()
            .map(|entry| entry.context.len())
            .sum::<usize>();
        let snapshot_data_bytes = message
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.data.len());
        let snapshot_index = message
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.metadata.as_ref())
            .map(|metadata| metadata.index);
        let snapshot_term = message
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.metadata.as_ref())
            .map(|metadata| metadata.term);

        f.debug_struct("RaftMessage")
            .field("msg_type", &message.msg_type)
            .field("to", &message.to)
            .field("from", &message.from)
            .field("term", &message.term)
            .field("log_term", &message.log_term)
            .field("index", &message.index)
            .field("commit", &message.commit)
            .field("commit_term", &message.commit_term)
            .field("entries_count", &message.entries.len())
            .field("entry_data_bytes", &entry_data_bytes)
            .field("entry_context_bytes", &entry_context_bytes)
            .field("snapshot_data_bytes", &snapshot_data_bytes)
            .field("snapshot_index", &snapshot_index)
            .field("snapshot_term", &snapshot_term)
            .field("request_snapshot", &message.request_snapshot)
            .field("reject", &message.reject)
            .field("reject_hint", &message.reject_hint)
            .field("context_bytes", &message.context.len())
            .field("priority", &message.priority)
            .finish()
    }
}

fn is_heartbeat(message: &RaftMessage) -> bool {
    message.msg_type == raft::eraftpb::MessageType::MsgHeartbeat as i32
        || message.msg_type == raft::eraftpb::MessageType::MsgHeartbeatResponse as i32
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::operations::verification::new_unchecked_verification_pass;
    use collection::private_hnsw_oram_store::{
        PrivateHnswOramConsensusWriteback, PrivateHnswOramEpochState,
    };
    use collection::shards::channel_service::ChannelService;
    use common::budget::ResourceBudget;
    use segment::types::Distance;
    use slog::Drain;
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::content_manager::consensus::operation_sender::OperationSender;
    use storage::content_manager::consensus::persistent::Persistent;
    use storage::content_manager::consensus_manager::{ConsensusManager, ConsensusStateRef};
    use storage::content_manager::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout, PrivateOramConsensusEpoch,
        PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramIndexKind,
        PrivateOramLayoutKey,
    };
    use storage::content_manager::toc::TableOfContent;
    use storage::dispatcher::{Dispatcher, PrivateOramReplicaPrepareAck};
    use storage::rbac::{Access, AccessRequirements, Auth};
    use tempfile::Builder;

    use super::Consensus;
    use crate::common::helpers::create_general_purpose_runtime;
    use crate::common::private_hnsw::{
        PrivateHnswClientSignature, PrivateHnswReadPadding,
        do_stage_private_hnsw_buckets_for_initial_replication,
        do_stage_private_hnsw_manifest_for_initial_replication,
    };
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_NAME, NEXT_EPOCH, PrivateHnswRouteWireFixture,
        PrivateResultOramRouteFixture, VECTOR_NAME,
        create_private_hnsw_collection_with_private_result_oram, route_e2e_guard,
    };
    use crate::common::private_result_oram::{
        do_stage_private_result_oram_buckets_for_initial_replication,
        do_stage_private_result_oram_manifest_for_initial_replication,
    };
    use crate::settings::ConsensusConfig;
    use crate::tonic::api::qdrant_internal_api::{
        close_private_hnsw_session_coordinated, close_private_result_oram_session_coordinated,
        commit_private_hnsw_paths_coordinated, commit_private_result_oram_buckets_coordinated,
        coordinate_private_hnsw_initial_upload, coordinate_private_result_oram_initial_upload,
        open_private_hnsw_session_coordinated, open_private_result_oram_session_coordinated,
        prepare_private_oram_replica_removal,
        private_oram_current_layout_candidate_for_reservation, read_private_hnsw_paths_coordinated,
        read_private_result_oram_buckets_coordinated, release_private_oram_transfer_reservation,
    };

    #[test]
    fn raft_message_log_projection_redacts_entry_payload_bytes() {
        let mut message = raft::eraftpb::Message {
            msg_type: raft::eraftpb::MessageType::MsgAppend as i32,
            to: 7,
            from: 3,
            term: 11,
            index: 13,
            commit: 17,
            context: b"qdrant-sec-raft-context-sentinel".to_vec(),
            snapshot: Some(raft::eraftpb::Snapshot {
                data: b"qdrant-sec-raft-snapshot-sentinel".to_vec(),
                metadata: Some(raft::eraftpb::SnapshotMetadata {
                    index: 19,
                    term: 23,
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        message.entries.push(raft::eraftpb::Entry {
            data: b"qdrant-sec-raft-entry-sentinel".to_vec(),
            context: b"qdrant-sec-raft-entry-context-sentinel".to_vec(),
            ..Default::default()
        });

        let log_line = format!("{:?}", super::redacted_raft_message(&message));

        assert!(!log_line.contains("qdrant-sec-raft-entry-sentinel"));
        assert!(!log_line.contains("qdrant-sec-raft-entry-context-sentinel"));
        assert!(!log_line.contains("qdrant-sec-raft-context-sentinel"));
        assert!(!log_line.contains("qdrant-sec-raft-snapshot-sentinel"));
        assert!(log_line.contains("entries_count: 1"), "{log_line}");
        assert!(log_line.contains("entry_data_bytes"), "{log_line}");
        assert!(log_line.contains("snapshot_data_bytes"), "{log_line}");
        assert!(log_line.contains("context_bytes"), "{log_line}");
    }

    #[test]
    fn collection_creation_and_private_oram_consensus_cas_pass_consensus() {
        // Given
        let _route_guard = route_e2e_guard();
        let private_hnsw_settings_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let private_result_settings_fixture = PrivateResultOramRouteFixture::build();
        let storage_dir = Builder::new().prefix("storage").tempdir().unwrap();
        let mut settings = crate::Settings::new(None).expect("Can't read config.");
        settings.crypto = private_result_settings_fixture
            .route_settings_with_private_hnsw(&private_hnsw_settings_fixture)
            .crypto;
        settings.storage.storage_path = storage_dir.path().to_path_buf();
        tracing_subscriber::fmt::init();
        let search_runtime =
            crate::create_search_runtime(settings.storage.performance.max_search_threads)
                .expect("Can't create search runtime.");
        let update_runtime =
            crate::create_update_runtime(settings.storage.performance.max_search_threads)
                .expect("Can't create update runtime.");
        let general_runtime =
            create_general_purpose_runtime().expect("Can't create general purpose runtime.");
        let handle = general_runtime.handle().clone();
        let (propose_sender, propose_receiver) = std::sync::mpsc::channel();
        let persistent_state =
            Persistent::load_or_init(&settings.storage.storage_path, true, false, None).unwrap();
        let operation_sender = OperationSender::new(propose_sender);
        let toc = TableOfContent::new(
            &settings.storage,
            search_runtime,
            update_runtime,
            general_runtime,
            ResourceBudget::default(),
            ChannelService::new(
                settings.service.http_port,
                settings.service.enable_tls,
                None,
                None,
            ),
            persistent_state.this_peer_id(),
            Some(operation_sender.clone()),
        )
        .unwrap();
        let toc_arc = Arc::new(toc);
        let storage_path = toc_arc.storage_path();
        let consensus_state: ConsensusStateRef = ConsensusManager::new(
            persistent_state,
            toc_arc.clone(),
            operation_sender,
            storage_path,
            collection::operations::types::PeerMetadata::current_with_crypto_runtime_capability_fingerprint(
                Some(crate::common::crypto::crypto_runtime_capability_fingerprint(&settings)),
            ),
        )
        .expect("initialize consensus manager")
        .into();
        let dispatcher =
            Dispatcher::new(toc_arc.clone()).with_consensus(consensus_state.clone(), true);
        let slog_logger = slog::Logger::root(slog_stdlog::StdLog.fuse(), slog::o!());
        let (mut consensus, message_sender) = Consensus::new(
            &slog_logger,
            consensus_state.clone(),
            None,
            Some("http://127.0.0.1:6335".parse().unwrap()),
            6335,
            ConsensusConfig::default(),
            None,
            ChannelService::new(
                settings.service.http_port,
                settings.service.enable_tls,
                None,
                None,
            ),
            handle.clone(),
            false,
        )
        .unwrap();

        let is_leader_established = consensus_state.is_leader_established.clone();
        thread::spawn(move || consensus.start().unwrap());
        thread::spawn(move || {
            while let Ok(entry) = propose_receiver.recv() {
                if message_sender
                    .blocking_send(super::Message::FromClient(entry))
                    .is_err()
                {
                    log::error!("Can not forward new entry to consensus as it was stopped.");
                    break;
                }
            }
        });
        // Wait for Raft to establish the leader
        is_leader_established.await_ready();
        // Leader election produces a raft log entry, and then origin peer adds itself to consensus
        assert_eq!(consensus_state.hard_state().commit, 2);
        // Initially there are 0 collections
        assert_eq!(toc_arc.all_collections_sync().len(), 0);

        // When

        // New runtime is used as timers need to be enabled.
        handle
            .block_on(
                dispatcher.submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "test".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(10, Distance::Cosine)
                                    .build()
                                    .into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(2),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: None,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    Auth::new_internal(Access::full("For test")),
                    None,
                ),
            )
            .unwrap();

        // Then
        assert_eq!(consensus_state.hard_state().commit, 5); // first peer self-election + add first peer + create collection + activate shard x2
        assert_eq!(toc_arc.all_collections_sync(), vec!["test"]);

        let private_oram_key = PrivateOramEpochKey {
            collection_id: "qdrant-sec-consensus-collection-sentinel".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "qdrant-sec-consensus-vector-sentinel".to_string(),
        };
        let initial_private_oram_epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: data_encoding::BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        handle
            .block_on(dispatcher.submit_private_oram_epoch_cas(
                CompareAndSwapPrivateOramEpoch {
                    key: private_oram_key.clone(),
                    expected: None,
                    new: initial_private_oram_epoch.clone(),
                },
                None,
            ))
            .unwrap();
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            Some(initial_private_oram_epoch.clone()),
        );
        handle
            .block_on(dispatcher.submit_private_oram_epoch_cas(
                CompareAndSwapPrivateOramEpoch {
                    key: private_oram_key.clone(),
                    expected: None,
                    new: initial_private_oram_epoch.clone(),
                },
                None,
            ))
            .unwrap();

        let stale = handle
            .block_on(dispatcher.submit_private_oram_epoch_cas(
                CompareAndSwapPrivateOramEpoch {
                    key: private_oram_key.clone(),
                    expected: None,
                    new: PrivateOramConsensusEpoch {
                        index_epoch: 43,
                        root_hash: data_encoding::BASE64URL_NOPAD.encode(&[43; 32]),
                        writeback_digest: None,
                    },
                },
                None,
            ))
            .unwrap_err();
        let rendered = stale.to_string();
        assert!(
            rendered.contains("consensus epoch/root CAS precondition failed"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-consensus-collection-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-consensus-vector-sentinel"),
            "{rendered}",
        );
        assert!(!rendered.contains(&initial_private_oram_epoch.root_hash));
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            Some(initial_private_oram_epoch.clone()),
        );

        let private_oram_layout_key = PrivateOramLayoutKey {
            collection_id: private_oram_key.collection_id.clone(),
        };
        let initial_private_oram_layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![dispatcher.this_peer_id()],
            layout_digest: data_encoding::BASE64URL_NOPAD.encode(&[51; 32]),
            index_state_digest: data_encoding::BASE64URL_NOPAD.encode(&[52; 32]),
        };
        handle
            .block_on(dispatcher.submit_private_oram_layout_cas(
                CompareAndSwapPrivateOramLayout {
                    key: private_oram_layout_key.clone(),
                    expected: None,
                    new: initial_private_oram_layout.clone(),
                },
                None,
            ))
            .unwrap();
        assert_eq!(
            dispatcher
                .private_oram_consensus_layout(&private_oram_layout_key)
                .unwrap(),
            Some(initial_private_oram_layout.clone()),
        );

        let next_private_oram_layout = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: initial_private_oram_layout.owner_peer_ids.clone(),
            layout_digest: data_encoding::BASE64URL_NOPAD.encode(&[53; 32]),
            index_state_digest: data_encoding::BASE64URL_NOPAD.encode(&[54; 32]),
        };
        handle
            .block_on(dispatcher.submit_private_oram_layout_cas(
                CompareAndSwapPrivateOramLayout {
                    key: private_oram_layout_key.clone(),
                    expected: Some(initial_private_oram_layout),
                    new: next_private_oram_layout.clone(),
                },
                None,
            ))
            .unwrap();
        assert_eq!(
            dispatcher
                .private_oram_consensus_layout(&private_oram_layout_key)
                .unwrap(),
            Some(next_private_oram_layout),
        );

        let stale_prepare_count = Arc::new(AtomicUsize::new(0));
        let stale_abort_count = Arc::new(AtomicUsize::new(0));
        let stale_finalize_count = Arc::new(AtomicUsize::new(0));
        let stale_prepare_count_for_call = stale_prepare_count.clone();
        let stale_abort_count_for_call = stale_abort_count.clone();
        let stale_finalize_count_for_call = stale_finalize_count.clone();
        let stale_coordinator = handle
            .block_on(dispatcher.coordinate_private_oram_writeback(
                CompareAndSwapPrivateOramEpoch {
                    key: private_oram_key.clone(),
                    expected: None,
                    new: PrivateOramConsensusEpoch {
                        index_epoch: 44,
                        root_hash: data_encoding::BASE64URL_NOPAD.encode(&[44; 32]),
                        writeback_digest: None,
                    },
                },
                None,
                || {
                    stale_prepare_count_for_call.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    stale_abort_count_for_call.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    stale_finalize_count_for_call.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            ))
            .unwrap_err();
        assert!(
            stale_coordinator
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(stale_prepare_count.load(Ordering::SeqCst), 1);
        assert_eq!(stale_abort_count.load(Ordering::SeqCst), 1);
        assert_eq!(stale_finalize_count.load(Ordering::SeqCst), 0);

        let local_writeback = PrivateHnswOramConsensusWriteback {
            old: PrivateHnswOramEpochState {
                index_epoch: initial_private_oram_epoch.index_epoch,
                root_hash: initial_private_oram_epoch.root_hash.clone(),
            },
            new: PrivateHnswOramEpochState {
                index_epoch: 43,
                root_hash: data_encoding::BASE64URL_NOPAD.encode(&[43; 32]),
            },
            writeback_digest: data_encoding::BASE64URL_NOPAD.encode(&[11; 32]),
        };
        let writeback_operation = dispatcher
            .private_hnsw_oram_writeback_cas(
                private_oram_key.collection_id.clone(),
                private_oram_key.index_name.clone(),
                &local_writeback,
            )
            .unwrap();
        assert_eq!(
            writeback_operation.expected,
            Some(initial_private_oram_epoch.clone()),
        );
        let next_private_oram_epoch = writeback_operation.new.clone();
        assert_eq!(
            next_private_oram_epoch.index_epoch,
            local_writeback.new.index_epoch
        );
        assert_eq!(
            next_private_oram_epoch.root_hash,
            local_writeback.new.root_hash
        );
        assert_eq!(
            next_private_oram_epoch.writeback_digest.as_deref(),
            Some(local_writeback.writeback_digest.as_str()),
        );
        let unexpected_post_prepare_count = Arc::new(AtomicUsize::new(0));
        let unexpected_abort_count_for_prepare_failure = unexpected_post_prepare_count.clone();
        let unexpected_finalize_count_for_prepare_failure = unexpected_post_prepare_count.clone();
        let prepare_failure = handle
            .block_on(dispatcher.coordinate_private_oram_writeback(
                writeback_operation.clone(),
                None,
                || {
                    Err(
                        storage::content_manager::errors::StorageError::service_error(
                            "simulated private ORAM durable prepare failure",
                        ),
                    )
                },
                || {
                    unexpected_abort_count_for_prepare_failure.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    unexpected_finalize_count_for_prepare_failure.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            ))
            .unwrap_err();
        assert!(
            prepare_failure
                .to_string()
                .contains("simulated private ORAM durable prepare failure"),
        );
        assert_eq!(unexpected_post_prepare_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            writeback_operation.expected.clone(),
        );

        let prepare_count = Arc::new(AtomicUsize::new(0));
        let finalize_count = Arc::new(AtomicUsize::new(0));
        let prepare_count_for_failure = prepare_count.clone();
        let finalize_count_for_failure = finalize_count.clone();
        let finalize_failure = handle
            .block_on(dispatcher.coordinate_private_oram_writeback(
                writeback_operation.clone(),
                None,
                || {
                    prepare_count_for_failure.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || Ok(()),
                || {
                    finalize_count_for_failure.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        dispatcher
                            .private_oram_consensus_epoch(&private_oram_key)
                            .unwrap(),
                        Some(next_private_oram_epoch.clone()),
                    );
                    Err(
                        storage::content_manager::errors::StorageError::service_error(
                            "simulated private ORAM local finalize failure",
                        ),
                    )
                },
            ))
            .unwrap_err();
        assert!(
            finalize_failure
                .to_string()
                .contains("simulated private ORAM local finalize failure"),
        );
        assert_eq!(prepare_count.load(Ordering::SeqCst), 1);
        assert_eq!(finalize_count.load(Ordering::SeqCst), 1);

        let prepare_count_for_retry = prepare_count.clone();
        let finalize_count_for_retry = finalize_count.clone();
        handle
            .block_on(dispatcher.coordinate_private_oram_writeback(
                writeback_operation,
                None,
                || {
                    prepare_count_for_retry.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || Ok(()),
                || {
                    finalize_count_for_retry.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!(prepare_count.load(Ordering::SeqCst), 2);
        assert_eq!(finalize_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            Some(next_private_oram_epoch.clone()),
        );

        let follow_up_writeback = PrivateHnswOramConsensusWriteback {
            old: local_writeback.new,
            new: PrivateHnswOramEpochState {
                index_epoch: 44,
                root_hash: data_encoding::BASE64URL_NOPAD.encode(&[44; 32]),
            },
            writeback_digest: data_encoding::BASE64URL_NOPAD.encode(&[12; 32]),
        };
        let follow_up_operation = dispatcher
            .private_hnsw_oram_writeback_cas(
                private_oram_key.collection_id.clone(),
                private_oram_key.index_name.clone(),
                &follow_up_writeback,
            )
            .unwrap();
        assert_eq!(follow_up_operation.expected, Some(next_private_oram_epoch),);
        assert_eq!(
            follow_up_operation.new.writeback_digest.as_deref(),
            Some(follow_up_writeback.writeback_digest.as_str()),
        );

        let required_replica_peers = BTreeSet::from([8, 9]);
        let failed_events = Arc::new(Mutex::new(Vec::new()));
        let prepare_local_events = failed_events.clone();
        let prepare_replicas_events = failed_events.clone();
        let abort_local_events = failed_events.clone();
        let abort_replicas_events = failed_events.clone();
        let unexpected_finalize_local_events = failed_events.clone();
        let unexpected_finalize_replicas_events = failed_events.clone();
        let incomplete = handle
            .block_on(dispatcher.coordinate_replicated_private_oram_writeback(
                follow_up_operation.clone(),
                &required_replica_peers,
                None,
                move || {
                    prepare_local_events.lock().unwrap().push("prepare_local");
                    Ok(())
                },
                {
                    let digest = follow_up_writeback.writeback_digest.clone();
                    move || {
                        prepare_replicas_events
                            .lock()
                            .unwrap()
                            .push("prepare_replicas");
                        async move {
                            Ok(vec![PrivateOramReplicaPrepareAck {
                                peer_id: 8,
                                writeback_digest: digest,
                            }])
                        }
                    }
                },
                move || {
                    abort_local_events.lock().unwrap().push("abort_local");
                    Ok(())
                },
                move || async move {
                    abort_replicas_events.lock().unwrap().push("abort_replicas");
                    Ok(())
                },
                move || {
                    unexpected_finalize_local_events
                        .lock()
                        .unwrap()
                        .push("finalize_local");
                    Ok(())
                },
                move || async move {
                    unexpected_finalize_replicas_events
                        .lock()
                        .unwrap()
                        .push("finalize_replicas");
                    Ok(())
                },
            ))
            .unwrap_err();
        assert!(
            incomplete
                .to_string()
                .contains("replica prepare acknowledgements are incomplete"),
        );
        assert_eq!(
            *failed_events.lock().unwrap(),
            vec![
                "prepare_local",
                "prepare_replicas",
                "abort_replicas",
                "abort_local",
            ],
        );
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            follow_up_operation.expected.clone(),
        );

        let successful_events = Arc::new(Mutex::new(Vec::new()));
        let prepare_local_events = successful_events.clone();
        let prepare_replicas_events = successful_events.clone();
        let unexpected_abort_local_events = successful_events.clone();
        let unexpected_abort_replicas_events = successful_events.clone();
        let finalize_local_events = successful_events.clone();
        let finalize_replicas_events = successful_events.clone();
        let follow_up_consensus_epoch = follow_up_operation.new.clone();
        handle
            .block_on(dispatcher.coordinate_replicated_private_oram_writeback(
                follow_up_operation,
                &required_replica_peers,
                None,
                move || {
                    prepare_local_events.lock().unwrap().push("prepare_local");
                    Ok(())
                },
                {
                    let digest = follow_up_writeback.writeback_digest.clone();
                    move || {
                        prepare_replicas_events
                            .lock()
                            .unwrap()
                            .push("prepare_replicas");
                        async move {
                            Ok(vec![
                                PrivateOramReplicaPrepareAck {
                                    peer_id: 8,
                                    writeback_digest: digest.clone(),
                                },
                                PrivateOramReplicaPrepareAck {
                                    peer_id: 9,
                                    writeback_digest: digest,
                                },
                            ])
                        }
                    }
                },
                move || {
                    unexpected_abort_local_events
                        .lock()
                        .unwrap()
                        .push("abort_local");
                    Ok(())
                },
                move || async move {
                    unexpected_abort_replicas_events
                        .lock()
                        .unwrap()
                        .push("abort_replicas");
                    Ok(())
                },
                move || {
                    finalize_local_events.lock().unwrap().push("finalize_local");
                    Ok(())
                },
                move || async move {
                    finalize_replicas_events
                        .lock()
                        .unwrap()
                        .push("finalize_replicas");
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!(
            *successful_events.lock().unwrap(),
            vec![
                "prepare_local",
                "prepare_replicas",
                "finalize_replicas",
                "finalize_local",
            ],
        );
        assert_eq!(
            dispatcher
                .private_oram_consensus_epoch(&private_oram_key)
                .unwrap(),
            Some(follow_up_consensus_epoch),
        );

        handle.block_on(async {
            create_private_hnsw_collection_with_private_result_oram(&dispatcher).await;
            let auth = Auth::new_internal(Access::full("private HNSW consensus route test"));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_hnsw_consensus_fixture_identity",
                )
                .unwrap();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let collection_config = collection.config_snapshot().await;
            let collection_id = collection_config
                .stable_crypto_id(collection.name())
                .unwrap();
            let collection_id: &'static str = Box::leak(collection_id.into_boxed_str());
            let private_hnsw_fixture =
                PrivateHnswRouteWireFixture::build_uploaded_for_collection_id(collection_id)
                    .with_result_privacy(qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired);
            let private_result_fixture =
                PrivateResultOramRouteFixture::build_for_collection_id(collection_id);
            do_stage_private_hnsw_manifest_for_initial_replication(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                private_hnsw_fixture.manifest.clone(),
                private_hnsw_fixture.manifest_signature.clone(),
            )
            .await
            .unwrap();
            do_stage_private_hnsw_buckets_for_initial_replication(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                BASE_EPOCH,
                private_hnsw_fixture.encrypted_build.root_hash.clone(),
                private_hnsw_fixture.encrypted_build.buckets.clone(),
            )
            .await
            .unwrap();
            coordinate_private_hnsw_initial_upload(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
            )
            .await
            .unwrap();

            let session = open_private_hnsw_session_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                "tenant-a/consensus-sdk-instance".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired,
            )
            .await
            .unwrap();
            let session_key = PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: VECTOR_NAME.to_string(),
            };
            let lease = dispatcher
                .private_oram_consensus_session_lease(&session_key)
                .unwrap()
                .expect("coordinated open must acquire a consensus lease");
            assert_eq!(lease.owner_peer_id, dispatcher.this_peer_id());
            assert_eq!(lease.expires_at_unix, session.lease_expires_unix);

            let paths = vec![private_hnsw_fixture.entry_leaf_label()];
            let read_signature = private_hnsw_fixture.sign_read_paths(&paths, 1, true);
            let read = read_private_hnsw_paths_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                &session.session_id,
                BASE_EPOCH,
                &session.root_hash,
                paths,
                PrivateHnswReadPadding {
                    requested_paths: 1,
                    dummy_paths_included: true,
                },
                PrivateHnswClientSignature {
                    alg: read_signature.alg,
                    key_id: read_signature.key_id,
                    sig: read_signature.sig,
                },
            )
            .await
            .unwrap();
            assert_eq!(read.index_epoch, BASE_EPOCH);
            assert_eq!(read.root_hash, session.root_hash);
            assert!(!read.buckets.is_empty());

            let search_run = private_hnsw_fixture.run_single_search_collect_writeback();
            let committed = commit_private_hnsw_paths_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                &session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                search_run.commit_plan.old_root_hash,
                search_run.commit_plan.new_root_hash.clone(),
                search_run.updated_buckets,
                PrivateHnswClientSignature {
                    alg: search_run.commit_signature.alg,
                    key_id: search_run.commit_signature.key_id,
                    sig: search_run.commit_signature.sig,
                },
            )
            .await
            .unwrap();
            assert_eq!(committed.index_epoch, NEXT_EPOCH);
            assert_eq!(committed.root_hash, search_run.commit_plan.new_root_hash);
            let consensus_epoch = dispatcher
                .private_oram_consensus_epoch(&session_key)
                .unwrap()
                .expect("coordinated commit must preserve consensus ownership");
            assert_eq!(consensus_epoch.index_epoch, committed.index_epoch);
            assert_eq!(consensus_epoch.root_hash, committed.root_hash);
            assert!(consensus_epoch.writeback_digest.is_some());

            assert!(
                close_private_hnsw_session_coordinated(
                    &dispatcher,
                    &auth,
                    &settings,
                    COLLECTION_NAME,
                    VECTOR_NAME,
                    &session.session_id,
                )
                .await
                .unwrap()
            );
            assert!(
                dispatcher
                    .private_oram_consensus_session_lease(&session_key)
                    .unwrap()
                    .is_none()
            );

            do_stage_private_result_oram_manifest_for_initial_replication(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                private_result_fixture.manifest.clone(),
                private_result_fixture.signature.clone(),
            )
            .await
            .unwrap();
            do_stage_private_result_oram_buckets_for_initial_replication(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                BASE_EPOCH,
                private_result_fixture.manifest.root_hash.clone(),
                private_result_fixture.buckets.clone(),
            )
            .await
            .unwrap();
            coordinate_private_result_oram_initial_upload(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
            )
            .await
            .unwrap();

            let result_session = open_private_result_oram_session_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/result-consensus-sdk-instance".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();
            let result_session_key = PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            };
            let result_lease = dispatcher
                .private_oram_consensus_session_lease(&result_session_key)
                .unwrap()
                .expect("coordinated result open must acquire a consensus lease");
            assert_eq!(result_lease.owner_peer_id, dispatcher.this_peer_id());
            assert_eq!(
                result_lease.expires_at_unix,
                result_session.lease_expires_unix
            );

            let result_bucket_ids = vec![0, 1, 3];
            let result_read_signature = private_result_fixture.read_signature(&result_bucket_ids);
            let result_read = read_private_result_oram_buckets_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                &result_session.session_id,
                BASE_EPOCH,
                result_session.root_hash.clone(),
                result_bucket_ids,
                result_read_signature,
            )
            .await
            .unwrap();
            assert_eq!(result_read.index_epoch, BASE_EPOCH);
            assert_eq!(result_read.root_hash, result_session.root_hash);
            assert!(!result_read.buckets.is_empty());

            let (updated_result_bucket, result_commit_signature, result_new_root) =
                private_result_fixture.commit_bucket();
            let committed_result = commit_private_result_oram_buckets_coordinated(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                &result_session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                private_result_fixture.manifest.root_hash.clone(),
                result_new_root.clone(),
                vec![updated_result_bucket],
                result_commit_signature,
            )
            .await
            .unwrap();
            assert_eq!(committed_result.index_epoch, NEXT_EPOCH);
            assert_eq!(committed_result.root_hash, result_new_root);
            let result_consensus_epoch = dispatcher
                .private_oram_consensus_epoch(&result_session_key)
                .unwrap()
                .expect("coordinated result commit must preserve consensus ownership");
            assert_eq!(
                result_consensus_epoch.index_epoch,
                committed_result.index_epoch
            );
            assert_eq!(result_consensus_epoch.root_hash, committed_result.root_hash);
            assert!(result_consensus_epoch.writeback_digest.is_some());

            assert!(
                close_private_result_oram_session_coordinated(
                    &dispatcher,
                    &auth,
                    &settings,
                    COLLECTION_NAME,
                    &result_session.session_id,
                )
                .await
                .unwrap()
            );
            assert!(
                dispatcher
                    .private_oram_consensus_session_lease(&result_session_key)
                    .unwrap()
                    .is_none()
            );

            let reservation = prepare_private_oram_replica_removal(
                &dispatcher,
                &auth,
                &settings,
                COLLECTION_NAME,
                &collection_config,
            )
            .await
            .unwrap();
            let layout_candidate = private_oram_current_layout_candidate_for_reservation(
                &dispatcher,
                COLLECTION_NAME,
                &collection_config,
                &reservation,
            )
            .await
            .unwrap();
            assert_eq!(layout_candidate.generation, 1);
            assert_eq!(
                layout_candidate.owner_peer_ids,
                vec![dispatcher.this_peer_id()]
            );
            assert_eq!(layout_candidate.layout_digest.len(), 43);
            assert_eq!(layout_candidate.index_state_digest.len(), 43);
            let layout_key = PrivateOramLayoutKey {
                collection_id: collection_id.to_string(),
            };
            assert!(
                dispatcher
                    .private_oram_consensus_layout(&layout_key)
                    .unwrap()
                    .is_none()
            );
            dispatcher
                .submit_private_oram_layout_cas(
                    CompareAndSwapPrivateOramLayout {
                        key: layout_key.clone(),
                        expected: None,
                        new: layout_candidate.clone(),
                    },
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                private_oram_current_layout_candidate_for_reservation(
                    &dispatcher,
                    COLLECTION_NAME,
                    &collection_config,
                    &reservation,
                )
                .await
                .unwrap(),
                layout_candidate,
            );

            let stale_index_layout = PrivateOramConsensusLayout {
                generation: 2,
                index_state_digest: data_encoding::BASE64URL_NOPAD.encode(&[70; 32]),
                ..layout_candidate.clone()
            };
            dispatcher
                .submit_private_oram_layout_cas(
                    CompareAndSwapPrivateOramLayout {
                        key: layout_key.clone(),
                        expected: Some(layout_candidate.clone()),
                        new: stale_index_layout.clone(),
                    },
                    None,
                )
                .await
                .unwrap();
            let refreshed_candidate = private_oram_current_layout_candidate_for_reservation(
                &dispatcher,
                COLLECTION_NAME,
                &collection_config,
                &reservation,
            )
            .await
            .unwrap();
            assert_eq!(refreshed_candidate.generation, 2);
            assert_eq!(
                refreshed_candidate.layout_digest,
                stale_index_layout.layout_digest
            );
            assert_ne!(
                refreshed_candidate.index_state_digest,
                stale_index_layout.index_state_digest
            );

            let drifted_layout = PrivateOramConsensusLayout {
                generation: 3,
                layout_digest: data_encoding::BASE64URL_NOPAD.encode(&[71; 32]),
                ..stale_index_layout.clone()
            };
            dispatcher
                .submit_private_oram_layout_cas(
                    CompareAndSwapPrivateOramLayout {
                        key: layout_key,
                        expected: Some(stale_index_layout),
                        new: drifted_layout.clone(),
                    },
                    None,
                )
                .await
                .unwrap();
            let drift_error = private_oram_current_layout_candidate_for_reservation(
                &dispatcher,
                COLLECTION_NAME,
                &collection_config,
                &reservation,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                drift_error.contains("does not match the stable collection layout"),
                "{drift_error}"
            );
            assert!(!drift_error.contains(collection_id), "{drift_error}");
            assert!(
                !drift_error.contains(&drifted_layout.layout_digest),
                "{drift_error}"
            );
            release_private_oram_transfer_reservation(&dispatcher, &reservation)
                .await
                .unwrap();
        });
    }
}

//! Dormant, dedicated Raft-state contract for private-ORAM activation authority.
//!
//! This module deliberately does not define a consensus operation. Old binaries cannot decode a
//! new externally tagged `ConsensusOperations` variant, so mutation remains unavailable until an
//! irreversible mixed-version activation barrier exists.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateOramActivationAuthorityBundleV1, PrivateOramActivationAuthorityManifestV1,
    PrivateOramActivationAuthorityTrustAnchorV1, PrivateOramActivationRegistryExpectationV1,
    PrivateOramConsensusConfigurationV1, PrivateOramPeerActivationChallengeV1,
    PrivateOramPeerRecoveryPublicKeyV1, VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    private_oram_activation_authority_manifest_digest_v1,
    private_oram_activation_signer_from_signed_manifest_for_challenge_v1,
    validate_private_oram_activation_authority_bundle_v1,
    validate_private_oram_activation_authority_manifest_v1_shape,
    validate_private_oram_activation_authority_signature_v1_shape,
    validate_private_oram_activation_authority_transition_v1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_STATE_VERSION: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateOramActivationAuthorityStoreInstanceId([u8; 32]);

impl Default for PrivateOramActivationAuthorityStoreInstanceId {
    fn default() -> Self {
        Self(rand::random())
    }
}

impl Debug for PrivateOramActivationAuthorityStoreInstanceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateOramActivationAuthorityStoreInstanceId([redacted])")
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramActivationAuthorityStateError {
    #[error("private ORAM activation authority state version is unsupported")]
    UnsupportedStateVersion,
    #[error("persisted private ORAM activation authority state is invalid")]
    InvalidPersistedState,
    #[error("private ORAM activation authority candidate is invalid")]
    InvalidCandidate,
    #[error("private ORAM activation authority CAS precondition failed")]
    PreconditionFailed,
    #[error("private ORAM activation authority snapshot transition is invalid")]
    InvalidSnapshotTransition,
    #[error("private ORAM activation challenge does not match the authority snapshot")]
    ChallengeContextMismatch,
}

impl Debug for PrivateOramActivationAuthorityStateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramActivationAuthorityStateError")
            .field(&self.to_string())
            .finish()
    }
}

/// Canonical value persisted as one dedicated Raft state field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramActivationAuthorityStateV1 {
    version: u16,
    manifest_digest: String,
    bundle: PrivateOramActivationAuthorityBundleV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_upgrade: Option<PrivateOramActivationCapabilityUpgradeV1>,
}

/// Bounded evidence for the interval between an operator's authority rotation and the new floor.
/// Keeping the complete signed predecessor lets restart verify the exact consecutive transition;
/// its floor binding cannot authorize a mismatch against a different applied floor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramActivationCapabilityUpgradeV1 {
    predecessor: PrivateOramActivationAuthorityBundleV1,
    format_floor_digest: String,
}

impl Debug for PrivateOramActivationAuthorityStateV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityStateV1")
            .field("version", &self.version)
            .field("registry_generation", &self.registry_generation())
            .field("manifest_digest", &"[redacted]")
            .field("bundle", &"[redacted]")
            .field("capability_upgrade", &self.capability_upgrade.is_some())
            .finish()
    }
}

impl PrivateOramActivationAuthorityStateV1 {
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn registry_generation(&self) -> u64 {
        self.bundle.manifest.registry_generation
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn bundle(&self) -> &PrivateOramActivationAuthorityBundleV1 {
        &self.bundle
    }

    pub fn manifest(&self) -> &PrivateOramActivationAuthorityManifestV1 {
        &self.bundle.manifest
    }

    pub fn locator(&self) -> PrivateOramActivationAuthorityLocatorV1 {
        PrivateOramActivationAuthorityLocatorV1 {
            registry_generation: self.registry_generation(),
            manifest_digest: self.manifest_digest.clone(),
        }
    }

    pub(super) fn retain_capability_upgrade_predecessor(
        &mut self,
        predecessor: &Self,
        format_floor_digest: &str,
    ) {
        self.capability_upgrade = Some(PrivateOramActivationCapabilityUpgradeV1 {
            predecessor: predecessor.bundle.clone(),
            format_floor_digest: format_floor_digest.to_string(),
        });
    }

    /// The caller must first verify this authority under the configured external trust anchor.
    pub(super) fn capability_upgrade_matches_floor(
        &self,
        format_floor_digest: &str,
        required_binary_capability_digest: &str,
    ) -> bool {
        self.capability_upgrade.as_ref().is_some_and(|upgrade| {
            upgrade.format_floor_digest == format_floor_digest
                && upgrade
                    .predecessor
                    .manifest
                    .required_binary_capability_digest
                    == required_binary_capability_digest
        })
    }

    fn from_verified(verified: &VerifiedSignedPrivateOramActivationAuthorityManifestV1) -> Self {
        Self {
            version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_STATE_VERSION,
            manifest_digest: verified.manifest_digest().to_string(),
            bundle: verified.bundle().clone(),
            capability_upgrade: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramActivationAuthorityLocatorV1 {
    registry_generation: u64,
    manifest_digest: String,
}

impl Debug for PrivateOramActivationAuthorityLocatorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityLocatorV1")
            .field("registry_generation", &self.registry_generation)
            .field("manifest_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramActivationAuthorityLocatorV1 {
    pub fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub(in crate::content_manager) fn from_verified_parts(
        registry_generation: u64,
        manifest_digest: String,
    ) -> Self {
        Self {
            registry_generation,
            manifest_digest,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        registry_generation: u64,
        manifest_digest: impl Into<String>,
    ) -> Self {
        Self {
            registry_generation,
            manifest_digest: manifest_digest.into(),
        }
    }
}

/// Authority verified from the dedicated persistent value while its read lock was held.
///
/// This is a point-in-time snapshot, not a lease. Callers must reacquire it after every network
/// round trip and compare the locator before accepting an acknowledgement or changing runtime
/// behavior.
#[must_use]
pub struct PrivateOramActivationAuthorityCurrentAtReadV1 {
    store_instance_id: PrivateOramActivationAuthorityStoreInstanceId,
    trust_anchor: PrivateOramActivationAuthorityTrustAnchorV1,
    view: PrivateOramActivationAuthorityAtReadViewV1,
}

enum PrivateOramActivationAuthorityAtReadViewV1 {
    Empty,
    V1(Box<VerifiedSignedPrivateOramActivationAuthorityManifestV1>),
}

impl Debug for PrivateOramActivationAuthorityCurrentAtReadV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PrivateOramActivationAuthorityCurrentAtReadV1");
        match &self.view {
            PrivateOramActivationAuthorityAtReadViewV1::Empty => {
                debug.field("state", &"empty");
            }
            PrivateOramActivationAuthorityAtReadViewV1::V1(verified) => {
                debug.field("state", &"v1").field(
                    "registry_generation",
                    &verified.manifest().registry_generation,
                );
            }
        }
        debug.finish()
    }
}

impl PrivateOramActivationAuthorityCurrentAtReadV1 {
    pub fn is_empty(&self) -> bool {
        matches!(
            &self.view,
            PrivateOramActivationAuthorityAtReadViewV1::Empty
        )
    }

    pub fn locator(&self) -> Option<PrivateOramActivationAuthorityLocatorV1> {
        match &self.view {
            PrivateOramActivationAuthorityAtReadViewV1::Empty => None,
            PrivateOramActivationAuthorityAtReadViewV1::V1(verified) => {
                Some(PrivateOramActivationAuthorityLocatorV1 {
                    registry_generation: verified.manifest().registry_generation,
                    manifest_digest: verified.manifest_digest().to_string(),
                })
            }
        }
    }

    pub fn manifest(&self) -> Option<&PrivateOramActivationAuthorityManifestV1> {
        match &self.view {
            PrivateOramActivationAuthorityAtReadViewV1::Empty => None,
            PrivateOramActivationAuthorityAtReadViewV1::V1(verified) => Some(verified.manifest()),
        }
    }

    pub(crate) fn verified_manifest(
        &self,
    ) -> Option<&VerifiedSignedPrivateOramActivationAuthorityManifestV1> {
        match &self.view {
            PrivateOramActivationAuthorityAtReadViewV1::Empty => None,
            PrivateOramActivationAuthorityAtReadViewV1::V1(verified) => Some(verified),
        }
    }

    pub fn signer_for_challenge_at_read<'a>(
        &'a self,
        configuration: &PrivateOramConsensusConfigurationV1,
        observed_target_uri_digest: &str,
        challenge: &PrivateOramPeerActivationChallengeV1,
    ) -> Result<&'a PrivateOramPeerRecoveryPublicKeyV1, PrivateOramActivationAuthorityStateError>
    {
        let PrivateOramActivationAuthorityAtReadViewV1::V1(verified) = &self.view else {
            return Err(PrivateOramActivationAuthorityStateError::ChallengeContextMismatch);
        };
        private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
            verified,
            configuration,
            observed_target_uri_digest,
            challenge,
        )
        .map_err(|_| PrivateOramActivationAuthorityStateError::ChallengeContextMismatch)
    }
}

pub fn validate_private_oram_activation_authority_state_v1_shape(
    state: &PrivateOramActivationAuthorityStateV1,
) -> Result<(), PrivateOramActivationAuthorityStateError> {
    if state.version != PRIVATE_ORAM_ACTIVATION_AUTHORITY_STATE_VERSION {
        return Err(PrivateOramActivationAuthorityStateError::UnsupportedStateVersion);
    }
    validate_private_oram_activation_authority_manifest_v1_shape(&state.bundle.manifest)
        .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
    validate_private_oram_activation_authority_signature_v1_shape(&state.bundle.signature)
        .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
    let expected_digest =
        private_oram_activation_authority_manifest_digest_v1(&state.bundle.manifest)
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
    if state.manifest_digest != expected_digest {
        return Err(PrivateOramActivationAuthorityStateError::InvalidPersistedState);
    }
    if let Some(upgrade) = &state.capability_upgrade {
        let invalid = || PrivateOramActivationAuthorityStateError::InvalidPersistedState;
        let predecessor = &upgrade.predecessor;
        validate_private_oram_activation_authority_manifest_v1_shape(&predecessor.manifest)
            .map_err(|_| invalid())?;
        validate_private_oram_activation_authority_signature_v1_shape(&predecessor.signature)
            .map_err(|_| invalid())?;
        let predecessor_digest =
            private_oram_activation_authority_manifest_digest_v1(&predecessor.manifest)
                .map_err(|_| invalid())?;
        let floor_digest = BASE64URL_NOPAD
            .decode(upgrade.format_floor_digest.as_bytes())
            .map_err(|_| invalid())?;
        if predecessor.manifest.registry_generation.checked_add(1)
            != Some(state.registry_generation())
            || state.manifest().parent_manifest_digest.as_deref()
                != Some(predecessor_digest.as_str())
            || floor_digest.len() != 32
            || BASE64URL_NOPAD.encode(&floor_digest) != upgrade.format_floor_digest
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn verify_private_oram_activation_authority_current_at_read_v1(
    state: Option<&PrivateOramActivationAuthorityStateV1>,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    store_instance_id: PrivateOramActivationAuthorityStoreInstanceId,
) -> Result<PrivateOramActivationAuthorityCurrentAtReadV1, PrivateOramActivationAuthorityStateError>
{
    let Some(state) = state else {
        return Ok(PrivateOramActivationAuthorityCurrentAtReadV1 {
            store_instance_id,
            trust_anchor: trust_anchor.clone(),
            view: PrivateOramActivationAuthorityAtReadViewV1::Empty,
        });
    };
    let verified = verify_private_oram_activation_authority_state_v1(state, trust_anchor)?;
    Ok(PrivateOramActivationAuthorityCurrentAtReadV1 {
        store_instance_id,
        trust_anchor: trust_anchor.clone(),
        view: PrivateOramActivationAuthorityAtReadViewV1::V1(Box::new(verified)),
    })
}

fn verify_private_oram_activation_authority_state_v1(
    state: &PrivateOramActivationAuthorityStateV1,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
) -> Result<
    VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    PrivateOramActivationAuthorityStateError,
> {
    validate_private_oram_activation_authority_state_v1_shape(state)?;
    let verified = validate_private_oram_activation_authority_bundle_v1(
        &state.bundle,
        trust_anchor,
        PrivateOramActivationRegistryExpectationV1::Anchored {
            registry_generation: state.registry_generation(),
            manifest_digest: state.manifest_digest(),
        },
    )
    .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
    if let Some(upgrade) = &state.capability_upgrade {
        let predecessor_digest =
            private_oram_activation_authority_manifest_digest_v1(&upgrade.predecessor.manifest)
                .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
        let predecessor = validate_private_oram_activation_authority_bundle_v1(
            &upgrade.predecessor,
            trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Anchored {
                registry_generation: upgrade.predecessor.manifest.registry_generation,
                manifest_digest: &predecessor_digest,
            },
        )
        .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
        validate_private_oram_activation_authority_transition_v1(
            &predecessor,
            &state.bundle,
            trust_anchor,
        )
        .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidPersistedState)?;
    }
    Ok(verified)
}

pub(super) fn plan_private_oram_activation_authority_cas_v1(
    current: Option<&PrivateOramActivationAuthorityStateV1>,
    expected: PrivateOramActivationAuthorityCurrentAtReadV1,
    new_bundle: &PrivateOramActivationAuthorityBundleV1,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    store_instance_id: PrivateOramActivationAuthorityStoreInstanceId,
) -> Result<PrivateOramActivationAuthorityStateV1, PrivateOramActivationAuthorityStateError> {
    if expected.store_instance_id != store_instance_id || expected.trust_anchor != *trust_anchor {
        return Err(PrivateOramActivationAuthorityStateError::PreconditionFailed);
    }
    match (current, expected.view) {
        (None, PrivateOramActivationAuthorityAtReadViewV1::Empty) => {
            let verified = validate_private_oram_activation_authority_bundle_v1(
                new_bundle,
                trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Genesis,
            )
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidCandidate)?;
            Ok(PrivateOramActivationAuthorityStateV1::from_verified(
                &verified,
            ))
        }
        (Some(current), PrivateOramActivationAuthorityAtReadViewV1::V1(expected_verified)) => {
            let reread = verify_private_oram_activation_authority_current_at_read_v1(
                Some(current),
                trust_anchor,
                store_instance_id,
            )?;
            let PrivateOramActivationAuthorityAtReadViewV1::V1(reread_verified) = reread.view
            else {
                return Err(PrivateOramActivationAuthorityStateError::InvalidPersistedState);
            };
            if expected_verified.manifest_digest() != reread_verified.manifest_digest()
                || expected_verified.bundle() != reread_verified.bundle()
            {
                return Err(PrivateOramActivationAuthorityStateError::PreconditionFailed);
            }
            let verified = validate_private_oram_activation_authority_transition_v1(
                &reread_verified,
                new_bundle,
                trust_anchor,
            )
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidCandidate)?;
            Ok(PrivateOramActivationAuthorityStateV1::from_verified(
                &verified,
            ))
        }
        _ => Err(PrivateOramActivationAuthorityStateError::PreconditionFailed),
    }
}

pub fn validate_private_oram_activation_authority_snapshot_transition_v1(
    current: Option<&PrivateOramActivationAuthorityStateV1>,
    incoming: Option<&PrivateOramActivationAuthorityStateV1>,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
) -> Result<(), PrivateOramActivationAuthorityStateError> {
    if let Some(current) = current {
        validate_private_oram_activation_authority_state_v1_shape(current)?;
    }
    if let Some(incoming) = incoming {
        verify_private_oram_activation_authority_state_v1(incoming, trust_anchor)
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition)?;
    }
    match (current, incoming) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
        (None, Some(incoming)) => {
            let verified = validate_private_oram_activation_authority_bundle_v1(
                incoming.bundle(),
                trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Genesis,
            )
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition)?;
            if verified.manifest_digest() != incoming.manifest_digest() {
                return Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition);
            }
            Ok(())
        }
        (Some(current), Some(incoming)) if current == incoming => {
            verify_private_oram_activation_authority_state_v1(current, trust_anchor)
                .map(|_| ())
                .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition)
        }
        (Some(current), Some(incoming)) => {
            let current = verify_private_oram_activation_authority_state_v1(current, trust_anchor)
                .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition)?;
            let verified = validate_private_oram_activation_authority_transition_v1(
                &current,
                incoming.bundle(),
                trust_anchor,
            )
            .map_err(|_| PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition)?;
            if verified.manifest_digest() != incoming.manifest_digest() {
                return Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) fn private_oram_activation_authority_fixture_v1_for_test() -> (
    ring::signature::Ed25519KeyPair,
    PrivateOramActivationAuthorityTrustAnchorV1,
    PrivateOramActivationAuthorityBundleV1,
) {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY, PrivateOramActivationPeerPinV1,
        PrivateOramActivationPeerUriSchemeV1,
        package_private_oram_activation_authority_manifest_v1,
        private_oram_activation_authority_public_key_v1, private_oram_peer_recovery_public_key_v1,
        try_private_oram_activation_cluster_identity_digest_v1,
        try_private_oram_activation_peer_uri_digest_v1,
    };

    let authority_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[10; 32]).unwrap();
    let authority = private_oram_activation_authority_public_key_v1(&authority_key, 1).unwrap();
    let cluster_identity_nonce = BASE64URL_NOPAD.encode(&[1; 32]);
    let cluster_first_voter_peer_id = 11;
    let peer = |peer_id: u64, seed: u8| PrivateOramActivationPeerPinV1 {
        peer_id,
        peer_uri_digest: try_private_oram_activation_peer_uri_digest_v1(
            PrivateOramActivationPeerUriSchemeV1::Https,
            &format!("node-{peer_id}.internal"),
            6335,
        )
        .unwrap(),
        signer: private_oram_peer_recovery_public_key_v1(
            &ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
            1,
        )
        .unwrap(),
    };
    let manifest = PrivateOramActivationAuthorityManifestV1 {
        version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        cluster_identity_digest: try_private_oram_activation_cluster_identity_digest_v1(
            &cluster_identity_nonce,
            cluster_first_voter_peer_id,
        )
        .unwrap(),
        cluster_identity_nonce,
        cluster_first_voter_peer_id,
        registry_generation: 1,
        parent_manifest_digest: None,
        required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
        required_binary_capability_digest: BASE64URL_NOPAD.encode(&[2; 32]),
        authority_key_epoch: authority.key_epoch,
        authority_key_id: authority.key_id.clone(),
        peers: vec![peer(7, 8), peer(9, 19), peer(11, 21), peer(13, 22)],
    };
    let trust_anchor = PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
        authority,
        manifest.cluster_identity_digest.clone(),
        manifest.cluster_first_voter_peer_id,
    )
    .unwrap();
    let bundle =
        package_private_oram_activation_authority_manifest_v1(&authority_key, 1, manifest).unwrap();
    (authority_key, trust_anchor, bundle)
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY, PrivateOramActivationAuthorityPublicKeyV1,
        PrivateOramActivationPeerPinV1, PrivateOramActivationPeerUriSchemeV1,
        package_private_oram_activation_authority_manifest_v1,
        private_oram_activation_authority_public_key_v1, private_oram_peer_recovery_public_key_v1,
        try_private_oram_activation_cluster_identity_digest_v1,
        try_private_oram_activation_peer_uri_digest_v1,
    };
    use ring::signature::Ed25519KeyPair;

    use super::*;

    fn digest(value: u8) -> String {
        BASE64URL_NOPAD.encode(&[value; 32])
    }

    fn key_pair(value: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[value; 32]).unwrap()
    }

    fn peer(peer_id: u64, seed: u8) -> PrivateOramActivationPeerPinV1 {
        PrivateOramActivationPeerPinV1 {
            peer_id,
            peer_uri_digest: try_private_oram_activation_peer_uri_digest_v1(
                PrivateOramActivationPeerUriSchemeV1::Https,
                &format!("node-{peer_id}.internal"),
                6335,
            )
            .unwrap(),
            signer: private_oram_peer_recovery_public_key_v1(&key_pair(seed), 1).unwrap(),
        }
    }

    fn genesis() -> (
        Ed25519KeyPair,
        PrivateOramActivationAuthorityTrustAnchorV1,
        PrivateOramActivationAuthorityBundleV1,
    ) {
        let key_pair = key_pair(10);
        let authority = private_oram_activation_authority_public_key_v1(&key_pair, 1).unwrap();
        let cluster_identity_nonce = digest(1);
        let cluster_first_voter_peer_id = 11;
        let manifest = PrivateOramActivationAuthorityManifestV1 {
            version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
            cluster_identity_digest: try_private_oram_activation_cluster_identity_digest_v1(
                &cluster_identity_nonce,
                cluster_first_voter_peer_id,
            )
            .unwrap(),
            cluster_identity_nonce,
            cluster_first_voter_peer_id,
            registry_generation: 1,
            parent_manifest_digest: None,
            required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            required_binary_capability_digest: digest(2),
            authority_key_epoch: authority.key_epoch,
            authority_key_id: authority.key_id.clone(),
            peers: vec![peer(11, 21), peer(13, 22)],
        };
        let trust_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                authority,
                manifest.cluster_identity_digest.clone(),
                manifest.cluster_first_voter_peer_id,
            )
            .unwrap();
        let bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, manifest).unwrap();
        (key_pair, trust_anchor, bundle)
    }

    fn successor(
        key_pair: &Ed25519KeyPair,
        current: &PrivateOramActivationAuthorityStateV1,
    ) -> PrivateOramActivationAuthorityBundleV1 {
        let mut manifest = current.manifest().clone();
        manifest.registry_generation += 1;
        manifest.parent_manifest_digest = Some(current.manifest_digest().to_string());
        manifest.required_binary_capability_digest =
            digest(u8::try_from(manifest.registry_generation + 1).unwrap());
        if manifest.peers.iter().all(|peer| peer.peer_id != 17) {
            manifest.peers.push(peer(17, 23));
        }
        package_private_oram_activation_authority_manifest_v1(key_pair, 1, manifest).unwrap()
    }

    #[test]
    fn genesis_requires_empty_state_and_yields_current_at_read_snapshot() {
        let (_, trust_anchor, bundle) = genesis();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert!(expected.is_empty());
        let state = plan_private_oram_activation_authority_cas_v1(
            None,
            expected,
            &bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert_eq!(state.registry_generation(), 1);
        let current = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&state),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert_eq!(current.locator().unwrap().registry_generation(), 1);
    }

    #[test]
    fn successor_consumes_exact_same_store_observation() {
        let (key_pair, trust_anchor, bundle) = genesis();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let empty = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let current = plan_private_oram_activation_authority_cas_v1(
            None,
            empty,
            &bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let stale = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&current),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&current),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let next_bundle = successor(&key_pair, &current);
        let next = plan_private_oram_activation_authority_cas_v1(
            Some(&current),
            expected,
            &next_bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert_eq!(next.registry_generation(), 2);
        assert_eq!(
            plan_private_oram_activation_authority_cas_v1(
                Some(&next),
                stale,
                &next_bundle,
                &trust_anchor,
                store_instance_id,
            )
            .unwrap_err(),
            PrivateOramActivationAuthorityStateError::PreconditionFailed,
        );

        let foreign_store = PrivateOramActivationAuthorityStoreInstanceId::default();
        let foreign_expected = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&next),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert_eq!(
            plan_private_oram_activation_authority_cas_v1(
                Some(&next),
                foreign_expected,
                &successor(&key_pair, &next),
                &trust_anchor,
                foreign_store,
            )
            .unwrap_err(),
            PrivateOramActivationAuthorityStateError::PreconditionFailed,
        );
    }

    #[test]
    fn capability_upgrade_evidence_requires_the_exact_signed_predecessor() {
        let (key_pair, trust_anchor, bundle) = genesis();
        let verified = validate_private_oram_activation_authority_bundle_v1(
            &bundle,
            &trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Genesis,
        )
        .unwrap();
        let current = PrivateOramActivationAuthorityStateV1::from_verified(&verified);
        assert!(
            serde_json::to_value(&current)
                .unwrap()
                .get("capability_upgrade")
                .is_none()
        );
        let successor = successor(&key_pair, &current);
        let verified = validate_private_oram_activation_authority_transition_v1(
            &verified,
            &successor,
            &trust_anchor,
        )
        .unwrap();
        let mut next = PrivateOramActivationAuthorityStateV1::from_verified(&verified);
        next.retain_capability_upgrade_predecessor(&current, &digest(80));
        verify_private_oram_activation_authority_state_v1(&next, &trust_anchor).unwrap();
        validate_private_oram_activation_authority_snapshot_transition_v1(
            Some(&current),
            Some(&next),
            &trust_anchor,
        )
        .unwrap();
        assert!(next.capability_upgrade_matches_floor(&digest(80), &digest(2)));
        assert!(!next.capability_upgrade_matches_floor(&digest(81), &digest(2)));
        assert!(!next.capability_upgrade_matches_floor(&digest(80), &digest(3)));

        let mut bad_signature = next.clone();
        bad_signature
            .capability_upgrade
            .as_mut()
            .unwrap()
            .predecessor
            .signature
            .sig = BASE64URL_NOPAD.encode(&[91; 64]);
        let mut wrong_parent = next.clone();
        let mut other_manifest = bundle.manifest.clone();
        other_manifest.required_binary_capability_digest = digest(81);
        wrong_parent
            .capability_upgrade
            .as_mut()
            .unwrap()
            .predecessor =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, other_manifest)
                .unwrap();
        for invalid in [bad_signature, wrong_parent] {
            assert!(
                verify_private_oram_activation_authority_state_v1(&invalid, &trust_anchor).is_err()
            );
            assert!(
                validate_private_oram_activation_authority_snapshot_transition_v1(
                    Some(&current),
                    Some(&invalid),
                    &trust_anchor,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn current_at_read_rejects_wrong_external_trust_anchor() {
        let (_, trust_anchor, bundle) = genesis();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let state = plan_private_oram_activation_authority_cas_v1(
            None,
            expected,
            &bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let other_key = key_pair(42);
        let other_authority: PrivateOramActivationAuthorityPublicKeyV1 =
            private_oram_activation_authority_public_key_v1(&other_key, 1).unwrap();
        let wrong_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                other_authority,
                trust_anchor.cluster_identity_digest().to_string(),
                trust_anchor.cluster_first_voter_peer_id(),
            )
            .unwrap();
        assert_eq!(
            verify_private_oram_activation_authority_current_at_read_v1(
                Some(&state),
                &wrong_anchor,
                store_instance_id,
            )
            .unwrap_err(),
            PrivateOramActivationAuthorityStateError::InvalidPersistedState,
        );
    }

    #[test]
    fn empty_current_at_read_is_bound_to_the_observed_trust_anchor() {
        let (_, trust_anchor, bundle) = genesis();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();

        let other_key = key_pair(42);
        let other_authority =
            private_oram_activation_authority_public_key_v1(&other_key, 1).unwrap();
        let mut other_manifest = bundle.manifest.clone();
        other_manifest.authority_key_epoch = other_authority.key_epoch;
        other_manifest.authority_key_id = other_authority.key_id.clone();
        let other_bundle = package_private_oram_activation_authority_manifest_v1(
            &other_key,
            other_authority.key_epoch,
            other_manifest,
        )
        .unwrap();
        let other_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                other_authority,
                trust_anchor.cluster_identity_digest().to_string(),
                trust_anchor.cluster_first_voter_peer_id(),
            )
            .unwrap();

        assert_eq!(
            plan_private_oram_activation_authority_cas_v1(
                None,
                expected,
                &other_bundle,
                &other_anchor,
                store_instance_id,
            ),
            Err(PrivateOramActivationAuthorityStateError::PreconditionFailed),
        );
    }

    #[test]
    fn snapshot_transition_rejects_removal_rollback_and_same_generation_fork() {
        let (key_pair, trust_anchor, bundle) = genesis();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let empty = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let current = plan_private_oram_activation_authority_cas_v1(
            None,
            empty,
            &bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&current),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let next = plan_private_oram_activation_authority_cas_v1(
            Some(&current),
            expected,
            &successor(&key_pair, &current),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();

        let mut removed_manifest = next.manifest().clone();
        removed_manifest.peers.retain(|peer| peer.peer_id != 13);
        let removed_bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, removed_manifest)
                .unwrap();
        let removed = PrivateOramActivationAuthorityStateV1 {
            version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_STATE_VERSION,
            manifest_digest: private_oram_activation_authority_manifest_digest_v1(
                &removed_bundle.manifest,
            )
            .unwrap(),
            bundle: removed_bundle,
            capability_upgrade: None,
        };
        assert_eq!(
            validate_private_oram_activation_authority_snapshot_transition_v1(
                Some(&current),
                Some(&removed),
                &trust_anchor,
            ),
            Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
        );

        let mut invalid_signature = next.clone();
        invalid_signature.bundle.signature.sig = BASE64URL_NOPAD.encode(&[91; 64]);
        assert_eq!(
            validate_private_oram_activation_authority_snapshot_transition_v1(
                Some(&current),
                Some(&invalid_signature),
                &trust_anchor,
            ),
            Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
        );
        assert_eq!(
            validate_private_oram_activation_authority_snapshot_transition_v1(
                None,
                Some(&next),
                &trust_anchor,
            ),
            Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
        );

        validate_private_oram_activation_authority_snapshot_transition_v1(
            Some(&current),
            Some(&next),
            &trust_anchor,
        )
        .unwrap();
        for incoming in [None, Some(&current)] {
            assert_eq!(
                validate_private_oram_activation_authority_snapshot_transition_v1(
                    Some(&next),
                    incoming,
                    &trust_anchor,
                ),
                Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
            );
        }

        let mut fork = current.clone();
        fork.manifest_digest = digest(88);
        assert!(
            validate_private_oram_activation_authority_snapshot_transition_v1(
                Some(&current),
                Some(&fork),
                &trust_anchor,
            )
            .is_err()
        );

        let next_expected = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&next),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let skipped = plan_private_oram_activation_authority_cas_v1(
            Some(&next),
            next_expected,
            &successor(&key_pair, &next),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_snapshot_transition_v1(
                Some(&current),
                Some(&skipped),
                &trust_anchor,
            ),
            Err(PrivateOramActivationAuthorityStateError::InvalidSnapshotTransition),
        );
    }

    #[test]
    fn authority_state_debug_redacts_signed_material() {
        let (_, trust_anchor, bundle) = genesis();
        let signature = bundle.signature.sig.clone();
        let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
        let expected = verify_private_oram_activation_authority_current_at_read_v1(
            None,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let state = plan_private_oram_activation_authority_cas_v1(
            None,
            expected,
            &bundle,
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let current = verify_private_oram_activation_authority_current_at_read_v1(
            Some(&state),
            &trust_anchor,
            store_instance_id,
        )
        .unwrap();
        let rendered = format!("{state:?} {current:?}");
        assert!(!rendered.contains(&signature));
        assert!(!rendered.contains(state.manifest_digest()));
    }
}

//! Who may attest a portable authority checkpoint (OF-469, checkpoint v2): the
//! eligible roots and the quorum they must reach. The image commits the policy
//! it was built under; a joining device takes the policy from its pairing pin,
//! never from the image it received.
//!
//! Managed mode requires the managed host root. Relay and self-host use
//! owner-root keys: the sole root when only one is eligible, else at least two
//! distinct roots. Workers, agents and capability holders never vote, and
//! several software keys never stand in for a hardware root.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::*;
use crate::error::Result;
use crate::{HostingPrivacyPosture, Vault};

/// Distinct roots a checkpoint needs once two or more roots are eligible.
pub const CHECKPOINT_MULTI_ROOT_QUORUM: usize = 2;
/// A configured quorum floor above the canon minimum; 0 configures none.
pub const CHECKPOINT_CONFIGURED_QUORUM: usize = 0;
/// When any eligible root is hardware-backed, one attesting root must be.
pub const CHECKPOINT_HARDWARE_WHEN_ELIGIBLE: bool = true;

/// The hosting mode a checkpoint policy was fixed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointPosture {
    Managed,
    Relay,
    SelfHost,
}

impl From<HostingPrivacyPosture> for CheckpointPosture {
    fn from(posture: HostingPrivacyPosture) -> Self {
        match posture {
            HostingPrivacyPosture::Hosted => Self::Managed,
            HostingPrivacyPosture::Relay => Self::Relay,
            HostingPrivacyPosture::SelfHostLocal => Self::SelfHost,
        }
    }
}

/// One eligible root.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRoot {
    pub key: AuthorityKey,
    pub tier: AuthorityTier,
    /// The managed host root, which managed mode requires.
    pub host: bool,
}

/// The eligible roots of one vault and the quorum a checkpoint needs from them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRootPolicy {
    pub posture: CheckpointPosture,
    /// Ascending by key, one row per root.
    pub roots: Vec<CheckpointRoot>,
    /// Distinct eligible roots that must attest.
    pub quorum: u8,
    /// One attesting root must be hardware-backed.
    pub hardware: bool,
}

fn host_root(device: &FoldedDevice) -> bool {
    !device.revoked
        && device.roles & ROLE_OWNER != 0
        && device.roles & ROLE_CLOUD != 0
        && device.tier == AuthorityTier::CloudCustodial
}

fn owner_root(device: &FoldedDevice) -> bool {
    device.roles & ROLE_OWNER != 0 && folded_device_can_authority_consent(device)
}

impl CheckpointRootPolicy {
    /// The policy a roster fixes under `posture`, with `configured` as a
    /// stricter quorum floor (0 for none). Refused when no root is eligible or
    /// the floor exceeds the eligible roots.
    pub fn from_roster(
        roster: &BTreeMap<AuthorityKey, FoldedDevice>,
        posture: HostingPrivacyPosture,
        configured: usize,
    ) -> Result<Self> {
        let posture = CheckpointPosture::from(posture);
        let managed = posture == CheckpointPosture::Managed;
        let roots: Vec<CheckpointRoot> = roster
            .values()
            .filter(|device| {
                if managed {
                    host_root(device)
                } else {
                    owner_root(device)
                }
            })
            .map(|device| CheckpointRoot {
                key: device.key.clone(),
                tier: device.tier,
                host: managed,
            })
            .collect();
        let canon = match roots.len() {
            0 => return Err(invalid_authority()),
            1 => 1,
            _ if managed => 1,
            _ => CHECKPOINT_MULTI_ROOT_QUORUM,
        };
        let quorum = canon.max(configured);
        if quorum > roots.len() {
            return Err(invalid_authority());
        }
        Ok(Self {
            posture,
            hardware: CHECKPOINT_HARDWARE_WHEN_ELIGIBLE
                && roots
                    .iter()
                    .any(|root| root.tier == AuthorityTier::Hardware),
            quorum: u8::try_from(quorum).map_err(|_| invalid_authority())?,
            roots,
        })
    }

    /// The root `key` names, when it is eligible.
    pub fn root(&self, key: &AuthorityKey) -> Option<&CheckpointRoot> {
        self.roots.iter().find(|root| &root.key == key)
    }

    /// Whether distinct eligible roots `attested` reach this quorum: enough of
    /// them, the host root in managed mode, and a hardware root when required.
    pub fn admits(&self, attested: &BTreeSet<AuthorityKey>) -> bool {
        let voters: Vec<&CheckpointRoot> = self
            .roots
            .iter()
            .filter(|root| attested.contains(&root.key))
            .collect();
        voters.len() >= usize::from(self.quorum)
            && (self.posture != CheckpointPosture::Managed || voters.iter().any(|root| root.host))
            && (!self.hardware
                || voters
                    .iter()
                    .any(|root| root.tier == AuthorityTier::Hardware))
    }

    /// Canonical bytes: the roots ascending and unique, and a quorum they can meet.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.roots.is_empty()
            || self.quorum == 0
            || usize::from(self.quorum) > self.roots.len()
            || self.roots.windows(2).any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(invalid_authority());
        }
        rmp_serde::to_vec_named(self).map_err(|_| invalid_authority())
    }

    /// The digest a pin or image names this policy by.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(blake3::derive_key(
            "oneiron/authority/checkpoint-policy/v1",
            &self.canonical_bytes()?,
        ))
    }
}

impl Vault {
    /// The checkpoint root policy this vault's own fold fixes, read in `txn`.
    pub fn checkpoint_root_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<CheckpointRootPolicy> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        CheckpointRootPolicy::from_roster(
            &fold.roster,
            self.privacy_posture(),
            CHECKPOINT_CONFIGURED_QUORUM,
        )
    }
}

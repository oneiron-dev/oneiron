//! Who may attest a portable authority checkpoint (OF-469, checkpoint v2): the
//! eligible roots and the quorum they must reach. The image commits the policy
//! it was built under; a joining device takes the policy from its pairing pin,
//! never from the image it received.
//!
//! Managed mode requires the managed host root. Relay and self-host use
//! owner-root keys: one root while one or two are eligible, and two distinct
//! roots from three on (owner ruling 10-19, CHECKPOINT QUORUM = C; FIX 4936).
//! Workers, agents and capability holders never vote, and several software
//! keys never stand in for a hardware root.
//!
//! The owner may select the roots and quorum himself, on any host, Hosted
//! included (mesh PR2c, §A 06, K06): a main-log choice carrying his act
//! ([`CheckpointPolicySet`], folded by `checkpoint_choice`). While a choice of
//! his counts, it is the policy in force; the posture's policy is the
//! default when none does. A selected policy drops only the host-voter
//! requirement: eligibility, the multi-root quorum, the configured floor,
//! canonical order and hardware-when-eligible all stay. Each refusal names
//! its rule ([`RecordError::CheckpointPolicyRefused`]).
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::*;
use crate::error::{Error, RecordError, Result};
use crate::{HostingPrivacyPosture, Vault};

/// The most eligible roots one root's signature still attests for (FIX 4936:
/// one signature at one or two roots).
pub const CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS: usize = 2;
/// Distinct roots a checkpoint needs once more than
/// [`CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS`] roots are eligible.
pub const CHECKPOINT_MULTI_ROOT_QUORUM: usize = 2;
/// A configured quorum floor above the canon minimum; 0 configures none.
pub const CHECKPOINT_CONFIGURED_QUORUM: usize = 0;
/// When any eligible root is hardware-backed, one attesting root must be.
pub const CHECKPOINT_HARDWARE_WHEN_ELIGIBLE: bool = true;

/// Integrity: the roster holds no root the policy may name.
const NO_ELIGIBLE_ROOTS: &str = "checkpoint policy has no eligible authorized roots";
/// Integrity: the quorum is more distinct roots than the policy names.
const QUORUM_EXCEEDS_ROOTS: &str = "checkpoint policy quorum exceeds eligible roots";
/// Integrity: an owner's choice of several roots needs the multi-root
/// quorum, and every choice the configured floor.
const QUORUM_BELOW_FLOOR: &str = "checkpoint policy quorum is below the floor its roots need";
/// Integrity: roots unsorted or repeated, or a zero or impossible quorum.
const NOT_CANONICAL: &str = "checkpoint policy roots/quorum are not canonical";
/// Authority: the owner named a key the roster does not hold as an eligible
/// root (a live owner root, or the managed host root on a hosted vault).
const ROOT_NOT_ELIGIBLE: &str = "checkpoint policy names a key that is not an eligible root";
/// Integrity: a hardware requirement no chosen root can meet.
const HARDWARE_UNNAMED: &str = "checkpoint policy requires a hardware root it does not name";

/// A checkpoint policy refusal naming its rule.
pub(super) fn policy_refused(reason: &'static str) -> Error {
    Error::Record(RecordError::CheckpointPolicyRefused(reason))
}

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
    /// The owner selected these roots and this quorum (mesh PR2c): no host
    /// root need attest. A posture policy's bytes omit it, so its digest is
    /// what it was.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_selected: bool,
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

/// Policy hook (CALLS "mesh PR2c selectable roots"): the roots an owner's
/// choice may name. A live owner root on any host, and on a hosted vault the
/// managed host root as well, the one root its posture policy names today.
pub(super) fn selectable_root(device: &FoldedDevice, managed: bool) -> bool {
    owner_root(device) || (managed && host_root(device))
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
            0 => return Err(policy_refused(NO_ELIGIBLE_ROOTS)),
            n if n <= CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS => 1,
            _ if managed => 1,
            _ => CHECKPOINT_MULTI_ROOT_QUORUM,
        };
        let quorum = canon.max(configured);
        if quorum > roots.len() {
            return Err(policy_refused(QUORUM_EXCEEDS_ROOTS));
        }
        Ok(Self {
            posture,
            hardware: CHECKPOINT_HARDWARE_WHEN_ELIGIBLE
                && roots
                    .iter()
                    .any(|root| root.tier == AuthorityTier::Hardware),
            quorum: u8::try_from(quorum).map_err(|_| policy_refused(NOT_CANONICAL))?,
            roots,
            owner_selected: false,
        })
    }

    /// The policy the owner's `choice` fixes on `roster` under `posture`
    /// (mesh PR2c), with `configured` as a quorum floor (0 for none). Each
    /// chosen key the roster no longer holds as a selectable root drops out
    /// (CALLS "mesh PR2c selectable roots"), and the rest must still meet the
    /// quorum: there is no silent fallback to the posture's policy. More than
    /// [`CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS`] roots need the multi-root
    /// quorum on every host, the host-voter rule's managed exception included,
    /// since an owner's choice has no host voter.
    pub fn from_choice(
        roster: &BTreeMap<AuthorityKey, FoldedDevice>,
        posture: HostingPrivacyPosture,
        choice: &CheckpointRootChoice,
        configured: usize,
    ) -> Result<Self> {
        choice
            .validate()
            .map_err(|_| policy_refused(NOT_CANONICAL))?;
        let posture = CheckpointPosture::from(posture);
        let managed = posture == CheckpointPosture::Managed;
        let roots: Vec<CheckpointRoot> = choice
            .roots
            .iter()
            .filter_map(|key| roster.get(key))
            .filter(|device| selectable_root(device, managed))
            .map(|device| CheckpointRoot {
                key: device.key.clone(),
                tier: device.tier,
                host: host_root(device),
            })
            .collect();
        let canon = match roots.len() {
            0 => return Err(policy_refused(NO_ELIGIBLE_ROOTS)),
            n if n <= CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS => 1,
            _ => CHECKPOINT_MULTI_ROOT_QUORUM,
        };
        let quorum = usize::from(choice.quorum);
        if quorum > roots.len() {
            return Err(policy_refused(QUORUM_EXCEEDS_ROOTS));
        }
        if quorum < canon.max(configured) {
            return Err(policy_refused(QUORUM_BELOW_FLOOR));
        }
        let hardware_named = roots
            .iter()
            .any(|root| root.tier == AuthorityTier::Hardware);
        if choice.hardware && !hardware_named {
            return Err(policy_refused(HARDWARE_UNNAMED));
        }
        Ok(Self {
            posture,
            hardware: choice.hardware || (CHECKPOINT_HARDWARE_WHEN_ELIGIBLE && hardware_named),
            quorum: choice.quorum,
            roots,
            owner_selected: true,
        })
    }

    /// [`Self::from_choice`] at the writer, which refuses a choice that names
    /// any key that is not a selectable root now, rather than dropping it.
    pub(super) fn from_choice_exactly(
        roster: &BTreeMap<AuthorityKey, FoldedDevice>,
        posture: HostingPrivacyPosture,
        choice: &CheckpointRootChoice,
    ) -> Result<Self> {
        let policy = Self::from_choice(roster, posture, choice, CHECKPOINT_CONFIGURED_QUORUM)?;
        if policy.roots.len() != choice.roots.len() {
            return Err(policy_refused(ROOT_NOT_ELIGIBLE));
        }
        Ok(policy)
    }

    /// The root `key` names, when it is eligible.
    pub fn root(&self, key: &AuthorityKey) -> Option<&CheckpointRoot> {
        self.roots.iter().find(|root| &root.key == key)
    }

    /// Whether distinct eligible roots `attested` reach this quorum: enough of
    /// them, the host root in managed mode unless the owner selected the
    /// policy, and a hardware root when required.
    pub fn admits(&self, attested: &BTreeSet<AuthorityKey>) -> bool {
        self.shortfall(attested).is_none()
    }

    /// What `attested` lacks to reach this policy, named; `None` when it
    /// reaches it.
    pub fn shortfall(&self, attested: &BTreeSet<AuthorityKey>) -> Option<&'static str> {
        let voters: Vec<&CheckpointRoot> = self
            .roots
            .iter()
            .filter(|root| attested.contains(&root.key))
            .collect();
        if voters.len() < usize::from(self.quorum) {
            return Some("checkpoint attestations lack the pinned quorum");
        }
        if self.posture == CheckpointPosture::Managed
            && !self.owner_selected
            && !voters.iter().any(|root| root.host)
        {
            return Some("checkpoint attestations lack the managed host root");
        }
        if self.hardware
            && !voters
                .iter()
                .any(|root| root.tier == AuthorityTier::Hardware)
        {
            return Some("checkpoint attestations lack the required hardware root");
        }
        None
    }

    /// Canonical bytes: the roots ascending and unique, and a quorum they can meet.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.roots.is_empty()
            || self.quorum == 0
            || usize::from(self.quorum) > self.roots.len()
            || self.roots.windows(2).any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(policy_refused(NOT_CANONICAL));
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

/// The checkpoint root policy in force in `fold` under `posture`, on any
/// host: the owner's selected roots and quorum while a choice of his counts
/// there, else the policy the posture fixes (mesh PR2c). Image building,
/// the adopted build, attestation and the pairing pin all read this one
/// function, so none re-derives the posture's policy past his choice.
pub(super) fn checkpoint_root_policy_of(
    fold: &AuthorityFold,
    posture: HostingPrivacyPosture,
) -> Result<CheckpointRootPolicy> {
    match fold.checkpoint_policy.selected() {
        Some(choice) => CheckpointRootPolicy::from_choice(
            &fold.roster,
            posture,
            choice,
            CHECKPOINT_CONFIGURED_QUORUM,
        ),
        None => {
            CheckpointRootPolicy::from_roster(&fold.roster, posture, CHECKPOINT_CONFIGURED_QUORUM)
        }
    }
}

impl Vault {
    /// The checkpoint root policy in force in this vault's own fold, read in
    /// `txn`: the owner's choice when one counts, else the posture's.
    pub fn checkpoint_root_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<CheckpointRootPolicy> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        checkpoint_root_policy_of(&fold, self.privacy_posture())
    }

    /// Whether `root` is an eligible root of the policy in force. A policy
    /// the roster cannot fix refuses, naming its rule.
    pub fn checkpoint_root_eligible(&self, root: &AuthorityKey) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .checkpoint_root_policy_in_txn(&txn)?
            .root(root)
            .is_some())
    }
}

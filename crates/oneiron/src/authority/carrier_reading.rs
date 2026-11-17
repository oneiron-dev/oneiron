//! Who carried a signed act, as this install's own records read the key
//! that signed it (FIX [CARRIED-PIN-ASKER-UNSERVED]; the lead's
//! CARRIED-PIN-PROMPT-HOSTED-CARRIER = A: a surface names a carrier from
//! the target's own records, never from the act's own words).
//!
//! An act names its carrier by machine id, and its entry is signed by one
//! install key. The fold admits the entry when some chain of that machine
//! names the key, a chain of an anchor this install does not pin among
//! them, and an anchor's mark names any machine id under any keys that
//! prove themselves. So the id alone says nothing a surface may show the
//! owner. A reading starts from the signing key: the machine is the owner's
//! here only when that key is the machine key of the identity this install
//! trusts for it ([`AuthorityFold::trusted_machine`]): the rule of
//! [`AuthorityFold::mine_machine_by_key`] for one named machine, and the one
//! the fold's own gate applies to a carried answer.

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The machine an act names as its carrier, as this install reads the key
/// that signed the act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierReading {
    /// The machine the act names as its carrier.
    pub machine: EntityId,
    /// The role this install's records give the signing key on that
    /// machine: the trusted identity's when the key is its machine key,
    /// else the roster head's when the roster's head names the key. `None`
    /// when neither does (the key stands only under a chain this install
    /// does not read), and when the act's row is not stored here.
    pub role: Option<MachineRole>,
    /// Whether the signing key is the machine key of the identity this
    /// install trusts as the owner's machine. Never true on the id alone.
    pub is_mine: bool,
}

impl CarrierReading {
    /// The reading of a carrier whose signing key this install cannot read.
    fn unread(machine: EntityId) -> Self {
        Self {
            machine,
            role: None,
            is_mine: false,
        }
    }
}

impl AuthorityFold {
    /// This install's reading of `machine` as the carrier of an act that
    /// `signer` signed.
    #[must_use]
    pub fn carrier_reading(&self, machine: EntityId, signer: &AuthorityKey) -> CarrierReading {
        let signed =
            |profile: &MachineProfile| AuthorityKey::Ed25519(profile.machine_key) == *signer;
        let trusted = self
            .trusted_machine(machine)
            .filter(|trusted| signed(trusted.profile));
        let roster = self
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .filter(|head| signed(&head.profile));
        CarrierReading {
            machine,
            role: trusted
                .map(|trusted| trusted.profile.role)
                .or_else(|| roster.map(|head| head.profile.role)),
            is_mine: trusted.is_some(),
        }
    }
}

impl Vault {
    /// [`AuthorityFold::carrier_reading`] of `machine` for the act stored
    /// as entry `act`, read in `txn`, the snapshot `fold` was read in. An
    /// act whose row this vault does not store (an adopted checkpoint image
    /// covers it) has no key to read here: no role, and not mine.
    pub(crate) fn stored_carrier_reading_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        machine: EntityId,
        act: &AuthorityEntryHash,
    ) -> Result<CarrierReading> {
        Ok(match super::stored_authority_row(&self.store, txn, act)? {
            Some(entry) => fold.carrier_reading(machine, entry.signer_key()),
            None => CarrierReading::unread(machine),
        })
    }
}

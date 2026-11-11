//! Door for `tests/check_in_pending_handle.rs` and `tests/check_in_rung_waits.rs`
//! (ROLES-CHECKIN P2.2, pieces 2b and 2d): the pending check-in's doors, each
//! in one write transaction at the vault's store clock, read once. The chain
//! is the test's: each rung's holders as the test names them, where 2c names
//! them from verified records.

use std::collections::BTreeMap;

use crate::check_in::{
    CheckInTransition, HolderAnswer, OpenPendingCheckIn, PendingCheckIn, Rung, RungMembers,
    RungResolver, advance_pending_check_in_in_txn, answer_pending_check_in_in_txn,
    extend_pending_check_in_in_txn, open_pending_check_in_in_txn, record_objection_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::store::Store;
use crate::{EntityId, Vault};

/// A chain the test names: each rung's members. A rung it does not name is
/// missing, with the link "not in the test chain".
#[derive(Clone, Debug, Default)]
pub struct FixedChain {
    rungs: BTreeMap<Rung, RungMembers>,
}

impl FixedChain {
    /// This chain, with `rung`'s members.
    #[must_use]
    pub fn with(mut self, rung: Rung, members: RungMembers) -> Self {
        self.rungs.insert(rung, members);
        self
    }
}

impl RungResolver for FixedChain {
    fn members(
        &self,
        _store: &Store,
        _txn: &heed::RoTxn<'_>,
        _pending: &PendingCheckIn,
        rung: Rung,
    ) -> Result<RungMembers> {
        Ok(self
            .rungs
            .get(&rung)
            .cloned()
            .unwrap_or_else(|| RungMembers::Missing("not in the test chain".to_owned())))
    }
}

/// Opens a pending check-in for `request` on `chain`.
///
/// # Errors
///
/// As `open_pending_check_in_in_txn`.
pub fn open(
    vault: &Vault,
    request: OpenPendingCheckIn,
    chain: &FixedChain,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        open_pending_check_in_in_txn(vault, txn, request, chain, now)
    })
}

/// Makes the one transition due now for `id` on `chain`.
///
/// # Errors
///
/// As `advance_pending_check_in_in_txn`.
pub fn advance(
    vault: &Vault,
    id: &EntityId,
    chain: &FixedChain,
) -> Result<Option<CheckInTransition>> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        advance_pending_check_in_in_txn(vault, txn, id, chain, now)
    })
}

/// `person`'s answer to `id` over `effect_digest`.
///
/// # Errors
///
/// As `answer_pending_check_in_in_txn`.
pub fn answer(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    effect_digest: &[u8; 32],
    answer: HolderAnswer,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        answer_pending_check_in_in_txn(vault, txn, person, id, effect_digest, answer, now)
    })
}

/// `person`'s "give me until `until`" on `id`'s current rung.
///
/// # Errors
///
/// As `extend_pending_check_in_in_txn`.
pub fn extend(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    until: u64,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        extend_pending_check_in_in_txn(vault, txn, person, id, until, now)
    })
}

/// An objection by `by` to `id`'s delay window, as canon's PR 4 producer
/// would admit it.
///
/// # Errors
///
/// As `record_objection_in_txn`.
pub fn object(vault: &Vault, id: &EntityId, by: EntityId) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        record_objection_in_txn(&vault.store, txn, id, by, now)
    })
}

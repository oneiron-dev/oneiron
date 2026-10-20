//! Engine authorship of booking lifecycle heads (FIX 5994).
//!
//! The booking process stamps every head it writes with its own row birth,
//! in the transaction that writes the head, and a lifecycle read counts a
//! head only when that process issued it: an `Observed` head born of it. A
//! head another door wrote carries that door's birth or its write envelope,
//! and is ignored, never fatal. An `Observed` head with neither is one this
//! process wrote before it stamped births (no migration backfills them), so
//! it still counts and every booking made before keeps its doors.

use sha2::{Digest, Sha256};

use super::claim::is_booking_lifecycle_claim_predicate;
use crate::claim::{ClaimBody, ClaimSource};
use crate::entity_id::EntityId;
use crate::provenance::birth::{RowBirth, row_birth_in_txn, stamp_row_birth_in_txn};
use crate::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use crate::vault::Vault;

/// FIX 5994: lifecycle reads count only the heads the booking process
/// issued. `false` reads every surfaceable head, as before.
const BOOKING_REQUIRE_ENGINE_HEADS: bool = true;

/// The process identity on every head the booking engine writes.
const BOOKING_PROCESS: &str = "booking.lifecycle";

/// Stamps `claim`, a head the booking process just wrote in `wtxn`, as born
/// of that process. The engine records a fact it witnessed, so the birth is
/// stated, as the head's `Observed` source reads.
pub(super) fn stamp_engine_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
    at: u64,
) -> crate::Result<()> {
    let birth = RowBirth::stated(MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: crate::vault::embedded_owner_actor_id()?,
            class: MadeByClass::Stated,
            identity: BOOKING_PROCESS.to_owned(),
            version: "1".to_owned(),
            params_hash: format!("{:x}", Sha256::digest([])),
        },
        at,
        trigger: None,
    });
    stamp_row_birth_in_txn(&vault.store, wtxn, claim, &birth)
}

/// Whether `body`, a surfaceable claim about a booking, counts on a lifecycle
/// read: a claim outside the lifecycle family always does; a lifecycle head
/// does when it is `Observed` and the booking process issued it.
pub(in crate::booking) fn counts_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    claim: &EntityId,
    body: &ClaimBody,
) -> crate::Result<bool> {
    if !BOOKING_REQUIRE_ENGINE_HEADS || !is_booking_lifecycle_claim_predicate(&body.predicate) {
        return Ok(true);
    }
    if body.source != Some(ClaimSource::Observed) {
        return Ok(false);
    }
    Ok(match row_birth_in_txn(&vault.store, rtxn, claim)? {
        Some(birth) => birth.made_by.process.identity == BOOKING_PROCESS,
        None => body.evidence.is_none(),
    })
}

//! FIX 6740 (Engine 10-21 01:0x): the owner reads the failure-signal batch
//! the vault carries, beside the press that releases it
//! (`vault.consent.approve_once` / `vault.consent.deny`), so he approves
//! exactly what he saw (CALLS `FIX 6740 held batch owner read`). The read
//! answers the custody row's body byte for byte and the approve-once digest
//! the carried send's press names, composed by the same composer the carry,
//! the Gate's lookup and its spend use; nothing is parsed, capped, cut or
//! held back (CALLS `FIX 6740 view shape`). It writes nothing and runs no
//! carry, retirement, settlement, staging or selection: what it answers is a
//! snapshot, never a reservation, and the next pass decides the batch as it
//! always does (CALLS `FIX 6740 empty and broken states`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{HELD, HeldBatch, HeldStage};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::failure_signals::FAILURE_SIGNALS_CHANNEL;
use crate::failure_signals::delivery::batch_request;
use crate::memory::{MemoryResult, facade_error_from_outbound_dispatch};
use crate::outbound::{connector_actor_id, outbound_approve_once_digest};
use crate::{EntityId, Vault};

/// A custody row whose body no longer hashes to its digest.
const BODY_NOT_INTACT: &str = "the held failure-signal batch no longer matches its digest";
/// A carried batch whose send names no approve-once digest.
const NO_APPROVAL_DIGEST: &str = "the held failure-signal batch names no approve-once digest";
/// Frozen quantities whose sum does not fit.
const SIGNAL_COUNT_OVERFLOW: &str = "the held failure-signal batch's quantities overflow";

/// The failure-signal batch the vault carries, as its owner reads it before
/// he presses (FIX 6740; CALLS `FIX 6740 view shape`). `content` is the
/// batch exactly as it was first serialized and is sent, and
/// `approval_digest` the one value `vault.consent.approve_once` or
/// `vault.consent.deny` takes for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HeldFailureSignalBatchView {
    /// Its random id.
    pub batch_id: String,
    /// The publisher endpoint it was built for, and is sent to.
    pub endpoint: String,
    /// The send ref every send of it carries: `failure_signals:batch:{batch_id}`.
    pub send_ref: String,
    /// Its content ref: `failure_signals:digest:{content_digest}`.
    pub content_ref: String,
    /// The batch JSON, the exact UTF-8 the publisher receives.
    pub content: String,
    /// Lowercase hex BLAKE3 of `content`'s bytes.
    pub content_digest: String,
    /// The approve-once digest the owner's press on it names, 64 lower-hex.
    pub approval_digest: String,
    /// The aggregate count rows it froze.
    pub count_rows: u64,
    /// The sum of the quantities those rows froze.
    pub signal_count: u64,
    /// The code-fix records it carries.
    pub code_fix_records: u64,
    /// Whether the deployment let the publisher train on it when it was
    /// built.
    pub training_permitted: bool,
    /// Seconds since the epoch.
    pub created_at: u64,
    /// Where its custody stood after its last send: `staged`, `held` or
    /// `admitted`. A record only, never proof the owner is still awaited.
    pub custody_stage: String,
}

impl Vault {
    /// `vault.consent.failure_signals_held`: the batch this vault carries,
    /// read under `owner`'s proof, revalidated in the snapshot it is read
    /// from, beside the worlds its code-fix records touched, by which every
    /// served door releases it (CALLS `FIX 6740 release scans`). `None` when
    /// no batch is carried, or an actor erase kept only its frozen shares. It
    /// writes nothing, and a later pass may settle, retire or erase it.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; a custody row that does not decode, or
    /// whose body no longer hashes to its digest; the composer's own
    /// refusal; a storage failure. None of these is repaired here.
    pub fn held_failure_signal_batch(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<(Option<HeldFailureSignalBatchView>, Vec<EntityId>)> {
        let Some(held) = held_as_owner(self, owner)? else {
            return Ok((None, Vec::new()));
        };
        let sender = connector_actor_id(FAILURE_SIGNALS_CHANNEL)?;
        let request = batch_request(sender, &held, held.created_at);
        let approval_digest = outbound_approve_once_digest(self, &request)
            .map_err(facade_error_from_outbound_dispatch)?
            .ok_or(Error::InvariantViolation(NO_APPROVAL_DIGEST))?
            .to_hex();
        let signal_count = held
            .counts
            .iter()
            .try_fold(0_u64, |sum, (_, quantity)| sum.checked_add(*quantity))
            .ok_or(Error::InvariantViolation(SIGNAL_COUNT_OVERFLOW))?;
        let worlds = code_fix_worlds(&held);
        let view = HeldFailureSignalBatchView {
            send_ref: held.send_ref(),
            content_ref: held.content_ref(),
            count_rows: held.counts.len() as u64,
            code_fix_records: held.code_fix.len() as u64,
            custody_stage: custody_stage(held.stage).to_owned(),
            batch_id: held.batch_id,
            endpoint: held.endpoint,
            content: held.body,
            content_digest: held.digest,
            approval_digest,
            signal_count,
            training_permitted: held.training_permitted,
            created_at: held.created_at,
        };
        Ok((Some(view), worlds))
    }
}

/// The carried batch, read in one snapshot with `owner`'s proof checked in
/// it; `None` for no row, or for the frozen shares an actor erase keeps
/// (its body and digest both cleared).
fn held_as_owner(vault: &Vault, owner: &AuthenticatedOwner) -> Result<Option<HeldBatch>> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let Some(held) = HELD.get(&vault.store, &txn, &())? else {
        return Ok(None);
    };
    if held.body.is_empty() && held.digest.is_empty() {
        return Ok(None);
    }
    if !held.body_intact() {
        return Err(Error::InvariantViolation(BODY_NOT_INTACT));
    }
    Ok(Some(held))
}

/// Every world `held`'s code-fix records touched, once each: the rows its
/// content derives from, which the read lists beside it.
fn code_fix_worlds(held: &HeldBatch) -> Vec<EntityId> {
    let mut worlds = held
        .code_fix
        .iter()
        .flat_map(|(_, worlds)| worlds.iter().copied())
        .collect::<Vec<_>>();
    worlds.sort_unstable();
    worlds.dedup();
    worlds
}

/// The advisory name of a custody stage.
fn custody_stage(stage: HeldStage) -> &'static str {
    match stage {
        HeldStage::Staged => "staged",
        HeldStage::Held => "held",
        HeldStage::Admitted => "admitted",
    }
}

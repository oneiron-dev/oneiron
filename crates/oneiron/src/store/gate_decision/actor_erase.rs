//! An erased actor out of the Gate decision ledger (FIX 4230, 4231).

use heed::RwTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::ledger::{LEDGER, encode_gate_decision};
use super::orcb;
use super::types::GateDecisionRecord;
use super::vet::vet_gate_decision_record;
use crate::store::Store;
use crate::store::key_custody::LocalCustody;

/// What an actor's erase does with the Gate decisions that name it as the
/// actor they judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAttributionErase {
    /// Each decision stays in place with its id, its time, its outcome, its
    /// reasons, its class, its policy, its grant, its diff and its frontier,
    /// and names no actor.
    ClearActorRefOnly,
}

/// A Gate decision is the receipt of what was decided, so it stays; who
/// asked for it goes with that actor's erase (FIX 4230, 4231; a call).
pub const ACTOR_ERASE_GATE_ATTRIBUTION: GateAttributionErase =
    GateAttributionErase::ClearActorRefOnly;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the ledger.
use crate::deletion::names_no_actor;

/// Erasing `actor` from the Gate decisions (FIX 4230, 4231): each decision
/// whose actor it is names no actor, as [`ACTOR_ERASE_GATE_ATTRIBUTION`]
/// says. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing. A decision whose own partition a legal hold keeps
/// keeps its attribution, and the erase owes it the clear until the hold
/// lifts (FIX 7993): the actor's erase is never refused for it.
///
/// # Errors
///
/// Storage errors, or a decision row that cannot be read.
pub(crate) fn erase_gate_decision_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let at = vault.store.clock.now_recorded_at();
    match ACTOR_ERASE_GATE_ATTRIBUTION {
        GateAttributionErase::ClearActorRefOnly => vault
            .store
            .clear_gate_decision_actor_in_txn(wtxn, actor, at),
    }
}

impl Store {
    /// Clears `actor_ref` in place on every ledger row that names `actor`,
    /// and each read context its writer copied that names it, and nothing
    /// else: the claim skeleton redactor is for an erased claim.
    /// A row goes back as it was stored, plain or sealed to its claim under
    /// the key generation that sealed it. A sealed row whose key was retired
    /// can be read by no one and stays as it is. A row whose own partition,
    /// its claim's or the claim-free one, a legal hold keeps stays whole and
    /// is owed the clear, timed `at`.
    fn clear_gate_decision_actor_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
        at: u64,
    ) -> Result<()> {
        let mut cleared = Vec::new();
        let mut held = Vec::new();
        let custody = self.core.key_custody.local();
        for row in LEDGER.iter_from(self, &*wtxn, &[])? {
            let (decision_id, raw) = row?;
            let mut record = match self.decode_gate_decision_value(decision_id, &raw) {
                Err(error @ Error::CorruptedIndex("gate decision ORCB")) => {
                    if orcb::raw_key_retired(custody, &raw)? {
                        continue;
                    }
                    return Err(error);
                }
                decoded => decoded?,
            };
            if !record.names_actor(actor) {
                continue;
            }
            if self.gate_partition_held_in_txn(&*wtxn, record.claim_id.as_ref())? {
                held.push(decision_id);
                continue;
            }
            record.scrub_actor(actor);
            cleared.push((decision_id, reseal_gate_decision(custody, &raw, &record)?));
        }
        for (decision_id, value) in &cleared {
            LEDGER.put(self, wtxn, decision_id, value)?;
        }
        for decision_id in held {
            self.owe_gate_actor_scrub_in_txn(wtxn, actor, decision_id, at)?;
        }
        Ok(())
    }
}

/// `record` encoded as the row `raw` was stored: plain, or sealed to its
/// claim under the key generation that sealed it.
pub(super) fn reseal_gate_decision(
    custody: Option<LocalCustody<'_>>,
    raw: &[u8],
    record: &GateDecisionRecord,
) -> Result<Vec<u8>> {
    vet_gate_decision_record(record)?;
    match (orcb::raw_claim_generation(raw), custody) {
        (Some((_, generation)), Some(custody)) => orcb::encode_hot_at(custody, record, generation),
        (Some(_), None) => Err(orcb::corrupt()),
        (None, _) => encode_gate_decision(record),
    }
}

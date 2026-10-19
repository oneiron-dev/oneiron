//! An erased actor out of the Gate decision ledger (FIX 4230, 4231).

use heed::RwTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::ledger::{LEDGER, encode_gate_decision};
use super::orcb;
use super::vet::vet_gate_decision_record;
use crate::store::Store;

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
fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the Gate decisions (FIX 4230, 4231): each decision
/// whose actor it is names no actor, as [`ACTOR_ERASE_GATE_ATTRIBUTION`]
/// says. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
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
    match ACTOR_ERASE_GATE_ATTRIBUTION {
        GateAttributionErase::ClearActorRefOnly => vault
            .store
            .clear_gate_decision_actor_in_txn(wtxn, &actor.to_hex()),
    }
}

impl Store {
    /// Clears `actor_ref` in place on every ledger row that names it, and
    /// nothing else: the claim skeleton redactor is for an erased claim. A
    /// row goes back as it was stored, plain or sealed to its claim under
    /// the key generation that sealed it. A sealed row whose key was retired
    /// can be read by no one and stays as it is.
    fn clear_gate_decision_actor_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        actor_ref: &str,
    ) -> Result<()> {
        let mut cleared = Vec::new();
        for row in LEDGER.iter_from(self, &*wtxn, &[])? {
            let (decision_id, raw) = row?;
            let mut record = match self.decode_gate_decision_value(decision_id, &raw) {
                Err(error @ Error::CorruptedIndex("gate decision ORCB")) => {
                    if orcb::raw_key_retired(&self.core.gate_custody_root, &raw)? {
                        continue;
                    }
                    return Err(error);
                }
                decoded => decoded?,
            };
            if record.actor_ref.as_deref() != Some(actor_ref) {
                continue;
            }
            record.actor_ref = None;
            vet_gate_decision_record(&record)?;
            let value = match orcb::raw_claim_generation(&raw) {
                Some((_, generation)) => {
                    orcb::encode_hot_at(&self.core.gate_custody_root, &record, generation)?
                }
                None => encode_gate_decision(&record)?,
            };
            cleared.push((decision_id, value));
        }
        for (decision_id, value) in &cleared {
            LEDGER.put(self, wtxn, decision_id, value)?;
        }
        Ok(())
    }
}

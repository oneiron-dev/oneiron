//! The owner's selection of a proposed pack lens for its slot, and its
//! clearing (OF-250).
//!
//! Both doors take the owner's proof a host minted from the request, never a
//! caller's flag, and revalidate it in the writer that changes the slot. The
//! owner's confirmation is the consent: it names the exact revision
//! (`compiled_hash`) and the slot state it saw (`expected_active_ref`). An
//! agent can propose a lens; it cannot select one.

use serde::{Deserialize, Serialize};

use super::GeneratedLens;
use super::proposal::{
    LensSlot, LensSlotRecord, PROPOSALS, SLOTS, active_at, invalid_state, slot_key,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::receipt::{LensActivationReceipt, LensSlotDecision};
use crate::store::GateDecisionId;
use crate::{EntityId, Error, Result, Vault};

/// `vault.lenses.activate`'s input: the proposal to select, the revision the
/// owner was shown, and the lens the slot held when they looked.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensActivateRequest {
    pub lens_ref: String,
    pub compiled_hash: String,
    /// The slot's active lens as shown, or none when it held none.
    #[serde(default)]
    pub expected_active_ref: Option<String>,
}

/// `vault.lenses.deactivate`'s input: the slot to clear and the lens it was
/// shown holding. It clears the selection only; the pack, its skill and the
/// proposal stay.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDeactivateRequest {
    pub slot: LensSlot,
    pub expected_active_ref: String,
}

fn lens_id(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} is a lens_ref")))
}

impl Vault {
    /// `vault.lenses.activate` under the owner's proof: select one proposed
    /// revision for its slot. In the writer the proof is revalidated, the
    /// proposal must still hold `compiled_hash`, its pack must still be
    /// installed Active at the content it was proposed against with the
    /// skill loading, and the slot must hold `expected_active_ref`.
    pub fn activate_lens(
        &self,
        owner: &AuthenticatedOwner,
        input: LensActivateRequest,
    ) -> MemoryResult<LensActivationReceipt> {
        let lens_ref = lens_id("lens_ref", &input.lens_ref)?;
        let expected = input
            .expected_active_ref
            .as_deref()
            .map(|value| lens_id("expected_active_ref", value))
            .transpose()?;
        self.try_with_write_txn_grouped(|txn| {
            let decided_by = owner.revalidate_in_txn(self, txn)?;
            let proposal = PROPOSALS
                .get(&self.store, txn, &lens_ref)?
                .ok_or_else(|| MemoryError::not_found("no lens proposal has that lens_ref"))?;
            if proposal.compiled_hash != input.compiled_hash {
                return Err(invalid_state(
                    "compiled_hash is not the proposal's revision",
                    "List the proposal again and confirm the revision it holds.",
                ));
            }
            let skill_id = EntityId::from_hex(&proposal.skill_id)
                .map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
            let live = self.live_pack_skill_in_txn(txn, &proposal.pack_name, &skill_id)?;
            if !live
                .as_ref()
                .is_some_and(|install| active_at(install, &proposal.pack_content_hash))
            {
                return Err(invalid_state(
                    "the lens's pack is no longer installed Active at the content it was proposed against, with that skill loading",
                    "Propose the lens again against the installed pack.",
                ));
            }
            let key = slot_key(&proposal.pack_name, &skill_id);
            let previous = SLOTS.get(&self.store, txn, &key)?.map(|slot| slot.lens_ref);
            if previous != expected.map(|id| id.to_hex()) {
                return Err(invalid_state(
                    "the slot's active lens is not expected_active_ref",
                    "List the slot again and confirm against what it holds now.",
                ));
            }
            let record = LensSlotRecord {
                lens_ref: lens_ref.to_hex(),
                compiled_hash: proposal.compiled_hash,
                pack_content_hash: proposal.pack_content_hash,
                decided_by: decided_by.to_hex(),
                decision_ref: GateDecisionId::now().to_hex(),
                authenticated_under: owner.decision_id().to_hex(),
                decided_at: crate::unix_seconds_now(),
            };
            SLOTS.put(&self.store, txn, &key, &record)?;
            Ok(slot_receipt(
                LensSlotDecision::Activated,
                &proposal.pack_name,
                &skill_id,
                record,
                previous,
            ))
        })
    }

    /// `vault.lenses.deactivate` under the owner's proof: clear one slot's
    /// selection when it still holds `expected_active_ref`. Not a delete, a
    /// skill quarantine or a pack uninstall.
    pub fn deactivate_lens(
        &self,
        owner: &AuthenticatedOwner,
        input: LensDeactivateRequest,
    ) -> MemoryResult<LensActivationReceipt> {
        let skill_id = input.slot.skill()?;
        let expected = lens_id("expected_active_ref", &input.expected_active_ref)?;
        let key = slot_key(&input.slot.pack_name, &skill_id);
        self.try_with_write_txn_grouped(|txn| {
            let decided_by = owner.revalidate_in_txn(self, txn)?;
            let Some(current) = SLOTS.get(&self.store, txn, &key)? else {
                return Err(MemoryError::not_found("that slot has no active lens"));
            };
            if current.lens_ref != expected.to_hex() {
                return Err(invalid_state(
                    "the slot's active lens is not expected_active_ref",
                    "List the slot again and confirm against what it holds now.",
                ));
            }
            SLOTS.delete(&self.store, txn, &key)?;
            let record = LensSlotRecord {
                decided_by: decided_by.to_hex(),
                decision_ref: GateDecisionId::now().to_hex(),
                authenticated_under: owner.decision_id().to_hex(),
                decided_at: crate::unix_seconds_now(),
                ..current
            };
            Ok(slot_receipt(
                LensSlotDecision::Deactivated,
                &input.slot.pack_name,
                &skill_id,
                record,
                None,
            ))
        })
    }

    /// The generated lens the owner selected for a pack/skill slot, rechecked
    /// against the live install now: `None` when the slot holds none, or its
    /// pack is no longer installed Active at the content the lens was
    /// proposed against, or the skill no longer loads. Call it before every
    /// render; it is not a cache.
    pub fn active_pack_lens(
        &self,
        pack_name: &str,
        skill_id: &EntityId,
    ) -> Result<Option<(EntityId, GeneratedLens)>> {
        let txn = self.store.env.read_txn()?;
        let Some(slot) = SLOTS.get(&self.store, &txn, &slot_key(pack_name, skill_id))? else {
            return Ok(None);
        };
        if !self
            .live_pack_skill_in_txn(&txn, pack_name, skill_id)?
            .is_some_and(|install| active_at(&install, &slot.pack_content_hash))
        {
            return Ok(None);
        }
        let lens_ref = EntityId::from_hex(&slot.lens_ref)
            .map_err(|_| Error::CorruptedIndex("lens slot record"))?;
        let proposal = PROPOSALS
            .get(&self.store, &txn, &lens_ref)?
            .ok_or(Error::CorruptedIndex("lens slot record"))?;
        if proposal.compiled_hash != slot.compiled_hash {
            return Err(Error::CorruptedIndex("lens slot record"));
        }
        Ok(Some((lens_ref, proposal.compiled()?)))
    }
}

fn slot_receipt(
    decision: LensSlotDecision,
    pack_name: &str,
    skill_id: &EntityId,
    record: LensSlotRecord,
    previous_ref: Option<String>,
) -> LensActivationReceipt {
    LensActivationReceipt {
        decision,
        pack_name: pack_name.to_owned(),
        skill_id: skill_id.to_hex(),
        lens_ref: record.lens_ref,
        compiled_hash: record.compiled_hash,
        previous_ref,
        decided_by: record.decided_by,
        decision_ref: record.decision_ref,
        authenticated_under: record.authenticated_under,
        decided_at: record.decided_at,
    }
}

/// `vault.lenses.activate` on an embedded handle: the vault's embedded
/// owner's selection.
pub fn activate_lens_embedded(
    memory: &Memory<'_>,
    input: LensActivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = memory.embedded_owner("vault.lenses.activate")?;
    memory.vault().activate_lens(&owner, input)
}

/// `vault.lenses.deactivate` on an embedded handle: the vault's embedded
/// owner's clearing.
pub fn deactivate_lens_embedded(
    memory: &Memory<'_>,
    input: LensDeactivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = memory.embedded_owner("vault.lenses.deactivate")?;
    memory.vault().deactivate_lens(&owner, input)
}

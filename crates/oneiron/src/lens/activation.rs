//! The owner's selection of a proposed pack lens for its slot, and its
//! clearing (OF-250), and an agent's beside them (restriction census C33).
//!
//! The owner's doors take the owner's proof a host minted from the request,
//! never a caller's flag, and revalidate it in the writer that changes the
//! slot. The owner's confirmation is the consent: it names the exact revision
//! (`compiled_hash`) and the slot state it saw (`expected_active_ref`). An
//! agent can propose a lens. It selects or clears one only through its own
//! doors, [`activate_lens_as_agent`] and [`deactivate_lens_as_agent`], when
//! the owner's `lens.slot.agent_select` row is on for it and its live Grant
//! lists the verb, both read in the writer that changes the slot; it never
//! selects a revision its own lineage proposed, whatever that row says
//! (DEC-0006).

use super::GeneratedLens;
use super::proposal::{LensSlotRecord, PROPOSALS, SLOTS, active_at, invalid_state, slot_key};
use super::setting_keys::LENS_SLOT_AGENT_SELECT;
use crate::agent_dispatch::{LineageStart, settling_lineage_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::receipt::{LensActivationReceipt, LensSlotDecision};
use crate::setting::SettingScope;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::lens::activation::{LensActivateRequest, LensDeactivateRequest};

/// `vault.lenses.activate_as`, the name a Grant lists to name an agent's
/// selection.
const LENS_ACTIVATE_AS_VERB: &str = "vault.lenses.activate_as";
/// `vault.lenses.deactivate_as`, the name a Grant lists to name an agent's
/// clearing.
const LENS_DEACTIVATE_AS_VERB: &str = "vault.lenses.deactivate_as";

fn lens_id(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} is a lens_ref")))
}

/// Who changes a slot, as the slot's writer admitted them.
struct SlotDecider {
    /// The owner whose proof the writer revalidated, or the agent it admitted.
    actor: EntityId,
    /// What the decision was made under: the owner's authentication, or the
    /// agent's admitting Grant as `grant:<hex>`.
    authenticated_under: String,
    /// `Human` for the owner, `Agent` for an agent.
    actor_class: EdgeActorClass,
    /// The agent's admitting Grant; `None` for the owner.
    grant: Option<EntityId>,
}

impl SlotDecider {
    /// The owner behind `owner`, revalidated in `txn`.
    fn owner_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<Self> {
        Ok(Self {
            actor: owner.revalidate_in_txn(vault, txn)?,
            authenticated_under: owner.decision_id().to_hex(),
            actor_class: EdgeActorClass::Human,
            grant: None,
        })
    }

    /// `memory`'s agent, admitted in `txn` for `verb`: the handle's
    /// credential still holds, a live Grant from a live owner lists `verb`
    /// for it, and the owner's `LENS_SLOT_AGENT_SELECT` row is on for it.
    /// With the key off the slot stays the owner's, as at the owner doors.
    fn agent_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, verb: &str) -> MemoryResult<Self> {
        memory.prove_read_authority_in_txn(txn)?;
        let vault = memory.vault();
        let agent = memory.actor();
        let grant = crate::authority::principal_standing_in_txn(
            vault,
            txn,
            agent,
            EdgeActorClass::Agent,
            verb,
        )?
        .and_then(|standing| standing.grant);
        let Some(grant) = grant else {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{verb} takes a live Grant listing {verb}: no live Grant from a live owner names this caller and lists the verb"
                ),
                &["Have the owner grant this caller the verb by name."],
            ));
        };
        let delegated = LENS_SLOT_AGENT_SELECT
            .read_in_txn(vault, txn, &[SettingScope::Agent(agent)], None)?
            .value;
        if !delegated {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{verb} is the vault owner's: the owner has not turned on {} for this agent",
                    LENS_SLOT_AGENT_SELECT.spec.name
                ),
                &["Ask the owner to turn the setting on for this agent."],
            ));
        }
        Ok(Self {
            actor: agent,
            authenticated_under: format!("grant:{}", grant.to_hex()),
            actor_class: EdgeActorClass::Agent,
            grant: Some(grant),
        })
    }

    /// Refuses an agent's selection of a revision `proposed_by` proposed when
    /// the two share a lineage ([`settling_lineage_in_txn`]): the opener's
    /// lineage and its forks never settle their own proposal (DEC-0006),
    /// whatever the key says. A proposer the record no longer names (an
    /// erased one), or a lineage the engine cannot read whole, counts as the
    /// agent's own. The owner's selection is not a lineage's.
    fn refuse_own_lineage_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        proposed_by: &str,
    ) -> MemoryResult<()> {
        if self.actor_class != EdgeActorClass::Agent {
            return Ok(());
        }
        let refused = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{LENS_ACTIVATE_AS_VERB} never selects a revision the selecting agent's own lineage proposed"
                ),
                &["Ask the owner, or an agent outside the proposer's lineage, to select it."],
            )
        };
        let Ok(proposer) = EntityId::from_hex(proposed_by) else {
            return Err(refused());
        };
        let decider = settling_lineage_in_txn(vault, txn, &[LineageStart::Actor(self.actor)])?;
        let proposer = settling_lineage_in_txn(vault, txn, &[LineageStart::Actor(proposer)])?;
        match (decider, proposer) {
            (Some(decider), Some(proposer)) if decider.is_disjoint(&proposer) => Ok(()),
            _ => Err(refused()),
        }
    }
}

/// The handle's own agent, or the refusal of any other caller: these doors
/// are an agent's; the owner selects through the owner doors.
fn lens_agent(memory: &Memory<'_>, verb: &str) -> MemoryResult<()> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is an agent's door: the caller is no agent"),
            &["Select the lens through the owner's door with the owner's own credential."],
        ));
    }
    Ok(())
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
        let request = ActivateSlot::parse(input)?;
        self.try_with_write_txn_grouped(|txn| {
            let decider = SlotDecider::owner_in_txn(self, txn, owner)?;
            self.activate_lens_in_txn(txn, &decider, request)
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
        let request = DeactivateSlot::parse(input)?;
        self.try_with_write_txn_grouped(|txn| {
            let decider = SlotDecider::owner_in_txn(self, txn, owner)?;
            self.deactivate_lens_in_txn(txn, &decider, &request)
        })
    }

    /// The selection [`Vault::activate_lens`] makes, by `decider`, in its
    /// writer `txn`: the proposal still holds the revision, its pack is still
    /// installed Active at the content it was proposed against with the skill
    /// loading, an agent shares no lineage with its proposer, and the slot
    /// holds the expected lens.
    fn activate_lens_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        decider: &SlotDecider,
        request: ActivateSlot,
    ) -> MemoryResult<LensActivationReceipt> {
        let ActivateSlot {
            lens_ref,
            compiled_hash,
            expected,
        } = request;
        let proposal = PROPOSALS
            .get(&self.store, txn, &lens_ref)?
            .ok_or_else(|| MemoryError::not_found("no lens proposal has that lens_ref"))?;
        if proposal.compiled_hash != compiled_hash {
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
        decider.refuse_own_lineage_in_txn(self, txn, &proposal.proposed_by)?;
        let key = slot_key(&proposal.pack_name, &skill_id);
        let previous = SLOTS.get(&self.store, txn, &key)?.map(|slot| slot.lens_ref);
        if previous != expected.map(|id| id.to_hex()) {
            return Err(invalid_state(
                "the slot's active lens is not expected_active_ref",
                "List the slot again and confirm against what it holds now.",
            ));
        }
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = LensSlotRecord {
            lens_ref: lens_ref.to_hex(),
            compiled_hash: proposal.compiled_hash,
            pack_content_hash: proposal.pack_content_hash,
            decided_by: decider.actor.to_hex(),
            decision_ref: decision_id.to_hex(),
            authenticated_under: decider.authenticated_under.clone(),
            decided_at: crate::unix_seconds_now(),
        };
        SLOTS.put(&self.store, txn, &key, &record)?;
        let receipt = slot_receipt(
            LensSlotDecision::Activated,
            &proposal.pack_name,
            &skill_id,
            record,
            previous,
        );
        self.append_lens_slot_decision_in_txn(txn, decider, decision_id, &receipt)?;
        Ok(receipt)
    }

    /// The clearing [`Vault::deactivate_lens`] makes, by `decider`, in its
    /// writer `txn`, when the slot still holds the expected lens.
    fn deactivate_lens_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        decider: &SlotDecider,
        request: &DeactivateSlot,
    ) -> MemoryResult<LensActivationReceipt> {
        let Some(current) = SLOTS.get(&self.store, txn, &request.key)? else {
            return Err(MemoryError::not_found("that slot has no active lens"));
        };
        if current.lens_ref != request.expected.to_hex() {
            return Err(invalid_state(
                "the slot's active lens is not expected_active_ref",
                "List the slot again and confirm against what it holds now.",
            ));
        }
        SLOTS.delete(&self.store, txn, &request.key)?;
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = LensSlotRecord {
            decided_by: decider.actor.to_hex(),
            decision_ref: decision_id.to_hex(),
            authenticated_under: decider.authenticated_under.clone(),
            decided_at: crate::unix_seconds_now(),
            ..current
        };
        let receipt = slot_receipt(
            LensSlotDecision::Deactivated,
            &request.pack_name,
            &request.skill_id,
            record,
            None,
        );
        self.append_lens_slot_decision_in_txn(txn, decider, decision_id, &receipt)?;
        Ok(receipt)
    }

    fn append_lens_slot_decision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        decider: &SlotDecider,
        decision_id: GateDecisionId,
        receipt: &LensActivationReceipt,
    ) -> Result<()> {
        let reason = match receipt.decision {
            LensSlotDecision::Activated => "gate.consent.lens_activated",
            LensSlotDecision::Deactivated => "gate.consent.lens_deactivated",
        };
        let mut digest = blake3::Hasher::new();
        digest.update(b"oneiron.lens-slot-decision.v1\0");
        let bytes = serde_json::to_vec(receipt)
            .map_err(|_| Error::InvariantViolation("lens slot receipt encoding failed"))?;
        digest.update(&bytes);
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: "allow".to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: decider.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(decider.actor.to_hex()),
            content_kind: "lens_slot".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            // An agent's decision names the Grant that admitted it.
            grant_ref: decider.grant.map(|grant| grant.to_hex()),
            diff_handle: digest.finalize().as_bytes().to_vec(),
            read_frontier_hash: [0_u8; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)
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
        Ok(Some((
            lens_ref,
            proposal.compiled_in(self, &txn, &lens_ref)?,
        )))
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

/// A selection's request, parsed before its writer opens.
struct ActivateSlot {
    lens_ref: EntityId,
    compiled_hash: String,
    expected: Option<EntityId>,
}

impl ActivateSlot {
    fn parse(input: LensActivateRequest) -> MemoryResult<Self> {
        Ok(Self {
            lens_ref: lens_id("lens_ref", &input.lens_ref)?,
            expected: input
                .expected_active_ref
                .as_deref()
                .map(|value| lens_id("expected_active_ref", value))
                .transpose()?,
            compiled_hash: input.compiled_hash,
        })
    }
}

/// A clearing's request, parsed before its writer opens.
struct DeactivateSlot {
    pack_name: String,
    skill_id: EntityId,
    key: String,
    expected: EntityId,
}

impl DeactivateSlot {
    fn parse(input: LensDeactivateRequest) -> MemoryResult<Self> {
        let skill_id = input.slot.skill()?;
        let expected = lens_id("expected_active_ref", &input.expected_active_ref)?;
        Ok(Self {
            key: slot_key(&input.slot.pack_name, &skill_id),
            pack_name: input.slot.pack_name,
            skill_id,
            expected,
        })
    }
}

/// `vault.lenses.activate_as`: [`Vault::activate_lens`] for the handle's own
/// agent, under its live Grant listing the verb and the owner's
/// `lens.slot.agent_select` row for it, both read in the writer that changes
/// the slot. A revision the agent's own lineage proposed is refused whatever
/// the key says (DEC-0006). The receipt and the gate ledger name the agent as
/// the decider and its Grant as what the decision was made under.
///
/// # Errors
/// `FORBIDDEN` for a caller that is no agent, an agent with no such Grant, an
/// agent the owner has not turned the key on for, and a revision its own
/// lineage proposed; a credential that no longer holds; the owner door's
/// refusals and storage faults.
pub fn activate_lens_as_agent(
    memory: &Memory<'_>,
    input: LensActivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    lens_agent(memory, LENS_ACTIVATE_AS_VERB)?;
    let request = ActivateSlot::parse(input)?;
    let vault = memory.vault();
    memory.with_verified_actor_write_txn(|txn| {
        let decider = SlotDecider::agent_in_txn(memory, txn, LENS_ACTIVATE_AS_VERB)?;
        vault.activate_lens_in_txn(txn, &decider, request)
    })
}

/// `vault.lenses.deactivate_as`: [`Vault::deactivate_lens`] for the handle's
/// own agent, admitted as [`activate_lens_as_agent`] admits. Clearing a slot
/// settles no proposal, so no lineage is checked.
///
/// # Errors
/// As [`activate_lens_as_agent`], but for the lineage refusal.
pub fn deactivate_lens_as_agent(
    memory: &Memory<'_>,
    input: LensDeactivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    lens_agent(memory, LENS_DEACTIVATE_AS_VERB)?;
    let request = DeactivateSlot::parse(input)?;
    let vault = memory.vault();
    memory.with_verified_actor_write_txn(|txn| {
        let decider = SlotDecider::agent_in_txn(memory, txn, LENS_DEACTIVATE_AS_VERB)?;
        vault.deactivate_lens_in_txn(txn, &decider, &request)
    })
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

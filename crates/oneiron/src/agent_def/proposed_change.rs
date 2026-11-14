//! The owner's answer to an agent's proposed change to a stored agent
//! definition (ARCH-0053:20, r6: "a skill update that widens the capability
//! surface requires human re-consent").
//!
//! An agent's put that grants a stored AGENT_DEF more than its author's slice
//! holds is stored beside it as a proposal (`agent_authored_update_in_txn`):
//! a Proposed row at [`proposed_change_id`] whose provenance names the stored
//! row under `replaces`, and the stored row stays as it is. Only the owner
//! answers one. Approving makes the proposal the stored row's next version
//! and deletes the proposal row, whose body the stored row now holds.
//! Rejecting leaves the stored row as it is and retires the proposal row in
//! place (Rejected, Retracted), where the owner still reads what the agent
//! proposed. Either answer appends one gate decision that records it, in the
//! one write transaction that rechecks the owner's proof.

use super::codec::{encode_agent_definition, validate_agent_definition_update};
use super::doors::proposed_change_id;
use super::types::AgentDefinition;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::scan_count::ScanCount;
use crate::store::{EngineScan, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};
use crate::temporal::TimeRange;
use crate::{EdgeActorClass, WriteActor};

/// The provenance key under which a proposal names the stored row it would
/// replace (`agent_authored_update_in_txn`).
pub(super) const REPLACES_KEY: &str = "replaces";
/// The provenance key naming the agent that wrote the proposal.
pub(super) const AUTHOR_KEY: &str = "author";
/// The provenance key naming the door the proposal was put through.
const DOOR_KEY: &str = "definedVia";
/// The content kind of the gate decision that records the owner's answer.
const CHANGE_CONTENT_KIND: &str = "agent_definition_change";
/// The reason code of an approval.
const APPROVE_REASON: &str = "gate.allow.owner_agent_definition_change";
/// The reason code of a rejection.
const REJECT_REASON: &str = "gate.deny.owner_agent_definition_change";

#[doc(hidden)]
pub use oneiron_verb_wire::agent_def::proposed_change::ProposedAgentDefinitionChangeDecision;

/// One proposed change waiting for the owner.
#[derive(Debug, Clone)]
pub(crate) struct ProposedAgentDefinitionChange {
    /// The proposal row.
    pub(crate) proposal: EntityId,
    /// The stored row the proposal would replace.
    pub(crate) target: EntityId,
    /// The definition the proposal holds.
    pub(crate) definition: AgentDefinition,
    /// The agent that put it, as its provenance names it.
    pub(crate) proposed_by: Option<EntityId>,
    /// The door it was put through, as its provenance names it.
    pub(crate) proposed_through: Option<String>,
}

/// What the owner's answer wrote.
#[derive(Debug, Clone)]
pub(crate) struct ProposedAgentDefinitionChangeSettlement {
    /// The proposal answered.
    pub(crate) change: ProposedAgentDefinitionChange,
    pub(crate) decision: ProposedAgentDefinitionChangeDecision,
    /// The stored row's version before the answer; `None` when a rejected
    /// proposal named a row that no longer stands.
    pub(crate) target_version_before: Option<String>,
    /// The stored row as the answer left it; `None` as above.
    pub(crate) target_after: Option<AgentDefinition>,
    /// The gate decision that records the answer, as `gate:<id hex>`.
    pub(crate) receipt_ref: String,
}

/// The text a definition's provenance map holds under `key`.
pub(super) fn provenance_text<'a>(definition: &'a AgentDefinition, key: &str) -> Option<&'a str> {
    let rmpv::Value::Map(entries) = &definition.provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}

/// `definition`, stored at `id`, as a proposed change waiting for the owner:
/// a Proposed row whose provenance names a stored row under `replaces`, at
/// the id the author writer derives for that row and the proposal's version.
/// `None` for every other definition.
///
/// # Errors
///
/// [`proposed_change_id`]'s.
fn waiting_change(
    id: &EntityId,
    definition: AgentDefinition,
) -> Result<Option<ProposedAgentDefinitionChange>> {
    if definition.approval_status != ClaimApprovalStatus::Proposed {
        return Ok(None);
    }
    let Some(target) =
        provenance_text(&definition, REPLACES_KEY).and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    if proposed_change_id(&target, &definition.version)? != *id {
        return Ok(None);
    }
    let proposed_by =
        provenance_text(&definition, AUTHOR_KEY).and_then(|hex| EntityId::from_hex(hex).ok());
    let proposed_through = provenance_text(&definition, DOOR_KEY).map(str::to_owned);
    Ok(Some(ProposedAgentDefinitionChange {
        proposal: *id,
        target,
        definition,
        proposed_by,
        proposed_through,
    }))
}

/// The stored row's next version under an approved proposal: every field the
/// proposal holds, except what makes the stored row the row it is (its
/// agent id, fork lineage, logical id and authorship), its standing
/// (approval and lifecycle) and its provenance, which stay the stored row's.
/// The proposer is named in the answer's receipt, not on the row.
fn approved_next_version(stored: &AgentDefinition, proposal: &AgentDefinition) -> AgentDefinition {
    let mut next = proposal.clone();
    next.agent_id.clone_from(&stored.agent_id);
    next.forked_from = stored.forked_from;
    next.logical_id.clone_from(&stored.logical_id);
    next.source = stored.source;
    next.generated = stored.generated;
    next.human_authored = stored.human_authored;
    next.approval_status = stored.approval_status;
    next.lifecycle_status = stored.lifecycle_status;
    next.provenance.clone_from(&stored.provenance);
    next
}

/// The digest of the owner's approval of the proposed change at `proposal`,
/// holding `definition`, while the stored row it names is at
/// `expected_target_version`: the effect an asker's `vault.check_in.open`
/// names for `vault.agents.proposed_changes.approve`, and the one the
/// approval spends (2k8; P25-SHAPE Q1 = A). The proposal's id names its
/// stored row and version, not its body, so the body is pinned here. BLAKE3,
/// key derived from `oneiron check_in proposed agent definition change
/// approve v1`, over the proposal's 16 id bytes, the expected version's
/// length as eight big-endian bytes and its UTF-8 bytes, then the
/// definition's stored encoding.
///
/// # Errors
///
/// A definition that does not encode.
pub fn proposed_agent_definition_change_approve_effect_digest(
    proposal: &EntityId,
    expected_target_version: &str,
    definition: &AgentDefinition,
) -> Result<[u8; 32]> {
    let body = encode_agent_definition(definition)?;
    let mut hasher = blake3::Hasher::new_derive_key(
        "oneiron check_in proposed agent definition change approve v1",
    );
    hasher.update(proposal.as_bytes());
    hasher.update(
        &u64::try_from(expected_target_version.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(expected_target_version.as_bytes());
    hasher.update(&body);
    Ok(*hasher.finalize().as_bytes())
}

/// The proposal as a rejection leaves it: Rejected and Retracted, so no
/// dispatch runs it and no list shows it as waiting, with every other field
/// as the agent proposed it. Its version moves to `rejected-` and the BLAKE3
/// hash of the proposed version, since a body changes only with its version.
fn rejected_proposal(proposal: &AgentDefinition) -> AgentDefinition {
    let mut rejected = proposal.clone();
    rejected.approval_status = ClaimApprovalStatus::Rejected;
    rejected.lifecycle_status = ClaimLifecycleStatus::Retracted;
    rejected.version = format!(
        "rejected-{}",
        blake3::hash(proposal.version.as_bytes()).to_hex()
    );
    rejected
}

impl Vault {
    /// The proposed changes waiting for the owner, each beside the stored row
    /// it would replace; only those naming `target` when one is given. Every
    /// AGENT_DEF row is read (rule 5: past the type's threshold the scan
    /// raises one scan check and reads on).
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// a stored definition that does not decode.
    pub(crate) fn proposed_agent_definition_changes_as(
        &self,
        owner: &AuthenticatedOwner,
        target: Option<&EntityId>,
    ) -> Result<Vec<(ProposedAgentDefinitionChange, Option<AgentDefinition>)>> {
        let rtxn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &rtxn)?;
        let mut count = ScanCount::start(
            &self.store,
            &rtxn,
            EngineScan::TypeIndexRows,
            &[ENTITY_TYPE_AGENT_DEF],
        )?;
        let mut changes = Vec::new();
        for id in self
            .store
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_AGENT_DEF, None)?
        {
            count.row();
            let id = id?;
            let definition = self.read_agent_definition_in_txn(&rtxn, &id)?;
            let Some(change) = waiting_change(&id, definition)? else {
                continue;
            };
            if target.is_some_and(|target| *target != change.target) {
                continue;
            }
            let current = self.standing_target_in_txn(&rtxn, &change.target)?;
            changes.push((change, current));
        }
        drop(rtxn);
        count.finish(self);
        Ok(changes)
    }

    /// The owner approves the proposed change at `proposal`: the stored row it
    /// names takes the proposal as its next version
    /// ([`approved_next_version`]), as the owner's own edit of exactly
    /// version `expected_target_version` of that row would, the id pin moves
    /// to the new ceiling, the proposal row is deleted, and one gate decision
    /// records the answer, all in one writer that rechecks the proof.
    ///
    /// The approval widens what the agent may do: it is the owner's own act
    /// on their own proof, never gated, and it answers that decision. With
    /// `check_in` the owner applies another asker's approved check-in for
    /// this exact approval
    /// ([`proposed_agent_definition_change_approve_effect_digest`], over the
    /// proposal's stored body), spent in this writer after every check, so a
    /// refusal leaves it eligible (ROLES-CHECKIN 2k8; P25-SHAPE Q1 = A).
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`] for no row at `proposal` or at the stored id
    /// it names; [`ArtifactError::InvalidAgentDefBody`] for a row that is no
    /// proposed change waiting for the owner, and the refusals the same body
    /// meets as an owner's update of the stored row;
    /// [`Error::ConcurrentWrite`] when the stored row is no longer at
    /// `expected_target_version`; a `check_in` that is not an approved ask
    /// for this approval. Every refusal writes nothing.
    pub(crate) fn approve_proposed_agent_definition_change_as(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &EntityId,
        expected_target_version: &str,
        check_in: Option<&EntityId>,
    ) -> Result<(
        ProposedAgentDefinitionChangeSettlement,
        crate::check_in::CheckInDecision,
    )> {
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let change = self.waiting_change_in_txn(txn, proposal)?;
            let stored = self.read_agent_definition_in_txn(txn, &change.target)?;
            if stored.version != expected_target_version {
                return Err(Error::ConcurrentWrite("agent definition revision changed"));
            }
            let next = approved_next_version(&stored, &change.definition);
            validate_agent_definition_update(&stored, &next)?;
            let applied = match check_in {
                Some(id) => Some(crate::check_in::AppliedCheckIn {
                    id: *id,
                    verb: "vault.agents.proposed_changes.approve",
                    effect_digest: proposed_agent_definition_change_approve_effect_digest(
                        proposal,
                        expected_target_version,
                        &change.definition,
                    )?,
                }),
                None => None,
            };
            let decision = crate::check_in::owner_act_decision_in_txn(
                self,
                txn,
                crate::check_in::ActClass::GrantWiden,
                applied.as_ref(),
            )?;
            super::id_pin::move_pin_for_owner_in_txn(&self.store, txn, &change.target, &next)?;
            self.apply_agent_definition_body(
                txn,
                &change.target,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                encode_agent_definition(&next)?,
            )?;
            self.delete_proposal_in_txn(txn, &change.proposal)?;
            let settlement = self.record_answer_in_txn(
                txn,
                actor,
                change,
                ProposedAgentDefinitionChangeDecision::Approved,
                Some(stored.version),
                Some(next),
            )?;
            Ok((settlement, decision))
        })
    }

    /// The owner rejects the proposed change at `proposal`: the stored row it
    /// names stays as it is, the proposal row is retired in place
    /// ([`rejected_proposal`]), and one gate decision records the answer, in
    /// one writer that rechecks the proof. A proposal whose stored row no
    /// longer stands is rejected all the same.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`] for no row at `proposal`;
    /// [`ArtifactError::InvalidAgentDefBody`] for a row that is no proposed
    /// change waiting for the owner. Every refusal writes nothing.
    pub(crate) fn reject_proposed_agent_definition_change_as(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &EntityId,
    ) -> Result<ProposedAgentDefinitionChangeSettlement> {
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let change = self.waiting_change_in_txn(txn, proposal)?;
            let stored = self.standing_target_in_txn(txn, &change.target)?;
            let before = stored.as_ref().map(|stored| stored.version.clone());
            let rejected = rejected_proposal(&change.definition);
            validate_agent_definition_update(&change.definition, &rejected)?;
            self.apply_agent_definition_body(
                txn,
                &change.proposal,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                encode_agent_definition(&rejected)?,
            )?;
            self.record_answer_in_txn(
                txn,
                actor,
                change,
                ProposedAgentDefinitionChangeDecision::Rejected,
                before,
                stored,
            )
        })
    }

    /// The proposed change at `proposal`, waiting for the owner.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for no row; a row that is no AGENT_DEF or
    /// does not decode; [`ArtifactError::InvalidAgentDefBody`] for a
    /// definition that is no proposed change waiting for the owner.
    fn waiting_change_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proposal: &EntityId,
    ) -> Result<ProposedAgentDefinitionChange> {
        let definition = self.read_agent_definition_in_txn(txn, proposal)?;
        waiting_change(proposal, definition)?.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("not a proposed change waiting for the owner"),
        ))
    }

    /// The stored row at `target`; `None` when no row stands there.
    ///
    /// # Errors
    ///
    /// A row there that is no AGENT_DEF, or does not decode.
    fn standing_target_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<Option<AgentDefinition>> {
        match self.read_agent_definition_in_txn(txn, target) {
            Ok(stored) => Ok(Some(stored)),
            Err(Error::EntityNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Deletes the approved proposal row: the stored row now holds its body.
    ///
    /// # Errors
    ///
    /// The delete's refusals.
    fn delete_proposal_in_txn(&self, txn: &mut heed::RwTxn<'_>, proposal: &EntityId) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![BatchOp::Delete { id: *proposal }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// Appends the gate decision that records the owner's answer: the owner
    /// as actor, `gate.allow.` or `gate.deny.owner_agent_definition_change`,
    /// the stored row as its `agent_def:` grant ref, the BLAKE3 hash of the
    /// proposal's body as its diff handle, and the ids, versions and proposer
    /// as audit details.
    ///
    /// # Errors
    ///
    /// The ledger's.
    fn record_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        change: ProposedAgentDefinitionChange,
        decision: ProposedAgentDefinitionChangeDecision,
        target_version_before: Option<String>,
        target_after: Option<AgentDefinition>,
    ) -> Result<ProposedAgentDefinitionChangeSettlement> {
        let proposal_body = encode_agent_definition(&change.definition)?;
        let (outcome, reason) = match decision {
            ProposedAgentDefinitionChangeDecision::Approved => ("allow", APPROVE_REASON),
            ProposedAgentDefinitionChangeDecision::Rejected => ("deny", REJECT_REASON),
        };
        let mut details = vec![
            format!("target:{}", change.target.to_hex()),
            format!("proposal:{}", change.proposal.to_hex()),
            format!("proposal_version:{}", change.definition.version),
        ];
        details.extend(
            target_version_before
                .as_deref()
                .map(|version| format!("target_version_before:{version}")),
        );
        details.extend(
            target_after
                .as_ref()
                .map(|after| format!("target_version_after:{}", after.version)),
        );
        details.extend(
            change
                .proposed_by
                .map(|author| format!("proposed_by:{}", author.to_hex())),
        );
        details.extend(
            change
                .proposed_through
                .as_deref()
                .map(|door| format!("proposed_through:{door}")),
        );
        let actor = WriteActor::new(actor, EdgeActorClass::Human);
        let mut record = GateDecisionRecord {
            version: crate::store::GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: outcome.to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(CHANGE_CONTENT_KIND, details),
            actor_class: actor.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            content_kind: CHANGE_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("agent_def:{}", change.target.to_hex())),
            diff_handle: blake3::hash(&proposal_body).as_bytes().to_vec(),
            read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, txn)?
                .read_frontier_hash()?,
            context: Default::default(),
            redacted_at: None,
        };
        self.store
            .append_fresh_gate_decision_in_txn(txn, &mut record)?;
        Ok(ProposedAgentDefinitionChangeSettlement {
            change,
            decision,
            target_version_before,
            target_after,
            receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
        })
    }
}

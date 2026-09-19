//! Fail-closed propose-widen and owner-authenticated, TASK-bound board approval.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::{
    AuthenticatedOwner, approve_once_authorization_in_txn, spend_approve_once_in_txn,
};
use crate::context_projection::{
    ContextResolutionRequest, ContextSpec, ResolvedContextProjection, resolve_context_spec,
    validate_context_narrows, validate_context_spec, validate_spec_narrows,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

use super::attenuation::source_content_fingerprint;
use super::codec::record_dispatch_input;
use super::widen_record::{
    SliceOverride, WidenIntent, WidenRecord, WidenRequest, decode, invalid, json, proposal_key,
    slice_key, widened_parent,
};
use super::{
    AgentDispatchInput, AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher,
    AgentSpawnContext, DispatchAgent,
};

impl AgentDispatcher<'_> {
    /// Re-resolves an attempt's live recursive slice, including approved widening.
    /// Executors must use this door rather than resolve a payload standalone.
    pub fn resolve_attempt_context(&self, attempt: AttemptId) -> Result<ResolvedContextProjection> {
        let mut projection = self
            .resolve_ancestor_projection(attempt, crate::pipeline::WorldScope::All)?
            .ok_or_else(|| invalid("attempt has no provable context lineage"))?;
        let row = AttemptQueue::new(self.vault)
            .get(attempt)?
            .ok_or_else(|| invalid("context attempt is missing"))?;
        let input =
            record_dispatch_input(&row).ok_or_else(|| invalid("context input is malformed"))?;
        let parent = decode_dreamer_attempt_payload(&row.payload)?.parent_attempt;
        self.require_sibling_result_lineage(parent, row.run_id.as_deref(), &input.context_from)?;
        projection.sibling_result_refs = resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: ContextSpec::excluded(),
                parent: None,
                context_from: input.context_from,
                world_scope: None,
            },
        )?
        .sibling_result_refs;
        Ok(projection)
    }

    /// Runs structural validation before classifying the *direct child's* refusal.
    /// Ancestor, descriptor, settlement and sibling-lineage errors remain errors.
    pub(super) fn propose_context_widen(
        &self,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
    ) -> Result<Option<AgentDispatchOutcome>> {
        let Some(parent_id) = input.parent_attempt else {
            return Ok(None);
        };
        let intent = WidenIntent::new(input, spawn)?;
        validate_context_spec(&intent.spec)?;
        self.require_sibling_result_lineage(
            Some(parent_id),
            input.run_id.as_deref(),
            &spawn.context_from,
        )?;
        // Validate settled refs independently, so a widen cannot hide a bad ref.
        resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: ContextSpec::excluded(),
                parent: None,
                context_from: spawn.context_from.clone(),
                world_scope: None,
            },
        )?;
        let Some(parent) = self.parent_dispatch_input(parent_id)? else {
            return Ok(None);
        };
        let parent_spec = self.effective_context_spec(parent_id, &parent)?;
        let projection = self.resolve_attempt_context(parent_id)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let key = intent.key()?;
        if let Some(bytes) = self.vault.store.vault_meta.get(&wtxn, &key)? {
            let record: WidenRecord = decode(&bytes)?;
            if record.version != 1 || record.request.intent != intent {
                return Err(invalid(
                    "existing widen dedupe key names a different dispatch",
                ));
            }
            return self.widen_outcome(&record).map(Some);
        }
        if validate_spec_narrows(&parent_spec, &intent.spec).is_ok()
            && validate_context_narrows(&projection, &intent.spec).is_ok()
        {
            return Ok(None);
        }
        // A request, not a grant: this transaction contains NO queue or slice write.
        let target = self.dispatchable_definition(&input.target)?;
        let record = WidenRecord {
            version: 1,
            request: WidenRequest {
                intent,
                target_fingerprint: source_content_fingerprint(&target)?.to_hex().to_string(),
                board: self.recorded_parent(parent_id)?,
                parent_spec: parent_spec.clone(),
                widened_spec: widened_parent(
                    &parent_spec,
                    &spawn.context_spec.clone().unwrap_or_default(),
                ),
            },
            landed: None,
        };
        let proposal = record.request.proposal()?;
        self.vault
            .store
            .vault_meta
            .put(&mut wtxn, &key, &json(&record)?)?;
        self.vault
            .store
            .vault_meta
            .put(&mut wtxn, &proposal_key(&proposal.proposal_id)?, &key)?;
        // Same decision ledger and exact consent digest as approve_once. The
        // suggested catastrophe bound can NEVER become a standing grant.
        self.vault.store.append_gate_decision_in_txn(
            &mut wtxn,
            &GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::now(),
                created_at: input.now,
                outcome: "pending".to_owned(),
                reason_codes: vec!["gate.context.propose_widen".to_owned()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".to_owned(),
                actor_ref: Some(parent.target.agent_definition_ref()?.to_hex()),
                content_kind: "consent_grant".to_owned(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: None,
                diff_handle: proposal.consent.effect_digest.as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            },
        )?;
        wtxn.commit()?;
        Ok(Some(AgentDispatchOutcome::ProposedWiden(Box::new(
            proposal,
        ))))
    }

    /// The board above acts on an exact, stored proposal. No caller-supplied
    /// actor, grant flag or replacement descriptor is accepted. The owner
    /// capability alone is insufficient: the board's TASK must prove ownership.
    /// Approval changes only the direct parent's slice and enqueues the child in
    /// the SAME transaction as the exact approve-once consent receipt.
    pub fn approve_context_widen(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &super::ContextWidenProposal,
        now: u64,
    ) -> Result<AgentDispatchOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        // Proposal ids are content hashes, not bearer authority. Find the exact
        // saved intent by its stable index, rejecting forged or edited objects.
        let (key, mut record) = self.stored_widen_proposal(&wtxn, &proposal.proposal_id)?;
        if record.request.proposal()? != *proposal {
            return Err(invalid("widen proposal differs from the stored request"));
        }
        let board = record
            .request
            .board
            .ok_or_else(|| invalid("widen has no provable board above"))?;
        self.require_board_owner(&wtxn, board, owner.actor())?;
        if self.recorded_parent(record.request.intent.parent)? != Some(board) {
            return Err(invalid("widen board is not the immediate board above"));
        }
        if record.landed.is_some() {
            return self.widen_outcome(&record);
        }
        let (input, spawn) = record.request.intent.dispatch(&proposal.proposal_id, now)?;
        self.child_depth_remaining(record.request.intent.parent)?;
        self.require_sibling_result_lineage(
            input.parent_attempt,
            input.run_id.as_deref(),
            &spawn.context_from,
        )?;
        let target = self.dispatchable_definition(&input.target)?;
        if source_content_fingerprint(&target)?.to_hex().as_str()
            != record.request.target_fingerprint
        {
            return Err(invalid("widen target changed since the proposal"));
        }
        let parent_input = self
            .parent_dispatch_input(record.request.intent.parent)?
            .ok_or_else(|| invalid("widen parent is no longer dispatchable lineage"))?;
        // First replay the existing chain; an invalid ancestor is not an offer
        // to repair or widen it. Concurrent approvals serialize on this writer.
        self.resolve_attempt_context(record.request.intent.parent)?;
        if self.effective_context_spec(record.request.intent.parent, &parent_input)?
            != record.request.parent_spec
        {
            return Err(invalid("widen parent slice changed since the proposal"));
        }
        let board_input = self
            .parent_dispatch_input(board)?
            .ok_or_else(|| invalid("widen board has no dispatch input"))?;
        let board_spec = self.effective_context_spec(board, &board_input)?;
        validate_spec_narrows(&board_spec, &record.request.widened_spec)?;
        let widened = resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: record.request.widened_spec.clone(),
                parent: Some(self.resolve_attempt_context(board)?),
                context_from: Vec::new(),
                world_scope: Some(
                    self.dispatchable_definition(&parent_input.target)?
                        .scope
                        .to_world_scope(),
                ),
            },
        )?;
        validate_spec_narrows(&record.request.widened_spec, &record.request.intent.spec)?;
        resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: record.request.intent.spec.clone(),
                parent: Some(widened),
                context_from: spawn.context_from.clone(),
                world_scope: Some(target.scope.to_world_scope()),
            },
        )?;
        // Only the existing authenticated-owner door mints approval. Spending
        // and landing are atomic, so a failed enqueue spends no owner act.
        self.vault
            .approve_once_in_txn(&mut wtxn, owner, proposal.consent.effect_digest)?;
        let authorization = approve_once_authorization_in_txn(
            &self.vault.store,
            &wtxn,
            &proposal.consent.effect_digest,
        )?
        .ok_or_else(|| invalid("board consent did not authorize this exact widening"))?;
        spend_approve_once_in_txn(&self.vault.store, &mut wtxn, &authorization)?;
        let outcome = self.dispatch_in_txn(&mut wtxn, None, input, spawn)?;
        let status = match &outcome {
            AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status) => {
                status
            }
            _ => {
                return Err(invalid("widen landing unexpectedly proposed again"));
            }
        };
        record.landed = Some(status.attempt.id);
        self.vault.store.vault_meta.put(
            &mut wtxn,
            &slice_key(record.request.intent.parent),
            &json(&SliceOverride {
                proposal_id: proposal.proposal_id.clone(),
                board,
                owner: owner.actor().to_hex(),
                spec: record.request.widened_spec.clone(),
            })?,
        )?;
        self.vault
            .store
            .vault_meta
            .put(&mut wtxn, &key, &json(&record)?)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    fn stored_widen_proposal(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &str,
    ) -> Result<(Vec<u8>, WidenRecord)> {
        let key = self
            .vault
            .store
            .vault_meta
            .get(txn, &proposal_key(id)?)?
            .ok_or_else(|| invalid("widen proposal was not issued by this vault"))?;
        if !key.starts_with(super::widen_record::WIDEN_PREFIX)
            || key.len() != super::widen_record::WIDEN_PREFIX.len() + 32
        {
            return Err(invalid("invalid widen intent index"));
        }
        let bytes = self
            .vault
            .store
            .vault_meta
            .get(txn, &key)?
            .ok_or_else(|| invalid("widen proposal intent is missing"))?;
        let record: WidenRecord = decode(&bytes)?;
        if record.version != 1
            || record.request.id()? != id
            || record.request.intent.key()?.as_slice() != key.as_ref()
        {
            return Err(invalid("widen proposal index does not match its request"));
        }
        Ok((key.to_vec(), record))
    }

    fn widen_outcome(&self, record: &WidenRecord) -> Result<AgentDispatchOutcome> {
        match record.landed {
            None => Ok(AgentDispatchOutcome::ProposedWiden(Box::new(
                record.request.proposal()?,
            ))),
            Some(id) => {
                let attempt = AttemptQueue::new(self.vault)
                    .get(id)?
                    .ok_or_else(|| invalid("approved widen dispatch is missing"))?;
                let input = record_dispatch_input(&attempt)
                    .ok_or_else(|| invalid("approved widen dispatch is malformed"))?;
                Ok(AgentDispatchOutcome::Existing(AgentDispatchStatus {
                    attempt,
                    input,
                }))
            }
        }
    }

    pub(super) fn effective_context_spec(
        &self,
        attempt: AttemptId,
        input: &AgentDispatchInput,
    ) -> Result<ContextSpec> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(bytes) = self.vault.store.vault_meta.get(&txn, &slice_key(attempt))? else {
            return Ok(input.context_spec.clone().unwrap_or_default());
        };
        let slice: SliceOverride = decode(&bytes)?;
        self.require_board_owner(&txn, slice.board, EntityId::from_hex(&slice.owner)?)?;
        let (_, record) = self.stored_widen_proposal(&txn, &slice.proposal_id)?;
        drop(txn);
        if self.recorded_parent(attempt)? != Some(slice.board) {
            return Err(invalid("approved slice has a different board lineage"));
        }
        if record.landed.is_none()
            || record.request.intent.parent != attempt
            || record.request.widened_spec != slice.spec
        {
            return Err(invalid("slice has no matching landed board decision"));
        }
        Ok(slice.spec)
    }

    fn recorded_parent(&self, attempt: AttemptId) -> Result<Option<AttemptId>> {
        let row = AttemptQueue::new(self.vault)
            .get(attempt)?
            .ok_or_else(|| invalid("widen lineage attempt is missing"))?;
        self.workflow_authority_parent(decode_dreamer_attempt_payload(&row.payload)?.parent_attempt)
    }

    fn require_board_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        board: AttemptId,
        owner: EntityId,
    ) -> Result<()> {
        let row = AttemptQueue::new(self.vault)
            .get_in_txn(txn, board)?
            .ok_or_else(|| invalid("widen board attempt is missing"))?;
        record_dispatch_input(&row)
            .ok_or_else(|| invalid("widen board is not an agent dispatch"))?;
        let task = row
            .task_ref
            .as_deref()
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or_else(|| invalid("widen board has no authority-bearing TASK"))?;
        let standing = self
            .vault
            .task_authority_state_in(txn, task)?
            .ok_or_else(|| invalid("widen board TASK has no owner proof"))?;
        if standing.cancelled || standing.owner_ref != owner {
            return Err(invalid("authenticated actor does not own the board above"));
        }
        let raw = self
            .vault
            .store
            .entities
            .get(txn, owner.as_bytes())?
            .ok_or_else(|| invalid("board owner is no longer present"))?;
        if crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_PERSON)
            || self.vault.entity_lifecycle_state_in_txn(txn, &owner)?
                != crate::identity_topology::EntityLifecycleState::Active
        {
            return Err(invalid("board owner is no longer an active human"));
        }
        Ok(())
    }
}

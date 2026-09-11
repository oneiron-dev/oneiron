//! The four durable memory writes, search, and the off-record policy that refuses them.

use rmpv::Value;

use crate::code_run::consent;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfDispatchOutcome, SelfEffect, SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall,
    SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult,
};
use crate::error::{Error, Result};
use crate::{ClaimSubject, EdgeKind};

use super::HostSelfDispatcher;
use super::envelope::edge_operation_gate_id;
use crate::error::OffRecordError;

/// Maximum results a first-party `self.memory.search` call can request.
pub const SELF_MEMORY_SEARCH_MAX_RESULTS: usize = 16;

impl HostSelfDispatcher<'_> {
    /// Effect-level off-record policy — the FIRST check on the session path.
    ///
    /// While the bound room is off record, the four durable memory-write
    /// verbs are refused before `write_envelope`, policy/gate evaluation,
    /// transaction acquisition, decision append, ONE-1936's stale-target
    /// guard, or any overlay/base mutation. Off-record is TALK-ONLY: a
    /// durable write is not made acceptable by being made ephemeral, so the
    /// answer is refusal, not redirection.
    ///
    /// The rejection is mode-scoped POLICY, never inferred from where a row
    /// would route: after the same live session flips `OnRecord` the ordinary
    /// verb path is available again to a run that binds after the flip. A run
    /// that was already in flight keeps its run-entry route, whose
    /// `revalidate` refuses the write instead of splitting the record across
    /// the flip.
    ///
    /// The match is exhaustive so a new effect cannot default into either
    /// answer — it has to be ruled on here.
    pub(super) fn enforce_off_record_effect_policy(&self, effect: SelfEffect) -> Result<()> {
        if !self.storage.off_record_policy_active()? {
            return Ok(());
        }
        match effect {
            // Delegation mints a synced TASK entity, so it lands on the
            // durable-record side of the talk-only line with the memory writes.
            SelfEffect::MemoryPutClaim
            | SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
            | SelfEffect::MemoryWriteFixture
            | SelfEffect::TaskDelegate => {
                Err(Error::OffRecord(OffRecordError::OffRecordTalkOnly {
                    session_ref: self.storage.session_ref().unwrap_or_default().to_owned(),
                }))
            }
            // `self.context` stores nothing and reads nothing — a descriptor
            // round-trip has no durable-record side for the talk-only line to
            // protect.
            //
            // The speech family is what TALK-ONLY means: a room that is off
            // record is still a room somebody is speaking in, and its
            // utterances ride the session's own route into the overlay, where
            // they evaporate with it. Refusing them here would make an
            // off-record room mute rather than private.
            SelfEffect::MemorySearch
            | SelfEffect::AskHuman
            | SelfEffect::DestructiveFixture
            | SelfEffect::OutboundFixture
            | SelfEffect::Context
            | SelfEffect::Speak
            | SelfEffect::Think
            | SelfEffect::Express => Ok(()),
        }
    }

    pub(super) fn dispatch_memory_search(
        &self,
        call: SelfMemorySearchCall,
    ) -> Result<SelfDispatchOutcome> {
        let limit = call.limit.min(SELF_MEMORY_SEARCH_MAX_RESULTS);
        let results = self.storage.search_text(&call.query, limit)?;
        Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: call.query,
            results,
        }))
    }

    pub(super) fn dispatch_memory_write_fixture(
        &self,
        call: SelfMemoryWriteFixtureCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryWriteFixture, admission.as_ref())?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .batch()
                .claim_candidate(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )
                .commit()?,
            ExecutorStorage::Session(binding) => {
                binding.session.executor_batch_claim_candidate(
                    &binding.route,
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )?;
            }
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    pub(super) fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryPutClaim, admission.as_ref())?;
        let gate_body = candidate.clone().into_claim_body(&envelope);
        self.check_write_gate(call.id, &gate_body, &envelope, true)?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .put_claim_candidate_without_lexical_query_reconcile(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )?,
            ExecutorStorage::Session(binding) => binding.session.executor_put_claim_candidate(
                &binding.route,
                &call.id,
                candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    pub(super) fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::CodeReviewUnsupportedOperation);
        }
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim, admission.as_ref())?;
        let claim_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Entity(call.old_id),
            Value::Binary(call.new_id.as_bytes().to_vec()),
            &envelope,
        );

        let supersedes_weight =
            EdgeKind::Supersedes
                .default_weight()
                .ok_or(Error::InvariantViolation(
                    "Supersedes edge missing default weight",
                ))?;
        let edge_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Edge {
                source: call.new_id,
                kind: EdgeKind::Supersedes,
                target: call.old_id,
            },
            Value::F32(supersedes_weight),
            &envelope,
        );
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            call.new_id,
            EdgeKind::Supersedes,
            call.old_id,
        )?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.supersede_claim_for_code_run_trap(
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
            )?,
            ExecutorStorage::Session(binding) => binding.session.executor_supersede_claim(
                &binding.route,
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    pub(super) fn dispatch_memory_put_edge(
        &self,
        call: SelfMemoryPutEdgeCall,
    ) -> Result<SelfDispatchOutcome> {
        ensure_public_memory_edge_kind(call.kind)?;
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::CodeReviewUnsupportedOperation);
        }
        let envelope = self.write_envelope(SelfEffect::MemoryPutEdge, admission.as_ref())?;
        let gate_body = self.operation_gate_body(
            SelfEffect::MemoryPutEdge,
            ClaimSubject::Edge {
                source: call.src,
                kind: call.kind,
                target: call.tgt,
            },
            Value::F32(call.weight),
            &envelope,
        );
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, call.src, call.kind, call.tgt)?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.put_edge_for_code_run_trap(
                &call.src,
                call.kind,
                &call.tgt,
                call.weight,
                &envelope,
                gate_id,
                &gate_body,
            )?,
            ExecutorStorage::Session(binding) => binding.session.executor_put_edge(
                &binding.route,
                &call.src,
                call.kind,
                &call.tgt,
                call.weight,
                &envelope,
                gate_id,
                &gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: call.src,
                kind: call.kind,
                tgt: call.tgt,
            },
        ))
    }
}

fn ensure_public_memory_edge_kind(kind: EdgeKind) -> Result<()> {
    match kind {
        EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => Ok(()),
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto
        | EdgeKind::BlockedBy
        // ONE-1608: `blocks` is the L2 code-memory readiness edge. Its
        // dedicated door binds the actor entity to its asserted class and
        // proves acyclicity; a guest `self.memory.put_edge` carries neither,
        // so guest code may not mint readiness dependencies.
        | EdgeKind::Blocks
        // ONE-1541 (CMT-4): the brief-fulfillment pair is structural and its
        // ruled directions are only meaningful written together, after both
        // endpoint classes have been proven. Guest code proves neither and
        // can only ask for one direction at a time, so both bytes land on
        // the refusal side with the rest of the structural kinds.
        | EdgeKind::Fulfills
        | EdgeKind::DischargedBy
        // ONE-1414: `same_as` is structural and its writes belong to the
        // federation coreference door (`put_coreference_link`), which writes
        // the link and its status Claim in ONE transaction under an actor
        // gate. A raw link here would assert identity with no status, no
        // consent surface, and no actor — so it lands on the refusal side
        // with the rest of the structural kinds.
        | EdgeKind::SameAs => Err(Error::InvalidClaimBody(
            "self.memory.put_edge rejects structural edge kinds",
        )),
    }
}

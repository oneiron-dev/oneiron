//! Session-owned typed asks for off-record hook pauses (FIX 10087).
//! The ordinary census validates recipients, the effective question and its
//! digest. Member TASKs, launch holds, fanout and durable ask rows do not
//! exist here. Answers and settlement live in the caller's session keep.

use super::ask_settlement;
use super::ask_types::*;
use crate::EdgeActorClass;
use crate::entity_id::{
    EntityId,
    derived_domains::{TASK_ASK_INTENT, TASK_ASK_ORIGIN},
};
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding};

/// The validated pieces of one session-owned ask.
#[derive(Debug, Clone)]
pub(crate) struct SessionAskParts {
    pub(crate) group_ref: EntityId,
    pub(crate) owner: EntityId,
    pub(crate) requested: TaskAskSpec,
    pub(crate) effective: TaskAskSpec,
    pub(crate) holders: Vec<EntityId>,
    pub(crate) question_digest: [u8; 32],
}

impl Memory<'_> {
    /// Runs the ordinary ask census without minting a group, member TASKs,
    /// a launch hold or any durable work.
    pub(crate) fn session_ask_parts(&self, input: &TaskAskSpec) -> MemoryResult<SessionAskParts> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let actor_origin = EntityId::derive(TASK_ASK_ORIGIN, &[self.actor().as_bytes()])?;
        let group_ref = EntityId::derive(
            TASK_ASK_INTENT,
            &[actor_origin.as_bytes(), input.intent_key.as_bytes()],
        )?;
        let now = self.vault().store.clock.now_recorded_at();
        let census = self.ask_census_in(&txn, input, group_ref, now)?;
        let question_digest =
            ask_settlement::question_digest(self.vault(), &txn, census.question())?
                .ok_or(crate::Error::EntityNotFound)?;
        Ok(census.into_session_parts(group_ref, self.actor(), input, question_digest))
    }
}

/// One session's ask, its answers and its terminal result.
#[derive(Debug, Clone)]
pub(crate) struct SessionAskRecord {
    parts: SessionAskParts,
    evidence: Vec<TaskAskEvidence>,
    result: Option<Box<TaskAskResult>>,
}

impl SessionAskRecord {
    pub(crate) fn new(parts: SessionAskParts) -> Self {
        Self {
            parts,
            evidence: Vec::new(),
            result: None,
        }
    }

    pub(crate) fn receipt(&self, idempotent_replay: bool) -> TaskAskReceipt {
        TaskAskReceipt::new(
            TaskAskHandle {
                group_ref: self.parts.group_ref,
            },
            Vec::new(),
            None,
            idempotent_replay,
            None,
        )
    }

    /// Audience is the asker or an admitted recipient, as on base.
    fn admits(&self, actor: EntityId) -> bool {
        self.parts.owner == actor || self.parts.holders.contains(&actor)
    }

    pub(crate) fn status(&self, actor: EntityId) -> MemoryResult<TaskAskStatus> {
        if !self.admits(actor) {
            return Err(MemoryError::bad_request(
                "ask handle is not addressed to this actor",
            ));
        }
        Ok(match &self.result {
            Some(result) => TaskAskStatus::Settled(result.clone()),
            None => TaskAskStatus::Pending { hold: None },
        })
    }

    /// Admits one recipient's word, idempotently for the same actor and word.
    /// No member TASK, notification, launch or durable background work runs.
    pub(crate) fn answer(
        &mut self,
        actor: EntityId,
        actor_class: EdgeActorClass,
        actor_kind: u8,
        result_kind: u8,
        word: &TaskAskWord,
        word_ref: EntityId,
        now: u64,
    ) -> MemoryResult<TaskAskAnswer> {
        if !self.admits(actor) {
            return Err(MemoryError::bad_request(
                "ask handle is not addressed to this actor",
            ));
        }
        if let Some(existing) = self
            .evidence
            .iter()
            .find(|entry| entry.answer.actor_ref == actor && entry.word == *word)
        {
            return Ok(existing.answer.clone());
        }
        if self.result.is_some() {
            return Err(MemoryError::bad_request("ask is already settled"));
        }
        if let Some(option) = word.option.as_ref()
            && !self.parts.effective.what.options.contains_key(option)
        {
            return Err(MemoryError::bad_request(
                "answer names no option of this ask",
            ));
        }
        let answer = TaskAskAnswer::new(
            self.parts.group_ref,
            actor,
            word.result_ref,
            word_ref,
            actor_kind,
            result_kind,
        );
        let source = if actor_class == EdgeActorClass::Human {
            TaskAskSource::Human
        } else {
            TaskAskSource::ForeignStated
        };
        self.evidence.push(TaskAskEvidence {
            answer: answer.clone(),
            word: word.clone(),
            source,
            person_ref: actor,
            order: self.evidence.len() as u64 + 1,
            reason: TaskAskEvidenceReason::Counted,
            ladder_changed: None,
            soft_confirm: false,
            delegation_grant_ref: None,
        });
        self.result = Some(self.settle(word_ref, now));
        Ok(answer)
    }

    fn settle(&self, reference: EntityId, now: u64) -> Box<TaskAskResult> {
        let responded: std::collections::BTreeSet<EntityId> = self
            .evidence
            .iter()
            .map(|entry| entry.answer.actor_ref)
            .collect();
        let unknown: std::collections::BTreeSet<EntityId> = self
            .parts
            .holders
            .iter()
            .copied()
            .filter(|holder| !responded.contains(holder))
            .collect();
        let first = self
            .evidence
            .first()
            .expect("a settled session ask has a word");
        let decision = match &first.word.option {
            Some(option) => TaskAskDecision::Answer(option.clone()),
            None => TaskAskDecision::First(first.answer.clone()),
        };
        let reason = if unknown.is_empty() {
            TaskAskSettlementReason::AllResponded
        } else {
            TaskAskSettlementReason::FirstWord
        };
        Box::new(TaskAskResult {
            effect_authorization: TaskAskEffectAuthorization::NotEvaluatedByAsk,
            coverage: TaskAskCoverage {
                met: true,
                required: u16::try_from(self.parts.holders.len()).unwrap_or(u16::MAX),
                responded,
                unmet_people: unknown.clone(),
                unknown,
            },
            decision,
            fallback: None,
            evidence: self.evidence.clone(),
            settlement: TaskAskSettlement {
                group_ref: self.parts.group_ref,
                reference,
                revision: self.parts.effective.what.revision,
                at: now,
                cutoff_order: self.evidence.len() as u64,
                reason,
                requested: self.parts.requested.clone(),
                effective: self.parts.effective.clone(),
                base_policy_version: 1,
                electorate: self.parts.holders.iter().copied().collect(),
                question_digest: self.parts.question_digest,
                unmet_sources: Default::default(),
                outcome_answer_ref: None,
                policy_surface: TaskAskSurface::Card,
                link_result_proof: None,
            },
        })
    }
}

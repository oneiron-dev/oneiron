//! The digest's urgent breakthrough (OF-194 L3; ARCH-0026: "urgent
//! breakthrough only when waiting would harm the user's intent").
//!
//! A candidate pairs one live owner's stored stated intent (an Approved,
//! Active, non-stale UserStated `profile.intent` about that owner) with one
//! pending result of an urgent group that owner reads, at the exact bytes of
//! each and the next regular digest's time. The host asks the shared
//! decision ladder whether delivering that result only at the next regular
//! digest would harm the intent, as a job on the Dreamer's maintenance queue
//! ([`DIGEST_ASSESS_FACET`]). Its answer, the full typed receipt kept, rides
//! a second job ([`DIGEST_URGENT_FACET`]), whose record is the witness: a no
//! or an abstain is kept as surely as a yes. Only a yes delivers, and only
//! while the intent and the result are still the bytes the ladder read: that
//! one result goes at once to that owner's inbox through the digest's own
//! screened write, and the regular cadence does not move. A basis that moved
//! is asked anew; a failed or unstaffed ask never reads as harmless or as
//! urgent, and leaves the regular digest as it is. Urgency breaks the
//! digest's cadence only, never quiet hours, a grant or an outbound send.

use rmpv::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::super::invalid;
use super::{DigestProposal, ProactivityCadence, ProactivityDigest};
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerParkCause, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::llm::decision::catalogue::URGENT_DIGEST_HARM;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionQuestion, TypedDecision, cut_text, fit_state,
};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};

/// The maintenance facet one harm question rides; the host's executor asks
/// it on the shared ladder.
pub const DIGEST_ASSESS_FACET: &str = "dreamer.digest.assess";

/// The maintenance facet one witnessed answer rides; its run delivers a yes.
pub const DIGEST_URGENT_FACET: &str = "dreamer.digest.urgent";

/// Why a harm question waits: no host lends this pass the shared ladder. It
/// resumes after the runner's retry delay, never read as an answer.
pub const DIGEST_ASSESS_UNLENT_PARK_REASON: &str =
    "no host lends this pass the decision ladder for an urgent digest question";

/// The stored claim an urgent digest answers to.
const INTENT_PREDICATE: &str = "profile.intent";

/// The payload keys a harm question and a witnessed answer ride under.
const CANDIDATE_KEY: &str = "candidate";
const QUESTION_KEY: &str = "question";
const ASSESSMENT_KEY: &str = "assessment";

/// One stored claim a candidate names, at the exact body bytes it was read
/// at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestVersionRef {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    /// BLAKE3 of the claim's body as stored.
    pub body_hash: [u8; 32],
}

/// The pending result a candidate asks about: a proposal at its digest
/// revision, and the derived group it renders under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestHarmResult {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    /// The proposal's digest revision: BLAKE3 of its body as stored.
    pub revision: [u8; 32],
    pub group: String,
}

/// A factual time the intent's need falls due, with the record that states
/// it: evidence the question reads, never a gate of its own. No producer
/// sets one yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestNeededBefore {
    pub at_unix_secs: u64,
    #[serde(with = "crate::serialize::entity_ref")]
    pub source_ref: EntityId,
    pub source_body_hash: [u8; 32],
}

/// One harm question's basis: whose stated intent, which pending result and
/// how long the regular digest would make it wait. Any change to it is a new
/// candidate, asked anew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestHarmCandidate {
    /// The live owner the intent is about: the only reader an urgent
    /// delivery of this result has.
    #[serde(with = "crate::serialize::entity_ref")]
    pub recipient: EntityId,
    pub intent: DigestVersionRef,
    pub result: DigestHarmResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needed_before: Option<DigestNeededBefore>,
    /// When the next regular digest is due, and the period it was read under.
    pub next_regular_at: u64,
    pub period_secs: u64,
}

impl DigestHarmCandidate {
    /// The candidate's identity under the host's `question` wording: its
    /// queue key, and what a host remembers it asked.
    ///
    /// # Errors
    ///
    /// The candidate does not encode.
    pub fn basis(&self, question: &str) -> Result<[u8; 32]> {
        let json = serde_json::to_vec(self).map_err(|_| invalid())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:digest-harm:v1");
        hasher.update(&(json.len() as u64).to_be_bytes());
        hasher.update(&json);
        hasher.update(question.as_bytes());
        Ok(*hasher.finalize().as_bytes())
    }

    /// The typed question the ladder answers for this candidate, in the
    /// host's wording, keyed by the result's group so its bands learn per
    /// group.
    fn question(&self, wording: &str) -> Result<DecisionQuestion> {
        URGENT_DIGEST_HARM.question(
            &[self.result.group.as_bytes()],
            wording.to_owned(),
            AnswerContract::Noul,
        )
    }
}

/// One queued harm question: its candidate and the host's wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestHarmAsk {
    pub candidate: DigestHarmCandidate,
    pub question: String,
}

impl DigestHarmAsk {
    /// The question an admitted [`DIGEST_ASSESS_FACET`] job carries.
    ///
    /// # Errors
    ///
    /// The job is not a harm question, or its payload does not decode.
    pub fn of_attempt(attempt: &DreamerAdmittedAttempt) -> Result<Self> {
        let payload = &attempt.status.payload;
        if payload.attempt_type != DIGEST_ASSESS_FACET {
            return Err(invalid());
        }
        Ok(Self {
            candidate: json_field(&payload.input, CANDIDATE_KEY)?,
            question: json_field(&payload.input, QUESTION_KEY)?,
        })
    }
}

/// What the ladder reads for one harm question: the typed question, its
/// state, the evidence ids and the Dreamer principal it is asked as.
#[derive(Debug, Clone)]
pub struct DigestHarmJudgeInput {
    pub question: DecisionQuestion,
    pub state: serde_json::Value,
    pub evidence: Vec<EntityId>,
    pub principal: EntityId,
}

/// One witnessed answer to a harm question: the candidate, the ladder's
/// decision with its full receipt, the Dreamer that asked and the job it
/// asked in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrgentDigestAssessment {
    pub candidate: DigestHarmCandidate,
    /// The answer and its receipt: question, rungs, bands, evidence
    /// versions and clock.
    pub decision: TypedDecision,
    #[serde(with = "crate::serialize::entity_ref")]
    pub judge: EntityId,
    #[serde(default)]
    pub assess_attempt: Option<AttemptId>,
    pub assessed_at: u64,
}

impl UrgentDigestAssessment {
    /// Whether the ladder answered yes: waiting would harm the intent. A no,
    /// an abstain and every other answer are not.
    #[must_use]
    pub fn waiting_harms(&self) -> bool {
        matches!(self.decision.answer, DecisionAnswer::Noul(true))
    }
}

impl Vault {
    /// Every urgent digest candidate now: each live owner's stored stated
    /// intent against each pending result of an urgent group that owner
    /// reads, while the cadence allows a breakthrough and the next regular
    /// digest is still ahead. No candidate past those, and none is dropped
    /// for a count.
    ///
    /// # Errors
    ///
    /// A digest row or a pending proposal that does not read.
    pub fn digest_harm_candidates(&self, now: u64) -> Result<Vec<DigestHarmCandidate>> {
        let authority = self.dreamer_authority()?.entity_ref();
        let txn = self.store.env.read_txn()?;
        let cadence = super::load_cadence(self, &txn)?;
        let state = super::load_state(self, &txn)?;
        let presentation = super::load_presentation(self, &txn)?;
        let Some(next) = state
            .last_regular
            .map(|last| last.saturating_add(cadence.period_secs))
        else {
            return Ok(Vec::new());
        };
        if !cadence.urgent_breakthrough || now >= next {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for (group, mut proposal) in
            super::pending_proposals(self, &txn, authority, &state, &cadence, None)?
        {
            if !presentation.urgent_groups.contains(&group) {
                continue;
            }
            // An unresolved private source withholds the item from every
            // view, so no one is asked about it.
            let Some(pins) =
                super::private_sources::digest_private_sources_in(self, &txn, proposal.claim_ref)
            else {
                continue;
            };
            proposal.private_sources = pins;
            results.push((group, proposal));
        }
        let mut candidates = Vec::new();
        if results.is_empty() {
            return Ok(candidates);
        }
        for owner in crate::policy_model::owners_in_txn(self, &txn)? {
            // A result an urgent digest already carried to this owner is no
            // candidate of theirs; another owner's still is (FIX 8952).
            let readable: Vec<_> = results
                .iter()
                .filter(|(_, proposal)| {
                    !state.urgent_seen_by(owner, &proposal.claim_ref.to_hex(), &proposal.revision)
                        && super::private_sources::digest_item_readable_by_in(
                            self, &txn, proposal, owner,
                        )
                })
                .collect();
            if readable.is_empty() {
                continue;
            }
            for intent in stated_intents_in(self, &txn, owner)? {
                for (group, proposal) in &readable {
                    candidates.push(DigestHarmCandidate {
                        recipient: owner,
                        intent,
                        result: DigestHarmResult {
                            claim_ref: proposal.claim_ref,
                            revision: proposal.revision,
                            group: group.clone(),
                        },
                        needed_before: None,
                        next_regular_at: next,
                        period_secs: cadence.period_secs,
                    });
                }
            }
        }
        Ok(candidates)
    }

    /// Queues one harm question on the Dreamer's maintenance queue, keyed by
    /// its basis: the same candidate under the same wording queues once
    /// while it waits.
    ///
    /// # Errors
    ///
    /// The wording is no askable question, or the queue write fails.
    pub fn request_digest_harm_assessment(
        &self,
        candidate: &DigestHarmCandidate,
        question: &str,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        candidate.question(question)?;
        let input = Value::Map(vec![
            json_entry(CANDIDATE_KEY, candidate)?,
            json_entry(QUESTION_KEY, question)?,
        ]);
        let key = format!(
            "{DIGEST_ASSESS_FACET}:{}",
            crate::entity_id::bytes_to_hex_lower(&candidate.basis(question)?)
        );
        DreamerRunnerStore::new(self).enqueue_maintenance(DIGEST_ASSESS_FACET, input, key, now)
    }

    /// What the ladder reads for one admitted harm question, read again from
    /// the stored rows: the intent's words and the result's summary, each
    /// still at the bytes the candidate names and the result still read by
    /// its owner. `None` when the basis moved: no question is asked, and the
    /// candidate for the new basis is asked in its place.
    ///
    /// # Errors
    ///
    /// The job is not a Dreamer harm question, or a row does not read.
    pub fn digest_harm_judge_input(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<Option<DigestHarmJudgeInput>> {
        let ask = DigestHarmAsk::of_attempt(attempt)?;
        let principal = self
            .dreamer_attempt_authority(attempt.status.attempt.id)?
            .ok_or_else(invalid)?
            .actor;
        let candidate = &ask.candidate;
        let txn = self.store.env.read_txn()?;
        let Some(intent) = self.get_claim_in_txn(&txn, &candidate.intent.claim_ref)? else {
            return Ok(None);
        };
        if stated_intent_of(&intent) != Some(candidate.recipient)
            || body_hash_in(self, &txn, candidate.intent.claim_ref)?
                != Some(candidate.intent.body_hash)
        {
            return Ok(None);
        }
        if let Some(needed) = &candidate.needed_before
            && body_hash_in(self, &txn, needed.source_ref)? != Some(needed.source_body_hash)
        {
            return Ok(None);
        }
        let Some(result) = self.get_claim_in_txn(&txn, &candidate.result.claim_ref)? else {
            return Ok(None);
        };
        let mut item = DigestProposal {
            claim_ref: candidate.result.claim_ref,
            revision: candidate.result.revision,
            summary: String::new(),
            private_sources: Vec::new(),
            unverified: false,
        };
        let Some(pins) =
            super::private_sources::digest_private_sources_in(self, &txn, item.claim_ref)
        else {
            return Ok(None);
        };
        item.private_sources = pins;
        if body_hash_in(self, &txn, item.claim_ref)? != Some(item.revision)
            || !super::private_sources::digest_item_readable_by_in(
                self,
                &txn,
                &item,
                candidate.recipient,
            )
        {
            return Ok(None);
        }
        let intent_text = intent.value.as_str().unwrap_or_default().to_owned();
        // The result as the digest would render it.
        let summary = format!("{}: {}", result.predicate, result.value);
        let state = fit_state(intent_text.len().max(summary.len()), |cut| {
            serde_json::json!({
                "intent": cut_text(&intent_text, cut),
                "result": {
                    "group": candidate.result.group,
                    "summary": cut_text(&summary, cut),
                },
                "now": now,
                "next_regular_at": candidate.next_regular_at,
                "wait_secs": candidate.next_regular_at.saturating_sub(now),
                "needed_before": candidate.needed_before.map(|needed| needed.at_unix_secs),
                "cut_at_bytes": cut,
            })
        });
        let mut evidence = vec![candidate.intent.claim_ref, candidate.result.claim_ref];
        evidence.extend(candidate.needed_before.map(|needed| needed.source_ref));
        Ok(Some(DigestHarmJudgeInput {
            question: candidate.question(&ask.question)?,
            state,
            evidence,
            principal,
        }))
    }

    /// Whether the ladder answered the harm question whose basis is `basis`
    /// (FIX 8950): its answer is kept as a witness, so a host never asks it
    /// again, a host that restarted included.
    ///
    /// # Errors
    ///
    /// The digest state does not read.
    pub fn digest_harm_answered(&self, basis: &[u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(super::load_state(self, &txn)?
            .answered_assessments
            .contains(&crate::entity_id::bytes_to_hex_lower(basis)))
    }

    /// Keeps the ladder's answer to one admitted harm question as a witness:
    /// a [`DIGEST_URGENT_FACET`] job carrying the candidate, the decision
    /// with its full receipt, the Dreamer that asked and the asking job, in
    /// that job's run. Every answer is kept, a no and an abstain as surely as
    /// a yes; a replayed ask finds the witness its basis already queued. The
    /// same write marks the basis answered, and keeps the mark only for
    /// bases still current under the same wording (FIX 8950).
    ///
    /// # Errors
    ///
    /// The job is not a Dreamer harm question, or the queue write fails.
    pub fn request_urgent_proactivity_digest(
        &self,
        assess: &DreamerAdmittedAttempt,
        decision: TypedDecision,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let ask = DigestHarmAsk::of_attempt(assess)?;
        let attempt = assess.status.attempt.id;
        let judge = self
            .dreamer_attempt_authority(attempt)?
            .ok_or_else(invalid)?
            .actor;
        let basis = crate::entity_id::bytes_to_hex_lower(&ask.candidate.basis(&ask.question)?);
        let key = format!("{DIGEST_URGENT_FACET}:{basis}");
        let mut current = std::collections::BTreeSet::new();
        for candidate in self.digest_harm_candidates(now)? {
            current.insert(crate::entity_id::bytes_to_hex_lower(
                &candidate.basis(&ask.question)?,
            ));
        }
        let assessment = UrgentDigestAssessment {
            candidate: ask.candidate,
            decision,
            judge,
            assess_attempt: Some(attempt),
            assessed_at: now,
        };
        let input = Value::Map(vec![json_entry(ASSESSMENT_KEY, &assessment)?]);
        self.with_write_txn_grouped(|txn| {
            let mut state = super::load_state(self, &*txn)?;
            state
                .answered_assessments
                .retain(|answered| current.contains(answered));
            state.answered_assessments.insert(basis.clone());
            super::STATE.put(&self.store, txn, &(), &state)?;
            DreamerRunnerStore::new(self).enqueue_kind_in_txn(
                txn,
                super::super::MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: DIGEST_URGENT_FACET.into(),
                    input,
                    parent_attempt: Some(attempt),
                },
                Some(key),
                assess.status.attempt.run_id.clone(),
                now,
            )
        })
    }
}

/// A harm question with no host to ask it waits for one, never judged.
pub(crate) fn unlent_assessment() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Park {
        reason: DIGEST_ASSESS_UNLENT_PARK_REASON.to_owned(),
        cause: DreamerParkCause::Retry,
    }
}

/// Runs one admitted witness: a yes delivers its result at once to its
/// owner's inbox; any other answer delivers nothing, its record the witness.
pub(crate) fn emit_urgent_proactivity_digest(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<ProactivityDigest>> {
    let payload = &attempt.status.payload;
    if payload.attempt_type != DIGEST_URGENT_FACET {
        return Err(invalid());
    }
    let assessment: UrgentDigestAssessment = json_field(&payload.input, ASSESSMENT_KEY)?;
    if !assessment.waiting_harms() {
        return Ok(None);
    }
    vault.assemble_proactivity_digest(
        DigestAudience::Witnessed(&assessment, attempt.status.attempt.id),
        now,
    )
}

/// Who one digest assembly is for.
pub(super) enum DigestAudience<'a> {
    /// The ownerless regular timer projection, every owner's to read.
    Timer,
    /// An authenticated owner's own read, with the urgent assessment its host
    /// passed, if any.
    Owner(
        &'a crate::consent::AuthenticatedOwner,
        Option<&'a UrgentDigestAssessment>,
    ),
    /// A witnessed yes: its intent's owner, resolved from the stored rows,
    /// never from a credential; and the witness job that keeps it.
    Witnessed(&'a UrgentDigestAssessment, AttemptId),
}

impl DigestAudience<'_> {
    /// The reader the digest is addressed to: `Some(None)` for the timer.
    /// `None` when a witnessed answer's basis no longer stands: its intent
    /// moved, or its owner is no live owner; nothing is delivered.
    pub(super) fn recipient_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<Option<EntityId>>> {
        match self {
            Self::Timer => Ok(Some(None)),
            Self::Owner(owner, _) => Ok(Some(Some(super::super::validate_owner_in_txn(
                vault, txn, owner,
            )?))),
            Self::Witnessed(assessment, _) => {
                let candidate = &assessment.candidate;
                let stands = stated_intent_owner_in(vault, txn, candidate.intent.claim_ref)?
                    == Some(candidate.recipient)
                    && body_hash_in(vault, txn, candidate.intent.claim_ref)?
                        == Some(candidate.intent.body_hash)
                    && crate::policy_model::owners_in_txn(vault, txn)?
                        .contains(&candidate.recipient);
                Ok(stands.then_some(Some(candidate.recipient)))
            }
        }
    }

    /// Whether this assembly runs the regular cadence and its asks. A
    /// witnessed delivery never does, so it never moves `last_regular`.
    pub(super) fn regular(&self) -> bool {
        !matches!(self, Self::Witnessed(..))
    }

    /// The witness job a witnessed delivery is kept by (FIX 8955); `None`
    /// for every other assembly.
    pub(super) const fn witness(&self) -> Option<AttemptId> {
        match self {
            Self::Witnessed(_, witness) => Some(*witness),
            Self::Timer | Self::Owner(..) => None,
        }
    }

    /// Whether an urgent answer breaks the cadence for `recipient` before
    /// `next`: the cadence allows it and the answer is a yes. An owner's
    /// own read checks that the intent is still their live stated intent; a
    /// witnessed delivery resolved its owner from it already, and goes only
    /// while the regular digest is still ahead.
    pub(super) fn breaks_through_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        recipient: Option<EntityId>,
        next: Option<u64>,
        now: u64,
        cadence: &ProactivityCadence,
    ) -> Result<bool> {
        let assessment = match self {
            Self::Timer | Self::Owner(_, None) => return Ok(false),
            Self::Owner(_, Some(assessment)) | Self::Witnessed(assessment, _) => assessment,
        };
        let (Some(owner), Some(next)) = (recipient, next) else {
            return Ok(false);
        };
        if !cadence.urgent_breakthrough || !assessment.waiting_harms() {
            return Ok(false);
        }
        Ok(match self {
            Self::Witnessed(..) => now < next,
            _ => {
                stated_intent_owner_in(vault, txn, assessment.candidate.intent.claim_ref)?
                    == Some(owner)
            }
        })
    }

    /// Whether this assembly may carry `proposal`: a witnessed delivery
    /// carries the result it judged, at the revision it judged, alone.
    pub(super) fn carries(&self, proposal: &DigestProposal) -> bool {
        match self {
            Self::Witnessed(assessment, _) => {
                let result = &assessment.candidate.result;
                proposal.claim_ref == result.claim_ref && proposal.revision == result.revision
            }
            Self::Timer | Self::Owner(..) => true,
        }
    }
}

/// The person a claim is the live stated intent of: an Approved, Active,
/// non-stale UserStated `profile.intent` with words, about one entity.
fn stated_intent_of(body: &crate::ClaimBody) -> Option<EntityId> {
    let crate::ClaimSubject::Entity(person) = &body.subject else {
        return None;
    };
    (body.predicate == INTENT_PREDICATE
        && body.source == Some(ClaimSource::UserStated)
        && body
            .value
            .as_str()
            .is_some_and(|text| !text.trim().is_empty())
        && body.approval == ClaimApprovalStatus::Approved
        && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale)
        .then_some(*person)
}

/// [`stated_intent_of`] the stored claim `id`, as the vault reads it.
fn stated_intent_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    Ok(vault
        .get_claim_in_txn(txn, &id)?
        .as_ref()
        .and_then(stated_intent_of))
}

/// Each live stated intent about `owner`, at the bytes it is stored at.
fn stated_intents_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<Vec<DigestVersionRef>> {
    let mut intents = Vec::new();
    for id in crate::ports::ClaimStore::port_claim_list(vault, txn, &owner)? {
        if stated_intent_owner_in(vault, txn, id)? != Some(owner) {
            continue;
        }
        if let Some(body_hash) = body_hash_in(vault, txn, id)? {
            intents.push(DigestVersionRef {
                claim_ref: id,
                body_hash,
            });
        }
    }
    Ok(intents)
}

/// BLAKE3 of the stored claim `id`'s body bytes, as a digest revision is
/// taken; `None` for no stored claim.
fn body_hash_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<[u8; 32]>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let claim = EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM);
    Ok((claim && raw.len() > ENTITY_METADATA_HEADER_LEN)
        .then(|| *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes()))
}

/// One payload entry: `value` as JSON text under `key`.
fn json_entry<T: Serialize + ?Sized>(key: &str, value: &T) -> Result<(Value, Value)> {
    let json = serde_json::to_string(value).map_err(|_| invalid())?;
    Ok((Value::from(key), Value::from(json)))
}

/// The JSON entry `key` of a payload, decoded.
fn json_field<T: DeserializeOwned>(input: &Value, key: &str) -> Result<T> {
    let json = input
        .as_map()
        .and_then(|entries| entries.iter().find(|(name, _)| name.as_str() == Some(key)))
        .and_then(|(_, value)| value.as_str())
        .ok_or_else(invalid)?;
    serde_json::from_str(json).map_err(|_| invalid())
}

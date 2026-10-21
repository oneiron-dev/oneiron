//! Feedback triage custody (OF-420 T1, ARCH-0056 #open-inbox): the sweep that
//! hands each open-inbox note to the Coach's triage, one revision at a time,
//! and the rows that remember what was handed off and what came back.
//!
//! A sweep (`coach.feedback_sweep`) reads the inbox from its stored
//! continuation to the end, a page at a time: a page is a traversal unit,
//! never a total. Each note it has not handed off is retained as a
//! host-written ASSET, gets its own `coach.feedback_triage` job on the
//! Coach's host queue and a handoff row, and moves the continuation, all in
//! one write. A note is named by its source and arrival number; its revision
//! is the BLAKE3 of its canonical encoding, so each revision is handed off
//! once and a revision that already succeeded answers its stored result.
//!
//! The queue stays the authority on job state; these rows hold source and
//! result identity, never a second queue. A revision is acknowledged only
//! when its triage commits a typed result, an empty one included, in the
//! write that files its findings. A triage that fails leaves it
//! unacknowledged, and the next sweep queues it again. Nothing here closes,
//! moderates or deletes a note, and no finding restricts anyone: findings
//! land Proposed in the owner's run tray.
//!
//! The triage runs the SKILL the owner bound. Until one is bound, a sweep
//! fails: it hands off nothing and keeps its continuation.
mod owner;

pub use self::owner::{
    FeedbackTriageBindingRequest, FeedbackTriageChild, FeedbackTriageHold, FeedbackTriageRun,
    FeedbackTriageRunRequest, FeedbackTriageStatus, FeedbackTriageStatusRequest,
};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::FeedbackInboxNote;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// The Coach's feedback sweep: one walk of each source from its
/// continuation, handing each new revision to its own triage job. It rides
/// the Coach's host queue under one fixed dedupe key, so a queued sweep
/// absorbs the next run.
pub const COACH_FEEDBACK_SWEEP_FACET: &str = "coach.feedback_sweep";
/// The Coach's triage of one handed-off revision on the bound skill. Input:
/// `{source, id, revision, evidence}`.
pub const COACH_FEEDBACK_TRIAGE_FACET: &str = "coach.feedback_triage";
/// The open inbox, as a triage source names it.
pub const FEEDBACK_TRIAGE_INBOX_SOURCE: &str = "inbox";
/// Predicate of one Proposed triage finding; its subject is the evidence
/// ASSET of the note it cites.
pub const FEEDBACK_TRIAGE_FINDING_PREDICATE: &str = "coach.feedback_triage.finding";

/// Notes one inbox read takes: a traversal unit, never a total.
const INBOX_PAGE: usize = 256;
/// The domain a note's revision digest is taken under.
const REVISION_DOMAIN: &[u8] = b"oneiron:feedback-triage:revision:v1";
/// The domain a handoff row's key is taken under.
const HANDOFF_DOMAIN: &[u8] = b"oneiron:feedback-triage:handoff:v1";
/// The domain a revision's evidence ASSET id is taken under.
const EVIDENCE_DOMAIN: &[u8] = b"oneiron:feedback-triage:evidence:v1";
/// The `seen` a binding change named is not the current revision.
const STALE_BINDING: &str = "the feedback triage binding changed since it was read";

/// The owner's binding. Key: ().
const BINDING: SideTable<(), FeedbackTriageBinding, Named> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_BINDING);
/// Every revision handed off. Key: [`handoff_key`].
const HANDOFFS: SideTable<[u8; 32], FeedbackTriageHandoff, Named> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_HANDOFF);
/// Each source's continuation. Key: the source's name.
const SOURCES: SideTable<String, FeedbackTriageContinuation, Named> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_SOURCE);

/// One item of one source, at one revision, as the triage names it.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageSourceRef {
    /// The source: [`FEEDBACK_TRIAGE_INBOX_SOURCE`] for the open inbox.
    pub source: String,
    /// The item's id in its source: an inbox note's arrival number, in
    /// decimal.
    pub id: String,
    /// 64 hex: the BLAKE3 of the item's canonical encoding.
    pub revision: String,
}

impl FeedbackTriageSourceRef {
    /// The inbox note `seq` at `revision`.
    fn inbox(seq: u64, revision: &[u8; 32]) -> Self {
        Self {
            source: FEEDBACK_TRIAGE_INBOX_SOURCE.to_owned(),
            id: seq.to_string(),
            revision: crate::entity_id::bytes_to_hex_lower(revision),
        }
    }

    /// The arrival number of the inbox note this names.
    fn inbox_seq(&self) -> Result<u64> {
        if self.source != FEEDBACK_TRIAGE_INBOX_SOURCE {
            return Err(invalid_job());
        }
        let seq: u64 = self.id.parse().map_err(|_| invalid_job())?;
        if seq.to_string() != self.id {
            return Err(invalid_job());
        }
        Ok(seq)
    }
}

/// The skill the triage runs, as the owner bound it. Unset until the owner
/// binds one: no skill is bound for him.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageBinding {
    /// The SKILL entity the triage loads; `None` while none is bound.
    pub skill: Option<EntityId>,
    /// 0 while never set, then one more for each change. A change names
    /// the revision it read.
    pub revision: u64,
    /// Vault seconds of the last change; `None` while never set.
    pub set_at: Option<u64>,
}

/// Where the next sweep resumes one source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageContinuation {
    /// The source.
    pub source: String,
    /// The inbox's last arrival number a sweep handed off or found handed
    /// off; the next sweep reads the notes after it.
    pub after: Option<u64>,
    /// 32 hex: the sweep that last moved it.
    pub sweep: EntityId,
    /// Vault seconds it last moved.
    pub moved_at: u64,
}

/// One revision a sweep handed off.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageHandoff {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// The host-written ASSET holding the exact encoded item the triage
    /// reads; every finding cites it.
    pub evidence: EntityId,
    /// The sweep that handed it off.
    pub sweep: EntityId,
    /// The sweep that queued its current triage job.
    pub queued_by: EntityId,
    /// Its current triage job.
    pub attempt: EntityId,
    /// Vault seconds it was handed off.
    pub handed_off_at: u64,
    /// The committed result; `None` while the revision is unacknowledged.
    pub result: Option<FeedbackTriageResult>,
}

/// One revision's committed triage result. An empty `findings` is a result:
/// the triage read the item and found nothing to propose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageResult {
    /// The triage job that committed it.
    pub attempt: EntityId,
    /// The Proposed findings it filed in the owner's run tray.
    pub findings: Vec<EntityId>,
    /// The SKILL entity that loaded, which may be an open proposal an
    /// exploration trial routed the job to.
    pub skill: EntityId,
    /// The version of the skill that loaded.
    pub skill_version: String,
    /// The model of the rung that answered, fallback included.
    pub served_model: String,
    /// Vault seconds it was committed.
    pub recorded_at: u64,
}

/// One problem the triage skill found in the items it read. It proposes; it
/// closes, rejects or changes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageFinding {
    /// The items it rests on, each as the input named it.
    pub source_refs: Vec<FeedbackTriageSourceRef>,
    /// What went wrong, in the skill's words.
    pub problem: String,
    /// The fix it proposes, if it has one.
    #[serde(default)]
    pub proposed_fix: Option<String>,
}

/// The triage skill's typed answer for one revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageOutput {
    /// Every finding; empty when the item shows nothing to propose.
    pub findings: Vec<FeedbackTriageFinding>,
}

/// What one triage job reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackTriageInput {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// The evidence ASSET the item was retained as.
    pub evidence: EntityId,
    /// The note, read back from the inbox and checked against its revision.
    pub note: FeedbackInboxNote,
    /// The SKILL entity bound now.
    pub skill: EntityId,
}

/// A leased triage job's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackTriageJob {
    /// The revision is acknowledged already: its stored result.
    Acknowledged(FeedbackTriageResult),
    /// The revision waits on this job.
    Pending(Box<FeedbackTriageInput>),
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedbackTriageSweep {
    /// Revisions it handed off for the first time.
    pub handed_off: usize,
    /// Notes whose revision was handed off before.
    pub known: usize,
    /// Unacknowledged revisions it queued again.
    pub requeued: usize,
}

/// A triage job's input as it rides the queue.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobInput {
    source: String,
    id: String,
    revision: String,
    evidence: EntityId,
}

fn invalid_job() -> Error {
    Error::InvalidConfig("invalid feedback triage job".into())
}

fn skill_unbound() -> Error {
    Error::InvalidConfig("no feedback triage skill is bound".into())
}

fn attempt_ref(id: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*id.as_bytes())
}

fn attempt_id(id: &EntityId) -> Result<AttemptId> {
    AttemptId::from_bytes(id.as_bytes())
}

/// A note's canonical encoding, the bytes its evidence keeps, and its
/// revision.
fn inbox_revision(note: &FeedbackInboxNote) -> Result<(Vec<u8>, [u8; 32])> {
    let bytes = rmp_serde::to_vec_named(note)
        .map_err(|_| Error::InvalidConfig("a feedback inbox note did not encode".into()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_DOMAIN);
    hasher.update(&bytes);
    Ok((bytes, *hasher.finalize().as_bytes()))
}

/// A handoff row's key: each part length-prefixed under the domain.
fn handoff_key(source_ref: &FeedbackTriageSourceRef) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HANDOFF_DOMAIN);
    for part in [&source_ref.source, &source_ref.id, &source_ref.revision] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn evidence_id(source_ref: &FeedbackTriageSourceRef) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        EVIDENCE_DOMAIN,
        &[
            source_ref.source.as_bytes(),
            source_ref.id.as_bytes(),
            source_ref.revision.as_bytes(),
        ],
    )
}

fn job_input(source_ref: &FeedbackTriageSourceRef, evidence: EntityId) -> Result<Value> {
    rmpv::ext::to_value(JobInput {
        source: source_ref.source.clone(),
        id: source_ref.id.clone(),
        revision: source_ref.revision.clone(),
        evidence,
    })
    .map_err(|_| invalid_job())
}

fn job_target(input: &Value) -> Result<(FeedbackTriageSourceRef, EntityId)> {
    let job: JobInput = rmpv::ext::from_value(input.clone()).map_err(|_| invalid_job())?;
    Ok((
        FeedbackTriageSourceRef {
            source: job.source,
            id: job.id,
            revision: job.revision,
        },
        job.evidence,
    ))
}

/// The binding as `txn` reads it; the default while never set.
fn binding_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<FeedbackTriageBinding> {
    Ok(BINDING.get(&vault.store, txn, &())?.unwrap_or_default())
}

/// The handoff of `source_ref`, checked against the key it is stored under.
fn handoff_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source_ref: &FeedbackTriageSourceRef,
) -> Result<Option<FeedbackTriageHandoff>> {
    let Some(handoff) = HANDOFFS.get(&vault.store, txn, &handoff_key(source_ref))? else {
        return Ok(None);
    };
    if handoff.source_ref != *source_ref {
        return Err(Error::CorruptedIndex("feedback triage handoff identity"));
    }
    Ok(Some(handoff))
}

/// The handoff a leased triage job's input names, its evidence checked.
pub(crate) fn job_handoff_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
) -> Result<FeedbackTriageHandoff> {
    let (source_ref, evidence) = job_target(&attempt.status.payload.input)?;
    let handoff = handoff_in_txn(vault, txn, &source_ref)?
        .ok_or(Error::CorruptedIndex("feedback triage handoff missing"))?;
    if handoff.evidence != evidence {
        return Err(invalid_job());
    }
    Ok(handoff)
}

/// Acknowledges `handoff`'s revision with `result`, in the write that files
/// the result's findings. A revision acknowledged already, or one whose
/// current job is not the result's, is refused.
pub(crate) fn acknowledge_feedback_triage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    handoff: &FeedbackTriageHandoff,
    result: FeedbackTriageResult,
) -> Result<()> {
    let key = handoff_key(&handoff.source_ref);
    let mut row = handoff_in_txn(vault, txn, &handoff.source_ref)?
        .ok_or(Error::CorruptedIndex("feedback triage handoff missing"))?;
    if row.result.is_some() || row.attempt != result.attempt {
        return Err(invalid_job());
    }
    row.result = Some(result);
    HANDOFFS.put(&vault.store, txn, &key, &row)
}

/// Hands one inbox note's revision to its own triage job in the caller's
/// write: retains the note's exact encoding as a host-written ASSET, queues
/// the job under `sweep`, saves the handoff and moves the inbox
/// continuation. A revision handed off before answers its handoff, with its
/// stored result when it has one, and queues nothing. The flag is true only
/// for a fresh handoff.
pub(crate) fn queue_feedback_triage_revision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sweep: AttemptId,
    run_id: Option<&str>,
    note: &FeedbackInboxNote,
    now: u64,
) -> Result<(FeedbackTriageHandoff, bool)> {
    let (bytes, revision) = inbox_revision(note)?;
    let source_ref = FeedbackTriageSourceRef::inbox(note.seq, &revision);
    let sweep_ref = attempt_ref(sweep)?;
    advance_inbox_in_txn(vault, txn, note.seq, sweep_ref, now)?;
    if let Some(handoff) = handoff_in_txn(vault, txn, &source_ref)? {
        return Ok((handoff, false));
    }
    let evidence = evidence_id(&source_ref)?;
    retain_evidence_in_txn(vault, txn, &evidence, &bytes, note.received_at, now)?;
    let attempt = enqueue_triage_in_txn(vault, txn, &source_ref, evidence, sweep, run_id, now)?;
    let handoff = FeedbackTriageHandoff {
        source_ref,
        evidence,
        sweep: sweep_ref,
        queued_by: sweep_ref,
        attempt,
        handed_off_at: now,
        result: None,
    };
    HANDOFFS.put(
        &vault.store,
        txn,
        &handoff_key(&handoff.source_ref),
        &handoff,
    )?;
    Ok((handoff, true))
}

/// Moves the inbox continuation to `seq`; it never moves back.
fn advance_inbox_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seq: u64,
    sweep: EntityId,
    now: u64,
) -> Result<()> {
    let source = FEEDBACK_TRIAGE_INBOX_SOURCE.to_owned();
    if SOURCES
        .get(&vault.store, txn, &source)?
        .and_then(|continuation| continuation.after)
        .is_some_and(|after| after >= seq)
    {
        return Ok(());
    }
    let continuation = FeedbackTriageContinuation {
        source: source.clone(),
        after: Some(seq),
        sweep,
        moved_at: now,
    };
    SOURCES.put(&vault.store, txn, &source, &continuation)
}

/// Retains `bytes` as the ASSET `evidence`, unless it holds them already.
/// No vector: the evidence is cited, never recalled.
fn retain_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    evidence: &EntityId,
    bytes: &[u8],
    received_at: u64,
    now: u64,
) -> Result<()> {
    if let Some(raw) =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, evidence)?
    {
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("feedback triage evidence header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ASSET
            || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != Some(bytes)
        {
            return Err(Error::CorruptedIndex("feedback triage evidence mismatch"));
        }
        return Ok(());
    }
    vault
        .batch_in()
        .put(
            evidence,
            crate::registry::ENTITY_TYPE_ASSET,
            TimeRange {
                start: received_at,
                end: received_at,
            },
            now,
            bytes,
        )
        .apply(txn)
}

/// Queues one revision's triage job on the Coach's host queue under
/// `sweep`, and answers its attempt. The key holds one live job per
/// revision; a settled job holds none, so a sweep can queue it again.
fn enqueue_triage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source_ref: &FeedbackTriageSourceRef,
    evidence: EntityId,
    sweep: AttemptId,
    run_id: Option<&str>,
    now: u64,
) -> Result<EntityId> {
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_FEEDBACK_TRIAGE_FACET.into(),
            input: job_input(source_ref, evidence)?,
            parent_attempt: Some(sweep),
        },
        Some(format!(
            "{COACH_FEEDBACK_TRIAGE_FACET}:{}:{}:{}",
            source_ref.source, source_ref.id, source_ref.revision
        )),
        run_id.map(str::to_owned),
        now,
    )?;
    let status = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    attempt_ref(status.attempt.id)
}

/// Queues again each unacknowledged revision whose job settled without a
/// result or is gone, under `sweep`. A live job keeps its revision.
fn requeue_unacknowledged(
    vault: &Vault,
    sweep: AttemptId,
    run_id: Option<&str>,
    now: u64,
) -> Result<usize> {
    let handoffs = {
        let txn = vault.store.env.read_txn()?;
        HANDOFFS.scan(&vault.store, &txn)?
    };
    let sweep_ref = attempt_ref(sweep)?;
    let queue = AttemptQueue::new(vault);
    let mut requeued = 0;
    for (key, read) in handoffs {
        if read.result.is_some() {
            continue;
        }
        // Read again under the writer: the job may have acknowledged since.
        let again = vault.with_write_txn_grouped(|txn| {
            let Some(mut handoff) = HANDOFFS.get(&vault.store, txn, &key)? else {
                return Ok(false);
            };
            if handoff.result.is_some() {
                return Ok(false);
            }
            if queue
                .get_in_txn(txn, attempt_id(&handoff.attempt)?)?
                .is_some_and(|record| !record.state.is_terminal())
            {
                return Ok(false);
            }
            handoff.attempt = enqueue_triage_in_txn(
                vault,
                txn,
                &handoff.source_ref,
                handoff.evidence,
                sweep,
                run_id,
                now,
            )?;
            handoff.queued_by = sweep_ref;
            HANDOFFS.put(&vault.store, txn, &key, &handoff)?;
            Ok(true)
        })?;
        requeued += usize::from(again);
    }
    Ok(requeued)
}

impl Vault {
    /// One feedback sweep as the Coach, under a leased `coach.feedback_sweep`
    /// attempt: every inbox note after the continuation, read to the end a
    /// page at a time, each new revision handed off in its own write; then
    /// each unacknowledged revision whose job settled without a result is
    /// queued again. With no skill bound it fails before it reads: it hands
    /// off nothing and the continuation stays.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; no bound skill;
    /// storage errors.
    pub fn run_coach_feedback_sweep(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<FeedbackTriageSweep> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        let mut after = {
            let txn = self.store.env.read_txn()?;
            if binding_in_txn(self, &txn)?.skill.is_none() {
                return Err(skill_unbound());
            }
            SOURCES
                .get(&self.store, &txn, &FEEDBACK_TRIAGE_INBOX_SOURCE.to_owned())?
                .and_then(|continuation| continuation.after)
        };
        let sweep = attempt.status.attempt.id;
        let run_id = attempt.status.attempt.run_id.as_deref();
        let mut report = FeedbackTriageSweep::default();
        loop {
            let notes = self.feedback_inbox(after, INBOX_PAGE)?;
            let Some(last) = notes.last() else {
                break;
            };
            after = Some(last.seq);
            for note in &notes {
                let (_, fresh) = self.with_write_txn_grouped(|txn| {
                    queue_feedback_triage_revision_in_txn(self, txn, sweep, run_id, note, now)
                })?;
                if fresh {
                    report.handed_off += 1;
                } else {
                    report.known += 1;
                }
            }
        }
        report.requeued = requeue_unacknowledged(self, sweep, run_id, now)?;
        Ok(report)
    }

    /// What a leased `coach.feedback_triage` job triages: the note its
    /// revision names, read back from the inbox and checked against that
    /// revision, with its evidence and the skill bound now; or the result
    /// committed for it already.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt or not the
    /// revision's current job; a job naming no handoff, or a note that no
    /// longer matches its revision; no bound skill; storage errors.
    pub fn feedback_triage_job(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<FeedbackTriageJob> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_TRIAGE_FACET)?;
        let (handoff, skill) = {
            let txn = self.store.env.read_txn()?;
            let handoff = job_handoff_in_txn(self, &txn, attempt)?;
            (handoff, binding_in_txn(self, &txn)?.skill)
        };
        if let Some(result) = handoff.result {
            return Ok(FeedbackTriageJob::Acknowledged(result));
        }
        if handoff.attempt != attempt_ref(attempt.status.attempt.id)? {
            return Err(invalid_job());
        }
        let skill = skill.ok_or_else(skill_unbound)?;
        let seq = handoff.source_ref.inbox_seq()?;
        let note = self
            .feedback_inbox(seq.checked_sub(1), 1)?
            .into_iter()
            .next()
            .filter(|note| note.seq == seq)
            .ok_or(Error::CorruptedIndex("feedback triage note missing"))?;
        let (_, revision) = inbox_revision(&note)?;
        if FeedbackTriageSourceRef::inbox(seq, &revision) != handoff.source_ref {
            return Err(Error::CorruptedIndex("feedback triage note revision"));
        }
        Ok(FeedbackTriageJob::Pending(Box::new(FeedbackTriageInput {
            source_ref: handoff.source_ref,
            evidence: handoff.evidence,
            note,
            skill,
        })))
    }
}

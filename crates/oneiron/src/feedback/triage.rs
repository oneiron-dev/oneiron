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
//! unacknowledged, and the next sweep queues it again; one whose evidence
//! ASSET the owner erased is settled erased instead (the `erased` child).
//! Nothing here closes, moderates or deletes a note, and no finding
//! restricts anyone: findings land Proposed in the owner's run tray.
//!
//! Beside the inbox, a sweep walks each GitHub repository the deployment
//! bound (the `github` child): the host reads each page of its listing and
//! hands it here, and the page's items take the same write a note does.
//! Each source keeps its own state, so one that fails holds no other back.
//!
//! The triage runs the SKILL the owner bound. Until one is bound, a sweep
//! completes doing nothing: it reads no source, retains and queues nothing,
//! keeps every continuation and writes no error, and the status shows the
//! `skill_unbound` hold.
//!
//! A revision whose whole request the Coach's window cannot take is triaged
//! in parts (FIX 7549, the `work` child): its job cuts the item into spans
//! that fit, each answered by a part child, then joins the answers in
//! ordered batches that fit, level after level, on synthesis children, every
//! answer kept on the handoff row. The job parks on its children and stays
//! the revision's owner; it alone files the final answer and acknowledges
//! the revision, and nothing is cut away. Its queue input and queueing are
//! the `jobs` child's; the graph's writers are the `work_store` child's.
mod erased;
mod github;
mod jobs;
mod owner;
mod source;
mod work;
mod work_store;

pub(crate) use self::erased::erase_handoff_in_txn;
pub(crate) use self::jobs::job_target;
use self::jobs::{
    attempt_id, attempt_ref, enqueue_triage_in_txn, invalid_job, requeue_unacknowledged,
};
pub(crate) use self::work_store::node_target;

pub use self::github::{
    FEEDBACK_TRIAGE_GITHUB_PREFIX, GithubIssueKind, GithubIssuePage, GithubIssueRevision,
    GithubSweepContinuation,
};
pub use self::owner::{
    FeedbackTriageBindingRequest, FeedbackTriageChild, FeedbackTriageErased, FeedbackTriageHold,
    FeedbackTriageRun, FeedbackTriageRunRequest, FeedbackTriageStatus, FeedbackTriageStatusRequest,
};
pub use self::source::{
    FeedbackTriageSourceError, FeedbackTriageSourceErrorKind, FeedbackTriageSourceFault,
};
pub use self::work::{
    FeedbackTriageNodeAnswer, FeedbackTriagePin, FeedbackTriageSpan, FeedbackTriageSplit,
    FeedbackTriageStep, FeedbackTriageWork, FeedbackTriageWorkNode,
};
pub use self::work_store::{FeedbackTriageNodeInput, FeedbackTriageNodeJob};

use serde::{Deserialize, Serialize};

use super::FeedbackInboxNote;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
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
/// One part of a long revision's item, answered on the bound skill (FIX
/// 7549). Input: `{source, id, revision, evidence, generation, node}`.
pub const COACH_FEEDBACK_TRIAGE_PART_FACET: &str = "coach.feedback_triage_part";
/// One ordered batch of a long revision's answers, joined on the bound
/// skill (FIX 7549). Input as a part's.
pub const COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET: &str = "coach.feedback_triage_synthesis";
/// The owner of the park a long revision's job holds while its part and
/// synthesis children run (a `Signal` park, kept across a restart).
pub const COACH_FEEDBACK_TRIAGE_PARK_OWNER: &str = "coach.feedback_triage";
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
    /// The source: [`FEEDBACK_TRIAGE_INBOX_SOURCE`] for the open inbox,
    /// `github:<owner>/<repo>` for a bound GitHub repository.
    pub source: String,
    /// The item's id in its source, in decimal: an inbox note's arrival
    /// number, or a GitHub item's upstream numeric id.
    pub id: String,
    /// An inbox note's: 64 hex, the BLAKE3 of its canonical encoding. A
    /// GitHub item's: its `updated_at`, `/`, and that 64-hex digest.
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

/// One source's state: where the next sweep resumes it, the walk that last
/// reached its end, and what stopped it last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageContinuation {
    /// The source.
    pub source: String,
    /// The inbox's last arrival number a sweep handed off or found handed
    /// off; the next sweep reads the notes after it. `None` for a GitHub
    /// source.
    pub after: Option<u64>,
    /// 32 hex: the sweep that last moved it, or that wrote it first.
    pub sweep: EntityId,
    /// Vault seconds it last moved, or was first written.
    pub moved_at: u64,
    /// A GitHub source's walk: its generation, next page and last ETag.
    /// `None` for the inbox, and before a GitHub source's first page.
    pub github: Option<GithubSweepContinuation>,
    /// Vault seconds a walk last reached the source's end; `None` while
    /// none has.
    pub completed_at: Option<u64>,
    /// 32 hex: the sweep whose walk last reached it.
    pub completed_by: Option<EntityId>,
    /// What stopped the source's last walk; cleared once a walk moves it or
    /// reaches its end.
    pub error: Option<FeedbackTriageSourceError>,
    /// Vault seconds the source named for a retry: the sweep leaves it
    /// until then.
    pub retry_after: Option<u64>,
    /// The items of the last page written that did not parse and were
    /// skipped, each by its number, id or place on the page; the walk went
    /// on past them (FIX 7631).
    pub skipped: Vec<String>,
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
    /// Vault seconds a sweep or the erase path found its evidence ASSET erased by the owner:
    /// settled, with or without a result, it is never queued again.
    pub erased_at: Option<u64>,
    /// The part and synthesis graph of an item too long for the Coach's
    /// window (FIX 7549), every answer kept; `None` for an item triaged
    /// whole, and once the owner erased its evidence.
    pub work: Option<FeedbackTriageWork>,
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

/// The item one triage job reads, checked against its revision. It is the
/// source's data, never an instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackTriageItem {
    /// An open-inbox note, read back from the inbox.
    Inbox(Box<FeedbackInboxNote>),
    /// A GitHub issue or pull request, read back from its evidence.
    Github(Box<GithubIssueRevision>),
}

impl FeedbackTriageItem {
    /// The item as a long revision's parts cut it (FIX 7549): its JSON, the
    /// encoding the whole-item request carries it in.
    ///
    /// # Errors
    ///
    /// An item that does not encode.
    pub fn text(&self) -> Result<String> {
        match self {
            Self::Inbox(note) => serde_json::to_string(note),
            Self::Github(issue) => serde_json::to_string(issue),
        }
        .map_err(|_| Error::InvalidConfig("a feedback triage item did not encode".into()))
    }
}

/// What one triage job reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackTriageInput {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// The evidence ASSET the item was retained as.
    pub evidence: EntityId,
    /// The item, as its source holds it.
    pub item: FeedbackTriageItem,
    /// The SKILL entity bound now.
    pub skill: EntityId,
    /// The part graph earlier runs of this job left (FIX 7549); `None`
    /// until an item too long for the window is first cut.
    pub work: Option<FeedbackTriageWork>,
}

/// A leased triage job's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackTriageJob {
    /// The revision is acknowledged already: its stored result.
    Acknowledged(FeedbackTriageResult),
    /// The owner erased the revision's evidence ASSET: nothing is triaged.
    Erased,
    /// No skill is bound now: nothing is triaged, as a sweep does nothing,
    /// and the revision stays unacknowledged for the next bound sweep to
    /// queue again (FIX 7627).
    Unbound,
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

/// Refuses `output` unless each finding cites only `own`, the item it was
/// given, and names a problem: what the filing writer and each part or
/// synthesis answer (FIX 7549) both hold to.
pub(crate) fn check_feedback_triage_findings(
    output: &FeedbackTriageOutput,
    own: &FeedbackTriageSourceRef,
) -> Result<()> {
    if output.findings.iter().any(|finding| {
        finding.problem.trim().is_empty()
            || finding.source_refs.is_empty()
            || finding.source_refs.iter().any(|cited| cited != own)
    }) {
        return Err(Error::InvalidConfig(
            "a feedback triage finding cites only the note it was given and names a problem".into(),
        ));
    }
    Ok(())
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
/// current job is not the result's, is refused, and so is one whose
/// evidence the owner erased, so the write rolls back (`Error::Refused`).
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
    erased::refuse_erased_in_txn(vault, txn, &row)?;
    row.result = Some(result);
    HANDOFFS.put(&vault.store, txn, &key, &row)
}

/// One revision as its source read it: its name, the exact bytes its
/// evidence keeps, and when the vault received it.
struct Revision<'a> {
    source_ref: FeedbackTriageSourceRef,
    bytes: &'a [u8],
    received_at: u64,
}

/// Hands one inbox note's revision to its own triage job in the caller's
/// write (`hand_off_revision_in_txn`) and moves the inbox continuation.
pub(crate) fn queue_feedback_triage_revision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sweep: AttemptId,
    run_id: Option<&str>,
    note: &FeedbackInboxNote,
    now: u64,
) -> Result<(FeedbackTriageHandoff, bool)> {
    let (bytes, revision) = inbox_revision(note)?;
    advance_inbox_in_txn(vault, txn, note.seq, attempt_ref(sweep)?, now)?;
    let revision = Revision {
        source_ref: FeedbackTriageSourceRef::inbox(note.seq, &revision),
        bytes: &bytes,
        received_at: note.received_at,
    };
    hand_off_revision_in_txn(vault, txn, sweep, run_id, revision, now)
}

/// The write every source's revision takes, in the caller's transaction:
/// retains the item's exact encoding as a host-written ASSET, queues its
/// triage job under `sweep` and saves the handoff. A revision handed off
/// before answers its handoff, with its stored result when it has one, and
/// queues nothing. The flag is true only for a fresh handoff.
fn hand_off_revision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sweep: AttemptId,
    run_id: Option<&str>,
    revision: Revision<'_>,
    now: u64,
) -> Result<(FeedbackTriageHandoff, bool)> {
    let Revision {
        source_ref,
        bytes,
        received_at,
    } = revision;
    if let Some(handoff) = handoff_in_txn(vault, txn, &source_ref)? {
        return Ok((handoff, false));
    }
    let sweep_ref = attempt_ref(sweep)?;
    let evidence = evidence_id(&source_ref)?;
    retain_evidence_in_txn(vault, txn, &evidence, bytes, received_at, now)?;
    let attempt = enqueue_triage_in_txn(vault, txn, &source_ref, evidence, sweep, run_id, now)?;
    let handoff = FeedbackTriageHandoff {
        source_ref,
        evidence,
        sweep: sweep_ref,
        queued_by: sweep_ref,
        attempt,
        handed_off_at: now,
        result: None,
        erased_at: None,
        work: None,
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
    let mut row = source::source_row_in_txn(vault, txn, FEEDBACK_TRIAGE_INBOX_SOURCE, sweep, now)?;
    if row.after.is_some_and(|after| after >= seq) {
        return Ok(());
    }
    row.after = Some(seq);
    row.sweep = sweep;
    row.moved_at = now;
    SOURCES.put(&vault.store, txn, &row.source, &row)
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
        let raw = vault.materialized_row_in_txn(&*txn, evidence, raw)?;
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

/// Walks the inbox from `after` to its end, a page at a time, each note's
/// revision handed off in its own write.
fn sweep_inbox(
    vault: &Vault,
    sweep: AttemptId,
    run_id: Option<&str>,
    mut after: Option<u64>,
    now: u64,
    report: &mut FeedbackTriageSweep,
) -> Result<()> {
    loop {
        let notes = vault.feedback_inbox(after, INBOX_PAGE)?;
        let Some(last) = notes.last() else {
            return Ok(());
        };
        after = Some(last.seq);
        for note in &notes {
            let (_, fresh) = vault.with_write_txn_grouped(|txn| {
                queue_feedback_triage_revision_in_txn(vault, txn, sweep, run_id, note, now)
            })?;
            if fresh {
                report.handed_off += 1;
            } else {
                report.known += 1;
            }
        }
    }
}

/// The inbox note `source_ref` names, read back from the inbox and checked
/// against its revision.
fn inbox_note(vault: &Vault, source_ref: &FeedbackTriageSourceRef) -> Result<FeedbackInboxNote> {
    let seq = source_ref.inbox_seq()?;
    let note = vault
        .feedback_inbox(seq.checked_sub(1), 1)?
        .into_iter()
        .next()
        .filter(|note| note.seq == seq)
        .ok_or(Error::CorruptedIndex("feedback triage note missing"))?;
    let (_, revision) = inbox_revision(&note)?;
    if FeedbackTriageSourceRef::inbox(seq, &revision) != *source_ref {
        return Err(Error::CorruptedIndex("feedback triage note revision"));
    }
    Ok(note)
}

impl Vault {
    /// One feedback sweep's inbox walk as the Coach, under a leased
    /// `coach.feedback_sweep` attempt: every inbox note after the
    /// continuation, read to the end a page at a time, each new revision
    /// handed off in its own write. The inbox's row then records the walk
    /// that reached its end, or that an engine error stopped it. Each
    /// unacknowledged revision of any source whose job settled without a
    /// result is then queued again, or settled erased once the owner erased
    /// its evidence. With no skill bound it completes doing nothing: it
    /// reads, retains, queues and writes nothing, and every continuation
    /// stays. The host walks each bound GitHub source beside it
    /// ([`Self::feedback_triage_source`]).
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; storage errors.
    pub fn run_coach_feedback_sweep(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<FeedbackTriageSweep> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        let after = {
            let txn = self.store.env.read_txn()?;
            if binding_in_txn(self, &txn)?.skill.is_none() {
                return Ok(FeedbackTriageSweep::default());
            }
            SOURCES
                .get(&self.store, &txn, &FEEDBACK_TRIAGE_INBOX_SOURCE.to_owned())?
                .and_then(|continuation| continuation.after)
        };
        let sweep = attempt.status.attempt.id;
        let run_id = attempt.status.attempt.run_id.as_deref();
        let sweep_ref = attempt_ref(sweep)?;
        let mut report = FeedbackTriageSweep::default();
        let walked = sweep_inbox(self, sweep, run_id, after, now, &mut report);
        // The inbox keeps its own state, as each GitHub source does.
        let marked =
            source::update_source_row(self, FEEDBACK_TRIAGE_INBOX_SOURCE, sweep_ref, now, |row| {
                if walked.is_ok() {
                    row.completed_at = Some(now);
                    row.completed_by = Some(sweep_ref);
                    row.error = None;
                } else {
                    row.error = Some(FeedbackTriageSourceError {
                        kind: FeedbackTriageSourceErrorKind::Engine,
                        status: None,
                        sweep: sweep_ref,
                        at: now,
                    });
                }
            });
        // Every source's revisions are queued again, whatever stopped the
        // inbox.
        let requeued = requeue_unacknowledged(self, sweep, run_id, now);
        walked?;
        marked?;
        report.requeued = requeued?;
        Ok(report)
    }
}

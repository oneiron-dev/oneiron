//! FIX6 code-fix exports (DEC-0005 #world-privacy-p8-tier2). Only two things
//! leave a vault for code fixes: the Coach's invented example of a failure (a
//! short general note and a made-up conversation that fails the same way,
//! verified by replay inside the vault, checked by the in-vault scrubber, and
//! sharing no verbatim span with the real chat), and the fixed or not-fixed
//! result of shadow-replaying a candidate fix inside the vault against the
//! real failure. Real chat text, and any id or digest of it, never leaves.
//!
//! Both follow the tier-1 participation switch
//! ([`FailureSignalConfig::exports`](crate::config::failure_signals::FailureSignalConfig::exports)):
//! automatic on Managed, off by default on SelfHost and Oss. A failure that
//! touched a private world sends its tier-1 counts only. Training stays a
//! separate opt-in.
//!
//! The replay runner and the scrubber are the host's: the Coach's model turn
//! and a candidate's build run there, inside the vault's boundary. Neither
//! has a default, and a missing or undecided one withholds the record.
//!
//! The vault reads the real failure itself, never from the caller: the
//! failing agent's instructions, the briefing its dispatch carried and the
//! task it ran ([`FailureSource`]), and every world those touched. A failure
//! is a failure-ladder case or a blocked report ([`CodeFixSource`]). A report
//! whose run is no agent dispatch's attempt reads the source its run's host
//! kept with it (FIX 2343); one whose run never gave this engine a model
//! request has no replay. The replay sends the request the failing call sent
//! when the vault kept it (FIX 1662, `exact`).

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use super::FailureClassV1;
use super::verbatim::shares_verbatim_span;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::batch::secret_scan::scan_joined_text;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::bytes_to_hex_lower;
use crate::failure_ladder::{BlockedReportRef, HealerCase, failure_case_ref, healer_case_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

mod exact;
mod queue;
mod subject;
pub(crate) use self::exact::exact_replay_request;
pub use self::exact::{ExactReplayRequest, ReplayFidelity};
pub(super) use self::queue::{
    CodeFixShare, ack_code_fix_records_in_txn, code_fix_still_eligible_in,
};
pub(crate) use self::subject::dispatch_worlds_in;
use self::subject::{SubjectFailure, blocked_source_failure_in};

pub const CODE_FIX_RECORD_VERSION: u16 = 1;
pub const CODE_FIX_MAX_NOTE_BYTES: usize = 1024;
pub const CODE_FIX_MAX_MESSAGES: usize = 32;
pub const CODE_FIX_MAX_MESSAGE_BYTES: usize = 4096;

/// Sealed records waiting for the host to deliver them, with the worlds each
/// failure touched (local only). A record stays until the host acks its
/// delivery. Key: id16, the record's public id.
const QUEUE: SideTable<[u8; 16], QueuedCodeFix, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_CODE_FIX);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventedRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedMessage {
    pub role: InventedRole,
    pub text: String,
}

/// What the Coach drafted for one failure. The door decides whether it
/// leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventedExampleDraft {
    pub failure_class: FailureClassV1,
    /// A short general note on the failure.
    pub note: String,
    /// A made-up conversation that fails the same way.
    pub conversation: Vec<InventedMessage>,
}

/// One candidate fix the host shadow-replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFix {
    /// The host's name for the candidate: a build, patch or skill revision.
    pub candidate_id: String,
    /// The invented example this result goes beside, when one left.
    pub example_id: Option<String>,
    pub failure_class: FailureClassV1,
}

/// The real failure as the vault holds it: the failing agent's
/// instructions, the briefing its dispatch carried and the task it ran. A
/// replay sends the request the failing call sent when the vault kept it
/// ([`ExactReplayRequest`], FIX 1662), and rebuilds the call from these when
/// it did not. None of it leaves the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSource {
    pub instructions: String,
    pub briefing: Option<String>,
    pub task: Option<String>,
}

/// What a code fix is for (OF-380): a failure-ladder case, or a blocked
/// report the Coach filed a heal for with no failed case behind it. Each door
/// checks that it still stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeFixSource {
    /// A durable failed case, by its ref.
    Case { case_ref: String },
    /// A blocked report, by its receipt, and the durable run that filed it,
    /// if it had one. A pumped agent's run id is its attempt's id.
    Blocked {
        receipt: EntityId,
        run: Option<EntityId>,
    },
}

/// What a code fix's source stands on.
pub(crate) struct CodeFixSubject {
    /// The failure-ladder case: the one a fix follows, or a blocked report's
    /// run's failed case, which left its code fix to the report's.
    pub(crate) case: Option<HealerCase>,
    /// The failure's blocked reports.
    pub(crate) reports: Vec<BlockedReportRef>,
    /// The real failure, as far as the vault can read it.
    pub(crate) failure: SubjectFailure,
}

impl FailureSource {
    /// Every text of it that is not blank, for the verbatim guard.
    fn texts(&self) -> Vec<String> {
        std::iter::once(self.instructions.as_str())
            .chain(self.briefing.as_deref())
            .chain(self.task.as_deref())
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedFailureExample {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub example_id: String,
    pub failure_class: FailureClassV1,
    pub note: String,
    pub conversation: Vec<InventedMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixOutcome {
    Fixed,
    NotFixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFixResult {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub result_id: String,
    pub candidate_id: String,
    pub example_id: Option<String>,
    pub failure_class: FailureClassV1,
    pub outcome: FixOutcome,
}

/// The only shapes a code-fix export takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeFixExport {
    InventedExample(InventedFailureExample),
    FixResult(CandidateFixResult),
}

impl CodeFixExport {
    /// The record's public id, which [`Vault::ack_code_fix_records`] takes.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::InventedExample(example) => &example.example_id,
            Self::FixResult(result) => &result.result_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRun {
    Reproduced,
    NotReproduced,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowRun {
    Fixed,
    NotFixed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubRun {
    Clean,
    Flagged,
    Unavailable,
}

/// The host's replay runner, inside the vault's boundary. Every effect of a
/// replay stays in it: no tool call leaves and nothing is written.
pub trait CodeFixReplay {
    /// Replays the invented conversation: does it fail the way `failure` did?
    fn reproduces(
        &self,
        failure: &FailureSource,
        example: &InventedExampleDraft,
    ) -> Result<ReplayRun>;
    /// Shadow-replays `candidate_id` against the real `failure`.
    fn shadow_replay(&self, failure: &FailureSource, candidate_id: &str) -> Result<ShadowRun>;
}

/// The host's in-vault scrubber. It judges the text and changes none of it.
pub trait ExportScrubber {
    fn scrub(&self, text: &str) -> Result<ScrubRun>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFixWithheld {
    /// This deployment does not export.
    NotEligible,
    /// No durable failed case, or blocked report its run filed, by that
    /// source.
    UnknownCase,
    /// The failure touched a private world, or one whose privacy is unknown:
    /// its tier-1 counts are all that leaves.
    PrivateWorld,
    /// The vault holds no text of the failure: no instructions, briefing
    /// or task.
    SourceUnavailable,
    /// The draft or candidate is out of shape.
    Malformed,
    /// The example copies a span of the real chat.
    VerbatimSpan,
    /// The example carries a credential shape.
    Credential,
    /// The scrubber flagged the example or could not judge it.
    Scrubber,
    /// The invented conversation does not fail the same way.
    NotReproduced,
    /// The host has no replay for this case.
    ReplayUnavailable,
    /// The Coach drafted no example for it.
    NotDrafted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CodeFixVerdict {
    /// Sealed and waiting for [`Vault::pending_code_fix_records`]; `id` is
    /// the record's public id.
    Queued {
        id: String,
    },
    Withheld {
        reason: CodeFixWithheld,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedCodeFix {
    worlds: Vec<EntityId>,
    record: CodeFixExport,
}

/// A record a door sealed and did not queue. Its caller queues it with
/// [`queue_sealed_in_txn`] in the write that keeps what the record reports,
/// so a crash leaves neither half alone.
pub(crate) struct SealedCodeFix {
    key: [u8; 16],
    row: QueuedCodeFix,
}

/// A door's verdict before anything is queued: `Queued` under the id its
/// sealed record carries, or `Withheld` with no record.
pub(crate) type Sealing = (CodeFixVerdict, Option<SealedCodeFix>);

fn withheld(reason: CodeFixWithheld) -> Result<Sealing> {
    Ok((CodeFixVerdict::Withheld { reason }, None))
}

/// One record sealed under a fresh random id.
fn seal(worlds: Vec<EntityId>, record: impl FnOnce(String) -> CodeFixExport) -> Sealing {
    let mut key = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut key);
    let id = bytes_to_hex_lower(&key);
    let row = QueuedCodeFix {
        worlds,
        record: record(id.clone()),
    };
    (
        CodeFixVerdict::Queued { id },
        Some(SealedCodeFix { key, row }),
    )
}

/// Queues `sealed` in `txn`, if its source still stands there.
pub(crate) fn queue_sealed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &CodeFixSource,
    sealed: SealedCodeFix,
) -> Result<CodeFixVerdict> {
    if code_fix_subject_in(vault, txn, source)?.is_none() {
        return Ok(CodeFixVerdict::Withheld {
            reason: CodeFixWithheld::UnknownCase,
        });
    }
    QUEUE.put(&vault.store, txn, &sealed.key, &sealed.row)?;
    Ok(CodeFixVerdict::Queued {
        id: bytes_to_hex_lower(&sealed.key),
    })
}

impl Vault {
    /// Seals the Coach's invented example of the failure `source` names for
    /// export. The vault reads the real failure itself; the example may copy
    /// no span of it. Every check runs before the record is queued, and the
    /// first that fails withholds it.
    pub fn prepare_invented_example(
        &self,
        source: &CodeFixSource,
        draft: InventedExampleDraft,
        replay: &dyn CodeFixReplay,
        scrubber: &dyn ExportScrubber,
    ) -> Result<CodeFixVerdict> {
        let sealing = self.seal_invented_example(source, draft, replay, scrubber)?;
        self.queue_sealing(source, sealing)
    }

    /// [`Vault::prepare_invented_example`] short of queueing: the caller
    /// queues the sealed record.
    pub(crate) fn seal_invented_example(
        &self,
        source: &CodeFixSource,
        draft: InventedExampleDraft,
        replay: &dyn CodeFixReplay,
        scrubber: &dyn ExportScrubber,
    ) -> Result<Sealing> {
        use CodeFixWithheld as W;
        if !self.config.failure_signals.exports() {
            return withheld(W::NotEligible);
        }
        if !draft_in_shape(&draft) {
            return withheld(W::Malformed);
        }
        self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let Some(subject) = code_fix_subject_in(self, &txn, source)? else {
            return withheld(W::UnknownCase);
        };
        let (failure, worlds) = match subject.failure.read() {
            Ok(read) => read,
            Err(reason) => return withheld(reason),
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !all_public(&fold, &worlds) {
            return withheld(W::PrivateWorld);
        }
        drop(txn);
        let sources = failure.texts();
        if sources.is_empty() {
            return withheld(W::SourceUnavailable);
        }

        let joined = std::iter::once(draft.note.as_str())
            .chain(draft.conversation.iter().map(|m| m.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        if shares_verbatim_span(&sources, &joined) {
            return withheld(W::VerbatimSpan);
        }
        drop(sources);
        let credential = std::iter::once(draft.note.as_str())
            .chain(draft.conversation.iter().map(|m| m.text.as_str()))
            .chain(std::iter::once(joined.as_str()))
            .any(|text| scan_joined_text(text).is_some());
        if credential {
            return withheld(W::Credential);
        }
        if scrubber.scrub(&joined)? != ScrubRun::Clean {
            return withheld(W::Scrubber);
        }
        match replay.reproduces(&failure, &draft)? {
            ReplayRun::Reproduced => {}
            ReplayRun::NotReproduced => return withheld(W::NotReproduced),
            ReplayRun::Unavailable => return withheld(W::ReplayUnavailable),
        }
        let InventedExampleDraft {
            failure_class,
            note,
            conversation,
        } = draft;
        Ok(seal(worlds, |id| {
            CodeFixExport::InventedExample(InventedFailureExample {
                version: CODE_FIX_RECORD_VERSION,
                example_id: id,
                failure_class,
                note,
                conversation,
            })
        }))
    }

    /// Seals the fixed or not-fixed result of shadow-replaying one candidate
    /// against the real failure `source` names. A replay the host could not
    /// run emits nothing, never a `NotFixed`.
    pub fn record_candidate_fix_result(
        &self,
        source: &CodeFixSource,
        candidate: CandidateFix,
        replay: &dyn CodeFixReplay,
    ) -> Result<CodeFixVerdict> {
        let sealing = self.seal_candidate_fix_result(source, candidate, replay)?;
        self.queue_sealing(source, sealing)
    }

    /// [`Vault::record_candidate_fix_result`] short of queueing: the caller
    /// queues the sealed record.
    pub(crate) fn seal_candidate_fix_result(
        &self,
        source: &CodeFixSource,
        candidate: CandidateFix,
        replay: &dyn CodeFixReplay,
    ) -> Result<Sealing> {
        use CodeFixWithheld as W;
        if !self.config.failure_signals.exports() {
            return withheld(W::NotEligible);
        }
        // Rule 5: the candidate's token names its pin whole (an engine
        // patch's two digests), measured, never cut.
        let _ = self.measure_limit(
            crate::limit_ask::EngineLimit::MaintenanceTextBytes,
            candidate.candidate_id.len() as u64,
        );
        if !candidate_in_shape(&candidate) {
            return withheld(W::Malformed);
        }
        let txn = self.store.env.read_txn()?;
        let Some(subject) = code_fix_subject_in(self, &txn, source)? else {
            return withheld(W::UnknownCase);
        };
        let (failure, worlds) = match subject.failure.read() {
            Ok(read) => read,
            Err(reason) => return withheld(reason),
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !all_public(&fold, &worlds) {
            return withheld(W::PrivateWorld);
        }
        drop(txn);
        let outcome = match replay.shadow_replay(&failure, &candidate.candidate_id)? {
            ShadowRun::Fixed => FixOutcome::Fixed,
            ShadowRun::NotFixed => FixOutcome::NotFixed,
            ShadowRun::Unavailable => return withheld(W::ReplayUnavailable),
        };
        let CandidateFix {
            candidate_id,
            example_id,
            failure_class,
        } = candidate;
        Ok(seal(worlds, |id| {
            CodeFixExport::FixResult(CandidateFixResult {
                version: CODE_FIX_RECORD_VERSION,
                result_id: id,
                candidate_id,
                example_id,
                failure_class,
                outcome,
            })
        }))
    }

    /// Queues a door's sealed record in a write of its own, if its source
    /// still stands at commit.
    fn queue_sealing(
        &self,
        source: &CodeFixSource,
        (verdict, sealed): Sealing,
    ) -> Result<CodeFixVerdict> {
        let Some(sealed) = sealed else {
            return Ok(verdict);
        };
        self.with_write_txn_grouped(|txn| queue_sealed_in_txn(self, txn, source, sealed))
    }
}

/// The durable case and its attempt, while that attempt stands failed.
pub(crate) fn failed_case_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    case_ref: &str,
) -> Result<Option<(HealerCase, AttemptRecord)>> {
    let Some(case) = healer_case_in_txn(vault, txn, case_ref)? else {
        return Ok(None);
    };
    let Some(attempt) = AttemptQueue::new(vault).get_in_txn(txn, case.failing_attempt_id)? else {
        return Ok(None);
    };
    if attempt.state != AttemptState::Failed {
        return Ok(None);
    }
    Ok(Some((case, attempt)))
}

/// What `source` stands on, while it stands: a case while its attempt
/// stands failed; a blocked report while its run's filing of it is on record
/// (or, with no durable run, while the Coach's heal of it is), with the
/// run's case and that case's reports joined on while the run's attempt
/// stands failed. A report whose run is no agent dispatch's attempt reads
/// the source its host kept with it (FIX 2343). `None` once it does not.
pub(crate) fn code_fix_subject_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &CodeFixSource,
) -> Result<Option<CodeFixSubject>> {
    match source {
        CodeFixSource::Case { case_ref } => {
            let Some((case, attempt)) = failed_case_in(vault, txn, case_ref)? else {
                return Ok(None);
            };
            let failure = failure_source_in(vault, txn, case.task_ref.as_deref(), &attempt)?;
            Ok(Some(CodeFixSubject {
                reports: case.blocked_reports.clone(),
                case: Some(case),
                failure: failure.map_or(SubjectFailure::Unproved, |(failure, worlds)| {
                    SubjectFailure::Read(failure, worlds)
                }),
            }))
        }
        CodeFixSource::Blocked { receipt, run } => {
            let stands = match run {
                Some(run) => {
                    crate::self_heal::blocked_reports::filed_by_run_in(vault, txn, *run, *receipt)?
                }
                None => crate::self_heal::blocked_reports::settled_in_txn(vault, txn, receipt)?
                    .is_some(),
            };
            if !stands {
                return Ok(None);
            }
            let attempt = match run {
                Some(run) => AttemptQueue::new(vault)
                    .get_in_txn(txn, AttemptId::from_bytes(run.as_bytes())?)?
                    .filter(|attempt| dispatch_input(attempt).is_some()),
                None => None,
            };
            let reports = vec![BlockedReportRef {
                receipt_ref: receipt.to_hex(),
            }];
            // A run that is no agent dispatch's attempt (none, a standalone
            // run, an MCP run) replays from what its host kept (FIX 2343).
            let Some(attempt) = attempt else {
                return Ok(Some(CodeFixSubject {
                    case: None,
                    reports,
                    failure: blocked_source_failure_in(vault, txn, receipt)?,
                }));
            };
            let id = attempt.id;
            let failure = failure_source_in(vault, txn, attempt.task_ref.as_deref(), &attempt)?;
            // A failed case on the run left its own code fix to this report's
            // (OF-380): its ladder class and evidence join the report here.
            let case = failed_case_in(vault, txn, &failure_case_ref(id))?.map(|(case, _)| case);
            let mut reports = reports;
            for report in case.iter().flat_map(|case| &case.blocked_reports) {
                if !reports.contains(report) {
                    reports.push(report.clone());
                }
            }
            Ok(Some(CodeFixSubject {
                case,
                reports,
                failure: failure.map_or(SubjectFailure::Unproved, |(failure, worlds)| {
                    SubjectFailure::Read(failure, worlds)
                }),
            }))
        }
    }
}

/// The real failure, and every world it touched: the failing dispatch's
/// scope and the world of its task `task_ref` (base reality for a row in
/// none). `None` when the attempt is no agent dispatch this can read, or a
/// world cannot be proved. A task row that is gone leaves nothing to read.
fn failure_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: Option<&str>,
    attempt: &AttemptRecord,
) -> Result<Option<(FailureSource, Vec<EntityId>)>> {
    use crate::ports::EntityStore;
    let base = crate::claim::base_world_id();
    let Some(input) = dispatch_input(attempt) else {
        return Ok(None);
    };
    let mut worlds = vec![input.scope.and_then(|scope| scope.world).unwrap_or(base)];
    let mut task = None;
    if let Some(raw) = task_ref {
        let Ok(task_ref) = EntityId::from_hex(raw) else {
            return Ok(None);
        };
        if let Some(row) = vault.port_entity_get(txn, &task_ref)? {
            let Some(world) = crate::federation::record_scope::record_world_in(
                &vault.store,
                txn,
                task_ref,
                row.entity_type,
                &row.body,
            )?
            else {
                return Ok(None);
            };
            worlds.push(world.unwrap_or(base));
            task = crate::task_verb::task_text_in(vault, txn, task_ref)?;
        }
    }
    worlds.sort_unstable();
    worlds.dedup();
    let source = FailureSource {
        instructions: input.definition.instructions.unwrap_or_default(),
        briefing: input.context_spec.and_then(|spec| spec.briefing),
        task,
    };
    Ok(Some((source, worlds)))
}

/// The failing agent dispatch's input; `None` when the attempt is no agent
/// dispatch this can read.
fn dispatch_input(attempt: &AttemptRecord) -> Option<crate::agent_dispatch::AgentDispatchInput> {
    let payload = decode_dreamer_attempt_payload(&attempt.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input).ok()
}

/// Readable everywhere: any narrower, conflicted or unknowable setting is
/// private.
fn all_public(fold: &AuthorityFold, worlds: &[EntityId]) -> bool {
    worlds
        .iter()
        .all(|world| fold.world_privacy(*world).read == EffectiveRead::Everywhere)
}

fn draft_in_shape(draft: &InventedExampleDraft) -> bool {
    let text_ok = |text: &str, max: usize| !text.trim().is_empty() && text.len() <= max;
    text_ok(&draft.note, CODE_FIX_MAX_NOTE_BYTES)
        && !draft.conversation.is_empty()
        && draft.conversation.len() <= CODE_FIX_MAX_MESSAGES
        && draft
            .conversation
            .iter()
            .all(|m| text_ok(&m.text, CODE_FIX_MAX_MESSAGE_BYTES))
}

/// A candidate id is a host token, never prose: printable ASCII with no
/// space, and no credential shape. Its length is its pin's: whole, with no
/// cap.
fn candidate_in_shape(candidate: &CandidateFix) -> bool {
    let id = &candidate.candidate_id;
    let token = !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_graphic())
        && scan_joined_text(id).is_none();
    let example = candidate.example_id.as_deref().is_none_or(|example| {
        example.len() == 32
            && example
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    token && example
}

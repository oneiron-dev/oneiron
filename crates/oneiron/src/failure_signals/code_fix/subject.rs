//! What a code fix reads of the real failure behind its source: the text
//! and every world it touched, a failure no world of which can be proved, or
//! one whose run never gave this engine a model request (FIX 2343). A
//! blocked report whose run is no agent dispatch's attempt reads the source
//! its run's host kept with it. One invocation reads it once, with the
//! reports and the failing call, into a snapshot every consumer shares
//! (OF-380 L1). Where the failing call's capture sits is read before its
//! bytes, and those only once the Coach's own Grant admits it (FIX 8704).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::super::verbatim::verbatim_spans;
use super::exact::{CodeFixReplaySelection, code_fix_replay_selection};
use super::{
    CodeFixSource, CodeFixWithheld, FailureSource, InventedExampleDraft, code_fix_subject_in,
    failure_source_in, invented_text,
};
use crate::attempt_queue::AttemptRecord;
use crate::authority::AuthorityFold;
use crate::code_run::ReadWorldSnapshot;
use crate::dreamer_runner::maintenance::code_fix::{
    CaptureRefs, CoachReplayAdmission, EngineAdmission,
};
use crate::failure_ladder::{BlockedReportRef, HealerCase};
use crate::limit_ask::EngineLimit;
use crate::self_heal::blocked_reports::{RunWorlds, blocked_source_in};
use crate::{ContentPart, EntityId, LlmRequest, Result, Vault};

/// One code-fix invocation's read of the real failure behind its source
/// (OF-380 L1): a first run's or a top-up's, read once and shared by its
/// questions, its replay, its engine pairs and the invented example's door,
/// so none of them chooses the failing call again. Local to the invocation:
/// never kept, queued or sent.
pub(crate) struct CodeFixSourceSnapshot {
    /// The failure-ladder case, when there is one.
    pub(crate) case: Option<HealerCase>,
    /// The failure's text.
    pub(crate) failure: FailureSource,
    /// The evidence its questions cite: the case's own and each report read.
    pub(crate) evidence: Vec<EntityId>,
    /// Each report that still reads, as the Coach reads it: its category
    /// and the agent's own words, whole.
    pub(crate) reports: Vec<Value>,
    /// The failing call, chosen once.
    pub(crate) replay: CodeFixReplaySelection,
    /// The Coach's admission to that call's capture, taken before any of it
    /// was read (FIX 8704), or why there is none: no copy of a capture it
    /// does not admit was read, and none is replayed.
    pub(crate) admission: std::result::Result<CoachReplayAdmission, EngineAdmission>,
    /// Every text the verbatim guard compares an invented example with
    /// (`code_fix_verbatim_sources`).
    pub(super) verbatim_sources: Vec<String>,
}

impl CodeFixSourceSnapshot {
    /// Each span `draft` copies of the real failure as this snapshot read
    /// it, as its folded words; empty when it copies none.
    pub(crate) fn copied_spans(&self, draft: &InventedExampleDraft) -> BTreeSet<String> {
        let sources: Vec<&str> = self.verbatim_sources.iter().map(String::as_str).collect();
        verbatim_spans(&sources, &invented_text(draft))
    }
}

/// The real failure `source` names, read once for one invocation
/// ([`CodeFixSourceSnapshot`]); or why a door withholds for want of it, as
/// it did before. The failing call's capture is found first, by where it
/// sits (the run's worlds and the rows it was taken from), the Coach's
/// admission to it taken, and only then is a copy of its request read.
pub(crate) fn code_fix_source_snapshot(
    vault: &Vault,
    source: &CodeFixSource,
) -> Result<std::result::Result<CodeFixSourceSnapshot, CodeFixWithheld>> {
    // Resolved outside any read: resolving it may seed the Coach.
    let coach = vault.coach_authority()?.entity_ref();
    let found = {
        let txn = vault.store.env.read_txn()?;
        code_fix_subject_in(vault, &txn, source)?
    };
    let Some(subject) = found else {
        return Ok(Err(CodeFixWithheld::UnknownCase));
    };
    let (failure, worlds) = match subject.failure.read() {
        Ok(read) => read,
        Err(reason) => return Ok(Err(reason)),
    };
    let refs = CaptureRefs::new(source, worlds, failure.source_rows.as_deref());
    let admission = CoachReplayAdmission::take(vault, coach, source, refs)?;
    let replay = code_fix_replay_selection(vault, source, admission.as_ref().ok())?;
    let (evidence, reports) = failure_context(vault, subject.case.as_ref(), &subject.reports)?;
    let request = replay.exact.request().map(|exact| &exact.request);
    let verbatim_sources = code_fix_verbatim_sources(&failure, &reports, request);
    Ok(Ok(CodeFixSourceSnapshot {
        case: subject.case,
        failure,
        evidence,
        reports,
        replay,
        admission,
        verbatim_sources,
    }))
}

/// The failure's evidence for its questions (the case's own and each report
/// it still reads), and its reports as those questions read them: every one,
/// each whole, measured.
fn failure_context(
    vault: &Vault,
    case: Option<&HealerCase>,
    reports: &[BlockedReportRef],
) -> Result<(Vec<EntityId>, Vec<Value>)> {
    let reports = crate::dreamer_runner::maintenance::coach_heal::case_reports(vault, reports)?;
    let mut evidence: Vec<EntityId> = case
        .and_then(|case| EntityId::from_hex(&case.evidence_ref).ok())
        .into_iter()
        .chain(reports.iter().map(|(receipt, _)| *receipt))
        .collect();
    evidence.sort();
    evidence.dedup();
    let longest = reports
        .iter()
        .map(|(_, report)| report.untrusted_detail.len())
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, reports.len() as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    let reports = reports
        .iter()
        .map(|(_, report)| {
            json!({
                "category": report.category.as_str(),
                "untrusted_detail": report.untrusted_detail,
            })
        })
        .collect();
    Ok((evidence, reports))
}

/// Every text the verbatim guard compares an invented example with (OF-380
/// L1): the failure's own instructions, briefing and task; each report the
/// Coach read, as its JSON and each string in it raw; and every message of
/// `request`, the kept request the replay sends, whatever its role: whole,
/// with a part that is not text as its JSON, and each string of such a part
/// raw. Nothing is cut or skipped.
fn code_fix_verbatim_sources(
    failure: &FailureSource,
    reports: &[Value],
    request: Option<&LlmRequest>,
) -> Vec<String> {
    let mut sources = failure.texts();
    for report in reports {
        sources.push(report.to_string());
        string_leaves(report, &mut sources);
    }
    for message in request.into_iter().flat_map(|request| &request.messages) {
        let mut whole = Vec::with_capacity(message.content.len());
        for part in &message.content {
            match part {
                ContentPart::Text { text } => whole.push(text.clone()),
                other => {
                    let value = serde_json::to_value(other).unwrap_or_default();
                    whole.push(value.to_string());
                    string_leaves(&value, &mut sources);
                }
            }
        }
        // The message whole, so a span across its parts is found too.
        sources.push(whole.join("\n\n"));
    }
    sources.retain(|text| !text.trim().is_empty());
    sources.sort_unstable();
    sources.dedup();
    sources
}

/// Each string in `value`, raw, so no escape in its JSON hides a copied
/// span: one that is a JSON object or array itself (a tool's result) is
/// read for its own strings too.
fn string_leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            out.push(text.clone());
            if text.trim_start().starts_with(['{', '['])
                && let Ok(inner @ (Value::Array(_) | Value::Object(_))) =
                    serde_json::from_str::<Value>(text)
            {
                string_leaves(&inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| string_leaves(item, out)),
        Value::Object(fields) => fields.values().for_each(|item| string_leaves(item, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The real failure as a code fix reads it.
pub(crate) enum SubjectFailure {
    /// Its text and every world it touched.
    Read(FailureSource, Vec<EntityId>),
    /// The attempt is no agent dispatch this can read, or a world it touched
    /// cannot be proved.
    Unproved,
    /// No model request of the failing run ever reached this engine (FIX
    /// 2343): its caller ran the call outside it, so there is nothing to
    /// replay, and nothing stands in for it.
    Unavailable,
}

impl SubjectFailure {
    /// The text and worlds, or why a door withholds for want of them.
    pub(crate) fn read(
        self,
    ) -> std::result::Result<(FailureSource, Vec<EntityId>), CodeFixWithheld> {
        match self {
            Self::Read(failure, worlds) => Ok((failure, worlds)),
            Self::Unproved => Err(CodeFixWithheld::PrivateWorld),
            Self::Unavailable => Err(CodeFixWithheld::ReplayUnavailable),
        }
    }
}

/// A blocked report's failure from the source its run's host kept with it
/// (FIX 2343): the request's text, and the worlds the run's host scoped it
/// to. A run scoped to no dispatch may have read any world, so every world
/// the vault withholds from an unknown destination counts as touched, and a
/// conflicted vault root proves none; where those withhold it, a run whose
/// read-world ledger was complete at its report touched the worlds of the
/// rows it was served (FIX 6130, [`served_or_inferred`]). No source, or one
/// with no request, leaves the replay unavailable.
pub(super) fn blocked_source_failure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<SubjectFailure> {
    let Some(source) = blocked_source_in(vault, txn, receipt)? else {
        return Ok(SubjectFailure::Unavailable);
    };
    let Some(request) = source.request else {
        return Ok(SubjectFailure::Unavailable);
    };
    let worlds = match source.worlds {
        RunWorlds::Scoped { worlds } => worlds,
        RunWorlds::Unscoped => {
            let fold = vault.authority_view_readonly_in_txn(txn)?;
            let Ok(withheld) = fold.worlds_withheld_from(crate::authority::Destination::Unknown)
            else {
                return Ok(SubjectFailure::Unproved);
            };
            let inferred = std::iter::once(crate::claim::base_world_id())
                .chain(withheld)
                .collect();
            served_or_inferred(&fold, inferred, source.read_worlds)
        }
        RunWorlds::Unproved => return Ok(SubjectFailure::Unproved),
    };
    Ok(SubjectFailure::Read(
        FailureSource {
            instructions: request.instructions,
            briefing: request.briefing,
            task: request.task,
            // A kept request is text only: no reader names the rows behind
            // it (FIX 6997).
            source_rows: None,
        },
        worlds,
    ))
}

/// The worlds a code fix of a run its host scoped to no dispatch discloses
/// by (FIX 6130): the ones `inferred` for it, every world the vault
/// withholds from an unknown destination, while they all read everywhere, as
/// before; else, when the run's read-world ledger was complete at its report
/// (`served`), the worlds of the rows it was served, which the delivery's own
/// check reads again; else the inferred ones, which withhold it as before.
/// Nothing the inferred worlds deliver is withheld.
fn served_or_inferred(
    fold: &AuthorityFold,
    inferred: Vec<EntityId>,
    served: Option<ReadWorldSnapshot>,
) -> Vec<EntityId> {
    match served {
        Some(served) if !super::all_public(fold, &inferred) => served.worlds,
        _ => inferred,
    }
}

/// The worlds the agent dispatch `attempt` touched: its scope's and its
/// task's. `None` when it is no agent dispatch this can read, or a world
/// cannot be proved.
pub(crate) fn dispatch_worlds_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<Option<Vec<EntityId>>> {
    Ok(
        failure_source_in(vault, txn, attempt.task_ref.as_deref(), attempt)?
            .map(|(_, worlds)| worlds),
    )
}

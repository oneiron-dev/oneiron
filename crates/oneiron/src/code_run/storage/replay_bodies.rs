//! A code run's replay outcomes under body custody (KS-2B1, FIX 5683 part
//! B1).
//!
//! A replay record's bridge outcomes and output previews are one body
//! instance, bound the first time a checkpoint carries the record. The image
//! row holds the record with each outcome failed and each preview withheld:
//! under a retired instance a restore keeps that terminal evidence (each
//! call's seq, effect, request, times and action digest; each output's
//! handle, digest, counts and completeness; the run's checkpoints, and so
//! its generation), so a resumed run that reaches an erased call traps on
//! it, never takes an empty success and never runs a fresh effect. Under a
//! live instance the exact record lands, and replay checks it as before.
//! Its owners are the run, the actor its live run binding names, the actor
//! a turn program's run runs as, and the source rows its verb calls served.
//! The live record's erase scrub is L11-B's (FIX 5718, [`erase_replies`]);
//! this retires every image's copy beside it.

use super::records::REPLAY_RECORDS;
use super::response_owners::response_owner_in_txn;
use crate::code_run::payload::{decode_self_dispatch_outcome, self_dispatch_outcome_value};
use crate::code_run::wait_rows::keep_erased_answer_rows;
use crate::code_run::{CodeRunReplayRecord, SelfDispatchOutcome, SelfFailedResult};
use crate::engine_executor::holds_reply_content;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::side_table::{ErasedForm, SideTableDbs};
use crate::store::ResponseCarriage;
use crate::task_verb::TaskAskStatus;

/// The error a call whose outcome an erase took replays with.
pub(crate) const RESPONSE_ERASED: &str = "response_erased";

/// The typed unavailable a run's read of reply content an erase of its actor
/// took answers with (FIX 5718; `ErrorKind::ResponseErased`): a replayed
/// call's, a wait's delivered or settled reply, a consent wait's resume.
/// `what` names the read. Nothing is sent again.
pub(crate) fn response_erased_error(what: &'static str) -> Error {
    Error::Code(CodeError::ResponseErased(what))
}

/// The preview text of a result whose record an erase retired.
pub(crate) const CODE_RUN_OUTPUT_PREVIEW_ERASED: &str =
    "[preview erased: its owner's erase retired this result]";

/// What a checkpoint carries of the replay record `value`: its outcomes and
/// previews, the record with each outcome failed and each preview withheld
/// as the stub its erased disposition keeps whole, a verb's answer keeping
/// the rows it was served from as the live erased form does (FIX 6535).
/// `None` for a record with no call and no output, and for one that does not
/// decode.
pub(crate) fn replay_carriage(value: &[u8]) -> Option<ResponseCarriage> {
    let mut record = REPLAY_RECORDS.decode_value(value).ok()?;
    if record.bridge_calls.is_empty() && record.outputs.is_empty() {
        return None;
    }
    for call in &mut record.bridge_calls {
        let rows = match decode_self_dispatch_outcome(&call.outcome) {
            Ok(SelfDispatchOutcome::AgentVerb(answer)) => Some(answer.rows),
            Ok(_) => None,
            Err(_) => Some(None),
        };
        call.outcome =
            self_dispatch_outcome_value(&SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect,
                error: RESPONSE_ERASED.to_owned(),
            }))
            .ok()?;
        if let Some(rows) = rows {
            keep_erased_answer_rows(&mut call.outcome, rows.as_deref());
        }
    }
    for output in &mut record.outputs {
        output.preview.text = CODE_RUN_OUTPUT_PREVIEW_ERASED.to_owned();
    }
    let stub = REPLAY_RECORDS.encode_value(&record).ok()?;
    Some(ResponseCarriage {
        keep: 0,
        retired: stub.len(),
        stub,
    })
}

/// Who owns the replay record `value`'s outcomes: its run, the actor its
/// live run binding names, the actor a turn program's run runs as, the run
/// and actor its owner row names (a write receipt's among them, FIX 5718),
/// and the source rows its verb calls listed as served. None for a record
/// that does not decode.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn replay_owners(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    value: &[u8],
) -> Result<Vec<EntityId>> {
    let Ok(record) = REPLAY_RECORDS.decode_value(value) else {
        return Ok(Vec::new());
    };
    let mut owners = vec![record.run_id];
    owners.extend(record.live_run.as_ref().map(|live| live.actor));
    owners.extend(record.agent_verb_rows().into_iter().flatten());
    owners.extend(crate::dreamer_runner::program_run_actor_in_txn(
        dbs,
        txn,
        &record.run_id,
    )?);
    // A write receipt names its run and actor here alone (FIX 5718).
    if let Some(owner) = response_owner_in_txn(dbs, txn, &record.run_id)? {
        owners.extend(Some(owner.run).filter(|run| *run != record.run_id));
        owners.extend(owner.actor());
    }
    Ok(owners)
}

/// What an erase of its run's actor leaves of `record` live (FIX 5718,
/// ruling 1): each call whose recorded outcome holds a reply
/// ([`outcome_holds_reply`]) fails with `response_erased` under its own
/// effect, as a checkpoint's image of it does, a verb's answer keeping the
/// rows it was served from, and each output that holds reply content
/// ([`holds_reply_content`]) previews as erased. What the run did stays
/// whole: every call's seq, effect, request, times and action
/// digest, every output's path, handle, digest, counts and completeness, its
/// checkpoints (so its generation), its names and its live run binding. A
/// resumed run that reaches an erased call traps on it, as a write whose
/// receipt holds one is never made again.
///
/// # Errors
///
/// An outcome that does not encode.
pub(crate) fn erase_replies(record: &mut CodeRunReplayRecord) -> Result<()> {
    for call in &mut record.bridge_calls {
        // A verb's answer keeps the rows it was served from; one that does
        // not decode names none it is known to be served from.
        let rows = match decode_self_dispatch_outcome(&call.outcome) {
            Ok(outcome) if !outcome_holds_reply(&outcome) => continue,
            Ok(SelfDispatchOutcome::AgentVerb(answer)) => Some(answer.rows),
            Ok(_) => None,
            Err(_) => Some(None),
        };
        call.outcome =
            self_dispatch_outcome_value(&SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect,
                error: RESPONSE_ERASED.to_owned(),
            }))?;
        if let Some(rows) = rows {
            keep_erased_answer_rows(&mut call.outcome, rows.as_deref());
        }
    }
    for output in &mut record.outputs {
        if holds_reply_content(&output.path) {
            output.preview.text = CODE_RUN_OUTPUT_PREVIEW_ERASED.to_owned();
        }
    }
    Ok(())
}

/// A replay record's erased form is [`erase_replies`]'s (FIX 5718): the
/// actor scrub writes it past the side-row wall, so no wall ever fails an
/// erase.
impl ErasedForm for CodeRunReplayRecord {
    fn into_erased(mut self) -> Result<Self> {
        erase_replies(&mut self)?;
        Ok(self)
    }
}

/// Whether a recorded outcome holds reply content an erase of its run's
/// actor takes (FIX 5718; CALLS "reply-bearing outcomes"): a verb's or a
/// fold's answer, a skill's return, a search's hits, the inference defaults
/// read, an ask's settled answer, a reader wait's reduction, a summary and
/// the leader's advice. What a call did and whom it named stays as it was
/// recorded: a speech bubble, the wait a call parked on, a refusal or a
/// failure, and every receipt (a spawn's, an ask's, a write's, a report's,
/// a reader's, a team's), a context spec, a written policy and a refusal's
/// dial. An outcome that does not decode holds one.
fn outcome_holds_reply(outcome: &SelfDispatchOutcome) -> bool {
    match outcome {
        SelfDispatchOutcome::AgentVerb(_)
        | SelfDispatchOutcome::Fold(_)
        | SelfDispatchOutcome::SkillCall(_)
        | SelfDispatchOutcome::MemorySearch(_)
        | SelfDispatchOutcome::InferenceDefaults(_)
        | SelfDispatchOutcome::TaskWaitSet(_)
        | SelfDispatchOutcome::Summarize(_)
        | SelfDispatchOutcome::Leader(_) => true,
        SelfDispatchOutcome::TaskAskStatus(status) => matches!(
            status,
            TaskAskStatus::Settled(_) | TaskAskStatus::WorldPrivacy(_)
        ),
        SelfDispatchOutcome::AgentSpawn(_)
        | SelfDispatchOutcome::AgentDefinitionPut(_)
        | SelfDispatchOutcome::TaskAsk(_)
        | SelfDispatchOutcome::MemoryWrite(_)
        | SelfDispatchOutcome::MemoryEdgeWrite(_)
        | SelfDispatchOutcome::DurableWait(_)
        | SelfDispatchOutcome::Denied(_)
        | SelfDispatchOutcome::Failed(_)
        | SelfDispatchOutcome::Context(_)
        | SelfDispatchOutcome::Speech(_)
        | SelfDispatchOutcome::ReportBlocked { .. }
        | SelfDispatchOutcome::WakePolicyWritten(_)
        | SelfDispatchOutcome::TaskRefusal(_)
        | SelfDispatchOutcome::ReaderSpawn(_)
        | SelfDispatchOutcome::ReaderReport(_)
        | SelfDispatchOutcome::Team(_)
        | SelfDispatchOutcome::TeamSubmitted(_) => false,
    }
}

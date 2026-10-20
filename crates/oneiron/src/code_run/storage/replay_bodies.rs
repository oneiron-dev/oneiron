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
//! The live record's erase scrub is L11-B's (FIX 5718); this retires every
//! image's copy beside it.

use super::records::REPLAY_RECORDS;
use crate::code_run::payload::self_dispatch_outcome_value;
use crate::code_run::{SelfDispatchOutcome, SelfFailedResult};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideTableDbs;
use crate::store::ResponseCarriage;

/// The error a call whose outcome an erase took replays with.
const ERASED_OUTCOME: &str = "response_erased";

/// The preview text of a result whose record an erase retired.
const CODE_RUN_OUTPUT_PREVIEW_ERASED: &str =
    "[preview erased: its owner's erase retired this result]";

/// What a checkpoint carries of the replay record `value`: its outcomes and
/// previews, the record with each outcome failed and each preview withheld
/// as the stub its erased disposition keeps whole. `None` for a record with
/// no call and no output, and for one that does not decode.
pub(crate) fn replay_carriage(value: &[u8]) -> Option<ResponseCarriage> {
    let mut record = REPLAY_RECORDS.decode_value(value).ok()?;
    if record.bridge_calls.is_empty() && record.outputs.is_empty() {
        return None;
    }
    for call in &mut record.bridge_calls {
        call.outcome =
            self_dispatch_outcome_value(&SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect,
                error: ERASED_OUTCOME.to_owned(),
            }))
            .ok()?;
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
/// live run binding names, the actor a turn program's run runs as, and the
/// source rows its verb calls listed as served. None for a record that does
/// not decode.
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
    Ok(owners)
}

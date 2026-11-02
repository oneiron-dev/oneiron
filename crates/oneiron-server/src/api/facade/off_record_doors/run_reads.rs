//! The read and answer doors of a session-bound code run (FIX 4284):
//! `self.off_record.results.list` and `.results.read` read the named
//! results of a run `self.off_record.execute` entered, and
//! `self.off_record.waits.get` and `.waits.answer` read and answer the wait
//! it parked on. Each admits the session's manager as the run's entries
//! do, binds the stretch for them again ([`managed_session`]) and reads the
//! run their `run_ref` names there as its entries run it: through the
//! session, as their participant, never through the vault's canonical
//! result readers. A result read is withheld as `read_result` withholds
//! one, by the rows the run's answers were served from and the result's
//! taint.
//!
//! None keeps a call receipt (`no_record`). A result read lists the rows
//! the run's answers were served from; a wait read and an answer list none.

use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::off_record::SessionCodeRun;
use oneiron::settings::ReadDestination;
use oneiron::task_verb::sdk::{
    OffRecordResultCards, OffRecordResultRead, OffRecordResultReadRequest, OffRecordResultsRequest,
    OffRecordRunWait, OffRecordWaitAnswerRequest, OffRecordWaitAnswered, OffRecordWaitRequest,
    OffRecordWaitView,
};
use oneiron::{EntityId, Vault};

use super::{Caller, as_caller, managed_session, session_refusal};
use crate::api::facade::host_doors::support::Listed;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The actor a run's entries run as for this caller: the door's own.
fn run_actor(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<EntityId> {
    crate::api::facade::facade_actor(server, auth)
        .map(|(actor, _)| actor)
        .map_err(|error| error.into_memory_error())
}

/// The run `run_ref` names in the stretch `session_ref`, bound for
/// `caller` to manage as `self.off_record.execute` binds it, read as
/// `actor`, the participant its entries run as.
fn session_run<'v>(
    vault: &'v Vault,
    caller: &Caller,
    actor: EntityId,
    verb: &str,
    session_ref: &str,
    run_ref: &str,
) -> MemoryResult<SessionCodeRun<'v>> {
    let session = managed_session(vault, caller, verb, session_ref)?;
    let run_id = crate::mcp::off_record_run_id(session.session_ref(), actor, run_ref);
    session
        .code_run(actor, run_ref, run_id)
        .map_err(|error| session_refusal(error, session_ref))
}

/// Whether the rows a run's answers were served from (`None` when its
/// record keeps no set) stay where this caller is not, as `read_result`
/// judges them: never for a caller on this device.
fn withholds(
    vault: &Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
) -> oneiron::Result<bool> {
    if !destination.is_off_device() {
        return Ok(false);
    }
    rows.map_or(Ok(true), |rows| {
        crate::device_local::withholds_retained(vault, destination.clone(), rows, &[])
    })
}

/// `act`'s answer for the caller the row admits, beside the rows it lists.
async fn listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Caller) -> MemoryResult<(T, Vec<EntityId>)> + Send + 'static,
) -> Listed<T> {
    match as_caller(server, auth, verb, act).await {
        Ok((answer, rows)) => (Ok(answer), rows),
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

fn refused<T>(refusal: MemoryError) -> Listed<T> {
    (Err(refusal), Vec::new())
}

/// `self.off_record.results.list`: a page of the run's result cards,
/// newest name first, listing the rows its answers were served from.
pub(crate) async fn self_off_record_results_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordResultsRequest,
) -> Listed<OffRecordResultCards> {
    const VERB: &str = "self.off_record.results.list";
    let actor = match run_actor(server, auth) {
        Ok(actor) => actor,
        Err(refusal) => return refused(refusal),
    };
    let destination = auth.destination();
    listing(server, auth, VERB, move |server, caller| {
        let vault = server.vault();
        let run = session_run(
            vault,
            caller,
            actor,
            VERB,
            &input.session_ref,
            &input.run_ref,
        )?;
        let page = run.result_cards(
            input.offset.map_or(0, |offset| offset as usize),
            input.limit.map(|limit| limit as usize),
            |rows| withholds(vault, &destination, rows),
        )?;
        let rows = if page.withheld {
            Vec::new()
        } else {
            page.served_rows.clone().unwrap_or_default()
        };
        let cards = OffRecordResultCards::of(input.run_ref, run.run_id(), page)?;
        Ok((cards, rows))
    })
    .await
}

/// `self.off_record.results.read`: one read of one of the run's results,
/// its card or a facet page, listing the rows its answers were served from.
pub(crate) async fn self_off_record_results_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordResultReadRequest,
) -> Listed<OffRecordResultRead> {
    const VERB: &str = "self.off_record.results.read";
    let actor = match run_actor(server, auth) {
        Ok(actor) => actor,
        Err(refusal) => return refused(refusal),
    };
    let destination = auth.destination();
    listing(server, auth, VERB, move |server, caller| {
        let vault = server.vault();
        let run = session_run(
            vault,
            caller,
            actor,
            VERB,
            &input.session_ref,
            &input.run_ref,
        )?;
        let read = run.read_result(
            &input.reference,
            input.facet,
            input.input.unwrap_or_else(|| serde_json::json!({})),
            |rows| withholds(vault, &destination, rows),
        )?;
        let answer = OffRecordResultRead::of(read.reply, input.facet)?;
        let rows = if matches!(answer, OffRecordResultRead::Denied { .. }) {
            Vec::new()
        } else {
            read.served_rows.unwrap_or_default()
        };
        Ok((answer, rows))
    })
    .await
}

/// `self.off_record.waits.get`: the wait the run is parked on now, whether
/// its runner's reply answers it, and whether one was delivered.
pub(crate) async fn self_off_record_waits_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordWaitRequest,
) -> Listed<OffRecordWaitView> {
    const VERB: &str = "self.off_record.waits.get";
    let actor = match run_actor(server, auth) {
        Ok(actor) => actor,
        Err(refusal) => return refused(refusal),
    };
    listing(server, auth, VERB, move |server, caller| {
        let run = session_run(
            server.vault(),
            caller,
            actor,
            VERB,
            &input.session_ref,
            &input.run_ref,
        )?;
        let view = OffRecordWaitView {
            run_id: run.run_id().to_hex(),
            wait: run.wait()?.map(OffRecordRunWait::of),
            run_ref: input.run_ref,
        };
        Ok((view, Vec::new()))
    })
    .await
}

/// `self.off_record.waits.answer`: delivers the runner's reply to the wait
/// the run is parked on now, once. It enters nothing: the runner enters the
/// run again with `self.off_record.execute` to go on.
pub(crate) async fn self_off_record_waits_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordWaitAnswerRequest,
) -> Listed<OffRecordWaitAnswered> {
    const VERB: &str = "self.off_record.waits.answer";
    let actor = match run_actor(server, auth) {
        Ok(actor) => actor,
        Err(refusal) => return refused(refusal),
    };
    listing(server, auth, VERB, move |server, caller| {
        let run = session_run(
            server.vault(),
            caller,
            actor,
            VERB,
            &input.session_ref,
            &input.run_ref,
        )?;
        let answer = run.answer_wait(input.wait_id, input.generation, &input.reply)?;
        let answered = OffRecordWaitAnswered::of(input.run_ref, run.run_id(), answer);
        Ok((answered, Vec::new()))
    })
    .await
}

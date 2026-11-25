//! `vault.jobs.history` (design pass 34 section 5, row Q2): the ended attempts and their totals
//! by machine, family, line and period, as a view over the rows the vault keeps. A read: the
//! owner under their own proof, who sees every attempt, or an agent whose own Grant lists the
//! verb (`verb_grant_caller`), who sees the attempts it started or reserved. The engine reads
//! (`oneiron::job_history`); the door writes nothing and lists no row.

use std::sync::Arc;

use oneiron::job_history::{JOB_HISTORY_VERB, JobHistory, JobHistoryRequest, job_history_as};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.jobs.history`: the ended attempts `input` names, one page, and their totals.
pub(crate) async fn vault_jobs_history(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: JobHistoryRequest,
) -> Listed<JobHistory> {
    verb_grant_door(server, auth, JOB_HISTORY_VERB, move |_, memory, owner| {
        job_history_as(memory, owner, &input)
    })
    .await
}

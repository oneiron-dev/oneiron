//! The idle-fold return tables, rebuilt weekly (L2-37 PR-1; ARCH-0067 #idle-fold-policy: "E+'s
//! tables are rebuilt weekly"). The job rides the Coach's nightly maintenance and rebuilds once
//! the last build is a week old (see [`crate::idle_fold`]). A closed-form job: no model is
//! called, nothing is proposed, and it writes derived rows only.

use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::{Result, Vault};

/// The weekly rebuild of the idle-fold return tables (L2-37): the return gaps of the trailing
/// eight weeks' waits by session kind, wait class, four-hour band and weekend.
pub const COACH_IDLE_RETURN_TABLES_FACET: &str = "coach.idle_return_tables";

/// One night's run: a rebuild when the tables are a week old, else nothing.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    vault.require_coach_attempt(attempt, COACH_IDLE_RETURN_TABLES_FACET)?;
    if crate::idle_fold::rebuild_return_tables(vault, now)? {
        tracing::debug!("the Coach rebuilt the idle-fold return tables");
    }
    Ok(())
}

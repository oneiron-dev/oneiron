//! A session's renewal on the systemd scope (pass 34, 2.5; row W1), as root,
//! through the job control socket's `renew` verb.
//!
//! systemd cannot move a running service's `RuntimeMaxSec` or a timer's
//! elapse time: both are set only when the unit is made. So the cutoff moves
//! by a handoff. Root checks the renewal against its own `prepared.json` (the
//! session's latest allowed cutoff, the current stop time) and the unit
//! (active), then:
//! 1. arms a new cutoff timer, `oneiron-job-cutoff-<id>-<stop ns>`, for the
//!    later stop time, naming that time (`job-cutoff --stop-at`);
//! 2. records the new plan in `prepared.json`;
//! 3. stops the old timer.
//!
//! A failure before step 2 leaves the old timer the record names, which
//! stops the run at its paid end. An old timer that fires after step 2 finds
//! a later stop time in the record and stops nothing
//! ([`super::cutoff::cutoff_superseded`]). The unit's own `RuntimeMaxSec`
//! backstop covers each session template's longest run
//! ([`super::install::unit_runtime_max_secs`]).

use std::path::Path;

use super::super::jobs::JobKeyId;
use super::prepare::arm_cutoff;
use super::records::{CutoffPlan, PreparedRecord};
use super::safe_fs::boot_ns;
use super::step::{StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
use super::unit_file::installed_runtime_max_secs;
use super::{CUTOFF_UNIT_PREFIX, PREPARED_FILE_NAME, UNIT_TEMPLATE_PATH};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// `Ok` while the job unit is active: its cutoff may move.
fn running(id: &JobKeyId) -> Result<(), String> {
    let found = show(&id.unit_name(), &["ActiveState"])?;
    let state = found.get("ActiveState").map_or("", String::as_str);
    if state == "active" {
        Ok(())
    } else {
        Err(format!("unit_not_running: the unit is {state:?}"))
    }
}

/// How long before the current stop time a renewal must be taken: a timer
/// this close may already be firing.
const RENEW_BEFORE_STOP_NS: u64 = NANOS_PER_SEC;

/// The cutoff plan a renewal to `cutoff_boot_ns` makes of `prepared`'s, at
/// boot-clock time `now_boot_ns`: `Ok(None)` when the record already holds
/// that cutoff, so a renewal asked twice changes nothing. The timer stops the
/// unit a stop grace before the cutoff, as the prepare step's does.
///
/// # Errors
///
/// The refusal: the run is no session's or no cutoff was armed, the cutoff
/// would move back or past the session's longest run, or the current stop
/// is too near to hand over.
pub fn renewed_cutoff_plan(
    prepared: &PreparedRecord,
    cutoff_boot_ns: u64,
    now_boot_ns: u64,
) -> Result<Option<CutoffPlan>, String> {
    let current = prepared
        .cutoff
        .as_ref()
        .ok_or("cutoff_not_armed: the prepare step armed no cutoff")?;
    let until = prepared
        .session_until_boot_ns
        .ok_or("template_not_session: this run's cutoff does not move")?;
    if cutoff_boot_ns > until {
        return Err("session_max_reached".to_owned());
    }
    let stop_at_boot_ns =
        cutoff_boot_ns.saturating_sub(current.stop_grace_secs.saturating_mul(NANOS_PER_SEC));
    if stop_at_boot_ns == current.stop_at_boot_ns {
        return Ok(None);
    }
    if stop_at_boot_ns < current.stop_at_boot_ns {
        return Err("cutoff_not_forward: a cutoff only moves forward".to_owned());
    }
    if now_boot_ns.saturating_add(RENEW_BEFORE_STOP_NS) >= current.stop_at_boot_ns {
        return Err("cutoff_passed: the current cutoff is already stopping the run".to_owned());
    }
    Ok(Some(CutoffPlan {
        unit: format!(
            "{CUTOFF_UNIT_PREFIX}{}-{stop_at_boot_ns}.timer",
            prepared.instance
        ),
        stop_at_boot_ns,
        stop_grace_secs: current.stop_grace_secs,
    }))
}

/// The `renew` verb, as root: moves the job unit `id`'s cutoff to
/// `cutoff_boot_ns` by the handoff of the module doc.
///
/// # Errors
///
/// The refusal, in words: the step could not open, the record is missing or
/// not this instance's, the unit is not running, [`renewed_cutoff_plan`]
/// refused, or the service manager did not take the new timer or the record
/// was not written.
pub fn renew_cutoff(
    node_file: &Path,
    engine_account: &str,
    id: &JobKeyId,
    cutoff_boot_ns: u64,
) -> Result<(), String> {
    let context = StepContext::open(StepArgs {
        node_file: node_file.to_owned(),
        engine_account: engine_account.to_owned(),
        instance: id.as_str().to_owned(),
        after_exec: false,
        host_namespace_error: None,
        stop_at_boot_ns: None,
    })?;
    let mut prepared = context
        .read_record::<PreparedRecord>(PREPARED_FILE_NAME)?
        .filter(|record| record.instance == id.as_str())
        .ok_or("not_prepared: no prepared record of this instance")?;
    running(id)?;
    let Some(plan) = renewed_cutoff_plan(&prepared, cutoff_boot_ns, boot_ns())? else {
        return Ok(());
    };
    // The unit's backstop, as the prepare step checks it: a node file whose
    // session ceiling grew without `oneiron execution-node install` again
    // would let the backstop stop a paid chunk.
    let unit_text = std::fs::read_to_string(UNIT_TEMPLATE_PATH)
        .map_err(|error| format!("unit_template_unreadable: {error}"))?;
    let run_ns = cutoff_boot_ns.saturating_sub(prepared.at_boot_ns);
    if installed_runtime_max_secs(&unit_text)
        .is_none_or(|ceiling| run_ns > ceiling.saturating_mul(NANOS_PER_SEC))
    {
        return Err(
            "unit_runtime_max_below_maximum: run `oneiron execution-node install` again".to_owned(),
        );
    }
    let base = prepared.cutoff.clone();
    let previous = prepared.cutoff.replace(plan.clone());
    let timer = plan.unit.trim_end_matches(".timer");
    arm_cutoff(&context, timer, plan.stop_at_boot_ns)?;
    // Record the new plan only while the unit still runs and no other
    // renewal moved the record meanwhile: else the new timer goes, and the
    // engine asks again.
    let current = context
        .read_record::<PreparedRecord>(PREPARED_FILE_NAME)
        .ok()
        .flatten()
        .and_then(|record| record.cutoff);
    let unchanged = current == base;
    if let Err(why) = running(id).and_then(|()| {
        unchanged
            .then_some(())
            .ok_or_else(|| "renew_raced: another renewal moved the cutoff".to_owned())
    }) {
        let _ = run_tool(
            "systemctl",
            &["stop", "--no-block", &plan.unit],
            SYSTEMCTL_TIMEOUT,
        );
        return Err(why);
    }
    context.write_record(PREPARED_FILE_NAME, &prepared)?;
    if let Some(previous) = previous {
        let _ = run_tool(
            "systemctl",
            &["stop", "--no-block", &previous.unit],
            SYSTEMCTL_TIMEOUT,
        );
    }
    Ok(())
}

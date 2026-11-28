//! `oneiron job-cutoff <id>` (root): the command of the cutoff timer the
//! prepare step armed (pass 33, 7.6, "the cutoff timer"). It stops the job
//! unit, and then marks the cutoff in the key's control directory, so the end
//! record says the cutoff ended the job. The stop waits on nothing the mark
//! needs: a node file that no longer reads, or a stalled state disk, still
//! stops the unit.
//!
//! One exception (pass 34, 2.5; row W1): a session's renewal arms a later
//! timer and then stops this one, so a timer that fires between the two
//! finds `prepared.json` naming a later stop time than its own `--stop-at`,
//! and stops nothing. Only a record that reads within
//! [`RECORD_READ_DEADLINE`], is root's and names a later stop skips the
//! stop: anything else stops the unit. Only a session's timer names a stop
//! time; a job's reads nothing before its stop. A stop the service manager
//! does not take is asked for again, a few times.

use std::sync::mpsc;
use std::time::Duration;

use super::network_unit::{host_network_unit_installed, installed_unit_names};
use super::records::{CutoffMark, CutoffPlan, PreparedRecord};
use super::safe_fs::boot_ns;
use super::step::{StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
use super::{CUTOFF_FILE_NAME, PREPARED_FILE_NAME, is_job_instance};

/// How long a session's cutoff waits for its record before it stops the
/// unit anyway: a stalled state disk holds the stop no longer than this.
pub const RECORD_READ_DEADLINE: Duration = Duration::from_secs(2);

/// How often the cutoff asks the service manager to stop the unit when it
/// does not take the stop, and the pause between two asks: the unit's own
/// `RuntimeMaxSec` backstop may be days away.
const STOP_ASKS: u32 = 4;
const STOP_ASK_PAUSE: Duration = Duration::from_secs(1);

/// Whether a cutoff timer armed for `own_stop_at_boot_ns` was superseded by
/// a renewal: root's record names a later stop time. A timer that names no
/// stop time (armed before sessions) or a record without a cutoff is never
/// superseded.
#[must_use]
pub fn cutoff_superseded(own_stop_at_boot_ns: Option<u64>, recorded: Option<&CutoffPlan>) -> bool {
    match (own_stop_at_boot_ns, recorded) {
        (Some(own), Some(plan)) => plan.stop_at_boot_ns > own,
        _ => false,
    }
}

/// The cutoff plan root's record of `args`'s instance names, read on a
/// helper thread: `None` when it does not read, is not this instance's, or
/// does not come within [`RECORD_READ_DEADLINE`]. A read that blocks keeps
/// its thread, which ends with the step.
fn recorded_cutoff(args: &StepArgs) -> Option<CutoffPlan> {
    let (sender, receiver) = mpsc::channel();
    let args = args.clone();
    std::thread::Builder::new()
        .name("job-cutoff-record".to_owned())
        .spawn(move || {
            let recorded = StepContext::open(args.clone())
                .and_then(|context| context.read_record::<PreparedRecord>(PREPARED_FILE_NAME))
                .ok()
                .flatten()
                // Root's record for this instance only: one moved in from
                // another key's control directory is no record.
                .filter(|prepared| prepared.instance == args.instance)
                .and_then(|prepared| prepared.cutoff);
            let _ = sender.send(recorded);
        })
        .ok()?;
    match receiver.recv_timeout(RECORD_READ_DEADLINE) {
        Ok(recorded) => recorded,
        Err(why) => {
            journal_line!("job-cutoff: the record did not read in time ({why}); stopping the unit");
            None
        }
    }
}

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    if !is_job_instance(&args.instance) {
        journal_line!("job-cutoff: {:?} is not a job instance", args.instance);
        return 1;
    }
    // The key's unit under each installed template (row
    // NODE-NETWORK-HOST-UNIT): stopping the one it does not run in changes
    // nothing, so a timer a renewal armed needs no flag.
    let units = installed_unit_names(&args.instance, host_network_unit_installed());
    let unit = units.join(" ");
    let mut stop_args = vec!["stop", "--no-block"];
    stop_args.extend(units.iter().map(String::as_str));
    let fired_boot_ns = boot_ns();
    if let Some(own) = args.stop_at_boot_ns {
        let recorded = recorded_cutoff(&args);
        if cutoff_superseded(Some(own), recorded.as_ref()) {
            journal_line!(
                "job-cutoff: {unit}: a renewal moved the stop past {own}; this timer stops nothing"
            );
            return 0;
        }
    }
    // The stop goes first: nothing the mark needs (the node file, the state
    // disk) may hold it back. The end step also counts the cutoff by the time
    // the unit ended, so a mark that lands late or never still ends the run
    // as its time limit.
    let mut stopped = run_tool("systemctl", &stop_args, SYSTEMCTL_TIMEOUT);
    for _ in 1..STOP_ASKS {
        let Err(why) = &stopped else {
            break;
        };
        journal_line!("job-cutoff: {unit} did not take the stop ({why}); asking again");
        std::thread::sleep(STOP_ASK_PAUSE);
        stopped = run_tool("systemctl", &stop_args, SYSTEMCTL_TIMEOUT);
    }
    let mark = CutoffMark {
        instance: args.instance.clone(),
        fired_boot_ns,
    };
    match StepContext::open(args) {
        Ok(context) => {
            if let Err(why) = context.write_record(CUTOFF_FILE_NAME, &mark) {
                journal_line!("job-cutoff: the mark was not written: {why}");
            }
        }
        Err(why) => journal_line!("job-cutoff: the mark was not written: {why}"),
    }
    match stopped {
        Ok(_) => 0,
        Err(why) => {
            journal_line!("job-cutoff: {unit} did not take the stop: {why}");
            1
        }
    }
}

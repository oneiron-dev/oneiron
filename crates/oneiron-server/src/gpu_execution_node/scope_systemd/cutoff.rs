//! `oneiron job-cutoff <id>` (root): the command of the cutoff timer the
//! prepare step armed (pass 33, 7.6, "the cutoff timer"). It stops the job
//! unit, and then marks the cutoff in the key's control directory, so the end
//! record says the cutoff ended the job. The stop waits on nothing the mark
//! needs: a node file that no longer reads, or a stalled state disk, still
//! stops the unit.

use super::records::CutoffMark;
use super::safe_fs::boot_ns;
use super::step::{StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
use super::{CUTOFF_FILE_NAME, is_job_instance};

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    if !is_job_instance(&args.instance) {
        journal_line!("job-cutoff: {:?} is not a job instance", args.instance);
        return 1;
    }
    let unit = format!("oneiron-job@{}.service", args.instance);
    let fired_boot_ns = boot_ns();
    // The stop goes first: nothing the mark needs (the node file, the state
    // disk) may hold it back. The end step also counts the cutoff by the time
    // the unit ended, so a mark that lands late or never still ends the run
    // as its time limit.
    let stopped = run_tool(
        "systemctl",
        &["stop", "--no-block", &unit],
        SYSTEMCTL_TIMEOUT,
    );
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

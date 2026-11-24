//! `oneiron job-cutoff <id>` (root): the command of the cutoff timer the
//! prepare step armed (pass 33, 7.6, "the cutoff timer"). It marks the cutoff
//! in the key's control directory, so the end record says the cutoff ended
//! the job, and then stops the job unit. The stop does not wait on anything
//! the mark needs: a node file that no longer reads still stops the unit.

use super::records::CutoffMark;
use super::safe_fs::boot_ns;
use super::step::{StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
use super::{CUTOFF_FILE_NAME, is_job_instance};

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    if !is_job_instance(&args.instance) {
        eprintln!("job-cutoff: {:?} is not a job instance", args.instance);
        return 1;
    }
    let unit = format!("oneiron-job@{}.service", args.instance);
    let instance = args.instance.clone();
    match StepContext::open(args) {
        Ok(context) => {
            let mark = CutoffMark {
                instance,
                fired_boot_ns: boot_ns(),
            };
            if let Err(why) = context.write_record(CUTOFF_FILE_NAME, &mark) {
                eprintln!("job-cutoff: the mark was not written: {why}");
            }
        }
        Err(why) => eprintln!("job-cutoff: the mark was not written: {why}"),
    }
    match run_tool("systemctl", &["stop", "--no-block", &unit], SYSTEMCTL_TIMEOUT) {
        Ok(_) => 0,
        Err(why) => {
            eprintln!("job-cutoff: {unit} did not take the stop: {why}");
            1
        }
    }
}

//! The job units' slice and CPU weights (row NODE-JOB-SLICE-AND-WEIGHT;
//! FLEET-TOOL-PARITY.md, kind 11): the node file's
//! `[execution_node.job_cgroup]` table. Absent, a node runs its jobs as
//! before it (no `Slice=` line, systemd's default weight for a job that
//! leases a device); a job that leases no device yields to one that does;
//! the slice is a top-level slice of the node's own, and its weight comes
//! only with it.
//!
//! The template's `Slice=` line is checked by the unit file's own tests
//! (`scope_systemd::unit_file`), and the prepare step sets the weights as
//! root on a real host.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! execution_node_job_cgroup`.

use oneiron_server::gpu_execution_node::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::job_cgroup::{
    CPU_JOB_CPU_WEIGHT_DEFAULT, DEVICE_JOB_CPU_WEIGHT_DEFAULT, JobCgroupSettings,
};

/// The issuer every file here names.
const ISSUER: &str = "5d1e3c8a9b7f4e21a0c6d2b8f3e9a714";

/// A node file with `table` as its `[execution_node.job_cgroup]` lines
/// (none when empty).
fn node_text(table: &str) -> String {
    let table = if table.is_empty() {
        String::new()
    } else {
        format!("\n[execution_node.job_cgroup]\n{table}\n")
    };
    format!(
        r#"[execution_node]
enabled = true
issuers = ["{ISSUER}"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"
{table}"#
    )
}

fn parsed(table: &str) -> Result<JobCgroupSettings, String> {
    ExecutionNodeSettings::parse(&node_text(table)).map(|settings| settings.job_cgroup)
}

#[test]
fn a_node_file_without_the_table_runs_its_jobs_as_before() {
    let table = parsed("").expect("a file without the table");
    assert_eq!(table, JobCgroupSettings::default());
    assert_eq!(table.slice, None, "no Slice= line: systemd's own slice");
    assert_eq!(table.slice_cpu_weight, None);
    assert_eq!(DEVICE_JOB_CPU_WEIGHT_DEFAULT, 100, "systemd's own default");
    assert_eq!(table.job_cpu_weight(true), 100);
    assert_eq!(CPU_JOB_CPU_WEIGHT_DEFAULT, 10);
}

#[test]
fn a_job_that_leases_no_device_yields_to_one_that_does() {
    let table = parsed("").expect("defaults");
    assert!(
        table.job_cpu_weight(false) < table.job_cpu_weight(true),
        "a CPU job's weight {} is below a device job's {}",
        table.job_cpu_weight(false),
        table.job_cpu_weight(true)
    );
    let set = parsed("device_job_cpu_weight = 200\ncpu_job_cpu_weight = 2").expect("both set");
    assert_eq!(set.job_cpu_weight(true), 200);
    assert_eq!(set.job_cpu_weight(false), 2);
}

#[test]
fn a_node_file_names_a_top_level_slice_and_its_weight() {
    let table = parsed(
        "slice = \"oneiron.slice\"\nslice_cpu_weight = 5\ndevice_job_cpu_weight = 100\ncpu_job_cpu_weight = 10",
    )
    .expect("all four keys");
    assert_eq!(table.slice.as_deref(), Some("oneiron.slice"));
    assert_eq!(table.slice_cpu_weight, Some(5));
    assert_eq!(table.job_cpu_weight(false), 10);
}

#[test]
fn a_weight_outside_systemds_range_does_not_validate() {
    for table in [
        "cpu_job_cpu_weight = 0",
        "device_job_cpu_weight = 10001",
        "slice = \"oneiron.slice\"\nslice_cpu_weight = 0",
    ] {
        let refused = parsed(table).expect_err(table);
        assert!(refused.contains("must be 1 to 10000"), "{table}: {refused}");
    }
}

#[test]
fn a_slice_that_is_not_the_nodes_own_top_level_slice_does_not_validate() {
    for (slice, why) in [
        ("oneiron.service", "ends in"),
        ("oneiron-job.slice", "no '-'"),
        ("-.slice", "no '-'"),
        (".slice", "1 to 249 bytes"),
        ("system.slice", "systemd's own slice"),
        ("user.slice", "systemd's own slice"),
        ("machine.slice", "systemd's own slice"),
        ("jobs/oneiron.slice", "only letters"),
        ("one iron.slice", "only letters"),
    ] {
        let refused = parsed(&format!("slice = \"{slice}\"")).expect_err(slice);
        assert!(
            refused.contains("execution_node.job_cgroup.slice") && refused.contains(why),
            "{slice}: {refused}"
        );
    }
    let long = format!("{}.slice", "a".repeat(250));
    let refused = parsed(&format!("slice = \"{long}\"")).expect_err("a 256-byte name");
    assert!(refused.contains("1 to 249 bytes"), "{refused}");
}

#[test]
fn a_slice_weight_without_a_slice_does_not_validate() {
    let refused = parsed("slice_cpu_weight = 5").expect_err("a weight with no slice");
    assert!(
        refused.contains("slice_cpu_weight needs execution_node.job_cgroup.slice"),
        "{refused}"
    );
}

#[test]
fn an_unknown_key_in_the_table_does_not_validate() {
    let refused = parsed("cpu_weight = 5").expect_err("an unknown key");
    assert!(refused.contains("unknown field"), "{refused}");
}

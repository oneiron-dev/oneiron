//! Row NODE-NETWORK-HOST-UNIT (FLEET-TOOL-PARITY, order 1): a second job
//! unit with the machine's own network, for a pin whose template lists
//! `host`. The root control handler starts it only for a host pin, the
//! prepare step refuses a pin whose network is not its unit's, a host pin
//! under a template that requires `network_closed` is refused at admission,
//! and every step that names a key's unit by id names it under both
//! templates. Pure functions of the scope: no service manager, no root.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features --test node_network_host_unit`.

use std::collections::BTreeSet;

use oneiron_server::gpu_execution_node::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::jobs::{JobKeyId, JobUnitPhase, JobUnitStatus};
use oneiron_server::gpu_execution_node::scope_systemd::network_unit::{
    HOST_NETWORK_UNIT_TEMPLATE_PATH, UnitNetwork, installed_unit_names, key_status,
    listed_job_units, start_unit_network, unit_admits_pin_network,
};
use oneiron_server::gpu_execution_node::scope_systemd::step::StepArgs;
use oneiron_server::gpu_execution_node::scope_systemd::unit_file::{
    UnitInputs, render_job_unit, render_job_unit_for,
};
use oneiron_server::gpu_execution_node::wire::{
    NetworkMode, OutputDecl, ResourceRequest, ScopeKind, WorkloadPin,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn inputs() -> UnitInputs {
    UnitInputs {
        binary: "/usr/bin/oneiron".into(),
        node_file: "/etc/oneiron/execution-node.toml".into(),
        engine_account: "oneiron".to_owned(),
        job_account: "oneiron-job".to_owned(),
        state_dir: "/var/lib/oneiron/jobs".into(),
        work_dir: "/data/oneiron-jobs".into(),
        protected: vec!["/var/lib/oneiron".into()],
        runtime_max_secs: 86_400,
        stop_grace_secs: 10,
        start_timeout_secs: 60,
    }
}

/// A node file holding the template `fetch`, with `extra` lines appended to
/// that template's table.
fn node_text(extra: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["5d1e3c8a9b7f4e21a0c6d2b8f3e9a714"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"

[execution_node.templates.fetch]
repo = "/srv/git/fetch.git"
entries = ["tools/*.sh"]
interpreter = ["/usr/bin/bash"]
returnable = ["verdict.json"]
max_secs = 1800
memory_gib = 8
disk_gib = 4
{extra}
"#
    )
}

/// A CPU-only pin of `fetch` at `digest` asking `network`.
fn pin(digest: &str, network: NetworkMode) -> WorkloadPin {
    WorkloadPin {
        template: "fetch".to_owned(),
        template_digest: digest.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/fetch.json".to_owned(),
        entry: "tools/fetch.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 1_024,
            disk_mib: 1_024,
            devices: Vec::new(),
            maximum_secs: 1_800,
        },
        scope: ScopeKind::Host,
        network,
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: true,
        }],
    }
}

fn status(phase: JobUnitPhase, cgroup_empty: bool) -> JobUnitStatus {
    JobUnitStatus {
        phase,
        cgroup_empty,
    }
}

#[test]
fn the_host_network_unit_is_the_private_unit_with_the_host_network() {
    let private = render_job_unit(&inputs());
    assert_eq!(
        private,
        render_job_unit_for(&inputs(), UnitNetwork::Private),
        "the private template is the one install wrote before this row"
    );
    assert!(private.contains("PrivateNetwork=yes\n"));
    assert!(!private.contains("--host-network"));
    assert!(!private.contains("RestrictAddressFamilies="));

    let host = render_job_unit_for(&inputs(), UnitNetwork::Host);
    let private_lines: BTreeSet<&str> = private.lines().collect();
    let host_lines: BTreeSet<&str> = host.lines().collect();
    let only_host: BTreeSet<&str> = host_lines.difference(&private_lines).copied().collect();
    let only_private: BTreeSet<&str> = private_lines.difference(&host_lines).copied().collect();
    let root =
        "--host-network --node-file /etc/oneiron/execution-node.toml --engine-account oneiron %i";
    let expected_host: BTreeSet<String> = [
        "Description=Oneiron job %i (host network)".to_owned(),
        format!("ExecStartPre=+/usr/bin/oneiron job-prepare {root}"),
        format!("ExecStartPost=+/usr/bin/oneiron job-prepare --after-exec {root}"),
        format!("ExecStopPost=+/usr/bin/oneiron job-ended {root}"),
        "PrivateNetwork=no".to_owned(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK".to_owned(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        only_host
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<BTreeSet<_>>(),
        expected_host,
        "the host network unit differs only in its network and its root steps' flag"
    );
    assert_eq!(only_private.len(), 5, "{only_private:?}");
    assert!(only_private.contains("PrivateNetwork=yes"));
    // The job itself, every other bound and the backstop are the same.
    assert!(host.contains("ExecStart=/usr/bin/oneiron job-exec %i\n"));
    assert!(host.contains("RuntimeMaxSec=86400\n"));
    assert!(host.contains("ProtectSystem=strict\n"));
    assert!(host.contains("DevicePolicy=closed\n"));
    assert_eq!(
        HOST_NETWORK_UNIT_TEMPLATE_PATH,
        "/etc/systemd/system/oneiron-job-host-network@.service"
    );
}

#[test]
fn the_control_handler_starts_the_host_network_unit_only_for_a_host_pin() {
    assert_eq!(
        start_unit_network(NetworkMode::Host, true),
        UnitNetwork::Host
    );
    assert_eq!(
        start_unit_network(NetworkMode::None, true),
        UnitNetwork::Private
    );
    assert_eq!(
        start_unit_network(NetworkMode::None, false),
        UnitNetwork::Private
    );
    // No host network template installed: the private unit starts, and its
    // prepare step refuses the host pin.
    assert_eq!(
        start_unit_network(NetworkMode::Host, false),
        UnitNetwork::Private
    );
}

#[test]
fn prepare_refuses_a_pin_whose_network_is_not_its_units() {
    assert_eq!(
        unit_admits_pin_network(UnitNetwork::Private, NetworkMode::None),
        Ok(())
    );
    assert_eq!(
        unit_admits_pin_network(UnitNetwork::Host, NetworkMode::Host),
        Ok(())
    );
    let host_in_private = unit_admits_pin_network(UnitNetwork::Private, NetworkMode::Host)
        .expect_err("a host pin in the private unit is refused");
    assert!(
        host_in_private.starts_with("network_host_unit_not_installed: "),
        "{host_in_private}"
    );
    let none_in_host = unit_admits_pin_network(UnitNetwork::Host, NetworkMode::None)
        .expect_err("a pin of no network in the host network unit is refused");
    assert!(
        none_in_host.starts_with("network_unit_not_private: "),
        "{none_in_host}"
    );
}

#[test]
fn a_host_pin_under_a_template_that_requires_network_closed_is_refused() -> TestResult {
    // The default `require` holds network_closed.
    let closed = ExecutionNodeSettings::parse(&node_text(r#"network = ["none", "host"]"#))
        .map_err(|why| format!("the node's file: {why}"))?;
    let digest = closed
        .template_digest("fetch")
        .ok_or("the template fetch")?;
    assert_eq!(closed.admit_pin(&pin(&digest, NetworkMode::None)), Ok(()));
    let refused = closed
        .admit_pin(&pin(&digest, NetworkMode::Host))
        .expect_err("a host pin cannot have network_closed");
    assert!(
        refused.starts_with("network_closed_required: "),
        "{refused}"
    );

    // The template opens host by leaving network_closed out of `require`.
    let open = ExecutionNodeSettings::parse(&node_text(
        "network = [\"none\", \"host\"]\nrequire = [\"file_wall\"]",
    ))
    .map_err(|why| format!("the node's file: {why}"))?;
    let digest = open.template_digest("fetch").ok_or("the template fetch")?;
    assert_eq!(open.admit_pin(&pin(&digest, NetworkMode::Host)), Ok(()));
    assert_eq!(open.admit_pin(&pin(&digest, NetworkMode::None)), Ok(()));

    // The default network list stays closed, whatever `require` says.
    let default = ExecutionNodeSettings::parse(&node_text("require = [\"file_wall\"]"))
        .map_err(|why| format!("the node's file: {why}"))?;
    let digest = default
        .template_digest("fetch")
        .ok_or("the template fetch")?;
    assert_eq!(
        default.admit_pin(&pin(&digest, NetworkMode::Host)),
        Err("network_not_permitted".to_owned())
    );
    Ok(())
}

#[test]
fn a_stop_names_the_key_unit_under_each_installed_template() {
    let id = JobKeyId::for_key("k");
    assert_eq!(
        installed_unit_names(id.as_str(), true),
        [
            format!("oneiron-job@{id}.service"),
            format!("oneiron-job-host-network@{id}.service"),
        ]
    );
    // A machine whose install predates this row has the private unit alone.
    assert_eq!(
        installed_unit_names(id.as_str(), false),
        [format!("oneiron-job@{id}.service")]
    );
    assert_eq!(id.unit_name(), UnitNetwork::Private.unit_name(id.as_str()));
}

#[test]
fn live_units_lists_job_units_of_both_templates() {
    let a = JobKeyId::for_key("a");
    let b = JobKeyId::for_key("b");
    let listing = format!(
        "oneiron-job@{a}.service loaded active running Oneiron job {a}\n\
         oneiron-job-host-network@{b}.service loaded active running Oneiron job {b} (host network)\n\
         oneiron-job-cutoff-{a}.service loaded inactive dead x\n\
         oneiron-job-host-network@nothex.service loaded failed failed x\n"
    );
    assert_eq!(
        listed_job_units(&listing),
        [(a, UnitNetwork::Private), (b, UnitNetwork::Host)]
    );
}

#[test]
fn a_key_status_is_the_live_one_of_its_two_units() {
    let gone = status(JobUnitPhase::Inactive, true);
    let running = status(JobUnitPhase::Active, false);
    assert_eq!(key_status(&[gone, running]), running);
    assert_eq!(key_status(&[running, gone]), running);
    assert!(key_status(&[gone, gone]).is_gone());
    // A unit that ended with a process left keeps the key from reading gone.
    let leftover = status(JobUnitPhase::Inactive, false);
    assert!(!key_status(&[gone, leftover]).is_gone());
    assert_eq!(key_status(&[gone]), gone);
}

#[test]
fn a_root_step_reads_its_host_network_flag() -> TestResult {
    let id = JobKeyId::for_key("k");
    let words = |extra: &[&str]| -> Vec<String> {
        let mut words = vec![
            "--node-file".to_owned(),
            "/etc/oneiron/execution-node.toml".to_owned(),
            "--engine-account".to_owned(),
            "oneiron".to_owned(),
        ];
        words.extend(extra.iter().map(|word| (*word).to_owned()));
        words.push(id.as_str().to_owned());
        words
    };
    let host = StepArgs::parse(&words(&["--host-network", "--after-exec"]))?;
    assert!(host.host_network && host.after_exec);
    assert_eq!(
        host.unit_name(),
        format!("oneiron-job-host-network@{id}.service")
    );
    let private = StepArgs::parse(&words(&[]))?;
    assert!(!private.host_network);
    assert_eq!(private.unit_name(), id.unit_name());
    Ok(())
}

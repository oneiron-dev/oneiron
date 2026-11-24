//! An execution node's template check (pass 33 row R1,
//! `33-exec-node/DESIGN.md` section 11 T6, T7, T8; section 7.3 reserve step
//! 5): a pin runs only inside a template the node holds now, by digest,
//! entry, ceilings and parameters. The node reads its `[execution_node]`
//! file fresh at each admission, so an edit binds the next one.
//!
//! The half of T7 that writes the refusal down as a closed key is the
//! journal's (row R3a, `node_job_journal.rs`): the check here is the reason
//! it records, and it holds no device.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! execution_node_templates`.

use std::path::Path;
use std::sync::Arc;

use oneiron::job_workload::{
    BoundRequirement, DeviceKind, DeviceLease, DevicePlacement, ScopeBound, Sharing,
};
use oneiron::{Vault, VaultConfig};
use oneiron_server::gpu_execution_node::wire::{
    DeviceClaim, NetworkMode, OutputDecl, ResourceRequest, ScopeKind, WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    ExecutionNode, ExecutionNodeSettings, GpuDeviceOffer, GpuSlotTable, NvidiaSmiProbe,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The issuer every file here names.
const ISSUER: &str = "5d1e3c8a9b7f4e21a0c6d2b8f3e9a714";

/// A node file holding the template `probe`, with `extra` lines appended to
/// that template's table.
fn node_text(max_secs: u64, extra: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["{ISSUER}"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"

[execution_node.templates.probe]
repo = "/srv/git/probe.git"
entries = ["tools/units/*.sh"]
interpreter = ["/usr/bin/bash"]
returnable = ["verdict.json"]
max_secs = {max_secs}
memory_gib = 8
disk_gib = 4
{extra}
"#
    )
}

fn settings(text: &str) -> Result<ExecutionNodeSettings, Box<dyn std::error::Error>> {
    ExecutionNodeSettings::parse(text).map_err(|why| format!("the node's file: {why}").into())
}

/// A pin of `probe` at `digest` that fits it.
fn pin(digest: &str) -> WorkloadPin {
    WorkloadPin {
        template: "probe".to_owned(),
        template_digest: digest.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/probe.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 8 * 1_024,
            disk_mib: 4 * 1_024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 1_024,
                features: vec!["cuda".to_owned()],
                sharing: Sharing::Exclusive,
            }],
            maximum_secs: 1_800,
        },
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: true,
        }],
    }
}

/// The node of a fresh vault, reading its file at `file`.
fn node_at(dir: &Path, file: &Path) -> Result<ExecutionNode, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let vault = Vault::open(dir, VaultConfig::device()).map_err(|error| format!("{error:?}"))?;
    Ok(ExecutionNode::new(
        file.to_path_buf(),
        Arc::new(vault),
        Arc::new(GpuSlotTable::new(
            Arc::new(NvidiaSmiProbe),
            GpuDeviceOffer::default(),
        )),
    ))
}

#[test]
fn a_pin_for_a_changed_template_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("execution-node.toml");
    std::fs::write(&file, node_text(1_800, ""))?;
    let node = node_at(&dir.path().join("vault"), &file)?;
    let digest = node
        .template_digest("probe")
        .ok_or("the node holds the template probe")?;
    let pinned = pin(&digest);
    assert_eq!(node.admit_pin(&pinned), Ok(()), "the pin fits its template");

    // The operator edits the template at the box: the next admission reads
    // the file again, and the old digest no longer names what would run.
    std::fs::write(&file, node_text(3_600, ""))?;
    let changed = node
        .template_digest("probe")
        .ok_or("the node still holds probe")?;
    assert_ne!(
        changed, digest,
        "an edit of the template changes its digest"
    );
    assert_eq!(
        node.admit_pin(&pinned),
        Err("template_digest_changed".to_owned())
    );
    assert_eq!(node.admit_pin(&pin(&changed)), Ok(()));

    // A template the node does not hold refuses every pin of it.
    let mut other = pin(&changed);
    other.template = "other".to_owned();
    assert_eq!(node.admit_pin(&other), Err("template_unknown".to_owned()));

    // EM-11 = B: no heads, or a head that is no entry hash, is never held.
    assert!(!node.folded(&[]), "an empty position is never held");
    assert!(
        !node.folded(&["not-an-entry-hash".to_owned()]),
        "a malformed head is never held"
    );
    Ok(())
}

#[test]
fn an_entry_outside_the_templates_list_is_refused_as_a_closed_key_with_no_lease() -> TestResult {
    let node = settings(&node_text(1_800, ""))?;
    let digest = node.template_digest("probe").ok_or("probe")?;
    for (entry, reason) in [
        ("tools/other/run.sh", "entry_not_listed"),
        ("tools/units/nested/run.sh", "entry_not_listed"),
        ("tools/units/run.py", "entry_not_listed"),
        ("../tools/units/run.sh", "entry_not_relative"),
        ("tools/units/../../run.sh", "entry_not_relative"),
        ("/tools/units/run.sh", "entry_not_relative"),
        ("tools/units/./run.sh", "entry_not_relative"),
        ("tools//units/run.sh", "entry_not_relative"),
    ] {
        let mut outside = pin(&digest);
        outside.entry = entry.to_owned();
        assert_eq!(
            node.admit_pin(&outside),
            Err(reason.to_owned()),
            "entry {entry:?}"
        );
    }
    let mut unreturnable = pin(&digest);
    unreturnable.outputs.push(OutputDecl {
        name: "weights.bin".to_owned(),
        returnable: true,
    });
    assert_eq!(
        node.admit_pin(&unreturnable),
        Err("output_not_returnable: weights.bin".to_owned())
    );
    let mut networked = pin(&digest);
    networked.network = NetworkMode::Host;
    assert_eq!(
        node.admit_pin(&networked),
        Err("network_not_permitted".to_owned())
    );
    let mut contained = pin(&digest);
    contained.scope = ScopeKind::Container {
        image: "registry.example/probe@sha256:00".to_owned(),
    };
    assert_eq!(
        node.admit_pin(&contained),
        Err("scope_not_permitted".to_owned())
    );
    Ok(())
}

#[test]
fn a_request_above_the_templates_ceiling_is_refused() -> TestResult {
    let node = settings(&node_text(1_800, ""))?;
    let digest = node.template_digest("probe").ok_or("probe")?;
    assert_eq!(
        node.admit_pin(&pin(&digest)),
        Ok(()),
        "a request at every ceiling fits"
    );
    let above: [(&str, fn(&mut ResourceRequest)); 6] = [
        ("devices", |request| request.devices[0].count = 2),
        ("devices", |request| {
            let second = request.devices[0].clone();
            request.devices.push(second);
        }),
        ("cpu_threads", |request| request.cpu_threads = 5),
        ("maximum_secs", |request| request.maximum_secs = 1_801),
        ("memory_mib", |request| request.memory_mib = 8 * 1_024 + 1),
        ("disk_mib", |request| request.disk_mib = 4 * 1_024 + 1),
    ];
    for (field, raise) in above {
        let mut asked = pin(&digest);
        raise(&mut asked.request);
        assert_eq!(
            node.admit_pin(&asked),
            Err(format!("request_above_ceiling: {field}")),
            "{field}"
        );
    }
    let mut at_threads = pin(&digest);
    at_threads.request.cpu_threads = 4;
    assert_eq!(
        node.admit_pin(&at_threads),
        Ok(()),
        "a request at the template's default threads fits"
    );
    Ok(())
}

#[test]
fn a_placement_whose_unified_memory_and_host_memory_pass_the_ceiling_is_refused() -> TestResult {
    let node = settings(&node_text(1_800, ""))?;
    let digest = node.template_digest("probe").ok_or("probe")?;
    let asked = pin(&digest);
    let placed = |host_memory_mib| DevicePlacement {
        devices: vec![DeviceLease {
            claim: 0,
            device_id: "GPU-0f1e2d3c".to_owned(),
            sharing: Sharing::Exclusive,
        }],
        host_memory_mib,
    };
    // A dedicated card leases the request's host memory alone: at the
    // template's 8 GiB it fits.
    assert_eq!(node.admit_placement(&asked, &placed(8 * 1_024)), Ok(()));
    // A unified device adds its claim's 1 GiB to the same pool (pass 34,
    // section 2.1): past the ceiling, the launch is refused.
    assert_eq!(
        node.admit_placement(&asked, &placed(8 * 1_024 + 1_024)),
        Err("request_above_ceiling: host_memory_mib".to_owned())
    );
    Ok(())
}

#[test]
fn an_argument_outside_the_templates_params_is_refused() -> TestResult {
    let node = settings(&node_text(
        1_800,
        r#"params = { seed = "[0-9]{1,6}", arm = "[a-z0-9-]{1,40}" }"#,
    ))?;
    let digest = node.template_digest("probe").ok_or("probe")?;
    let with_args = |args: &[&str]| {
        let mut pinned = pin(&digest);
        pinned.args = args.iter().map(|arg| (*arg).to_owned()).collect();
        node.admit_pin(&pinned)
    };
    assert_eq!(with_args(&["seed=42", "arm=ner-m1"]), Ok(()));
    assert_eq!(
        with_args(&["seed=42; rm -rf /"]),
        Err("arg_pattern_mismatch: seed".to_owned())
    );
    assert_eq!(
        with_args(&["seed=1234567"]),
        Err("arg_pattern_mismatch: seed".to_owned())
    );
    assert_eq!(with_args(&["--seed"]), Err("arg_not_name_value".to_owned()));
    assert_eq!(
        with_args(&["lr=0.1"]),
        Err("arg_not_declared: lr".to_owned())
    );
    Ok(())
}

#[test]
fn a_template_that_declares_no_params_refuses_every_argument() -> TestResult {
    let node = settings(&node_text(1_800, "params = {}"))?;
    let digest = node.template_digest("probe").ok_or("probe")?;
    let mut with_arg = pin(&digest);
    with_arg.args = vec!["mode=debug".to_owned()];
    assert_eq!(
        node.admit_pin(&with_arg),
        Err("arg_not_declared: mode".to_owned())
    );
    assert_eq!(node.admit_pin(&pin(&digest)), Ok(()), "no argument fits");
    Ok(())
}

#[test]
fn a_param_pattern_that_does_not_compile_alone_does_not_validate() {
    let text = node_text(1_800, r#"params = { seed = "[0-9]{1,6})|reject(?:" }"#);
    let refused = ExecutionNodeSettings::parse(&text);
    assert!(
        refused.is_err(),
        "a pattern that closes its own group must not validate: {refused:?}"
    );
}

#[test]
fn a_template_requires_the_file_wall_and_the_closed_network_unless_it_says_otherwise() -> TestResult
{
    let plain = settings(&node_text(1_800, ""))?;
    let template = plain.templates.get("probe").ok_or("probe")?;
    assert_eq!(
        template.require,
        [ScopeBound::FileWall, ScopeBound::NetworkClosed].map(|bound| BoundRequirement {
            bound,
            kernel: false
        }),
        "the default list keeps a workload out of the vault and off the network"
    );
    let sealed = settings(&node_text(
        1_800,
        r#"require = ["file_wall", "network_closed", "device_closure", "memory_cap:kernel"]"#,
    ))?;
    assert_ne!(
        sealed.template_digest("probe"),
        plain.template_digest("probe"),
        "the required bounds are part of what a pin names"
    );
    assert!(
        ExecutionNodeSettings::parse(&node_text(1_800, r#"require = ["wishful"]"#)).is_err(),
        "a bound outside the closed list does not validate"
    );
    Ok(())
}

#[test]
fn a_node_file_that_names_no_single_issuer_does_not_validate() {
    let text = node_text(1_800, "").replace(&format!("[\"{ISSUER}\"]"), "[]");
    let refused = ExecutionNodeSettings::parse(&text);
    assert!(
        refused
            .as_ref()
            .is_err_and(|why| why.contains("exactly one MACHINE id")),
        "an enabled node with no issuer must not validate: {refused:?}"
    );
}

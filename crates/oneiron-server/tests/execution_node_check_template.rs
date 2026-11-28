//! The `oneiron-check` template as committed
//! (`scripts/execution-node/check/oneiron-check.template.toml`; FIX
//! [ONEIRON-CHECK-TEMPLATE], `docs/ops/execution-node-mirror-and-check.md`).
//! The table an execution node appends to its `[execution_node]` file
//! validates, and a CPU-only check pin of it passes reserve step 5. The
//! template's params and ceilings refuse what the check script and the
//! fleet's check booking would refuse.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! execution_node_check_template`.

use oneiron::job_workload::{DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::wire::{
    DeviceClaim, NetworkMode, OutputDecl, ResourceRequest, ScopeKind, WorkloadPin,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The template table, byte for byte as the node's operator appends it.
const TEMPLATE: &str =
    include_str!("../../../scripts/execution-node/check/oneiron-check.template.toml");

/// The template's one entry, which is also the contract a check pin names.
const ENTRY: &str = "scripts/execution-node/check/oneiron_check.sh";

/// A lane check as the fleet books it today: both crates, all features, two
/// test targets under the test cfg, and the format check.
const LANE_CHECK: [&str; 4] = [
    "packages=oneiron,oneiron-server",
    "features=all",
    "tests=oneiron-server:lib,vault_models_owner_doors",
    "fmt=1",
];

/// A node file: the `[execution_node]` table every enabled node has, then the
/// committed template.
fn node_file() -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["5d1e3c8a9b7f4e21a0c6d2b8f3e9a714"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"

{TEMPLATE}"#
    )
}

fn settings() -> Result<ExecutionNodeSettings, Box<dyn std::error::Error>> {
    ExecutionNodeSettings::parse(&node_file())
        .map_err(|why| format!("the node's file: {why}").into())
}

/// A check pin of the template at its digest, at the template's ceilings.
fn check_pin(
    settings: &ExecutionNodeSettings,
    args: &[&str],
) -> Result<WorkloadPin, Box<dyn std::error::Error>> {
    let template_digest = settings
        .template_digest("oneiron-check")
        .ok_or("the node holds no oneiron-check template")?;
    Ok(WorkloadPin {
        template: "oneiron-check".to_owned(),
        template_digest,
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: ENTRY.to_owned(),
        entry: ENTRY.to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        request: ResourceRequest {
            cpu_threads: 6,
            memory_mib: 28 * 1_024,
            disk_mib: 60 * 1_024,
            devices: Vec::new(),
            maximum_secs: 10_800,
        },
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: true,
        }],
    })
}

#[test]
fn the_committed_check_template_admits_a_cpu_check_pin() -> TestResult {
    let settings = settings()?;
    let offers = settings.template_offers()?;
    let offer = offers
        .iter()
        .find(|offer| offer.name == "oneiron-check")
        .ok_or("the node offers no oneiron-check template")?;
    assert_eq!(offer.network, vec![NetworkMode::None]);
    assert_eq!(offer.returnable, vec!["verdict.json".to_owned()]);

    settings.admit_pin(&check_pin(&settings, &LANE_CHECK)?)?;
    // An empty `tests` value is a check with no test targets.
    settings.admit_pin(&check_pin(
        &settings,
        &["packages=oneiron", "features=default", "tests=", "fmt=0"],
    )?)?;
    Ok(())
}

#[test]
fn the_check_template_refuses_what_the_check_does_not_run() -> TestResult {
    let settings = settings()?;
    let refusal = |pin: &WorkloadPin| settings.admit_pin(pin).err();

    let nightly = check_pin(&settings, &["packages=oneiron", "features=nightly"])?;
    assert_eq!(
        refusal(&nightly).as_deref(),
        Some("arg_pattern_mismatch: features")
    );
    let shell_text = check_pin(&settings, &["packages=oneiron;true"])?;
    assert_eq!(
        refusal(&shell_text).as_deref(),
        Some("arg_pattern_mismatch: packages")
    );
    let undeclared = check_pin(&settings, &["packages=oneiron", "jobs=64"])?;
    assert_eq!(
        refusal(&undeclared).as_deref(),
        Some("arg_not_declared: jobs")
    );

    let mut other_entry = check_pin(&settings, &LANE_CHECK)?;
    other_entry.entry = "scripts/execution-node/check/test_vendor_config.sh".to_owned();
    assert_eq!(refusal(&other_entry).as_deref(), Some("entry_not_listed"));

    let mut networked = check_pin(&settings, &LANE_CHECK)?;
    networked.network = NetworkMode::Host;
    assert_eq!(
        refusal(&networked).as_deref(),
        Some("network_not_permitted")
    );

    let mut with_card = check_pin(&settings, &LANE_CHECK)?;
    with_card.request.devices = vec![DeviceClaim {
        kind: DeviceKind::Gpu,
        count: 1,
        memory_mib: 1_024,
        features: Vec::new(),
        sharing: Sharing::Exclusive,
    }];
    assert_eq!(
        refusal(&with_card).as_deref(),
        Some("request_above_ceiling: devices")
    );

    let mut over_memory = check_pin(&settings, &LANE_CHECK)?;
    over_memory.request.memory_mib += 1;
    assert_eq!(
        refusal(&over_memory).as_deref(),
        Some("request_above_ceiling: memory_mib")
    );

    let mut over_time = check_pin(&settings, &LANE_CHECK)?;
    over_time.request.maximum_secs += 1;
    assert_eq!(
        refusal(&over_time).as_deref(),
        Some("request_above_ceiling: maximum_secs")
    );
    Ok(())
}

//! What this machine's systemd scope can enforce, bound by bound (pass 34,
//! 2.2, `ScopeCapabilities`): from the kernel and the service manager as the
//! engine's account can read them, from the installed unit template, and
//! from the last probe `execution-node check` ran on this boot. A bound
//! nothing shows is `none`. Each job's `job-exec` proves its template's
//! required bounds again from inside its own unit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::super::jobs::ScopeCapabilities;
use super::records::{BoundReport, bound};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
use super::{CHECK_REPORT_SUFFIX, POLKIT_RULE_PATH, UNIT_TEMPLATE_PATH};

/// What the kernel and the service manager offer, read without privilege.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelFacts {
    /// The service manager's version, when `systemctl --version` answers.
    pub systemd_version: Option<u32>,
    /// Whether process 1 is systemd.
    pub systemd_is_init: bool,
    /// The cgroup v2 controllers at the root (`cgroup.controllers`); empty
    /// on a machine without the unified hierarchy.
    pub cgroup_controllers: BTreeSet<String>,
    /// Landlock's ABI version; below 1 where the kernel has none.
    pub landlock_abi: i32,
    /// Whether the unit template and the polkit rule are installed.
    pub unit_installed: bool,
    pub rule_installed: bool,
}

/// The facts, now.
#[must_use]
pub fn kernel_facts() -> KernelFacts {
    let systemd_version = run_tool("systemctl", &["--version"], SYSTEMCTL_TIMEOUT)
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .nth(1)
                .and_then(|word| word.parse().ok())
        });
    let systemd_is_init = std::fs::read_to_string("/proc/1/comm")
        .map(|name| name.trim() == "systemd")
        .unwrap_or(false);
    let cgroup_controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .map(|text| text.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    KernelFacts {
        systemd_version,
        systemd_is_init,
        cgroup_controllers,
        landlock_abi: oneiron_container::landlock_abi(),
        unit_installed: Path::new(UNIT_TEMPLATE_PATH).is_file(),
        rule_installed: Path::new(POLKIT_RULE_PATH).is_file(),
    }
}

/// The report `execution-node check` writes beside the node file (root,
/// mode 0644): the probe unit's proofs on one boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub boot_id: String,
    pub at_ms: u64,
    pub facts: KernelFacts,
    /// Each bound the probe unit proved or failed from inside.
    pub proofs: BTreeMap<String, BoundReport>,
    /// Why the probe unit did not report, when it did not.
    pub probe_failure: Option<String>,
}

/// Where `check` writes its report for the node file `node_file`.
#[must_use]
pub fn check_report_path(node_file: &Path) -> PathBuf {
    let mut name = node_file.as_os_str().to_os_string();
    name.push(CHECK_REPORT_SUFFIX);
    PathBuf::from(name)
}

/// The machine's capability report for jobs (pass 34, 2.2).
#[must_use]
pub fn report(node_file: &Path) -> BTreeMap<String, BoundReport> {
    let facts = kernel_facts();
    let boot = super::safe_fs::boot_id();
    let probed = std::fs::read(check_report_path(node_file))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CheckReport>(&bytes).ok())
        .filter(|report| report.boot_id == boot);
    capabilities_of(&facts, probed.as_ref())
}

/// The capability report from the facts and, when there is one from this
/// boot, the probe's proofs: a proof from inside wins over what the
/// configuration promises.
#[must_use]
pub fn capabilities_of(
    facts: &KernelFacts,
    probed: Option<&CheckReport>,
) -> BTreeMap<String, BoundReport> {
    let manager = facts.systemd_is_init && facts.systemd_version.is_some();
    let unified = !facts.cgroup_controllers.is_empty();
    let installed = manager && unified && facts.unit_installed;
    let has = |controller: &str| facts.cgroup_controllers.contains(controller);
    let promise = |holds: bool, yes: &str, no: &str| {
        if holds {
            BoundReport::kernel(yes)
        } else {
            BoundReport::none(no)
        }
    };
    let mut out = BTreeMap::new();
    out.insert(
        bound::TREE_KILL.to_owned(),
        promise(
            installed,
            "the unit's cgroup, KillMode=control-group",
            "needs systemd as process 1, cgroup v2 and `execution-node install`",
        ),
    );
    out.insert(
        bound::CUTOFF_WITHOUT_ENGINE.to_owned(),
        promise(
            installed,
            "a timer unit of the service manager that the engine's account cannot stop",
            "needs systemd as process 1 and `execution-node install`",
        ),
    );
    out.insert(
        bound::EMPTINESS.to_owned(),
        promise(
            installed,
            "cgroup v2 cgroup.events populated",
            "needs cgroup v2 and `execution-node install`",
        ),
    );
    out.insert(
        bound::MEMORY_CAP.to_owned(),
        promise(
            installed && has("memory"),
            "MemoryMax= on the unit's cgroup, no swap",
            "needs the cgroup v2 memory controller",
        ),
    );
    out.insert(
        bound::CPU_CAP.to_owned(),
        BoundReport::none("this scope sets no CPU cap yet"),
    );
    out.insert(
        bound::FILE_WALL.to_owned(),
        promise(
            installed && facts.landlock_abi >= 3,
            "ProtectSystem=strict, InaccessiblePaths= and Landlock",
            "needs Landlock ABI 3",
        ),
    );
    out.insert(
        bound::NETWORK_CLOSED.to_owned(),
        promise(
            installed,
            "PrivateNetwork=yes",
            "needs `execution-node install`",
        ),
    );
    out.insert(
        bound::DEVICE_CLOSURE.to_owned(),
        promise(
            installed,
            "DevicePolicy=closed with DeviceAllow= per claim",
            "needs cgroup v2 and `execution-node install`",
        ),
    );
    out.insert(
        bound::PROCESSES_HIDDEN.to_owned(),
        promise(
            installed,
            "ProtectProc=invisible under the job's own account",
            "needs `execution-node install`",
        ),
    );
    out.insert(
        bound::WRITE_RATE_CAP.to_owned(),
        promise(
            installed && has("io"),
            "IOWriteBandwidthMax= on the payload device",
            "needs the cgroup v2 io controller",
        ),
    );
    if let Some(report) = probed {
        for (name, proof) in &report.proofs {
            if let Some(slot) = out.get_mut(name) {
                if !proof.enforced() || slot.enforced() {
                    *slot = proof.clone();
                }
            }
        }
    }
    out
}

/// R3a's [`ScopeCapabilities`] from the report by name; a bound the report
/// lacks is `none`.
#[must_use]
pub fn scope_capabilities(report: &BTreeMap<String, BoundReport>) -> ScopeCapabilities {
    let get = |name: &str| {
        report
            .get(name)
            .cloned()
            .unwrap_or_else(|| BoundReport::none("not reported"))
    };
    ScopeCapabilities {
        tree_kill: get(bound::TREE_KILL),
        cutoff_without_engine: get(bound::CUTOFF_WITHOUT_ENGINE),
        emptiness: get(bound::EMPTINESS),
        memory_cap: get(bound::MEMORY_CAP),
        cpu_cap: get(bound::CPU_CAP),
        file_wall: get(bound::FILE_WALL),
        network_closed: get(bound::NETWORK_CLOSED),
        device_closure: get(bound::DEVICE_CLOSURE),
        processes_hidden: get(bound::PROCESSES_HIDDEN),
        write_rate_cap: get(bound::WRITE_RATE_CAP),
    }
}

/// Whether a machine meets the minimum contract (pass 34, I4 and I5): tree
/// kill, a cutoff with the engine stopped, and emptiness. One that does not
/// offers no jobs.
#[must_use]
pub fn meets_minimum_contract(capabilities: &BTreeMap<String, BoundReport>) -> bool {
    bound::MINIMUM_CONTRACT
        .iter()
        .all(|name| capabilities.get(*name).is_some_and(BoundReport::enforced))
}

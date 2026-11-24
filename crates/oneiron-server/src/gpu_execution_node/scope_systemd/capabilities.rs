//! What this machine's systemd scope can enforce, bound by bound (pass 34,
//! 2.2, `ScopeCapabilities`): from the kernel and the service manager as the
//! engine's account can read them, from the installed unit template, and
//! from the last probe `execution-node check` ran on this boot. A bound
//! nothing shows is `none`. Each job's `job-exec` proves its template's
//! required bounds again from inside its own unit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::records::{
    BoundReport, ScopeBound, ScopeCapabilities, enforced_by_kernel, is_enforced, not_enforced,
    scope_capabilities,
};
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
    pub proofs: BTreeMap<ScopeBound, BoundReport>,
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
pub fn report(node_file: &Path) -> ScopeCapabilities {
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
/// configuration promises. The minimum contract (tree kill, the cutoff with
/// the engine stopped, emptiness) holds only after a probe unit of this
/// installation started, reported and stopped on this boot.
#[must_use]
pub fn capabilities_of(facts: &KernelFacts, probed: Option<&CheckReport>) -> ScopeCapabilities {
    let manager = facts.systemd_is_init && facts.systemd_version.is_some();
    let unified = !facts.cgroup_controllers.is_empty();
    let installed = manager && unified && facts.unit_installed;
    let probe_ran = probed.is_some_and(|report| report.probe_failure.is_none());
    let contract = installed && probe_ran;
    let has = |controller: &str| facts.cgroup_controllers.contains(controller);
    let promise = |holds: bool, yes: &str, no: &str| {
        if holds {
            enforced_by_kernel(yes)
        } else {
            not_enforced(no)
        }
    };
    let mut out = BTreeMap::new();
    out.insert(
        ScopeBound::TreeKill,
        promise(
            contract,
            "the unit's cgroup, KillMode=control-group; this boot's probe unit stopped",
            "needs systemd as process 1, cgroup v2, `execution-node install` and a passing `execution-node check` on this boot",
        ),
    );
    out.insert(
        ScopeBound::CutoffWithoutEngine,
        promise(
            contract,
            "a timer unit of the service manager that the engine's account cannot stop",
            "needs systemd as process 1, `execution-node install` and a passing `execution-node check` on this boot",
        ),
    );
    out.insert(
        ScopeBound::Emptiness,
        promise(
            contract,
            "cgroup v2 cgroup.events populated",
            "needs cgroup v2, `execution-node install` and a passing `execution-node check` on this boot",
        ),
    );
    out.insert(
        ScopeBound::MemoryCap,
        promise(
            installed && has("memory"),
            "MemoryMax= on the unit's cgroup, no swap",
            "needs the cgroup v2 memory controller",
        ),
    );
    out.insert(
        ScopeBound::CpuCap,
        not_enforced("this scope sets no CPU cap yet"),
    );
    out.insert(
        ScopeBound::FileWall,
        promise(
            installed && facts.landlock_abi >= 3,
            "ProtectSystem=strict, InaccessiblePaths= and Landlock",
            "needs Landlock ABI 3",
        ),
    );
    out.insert(
        ScopeBound::NetworkClosed,
        promise(
            installed,
            "PrivateNetwork=yes",
            "needs `execution-node install`",
        ),
    );
    out.insert(
        ScopeBound::DeviceClosure,
        promise(
            installed,
            "DevicePolicy=closed with DeviceAllow= per claim",
            "needs cgroup v2 and `execution-node install`",
        ),
    );
    out.insert(
        ScopeBound::ProcessesHidden,
        promise(
            installed,
            "ProtectProc=invisible under the job's own account",
            "needs `execution-node install`",
        ),
    );
    out.insert(
        ScopeBound::WriteRateCap,
        promise(
            installed && has("io"),
            "IOWriteBandwidthMax= on the payload device",
            "needs the cgroup v2 io controller",
        ),
    );
    if let Some(report) = probed {
        for (bound, proof) in &report.proofs {
            if let Some(slot) = out.get_mut(bound) {
                if !is_enforced(proof) || is_enforced(slot) {
                    *slot = proof.clone();
                }
            }
        }
    }
    scope_capabilities(|bound| {
        out.get(&bound)
            .cloned()
            .unwrap_or_else(|| not_enforced("not reported"))
    })
}

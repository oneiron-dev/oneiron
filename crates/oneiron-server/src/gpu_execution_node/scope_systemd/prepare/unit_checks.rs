//! The prepare step's checks of the unit as the service manager runs it: its
//! effective settings, its cgroup's files, and each bound those give.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::super::capabilities::kernel_facts;
use super::super::records::{
    BoundReport, BoundRequirement, ScopeBound, enforced_by_kernel, not_enforced,
};
use super::super::systemd_unit::show;

/// The unit's effective settings (its file and every drop-in, review r9
/// R9-14): its stop timeout is the node file's stop grace, so the cutoff's
/// TERM comes a whole grace before the maximum and the KILL by it; and it
/// names no job account and bounds `job-exec` to the two id capabilities, so
/// `job-exec` can take the job's own ids.
pub(super) fn effective_unit_matches(unit: &str, stop_grace_secs: u64) -> Result<(), String> {
    let found = show(
        unit,
        &["TimeoutStopUSec", "User", "Group", "CapabilityBoundingSet"],
    )
    .map_err(|why| format!("stop_grace_unknown: {why}"))?;
    let text = found.get("TimeoutStopUSec").map_or("", String::as_str);
    match timespan_usec(text) {
        Some(usec) if usec == stop_grace_secs.saturating_mul(1_000_000) => {}
        _ => {
            return Err(format!(
                "stop_grace_not_unit_timeout: the unit's TimeoutStopSec is {text:?} and the node file's stop grace {stop_grace_secs} s: run `oneiron execution-node install` again"
            ));
        }
    }
    match effective_identity_refusal(&found) {
        Some(why) => Err(format!(
            "unit_template_old: {why}: run `oneiron execution-node install` again"
        )),
        None => Ok(()),
    }
}

/// Why the unit's effective `User`, `Group` and `CapabilityBoundingSet` (as
/// `systemctl show` gives them) keep `job-exec` from taking the job's ids, if
/// they do.
pub(super) fn effective_identity_refusal(found: &BTreeMap<String, String>) -> Option<String> {
    for name in ["User", "Group"] {
        if let Some(value) = found.get(name).filter(|value| !value.is_empty()) {
            return Some(format!("the unit's effective {name}= is {value}"));
        }
    }
    let bounding = found
        .get("CapabilityBoundingSet")
        .map_or("", String::as_str);
    let mut capabilities: Vec<&str> = bounding.split_whitespace().collect();
    capabilities.sort_unstable();
    (capabilities != ["cap_setgid", "cap_setuid"]).then(|| {
        format!(
            "the unit's effective CapabilityBoundingSet= is {bounding:?}, not cap_setgid cap_setuid"
        )
    })
}

/// The bounds a job must have: its template's, and the device policy at the
/// kernel's strength when the job holds the job device group (review r9
/// R9-07). The group opens every card's files, so only the unit's device
/// policy keeps the job to the devices it leased.
pub(super) fn required_bounds(
    template: &[BoundRequirement],
    holds_device_group: bool,
) -> Vec<BoundRequirement> {
    let mut required = template.to_vec();
    if holds_device_group {
        required.retain(|requirement| requirement.bound != ScopeBound::DeviceClosure);
        required.push(BoundRequirement {
            bound: ScopeBound::DeviceClosure,
            kernel: true,
        });
    }
    required
}

/// A systemd time span as `systemctl show` prints it (`10s`, `1min 30s`,
/// `500ms`), in microseconds; `None` for `infinity` or a word it does not
/// know.
#[must_use]
pub(super) fn timespan_usec(text: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut any = false;
    for word in text.split_whitespace() {
        let digits = word.find(|c: char| !c.is_ascii_digit())?;
        let (number, unit) = word.split_at(digits);
        let number: u64 = number.parse().ok()?;
        let scale: u64 = match unit {
            "us" => 1,
            "ms" => 1_000,
            "s" => 1_000_000,
            "min" => 60_000_000,
            "h" => 3_600_000_000,
            "d" => 86_400_000_000,
            _ => return None,
        };
        total = total.checked_add(number.checked_mul(scale)?)?;
        any = true;
    }
    any.then_some(total)
}

/// The unit's cgroup directory under `/sys/fs/cgroup`, from the service
/// manager.
pub(super) fn unit_cgroup(unit: &str) -> Option<PathBuf> {
    let found = show(unit, &["ControlGroup"]).ok()?;
    let group = found
        .get("ControlGroup")
        .filter(|group| !group.is_empty())?;
    Some(Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
}

/// One file of the unit's cgroup, trimmed: what the kernel holds now, not
/// only what the service manager accepted.
pub(super) fn cgroup_file(group: Option<&Path>, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(group?.join(name)).ok()?;
    Some(text.trim().to_owned())
}

/// Each bound as the unit's effective properties and this kernel give it.
pub(super) fn configured_bounds(
    unit: &str,
    group: Option<&Path>,
    write_rate_failure: Option<String>,
    has_denied_device: bool,
) -> BTreeMap<ScopeBound, BoundReport> {
    let facts = kernel_facts();
    let found = show(
        unit,
        &[
            "KillMode",
            "PrivateNetwork",
            "ProtectProc",
            "ProtectSystem",
            "DevicePolicy",
        ],
    )
    .unwrap_or_default();
    let is = |name: &str, value: &str| found.get(name).is_some_and(|got| got == value);
    let cgroup_file = |name: &str| cgroup_file(group, name);
    let memory_max = cgroup_file("memory.max");
    let io_max = cgroup_file("io.max");
    let on = |holds: bool, evidence: String| {
        if holds {
            enforced_by_kernel(evidence)
        } else {
            not_enforced(evidence)
        }
    };
    let unified = !facts.cgroup_controllers.is_empty();
    let mut out = BTreeMap::new();
    out.insert(
        ScopeBound::TreeKill,
        on(
            unified && is("KillMode", "control-group"),
            format!(
                "KillMode={}",
                found.get("KillMode").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::CutoffWithoutEngine,
        enforced_by_kernel("the service manager's cutoff timer, armed before the workload"),
    );
    out.insert(
        ScopeBound::Emptiness,
        on(unified, "cgroup v2 cgroup.events".to_owned()),
    );
    out.insert(
        ScopeBound::MemoryCap,
        on(
            memory_max
                .as_deref()
                .is_some_and(|value| value.parse::<u64>().is_ok()),
            format!(
                "memory.max {}",
                memory_max.as_deref().unwrap_or("unreadable")
            ),
        ),
    );
    let cpu_max = cgroup_file("cpu.max");
    out.insert(
        ScopeBound::CpuCap,
        on(
            cpu_max
                .as_deref()
                .and_then(|text| text.split_whitespace().next())
                .is_some_and(|quota| quota.parse::<u64>().is_ok()),
            format!("cpu.max {}", cpu_max.as_deref().unwrap_or("unreadable")),
        ),
    );
    out.insert(
        ScopeBound::FileWall,
        on(
            is("ProtectSystem", "strict") && facts.landlock_abi >= 3,
            format!(
                "ProtectSystem={}, Landlock ABI {}",
                found.get("ProtectSystem").map_or("?", String::as_str),
                facts.landlock_abi
            ),
        ),
    );
    out.insert(
        ScopeBound::NetworkClosed,
        on(
            is("PrivateNetwork", "yes"),
            format!(
                "PrivateNetwork={}",
                found.get("PrivateNetwork").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::DeviceClosure,
        on(
            is("DevicePolicy", "closed"),
            format!(
                "DevicePolicy={}{}",
                found.get("DevicePolicy").map_or("?", String::as_str),
                if has_denied_device {
                    ""
                } else {
                    "; no other device to try"
                }
            ),
        ),
    );
    out.insert(
        ScopeBound::ProcessesHidden,
        on(
            is("ProtectProc", "invisible"),
            format!(
                "ProtectProc={}",
                found.get("ProtectProc").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::WriteRateCap,
        match (write_rate_failure, io_max.as_deref()) {
            (None, Some(text)) if text.contains("wbps=") && !text.contains("wbps=max") => {
                enforced_by_kernel(format!("io.max {text}"))
            }
            (None, text) => not_enforced(format!(
                "IOWriteBandwidthMax= accepted, but io.max holds no write rate ({}): no block device under the payload directory?",
                text.unwrap_or("unreadable")
            )),
            (Some(why), _) => not_enforced(format!("IOWriteBandwidthMax= not applied: {why}")),
        },
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effective(user: &str, group: &str, bounding: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("User".to_owned(), user.to_owned()),
            ("Group".to_owned(), group.to_owned()),
            ("CapabilityBoundingSet".to_owned(), bounding.to_owned()),
        ])
    }

    #[test]
    fn a_unit_with_a_job_account_or_other_capabilities_cannot_take_the_jobs_ids() {
        assert_eq!(
            effective_identity_refusal(&effective("", "", "cap_setgid cap_setuid")),
            None
        );
        assert_eq!(
            effective_identity_refusal(&effective("", "", "cap_setuid cap_setgid")),
            None
        );
        assert!(
            effective_identity_refusal(&effective("oneiron-job", "", "cap_setgid cap_setuid"))
                .is_some_and(|why| why.contains("User="))
        );
        assert!(
            effective_identity_refusal(&effective("", "oneiron-job", "cap_setgid cap_setuid"))
                .is_some_and(|why| why.contains("Group="))
        );
        assert!(effective_identity_refusal(&effective("", "", "")).is_some());
        assert!(
            effective_identity_refusal(&effective("", "", "cap_setgid cap_setuid cap_kill"))
                .is_some()
        );
    }

    #[test]
    fn a_job_that_holds_the_device_group_needs_the_kernels_device_policy() {
        let template = [BoundRequirement {
            bound: ScopeBound::DeviceClosure,
            kernel: false,
        }];
        assert_eq!(required_bounds(&template, false), template.to_vec());
        assert_eq!(
            required_bounds(&template, true),
            vec![BoundRequirement {
                bound: ScopeBound::DeviceClosure,
                kernel: true,
            }]
        );
        assert_eq!(
            required_bounds(&[], true),
            vec![BoundRequirement {
                bound: ScopeBound::DeviceClosure,
                kernel: true,
            }]
        );
    }

    #[test]
    fn a_time_span_reads_in_microseconds() {
        assert_eq!(timespan_usec("10s"), Some(10_000_000));
        assert_eq!(timespan_usec("1min 30s"), Some(90_000_000));
        assert_eq!(timespan_usec("infinity"), None);
    }
}

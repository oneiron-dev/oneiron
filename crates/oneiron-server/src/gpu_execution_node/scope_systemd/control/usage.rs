//! The job control socket's `usage` verb ([`super`]; design 7.9, FIX
//! EXEC-NODE-DISK-CHECK-UNBUILT): its three bounds as the request line
//! carries them, and root's measure of the job's payload. Ported from #10512
//! (OPUS-EXEC-R3B-UNIT, reviews r12 to r14 there) onto one job account: the
//! handler takes that account's uid from the node file.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Instant;

use super::super::super::jobs::payload_usage::{PayloadWalkBounds, measure_payload_fd_counting};
use super::super::super::jobs::{JobKeyId, PayloadUsage};
use super::super::PAYLOAD_ROOT;
use super::super::held_files::{HeldScan, add_unlinked_held};
use super::super::safe_fs::{borrow, facts, open_dir_beneath, open_dir_path};
use super::super::step::{StepArgs, StepContext};
use super::super::systemd_unit::show;
use super::ControlVerb;

/// The most digits a `usage` number has: `u64::MAX`'s.
const USAGE_NUMBER_MAX_DIGITS: usize = 20;

/// A `usage` verb's three numbers, `<bytes> <entries> <depth>`: each 1 to
/// 20 decimal digits, one space between them, the depth within a `u32`.
pub(super) fn usage_bounds(text: &str) -> Option<ControlVerb> {
    let number = |word: &str| -> Option<u64> {
        (!word.is_empty()
            && word.len() <= USAGE_NUMBER_MAX_DIGITS
            && word.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| word.parse().ok())
        .flatten()
    };
    let mut words = text.split(' ');
    let stop_past = number(words.next()?)?;
    let entries_max = number(words.next()?)?;
    let depth_max = u32::try_from(number(words.next()?)?).ok()?;
    if words.next().is_some() {
        return None;
    }
    Some(ControlVerb::Usage {
        stop_past,
        entries_max,
        depth_max,
    })
}

/// Root's measure of the job `id`'s payload: the unit's bind source
/// `<PAYLOAD_ROOT>/<id>`, opened beneath the root-only payload root and
/// never through a link, so the walk counts the directory the unit binds
/// and no path the engine's account could replace (the bind carries no
/// submount), and then the inodes on a device the walk met that the unit's
/// tasks hold with no name left and the job account owns (review r12
/// R12-01, r13 R13-01..R13-04, r14 R14-08 of #10512). Both within the walk's
/// time bound, from the request's start; the held files' links have a bound
/// of their own, the size of the walk's entry bound (r14 R14-10). The job
/// account comes from the node file, read as the root steps read it.
pub(super) fn payload_usage(
    node_file: &Path,
    engine_account: &str,
    id: &JobKeyId,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
) -> Result<PayloadUsage, String> {
    let deadline = Instant::now() + bounds.time_max;
    let unit = id.unit_name();
    let found = show(&unit, &["ControlGroup"])?;
    let control_group = found.get("ControlGroup").map_or("", String::as_str);
    // One job account runs every job of this node: its uid owns the
    // unlinked inodes the unit's own tasks hold.
    let job_uid = StepContext::open(StepArgs {
        node_file: node_file.to_owned(),
        engine_account: engine_account.to_owned(),
        instance: id.as_str().to_owned(),
        after_exec: false,
        host_namespace_error: None,
        stop_at_boot_ns: None,
    })?
    .job_uid;
    let root = open_dir_path(Path::new(PAYLOAD_ROOT))
        .map_err(|error| format!("payload_not_published: {error}"))?;
    let root_facts = facts(borrow(&root)).map_err(|error| format!("payload_root: {error}"))?;
    if root_facts.uid != 0 || root_facts.mode & 0o077 != 0 {
        return Err(format!(
            "payload_root_not_root_only: {PAYLOAD_ROOT} is uid {} mode {:o}",
            root_facts.uid, root_facts.mode
        ));
    }
    let payload = open_dir_beneath(borrow(&root), OsStr::new(id.as_str()))
        .map_err(|error| format!("payload_not_published: {error}"))?;
    let walk_bounds = PayloadWalkBounds {
        time_max: deadline.saturating_duration_since(Instant::now()),
        ..bounds.clone()
    };
    let mut counted = HashSet::new();
    let walked = measure_payload_fd_counting(payload, stop_past, &walk_bounds, &mut counted)
        .map_err(|error| format!("payload_not_measured: {error}"))?;
    let PayloadUsage::Measured { bytes } = walked else {
        return Ok(walked);
    };
    // The payload directory's own device is among them: the walk counts it.
    let payload_devices: HashSet<u64> = counted.iter().map(|&(device, _)| device).collect();
    let scan = HeldScan {
        control_group,
        payload_devices: &payload_devices,
        job_uid,
        deadline,
        links_max: bounds.entries_max,
    };
    add_unlinked_held(&scan, &mut counted, bytes, stop_past)
        .map_err(|why| format!("payload_not_measured: {why}"))
}

#[cfg(test)]
mod tests {
    use super::super::{REQUEST_MAX_BYTES, parse_request, render_request};
    use super::*;

    #[test]
    fn a_usage_request_carries_its_three_bounds_and_nothing_else() {
        let id = JobKeyId::for_key("job-usage/chunk-0");
        for (stop_past, entries_max, depth_max) in [
            (0, 1, 1),
            (1_048_576, 1_000_000, 64),
            (u64::MAX, u64::MAX, u32::MAX),
        ] {
            let verb = ControlVerb::Usage {
                stop_past,
                entries_max,
                depth_max,
            };
            let line = render_request(verb, &id);
            assert_eq!(
                line,
                format!("usage {id} {stop_past} {entries_max} {depth_max}\n")
            );
            assert!(line.len() <= REQUEST_MAX_BYTES);
            assert_eq!(parse_request(line.as_bytes()), Ok((verb, id.clone())));
            // Root answers it itself, never through systemctl.
            assert_eq!(verb.systemctl_args("u"), None);
        }
        for (line, why) in [
            (format!("usage {id}\n"), "usage_bound_missing"),
            (format!("usage {id} \n"), "usage_bound_malformed"),
            (format!("usage {id} 5\n"), "usage_bound_malformed"),
            (format!("usage {id} 5 6\n"), "usage_bound_malformed"),
            (format!("usage {id} -1 6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} +5 6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} 5  6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} 5 6 7 8\n"), "usage_bound_malformed"),
            (
                format!("usage {id} 18446744073709551616 6 7\n"),
                "usage_bound_malformed",
            ),
            (
                format!("usage {id} 5 6 4294967296\n"),
                "usage_bound_malformed",
            ),
            (format!("usage {id}.service 5 6 7\n"), "instance_not_a_job"),
        ] {
            assert_eq!(
                parse_request(line.as_bytes()),
                Err(why.to_owned()),
                "{line:?}"
            );
        }
    }
}

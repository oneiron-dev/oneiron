//! Pass 34 row W1 (`34-compute-general/DESIGN.md` 2.5), the systemd scope's
//! half of a session's renewal: the control socket's `renew` request, root's
//! decision on a renewal (forward only, a session's run only, within its
//! longest run, early enough for the handoff), the cutoff timer a renewal
//! superseded, the control handler a session needs, and the job unit's
//! backstop. Pure functions of the scope: no service manager, no root.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features --test execution_node_session_cutoff`.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use oneiron_server::gpu_execution_node::jobs::JobKeyId;
use oneiron_server::gpu_execution_node::node_settings::{
    ExecutionNodeSettings, SESSION_MAX_SECS_DEFAULT, TemplateKind,
};
use oneiron_server::gpu_execution_node::scope_systemd::control::{
    ControlVerb, parse_request, render_request,
};
use oneiron_server::gpu_execution_node::scope_systemd::cutoff::cutoff_superseded;
use oneiron_server::gpu_execution_node::scope_systemd::install::unit_runtime_max_secs;
use oneiron_server::gpu_execution_node::scope_systemd::records::{CutoffPlan, PreparedRecord};
use oneiron_server::gpu_execution_node::scope_systemd::renew::renewed_cutoff_plan;
use oneiron_server::gpu_execution_node::scope_systemd::unit_file::control_service_renews;

const NANOS_PER_SEC: u64 = 1_000_000_000;
const LAUNCH_NS: u64 = 50 * NANOS_PER_SEC;
const GRACE_SECS: u64 = 10;
const ISSUER: &str = "5d1e3c8a9b7f4e21a0c6d2b8f3e9a714";

fn secs(secs: u64) -> u64 {
    LAUNCH_NS + secs * NANOS_PER_SEC
}

/// Root's record of a run launched at `LAUNCH_NS` with a 600 s first chunk;
/// a session's (`until`, its latest cutoff) or a job's (`None`).
fn prepared(instance: &str, until: Option<u64>) -> PreparedRecord {
    PreparedRecord {
        key: "session-0".to_owned(),
        instance: instance.to_owned(),
        refusal: None,
        boot_id: "boot".to_owned(),
        at_boot_ns: LAUNCH_NS,
        account: "oneiron-job".to_owned(),
        properties: Vec::new(),
        devices: Vec::new(),
        cutoff: Some(CutoffPlan {
            unit: format!("oneiron-job-cutoff-{instance}.timer"),
            stop_at_boot_ns: secs(600 - GRACE_SECS),
            stop_grace_secs: GRACE_SECS,
        }),
        awake_unit: None,
        configured: BTreeMap::new(),
        required: Vec::new(),
        fence: Vec::new(),
        credentials: Vec::new(),
        session_until_boot_ns: until,
    }
}

fn node_text(templates: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["{ISSUER}"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"
{templates}
"#
    )
}

fn template(name: &str, max_secs: u64, extra: &str) -> String {
    format!(
        r#"
[execution_node.templates.{name}]
repo = "/srv/git/{name}.git"
entries = ["tools/units/*.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = {max_secs}
memory_gib = 8
disk_gib = 4
{extra}
"#
    )
}

/// The request names its verb, the unit's id and the cutoff, and nothing
/// else: a missing, non-decimal, zero or too long cutoff is refused.
#[test]
fn a_renew_request_names_its_unit_and_cutoff_and_nothing_else() {
    let id = JobKeyId::for_key("session-0");
    let verb = ControlVerb::Renew {
        cutoff_boot_ns: u64::MAX,
    };
    let line = render_request(verb, &id);
    assert_eq!(line, format!("renew {id} {}\n", u64::MAX));
    assert!(line.len() <= 64, "the longest renewal fits one request");
    assert_eq!(parse_request(line.as_bytes()), Ok((verb, id.clone())));
    assert_eq!(verb.word(), "renew");
    for (line, reason) in [
        (format!("renew {id}\n"), "renew_cutoff_missing"),
        (format!("renew {id} 12a\n"), "renew_cutoff_malformed"),
        (format!("renew {id} 0\n"), "renew_cutoff_malformed"),
        (format!("renew {id} -5\n"), "renew_cutoff_malformed"),
        (
            format!("renew {id} {}0\n", u64::MAX),
            "renew_cutoff_malformed",
        ),
        (format!("renew {id} 5 6\n"), "renew_cutoff_malformed"),
        (format!("renew x{id} 5\n"), "instance_not_a_job"),
    ] {
        assert_eq!(
            parse_request(line.as_bytes()),
            Err(reason.to_owned()),
            "{line:?}"
        );
    }
    // The verbs that were there keep their words.
    assert_eq!(
        parse_request(format!("stop {id}\n").as_bytes()),
        Ok((ControlVerb::Stop, id))
    );
}

/// Root moves a session's cutoff forward only, within its longest run, and
/// never once the current cutoff is already stopping the run; the same
/// cutoff asked again changes nothing; a job's cutoff never moves.
#[test]
fn the_root_renewal_moves_a_sessions_cutoff_only_forward_and_within_its_longest_run() {
    let instance = JobKeyId::for_key("session-0").as_str().to_owned();
    let session = prepared(&instance, Some(secs(3_600)));
    let now = secs(300);

    let plan = renewed_cutoff_plan(&session, secs(1_200), now)
        .expect("a renewal of a running session")
        .expect("a moved cutoff");
    assert_eq!(plan.stop_at_boot_ns, secs(1_200 - GRACE_SECS));
    assert_eq!(plan.stop_grace_secs, GRACE_SECS);
    assert_eq!(
        plan.unit,
        format!(
            "oneiron-job-cutoff-{instance}-{}.timer",
            secs(1_200 - GRACE_SECS)
        ),
        "each renewal arms a timer of its own"
    );

    let mut renewed = session.clone();
    renewed.cutoff = Some(plan);
    assert_eq!(
        renewed_cutoff_plan(&renewed, secs(1_200), now),
        Ok(None),
        "asked again: nothing changes"
    );
    assert_eq!(
        renewed_cutoff_plan(&renewed, secs(900), now),
        Err("cutoff_not_forward: a cutoff only moves forward".to_owned())
    );
    assert_eq!(
        renewed_cutoff_plan(&session, secs(3_601), now),
        Err("session_max_reached".to_owned())
    );
    assert_eq!(
        renewed_cutoff_plan(&session, secs(1_200), secs(600 - GRACE_SECS) - 1),
        Err("cutoff_passed: the current cutoff is already stopping the run".to_owned())
    );
    let job = prepared(&instance, None);
    assert!(
        renewed_cutoff_plan(&job, secs(1_200), now)
            .is_err_and(|why| why.starts_with("template_not_session")),
        "a job's cutoff never moves"
    );
    let mut unarmed = session;
    unarmed.cutoff = None;
    assert!(
        renewed_cutoff_plan(&unarmed, secs(1_200), now)
            .is_err_and(|why| why.starts_with("cutoff_not_armed"))
    );
}

/// Root takes a renewal only while its handoff can finish before the old
/// timer fires (EM-22, R3B's review of #10502): 30 s before the current
/// stop time is too late, 32 s is in time, also for a renewal asked again.
/// A control handler written before sessions takes no renewal, so a
/// session's launch is refused at its prepare step instead of at its first
/// renewal.
#[test]
fn a_renewal_needs_the_whole_handoff_before_the_old_timer_fires() {
    let instance = JobKeyId::for_key("session-0").as_str().to_owned();
    let session = prepared(&instance, Some(secs(3_600)));
    let stop_at = secs(600 - GRACE_SECS);
    assert_eq!(
        renewed_cutoff_plan(&session, secs(1_200), stop_at - 30 * NANOS_PER_SEC),
        Err("cutoff_passed: the current cutoff is already stopping the run".to_owned())
    );
    let plan = renewed_cutoff_plan(&session, secs(1_200), stop_at - 32 * NANOS_PER_SEC)
        .expect("32 s before the stop is in time")
        .expect("a moved cutoff");
    // Asked again once the renewed timer may be firing, the renewal is not
    // answered as taken either (Sol review r3, finding 8).
    let renewed_stop_at = plan.stop_at_boot_ns;
    let mut renewed = session.clone();
    renewed.cutoff = Some(plan);
    assert_eq!(
        renewed_cutoff_plan(&renewed, secs(1_200), renewed_stop_at - 30 * NANOS_PER_SEC),
        Err("cutoff_passed: the current cutoff is already stopping the run".to_owned())
    );
    assert_eq!(
        renewed_cutoff_plan(&renewed, secs(1_200), renewed_stop_at - 32 * NANOS_PER_SEC),
        Ok(None)
    );

    let before_sessions = "[Service]\n\
        ExecStart=/usr/bin/oneiron job-control --engine-account oneiron\n\
        StandardInput=socket\n\
        RuntimeMaxSec=30\n\
        ProtectSystem=strict\n\
        ProtectHome=read-only\n";
    let since_sessions = "[Service]\n\
        ExecStart=/usr/bin/oneiron job-control --engine-account oneiron --node-file /etc/oneiron/execution-node.toml\n\
        StandardInput=socket\n\
        RuntimeMaxSec=30\n\
        ProtectSystem=strict\n\
        ProtectHome=read-only\n\
        ReadWritePaths=/var/lib/oneiron/jobs\n";
    assert!(!control_service_renews(before_sessions));
    assert!(control_service_renews(since_sessions));
}

/// A cutoff timer whose stop time a renewal moved past stops nothing; the
/// current timer, a timer armed before sessions (no stop time) and a record
/// with no cutoff all stop the unit.
#[test]
fn a_cutoff_timer_a_renewal_superseded_stops_nothing() {
    let renewed = CutoffPlan {
        unit: "oneiron-job-cutoff-x-2.timer".to_owned(),
        stop_at_boot_ns: secs(1_190),
        stop_grace_secs: GRACE_SECS,
    };
    assert!(cutoff_superseded(Some(secs(590)), Some(&renewed)));
    assert!(!cutoff_superseded(Some(secs(1_190)), Some(&renewed)));
    assert!(!cutoff_superseded(None, Some(&renewed)));
    assert!(!cutoff_superseded(Some(secs(590)), None));
}

/// A template without `kind` is a job and keeps its digest; a session
/// template's longest run defaults to seven days, may not be shorter than
/// its chunk, and sets the unit's backstop, so the backstop never ends a
/// paid session at one chunk's maximum.
#[test]
fn a_session_templates_longest_run_sets_the_unit_backstop_and_a_job_keeps_its_digest() {
    let plain = ExecutionNodeSettings::parse(&node_text(&template("probe", 1_800, "")))
        .expect("a job template");
    let stated =
        ExecutionNodeSettings::parse(&node_text(&template("probe", 1_800, r#"kind = "job""#)))
            .expect("a job template, kind stated");
    let job = &plain.templates["probe"];
    assert_eq!(job.kind, TemplateKind::Job);
    assert_eq!(job.session_max_secs(), None);
    assert_eq!(
        job.digest(),
        stated.templates["probe"].digest(),
        "the default kind is left out of the digest"
    );
    assert_eq!(unit_runtime_max_secs(&plain), 1_800);

    let both = ExecutionNodeSettings::parse(&node_text(&format!(
        "{}{}",
        template("probe", 1_800, ""),
        template("agent", 600, r#"kind = "session""#)
    )))
    .expect("a job and a session template");
    assert_eq!(
        both.templates["agent"].session_max_secs(),
        Some(SESSION_MAX_SECS_DEFAULT)
    );
    assert_eq!(unit_runtime_max_secs(&both), SESSION_MAX_SECS_DEFAULT);
    let bounded = ExecutionNodeSettings::parse(&node_text(&template(
        "agent",
        600,
        "kind = \"session\"\nsession_max_secs = 7200",
    )))
    .expect("a session template with its longest run");
    assert_eq!(unit_runtime_max_secs(&bounded), 7_200);

    for refused in [
        template("agent", 600, "kind = \"session\"\nsession_max_secs = 300"),
        template("probe", 600, "session_max_secs = 7200"),
        template("probe", 600, r#"kind = "daemon""#),
    ] {
        assert!(
            ExecutionNodeSettings::parse(&node_text(&refused)).is_err(),
            "{refused}"
        );
    }
}

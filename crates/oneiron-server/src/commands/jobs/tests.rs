//! `oneiron jobs` against a scripted issuer: each verb answers what the test says, and every
//! call is kept. Nothing runs curl, git or a clock: the pauses are no-ops.
//!
//! Run on the fleet, never on a workstation:
//! cargo test --locked -p oneiron-server --all-features --lib commands::jobs

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::time::Duration;

use clap::Parser;
use oneiron::EntityId;
use oneiron::job_workload::{ResourceRequest, ScopeKind, WorkloadPin, WorkloadPinRequest};
use oneiron::memory::{MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use oneiron::work_order::{
    CancelWhy, EndKind, GiveUpWhy, OrderCharge, OrderState, WaitRule, WorkOrder, WorkOrderRequest,
};
use serde_json::{Value, json};

use super::Booker;
use super::end::{EXIT_KEY_HELD, EXIT_NO_ROOM, EXIT_REFUSED, OwnStop, end_code, order_code};
use super::request::{duration_secs, sha256_hex, size_mib};
use super::transport::{CallError, VerbCall, answer_of};
use crate::cli::{JobsCommand, JobsRunArgs};

const NELLY_DIGEST: &str = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
const MEL_DIGEST: &str = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const WORKLOAD: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

/// The verbs the booker calls; its Grant lists these, `vault.gpu.jobs.start` (the allowance
/// beside the Grant needs it, gpu_job/allowance.rs) and `read`.
const BOOKER_CALLED_VERBS: [&str; 6] = [
    "vault.machines.execution.get",
    "vault.jobs.workloads.pin",
    "vault.jobs.order",
    "vault.jobs.orders.wait",
    "vault.jobs.orders.cancel",
    "vault.jobs.logs.tail",
];
const BOOKER_GRANT_ONLY_VERB: &str = "vault.gpu.jobs.start";

#[derive(Parser)]
struct JobsCli {
    #[command(subcommand)]
    command: JobsCommand,
}

/// `oneiron jobs run` with the fleet-shaped flags every test shares, then `extra`.
fn run_args(extra: &[&str]) -> JobsRunArgs {
    let mut argv = vec![
        "oneiron-jobs",
        "run",
        "--url",
        "http://issuer.test",
        "--template",
        "oneiron-check",
        "--commit",
        COMMIT,
        "--entry",
        "scripts/execution-node/check/oneiron_check.sh",
        "--contract",
        "scripts/execution-node/check/oneiron_check.sh",
        "--offer",
        "nelly-cpu",
        "--mem",
        "28G",
        "--disk",
        "60G",
        "--threads",
        "6",
        "--timeout",
        "3h",
    ];
    argv.extend_from_slice(extra);
    match JobsCli::try_parse_from(argv)
        .expect("the flags parse")
        .command
    {
        JobsCommand::Run(args) => *args,
        JobsCommand::Follow(_) => panic!("run"),
    }
}

fn nelly() -> EntityId {
    EntityId::from_hex("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a").expect("an id")
}

fn mel() -> EntityId {
    EntityId::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("an id")
}

fn order_id() -> EntityId {
    EntityId::from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").expect("an id")
}

/// One machine as `vault.machines.execution.get` answers it, its node holding `template`.
fn machine(id: EntityId, name: &str, template: &str, digest: &str) -> Value {
    json!({
        "machine": id.to_hex(),
        "name": name,
        "this_install": false,
        "job_grant": true,
        "job_status_grant": true,
        "node": {
            "state": "answered",
            "asked_at_ms": 1,
            "answer": {
                "enabled": true,
                "templates": [{
                    "name": template,
                    "digest": digest,
                    "scopes": ["host"],
                    "network": ["none"],
                    "returnable": [],
                    "require": [],
                }],
                "scopes": [],
                "disk_free_bytes": 0,
                "disk_reserved_bytes": 0,
                "disk_reserve_bytes": 0,
                "swept": true,
                "boot_id": "boot",
                "engine_version": "test",
            },
        },
        "availability": { "state": "not_asked" },
        "live_keys": { "state": "not_asked" },
    })
}

fn machines() -> Value {
    json!({ "machines": [
        machine(nelly(), "nelly", "oneiron-check", NELLY_DIGEST),
        machine(mel(), "mel", "open-models", MEL_DIGEST),
    ]})
}

fn decision() -> Value {
    json!({ "slot": "place", "options": [], "pick": "", "by": { "kind": "rule", "name": "test" }, "why": "" })
}

/// Attempt `n` on nelly, ended `end` (a JSON end kind) or still running.
fn attempt(n: u16, end: Option<Value>) -> Value {
    json!({
        "n": n,
        "job": EntityId::now().to_hex(),
        "machine": nelly().to_hex(),
        "ranked": decision(),
        "placed": decision(),
        "made_at_ms": 1,
        "started_at_ms": 2,
        "end": end.map(|kind| json!({ "kind": kind, "at_ms": 3, "after": decision() })),
    })
}

/// The order in `state` (a JSON state) with `attempts`.
fn order(state: Value, attempts: Vec<Value>) -> Value {
    json!({
        "id": order_id().to_hex(),
        "ordered_by": { "kind": "owner", "owner": null },
        "workload": WORKLOAD,
        "request": { "cpu_threads": 6, "memory_mib": 28_672, "disk_mib": 61_440, "devices": [], "maximum_secs": 10_800 },
        "charge": { "kind": "offer", "name": "nelly-cpu" },
        "wait": { "kind": "open" },
        "state": state,
        "attempts": attempts,
        "ordered_at_ms": 1,
        "updated_at_ms": 1,
        "revision": 1,
    })
}

/// A wait's answer: the order, and the receipt of attempt `n` under `key`.
fn waited(order: Value, receipt: Option<(u16, &str)>) -> Value {
    let receipt = receipt.map(|(n, key)| {
        json!({ "attempt": n, "key": key, "machine": nelly().to_hex(), "signed": "", "observed_at_ms": 1 })
    });
    json!({ "view": { "order": order, "replayed": false, "receipt": receipt }, "reached": false })
}

fn tail(bytes: &str, next_offset: u64, ended: bool) -> Value {
    json!({ "bytes": bytes, "next_offset": next_offset, "ended": ended, "truncated": null })
}

fn pinned() -> Value {
    json!({
        "changed": true,
        "workload": {
            "digest": WORKLOAD,
            "pin": serde_json::to_value(expected_pin()).expect("a pin"),
            "standing": "cleared",
            "pinned_by": null,
            "pinned_under": null,
            "pinned_at_ms": 1,
            "approval": null,
            "revoked_at_ms": null,
        },
    })
}

fn ordered() -> Value {
    json!({ "order": order(json!({ "kind": "open", "blocked": [], "looked_at_ms": 1, "earliest_ms": null }), vec![]), "replayed": false })
}

fn refusal(code: &str, reasons: &[&str]) -> CallError {
    CallError::Refused {
        body: json!({ "error": { "code": code, "message": "refused", "reason_codes": reasons } })
            .to_string(),
    }
}

/// The pin `run_args(&[])` makes on nelly, with `--project` unset.
fn expected_pin() -> WorkloadPin {
    WorkloadPin {
        template: "oneiron-check".to_owned(),
        template_digest: NELLY_DIGEST.to_owned(),
        commit: COMMIT.to_owned(),
        contract_sha256: CONTRACT_SHA256.to_owned(),
        contract_path: "scripts/execution-node/check/oneiron_check.sh".to_owned(),
        entry: "scripts/execution-node/check/oneiron_check.sh".to_owned(),
        args: vec!["packages=oneiron".to_owned(), "features=all".to_owned()],
        request: ResourceRequest {
            cpu_threads: 6,
            memory_mib: 28 * 1_024,
            disk_mib: 60 * 1_024,
            devices: Vec::new(),
            maximum_secs: 3 * 3_600,
        },
        scope: ScopeKind::Host,
        network: oneiron::job_workload::NetworkMode::None,
        outputs: Vec::new(),
    }
}

/// An issuer that answers each verb (a log read by its attempt and stream) from its queue; the
/// last answer of a queue repeats.
#[derive(Default)]
struct Script {
    answers: HashMap<String, VecDeque<Result<Value, CallError>>>,
    calls: Vec<(String, Value)>,
}

impl Script {
    fn answer(mut self, key: &str, answer: Result<Value, CallError>) -> Self {
        self.answers
            .entry(key.to_owned())
            .or_default()
            .push_back(answer);
        self
    }

    /// The machines, the pin and the order answer, as every booking starts.
    fn booking() -> Self {
        Self::default()
            .answer("vault.machines.execution.get", Ok(machines()))
            .answer("vault.jobs.workloads.pin", Ok(pinned()))
            .answer("vault.jobs.order", Ok(ordered()))
    }

    fn inputs(&self, verb: &str) -> Vec<&Value> {
        self.calls
            .iter()
            .filter(|(called, _)| called == verb)
            .map(|(_, input)| input)
            .collect()
    }

    fn verbs(&self) -> BTreeSet<&str> {
        self.calls.iter().map(|(verb, _)| verb.as_str()).collect()
    }
}

impl VerbCall for Script {
    fn call(&mut self, verb: &str, input: &Value) -> Result<Value, CallError> {
        self.calls.push((verb.to_owned(), input.clone()));
        let key = match (input.get("attempt"), input.get("stream")) {
            (Some(attempt), Some(stream)) => format!(
                "{verb}/{}/{}",
                attempt.as_str().unwrap_or_default(),
                stream.as_str().unwrap_or_default()
            ),
            _ => verb.to_owned(),
        };
        let queue = self
            .answers
            .get_mut(&key)
            .unwrap_or_else(|| panic!("no answer scripted for {key}"));
        if queue.len() > 1 {
            queue.pop_front().expect("an answer")
        } else {
            queue.front().cloned().expect("an answer")
        }
    }
}

/// What one booking wrote and exited with.
struct Booked {
    code: i32,
    out: String,
    err: String,
}

fn book(script: &mut Script, args: &JobsRunArgs, stop: Option<OwnStop>) -> Booked {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut pause = |_: Duration| {};
    let taken = move || stop;
    let code = Booker {
        call: script,
        out: &mut out,
        err: &mut err,
        stop: &taken,
        pause: &mut pause,
    }
    .run(args, CONTRACT_SHA256, Path::new("."));
    Booked {
        code,
        out: String::from_utf8(out).expect("stdout"),
        err: String::from_utf8(err).expect("stderr"),
    }
}

/// U1: the pin names the template's digest as nelly's node reported it, the commit, the
/// contract's sha256, the entry and its arguments, and the fleet-shaped sizes in MiB and
/// seconds. The contract digest is sha256.
#[test]
fn the_pin_names_the_node_template_digest_and_the_contract_sha256() {
    let mut script = Script::booking();
    let args = run_args(&[
        "--host",
        "nelly",
        "--detach",
        "--",
        "packages=oneiron",
        "features=all",
    ]);
    assert_eq!(book(&mut script, &args, None).code, 0);
    let pins = script.inputs("vault.jobs.workloads.pin");
    let request: WorkloadPinRequest =
        serde_json::from_value(pins[0].clone()).expect("the pin request decodes");
    assert_eq!(request.pin, expected_pin());
    assert_eq!(request.project, None);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "the contract digest is sha256, as the node checks it"
    );

    let project = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
    let mut script = Script::booking();
    let args = run_args(&["--project", project, "--gpu", "1:20000:cuda", "--detach"]);
    assert_eq!(book(&mut script, &args, None).code, 0);
    let request: WorkloadPinRequest =
        serde_json::from_value(script.inputs("vault.jobs.workloads.pin")[0].clone())
            .expect("the pin request decodes");
    assert_eq!(request.project.as_deref(), Some(project));
    let gpu = &request.pin.request.devices[0];
    assert_eq!(
        (gpu.count, gpu.memory_mib, gpu.features.clone()),
        (1, 20_000, vec!["cuda".to_owned()])
    );
}

/// U2: a host the vault does not show, or a template its node does not hold, is refused with
/// nothing pinned or ordered.
#[test]
fn an_unknown_host_or_a_missing_template_sends_nothing() {
    for extra in [&["--host", "kel"][..], &["--host", "mel"][..]] {
        let mut script = Script::booking();
        let booked = book(&mut script, &run_args(extra), None);
        assert_eq!(booked.code, EXIT_REFUSED, "{extra:?}: {}", booked.err);
        assert_eq!(
            script.verbs(),
            BTreeSet::from(["vault.machines.execution.get"]),
            "{extra:?}"
        );
        assert!(booked.err.contains("nothing was ordered"), "{}", booked.err);
    }
}

/// U3: `--key` is the order's intent key and `--host` its `limits.machines`; it waits by
/// default and `--no-wait` asks for a refusal at once.
#[test]
fn the_key_is_the_intent_key_and_the_host_is_limits_machines() {
    let mut script = Script::booking();
    let args = run_args(&["--host", "nelly", "--key", "lane/check/1", "--detach"]);
    assert_eq!(book(&mut script, &args, None).code, 0);
    let request: WorkOrderRequest =
        serde_json::from_value(script.inputs("vault.jobs.order")[0].clone())
            .expect("the order request decodes as the door reads it");
    assert_eq!(request.intent_key.as_deref(), Some("lane/check/1"));
    assert_eq!(request.limits.machines, vec![nelly()]);
    assert_eq!(
        request.workload, WORKLOAD,
        "it orders the digest the pin answered"
    );
    assert_eq!(
        request.charge,
        OrderCharge::Offer {
            name: "nelly-cpu".to_owned()
        }
    );
    assert_eq!(request.wait, WaitRule::Open);

    let mut script = Script::booking();
    assert_eq!(
        book(&mut script, &run_args(&["--no-wait", "--detach"]), None).code,
        0
    );
    let request: WorkOrderRequest =
        serde_json::from_value(script.inputs("vault.jobs.order")[0].clone()).expect("decodes");
    assert_eq!(request.wait, WaitRule::No);
    assert!(
        request.limits.machines.is_empty(),
        "no --host: every approved machine"
    );
}

/// U4: the follow writes the attempt's stdout to stdout and its stderr to stderr, reading on
/// from each answer's offset, and exits with the job's own code.
#[test]
fn follow_writes_both_logs_in_order_and_exits_with_the_job_code() {
    let running = order(
        json!({ "kind": "running", "attempt": 1 }),
        vec![attempt(1, None)],
    );
    let ended = order(
        json!({ "kind": "given_up", "why": { "kind": "ended", "end": { "kind": "exited", "code": 3 } } }),
        vec![attempt(1, Some(json!({ "kind": "exited", "code": 3 })))],
    );
    let open = order(
        json!({ "kind": "open", "blocked": [], "looked_at_ms": 1, "earliest_ms": null }),
        vec![],
    );
    let mut script = Script::booking()
        .answer("vault.jobs.orders.wait", Ok(waited(open, None)))
        .answer(
            "vault.jobs.orders.wait",
            Ok(waited(running, Some((1, "k1")))),
        )
        .answer("vault.jobs.orders.wait", Ok(waited(ended, Some((1, "k1")))))
        .answer("vault.jobs.logs.tail/k1/stdout", Ok(tail("a", 1, false)))
        .answer("vault.jobs.logs.tail/k1/stdout", Ok(tail("b", 2, true)))
        .answer(
            "vault.jobs.logs.tail/k1/stderr",
            Ok(tail("warn\n", 5, true)),
        );
    let booked = book(&mut script, &run_args(&["--host", "nelly"]), None);
    assert_eq!(booked.code, 3, "{}", booked.err);
    assert_eq!(booked.out, "ab");
    assert!(booked.err.contains("warn\n"), "{}", booked.err);
    let end = format!(
        "[oneiron] order {} on nelly ended: exit 3 (exited 3)",
        order_id().to_hex()
    );
    assert!(booked.err.trim_end().ends_with(&end), "{}", booked.err);
    let stdout_offsets: Vec<_> = script
        .inputs("vault.jobs.logs.tail")
        .into_iter()
        .filter(|input| input["stream"] == "stdout")
        .map(|input| input["offset"].clone())
        .collect();
    assert_eq!(stdout_offsets, vec![json!(0), json!(1)]);
}

/// U5: an attempt the order retries under a new key is followed there too.
#[test]
fn a_retried_attempt_is_followed_on_its_new_key() {
    let first = order(
        json!({ "kind": "running", "attempt": 1 }),
        vec![attempt(1, None)],
    );
    let second = order(
        json!({ "kind": "running", "attempt": 2 }),
        vec![
            attempt(1, Some(json!({ "kind": "exited", "code": 1 }))),
            attempt(2, None),
        ],
    );
    let done = order(
        json!({ "kind": "done" }),
        vec![
            attempt(1, Some(json!({ "kind": "exited", "code": 1 }))),
            attempt(2, Some(json!({ "kind": "exited", "code": 0 }))),
        ],
    );
    let mut script = Script::booking()
        .answer("vault.jobs.orders.wait", Ok(waited(first, Some((1, "k1")))))
        .answer(
            "vault.jobs.orders.wait",
            Ok(waited(second, Some((2, "k2")))),
        )
        .answer("vault.jobs.orders.wait", Ok(waited(done, Some((2, "k2")))))
        .answer("vault.jobs.logs.tail/k1/stdout", Ok(tail("one ", 4, true)))
        .answer("vault.jobs.logs.tail/k1/stderr", Ok(tail("", 0, true)))
        .answer("vault.jobs.logs.tail/k2/stdout", Ok(tail("two", 3, true)))
        .answer("vault.jobs.logs.tail/k2/stderr", Ok(tail("", 0, true)));
    let booked = book(&mut script, &run_args(&["--retry-on", "exited:1"]), None);
    assert_eq!(booked.code, 0, "{}", booked.err);
    assert_eq!(booked.out, "one two");
    let request: WorkOrderRequest =
        serde_json::from_value(script.inputs("vault.jobs.order")[0].clone()).expect("decodes");
    assert_eq!(request.retry_on, vec![EndKind::Exited { code: 1 }]);
}

/// U6: each end exits with the job's own code, or the code `fleet run` gives the same end.
#[test]
fn every_end_maps_to_its_exit_code() {
    let ends = [
        (EndKind::Exited { code: 0 }, 0),
        (EndKind::Exited { code: 3 }, 3),
        (EndKind::Exited { code: 300 }, 1),
        (EndKind::TimeLimit, 124),
        (EndKind::MemoryLimit, 137),
        (EndKind::Lost, 77),
        (EndKind::NeverStarted, 79),
        (EndKind::Expired, 79),
        (EndKind::DiskLimit, 1),
        (EndKind::LaunchRefusedChanged, 1),
        (EndKind::Revoked, 1),
        (EndKind::Stopped, 1),
        (EndKind::WrittenOff, 1),
        (EndKind::Closed, 1),
    ];
    for (end, code) in ends {
        assert_eq!(end_code(&end).0, code, "{end:?}");
    }
    let at = |state: OrderState| -> WorkOrder {
        let mut row: WorkOrder =
            serde_json::from_value(order(json!({ "kind": "done" }), vec![])).expect("an order");
        row.state = state;
        row
    };
    let cancelled = || OrderState::Cancelled {
        why: CancelWhy::Asked { by: None },
    };
    assert_eq!(
        order_code(
            &at(OrderState::GivenUp {
                why: GiveUpWhy::WaitEnded { blocked: vec![] }
            }),
            None
        )
        .map(|end| end.0),
        Some(75)
    );
    assert_eq!(
        order_code(
            &at(OrderState::GivenUp {
                why: GiveUpWhy::NeverFits { blocked: vec![] }
            }),
            None
        )
        .map(|end| end.0),
        Some(1)
    );
    assert_eq!(
        order_code(
            &at(OrderState::GivenUp {
                why: GiveUpWhy::Ended {
                    end: EndKind::TimeLimit
                }
            }),
            None
        )
        .map(|end| end.0),
        Some(124)
    );
    assert_eq!(
        order_code(&at(cancelled()), None).map(|end| end.0),
        Some(78)
    );
    assert_eq!(
        order_code(&at(cancelled()), Some(OwnStop::Terminate)).map(|end| end.0),
        Some(143)
    );
    assert_eq!(
        order_code(&at(cancelled()), Some(OwnStop::Interrupt)).map(|end| end.0),
        Some(130)
    );
    assert_eq!(
        order_code(&at(OrderState::Done), None).map(|end| end.0),
        Some(0)
    );
    assert_eq!(
        order_code(&at(OrderState::Running { attempt: 1 }), None),
        None
    );
}

/// U7: `--detach` prints the order's id and asks for no wait and no log.
#[test]
fn detach_prints_the_order_and_waits_on_nothing() {
    let mut script = Script::booking();
    let booked = book(&mut script, &run_args(&["--detach"]), None);
    assert_eq!(booked.code, 0);
    assert_eq!(booked.out, format!("order {}\n", order_id().to_hex()));
    assert!(!script.verbs().contains("vault.jobs.orders.wait"));
    assert!(!script.verbs().contains("vault.jobs.logs.tail"));
}

/// U8: a TERM this process takes asks the issuer to cancel the order once, follows it to its
/// end and exits 143.
#[test]
fn a_term_cancels_the_order_once() {
    let running = order(
        json!({ "kind": "running", "attempt": 1 }),
        vec![attempt(1, None)],
    );
    let cancelled = order(
        json!({ "kind": "cancelled", "why": { "kind": "asked", "by": null } }),
        vec![attempt(1, Some(json!({ "kind": "stopped" })))],
    );
    let mut script = Script::booking()
        .answer("vault.jobs.orders.cancel", Ok(ordered()))
        .answer("vault.jobs.orders.wait", Ok(waited(running.clone(), None)))
        .answer("vault.jobs.orders.wait", Ok(waited(running, None)))
        .answer("vault.jobs.orders.wait", Ok(waited(cancelled, None)));
    let booked = book(&mut script, &run_args(&[]), Some(OwnStop::Terminate));
    assert_eq!(booked.code, 143, "{}", booked.err);
    let cancels = script.inputs("vault.jobs.orders.cancel");
    assert_eq!(
        cancels,
        vec![&json!({ "order": order_id().to_hex() })],
        "asked once"
    );
}

/// U9: a pin no grant covers waits on its check-in: nothing is ordered, and the refusal's body
/// reaches stderr as the server sent it.
#[test]
fn a_pending_check_in_orders_nothing() {
    let body = json!({ "error": { "code": "CHECK_IN_PENDING", "message": "the pin waits", "pending": { "check_in": "c1" } } }).to_string();
    let mut script = Script::default()
        .answer("vault.machines.execution.get", Ok(machines()))
        .answer("vault.jobs.workloads.pin", answer_of(body.clone()));
    let booked = book(&mut script, &run_args(&[]), None);
    assert_eq!(booked.code, EXIT_REFUSED);
    assert!(booked.err.contains(&body), "{}", booked.err);
    assert!(!script.verbs().contains("vault.jobs.order"));
}

/// U10: an order refused for a key that made another order exits 80; one refused with its
/// blockers under `--no-wait` exits 75; any other refusal exits 2.
#[test]
fn the_order_refusals_map_to_fleet_codes() {
    let cases = [
        (
            refusal(MEMORY_CODE_INVALID_STATE, &[]),
            &["--key", "k"][..],
            EXIT_KEY_HELD,
        ),
        (
            refusal(MEMORY_CODE_INVALID_STATE, &["device_busy"]),
            &["--no-wait"][..],
            EXIT_NO_ROOM,
        ),
        (
            refusal(MEMORY_CODE_BUDGET_SPENT, &["allowance_exceeded"]),
            &["--no-wait"][..],
            EXIT_NO_ROOM,
        ),
        (
            refusal(MEMORY_CODE_INVALID_STATE, &["workload_unknown"]),
            &[][..],
            EXIT_REFUSED,
        ),
        (
            refusal(MEMORY_CODE_FORBIDDEN, &[]),
            &["--key", "k"][..],
            EXIT_REFUSED,
        ),
    ];
    for (refused, extra, code) in cases {
        let mut script = Script::default()
            .answer("vault.machines.execution.get", Ok(machines()))
            .answer("vault.jobs.workloads.pin", Ok(pinned()))
            .answer("vault.jobs.order", Err(refused.clone()));
        let booked = book(&mut script, &run_args(extra), None);
        assert_eq!(booked.code, code, "{refused:?} {extra:?}");
        assert!(booked.err.contains(refused.text()), "{}", booked.err);
    }
}

/// U11: the booker's Grant lists exactly the verbs it calls, and the verb its allowance needs;
/// the runbook's Grant line names the same.
#[test]
fn the_grant_lists_exactly_the_verbs_the_code_calls() {
    let running = order(
        json!({ "kind": "running", "attempt": 1 }),
        vec![attempt(1, None)],
    );
    let cancelled = order(
        json!({ "kind": "cancelled", "why": { "kind": "asked", "by": null } }),
        vec![attempt(1, Some(json!({ "kind": "stopped" })))],
    );
    let mut script = Script::booking()
        .answer("vault.jobs.orders.cancel", Ok(ordered()))
        .answer(
            "vault.jobs.orders.wait",
            Ok(waited(running, Some((1, "k1")))),
        )
        .answer(
            "vault.jobs.orders.wait",
            Ok(waited(cancelled, Some((1, "k1")))),
        )
        .answer("vault.jobs.logs.tail/k1/stdout", Ok(tail("", 0, true)))
        .answer("vault.jobs.logs.tail/k1/stderr", Ok(tail("", 0, true)));
    book(&mut script, &run_args(&[]), Some(OwnStop::Interrupt));
    assert_eq!(script.verbs(), BTreeSet::from(BOOKER_CALLED_VERBS));
    let runbook = include_str!("../../../../../docs/ops/jobs-booker.md");
    let grant_line = runbook
        .lines()
        .find(|line| line.starts_with("GRANT VERBS:"))
        .expect("the runbook's Grant line");
    let listed: BTreeSet<&str> = grant_line["GRANT VERBS:".len()..]
        .split(',')
        .map(|verb| verb.trim().trim_matches('`'))
        .collect();
    let mut expected: BTreeSet<&str> = BTreeSet::from(BOOKER_CALLED_VERBS);
    expected.extend(["read", BOOKER_GRANT_ONLY_VERB]);
    assert_eq!(listed, expected);
}

/// U12: sizes and durations in fleet's forms.
#[test]
fn sizes_and_durations_read_as_fleet_writes_them() {
    assert_eq!(size_mib("--mem", "28G").ok(), Some(28_672));
    assert_eq!(size_mib("--mem", "512M").ok(), Some(512));
    assert_eq!(size_mib("--disk", "1T").ok(), Some(1_048_576));
    for refused in ["28", "0G", "G", "28X", ""] {
        assert!(size_mib("--mem", refused).is_err(), "{refused:?}");
    }
    assert_eq!(duration_secs("3h").ok(), Some(10_800));
    assert_eq!(duration_secs("1h30m").ok(), Some(5_400));
    assert_eq!(duration_secs("600s").ok(), Some(600));
    assert_eq!(duration_secs("600").ok(), Some(600));
    for refused in ["0", "0s", "3x", "h", "90m5"] {
        assert!(duration_secs(refused).is_err(), "{refused:?}");
    }
}

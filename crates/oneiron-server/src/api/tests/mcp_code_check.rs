//! Done-means (TSC-WIRE): shadow mode changes no program's behaviour or
//! result. The synthetic programs of the tsc-check evidence run through
//! `execute_code` on the production QuickJS provider twice, with the type
//! check off and in shadow mode on tsc-rs; the replies and the replay records
//! match, and the shadow record carries what the check found. The two servers
//! are built by one function that differs only in the check, but each keys
//! its credentials afresh, so each run has its own run id (and the seed and
//! config hash derived from it). The runs are compared on everything else:
//! the replies, host calls, steps with their clock, outputs and the prompt
//! fingerprint, with the run id and the run-identity hash masked.
use super::mcp_quickjs::{CodeMode, code_mode_server_with};
use super::*;
use oneiron::code_run::CodeRunReplayRecord;
use oneiron_code_check::{ShadowCheck, TscRsBudget, TscRsWasm};

/// Each program, with the codes the evidence measured on both checkers.
const FIXTURES: [(&str, &str, &[u32]); 7] = [
    (
        "01-correct",
        include_str!("../../../../oneiron-code-check/tests/fixtures/01-correct.js"),
        &[],
    ),
    (
        "02-wrong-verb",
        include_str!("../../../../oneiron-code-check/tests/fixtures/02-wrong-verb.js"),
        &[2551],
    ),
    (
        "03-wrong-argument",
        include_str!("../../../../oneiron-code-check/tests/fixtures/03-wrong-argument.js"),
        &[2322],
    ),
    (
        "04-missing-await",
        include_str!("../../../../oneiron-code-check/tests/fixtures/04-missing-await.js"),
        &[2339],
    ),
    (
        "05-undefined-path",
        include_str!("../../../../oneiron-code-check/tests/fixtures/05-undefined-path.js"),
        &[18048],
    ),
    (
        "06-floating-promise",
        include_str!("../../../../oneiron-code-check/tests/fixtures/06-floating-promise.js"),
        &[],
    ),
    (
        "07-any-null-path",
        include_str!("../../../../oneiron-code-check/tests/fixtures/07-any-null-path.js"),
        &[],
    ),
];

/// A program that ends any run it follows, so every run has a record to read.
const AFTER: &str = "finish('after');";

struct Run {
    first: Value,
    second: Value,
    record: CodeRunReplayRecord,
    mode: CodeMode,
}

/// Runs `program`, then calls the same run again: it resumes after the
/// program's step, or starts over with [`AFTER`] when the program failed
/// before any host call left a record.
async fn run(program: &str, check: Option<Arc<ShadowCheck>>) -> Run {
    let mode = code_mode_server_with(vec![program.to_owned(), AFTER.to_owned()], check);
    let actor = seeded_test_entity_id(0x0024_7001);
    let credential = "shadow-check-credential";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let mut replies = Vec::new();
    for request in ["first", "second"] {
        let args = mcp_merge_args(
            mcp_endpoint_envelope(actor, "write_memory"),
            json!({"run_ref": "shadow-check", "task": "run the synthetic program"}),
        );
        let (_, body) = route_json(
            mode.server.clone(),
            mcp_endpoint_call_request("/mcp", credential, request, "execute_code", args),
        )
        .await;
        replies.push(body);
    }
    let second = replies.pop().unwrap();
    let first = replies.pop().unwrap();
    let run_id = second["result"]["structuredContent"]["run_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the second call ends its run: {second}"));
    let record = mode
        .vault
        .get_code_run_replay_record(&oneiron::EntityId::from_hex(run_id).unwrap())
        .unwrap()
        .unwrap();
    Run {
        first,
        second,
        record,
        mode,
    }
}

impl Run {
    /// A text output of the run's record, by path.
    fn text(&self, path: &str) -> Option<String> {
        let output = self
            .record
            .outputs
            .iter()
            .find(|output| output.path == path)?;
        let raw = self
            .mode
            .vault
            .get_code_run_raw_output(output)
            .unwrap()
            .unwrap();
        // The executor's text envelope: a version line, the path line, the text.
        let text = String::from_utf8(raw).unwrap();
        Some(text.splitn(3, '\n').nth(2).unwrap().to_owned())
    }

    /// What the run did, with its id masked: both replies, each host call,
    /// each step, and each output other than the checks'.
    fn view(&self) -> Value {
        let record = &self.record;
        let view = json!({
            "first": self.first,
            "second": self.second,
            "bridge_calls": record.bridge_calls.iter().map(|call| json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "request": call.request,
                "outcome": call.outcome,
            })).collect::<Vec<_>>(),
            "clock": record.determinism.frozen_unix_ms,
            "steps": record.step_checkpoints.iter().map(|step| json!({
                "seq": step.seq,
                "label": step.label,
                "created_at_ms": step.created_at_ms,
            })).collect::<Vec<_>>(),
            "outputs": record.outputs.iter()
                .filter(|output| !output.path.ends_with(".code-check.json"))
                .map(|output| {
                    let text = self.text(&output.path);
                    json!({
                        "path": output.path,
                        "text": if output.path == RUN_CONFIG { text.map(mask_run_identity) } else { text },
                    })
                }).collect::<Vec<_>>(),
        });
        let run_id = record.run_id.to_hex();
        serde_json::from_str(&view.to_string().replace(&run_id, "<run>")).unwrap()
    }

    fn checks(&self) -> usize {
        self.record
            .outputs
            .iter()
            .filter(|output| output.path.ends_with(".code-check.json"))
            .count()
    }
}

/// The executor's config marker.
const RUN_CONFIG: &str = "executor/repl/run.config.json";

/// The config marker's hash binds the run id with the rest of the run's
/// config; only the hash is masked, and the marker must carry one.
fn mask_run_identity(text: String) -> String {
    let mut marker: Value = serde_json::from_str(&text).unwrap();
    assert!(marker["config_hash"].is_string(), "{text}");
    marker["config_hash"] = json!("<run identity>");
    marker.to_string()
}

#[tokio::test]
async fn shadow_mode_changes_no_programs_behaviour_or_result() {
    let shadow = Arc::new(ShadowCheck::new(Arc::new(
        TscRsWasm::load(TscRsBudget::default()).unwrap(),
    )));
    for (name, program, codes) in FIXTURES {
        let off = run(program, None).await;
        let checked = run(program, Some(shadow.clone())).await;
        assert_eq!(off.view(), checked.view(), "{name}");
        assert_eq!(off.checks(), 0, "{name}: off checks nothing");
        // Every step in the shadow record carries its check.
        assert_eq!(
            checked.checks(),
            checked.record.step_checkpoints.len(),
            "{name}"
        );
        let report: Value = serde_json::from_str(
            &checked
                .text("executor/repl/000000.code-check.json")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["mode"], "shadow", "{name}");
        assert_eq!(report["backend"], "tsc-rs", "{name}");
        let found: Vec<u64> = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|diagnostic| diagnostic["code"].as_u64().unwrap())
            .collect();
        // Step 0 is the program's own unless it failed before any host call.
        let program_step =
            checked.text("executor/repl/000000.generated.js").as_deref() == Some(program);
        let expected: Vec<u64> = if program_step {
            codes.iter().copied().map(u64::from).collect()
        } else {
            Vec::new()
        };
        assert_eq!(found, expected, "{name}: {report}");
    }
    // A program that failed before its step was recorded still counts.
    let totals = shadow.metrics().snapshot();
    assert_eq!(totals.with_diagnostics, 4, "{totals:?}");
    assert_eq!(
        totals.codes,
        std::collections::BTreeMap::from([(2322, 1), (2339, 1), (2551, 1), (18048, 1)]),
        "{totals:?}"
    );
}

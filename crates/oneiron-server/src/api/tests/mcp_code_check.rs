//! Done-means (TSC-WIRE): feedback mode changes no program's behaviour or
//! result. The synthetic programs of the tsc-check evidence run through
//! `execute_code` on the production QuickJS provider twice, with the type
//! check off and in feedback mode on tsc-rs (FIX 8277, owner ruling
//! CODE-MODE-TS rule 4); the replies and the replay records match, and each
//! step's feedback carries what the check found. Each server's vault keys its
//! credentials afresh, so each run has its own run id, and the seed and
//! config hash derived from it. The two providers give a fixed run the same
//! config, and the runs are compared on everything else: the replies, host
//! calls, steps with their clock, outputs and the prompt fingerprint, with
//! the run id and the config hash masked.
use super::mcp_quickjs::{CodeMode, code_mode_server_with};
use super::*;
use oneiron::code_run::CodeRunReplayRecord;
use oneiron::code_run::{
    DiagnosticCollection, KeptProgramSteps, ProgramStepFeedback, TypeDiagnostics,
};
use oneiron_code_check::{FeedbackCheck, TscRsBudget, TscRsWasm};

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
async fn run(program: &str, check: Option<Arc<FeedbackCheck>>) -> Run {
    let mode = code_mode_server_with(vec![program.to_owned(), AFTER.to_owned()], check);
    let actor = seeded_test_entity_id(0x0024_7001);
    let credential = "feedback-check-credential";
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
            json!({"run_ref": "feedback-check", "task": "run the synthetic program"}),
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
        // The executor writes a text output as it is, with no envelope.
        Some(String::from_utf8(raw).unwrap())
    }

    /// What the run did, with its id masked: both replies without their
    /// type feedback, each host call, each step, and each output other than
    /// the checks'.
    fn view(&self) -> Value {
        let record = &self.record;
        let view = json!({
            "first": without_feedback(&self.first),
            "second": without_feedback(&self.second),
            "bridge_calls": record.bridge_calls.iter().map(|call| json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "request": call.request,
                "outcome": call.outcome,
            })).collect::<Vec<_>>(),
            // determinism is an Option on today's record (witnessed here).
            "clock": record.determinism.as_ref().map(|determinism| determinism.frozen_unix_ms),
            "steps": record.step_checkpoints.iter().map(|step| json!({
                "seq": step.seq,
                "label": step.label,
                "created_at_ms": step.created_at_ms,
            })).collect::<Vec<_>>(),
            "outputs": record.outputs.iter()
                .filter(|output| !output.path.ends_with(".type-diagnostics.json"))
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

    /// The check's own outputs: a step's diagnostics past one reply, kept
    /// whole in a body of the run.
    fn checks(&self) -> usize {
        self.record
            .outputs
            .iter()
            .filter(|output| output.path.ends_with(".type-diagnostics.json"))
            .count()
    }
}

/// `reply` as its program's run gave it, without the type feedback the reply
/// carries beside it: a success's `program_steps` (and the text copy that
/// restates its structured content), a refusal's `program_steps` or
/// `program_steps_unavailable`. The feedback is all the check changes in a
/// reply: off, each step's check is unavailable at once; in feedback mode it
/// is pending or complete. What it holds is read from the run's kept steps.
fn without_feedback(reply: &Value) -> Value {
    let mut reply = reply.clone();
    let copies = reply
        .pointer_mut("/result/structuredContent")
        .and_then(|structured| {
            let before = crate::mcp::mcp_canonical_json(structured);
            structured.as_object_mut()?.shift_remove("program_steps")?;
            Some((before, crate::mcp::mcp_canonical_json(structured)))
        });
    if let Some((before, after)) = copies
        && let Some(content) = reply
            .pointer_mut("/result/content")
            .and_then(Value::as_array_mut)
    {
        for item in content {
            if item.get("text").and_then(Value::as_str) == Some(before.as_str()) {
                item["text"] = Value::String(after.clone());
            }
        }
    }
    if let Some(data) = reply
        .pointer_mut("/error/data")
        .and_then(Value::as_object_mut)
    {
        data.shift_remove("program_steps");
        data.shift_remove("program_steps_unavailable");
    }
    reply
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

/// Every step's feedback of `run`, once no check is still pending: a check
/// runs beside its step and never delays it, so each read sees the feedback
/// as it stands. Panics when the feedback does not settle within ten seconds,
/// or was not kept.
async fn settled_feedback(
    vault: &oneiron::Vault,
    run: oneiron::EntityId,
    expected_steps: usize,
    name: &str,
) -> Vec<ProgramStepFeedback> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match vault.kept_program_steps(run) {
            KeptProgramSteps::Kept(steps)
                if steps.len() == expected_steps
                    && steps
                        .iter()
                        .all(|feedback| !feedback.type_diagnostics.is_pending()) =>
            {
                return steps;
            }
            KeptProgramSteps::Kept(steps) => {
                if std::time::Instant::now() >= deadline {
                    panic!("{name}: type feedback did not settle within 10s: {steps:?}");
                }
            }
            KeptProgramSteps::NotKept { detail } => {
                panic!("{name}: type feedback was not kept: {detail}");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The diagnostic codes `feedback` carries: the check finished on tsc-rs with
/// every diagnostic inline. A stored collection, a failure or an unavailable
/// check panics: these single-diagnostic fixtures stay inline.
fn diagnostic_codes(feedback: &ProgramStepFeedback, name: &str) -> Vec<u32> {
    match &feedback.type_diagnostics {
        TypeDiagnostics::Complete {
            check,
            diagnostics: DiagnosticCollection::Inline { diagnostics },
            ..
        } => {
            assert_eq!(check.backend, "tsc-rs", "{name}: {}", feedback.check_ref);
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect()
        }
        TypeDiagnostics::Complete {
            diagnostics: DiagnosticCollection::Stored { .. },
            ..
        } => {
            panic!(
                "{name}: one diagnostic stays inline, never in a stored body: {}",
                feedback.check_ref
            )
        }
        other => {
            panic!(
                "{name}: the check finished on tsc-rs: {}: {other:?}",
                feedback.check_ref
            )
        }
    }
}

#[tokio::test]
async fn feedback_mode_changes_no_programs_behaviour_or_result() {
    // Feedback mode (FIX 8277, owner ruling CODE-MODE-TS rule 4): each program
    // is checked beside its run on tsc-rs, and nothing waits on the check.
    let feedback = Arc::new(FeedbackCheck::new(Arc::new(
        TscRsWasm::load(TscRsBudget::default()).unwrap(),
    )));
    let mut failed_steps = 0;
    for (name, program, codes) in FIXTURES {
        let off = run(program, None).await;
        let checked = run(program, Some(feedback.clone())).await;
        // The check changes no setting the masked config hash binds.
        assert_eq!(off.mode.config, checked.mode.config, "{name}");
        assert_eq!(off.view(), checked.view(), "{name}");
        assert_eq!(off.checks(), 0, "{name}: off checks nothing");
        // One diagnostic stays inline past no reply; no step keeps a stored body.
        assert_eq!(checked.checks(), 0, "{name}: no stored diagnostics body");
        // Every fixture ends its program with `finish`, so a step before the
        // run's last is a program that failed after a host call, and the last
        // step completed the run. Every step keeps its feedback, a failed one
        // included. The step ran the fixture (as the executor heals it,
        // without its trailing newline), or the clean program that ends the run.
        let steps = &checked.record.step_checkpoints;
        let last = steps.last().map(|step| step.seq);
        let settled = settled_feedback(
            &checked.mode.vault,
            checked.record.run_id,
            steps.len(),
            name,
        )
        .await;
        assert_eq!(
            settled.len(),
            steps.len(),
            "{name}: every step keeps its feedback"
        );
        let ran_fixture = |seq: u64| {
            checked
                .text(&format!("executor/repl/{seq:06}.generated.js"))
                .is_some_and(|generated| generated.trim_end() == program.trim_end())
        };
        // A fixture that fails before its first host call commits no step, and
        // the program that ends the run takes its step: both checks keep their
        // feedback under that one step identity, each on its own thread, and
        // the one that lands last holds the row (repl.rs keeps a step's
        // feedback before it knows whether the step commits).
        let fixture_committed = steps.iter().any(|step| ran_fixture(step.seq));
        for step in steps {
            if Some(step.seq) != last {
                failed_steps += 1;
            }
            let program_step = ran_fixture(step.seq);
            let step_feedback = settled
                .iter()
                .find(|feedback| {
                    feedback.step.program_seq == step.seq && feedback.step.invocation == 0
                })
                .unwrap_or_else(|| panic!("{name}: step {} keeps its feedback", step.seq));
            let found = diagnostic_codes(step_feedback, name);
            if program_step || fixture_committed {
                let expected: Vec<u32> = if program_step {
                    codes.to_vec()
                } else {
                    Vec::new()
                };
                assert_eq!(
                    found, expected,
                    "{name}: step {}: {step_feedback:?}",
                    step.seq
                );
            } else {
                assert!(
                    found.is_empty() || found == codes,
                    "{name}: step {} holds the clean program's or the uncommitted fixture's \
                     feedback: {step_feedback:?}",
                    step.seq
                );
            }
        }
    }
    // 05-undefined-path fails after its speech, so a failed step was seen.
    assert!(failed_steps > 0);
    // A program whose step failed still counts: the checks land on their own
    // threads, so the totals are read once they settle.
    let expected_codes: std::collections::BTreeMap<u32, u64> =
        std::collections::BTreeMap::from([(2322, 1), (2339, 1), (2551, 1), (18048, 1)]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let totals = loop {
        let totals = feedback.metrics().snapshot();
        if totals.with_diagnostics == 4 && totals.codes == expected_codes {
            break totals;
        }
        if std::time::Instant::now() >= deadline {
            panic!("feedback checks did not settle within 10s: {totals:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert_eq!(totals.with_diagnostics, 4, "{totals:?}");
    assert_eq!(totals.codes, expected_codes, "{totals:?}");
}

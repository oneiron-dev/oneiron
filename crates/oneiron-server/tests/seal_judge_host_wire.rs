//! The host seal check's wire ([SEAL-JUDGE-HOST-WIRE-UNTESTED]): the
//! `SealJudge` decision provider and `check()` in
//! `ai_host/coach_host/seal_checks.rs`, over a stub of the Coach's models
//! (`crate::test_doors::seal_judge`). The engine half of the ladder call is
//! covered in `oneiron/tests/seal_check_decide.rs`; these tests pin the
//! host half: which seat judges, what the judge is shown, and how the
//! check reads the rungs that answered.
//!
//! * `checked_findings_name_the_served_rung_and_its_contract`: a served
//!   independent judge checks both objectives on the Checker seat, the one
//!   the executor did not use. Each finding names the result the judge
//!   read; the outcome names the served revision; the protocol names the
//!   role, the checker's digest, and the answering rung as the call
//!   returned it. The judge's one call carries the result and the
//!   objectives as data.
//! * `no_independent_seat_is_unavailable`: the executor at the Checker's
//!   own seat model leaves no independent seat, so the check is
//!   Unavailable and no judge is asked.
//! * `an_unserved_call_is_unavailable`: the judge is asked and no seat
//!   serves the call, so the check is Unavailable.
//! * `an_unreadable_result_is_unavailable`: a result ref that names
//!   neither an output nor an agent run's answer is Unavailable, and no
//!   judge is asked.
//! * `answers_from_two_rungs_are_inconclusive`: seventeen objectives go
//!   as two calls under one clock; answered from two rungs, the check is
//!   Inconclusive: one rung answers a check.
//! * `a_served_model_equal_to_the_executor_is_inconclusive`: a fallback
//!   rung serving the executor's own model is Inconclusive, even at
//!   another revision.
//! * `a_repeated_objective_is_inconclusive_without_a_call`: one question
//!   cannot stand for two findings, so the check is Inconclusive and no
//!   judge is asked.
//! * `the_check_budget_is_thirty_minutes`: one check's clock on the
//!   decision ladder is 30 minutes.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test seal_judge_host_wire`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use fake_llm::FakeLlm;
use oneiron::compaction::output::store_output;
use oneiron::dreamer_runner::maintenance::seal_checks::SealCheck;
use oneiron::llm::manifest::ModelRole;
use oneiron::self_heal::audit::{ObjectiveConfession, SealCheckKind, SealCheckRequest};
use oneiron::{AttemptId, ModelLocality, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::seal_judge::{
    SealScriptAnswer, check_budget, check_with_scripted_answers, scripted_answer,
    seal_protocol_digest,
};

/// The result the judge reads, stored as an output.
const RESULT: &str = "the attempt's answer under check";
/// The model that produced the result: no seat's model, so the Checker
/// seat is independent of it.
const EXECUTOR: &str = "other/executor-model@r9";
/// An executor on the Checker's seat model (`models::seat_for` spells a
/// seat `seat/<role>@<digest>`): no seat is independent of it. Any
/// revision pins the same seat: independence ignores the revision.
const CHECKER_SEAT_MODEL: &str = "seat/checker@fixture-revision";

/// The models config: only the Checker role holds a seat, on the fake
/// model. The Coach and the chat seat stay unseated, so the executor at
/// the Checker's seat model leaves no independent seat at all.
fn models_text(base_url: &str) -> String {
    format!(
        "extraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         [roles.checker]\nmodel = \"local:test-model\"\n"
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    host: AiHost,
    _model: FakeLlm,
}

impl Fixture {
    async fn new() -> Self {
        let model = FakeLlm::start(vec![], None).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("seal-judge-host-wire".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Self {
            _dir: dir,
            vault,
            server: Arc::new(server),
            host,
            _model: model,
        }
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }
}

/// A random audit of `objectives`: `result_ref` names the result, or the
/// checked result is stored and its handle names it.
fn check_request(vault: &Vault, objectives: &[&str], result_ref: Option<&str>) -> SealCheckRequest {
    let result_ref = match result_ref {
        Some(result_ref) => result_ref.to_owned(),
        None => store_output(vault, RESULT.as_bytes())
            .expect("store the checked result")
            .handle(),
    };
    SealCheckRequest {
        reference: "seal-judge-host-wire".to_owned(),
        attempt: AttemptId::now(),
        kind: SealCheckKind::RandomAudit,
        result_ref,
        objectives: objectives
            .iter()
            .map(|objective| ObjectiveConfession {
                objective: (*objective).to_owned(),
                met: Some(true),
                flaw: None,
                uncertainty: None,
            })
            .collect(),
        rate: 1.0,
        created_at: 1,
    }
}

/// The judge's answer over `objectives`: `flaws` says per objective
/// whether a flaw is present, keyed by the check's own question ids.
fn answer(objectives: &[&str], flaws: &[bool]) -> String {
    scripted_answer(SealCheckKind::RandomAudit, objectives, flaws).expect("script the answer")
}

fn served(text: String, model: &str) -> Option<SealScriptAnswer> {
    Some(SealScriptAnswer {
        text,
        model: model.to_owned(),
    })
}

#[test]
fn checked_findings_name_the_served_rung_and_its_contract() {
    run_on_engine_stack("seal-judge-checked", || async {
        let fixture = Fixture::new().await;
        let objectives = ["every endpoint has a test", "the change is documented"];
        let request = check_request(&fixture.vault, &objectives, None);
        let text = answer(&objectives, &[true, false]);
        let judge = "judge/independent-model@r3";
        let now = 1_700_000_001;
        let (check, seen) = check_with_scripted_answers(
            &fixture.server,
            &request,
            EXECUTOR,
            vec![served(text, judge)],
            now,
        )
        .expect("the host checks");
        let SealCheck::Checked { outcome, protocol } = check else {
            panic!("a served independent judge checks: {check:?}");
        };
        assert_eq!(outcome.judge_revision, judge, "the served revision");
        assert_eq!(outcome.checked_at, now);
        assert_eq!(outcome.findings.len(), 2, "one finding per objective");
        assert_eq!(outcome.findings[0].objective, objectives[0]);
        assert!(outcome.findings[0].flaw_present, "yes is a flaw present");
        assert_eq!(outcome.findings[1].objective, objectives[1]);
        assert!(!outcome.findings[1].flaw_present, "no is none present");
        assert!(
            outcome
                .findings
                .iter()
                .all(|finding| finding.evidence_ref == request.result_ref),
            "each finding names the result the judge read"
        );
        assert_eq!(protocol.role, ModelRole::Checker, "the independent seat");
        assert_eq!(protocol.digest, seal_protocol_digest());
        let (locality, _route) = protocol
            .judge_rung
            .as_ref()
            .expect("the answering rung is named");
        assert_eq!(*locality, ModelLocality::OwnServer, "where it ran");
        assert_eq!(seen.len(), 1, "the judge's one call");
        assert_eq!(seen[0].role, ModelRole::Checker);
        assert!(
            seen[0].user_text.contains(RESULT),
            "the judge reads the result"
        );
        assert!(
            seen[0].user_text.contains(objectives[0]) && seen[0].user_text.contains(objectives[1]),
            "the judge reads the objectives"
        );
        fixture.finish().await;
    });
}

#[test]
fn no_independent_seat_is_unavailable() {
    run_on_engine_stack("seal-judge-no-seat", || async {
        let fixture = Fixture::new().await;
        let objectives = ["every endpoint has a test"];
        let request = check_request(&fixture.vault, &objectives, None);
        let (check, seen) =
            check_with_scripted_answers(&fixture.server, &request, CHECKER_SEAT_MODEL, vec![], 2)
                .expect("the host checks");
        assert_eq!(check, SealCheck::Unavailable, "no seat is independent");
        assert!(seen.is_empty(), "no judge is asked: {seen:?}");
        fixture.finish().await;
    });
}

#[test]
fn an_unserved_call_is_unavailable() {
    run_on_engine_stack("seal-judge-unserved", || async {
        let fixture = Fixture::new().await;
        let objectives = ["every endpoint has a test"];
        let request = check_request(&fixture.vault, &objectives, None);
        let (check, seen) =
            check_with_scripted_answers(&fixture.server, &request, EXECUTOR, vec![None], 3)
                .expect("the host checks");
        assert_eq!(check, SealCheck::Unavailable, "nothing was asked");
        assert_eq!(seen.len(), 1, "the judge was asked once");
        fixture.finish().await;
    });
}

#[test]
fn an_unreadable_result_is_unavailable() {
    run_on_engine_stack("seal-judge-no-result", || async {
        let fixture = Fixture::new().await;
        let objectives = ["every endpoint has a test"];
        let request = check_request(&fixture.vault, &objectives, Some("not-a-result-ref"));
        let (check, seen) =
            check_with_scripted_answers(&fixture.server, &request, EXECUTOR, vec![], 4)
                .expect("the host checks");
        assert_eq!(check, SealCheck::Unavailable, "no readable result");
        assert!(seen.is_empty(), "no judge is asked: {seen:?}");
        fixture.finish().await;
    });
}

#[test]
fn answers_from_two_rungs_are_inconclusive() {
    run_on_engine_stack("seal-judge-two-rungs", || async {
        let fixture = Fixture::new().await;
        // Past the sixteen-questions-per-call row the pack goes as two
        // calls in turn under one clock.
        let objectives: Vec<String> = (0..17).map(|index| format!("objective {index}")).collect();
        let refs: Vec<&str> = objectives.iter().map(String::as_str).collect();
        let request = check_request(&fixture.vault, &refs, None);
        let text = answer(&refs, &[false; 17]);
        let (check, seen) = check_with_scripted_answers(
            &fixture.server,
            &request,
            EXECUTOR,
            vec![
                served(text.clone(), "judge/first-rung@r1"),
                served(text, "judge/second-rung@r1"),
            ],
            5,
        )
        .expect("the host checks");
        assert_eq!(seen.len(), 2, "two calls under one clock");
        assert_eq!(check, SealCheck::Inconclusive, "one rung answers a check");
        fixture.finish().await;
    });
}

#[test]
fn a_served_model_equal_to_the_executor_is_inconclusive() {
    run_on_engine_stack("seal-judge-executor-rung", || async {
        let fixture = Fixture::new().await;
        let objectives = ["every endpoint has a test", "the change is documented"];
        let request = check_request(&fixture.vault, &objectives, None);
        let text = answer(&objectives, &[false, false]);
        // The executor's own model at another revision: a fallback rung
        // may serve it, and the check refuses it all the same.
        let (check, seen) = check_with_scripted_answers(
            &fixture.server,
            &request,
            EXECUTOR,
            vec![served(text, "other/executor-model@r10")],
            6,
        )
        .expect("the host checks");
        assert_eq!(seen.len(), 1, "the judge was asked");
        assert_eq!(
            check,
            SealCheck::Inconclusive,
            "the executor cannot judge itself"
        );
        fixture.finish().await;
    });
}

#[test]
fn a_repeated_objective_is_inconclusive_without_a_call() {
    run_on_engine_stack("seal-judge-repeated", || async {
        let fixture = Fixture::new().await;
        let request = check_request(
            &fixture.vault,
            &["the same objective", "the same objective"],
            None,
        );
        let (check, seen) =
            check_with_scripted_answers(&fixture.server, &request, EXECUTOR, vec![], 7)
                .expect("the host checks");
        assert_eq!(
            check,
            SealCheck::Inconclusive,
            "one question cannot stand for two findings"
        );
        assert!(seen.is_empty(), "no judge is asked: {seen:?}");
        fixture.finish().await;
    });
}

#[test]
fn the_check_budget_is_thirty_minutes() {
    assert_eq!(check_budget(), Duration::from_secs(30 * 60));
}

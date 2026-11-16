#![cfg(oneiron_test_support)]
//! The owner stamps a wire health check's outcome label (ARCH-0044 C5: "The
//! owner's later outcome is kept as a label under `wire.health.outcome`";
//! Engine ruling WIRE-HEALTH-OUTCOME-STAMPER = A, 15 Nov 2026). The label is
//! the owner's own act, UserStated and Approved, written under the proof the
//! door that admitted him holds: the decision answer door, in the write that
//! keeps his answer, and `POST /v1/owner/wire-health/outcome`. Both doors
//! land the same stamp, the sweep that settles the check lands no second
//! label, and a label written without the owner's proof keeps the
//! criticality floor (FIX [WIRE-HEALTH-OWNER-ANSWER-FLOOR]).
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test wire_health_outcome_stamper`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::llm::decision::DecisionAnswer;
use oneiron::llm::decision::questions::HEALTH_OUTCOME_PREDICATE;
use oneiron::own_rate::OwnRateKind;
use oneiron::test_doors::advisory_rate_window::count_own_acts;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::build_server::build_served_server;
use oneiron_server::test_doors::wire_health_sweep::sweep_once;
use oneiron_server::wire_health::{self, CheckState, HealthCheck};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The advisory threshold these tests count against.
const THRESHOLD: u64 = 2;
/// A window wider than the clock's range, so every act of one test lands in
/// the same window whatever second it runs at.
const WINDOW_SECONDS: u64 = 1 << 40;
/// The owner's outcome door.
const OUTCOME: &str = "/v1/owner/wire-health/outcome";

/// A rooted vault with its embedded owner, served with the default `[serve]`
/// settings (the host ladder is the rule table and the owner's ask queue),
/// and the served app the owner reaches over HTTP with the host root slip.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: axum::Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner_proof: oneiron::consent::AuthenticatedOwner,
}

async fn served() -> TestResult<Served> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (_, owner_proof) = embedded_owner(&vault)?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let server = Arc::new(
        build_served_server(
            Arc::clone(&vault),
            dir.path(),
            Some("wire-health-outcome-stamper".into()),
        )
        .await?,
    );
    let app = build_app(Arc::clone(&server));
    Ok(Served {
        _dir: dir,
        vault,
        server,
        app,
        issuer,
        root,
        owner_proof,
    })
}

impl Served {
    /// The owner's `POST /v1/owner/wire-health/outcome` over HTTP, under the
    /// host root slip and its holder proof: the status and the answer, the
    /// answer as text when it is not JSON.
    async fn post_outcome(&self, unit: EntityId, outcome: &str) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&self.issuer.binding_proof(&self.root, &challenge)?),
        });
        let request = Request::post(OUTCOME)
            .header("authorization", format!("Bearer {}", self.root.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"unit": unit.to_hex(), "outcome": outcome}).to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, answer))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn own_rate_subject(kind: OwnRateKind, actor: EntityId) -> String {
    format!("own_rate:{}:{}", kind.token(), actor.to_hex())
}

/// The health check kept for `subject`.
fn check_for(vault: &Vault, subject: &str) -> TestResult<HealthCheck> {
    wire_health::checks(vault)?
        .into_iter()
        .find(|check| check.subject == subject)
        .ok_or_else(|| format!("the sweep keeps a check for {subject}").into())
}

/// A crossing by a new own actor of `kind`, folded and asked by one pass:
/// its subject, the question its ask waits on (hex) and its crossing unit.
fn asked_crossing(served: &Served, kind: OwnRateKind) -> TestResult<(String, String, EntityId)> {
    let actor = served.vault.new_entity_id()?;
    count_own_acts(
        &served.vault,
        kind,
        actor,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    sweep_once(&served.server)?;
    let subject = own_rate_subject(kind, actor);
    match check_for(&served.vault, &subject)?.state {
        CheckState::Asked { question, unit } => {
            let unit = EntityId::from_hex(&unit).map_err(|_| "an asked check names its unit")?;
            Ok((subject, question, unit))
        }
        other => Err(format!("the crossing waits in the owner's queue, not {other:?}").into()),
    }
}

/// The owner's answer `outcome` to the one ask raised on `question` (hex), at
/// the decision answer door.
fn answer_as_owner(served: &Served, question: &str, outcome: &str) -> TestResult {
    let asks: Vec<_> = served
        .vault
        .decision_asks(None, 10_000, false)?
        .into_iter()
        .filter(|ask| ask.question.id.to_hex() == question)
        .collect();
    let [ask] = asks.as_slice() else {
        return Err(format!("one ask on the check's question, not {}", asks.len()).into());
    };
    served.vault.answer_decision_ask(
        &served.owner_proof,
        ask.seq,
        DecisionAnswer::Choice(outcome.to_owned()),
    )?;
    Ok(())
}

/// One outcome label as it is stored: its id, value, approval and source.
#[derive(Debug, PartialEq)]
struct Label {
    id: EntityId,
    value: String,
    approval: ClaimApprovalStatus,
    source: Option<ClaimSource>,
}

/// Every `wire.health.outcome` label kept on the crossing `unit`.
fn outcome_labels(vault: &Vault, unit: EntityId) -> TestResult<Vec<Label>> {
    let mut labels = Vec::new();
    for id in vault.claims_for_subject(&unit)? {
        let Some(claim) = vault.get_claim(&id)? else {
            continue;
        };
        if claim.predicate != HEALTH_OUTCOME_PREDICATE {
            continue;
        }
        labels.push(Label {
            id,
            value: claim
                .value
                .as_str()
                .ok_or("an outcome label holds its answer option")?
                .to_owned(),
            approval: claim.approval,
            source: claim.source,
        });
    }
    Ok(labels)
}

/// The owner's answer at the decision answer door lands one outcome label,
/// his own act: UserStated and Approved under his proof, the option he
/// chose. The sweep then settles the check and writes no second label, on
/// that pass or a later one. Red on main: the sweep's label write carries
/// no owner proof and keeps the criticality floor, so no label lands.
#[test]
fn the_owner_answer_lands_one_owner_stamped_outcome_label() -> TestResult {
    on_engine_stack(owner_answer_lands_one_owner_stamped_outcome_label)
}

async fn owner_answer_lands_one_owner_stamped_outcome_label() -> TestResult {
    let served = served().await?;
    let (subject, question, unit) = asked_crossing(&served, OwnRateKind::ConsultFanout)?;

    answer_as_owner(&served, &question, wire_health::VALID_BURST)?;
    sweep_once(&served.server)?;
    sweep_once(&served.server)?;

    let labels = outcome_labels(&served.vault, unit)?;
    let [label] = labels.as_slice() else {
        panic!("one outcome label on the crossing's unit, not {labels:?}");
    };
    assert_eq!(label.value, wire_health::VALID_BURST);
    assert_eq!(label.approval, ClaimApprovalStatus::Approved);
    assert_eq!(label.source, Some(ClaimSource::UserStated));
    assert!(
        matches!(
            check_for(&served.vault, &subject)?.state,
            CheckState::Answered { .. }
        ),
        "the owner's answer settles the check"
    );
    Ok(())
}

/// The owner's outcome door lands the label with the same stamp as his
/// answer at the decision door: one label on the unit he named, UserStated
/// and Approved, and the fact the door answers is that label. Red on main:
/// the door writes the label with no owner proof, the criticality floor
/// refuses it, and the door answers 400.
#[test]
fn post_outcome_agrees_with_poll() -> TestResult {
    on_engine_stack(post_outcome_agrees_with_poll_case)
}

async fn post_outcome_agrees_with_poll_case() -> TestResult {
    let served = served().await?;
    let (_, answered_question, answered_unit) =
        asked_crossing(&served, OwnRateKind::ConsultFanout)?;
    let (_, _, posted_unit) = asked_crossing(&served, OwnRateKind::TaskCreate)?;
    answer_as_owner(&served, &answered_question, wire_health::BOT)?;
    sweep_once(&served.server)?;

    let (status, answer) = served.post_outcome(posted_unit, wire_health::BOT).await?;
    assert_eq!(status, 200, "the owner's outcome door answers {answer}");
    let fact = answer
        .get("fact")
        .and_then(Value::as_str)
        .and_then(|fact| EntityId::from_hex(fact).ok())
        .ok_or("the door answers the label it landed")?;

    let posted = outcome_labels(&served.vault, posted_unit)?;
    let [posted] = posted.as_slice() else {
        panic!("one outcome label on the posted unit, not {posted:?}");
    };
    assert_eq!(posted.id, fact);
    let polled = outcome_labels(&served.vault, answered_unit)?;
    let [polled] = polled.as_slice() else {
        panic!("one outcome label on the answered unit, not {polled:?}");
    };
    assert_eq!(
        (&posted.value, &posted.approval, &posted.source),
        (&polled.value, &polled.approval, &polled.source),
        "both owner doors stamp the label alike"
    );
    assert_eq!(posted.approval, ClaimApprovalStatus::Approved);
    assert_eq!(posted.source, Some(ClaimSource::UserStated));
    Ok(())
}

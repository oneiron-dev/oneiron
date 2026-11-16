//! A session-branch claim edit through the served doors (FIX
//! [SKILL-HUB-PROMOTION-VERBS], ND-001's claim half). The owner reserves the
//! held-out split (`vault.claims.refinements.holdouts.reserve`) and stages the
//! edit (`vault.claims.refinements.offer`); the owner's approve route
//! (`POST /v1/owner/claims/refinements/{candidate}/approve`) rules on it with
//! the host's typed decisions: the useful-upstream yes/no on the System One
//! seat, then, on a yes, one held-out replay score per arm on the Big rung.
//!
//! Each case ports one quarantined engine test of
//! `crates/oneiron/src/skill_hub/claim_refinement_tests.rs` (named on the
//! case). The System One seat is a loopback stub of its native
//! `/v1/systemone` protocol and the Big rung's model a scripted `FakeLlm`, so a
//! case sets both answers before each approve call. Deletion goes through the
//! `vault.delete` facade verb; a peer's replayed tombstone and the replicated
//! put an erased id is fenced against go through `oneiron::test_doors`.
//!
//! Reads JSON only for the new verbs, so on a main without them every case
//! fails at its first reserve or offer status.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --no-fail-fast --test claim_refinement_doors`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::deletion::TombstoneReason;
use oneiron::test_doors::claim_refinement_erase::{apply_replayed_tombstone, put_replicated_claim};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The session branch every edit is staged on.
const SESSION_TAG: &str = "session:claim-refine";
/// The owner's useful-upstream question; the System One stub answers it.
const USEFUL_QUESTION: &str = "Useful upstream?";
/// The start of the host's held-out replay wording (decision_host/claim_merge.rs).
const REPLAY_QUESTION: &str = "How well does this claim fit the owner's held-out labels?";

/// What the Big rung's replay scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replay {
    /// 0.9 for the arm whose value is "improved", 0.2 for any other.
    Improved,
    /// 0.5 for every arm.
    Tie,
}

/// The answers both stubs give, set by a case before each approve call,
/// and the calls they took.
struct Script {
    useful: AtomicBool,
    replay: Mutex<Replay>,
    useful_calls: AtomicUsize,
    replay_calls: AtomicUsize,
    /// System One questions that were not a yes/no.
    unexpected: AtomicUsize,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            useful: AtomicBool::new(false),
            replay: Mutex::new(Replay::Improved),
            useful_calls: AtomicUsize::new(0),
            replay_calls: AtomicUsize::new(0),
            unexpected: AtomicUsize::new(0),
        })
    }

    fn set(&self, useful: bool, replay: Replay) {
        self.useful.store(useful, Ordering::SeqCst);
        *self.replay.lock().expect("script lock") = replay;
    }
}

/// The System One seat's native protocol: one `decision` answer per call,
/// echoing the request's `<model>-<version>`.
async fn system_one(State(script): State<Arc<Script>>, body: Bytes) -> axum::Json<Value> {
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if request["questions"]["decision"]["type"] != "noul" {
        script.unexpected.fetch_add(1, Ordering::SeqCst);
    }
    script.useful_calls.fetch_add(1, Ordering::SeqCst);
    let yes = if script.useful.load(Ordering::SeqCst) {
        0.99
    } else {
        0.01
    };
    axum::Json(json!({
        "model": request["model"],
        "answers": {"decision": {"type": "noul", "noul": yes}},
        "usage": {"input_tokens": 11, "output_tokens": 7},
    }))
}

async fn start_system_one(script: Arc<Script>) -> String {
    let app = Router::new()
        .route("/v1/systemone", post(system_one))
        .with_state(script);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the System One stub");
    let addr = listener.local_addr().expect("System One stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/v1/systemone")
}

/// The text of the last user message of a chat request.
fn user_text(request: &Value) -> String {
    request["messages"]
        .as_array()
        .and_then(|messages| messages.iter().rev().find(|m| m["role"] == "user"))
        .map(|message| match &message["content"] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// The Big rung's model: a held-out replay score per the script, and the
/// script's yes/no for any yes/no question that escalates this far.
fn big_reply(script: Arc<Script>) -> Reply {
    Reply::Computed(Arc::new(move |request: &Value| {
        let user = user_text(request);
        if !user.contains(REPLAY_QUESTION) {
            return json!({"answer": script.useful.load(Ordering::SeqCst), "probability": 0.99})
                .to_string();
        }
        script.replay_calls.fetch_add(1, Ordering::SeqCst);
        let state = user
            .split_once("State (JSON): ")
            .and_then(|(_, rest)| rest.lines().next())
            .and_then(|line| serde_json::from_str::<Value>(line).ok())
            .unwrap_or(Value::Null);
        let score = match *script.replay.lock().expect("script lock") {
            Replay::Tie => 0.5,
            Replay::Improved if state["claim"]["value"] == "improved" => 0.9,
            Replay::Improved => 0.2,
        };
        json!({"answer": score, "probability": 0.99}).to_string()
    }))
}

fn models_text(chat: &str, system_one: &str) -> String {
    format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{chat}\"\n\
         [decisions.system_one]\nendpoint = \"{system_one}\"\n\
         key_env = \"PATH\"\nmodel = \"fixture-head\"\nversion = \"1\"\nremote_opt_in = true\n\
         [decisions.big]\nversion = \"1\"\n\
         wording = \"Answer the typed question using only the supplied state.\"\nreply = \"json\"\n"
    )
}

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// A served host with both stubs, its owner's credential and the seeded
/// resident agent.
struct Served {
    vault: Arc<Vault>,
    app: Router,
    host: AiHost,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    script: Arc<Script>,
    _chat: FakeLlm,
    /// The embedded owner: every claim's subject.
    owner: EntityId,
    resident: EntityId,
}

impl Served {
    async fn start(path: &Path) -> Self {
        let script = Script::new();
        let chat = FakeLlm::start(vec![], Some(big_reply(Arc::clone(&script)))).await;
        let system_one = start_system_one(Arc::clone(&script)).await;
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("claim-refinement-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let models = ModelsConfig::from_toml(&models_text(&chat.base_url, &system_one), None)
            .expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let app = build_app(Arc::new(server));
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let resident = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agent")
            .expect("seeded agent")
            .0;
        Self {
            vault,
            app,
            host,
            issuer,
            slip,
            token,
            script,
            _chat: chat,
            owner,
            resident,
        }
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }

    async fn send(&self, method: &str, uri: &str, body: Option<&Value>) -> (StatusCode, Value) {
        // Each request proves possession afresh; the host secret is not a bearer.
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn facade(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        self.send("POST", &format!("/v1/core/facade/{verb}"), Some(body))
            .await
    }

    /// An active, owner-adjudicated base claim number `n` and its one label,
    /// reserved as its held-out split through the reserve door.
    async fn base(&self, n: u8) -> EntityId {
        let base = EntityId::now();
        let mut original = ClaimBody::new(
            format!("booking.refinement_{n}"),
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from("old"),
            0.8,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("base claim body");
        original.source = Some(ClaimSource::Inferred);
        self.vault
            .put_claim(&base, &original, at(2), 2)
            .expect("put the base claim");
        let label = EntityId::now();
        let mut evidence = ClaimBody::new(
            format!("booking.label_{n}"),
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from("adjudicated"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("label claim body");
        evidence.source = Some(ClaimSource::UserStated);
        self.vault
            .put_claim(&label, &evidence, at(3), 3)
            .expect("put the label claim");
        let (status, answer) = self
            .facade(
                "vault.claims.refinements.holdouts.reserve",
                &json!({"base": base.to_hex(), "labels": [label.to_hex()]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "reserve: {answer}");
        assert_eq!(answer["base"], base.to_hex().as_str(), "{answer}");
        assert_eq!(answer["labels"], json!([label.to_hex()]), "{answer}");
        base
    }

    /// The edit of `base` to `value` the resident's session branch holds.
    async fn offer(&self, base: EntityId, value: &str) -> EntityId {
        let (status, answer) = self
            .facade(
                "vault.claims.refinements.offer",
                &json!({
                    "base": base.to_hex(),
                    "resident": self.resident.to_hex(),
                    "session_tag": SESSION_TAG,
                    "value": value,
                    "confidence": 0.9,
                    "source": "inferred",
                    "occurred": {"start": 5, "end": 5},
                    "learned_at": 5,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "offer: {answer}");
        assert_eq!(answer["base"], base.to_hex().as_str(), "{answer}");
        assert_eq!(
            answer["resident"],
            self.resident.to_hex().as_str(),
            "{answer}"
        );
        assert_eq!(answer["session_tag"], SESSION_TAG, "{answer}");
        EntityId::from_hex(answer["candidate"].as_str().expect("candidate id"))
            .expect("candidate id hex")
    }

    /// The owner's approve route on `candidate` with the stubs answering
    /// `useful` and scoring by `replay`; the ruling it answers.
    async fn approve(&self, candidate: EntityId, useful: bool, replay: Replay) -> Value {
        self.script.set(useful, replay);
        let (status, ruling) = self
            .send(
                "POST",
                &format!(
                    "/v1/owner/claims/refinements/{}/approve",
                    candidate.to_hex()
                ),
                Some(&json!({"question": USEFUL_QUESTION, "question_version": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "approve: {ruling}");
        assert_eq!(ruling["consent"]["outcome"], "approved", "{ruling}");
        ruling
    }

    /// The owner's read of `candidate`'s branch row and stored ruling.
    async fn refinement(&self, candidate: EntityId) -> (StatusCode, Value) {
        self.send(
            "GET",
            &format!("/v1/owner/claims/refinements/{}", candidate.to_hex()),
            None,
        )
        .await
    }

    /// The owner deletes `candidate` through `vault.delete` under `reason`.
    async fn delete(&self, candidate: EntityId, reason: &str) {
        let (status, receipt) = self
            .facade(
                "vault.delete",
                &json!({"entity_ref": candidate.to_hex(), "reason": reason}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "delete: {receipt}");
        assert_eq!(receipt["existed"], true, "real delete scope: {receipt}");
    }

    fn replay_calls(&self) -> usize {
        self.script.replay_calls.load(Ordering::SeqCst)
    }

    fn assert_no_unexpected_question(&self) {
        assert_eq!(
            self.script.unexpected.load(Ordering::SeqCst),
            0,
            "the System One seat was asked only yes/no questions"
        );
    }
}

fn lifecycle(vault: &Vault, id: EntityId) -> Option<ClaimLifecycleStatus> {
    vault
        .get_claim(&id)
        .expect("read a claim")
        .map(|body| body.lifecycle)
}

/// After the host is gone, a fresh open of the vault keeps no branch row, no
/// stored ruling and no claim for any of `erased`.
fn assert_erased_after_reopen(path: &Path, erased: &[EntityId]) {
    let reopened = Vault::open(path, VaultConfig::device()).expect("reopen vault");
    for candidate in erased {
        assert!(
            reopened
                .local_claim_refinement(*candidate)
                .expect("read the branch row")
                .is_none(),
            "{candidate:?}: branch row after reopen"
        );
        assert!(
            reopened
                .claim_refinement_merge_receipt(*candidate)
                .expect("read the ruling")
                .is_none(),
            "{candidate:?}: ruling after reopen"
        );
    }
}

/// Runs `case` on the engine stack over a vault at `path`; the host and every
/// task it started end before this returns.
fn served<F, Fut>(name: &str, path: PathBuf, case: F)
where
    F: FnOnce(Served) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    run_on_engine_stack(name, move || async move {
        case(Served::start(&path).await).await;
    });
}

/// Port of `rejected_branch_claim_stays_local_and_cannot_use_the_generic_claim_door`.
#[test]
fn a_refused_branch_edit_stays_local_and_the_generic_claim_door_cannot_overwrite_it() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    served(
        "claim-refinement-refused",
        dir.path().into(),
        |host| async move {
            let base = host.base(1).await;
            let candidate = host.offer(base, "improved").await;
            let (status, staged) = host.refinement(candidate).await;
            assert_eq!(status, StatusCode::OK, "{staged}");
            assert_eq!(staged["receipt"], Value::Null, "{staged}");
            assert_eq!(
                staged["refinement"]["resident"],
                host.resident.to_hex().as_str(),
                "{staged}"
            );

            let ruling = host.approve(candidate, false, Replay::Improved).await;
            assert_eq!(ruling["outcome"], "refused", "{ruling}");
            let receipt = &ruling["receipt"];
            assert_eq!(receipt["accepted"], false, "{ruling}");
            assert_eq!(receipt["useful_upstream"], false, "{ruling}");
            assert_eq!(receipt["before"], Value::Null, "{ruling}");
            assert_eq!(receipt["after"], Value::Null, "{ruling}");
            assert_eq!(
                receipt["resident"],
                host.resident.to_hex().as_str(),
                "{ruling}"
            );
            assert_eq!(host.replay_calls(), 0, "a no never runs the replay");
            host.assert_no_unexpected_question();

            // The branch claim stays a proposal under its session tag.
            let claim = host
                .vault
                .get_claim(&candidate)
                .expect("read the branch claim")
                .expect("the branch claim survives a refusal");
            assert_eq!(claim.approval, ClaimApprovalStatus::Proposed);
            assert_eq!(claim.value, rmpv::Value::from("improved"));
            assert_eq!(claim.session_tag.as_deref(), Some(SESSION_TAG));
            let local = host
                .vault
                .local_claim_refinement(candidate)
                .expect("read the branch row")
                .expect("the branch row survives a refusal");
            assert_eq!(local.resident, host.resident.to_hex());
            // The generic claim door cannot overwrite the branch claim with the
            // same proposal.
            let mut overwrite = ClaimBody::new(
                "booking.refinement_1",
                ClaimSubject::Entity(host.owner),
                rmpv::Value::from("improved"),
                0.9,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            )
            .expect("proposal body");
            overwrite.source = Some(ClaimSource::Inferred);
            overwrite.session_tag = Some(SESSION_TAG.to_owned());
            assert!(
                host.vault
                    .put_claim(&candidate, &overwrite, at(7), 7)
                    .is_err(),
                "the generic claim door overwrote a branch claim"
            );
            assert_eq!(
                lifecycle(&host.vault, base),
                Some(ClaimLifecycleStatus::Active)
            );
            // The stored ruling is the one the route answered.
            let (status, read) = host.refinement(candidate).await;
            assert_eq!(status, StatusCode::OK, "{read}");
            assert_eq!(read["receipt"], ruling["receipt"], "{read}");
            host.finish().await;
        },
    );
}

/// Port of `claim_yes_needs_held_out_win_and_supersedes_only_at_the_merge_door`.
#[test]
fn a_useful_edit_that_wins_the_held_out_replay_supersedes_its_base() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    served(
        "claim-refinement-admitted",
        dir.path().into(),
        |host| async move {
            let base = host.base(1).await;
            let candidate = host.offer(base, "improved").await;
            let ruling = host.approve(candidate, true, Replay::Improved).await;
            assert_eq!(ruling["outcome"], "admitted", "{ruling}");
            let receipt = &ruling["receipt"];
            assert_eq!(receipt["accepted"], true, "{ruling}");
            assert_eq!(receipt["useful_upstream"], true, "{ruling}");
            let before = receipt["before"].as_f64().expect("base arm score");
            let after = receipt["after"].as_f64().expect("edit arm score");
            assert!((before - 0.2).abs() < 1e-6, "{ruling}");
            assert!((after - 0.9).abs() < 1e-6, "{ruling}");
            assert_eq!(host.replay_calls(), 2, "one replay score per arm");
            host.assert_no_unexpected_question();
            let claim = host
                .vault
                .get_claim(&candidate)
                .expect("read the merged claim")
                .expect("the merged claim");
            assert_eq!(claim.approval, ClaimApprovalStatus::Approved);
            assert_eq!(
                lifecycle(&host.vault, base),
                Some(ClaimLifecycleStatus::Superseded)
            );
            let (status, read) = host.refinement(candidate).await;
            assert_eq!(status, StatusCode::OK, "the branch row stays: {read}");
            host.finish().await;
        },
    );
}

/// Port of `claim_tie_keeps_the_branch_and_base` (beside the six ND-001
/// rows: the same route with a tied replay).
#[test]
fn a_tied_held_out_replay_keeps_the_branch_and_the_base() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    served(
        "claim-refinement-tie",
        dir.path().into(),
        |host| async move {
            let base = host.base(1).await;
            let candidate = host.offer(base, "improved").await;
            let ruling = host.approve(candidate, true, Replay::Tie).await;
            assert_eq!(ruling["outcome"], "refused", "{ruling}");
            assert_eq!(ruling["receipt"]["accepted"], false, "{ruling}");
            let claim = host
                .vault
                .get_claim(&candidate)
                .expect("read the branch claim")
                .expect("the branch claim");
            assert_eq!(claim.approval, ClaimApprovalStatus::Proposed);
            assert_eq!(
                lifecycle(&host.vault, base),
                Some(ClaimLifecycleStatus::Active)
            );
            host.finish().await;
        },
    );
}

/// Port of `explicit_delete_erases_pending_rejected_and_admitted_claim_branch_bytes_even_after_reopen`.
#[test]
fn an_explicit_delete_erases_pending_refused_and_admitted_branch_edits_after_reopen() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let erased = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&erased);
    served(
        "claim-refinement-delete",
        dir.path().into(),
        |host| async move {
            let base = host.base(1).await;
            let pending = host.offer(base, "unique-branch-payload-pending").await;
            let refused = host.offer(base, "unique-branch-payload-refused").await;
            let ruling = host.approve(refused, false, Replay::Improved).await;
            assert_eq!(ruling["outcome"], "refused", "{ruling}");
            // The admitted edit supersedes its base, so it goes last.
            let admitted = host.offer(base, "improved").await;
            let ruling = host.approve(admitted, true, Replay::Improved).await;
            assert_eq!(ruling["outcome"], "admitted", "{ruling}");
            for candidate in [pending, refused, admitted] {
                host.delete(candidate, "user_hard_delete").await;
                let (status, read) = host.refinement(candidate).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{read}");
                assert!(
                    host.vault
                        .claim_refinement_merge_receipt(candidate)
                        .expect("read the ruling")
                        .is_none()
                );
            }
            assert!(
                host.vault
                    .get_claim(&admitted)
                    .expect("read the merged claim")
                    .is_none()
            );
            kept.lock()
                .expect("ids lock")
                .extend([pending, refused, admitted]);
            host.finish().await;
        },
    );
    let erased = erased.lock().expect("ids lock").clone();
    assert_eq!(erased.len(), 3, "every case ran");
    assert_erased_after_reopen(dir.path(), &erased);
    let reopened = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
    assert!(
        reopened
            .get_claim(&erased[2])
            .expect("read the merged claim")
            .is_none()
    );
}

/// Port of `replayed_delete_erases_admitted_claim_branch_copy_after_reopen`.
#[test]
fn a_replayed_delete_erases_an_admitted_branch_edit_after_reopen() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let erased = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&erased);
    served(
        "claim-refinement-replayed",
        dir.path().into(),
        |host| async move {
            for (n, reason) in [
                (1, TombstoneReason::UserDelete),
                (2, TombstoneReason::GdprDelete),
            ] {
                let base = host.base(n).await;
                let candidate = host.offer(base, "improved").await;
                let ruling = host.approve(candidate, true, Replay::Improved).await;
                assert_eq!(ruling["outcome"], "admitted", "{ruling}");
                assert!(
                    apply_replayed_tombstone(&host.vault, &candidate, reason, 9)
                        .expect("apply the replayed tombstone"),
                    "{reason:?}: the replay erased the branch claim"
                );
                let (status, read) = host.refinement(candidate).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{reason:?}: {read}");
                kept.lock().expect("ids lock").push(candidate);
            }
            host.finish().await;
        },
    );
    let erased = erased.lock().expect("ids lock").clone();
    assert_eq!(erased.len(), 2, "every case ran");
    assert_erased_after_reopen(dir.path(), &erased);
}

/// Port of `replayed_soft_and_hard_delete_erase_headerless_claim_refinement`.
#[test]
fn replayed_soft_and_hard_deletes_erase_pending_and_refused_branch_edits() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    served(
        "claim-refinement-headerless",
        dir.path().into(),
        |host| async move {
            let base = host.base(1).await;
            for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
                for refused in [false, true] {
                    let value = format!("branch-replay-payload-{reason:?}-{refused}");
                    let candidate = host.offer(base, &value).await;
                    if refused {
                        let ruling = host.approve(candidate, false, Replay::Improved).await;
                        assert_eq!(ruling["outcome"], "refused", "{ruling}");
                    }
                    assert!(
                        apply_replayed_tombstone(&host.vault, &candidate, reason, 9)
                            .expect("apply the replayed tombstone"),
                        "{reason:?}/refused={refused}: the replay erased the branch claim"
                    );
                    assert!(
                        host.vault
                            .local_claim_refinement(candidate)
                            .expect("read the branch row")
                            .is_none(),
                        "{reason:?}/refused={refused}"
                    );
                    assert!(
                        host.vault
                            .claim_refinement_merge_receipt(candidate)
                            .expect("read the ruling")
                            .is_none(),
                        "{reason:?}/refused={refused}"
                    );
                }
            }
            assert_eq!(host.replay_calls(), 0, "a no never runs the replay");
            host.finish().await;
        },
    );
}

/// Port of `native_claim_erase_matrix_keeps_the_id_fenced_after_reopen`.
#[test]
fn an_erased_branch_edit_id_stays_fenced_after_reopen() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let erased = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&erased);
    served(
        "claim-refinement-fence",
        dir.path().into(),
        |host| async move {
            let mut n = 0;
            for state in ["pending", "refused", "admitted"] {
                for mode in ["raw", "local", "replayed"] {
                    n += 1;
                    let base = host.base(n).await;
                    let candidate = host.offer(base, "improved").await;
                    match state {
                        "refused" => {
                            let ruling = host.approve(candidate, false, Replay::Improved).await;
                            assert_eq!(ruling["outcome"], "refused", "{ruling}");
                        }
                        "admitted" => {
                            let ruling = host.approve(candidate, true, Replay::Improved).await;
                            assert_eq!(ruling["outcome"], "admitted", "{ruling}");
                        }
                        _ => {}
                    }
                    let mut attempted = host
                        .vault
                        .get_claim(&candidate)
                        .expect("read the branch claim")
                        .expect("the branch claim before deletion");
                    attempted.approval = ClaimApprovalStatus::Approved;
                    attempted.session_tag = None;
                    match mode {
                        "raw" => host
                            .vault
                            .batch()
                            .delete(&candidate)
                            .commit()
                            .expect("raw delete"),
                        "local" => host.delete(candidate, "user_delete").await,
                        _ => {
                            apply_replayed_tombstone(
                                &host.vault,
                                &candidate,
                                TombstoneReason::GdprDelete,
                                10,
                            )
                            .expect("apply the replayed tombstone");
                        }
                    }
                    assert!(
                        host.vault
                            .local_claim_refinement(candidate)
                            .expect("read the branch row")
                            .is_none(),
                        "{state}/{mode}"
                    );
                    assert!(
                        host.vault
                            .claim_refinement_merge_receipt(candidate)
                            .expect("read the ruling")
                            .is_none(),
                        "{state}/{mode}"
                    );
                    kept.lock().expect("ids lock").push((
                        format!("{state}/{mode}"),
                        candidate,
                        attempted,
                    ));
                }
            }
            host.finish().await;
        },
    );
    let erased = erased.lock().expect("ids lock").clone();
    assert_eq!(erased.len(), 9, "every case ran");
    let ids: Vec<EntityId> = erased.iter().map(|(_, id, _)| *id).collect();
    assert_erased_after_reopen(dir.path(), &ids);
    let reopened = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
    for (case, candidate, attempted) in &erased {
        assert!(
            put_replicated_claim(&reopened, candidate, attempted, 11).is_err(),
            "{case}: an erased id stays fenced"
        );
    }
}

//! A shared skill's merge through the served doors (FIX
//! [SKILL-HUB-PROMOTION-VERBS], ND-001's merge half). `vault.skills.merges.offer`
//! stages the package bytes a federation merge-back or a company pull request
//! carried as an untrusted Candidate; the owner's approve route
//! (`POST /v1/owner/packs/skills/merges/{candidate}/approve`) rules on it with
//! the host's typed decisions: the useful-upstream yes/no on the System One
//! seat, then, on a yes, the held-out replay on the host's registered judge,
//! whose scores the Big rung answers.
//!
//! The judge registers once per process and keeps the host it was built on,
//! as `serve` registers it, so one served host runs every case, each on its
//! own active base. Each case names the quarantined engine test of
//! `crates/oneiron/src/skill_hub/admission_tests.rs` it ports. The System One
//! seat is a loopback stub of its native `/v1/systemone` protocol and the Big
//! rung's model a scripted `FakeLlm` scoring the instructions it is shown.
//!
//! Reads JSON only for the new verb, so on a main without it the test fails
//! at its first offer status.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --no-fail-fast --test skill_merge_doors`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, ManifestEntry,
    ManifestKind,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    HubFile, HubPackage, SharedSkillLane, SkillCapabilitySurface, encode_hub_package,
};
use oneiron::skill_optimize::HeldOutReplayNotes;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, replay_judge, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The instructions every offered revision carries; the judge scores them
/// above the base while the script lifts.
const CANDIDATE_TEXT: &str = "check result";
/// Who every offer names as its submitter.
const SUBMITTED_BY: &str = "member:fixture";

/// The active shared skill each case's offers revise.
const FEDERATION_BASE: &str = "fixture.federation";
const COMPANY_BASE: &str = "fixture.company";
const NO_GAIN_BASE: &str = "fixture.no-gain";
const USELESS_BASE: &str = "fixture.useless";
const REFUSAL_BASE: &str = "fixture.refusal";
const BASES: [&str; 5] = [
    FEDERATION_BASE,
    COMPANY_BASE,
    NO_GAIN_BASE,
    USELESS_BASE,
    REFUSAL_BASE,
];

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// What both stubs answer, set by a case before each approve call, and the
/// calls they took.
struct Script {
    /// The System One seat's useful-upstream answer.
    useful: AtomicBool,
    /// While true an offered revision's instructions score 0.9, else 0.2;
    /// a base always scores 0.2.
    lift: AtomicBool,
    useful_calls: AtomicUsize,
    scores: AtomicUsize,
    /// System One questions that were not a yes/no, and Big rung requests
    /// that were not a held-out replay score.
    unexpected: AtomicUsize,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            useful: AtomicBool::new(true),
            lift: AtomicBool::new(true),
            useful_calls: AtomicUsize::new(0),
            scores: AtomicUsize::new(0),
            unexpected: AtomicUsize::new(0),
        })
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

/// The Big rung's model: one held-out replay score per call, read from the
/// instructions in the state it is shown, and the script's yes/no for any
/// yes/no question that escalates this far.
fn big_reply(script: Arc<Script>) -> Reply {
    Reply::Computed(Arc::new(move |request: &Value| {
        let user = user_text(request);
        if !user.contains("held_out_receipts") {
            script.unexpected.fetch_add(1, Ordering::SeqCst);
            return json!({"answer": script.useful.load(Ordering::SeqCst), "probability": 0.99})
                .to_string();
        }
        script.scores.fetch_add(1, Ordering::SeqCst);
        let score = if user.contains(CANDIDATE_TEXT) && script.lift.load(Ordering::SeqCst) {
            0.9
        } else {
            0.2
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

/// A hub package of one SKILL.md named `name` at `version`.
fn package(name: &str, version: &str, instructions: &str) -> HubPackage {
    let content = format!(
        "---\nname: {name}\ndescription: fixture\nversion: {version}\n---\n{instructions}\n"
    );
    let record = SkillRecord::new(
        name,
        "fixture",
        version,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    );
    let mut package = HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.into_bytes())],
        SkillCapabilitySurface::default(),
    );
    package.record.content_hash = Some(package.content_hash().expect("package hash"));
    package
}

/// The offered bytes of a version-2 revision of `base_name`, in the host
/// transport encoding, standard base64.
fn offered_bytes(base_name: &str, instructions: &str) -> String {
    let bytes =
        encode_hub_package(&package(base_name, "2", instructions)).expect("encode the package");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// An owner-authored skill named `name`, put Active at version 1.
fn active_skill(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let mut record = package(name, "1", "baseline").record;
    record.source = ClaimSource::UserStated;
    record.content_hash = None;
    let now = vault.now_recorded_at();
    vault
        .put_skill_record(&id, &record, at(now), now)
        .expect("base candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    record.approval_status = ClaimApprovalStatus::Approved;
    vault
        .update_skill_record(&id, &record, at(now + 1), now + 1)
        .expect("active base");
    id
}

/// Completed typed attempts whose manifest loaded `skill_id`, each credited
/// to `skill` through the reliability door, until the held-out split holds one.
fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    let queue = AttemptQueue::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    for _ in 0..200 {
        let now = vault.now_recorded_at();
        let AgentDispatchOutcome::Dispatched(dispatched) = dispatcher
            .dispatch_default_base(None, None, None, now)
            .expect("enqueue typed agent dispatch")
        else {
            panic!("fresh agent dispatch");
        };
        let attempt = dispatched.attempt;
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, skill_id, "1", now),
            )
            .expect("skill manifest");
        let ClaimOutcome::Claimed(leased) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "fixture".to_owned(),
                    now: vault.now_recorded_at(),
                },
            )
            .expect("claim")
        else {
            panic!("claimable attempt");
        };
        assert_eq!(leased.id, attempt.id);
        queue
            .set_executor_model(
                attempt.id,
                "fixture",
                leased.attempt_count,
                "fixture/model@1",
            )
            .expect("executor stamp");
        assert!(matches!(
            queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "fixture".to_owned(),
                    attempt_count: leased.attempt_count,
                    now: vault.now_recorded_at(),
                })
                .expect("complete"),
            CompleteOutcome::Completed(_)
        ));
        let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
        oneiron::skill_reliability::record_skill_contributing_win(
            vault,
            skill,
            &receipt,
            vault.now_recorded_at(),
        )
        .expect("attribute win");
        if !oneiron::skill_optimize::held_out_receipts(vault, skill)
            .expect("held-out reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}

/// A fork of a resident's own skill in a member's personal vault, which is
/// dropped, directory and all, before anything reaches the served host: the
/// fork id the offer names, and nothing the host could read.
fn personal_fork() -> EntityId {
    let dir = tempfile::tempdir().expect("personal vault directory");
    let personal = Vault::open(dir.path(), VaultConfig::default()).expect("personal vault");
    personal
        .ensure_embedded_owner_actor()
        .expect("personal vault owner");
    let base = active_skill(&personal, "fixture.personal");
    let resident = EntityId::now();
    let now = personal.now_recorded_at();
    personal
        .put_entity(
            &resident,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at(now),
            now,
            b"resident",
        )
        .expect("resident person");
    let fork = EntityId::now();
    personal
        .fork_skill_for_resident(
            &resident,
            &base,
            &fork,
            "fixture.personal-fork",
            at(now + 1),
            now + 1,
        )
        .expect("resident fork");
    personal
        .write_shared_skill_fork_package(
            &fork,
            &package("fixture.personal-fork", "2", CANDIDATE_TEXT),
            at(now + 2),
            now + 2,
        )
        .expect("fork package");
    drop(personal);
    drop(dir);
    fork
}

/// A served host with both stubs and the registered held-out judge, its
/// owner's credential, the seeded resident agent and one reserved active
/// base per case.
struct Served {
    vault: Arc<Vault>,
    app: Router,
    host: AiHost,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    script: Arc<Script>,
    _chat: FakeLlm,
    resident: EntityId,
    /// The active base of each name in `BASES`, in that order.
    bases: Vec<EntityId>,
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
                auth_secret: Some("skill-merge-doors".into()),
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
        vault.ensure_embedded_owner_actor().expect("embedded owner");
        // The reserves claim their own attempts, before any host worker runs.
        let bases = BASES
            .iter()
            .map(|name| {
                let base = active_skill(&vault, name);
                reserve(&vault, &base, name);
                base
            })
            .collect();
        let resident = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agent")
            .expect("seeded agent")
            .0;
        let models = ModelsConfig::from_toml(&models_text(&chat.base_url, &system_one), None)
            .expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        // As `serve` does, on the ladder the host just built.
        replay_judge::register(&server, None);
        assert!(
            replay_judge::registered().is_some(),
            "the host's held-out judge is registered"
        );
        let app = build_app(Arc::new(server));
        Self {
            vault,
            app,
            host,
            issuer,
            slip,
            token,
            script,
            _chat: chat,
            resident,
            bases,
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

    /// The active base named `name`.
    fn base(&self, name: &str) -> EntityId {
        let index = BASES
            .iter()
            .position(|base| *base == name)
            .expect("a fixture base");
        self.bases[index]
    }

    /// `vault.skills.merges.offer` of `package_base64` against `base`.
    async fn try_offer(
        &self,
        base: EntityId,
        package_base64: &str,
        lane: SharedSkillLane,
        fork: EntityId,
    ) -> (StatusCode, Value) {
        self.send(
            "POST",
            "/v1/core/facade/vault.skills.merges.offer",
            Some(&json!({
                "base": base.to_hex(),
                "package_base64": package_base64,
                "lane": lane,
                "submitted_by": SUBMITTED_BY,
                "submitted_fork": fork.to_hex(),
            })),
        )
        .await
    }

    /// An offer that stages; its candidate, checked against the stored offer
    /// and the owner's pending list.
    async fn offer(
        &self,
        base: EntityId,
        package_base64: &str,
        lane: SharedSkillLane,
        fork: EntityId,
    ) -> EntityId {
        let (status, offered) = self.try_offer(base, package_base64, lane, fork).await;
        assert_eq!(status, StatusCode::OK, "offer: {offered}");
        let candidate = EntityId::from_hex(offered["candidate"].as_str().expect("candidate"))
            .expect("candidate id");
        let delta = &offered["delta"];
        assert_eq!(delta["candidate"], candidate.to_hex().as_str(), "{offered}");
        assert_eq!(delta["base"], base.to_hex().as_str(), "{offered}");
        assert_eq!(delta["lane"], json!(lane), "{offered}");
        assert_eq!(delta["submitted_by"], SUBMITTED_BY, "{offered}");
        assert_eq!(delta["submitted_fork"], fork.to_hex().as_str(), "{offered}");
        assert_eq!(
            self.lifecycle(candidate),
            SkillLifecycle::Candidate,
            "an offer lands an untrusted Candidate"
        );
        let detail = self.merge_detail(candidate).await;
        assert_eq!(detail["state"], "pending", "{detail}");
        assert_eq!(detail["delta"], *delta, "the stored offer: {detail}");
        assert_eq!(
            detail["needs_owner"], false,
            "an un-widened merge asks no owner answer: {detail}"
        );
        assert!(
            self.pending().await.contains(delta),
            "the owner's pending list holds the offer"
        );
        candidate
    }

    /// The owner's read of the offer under `candidate`.
    async fn merge_detail(&self, candidate: EntityId) -> Value {
        let (status, detail) = self
            .send(
                "GET",
                &format!("/v1/owner/packs/skills/merges/{}", candidate.to_hex()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "merge detail: {detail}");
        detail
    }

    /// Every offer no merge has ruled on.
    async fn pending(&self) -> Vec<Value> {
        let (status, pending) = self
            .send("GET", "/v1/owner/packs/skills/merges", None)
            .await;
        assert_eq!(status, StatusCode::OK, "pending merges: {pending}");
        pending.as_array().expect("pending list").clone()
    }

    /// The owner's approve route on `candidate`, with the System One seat
    /// answering `useful` and the judge's scores lifting on `lift`; the
    /// ruling's outcome and its merge receipt, which the owner's read of the
    /// offer then holds.
    async fn approve(&self, candidate: EntityId, useful: bool, lift: bool) -> (String, Value) {
        self.script.useful.store(useful, Ordering::SeqCst);
        self.script.lift.store(lift, Ordering::SeqCst);
        let asked = self.script.useful_calls.load(Ordering::SeqCst);
        let (status, ruling) = self
            .send(
                "POST",
                &format!(
                    "/v1/owner/packs/skills/merges/{}/approve",
                    candidate.to_hex()
                ),
                Some(&json!({"resident": self.resident.to_hex()})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "approve: {ruling}");
        assert!(
            self.script.useful_calls.load(Ordering::SeqCst) > asked,
            "the System One seat answered the useful-upstream question"
        );
        assert_eq!(
            ruling.get("consent"),
            None,
            "a reversible merge takes no owner answer: {ruling}"
        );
        let receipt = ruling["receipt"].clone();
        assert_eq!(
            receipt["delta"]["candidate"],
            candidate.to_hex().as_str(),
            "{ruling}"
        );
        assert_eq!(
            receipt["resident"],
            self.resident.to_hex().as_str(),
            "{ruling}"
        );
        assert_eq!(
            receipt["decision"]["receipt"]["providers"][0]["rung"], "system_one",
            "the useful-upstream answer came from the System One seat: {ruling}"
        );
        assert_eq!(
            self.merge_detail(candidate).await["receipt"],
            ruling["receipt"],
            "the owner's read holds the ruling"
        );
        (
            ruling["outcome"]
                .as_str()
                .expect("ruling outcome")
                .to_owned(),
            receipt,
        )
    }

    fn lifecycle(&self, entity: EntityId) -> SkillLifecycle {
        self.vault
            .get_skill_record(&entity)
            .expect("read the skill")
            .expect("the skill")
            .lifecycle_status
    }

    fn scores(&self) -> usize {
        self.script.scores.load(Ordering::SeqCst)
    }
}

/// Port of `federation_and_company_merge_only_submitted_bytes_with_useful_and_replay_lineage`:
/// on both lanes, the offered bytes of a fork whose personal vault is gone
/// merge on the useful yes and the held-out win alone, with no per-merge
/// approval (ARCH-0053 r4): the revision is Active, its base Superseded, and
/// the stored receipt names the lane, the fork and the judge.
async fn both_lanes_merge_only_the_offered_bytes_on_useful_and_replay(host: &Served) {
    for (lane, name) in [
        (SharedSkillLane::FederationMergeBack, FEDERATION_BASE),
        (SharedSkillLane::CompanyPullRequest, COMPANY_BASE),
    ] {
        let base = host.base(name);
        let fork = personal_fork();
        let candidate = host
            .offer(base, &offered_bytes(name, CANDIDATE_TEXT), lane, fork)
            .await;
        let scored = host.scores();
        let (outcome, receipt) = host.approve(candidate, true, true).await;
        assert_eq!(outcome, "admitted", "{lane:?}: {receipt}");
        assert_eq!(receipt["accepted"], true, "{receipt}");
        assert_eq!(receipt["useful_upstream"], true, "{receipt}");
        assert_eq!(
            receipt["judge_revision"],
            replay_judge::registered()
                .expect("registered judge")
                .judge_revision(),
            "the host's judge scored it: {receipt}"
        );
        assert!(host.scores() > scored, "{lane:?}: the judge replayed it");
        assert_eq!(
            receipt["delta"]["submitted_fork"],
            fork.to_hex().as_str(),
            "{receipt}"
        );
        assert_eq!(receipt["delta"]["lane"], json!(lane), "{receipt}");
        assert_eq!(
            host.lifecycle(candidate),
            SkillLifecycle::Active,
            "{lane:?}"
        );
        assert_eq!(host.lifecycle(base), SkillLifecycle::Superseded, "{lane:?}");
        assert_eq!(
            host.merge_detail(candidate).await["state"],
            "admitted",
            "{lane:?}"
        );
    }
}

/// Port of `resident_fork_delta_without_held_out_gain_cannot_merge_upstream`:
/// a useful yes with no held-out gain refuses the merge after both arms
/// replayed; the base stays Active and the revision a Candidate.
async fn a_useful_offer_without_a_held_out_gain_cannot_merge(host: &Served) {
    let base = host.base(NO_GAIN_BASE);
    let candidate = host
        .offer(
            base,
            &offered_bytes(NO_GAIN_BASE, CANDIDATE_TEXT),
            SharedSkillLane::FederationMergeBack,
            EntityId::now(),
        )
        .await;
    let (outcome, receipt) = host.approve(candidate, true, false).await;
    assert_eq!(outcome, "refused", "{receipt}");
    assert_eq!(receipt["useful_upstream"], true, "{receipt}");
    assert_eq!(receipt["accepted"], false, "{receipt}");
    assert!(
        receipt["before"].is_number() && receipt["after"].is_number(),
        "both arms replayed: {receipt}"
    );
    assert_eq!(host.lifecycle(base), SkillLifecycle::Active);
    assert_eq!(host.lifecycle(candidate), SkillLifecycle::Candidate);
    assert_eq!(host.merge_detail(candidate).await["state"], "refused");
}

/// Port of `useless_shared_delta_never_runs_replay_or_changes_base`: a
/// useful no refuses the merge before any replay; the offer stays readable,
/// the revision a Candidate and the base Active.
async fn a_useless_offer_never_replays_or_changes_its_base(host: &Served) {
    let base = host.base(USELESS_BASE);
    let candidate = host
        .offer(
            base,
            &offered_bytes(USELESS_BASE, CANDIDATE_TEXT),
            SharedSkillLane::FederationMergeBack,
            EntityId::now(),
        )
        .await;
    let scored = host.scores();
    let (outcome, receipt) = host.approve(candidate, false, true).await;
    assert_eq!(outcome, "refused", "{receipt}");
    assert_eq!(receipt["useful_upstream"], false, "{receipt}");
    assert_eq!(receipt["accepted"], false, "{receipt}");
    assert_eq!(receipt["before"], Value::Null, "{receipt}");
    assert_eq!(host.scores(), scored, "a useless offer is never replayed");
    let detail = host.merge_detail(candidate).await;
    assert_eq!(detail["delta"]["candidate"], candidate.to_hex().as_str());
    assert_eq!(host.lifecycle(candidate), SkillLifecycle::Candidate);
    assert_eq!(host.lifecycle(base), SkillLifecycle::Active);
}

/// The door's own refusals: bytes that are not base64, a package that does
/// not revise its base (the same version) and a base that is not an active
/// skill stage nothing.
async fn an_offer_that_does_not_revise_an_active_base_stages_nothing(host: &Served) {
    let base = host.base(REFUSAL_BASE);
    let pending = host.pending().await.len();
    let lane = SharedSkillLane::CompanyPullRequest;
    let (status, refusal) = host
        .try_offer(base, "not base64 at all!", lane, EntityId::now())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "not base64: {refusal}");
    let same_version = base64::engine::general_purpose::STANDARD
        .encode(encode_hub_package(&package(REFUSAL_BASE, "1", CANDIDATE_TEXT)).expect("encode"));
    let (status, refusal) = host
        .try_offer(base, &same_version, lane, EntityId::now())
        .await;
    assert_ne!(status, StatusCode::OK, "the same version: {refusal}");
    let (status, refusal) = host
        .try_offer(
            EntityId::now(),
            &offered_bytes(REFUSAL_BASE, CANDIDATE_TEXT),
            lane,
            EntityId::now(),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "no such base: {refusal}");
    assert_eq!(host.pending().await.len(), pending, "nothing was staged");
    assert_eq!(host.lifecycle(base), SkillLifecycle::Active);
}

#[test]
fn a_shared_skill_merges_only_offered_bytes_through_the_useful_and_held_out_gates() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let path: PathBuf = dir.path().into();
    run_on_engine_stack("skill-merge-offer", move || async move {
        let host = Served::start(&path).await;
        both_lanes_merge_only_the_offered_bytes_on_useful_and_replay(&host).await;
        a_useful_offer_without_a_held_out_gain_cannot_merge(&host).await;
        a_useless_offer_never_replays_or_changes_its_base(&host).await;
        an_offer_that_does_not_revise_an_active_base_stages_nothing(&host).await;
        assert_eq!(
            host.script.unexpected.load(Ordering::SeqCst),
            0,
            "System One was asked only yes/no questions and the Big rung only replay scores"
        );
        host.finish().await;
    });
}

//! A hub skill's held-out activation through the served doors (FIX
//! [SKILL-HUB-PROMOTION-VERBS], ND-001's activation half). The owner's
//! prepare route shows the ask (`POST /v1/owner/packs/skills/{entity}/activation/prepare`),
//! `vault.skills.activation.admit` rules on it with the host's registered
//! held-out judge, and the approve route (`.../activation/approve`) records the
//! owner's answer to a permission widening.
//!
//! The judge registers once per process and keeps the host it was built on,
//! as `serve` registers it, so one served host runs every case, each on its
//! own candidates. Each case names the quarantined engine test of
//! `crates/oneiron/src/skill_hub/admission_tests.rs` it ports. The judge's
//! ladder is the Big rung alone, whose model is a scripted `FakeLlm` scoring
//! the instructions it is shown.
//!
//! Reads JSON only for the new verb, so on a main without it the test fails
//! at its first admit status.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --no-fail-fast --test skill_activation_doors`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, ManifestEntry,
    ManifestKind,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, SkillCapabilitySurface, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier,
};
use oneiron::skill_optimize::HeldOutReplayNotes;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, replay_judge, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The instructions every candidate carries; the judge scores them above the
/// baseline while the script lifts.
const CANDIDATE_TEXT: &str = "check result";
/// The publisher every ask names; the door admits it for the skill's hub.
const PUBLISHER: &str = "publisher:outside";

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// What the Big rung's model answers, set by a case before each admit, and
/// the calls it took.
struct Script {
    /// While true a candidate's instructions score 0.9, else 0.2; the
    /// baseline always scores 0.2.
    lift: AtomicBool,
    scores: AtomicUsize,
    /// Requests that were not a held-out replay score.
    unexpected: AtomicUsize,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            lift: AtomicBool::new(true),
            scores: AtomicUsize::new(0),
            unexpected: AtomicUsize::new(0),
        })
    }
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
/// instructions in the state it is shown.
fn big_reply(script: Arc<Script>) -> Reply {
    Reply::Computed(Arc::new(move |request: &Value| {
        let user = user_text(request);
        if !user.contains("held_out_receipts") {
            script.unexpected.fetch_add(1, Ordering::SeqCst);
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

fn models_text(chat: &str) -> String {
    format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{chat}\"\n\
         [decisions.big]\nversion = \"1\"\n\
         wording = \"Answer the typed question using only the supplied state.\"\nreply = \"json\"\n"
    )
}

/// A hub package of one SKILL.md; `read_file` declares a tool, a permission
/// widening (as `crates/oneiron/tests/skill_hub_admission_holds.rs` builds it).
fn package(name: &str, instructions: &str, read_file: bool) -> HubPackage {
    let tools = if read_file {
        "allowed-tools: [\"read_file\"]\n"
    } else {
        ""
    };
    let content = format!(
        "---\nname: {name}\ndescription: fixture\nversion: 1\n{tools}---\n{instructions}\n"
    );
    let record = SkillRecord::new(
        name,
        "fixture",
        "1",
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
    let capabilities = if read_file {
        SkillCapabilitySurface::default().with_allowed_tool("read_file")
    } else {
        SkillCapabilitySurface::default()
    };
    let mut package = HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.into_bytes())],
        capabilities,
    );
    package.record.content_hash = Some(package.content_hash().expect("package hash"));
    package
}

/// An active local skill with a held-out reserve of real attributed wins.
fn active_baseline(vault: &Vault) -> EntityId {
    let baseline = EntityId::now();
    let mut record = package("fixture.base", "baseline", false).record;
    record.source = ClaimSource::UserStated;
    record.content_hash = None;
    let now = vault.now_recorded_at();
    vault
        .put_skill_record(&baseline, &record, at(now), now)
        .expect("baseline candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    record.approval_status = ClaimApprovalStatus::Approved;
    vault
        .update_skill_record(&baseline, &record, at(now + 1), now + 1)
        .expect("active baseline");
    reserve(vault, &baseline, &record.skill_id);
    baseline
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

/// The ask the prepare route showed.
struct Ask {
    content_hash: String,
    effect_digest: String,
    surface: String,
}

/// A served host with the registered held-out judge, its owner's credential
/// and the evidence baseline every ask names.
struct Served {
    vault: Arc<Vault>,
    app: Router,
    host: AiHost,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    script: Arc<Script>,
    _chat: FakeLlm,
    owner: AuthenticatedOwner,
    baseline: EntityId,
}

impl Served {
    async fn start(path: &Path) -> Self {
        let script = Script::new();
        let chat = FakeLlm::start(vec![], Some(big_reply(Arc::clone(&script)))).await;
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("skill-activation-doors".into()),
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
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        // The reserve claims its own attempts, before any host worker runs.
        let baseline = active_baseline(&vault);
        let models =
            ModelsConfig::from_toml(&models_text(&chat.base_url), None).expect("models config");
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
            owner,
            baseline,
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

    /// A configured hub of `tier`.
    fn hub(&self, tier: SkillHubTrustTier) -> EntityId {
        let id = EntityId::now();
        let record = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "https://example.invalid/index.json",
            tier,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub record");
        let now = self.vault.now_recorded_at();
        self.vault
            .configure_skill_hub(&self.owner, &id, &record, at(now), now)
            .expect("configure hub");
        id
    }

    /// `package` imported from `hub` under `reference`, pinned to its hash:
    /// a Candidate.
    fn import(&self, hub: EntityId, reference: &str, package: &HubPackage) -> EntityId {
        let source = HubRef::new(
            hub,
            reference,
            HubPin::ContentHash(package.content_hash().expect("package hash").to_hex()),
        )
        .expect("pinned source");
        let now = self.vault.now_recorded_at();
        let id = self
            .vault
            .import_skill_from_hub(&source, package, at(now), now)
            .expect("import candidate");
        assert_eq!(self.lifecycle(id), SkillLifecycle::Candidate);
        id
    }

    fn ask_body(&self, effect_digest: Option<&str>) -> Value {
        let mut body = json!({
            "publisher": PUBLISHER,
            "evidence_skill": self.baseline.to_hex(),
        });
        if let Some(digest) = effect_digest {
            body["effect_digest"] = json!(digest);
        }
        body
    }

    /// The owner's prepare route on `entity`.
    async fn try_prepare(&self, entity: EntityId) -> (StatusCode, Value) {
        self.send(
            "POST",
            &format!(
                "/v1/owner/packs/skills/{}/activation/prepare",
                entity.to_hex()
            ),
            Some(&self.ask_body(None)),
        )
        .await
    }

    async fn prepare(&self, entity: EntityId) -> Ask {
        let (status, view) = self.try_prepare(entity).await;
        assert_eq!(status, StatusCode::OK, "prepare: {view}");
        assert_eq!(view["candidate"], entity.to_hex().as_str(), "{view}");
        let text = |key: &str| {
            view[key]
                .as_str()
                .unwrap_or_else(|| panic!("{key} in {view}"))
                .to_owned()
        };
        Ask {
            content_hash: text("content_hash"),
            effect_digest: text("effect_digest"),
            surface: text("surface"),
        }
    }

    /// The owner's answer on the approve route to the ask it was shown.
    async fn approve(&self, entity: EntityId, ask: &Ask) {
        let (status, consent) = self
            .send(
                "POST",
                &format!(
                    "/v1/owner/packs/skills/{}/activation/approve",
                    entity.to_hex()
                ),
                Some(&self.ask_body(Some(&ask.effect_digest))),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "approve: {consent}");
        assert_eq!(consent["outcome"], "approved", "{consent}");
    }

    /// `vault.skills.activation.admit` on `entity` with the digest shown.
    async fn admit(&self, entity: EntityId, effect_digest: &str) -> (StatusCode, Value) {
        let mut body = self.ask_body(Some(effect_digest));
        body["entity"] = json!(entity.to_hex());
        self.facade("vault.skills.activation.admit", &body).await
    }

    /// An admit that rules `outcome`; the ruling's admission receipt.
    async fn admit_ruled(&self, entity: EntityId, ask: &Ask, outcome: &str) -> Value {
        let (status, answer) = self.admit(entity, &ask.effect_digest).await;
        assert_eq!(status, StatusCode::OK, "admit: {answer}");
        assert_eq!(answer["outcome"], outcome, "{answer}");
        assert_eq!(answer["entity"], entity.to_hex().as_str(), "{answer}");
        let admission = answer["admission"].clone();
        assert_eq!(admission["candidate"], entity.to_hex().as_str(), "{answer}");
        assert_eq!(admission["consent_digest"], ask.effect_digest, "{answer}");
        assert_eq!(admission["content_hash"], ask.content_hash, "{answer}");
        assert_eq!(admission["publisher"], PUBLISHER, "{answer}");
        assert_eq!(
            admission["evidence_skill"],
            self.baseline.to_hex().as_str(),
            "{answer}"
        );
        assert_eq!(
            admission["judge_revision"],
            replay_judge::registered()
                .expect("registered judge")
                .judge_revision(),
            "the host's judge scored it: {answer}"
        );
        admission
    }

    /// The admission ruling `vault.skills.receipts` reads for `entity`.
    async fn stored_admission(&self, entity: EntityId) -> Value {
        let (status, receipts) = self
            .facade("vault.skills.receipts", &json!({"entity": entity.to_hex()}))
            .await;
        assert_eq!(status, StatusCode::OK, "receipts: {receipts}");
        receipts["admission"].clone()
    }

    fn lifecycle(&self, entity: EntityId) -> SkillLifecycle {
        self.vault
            .get_skill_record(&entity)
            .expect("read the skill")
            .expect("the skill")
            .lifecycle_status
    }

    fn set_lift(&self, lift: bool) {
        self.script.lift.store(lift, Ordering::SeqCst);
    }

    fn scores(&self) -> usize {
        self.script.scores.load(Ordering::SeqCst)
    }
}

/// Port of `every_hub_tier_installs_on_fit_and_only_a_permission_widening_asks`
/// (GATE-22, ARCH-0053 #r4b-hubs-h): every tier's ask keeps its surface; a
/// candidate that asks for no permission lands Active on its held-out win
/// with no owner answer; one that declares a tool waits for the owner's
/// answer before any replay.
async fn every_tier_installs_on_fit_and_only_a_widening_asks(host: &Served) {
    host.set_lift(true);
    for (tier, name, surface) in [
        (SkillHubTrustTier::Verified, "verified", "one_tap"),
        (
            SkillHubTrustTier::Community,
            "community",
            "summarized_review",
        ),
        (SkillHubTrustTier::Untrusted, "untrusted", "full_review"),
    ] {
        let hub = host.hub(tier);
        let plain = host.import(
            hub,
            name,
            &package(&format!("fixture.{name}"), CANDIDATE_TEXT, false),
        );
        let ask = host.prepare(plain).await;
        assert_eq!(ask.surface, surface, "{name}");
        let scored = host.scores();
        let admission = host.admit_ruled(plain, &ask, "admitted").await;
        assert_eq!(admission["accepted"], true, "{name}: {admission}");
        assert_eq!(admission["hub_id"], hub.to_hex().as_str(), "{admission}");
        assert!(host.scores() > scored, "{name}: the judge scored the ask");
        assert_eq!(host.lifecycle(plain), SkillLifecycle::Active, "{name}");
        assert_eq!(host.stored_admission(plain).await, admission, "{name}");

        // A permission widening asks on every tier, before any replay.
        let widened = host.import(
            hub,
            &format!("{name}-widened"),
            &package(&format!("fixture.{name}.widened"), CANDIDATE_TEXT, true),
        );
        let ask = host.prepare(widened).await;
        let scored = host.scores();
        let (status, pending) = host.admit(widened, &ask.effect_digest).await;
        assert_eq!(status, StatusCode::OK, "{name}: {pending}");
        assert_eq!(pending["outcome"], "pending_consent", "{name}: {pending}");
        assert_eq!(pending["effect_digest"], ask.effect_digest, "{pending}");
        assert_eq!(host.scores(), scored, "{name}: no replay before consent");
        assert_eq!(host.lifecycle(widened), SkillLifecycle::Candidate, "{name}");
        assert_eq!(host.stored_admission(widened).await, Value::Null, "{name}");
        host.approve(widened, &ask).await;
        let admission = host.admit_ruled(widened, &ask, "admitted").await;
        assert_eq!(admission["accepted"], true, "{name}: {admission}");
        assert_eq!(host.lifecycle(widened), SkillLifecycle::Active, "{name}");
    }
}

/// Port of `pending_legacy_admission_cannot_bypass_a_new_owner_hash_block`: an
/// owner hash rule set after the owner's answer refuses the admission and the
/// ask itself; clearing it admits the same ask.
async fn a_later_owner_hash_block_refuses_an_answered_ask(host: &Served) {
    host.set_lift(true);
    let hub = host.hub(SkillHubTrustTier::Verified);
    let id = host.import(
        hub,
        "blocked",
        &package("fixture.blocked", CANDIDATE_TEXT, false),
    );
    let ask = host.prepare(id).await;
    host.approve(id, &ask).await;
    let rule = |blocked: bool| json!({"content_hash": ask.content_hash, "blocked": blocked});
    let (status, receipt) = host.facade("vault.skills.rules.set", &rule(true)).await;
    assert_eq!(status, StatusCode::OK, "block: {receipt}");

    let scored = host.scores();
    let (status, refusal) = host.admit(id, &ask.effect_digest).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a later owner rule refuses: {refusal}"
    );
    assert_eq!(host.scores(), scored, "a blocked ask is never scored");
    assert_eq!(host.lifecycle(id), SkillLifecycle::Candidate);
    assert_eq!(host.stored_admission(id).await, Value::Null);
    let (status, view) = host.try_prepare(id).await;
    assert_ne!(status, StatusCode::OK, "blocked even on a new ask: {view}");

    // The refusal spent nothing: cleared, the same ask admits.
    let (status, receipt) = host.facade("vault.skills.rules.set", &rule(false)).await;
    assert_eq!(status, StatusCode::OK, "unblock: {receipt}");
    let admission = host.admit_ruled(id, &ask, "admitted").await;
    assert_eq!(admission["accepted"], true, "{admission}");
    assert_eq!(host.lifecycle(id), SkillLifecycle::Active);
}

/// Port of `two_hubs_dedup_and_raw_or_replayed_activation_cannot_bypass_rejection`:
/// the same bytes from two hubs are one skill; the record door cannot flip
/// it; a losing replay refuses it, and the refusal stands against a later
/// admit even with the owner's answer on file.
async fn a_refused_ask_stays_refused_across_two_hubs(host: &Served) {
    let first = host.hub(SkillHubTrustTier::Verified);
    let second = host.hub(SkillHubTrustTier::Community);
    let bytes = package("fixture.dedup", CANDIDATE_TEXT, false);
    let id = host.import(first, "dedup", &bytes);
    assert_eq!(host.import(second, "dedup", &bytes), id, "one skill");
    assert_eq!(
        host.vault
            .skill_hub_provenance_count(&id)
            .expect("provenance count"),
        2
    );
    let mut active = host
        .vault
        .get_skill_record(&id)
        .expect("read the candidate")
        .expect("the candidate");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Approved;
    let now = host.vault.now_recorded_at();
    assert!(
        host.vault
            .update_skill_record(&id, &active, at(now), now)
            .is_err(),
        "the record door cannot activate a hub candidate"
    );

    let ask = host.prepare(id).await;
    host.approve(id, &ask).await;
    host.set_lift(false);
    let scored = host.scores();
    let admission = host.admit_ruled(id, &ask, "refused").await;
    assert_eq!(admission["accepted"], false, "{admission}");
    assert_eq!(admission["before"], admission["after"], "{admission}");
    assert!(host.scores() > scored, "the judge scored the ask");
    assert_eq!(host.lifecycle(id), SkillLifecycle::Candidate);
    assert_eq!(host.stored_admission(id).await, admission);

    host.set_lift(true);
    let scored = host.scores();
    let (status, again) = host.admit(id, &ask.effect_digest).await;
    assert_ne!(status, StatusCode::OK, "the refusal stands: {again}");
    assert_eq!(host.scores(), scored, "a refused ask is not scored again");
    assert_eq!(host.lifecycle(id), SkillLifecycle::Candidate);
}

/// The door's own bind: an admit naming a digest other than the ask's is
/// refused before any replay; the shown digest then admits.
async fn an_admit_naming_another_digest_is_refused_unscored(host: &Served) {
    host.set_lift(true);
    let hub = host.hub(SkillHubTrustTier::Verified);
    let id = host.import(
        hub,
        "moved",
        &package("fixture.moved", CANDIDATE_TEXT, false),
    );
    let ask = host.prepare(id).await;
    let other = "00".repeat(32);
    assert_ne!(other, ask.effect_digest);
    let scored = host.scores();
    let (status, refusal) = host.admit(id, &other).await;
    assert_ne!(status, StatusCode::OK, "another digest: {refusal}");
    assert_eq!(host.scores(), scored, "a moved ask is never scored");
    assert_eq!(host.lifecycle(id), SkillLifecycle::Candidate);
    assert_eq!(host.stored_admission(id).await, Value::Null);
    let admission = host.admit_ruled(id, &ask, "admitted").await;
    assert_eq!(admission["accepted"], true, "{admission}");
}

#[test]
fn a_hub_skill_activates_only_through_the_held_out_admit_door() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let path: PathBuf = dir.path().into();
    run_on_engine_stack("skill-activation-admit", move || async move {
        let host = Served::start(&path).await;
        every_tier_installs_on_fit_and_only_a_widening_asks(&host).await;
        a_later_owner_hash_block_refuses_an_answered_ask(&host).await;
        a_refused_ask_stays_refused_across_two_hubs(&host).await;
        an_admit_naming_another_digest_is_refused_unscored(&host).await;
        assert_eq!(
            host.script.unexpected.load(Ordering::SeqCst),
            0,
            "the Big rung was asked only held-out replay scores"
        );
        host.finish().await;
    });
}

//! Shared fixture for the `vault.evals.authoring.execute` server tests: a
//! rooted vault served over the real facade router, its Coach seat on a
//! scripted local fake model, the shipped eval-authoring recipe installed,
//! one sealed case that gives the pass work, an owner credential and paired
//! agent credentials. Test-only.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::skill::{SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use oneiron::skill_optimize::{
    DerivationKind, EvalCaseDraft, EvalSeat, FamilyPurpose, eval_authoring_skill_id,
};
use oneiron::store::ports::ManualClock;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::fake_llm::{FakeLlm, Reply};

/// The verb under test and its result reader.
pub(crate) const VERB: &str = "vault.evals.authoring.execute";
pub(crate) const RESULT_VERB: &str = "vault.evals.authoring.result";
/// The Coach host queue's lease owner and budget line
/// (`ai_host/coach_heal.rs:67`, `ai_host/coach_host.rs:96`).
pub(crate) const COACH_HOST: &str = "coach.host";
/// The facet of the eval-authoring job (`oneiron/src/claim/maintenance_kind.rs:13`).
pub(crate) const EVAL_AUTHORING_FACET: &str = "coach.eval_authoring";

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
pub(crate) struct Agent {
    pub(crate) principal: EntityId,
    pub(crate) holder: SigningKey,
    pub(crate) slip: CapabilitySlip,
    pub(crate) token: String,
}

pub(crate) struct Fixture {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) vault: Arc<Vault>,
    pub(crate) server: Arc<SyncServer>,
    pub(crate) host: AiHost,
    pub(crate) app: Router,
    pub(crate) issuer: HostSlipIssuer,
    pub(crate) owner_slip: CapabilitySlip,
    pub(crate) owner_token: String,
    pub(crate) model: FakeLlm,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A model plan that decides nothing for the inventory in the request: the
/// user message is the inventory's JSON; the answer echoes its digest.
pub(crate) fn echo_plan() -> Reply {
    Reply::Computed(Arc::new(|request: &Value| {
        let inventory = request["messages"]
            .as_array()
            .and_then(|messages| messages.last())
            .and_then(|message| message["content"].as_str())
            .unwrap_or_default();
        let digest = serde_json::from_str::<Value>(inventory)
            .ok()
            .and_then(|value| value["inventory_digest"].as_str().map(str::to_owned))
            .unwrap_or_default();
        json!({ "inventory_digest": digest }).to_string()
    }))
}

/// An answer holding no JSON object: `parse_plan` returns `None`.
pub(crate) fn answer_without_plan() -> Reply {
    Reply::text("There is nothing I can decide for this inventory.")
}

fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

/// The shipped eval-authoring recipe through the offline door: the record
/// (Generated, Approved) and its native package in one writer, then
/// activated. The id is the fixed one the Coach pass loads.
pub(crate) fn install_eval_authoring_recipe(vault: &Vault) {
    let id = eval_authoring_skill_id().expect("eval-authoring skill id");
    let files = vec![HubFile::new(
        "SKILL.md",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../skills/eval-authoring/SKILL.md"
        ))
        .to_vec(),
    )];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("canonical skill tree hash");
    let record = SkillRecord::new(
        "eval-authoring",
        "Keep each model seat's eval set from the vault's own history, deciding purposes for new source groups, cases, date cuts and retirements.",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(SkillRole::Workflow, None)
    .with_content_hash(hash);
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    oneiron::test_doors::callable_skill::put_skill_record_and_package(
        vault,
        &id,
        &record,
        &package,
        TimeRange { start: 1, end: 1 },
        1,
    )
    .expect("persist the eval-authoring recipe");
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &active, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the eval-authoring recipe");
}

/// One sealed family holding one case no cohort holds: the inventory then
/// has work (an uncut family older than the pass), so the pass calls the model.
pub(crate) fn add_unheld_sealed_case(vault: &Vault) {
    let at = vault.now_recorded_at();
    let seat = EvalSeat::Companion;
    let root = "fixture-source:execute-served".to_owned();
    vault
        .assign_eval_family(
            &seat,
            &BTreeSet::from([root.clone()]),
            FamilyPurpose::SealedConfirmation,
            at,
        )
        .expect("assign the sealed family");
    vault
        .record_eval_case(
            &EvalCaseDraft {
                seat,
                kind: DerivationKind::Receipt,
                receipts: vec![root],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at: at - 86_400,
            },
            at,
        )
        .expect("record the sealed case");
}

/// The `coach.host` budget line after a settled lease: nothing reserved,
/// nothing overdrawn, the whole total remaining.
pub(crate) fn assert_budget_settled(vault: &Vault) {
    let line = DreamerRunnerStore::new(vault)
        .budget(COACH_HOST)
        .expect("read the budget line")
        .expect("the lease created the budget line");
    assert_eq!(line.reserved_units, 0, "nothing stays reserved: {line:?}");
    assert_eq!(line.overdraft_units, 0, "nothing overdrawn: {line:?}");
    assert_eq!(
        line.remaining_units, line.total_units,
        "all returned: {line:?}"
    );
}

/// No Coach eval-authoring job is queued: the Coach queue admits nothing, or
/// only a job of another facet. (The probe leases what it admits.)
pub(crate) fn assert_no_eval_authoring_job_queued(vault: &Vault) {
    let queued = DreamerRunnerStore::new(vault)
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now: vault.now_recorded_at(),
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })
        .expect("the Coach queue admits");
    match queued {
        DreamerAdmissionOutcome::Empty => {}
        DreamerAdmissionOutcome::Admitted(other) => assert_ne!(
            other.status.payload.attempt_type, EVAL_AUTHORING_FACET,
            "a refused request queued an eval-authoring job"
        ),
        other => panic!("the Coach queue answered {other:?}"),
    }
}

impl Fixture {
    /// `clock`: a manual vault clock (cases 4 and 5), else the real one.
    /// `script`/`fallback`: the fake model's replies.
    pub(crate) async fn new(
        clock: Option<Arc<ManualClock>>,
        script: Vec<Reply>,
        fallback: Option<Reply>,
    ) -> Self {
        let model = FakeLlm::start(script, fallback).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let mut config = VaultConfig::device();
        if let Some(clock) = &clock {
            config.store_clock = clock.bundle();
        }
        let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("eval-authoring-execute-server".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        install_eval_authoring_recipe(&vault);
        add_unheld_sealed_case(&vault);
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let server = Arc::new(server);
        let app = build_app(Arc::clone(&server));
        Self {
            _dir: dir,
            vault,
            server,
            host,
            app,
            issuer,
            owner_slip,
            owner_token,
            model,
        }
    }

    pub(crate) async fn finish(self) {
        self.host.shutdown().await;
    }

    /// Fake-model requests that carry the shipped skill body as their
    /// System message: the eval-authoring pass's own calls.
    pub(crate) fn eval_authoring_calls(&self) -> usize {
        self.model
            .seen()
            .iter()
            .filter(|call| {
                call.body["messages"][0]
                    .to_string()
                    .contains("# Eval authoring")
            })
            .count()
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn agent_binding(&self, agent: &Agent) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = agent
            .slip
            .binding_transcript(challenge.as_bytes())
            .expect("agent binding transcript");
        let signature: String = hex(&agent.holder.sign(&transcript).to_bytes());
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn post(
        &self,
        verb: &str,
        token: &str,
        binding: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("facade response body");
        // A refusal that is not JSON still shows its text in the assert message.
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    pub(crate) async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &self.owner_token, self.owner_binding(), body)
            .await
    }

    pub(crate) async fn as_agent(
        &self,
        agent: &Agent,
        verb: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.post(verb, &agent.token, self.agent_binding(agent), body)
            .await
    }

    /// The owner reads the kept result of `attempt` (hex).
    pub(crate) async fn result_of(&self, attempt: &str) -> Value {
        let (status, body) = self
            .as_owner(RESULT_VERB, json!({"attempt": attempt}))
            .await;
        assert_eq!(status, StatusCode::OK, "read the result: {body}");
        body
    }

    /// Pairs one agent the way `token agent` does (template
    /// `model_binding_proposer_grant.rs:153-233`).
    pub(crate) async fn pair_agent(&self, name: &str, seed: [u8; 32]) -> Agent {
        let principal = self
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&seed);
        let binding_key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &self.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(principal.to_hex()),
                    actor_class: Some("agent".to_owned()),
                    org_ref: None,
                    write_facet: None,
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
            .expect("pairing transcript");
        let signature: String = hex(&holder.sign(&transcript).to_bytes());
        let request = Request::post("/v1/core/pairing/redeem")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "code": link.code,
                    "holder_ref": principal.to_hex(),
                    "binding_key": hex(&binding_key),
                    "signature": signature,
                })
                .to_string(),
            ))
            .expect("pairing redeem request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("pairing redeem response");
        assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("pairing redeem body");
        let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
        let token = body["token"].as_str().expect("paired token").to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("paired slip");
        Agent {
            principal,
            holder,
            slip,
            token,
        }
    }

    /// The owner mints `agent` a Grant naming `read` and the verb; returns
    /// its grant ref.
    pub(crate) async fn mint_execute_grant(&self, agent_hex: &str) -> String {
        let (status, body) = self
            .as_owner(
                "vault.agents.grants.mint",
                json!({
                    "agent": agent_hex,
                    "authority_scope": {
                        "worlds": {"kind": "all"},
                        "facets": {"kind": "all"},
                        "bands": {"kind": "all"},
                        "audience": {"kind": "all"},
                        "verbs": {"kind": "some", "values": ["read", VERB]},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "mint the execute grant: {body}");
        assert_eq!(body["grant"]["agent"].as_str(), Some(agent_hex), "{body}");
        assert_eq!(body["grant"]["confers"].as_bool(), Some(true), "{body}");
        body["grant"]["grant_ref"]
            .as_str()
            .expect("minted grant ref")
            .to_owned()
    }
}

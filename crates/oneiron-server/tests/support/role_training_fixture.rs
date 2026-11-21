//! Shared fixture for the role-training run door tests (ROLE-TRAINING-RUN):
//! a rooted vault served over the real facade router, with a question
//! trainer connector and a role trainer named in its models file, an owner
//! credential and paired agent credentials. The role trainers run the tiny
//! pinned worker `role_trainer_worker.py` on this host's `python3`; the
//! scored one also names the tiny pinned scorer `role_trainer_scorer.py`.
//! `seed_role_run` lays out one role run's inputs: a training
//! pair in a development family, a held-out pair in a sealed family with its
//! labelled case, a cohort cut for the seat, the reservoir export's standing
//! disclosure grant and the owner's starting checkpoint in custody.
//! Test-only.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
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
use oneiron::consent::{AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound};
use oneiron::edit_distance::reservoir::{
    RESERVOIR_DISCLOSURE_CLASS, RESERVOIR_ENVELOPE_SELECTOR, RESERVOIR_EXPORT_AUDIENCE,
    amendment_receipt_id,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::manifest::{ModelBinding, ModelRole, ModelSlot};
use oneiron::skill_optimize::{
    CutDecision, DerivationKind, EvalCaseDraft, EvalCohortSetup, EvalLabel, EvalLabelKind,
    EvalSeat, FamilyPurpose, eval_authoring_inventory, setup_eval_cohorts,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::training_corpus::keep_amended_pair;
use oneiron::training_pack::{
    CheckpointFileKind, CheckpointFileUpload, CheckpointUpload, ComputeChoice, ProbeCase,
    SourcePin, SplitPolicy, TrainingPackDraft, TrainingPlan, TrainingTarget,
};
use oneiron::{EdgeActorClass, EntityId, ModelId, ModelTierRef, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::test_doors::lost_training_waiter::{self, LostWaiter};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::fake_llm::FakeLlm;

/// The verbs under test.
pub(crate) const PREPARE_VERB: &str = "vault.coach.training_runs.prepare";
pub(crate) const GET_VERB: &str = "vault.coach.training_runs.get";
/// The owner's authorization of a prepared spec, an existing owner route.
pub(crate) const AUTHORIZE_PATH: &str = "/v1/owner/coach/training-runs/authorize";
/// The question trainer connector the fixture's models file names: no role
/// run is ever trained on it.
pub(crate) const CONNECTOR: &str = "fixture-trainer";
/// The role trainer the fixture's models file names, with no scorer: its
/// returned runs hold with `training.no_evaluator`.
pub(crate) const ROLE_TRAINER: &str = "fixture-role-trainer";
/// The role trainer that also names the tiny pinned scorer, on the same
/// worker, recipe and jobs root.
pub(crate) const SCORED_ROLE_TRAINER: &str = "fixture-role-trainer-scored";
/// The one recipe the role trainer lists, and the seeded plan's.
pub(crate) const ROLE_RECIPE: &str = "fixture.role-adapter/1";
/// The execute verb.
pub(crate) const EXECUTE_VERB: &str = "vault.coach.training_runs.execute";
/// The tiny pinned role worker, written into each fixture's directory.
const ROLE_WORKER: &str = include_str!("role_trainer_worker.py");
/// The tiny pinned role scorer, written into each fixture's directory.
const ROLE_SCORER: &str = include_str!("role_trainer_scorer.py");

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
pub(crate) struct Agent {
    pub(crate) principal: EntityId,
    pub(crate) holder: SigningKey,
    pub(crate) slip: CapabilitySlip,
    pub(crate) token: String,
}

/// One role run's inputs: its draft as the wire carries it, and the two
/// amended pairs the reservoir holds for it.
pub(crate) struct SeededRun {
    pub(crate) draft: Value,
    pub(crate) training_pair: EntityId,
    pub(crate) held_out_pair: EntityId,
}

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
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

/// This host's `python3`, by an absolute path on `PATH`. A host without one
/// names the usual path, which only the role trainer cases run.
fn python3() -> std::path::PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join("python3"))
                .find(|path| path.is_absolute() && path.is_file())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/python3"))
}

/// Where the role trainer makes each run's job directory.
pub(crate) fn role_jobs_root(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("trainer").join("role-training-jobs")
}

fn models_text(base_url: &str, dir: &std::path::Path) -> String {
    // The question worker never runs in these tests; its paths only have to
    // be absolute.
    let path = |name: &str| dir.join("trainer").join(name).display().to_string();
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         [training.connectors.{CONNECTOR}]\npython = \"{python}\"\nworker = \"{worker}\"\n\
         jobs_root = \"{jobs}\"\nrevision = \"fixture-worker-r1\"\nunit_cost = 1\n\
         cost_unit = \"fixture-units\"\nservice_unit = \"gpu_wall_second\"\n\
         [training.role_trainers.{ROLE_TRAINER}]\npython = \"{python3}\"\n\
         worker = \"{role_worker}\"\njobs_root = \"{role_jobs}\"\n\
         revision = \"fixture-role-worker-r1\"\nunit_cost = 1\n\
         cost_unit = \"fixture-units\"\nservice_unit = \"gpu_wall_second\"\n\
         recipes = [\"{ROLE_RECIPE}\"]\n\
         [training.role_trainers.{SCORED_ROLE_TRAINER}]\npython = \"{python3}\"\n\
         worker = \"{role_worker}\"\njobs_root = \"{role_jobs}\"\n\
         revision = \"fixture-role-worker-r1\"\nunit_cost = 1\n\
         cost_unit = \"fixture-units\"\nservice_unit = \"gpu_wall_second\"\n\
         recipes = [\"{ROLE_RECIPE}\"]\nscorer = \"{role_scorer}\"\n",
        python = path("trainer-python"),
        worker = path("trainer-worker.py"),
        jobs = path("training-jobs"),
        python3 = python3().display(),
        role_worker = path("role_trainer_worker.py"),
        role_scorer = path("role_trainer_scorer.py"),
        role_jobs = role_jobs_root(dir).display(),
    )
}

fn source_pin() -> SourcePin {
    SourcePin {
        repository: "fixture/role-training".to_owned(),
        revision: "2222222222222222222222222222222222222222".to_owned(),
    }
}

fn checkpoint_upload(model: ModelId) -> CheckpointUpload {
    // Preparing checks byte custody only; no trainer or loader runs here.
    let bytes = b"role checkpoint custody fixture".to_vec();
    CheckpointUpload {
        model,
        files: vec![CheckpointFileUpload {
            name: "model.safetensors".to_owned(),
            kind: CheckpointFileKind::Weights,
            source: source_pin(),
            blake3: *blake3::hash(&bytes).as_bytes(),
            bytes,
        }],
    }
}

/// Lays out one Decision-head role run's inputs in `vault` (see the module
/// doc) and returns its draft.
pub(crate) fn seed_role_run(vault: &Vault) -> SeededRun {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let bound = GrantBound::disclosure(
        AudienceBound::singleton(RESERVOIR_EXPORT_AUDIENCE).expect("reservoir audience"),
        DisclosureClass::new(RESERVOIR_DISCLOSURE_CLASS).expect("reservoir class"),
        DisclosureEnvelope::new([RESERVOIR_ENVELOPE_SELECTOR.to_owned()])
            .expect("reservoir envelope"),
    )
    .expect("reservoir export bound");
    vault
        .create_standing_grant(&owner, bound)
        .expect("grant the reservoir export");

    let editor = WriteActor::new(actor, EdgeActorClass::Human);
    let training_pair = keep_amended_pair(
        vault,
        &editor,
        "Draft the weekly summary for owen.",
        "Draft the weekly summary for owen, open questions first.",
    )
    .expect("keep the training pair");
    let held_out_pair = keep_amended_pair(
        vault,
        &editor,
        "Reply to yuki about the venue.",
        "Reply to yuki about the venue and ask which date suits her.",
    )
    .expect("keep the held-out pair");

    let seat = EvalSeat::Decision;
    vault
        .assign_eval_family(
            &seat,
            &BTreeSet::from([amendment_receipt_id(training_pair)]),
            FamilyPurpose::Development,
            1,
        )
        .expect("assign the training family");
    let held_out_root = amendment_receipt_id(held_out_pair);
    vault
        .assign_eval_family(
            &seat,
            &BTreeSet::from([held_out_root.clone()]),
            FamilyPurpose::SealedConfirmation,
            1,
        )
        .expect("assign the sealed family");
    let case = vault
        .record_eval_case(
            &EvalCaseDraft {
                seat: seat.clone(),
                kind: DerivationKind::Receipt,
                receipts: vec![held_out_root],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at: 2,
            },
            2,
        )
        .expect("record the held-out case");
    vault
        .label_eval_case(
            &case.id,
            EvalLabel {
                kind: EvalLabelKind::AdjudicatedAudit,
                value: "yes".to_owned(),
                reference: "fixture/adjudication".to_owned(),
                weight: 1.0,
                at: 3,
                source_rows: None,
            },
        )
        .expect("label the held-out case");
    let inventory = eval_authoring_inventory(vault, 5).expect("eval inventory");
    let setup = setup_eval_cohorts(
        vault,
        &owner,
        EvalCohortSetup {
            inventory_at: 5,
            inventory_digest: inventory.inventory_digest,
            families: Vec::new(),
            cases: Vec::new(),
            cuts: vec![CutDecision {
                seat: seat.clone(),
                from: 0,
                until: 4,
                rubric_revision: "fixture/rubric-v1".to_owned(),
                reference: false,
            }],
        },
        5,
    )
    .expect("cut the held-out cohort");
    assert_eq!(setup.cohorts_cut.len(), 1, "{setup:?}");

    let starting_checkpoint = vault
        .keep_training_checkpoint(
            &owner,
            &checkpoint_upload(ModelId::new("local/decision-base@v1").expect("base model")),
        )
        .expect("keep the starting checkpoint");
    let draft = TrainingPackDraft {
        plan: TrainingPlan {
            target: TrainingTarget::Role {
                role: ModelRole::DecisionHead,
                output_binding: ModelBinding {
                    model: ModelId::new("local/decision-head-trained@v1").expect("output model"),
                    slot: ModelSlot::Llm,
                    tier: ModelTierRef("fixture".to_owned()),
                    route_models: BTreeMap::new(),
                    disposition: None,
                    reads_audio: false,
                },
            },
            seat,
            starting_checkpoint,
            purpose: "exercise the owner's role prepare with no offer".to_owned(),
            settings: json!({"fixture": true, "recipe": ROLE_RECIPE}),
            harness: source_pin(),
            probes: vec![ProbeCase {
                id: "fixture/probe".to_owned(),
                input: json!({"text": "Draft the weekly summary."}),
            }],
            export_logit_tolerance: 0.001,
        },
        split: SplitPolicy {
            held_out_cohort: setup.cohorts_cut[0],
        },
        compute: ComputeChoice::OwnerMachines,
        quantity: 1,
        consented_sources: Vec::new(),
    };
    SeededRun {
        draft: serde_json::to_value(&draft).expect("draft JSON"),
        training_pair,
        held_out_pair,
    }
}

impl Fixture {
    pub(crate) async fn new() -> Self {
        let model = FakeLlm::start(Vec::new(), None).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("role-training-run-doors".into()),
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
        let trainer_dir = dir.path().join("trainer");
        std::fs::create_dir_all(&trainer_dir).expect("trainer directory");
        std::fs::write(trainer_dir.join("role_trainer_worker.py"), ROLE_WORKER)
            .expect("write the role worker");
        std::fs::write(trainer_dir.join("role_trainer_scorer.py"), ROLE_SCORER)
            .expect("write the role scorer");
        let models = ModelsConfig::from_toml(&models_text(&model.base_url, dir.path()), None)
            .expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let server = Arc::new(server);
        let app = build_app(Arc::clone(&server));
        Self {
            dir,
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
        path: &str,
        token: &str,
        binding: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        // A refusal that is not JSON still shows its text in the assert message.
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    pub(crate) async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        let path = format!("/v1/core/facade/{verb}");
        self.post(&path, &self.owner_token, self.owner_binding(), body)
            .await
    }

    pub(crate) async fn as_agent(
        &self,
        agent: &Agent,
        verb: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let path = format!("/v1/core/facade/{verb}");
        self.post(&path, &agent.token, self.agent_binding(agent), body)
            .await
    }

    /// The owner's yes on the prepared `run` (hex) at `spec` (hex), through
    /// the existing owner route.
    pub(crate) async fn authorize(&self, run: &str, spec: &str) -> (StatusCode, Value) {
        self.post(
            AUTHORIZE_PATH,
            &self.owner_token,
            self.owner_binding(),
            json!({"run": run, "spec": spec}),
        )
        .await
    }

    /// One Coach host round, the worker unit that dispatches an authorized
    /// run, off the test's async thread.
    pub(crate) async fn coach_round(&self) {
        let server = Arc::clone(&self.server);
        tokio::task::spawn_blocking(move || {
            oneiron_server::test_doors::coach_round::coach_host_round(&server)
        })
        .await
        .expect("coach round thread")
        .expect("coach round");
    }

    /// Dispatches the authorized `run` (hex) on a waiter that records
    /// nothing until it rejoins, as after a host restart, off the test's
    /// async thread; returns once the run is sent to the role trainer.
    pub(crate) async fn dispatch_with_lost_waiter(&self, run: &str) -> LostWaiter {
        let server = Arc::clone(&self.server);
        let run = EntityId::from_hex(run).expect("run hex");
        tokio::task::spawn_blocking(move || {
            lost_training_waiter::dispatch_with_lost_waiter(&server, &run)
        })
        .await
        .expect("dispatch thread")
        .expect("dispatch with a lost waiter")
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

    /// The owner mints `agent` a Grant naming `read` and `verbs`; returns its
    /// grant ref.
    pub(crate) async fn mint_grant(&self, agent_hex: &str, verbs: &[&str]) -> String {
        let mut values = vec!["read"];
        values.extend_from_slice(verbs);
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
                        "verbs": {"kind": "some", "values": values},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "mint the grant: {body}");
        assert_eq!(body["grant"]["confers"].as_bool(), Some(true), "{body}");
        body["grant"]["grant_ref"]
            .as_str()
            .expect("minted grant ref")
            .to_owned()
    }
}

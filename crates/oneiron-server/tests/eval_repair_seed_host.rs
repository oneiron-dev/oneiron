//! The measuring host's repair-seed job (census L1-20 PR D): a Pending seed's
//! old and candidate arms answer the released task on the fake model, and the
//! gate confirms the seed when the old answer fails and the candidate's passes,
//! with the host's `eval_repair_seed:<key>:old|candidate:<handle>` receipts,
//! each naming the stored answer the gate graded by its content; a seed whose
//! model this host does not serve stays Pending and the model sees no call; a
//! measurement over a confirmed seed's Repair case scores exactly in fixed code,
//! with no judge call.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! eval_repair_seed_host`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeMap;
use std::sync::Arc;

use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::MachineRole;
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::llm::registry::{
    ModelBackendPin, ModelRegistryRow, ModelWireFormat, PricedModelBackend,
};
use oneiron::llm::{LlmCatalogCost, LlmCatalogEntry, ModelId, ModelLocality};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use oneiron::skill_optimize::{
    CutDecision, EvalArmPin, EvalAxisPin, EvalCohortSetup, EvalMeasurementRequest,
    EvalRepairLegAnswer, EvalRepairSeedLegs, EvalRepairSeedRequest, EvalRepairSeedState,
    EvalRepairTaskSource, EvalSeat, FloorSlicePolicy, HeldOutReplayNotes, MeasurementMethodPin,
    ScoreDirection, eval_authoring_inventory, setup_eval_cohorts,
};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};

/// The answer the person's repair gave, which the app observed.
const ANSWER: &str = "fixed answer";
/// The model the fixture's config serves, and the revision its registry row
/// pins: the arms of a served seed name both.
const SERVED_MODEL: &str = "local/test-model@live";
const SERVED_REVISION: &str = "live";
/// A model the router serves nothing of.
const UNSERVED_MODEL: &str = "local/unserved-model@live";
/// The rubric revision the measurement cohort is cut under.
const RUBRIC: &str = "fixture-rubric";

/// The old skill's body, as its leg's system message holds it.
const OLD_BODY: &str = "The old skill under test drafts delivery plans.";
/// The candidate skill's body.
const CANDIDATE_BODY: &str = "The candidate skill under test drafts delivery plans well.";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    host: AiHost,
    owner: EntityId,
    proof: AuthenticatedOwner,
    project: EntityId,
    model: FakeLlm,
}

fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

fn mapping(name: &str, kind: AgUiObservationKind) -> AgUiCustomMapping {
    AgUiCustomMapping {
        name: name.to_owned(),
        kind,
        id: Some("/value/id".to_owned()),
        thread_id: Some("/value/threadId".to_owned()),
        run_id: Some("/value/runId".to_owned()),
        tool_call_id: None,
        failure_id: None,
        repair_id: None,
        outcome: None,
    }
}

fn mappings() -> Vec<AgUiCustomMapping> {
    let failure = mapping("desk.failure", AgUiObservationKind::Failure);
    let repair = AgUiCustomMapping {
        failure_id: Some("/value/failureId".to_owned()),
        ..mapping("desk.repair", AgUiObservationKind::Repair)
    };
    let outcome = AgUiCustomMapping {
        repair_id: Some("/value/repairId".to_owned()),
        outcome: Some("/value/result".to_owned()),
        ..mapping("desk.outcome", AgUiObservationKind::Outcome)
    };
    vec![failure, repair, outcome]
}

/// A text-response task contract over `initial_state`, graded by the
/// observed outcome's `response`.
fn text_task(initial_state: Value) -> Value {
    json!({
        "world": "text_response",
        "initial_state": initial_state,
        "preconditions": [],
        "intent": "Answer the customer with the delivery plan.",
        "input": { "history": [{ "role": "user", "text": "Where does my parcel go?" }] },
        "tools": [],
        "allowed_actions": ["respond"],
        "grader": { "kind": "observed_response_equals", "pointer": "/response" },
    })
}

fn clean_state() -> Value {
    json!({ "orders": [{ "id": "A-1", "city": "Lyon", "status": "packed" }] })
}

/// Captures one failure carrying `task`, the person's repair and the app's
/// observed outcome `result`, and names that task as the outcome's source on
/// the companion seat.
fn capture(
    fixture: &Fixture,
    task: Value,
    result: Value,
) -> Result<EvalRepairTaskSource, Box<dyn std::error::Error>> {
    let events = [
        json!({
            "type": "CUSTOM",
            "name": "desk.failure",
            "value": { "id": "f-1", "threadId": "t-1", "runId": "r-1", "task": task },
        }),
        json!({
            "type": "CUSTOM",
            "name": "desk.repair",
            "value": { "id": "p-1", "threadId": "t-1", "runId": "r-1", "failureId": "f-1" },
        }),
        json!({
            "type": "CUSTOM",
            "name": "desk.outcome",
            "value": {
                "id": "o-1",
                "threadId": "t-1",
                "runId": "r-1",
                "repairId": "p-1",
                "result": result,
            },
        }),
    ];
    let jsonl = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let receipt = fixture.vault.ingest_ag_ui_file(
        &fixture.proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: fixture.project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings: mappings(),
            jsonl,
        },
    )?;
    assert_eq!(receipt.event_count, 3);
    Ok(EvalRepairTaskSource {
        claim_ref: receipt.claim_ref,
        source_hash: receipt.source_hash,
        outcome_ordinal: 2,
        task_pointer: "/value/task".to_owned(),
        seat: EvalSeat::Companion,
    })
}

/// A priced registry row for `model`, served by one backend at `revision`.
fn registry_row(model: &ModelId, revision: &str) -> ModelRegistryRow {
    let priced = PricedModelBackend {
        pin: ModelBackendPin {
            model: model.clone(),
            backend: "fixture-backend".to_owned(),
            serving_revision: revision.to_owned(),
            quantization: None,
            context_window_tokens: 4096,
        },
        price: LlmCatalogCost {
            input_per_million: "0".to_owned(),
            output_per_million: "0".to_owned(),
            cache_read_per_million: None,
            cache_write_per_million: None,
            currency: None,
        },
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "backends".to_owned(),
        serde_json::to_value(vec![&priced]).expect("backends JSON"),
    );
    ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::Local,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: model.as_str().to_owned(),
            locality: ModelLocality::OnDevice,
            context_window_tokens: 4096,
            max_output_tokens: None,
            cost: Some(priced.price.clone()),
            capabilities: Vec::new(),
            metadata,
        },
        scores: Default::default(),
        fetched_at: Default::default(),
        tokens_per_o200k: None,
        answer_tokens_per_o200k: None,
        stale_since: None,
        source_rows: None,
    }
}

/// Stores one active approved SKILL.md revision of `name` with `body` as its
/// text, and answers its id with its content-hash hex. Active and approved,
/// so the measuring host loads it through the pinned-pack load.
fn put_skill(
    vault: &Vault,
    name: &str,
    version: &str,
    body: &str,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    let markdown = format!(
        "---\nname: {name}\ndescription: {name} fixture\nversion: {version}\n---\n{body}\n"
    );
    let files = vec![HubFile::new("SKILL.md", markdown.into_bytes())];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        name,
        format!("{name} fixture"),
        version,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Active,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
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
    )?;
    Ok((id, hash.to_hex()))
}

impl Fixture {
    /// A rooted vault served by a host whose seats run on the fake model,
    /// answering `script` in order, then `fallback`.
    async fn new(script: Vec<Reply>, fallback: Option<Reply>) -> Self {
        let model = FakeLlm::start(script, fallback).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("eval-repair-seed-host".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let _ = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let project = vault.root_project().expect("root project");
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Self {
            _dir: dir,
            vault,
            server: Arc::new(server),
            host,
            owner,
            proof,
            project,
            model,
        }
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }

    /// One Coach host round, as the nightly worker runs it.
    async fn coach_round(&self) {
        let server = Arc::clone(&self.server);
        tokio::task::spawn_blocking(move || {
            oneiron_server::test_doors::coach_round::coach_host_round(&server)
        })
        .await
        .expect("the round thread")
        .expect("the Coach round");
    }

    /// Pins every role to the served model and registers its row, as an
    /// owner pins one.
    fn pin_served_model(&self) {
        let model = ModelId::new(SERVED_MODEL).expect("model id");
        oneiron_server::test_doors::replay_admission::pin_every_role(
            &self.vault,
            &model,
            ModelLocality::OwnServer,
        )
        .expect("the owner's manifest pin");
        self.vault
            .put_model_registry_row(&registry_row(&model, SERVED_REVISION))
            .expect("the registry row");
    }
}

#[test]
fn measuring_host_settles_pending_repair_seed() {
    run_on_engine_stack("repair-seed-settles", || async {
        let fixture = Fixture::new(
            vec![Reply::text("wrong answer"), Reply::text("fixed answer")],
            None,
        )
        .await;
        fixture.pin_served_model();
        let (_old, old_hex) =
            put_skill(&fixture.vault, "fixture.old", "1", OLD_BODY).expect("the old skill");
        let (_candidate, candidate_hex) =
            put_skill(&fixture.vault, "fixture.candidate", "1", CANDIDATE_BODY)
                .expect("the candidate skill");
        let source = capture(
            &fixture,
            text_task(clean_state()),
            json!({ "response": ANSWER }),
        )
        .expect("the capture");
        let at = fixture.vault.now_recorded_at();
        let request = EvalRepairSeedRequest {
            source: source.clone(),
            old: EvalArmPin {
                model: SERVED_MODEL.to_owned(),
                revision: SERVED_REVISION.to_owned(),
                skill_digest: Some(old_hex),
            },
            candidate: EvalArmPin {
                model: SERVED_MODEL.to_owned(),
                revision: SERVED_REVISION.to_owned(),
                skill_digest: Some(candidate_hex),
            },
        };
        let read = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .propose_eval_repair_seed(&request, at)
            .expect("propose the seed");
        assert!(
            matches!(
                read.seed.as_ref().map(|seed| &seed.state),
                Some(EvalRepairSeedState::Pending)
            ),
            "the seed proposes Pending"
        );

        fixture.coach_round().await;

        let seed = fixture
            .vault
            .eval_repair_seed(&source)
            .expect("read the seed")
            .expect("the seed stands");
        let EvalRepairSeedState::Confirmed {
            old_receipt,
            candidate_receipt,
            ..
        } = &seed.state
        else {
            panic!("the gate confirms the seed: {:?}", seed.state);
        };
        let (old_key, old_handle) = old_receipt
            .strip_prefix("eval_repair_seed:")
            .expect("the old receipt names the seed")
            .split_once(":old:")
            .expect("the old receipt names its leg");
        let (candidate_key, candidate_handle) = candidate_receipt
            .strip_prefix("eval_repair_seed:")
            .expect("the candidate receipt names the seed")
            .split_once(":candidate:")
            .expect("the candidate receipt names its leg");
        assert_eq!(old_key, candidate_key, "both legs name the seed key");
        // Each receipt names the stored answer the gate graded, by content.
        for (handle, answer) in [(old_handle, "wrong answer"), (candidate_handle, ANSWER)] {
            let output = oneiron::compaction::output::OutputRef::from_handle(handle)
                .expect("the receipt names a stored answer's handle");
            assert_eq!(
                output.hash,
                *blake3::hash(answer.as_bytes()).as_bytes(),
                "the receipt names the answer the leg gave"
            );
            assert_eq!(output.byte_len, answer.len() as u64);
        }
        assert_eq!(old_key.len(), 64, "the key is 32 bytes as hex");
        assert!(
            old_key.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the key is hex: {old_key}"
        );

        // Exactly two model calls, the old leg first: the script answers by
        // call order, so the order is the verdict.
        let seen = fixture.model.seen();
        assert_eq!(seen.len(), 2, "one call per leg");
        for call in &seen {
            assert_eq!(call.path, "/v1/chat/completions");
            for message in call.body["messages"].as_array().expect("messages") {
                let content = message["content"].as_str().expect("text content");
                assert!(
                    !content.contains(ANSWER),
                    "no leg is shown the expected answer"
                );
            }
        }
        assert!(
            seen[0].body["messages"][0]["content"]
                .as_str()
                .expect("the old system message")
                .contains(OLD_BODY),
            "the old leg runs first"
        );
        assert!(
            seen[1].body["messages"][0]["content"]
                .as_str()
                .expect("the candidate system message")
                .contains(CANDIDATE_BODY),
            "the candidate leg runs second"
        );
        fixture.finish().await;
    });
}

#[test]
fn measuring_host_leaves_an_unserved_seed_pending() {
    run_on_engine_stack("repair-seed-unserved", || async {
        let fixture = Fixture::new(vec![], None).await;
        let model = ModelId::new(UNSERVED_MODEL).expect("model id");
        fixture
            .vault
            .put_model_registry_row(&registry_row(&model, SERVED_REVISION))
            .expect("the registry row");
        let source = capture(
            &fixture,
            text_task(clean_state()),
            json!({ "response": ANSWER }),
        )
        .expect("the capture");
        let at = fixture.vault.now_recorded_at();
        let request = EvalRepairSeedRequest {
            source: source.clone(),
            old: EvalArmPin {
                model: UNSERVED_MODEL.to_owned(),
                revision: SERVED_REVISION.to_owned(),
                skill_digest: Some("old-skill-digest".to_owned()),
            },
            candidate: EvalArmPin {
                model: UNSERVED_MODEL.to_owned(),
                revision: SERVED_REVISION.to_owned(),
                skill_digest: Some("candidate-skill-digest".to_owned()),
            },
        };
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .propose_eval_repair_seed(&request, at)
            .expect("propose the seed");

        fixture.coach_round().await;

        let seed = fixture
            .vault
            .eval_repair_seed(&source)
            .expect("read the seed")
            .expect("the seed stands");
        assert_eq!(seed.state, EvalRepairSeedState::Pending);
        assert!(
            fixture.model.seen().is_empty(),
            "an unserved seed spends no model call"
        );
        fixture.finish().await;
    });
}

#[test]
fn a_repair_measurement_scores_exactly_with_no_judge_call() {
    run_on_engine_stack("repair-measurement-exact", || async {
        let fixture = Fixture::new(
            vec![
                Reply::text("wrong answer"),
                Reply::text("fixed answer"),
                Reply::text("wrong answer"),
            ],
            None,
        )
        .await;
        fixture.pin_served_model();
        let (_old, old_hex) =
            put_skill(&fixture.vault, "fixture.old", "1", OLD_BODY).expect("the old skill");
        let (_candidate, candidate_hex) =
            put_skill(&fixture.vault, "fixture.candidate", "1", CANDIDATE_BODY)
                .expect("the candidate skill");
        oneiron_server::replay_judge::register(&fixture.server, None);
        let scorer = oneiron_server::replay_judge::registered()
            .expect("the judge registers")
            .judge_revision()
            .to_owned();

        // Confirm a seed by its owner's own answers, backdated so the cohort
        // cut below covers its case.
        let source = capture(
            &fixture,
            text_task(clean_state()),
            json!({ "response": ANSWER }),
        )
        .expect("the capture");
        let at = fixture.vault.now_recorded_at().saturating_sub(100);
        let arms = |digest: String| EvalArmPin {
            model: SERVED_MODEL.to_owned(),
            revision: SERVED_REVISION.to_owned(),
            skill_digest: Some(digest),
        };
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .propose_eval_repair_seed(
                &EvalRepairSeedRequest {
                    source: source.clone(),
                    old: arms(old_hex.clone()),
                    candidate: arms(candidate_hex.clone()),
                },
                at,
            )
            .expect("propose the seed");
        let settled = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .settle_eval_repair_seed(
                &source,
                &EvalRepairLegAnswer::Response("wrong answer".to_owned()),
                &EvalRepairLegAnswer::Response(ANSWER.to_owned()),
                &EvalRepairSeedLegs {
                    old_receipt: "attempt:old-leg".to_owned(),
                    candidate_receipt: "attempt:candidate-leg".to_owned(),
                },
                at,
            )
            .expect("settle the seed")
            .seed
            .expect("the owner reads their capture");
        let EvalRepairSeedState::Confirmed { case, .. } = &settled.state else {
            panic!("the gate confirms the seed: {:?}", settled.state);
        };

        // Cut a cohort over the seed's family.
        let now = fixture.vault.now_recorded_at();
        let inventory = eval_authoring_inventory(&fixture.vault, now).expect("inventory");
        let report = setup_eval_cohorts(
            &fixture.vault,
            &fixture.proof,
            EvalCohortSetup {
                inventory_at: now,
                inventory_digest: inventory.inventory_digest,
                families: Vec::new(),
                cases: Vec::new(),
                cuts: vec![CutDecision {
                    seat: EvalSeat::Companion,
                    from: at.saturating_sub(3_600),
                    until: now,
                    rubric_revision: RUBRIC.to_owned(),
                    reference: false,
                }],
            },
            now,
        )
        .expect("cut the cohort");
        assert_eq!(report.cohorts_cut.len(), 1, "one cohort cut: {report:?}");
        let cohort = fixture
            .vault
            .eval_cohorts(&EvalSeat::Companion)
            .expect("the seat's cohorts")
            .into_iter()
            .find(|row| row.id == report.cohorts_cut[0])
            .expect("the cut cohort");
        assert!(
            cohort.cases.contains(case),
            "the cohort holds the Repair case"
        );

        // Request a measurement over it and run one round.
        let digest = fixture
            .vault
            .request_eval_measurement(
                &EvalMeasurementRequest {
                    decision: "fixture-decision".to_owned(),
                    seat: EvalSeat::Companion,
                    incumbent: arms(old_hex),
                    candidate: arms(candidate_hex),
                    requested_offers: None,
                    cohort: cohort.id,
                    membership_digest: cohort.membership_digest.clone(),
                    rubric_revision: cohort.rubric_revision.clone(),
                    scorer,
                    axis: EvalAxisPin {
                        axis: "fixture-axis".to_owned(),
                        direction: ScoreDirection::HigherIsBetter,
                        units: "score".to_owned(),
                    },
                    floor_slices: FloorSlicePolicy::default(),
                    canary: None,
                    method: MeasurementMethodPin::current(),
                    retry: 0,
                },
                fixture.vault.now_recorded_at(),
            )
            .expect("request the measurement");

        fixture.coach_round().await;

        let row = fixture
            .vault
            .eval_measurement(&digest)
            .expect("read the measurement")
            .expect("the row stands");
        assert_eq!(row.cases.len(), 1, "one case measured: {row:?}");
        let measured = &row.cases[0];
        assert_eq!(measured.case, *case);
        assert_eq!(measured.incumbent.score, Some(0.0), "{measured:?}");
        assert_eq!(measured.incumbent.judge, None, "{measured:?}");
        assert!(measured.incumbent.unavailable.is_none(), "{measured:?}");
        assert_eq!(measured.candidate.score, Some(1.0), "{measured:?}");
        assert_eq!(measured.candidate.judge, None, "{measured:?}");
        assert!(measured.candidate.unavailable.is_none(), "{measured:?}");
        assert_eq!(measured.retest.score, Some(0.0), "{measured:?}");
        assert_eq!(
            fixture.model.seen().len(),
            3,
            "the three legs and no judge call"
        );
        fixture.finish().await;
    });
}

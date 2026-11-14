//! The output archive's judge (ARM05 P3; ARCH-0053 #output-archive: an
//! output's cell is a typed judgment over the pinned axes and its score the
//! campaign's ruler; RULING ARCHIVE-QUALITY-RULER, 13 Nov 22:47). The
//! campaign's controller asks `research_archive_judge` for one output
//! revision; a scripted host stands in for the decision ladder on the
//! caller's line and for the embedder. Answers made at the band's high mark
//! with no person asked give the placement and score records that
//! `vault.research.archive.record` accepts. An abstain, a person ask, an
//! uncertain answer or a ladder fault records nothing and is refused with its
//! reason, a non-controller is refused before any question, the score reads
//! the rubric of the judge the pin names, and an embedding-cluster campaign
//! is placed by its pinned on-device embedder with no model judgment.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_judge`.
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::authority::MachineRole;
use oneiron::autoreason_campaign::archive::{
    ArchiveAxesMethod, ArchiveAxesMint, ArchiveAxis, ArchiveCell, ArchiveDescriptor,
    ArchiveJudgeAsk, ArchiveJudgeHost, ArchiveJudgeQuestion, ArchiveOutputRef,
    ArchiveQualityMetric, CampaignArchiveInstall, CampaignArchiveJudge, CampaignArchiveJudged,
    CampaignArchiveOutput, CampaignArchivePlacement, CampaignArchiveView, mint_archive_axes,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionReceipt, DecisionRung, HumanAskReason, ProviderPin,
    TypedDecision,
};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::archive_producers::archive_producer_records;
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{research_archive_install, research_archive_judge, research_archive_record};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The scripted embedder's space id.
const EMBEDDER_SPACE: &str = "fixture/embedder@r1";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    project: EntityId,
    goal_ref: EntityId,
    agent: EntityId,
    ruler: ArchiveQualityMetric,
}

/// A rooted vault (the five-step install, as `verb_vault_research_create_root`
/// opens it), the owner's authenticated root-project goal, the root's agent and
/// the seeded judge's ruler.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof: AuthenticatedOwner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("the owner's goal");
    let goal_ref = EntityId::from_hex(
        vault
            .project(project)
            .expect("project read")
            .expect("root project")
            .goal
            .as_deref()
            .expect("goal claim pointer"),
    )
    .expect("goal claim id");
    let agent = define_agent(&vault, "archive-judge-target").expect("the root's agent");
    let ruler = judge_ruler(&vault);
    Fixture {
        vault,
        _dir: dir,
        owner,
        project,
        goal_ref,
        agent,
        ruler,
    }
}

/// The seeded judge skill at its stored package's canonical tree hash.
fn judge_ruler(vault: &Vault) -> ArchiveQualityMetric {
    let rubric = oneiron::skill_optimize::judge_rubric(vault)
        .expect("judge rubric read")
        .expect("a fresh vault seeds the judge");
    let record = vault
        .get_skill_record(&rubric.skill)
        .expect("judge record read")
        .expect("judge record");
    ArchiveQualityMetric {
        metric_id: rubric.skill.to_hex(),
        revision: record
            .content_hash
            .expect("the seeded judge names its package")
            .to_hex(),
    }
}

fn owner_memory(f: &Fixture) -> Memory<'_> {
    f.vault.memory(f.owner, EdgeActorClass::Human)
}

/// A config campaign over a fresh root, as `verb_vault_research_create_root`
/// binds one, under `campaign_id`.
fn bound_root(f: &Fixture, campaign_id: &str) -> EntityId {
    let owner = owner_memory(f);
    let created = invoke(
        &owner,
        "vault.research.create_root",
        json!({
            "agent": f.agent.to_hex(),
            "intent_key": campaign_id,
            "briefing": "Search the parameter axis for a better quality score.",
        }),
    )
    .expect("the owner creates a root");
    let root_hex = created["root"].as_str().expect("root").to_owned();
    let incumbent: &[u8] = br#"{"parameter":"baseline"}"#;
    let digest: String = Sha256::digest(incumbent)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    invoke(
        &owner,
        "vault.research.bind",
        json!({
            "root": root_hex,
            "config": {
                "campaign_id": campaign_id,
                "search_axes": [{ "name": "parameter", "values": ["baseline", "alternative"] }],
                "metric_set": {
                    "set_id": "fixture-quality",
                    "revision": "r1",
                    "axes": [{ "name": "quality", "direction": "higher", "role": "primary" }],
                },
                "splits": {
                    "search": { "dataset_id": "fixture-search", "revision": "r1" },
                    "held_out": { "dataset_id": "fixture-held-out", "revision": "r1" },
                    "sealed": { "dataset_id": "fixture-sealed", "revision": "r1" },
                },
                "budget": { "budget_id": "fixture-lease", "max_units": 100, "exploration_units": 10 },
                "decide": { "kind": "dominance" },
            },
            "target": { "config": { "subject": campaign_id } },
            "holder": null,
            "confirmation": null,
            "share": null,
            "incumbent": { "config_ref": "fixture-config:baseline", "config_sha256": digest },
            "prior_ladder": [],
            "execution": null,
        }),
    )
    .expect("the owner binds the root");
    EntityId::from_hex(&root_hex).expect("root id")
}

fn task(f: &Fixture, summary: &str) -> EntityId {
    let receipt = invoke(
        &owner_memory(f),
        "tasks.create",
        json!({
            "spec": { "summary": summary },
            "assignee": { "child": { "actor_ref": f.agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    serde_json::from_value(receipt["task_ref"].clone()).expect("task id")
}

/// An owner-uploaded ARTIFACT at its first retained version's content hash.
fn artifact(f: &Fixture, name: &str, body: &str) -> ArchiveOutputRef {
    let view: Value = invoke(
        &owner_memory(f),
        "vault.artifacts.create",
        json!({
            "name": name,
            "media_type": "text/plain",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        }),
    )
    .expect("the owner uploads an artifact");
    ArchiveOutputRef {
        entity: serde_json::from_value(view["artifact_id"].clone()).expect("artifact id"),
        revision: view["versions"][0]["content_hash"]
            .as_str()
            .expect("version hash")
            .to_owned(),
    }
}

fn two_axes() -> ArchiveDescriptor {
    ArchiveDescriptor::Axes {
        axes: vec![
            ArchiveAxis {
                name: "tone".into(),
                bins: vec!["formal".into(), "casual".into()],
            },
            ArchiveAxis {
                name: "length".into(),
                bins: vec!["short".into(), "long".into()],
            },
        ],
    }
}

fn two_clusters() -> ArchiveDescriptor {
    ArchiveDescriptor::EmbeddingClusters {
        model_revision: EMBEDDER_SPACE.into(),
        centers: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
    }
}

/// A campaign whose archive is installed from the engine's own axes record,
/// and one output to judge.
struct Campaign {
    root: EntityId,
    revision: String,
    output: ArchiveOutputRef,
}

impl Campaign {
    fn judge(&self) -> CampaignArchiveJudge {
        CampaignArchiveJudge {
            root: self.root,
            descriptor_revision: self.revision.clone(),
            output: self.output.clone(),
        }
    }
}

fn campaign(f: &Fixture, campaign_id: &str, descriptor: ArchiveDescriptor) -> Campaign {
    let root = bound_root(f, campaign_id);
    let task = task(f, "answer the customer's request");
    let samples = vec![
        artifact(f, &format!("{campaign_id}-a.txt"), "a formal, short answer"),
        artifact(f, &format!("{campaign_id}-b.txt"), "a casual, long answer"),
    ];
    let method = match &descriptor {
        ArchiveDescriptor::Axes { .. } => ArchiveAxesMethod::CoachRecipe {
            recipe_revision: "fixture-recipe".into(),
            model: "fixture-model".into(),
        },
        ArchiveDescriptor::EmbeddingClusters { .. } => ArchiveAxesMethod::EmbeddingClusters,
    };
    let proposal = mint_archive_axes(
        &f.vault,
        ArchiveAxesMint {
            root,
            from: None,
            task,
            project: f.project,
            goal_ref: f.goal_ref,
            quality_metric: f.ruler.clone(),
            sample_outputs: samples.clone(),
            descriptor,
            producer: f.owner,
            method,
        },
    )
    .expect("the engine's axes record");
    let view = research_archive_install(
        &owner_memory(f),
        CampaignArchiveInstall {
            root,
            task,
            project: f.project,
            goal_ref: f.goal_ref,
            quality_metric: f.ruler.clone(),
            sample_outputs: samples,
            proposal,
        },
    )
    .expect("install");
    Campaign {
        root,
        revision: view.descriptor_revision,
        output: artifact(
            f,
            &format!("{campaign_id}-output.txt"),
            "a formal, short reply to the customer",
        ),
    }
}

/// A typed decision as the decision ladder returns one, on the Big rung.
fn decision(
    f: &Fixture,
    answer: DecisionAnswer,
    probability: f64,
    human_ask: Option<HumanAskReason>,
) -> TypedDecision {
    TypedDecision {
        answer,
        probability: Some(probability),
        evidence: Vec::new(),
        in_band: probability < 0.65,
        receipt: DecisionReceipt {
            question: EntityId::derive(b"archive-judge-fixture", &[b"question".as_slice()])
                .expect("question id"),
            question_version: 1,
            principal: f.owner,
            providers: vec![ProviderPin {
                rung: DecisionRung::Big,
                model: "fixture-model".into(),
                version: "1".into(),
            }],
            band: DecisionBand {
                low: 0.35,
                high: 0.65,
            },
            band_version: 0,
            evidence_versions: Vec::new(),
            cost_per_thousand: None,
            paired: Vec::new(),
            person: Vec::new(),
            time: None,
            images: Vec::new(),
            think_row: None,
            person_row: None,
            rule: None,
            asked: None,
            state_cut: None,
        },
        human_ask,
    }
}

fn choice(f: &Fixture, bin: &str) -> oneiron::Result<TypedDecision> {
    Ok(decision(f, DecisionAnswer::Choice(bin.into()), 0.99, None))
}

fn quality(f: &Fixture, value: f64, probability: f64) -> oneiron::Result<TypedDecision> {
    Ok(decision(f, DecisionAnswer::Score(value), probability, None))
}

/// The host the judge borrows, scripted: one answer per question in order,
/// and the embedder (or none). It keeps every question it was asked.
struct ScriptedLadder {
    answers: RefCell<VecDeque<oneiron::Result<TypedDecision>>>,
    embedder: Option<Arc<dyn Embedder>>,
    asks: RefCell<Vec<ArchiveJudgeAsk>>,
}

impl ScriptedLadder {
    fn new(
        answers: Vec<oneiron::Result<TypedDecision>>,
        embedder: Option<Arc<dyn Embedder>>,
    ) -> Self {
        Self {
            answers: RefCell::new(answers.into()),
            embedder,
            asks: RefCell::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<ArchiveJudgeQuestion> {
        self.asks
            .borrow()
            .iter()
            .map(|ask| ask.question.clone())
            .collect()
    }
}

impl ArchiveJudgeHost for ScriptedLadder {
    fn decide(&self, ask: &ArchiveJudgeAsk) -> oneiron::Result<TypedDecision> {
        self.asks.borrow_mut().push(ask.clone());
        self.answers
            .borrow_mut()
            .pop_front()
            .expect("a scripted answer for each question asked")
    }

    fn embedder(&self) -> Option<Arc<dyn Embedder>> {
        self.embedder.clone()
    }
}

/// An embedder that maps a "formal" text to one point and any other to
/// another. It counts its calls.
struct ScriptedEmbedder {
    locality: EmbedderLocality,
    calls: std::sync::Mutex<usize>,
}

impl ScriptedEmbedder {
    fn new(locality: EmbedderLocality) -> Arc<Self> {
        Arc::new(Self {
            locality,
            calls: std::sync::Mutex::new(0),
        })
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls lock")
    }
}

impl Embedder for ScriptedEmbedder {
    fn model_id(&self) -> &str {
        EMBEDDER_SPACE
    }
    fn dimensions(&self) -> usize {
        2
    }
    fn locality(&self) -> EmbedderLocality {
        self.locality
    }
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok(inputs
            .iter()
            .map(|input| match &input.payload {
                PendingEmbeddingPayload::SummaryText(text) if text.contains("formal") => {
                    vec![0.9, 0.1]
                }
                _ => vec![0.1, 0.9],
            })
            .collect())
    }
}

fn judge(
    memory: &Memory<'_>,
    input: CampaignArchiveJudge,
    host: &ScriptedLadder,
) -> Result<CampaignArchiveJudged, String> {
    research_archive_judge(memory, input, host).map_err(|error| format!("{error:?}"))
}

fn record(
    f: &Fixture,
    campaign: &Campaign,
    judged: CampaignArchiveJudged,
) -> Result<CampaignArchiveView, String> {
    research_archive_record(
        &owner_memory(f),
        CampaignArchiveOutput {
            root: campaign.root,
            descriptor_revision: campaign.revision.clone(),
            placement: judged.placement,
            score: judged.score,
        },
    )
    .map_err(|error| format!("{error:?}"))
}

fn producers(f: &Fixture) -> usize {
    archive_producer_records(&f.vault).expect("producer records read")
}

#[test]
fn scripted_answers_give_records_that_record_accepts() {
    let f = fixture();
    let campaign = campaign(&f, "judge-positive", two_axes());
    let before = producers(&f);
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "formal"),
            choice(&f, "short"),
            quality(&f, 0.8, 0.99),
        ],
        None,
    );
    let judged = judge(&owner_memory(&f), campaign.judge(), &ladder).expect("the owner's judgment");
    assert_eq!(
        ladder.asked(),
        [
            ArchiveJudgeQuestion::Placement {
                axis: "tone".into(),
                bins: vec!["formal".into(), "casual".into()],
            },
            ArchiveJudgeQuestion::Placement {
                axis: "length".into(),
                bins: vec!["short".into(), "long".into()],
            },
            ArchiveJudgeQuestion::Score,
        ],
        "one choice per pinned axis in axis order, then the score"
    );
    {
        let asks = ladder.asks.borrow();
        assert_eq!(
            asks[0].state["response"], "a formal, short reply to the customer",
            "the ladder read the output at its revision"
        );
        assert!(
            asks[0].state["task"]
                .to_string()
                .contains("answer the customer's request"),
            "the ladder read the task: {}",
            asks[0].state["task"]
        );
        assert_eq!(asks[0].key, [campaign.revision.clone(), "tone".to_owned()]);
        assert!(asks[0].evidence.contains(&campaign.output.entity));
    }
    assert_eq!(
        producers(&f),
        before + 2,
        "one placement and one score record"
    );
    let CampaignArchivePlacement::Judgment { judgment } = &judged.placement else {
        panic!("a typed placement, not {:?}", judged.placement);
    };
    let placement_receipt = judgment.receipt;
    assert_eq!(
        judgment.cell,
        ArchiveCell::Axes {
            bins: vec!["formal".into(), "short".into()]
        }
    );
    assert_eq!(judgment.output, campaign.output);
    assert_eq!(judged.score.quality.to_bits(), 0.8_f64.to_bits());
    let scoring_receipt = judged.score.receipt;
    let view = record(&f, &campaign, judged).expect("record takes the judge's receipts");
    assert_eq!(view.best.len(), 1, "one cell holds one best output");
    assert_eq!(view.best[0].output, campaign.output);
    assert_eq!(view.best[0].placement_receipt, placement_receipt);
    assert_eq!(view.best[0].scoring_receipt, scoring_receipt);
}

#[test]
fn an_unanswered_or_uncertain_question_records_nothing() {
    let f = fixture();
    let campaign = campaign(&f, "judge-unanswered", two_axes());
    let before = producers(&f);
    // A deadline on the second axis: the score is never asked.
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "formal"),
            Ok(decision(
                &f,
                DecisionAnswer::Abstain,
                0.0,
                Some(HumanAskReason::Deadline),
            )),
        ],
        None,
    );
    let refused =
        judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("an unanswered axis");
    assert!(
        refused.contains("recorded nothing") && refused.contains("the length placement"),
        "{refused}"
    );
    assert!(
        refused.contains("deadline"),
        "the reason is named: {refused}"
    );
    assert_eq!(ladder.asked().len(), 2, "the score was never asked");
    // A pure abstain.
    let ladder = ScriptedLadder::new(
        vec![Ok(decision(&f, DecisionAnswer::Abstain, 0.0, None))],
        None,
    );
    let refused = judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("an abstain");
    assert!(
        refused.contains("the tone placement abstained"),
        "{refused}"
    );
    // An answer below the band's high mark.
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "formal"),
            choice(&f, "short"),
            quality(&f, 0.9, 0.5),
        ],
        None,
    );
    let refused = judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("uncertain");
    assert!(
        refused.contains("the quality score was uncertain"),
        "{refused}"
    );
    // A choice of no pinned bin: no bin is invented.
    let ladder = ScriptedLadder::new(vec![choice(&f, "neutral")], None);
    let refused = judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("no pinned bin");
    assert!(
        refused.contains("the tone placement answered no pinned bin"),
        "{refused}"
    );
    // A ladder fault (a budget denial) fails the call.
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "formal"),
            choice(&f, "short"),
            Err(oneiron::Error::InvalidConfig("budget denied".into())),
        ],
        None,
    );
    let refused = judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("a fault");
    assert!(refused.contains("budget denied"), "{refused}");
    assert_eq!(producers(&f), before, "no refusal recorded anything");
    // The same output, answered: recorded.
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "formal"),
            choice(&f, "short"),
            quality(&f, 0.7, 0.9),
        ],
        None,
    );
    judge(&owner_memory(&f), campaign.judge(), &ladder).expect("answered");
    assert_eq!(producers(&f), before + 2);
}

#[test]
fn a_non_controller_is_refused_before_any_question() {
    let f = fixture();
    let campaign = campaign(&f, "judge-outsider", two_axes());
    let before = producers(&f);
    let outsider = f.vault.memory(f.agent, EdgeActorClass::Agent);
    let ladder = ScriptedLadder::new(Vec::new(), None);
    let refused = judge(&outsider, campaign.judge(), &ladder)
        .expect_err("an agent not running the root's attempt cannot judge");
    assert!(
        refused.contains("only the campaign's controller"),
        "refused by the controller gate: {refused}"
    );
    assert!(ladder.asked().is_empty(), "no question was asked");
    assert_eq!(producers(&f), before, "nothing was recorded");
}

#[test]
fn the_score_reads_the_rubric_of_the_judge_the_pin_names() {
    let f = fixture();
    let campaign = campaign(&f, "judge-ruler", two_axes());
    let ladder = ScriptedLadder::new(
        vec![
            choice(&f, "casual"),
            choice(&f, "long"),
            quality(&f, 0.4, 0.8),
        ],
        None,
    );
    judge(&owner_memory(&f), campaign.judge(), &ladder).expect("judged");
    let rubric = oneiron::skill_optimize::judge_rubric(&f.vault)
        .expect("judge rubric read")
        .expect("the seeded judge");
    let asks = ladder.asks.borrow();
    let score = &asks[2];
    assert_eq!(score.question, ArchiveJudgeQuestion::Score);
    assert_eq!(
        score.key,
        [f.ruler.metric_id.clone(), f.ruler.revision.clone()],
        "the score question is keyed by the pinned ruler"
    );
    assert_eq!(score.state["judge_rubric"], rubric.text.as_str());
    assert_eq!(
        score.state["judge_rubric_pin"]["skill"],
        f.ruler.metric_id.as_str()
    );
    assert_eq!(
        score.state["judge_rubric_pin"]["digest"],
        blake3::hash(rubric.text.as_bytes()).to_hex().as_str(),
        "the pin names the rubric text's digest"
    );
    assert!(
        score.evidence.contains(&rubric.skill),
        "the judge skill is evidence"
    );
    drop(asks);
    // Another descriptor revision than the pin's is refused before any question.
    let ladder = ScriptedLadder::new(Vec::new(), None);
    let refused = judge(
        &owner_memory(&f),
        CampaignArchiveJudge {
            descriptor_revision: "0".repeat(64),
            ..campaign.judge()
        },
        &ladder,
    )
    .expect_err("another descriptor revision");
    assert!(
        refused.contains("another archive descriptor revision"),
        "{refused}"
    );
    assert!(ladder.asked().is_empty());
}

#[test]
fn an_embedding_campaign_places_by_the_nearest_pinned_center() {
    let f = fixture();
    let campaign = campaign(&f, "judge-clusters", two_clusters());
    let before = producers(&f);
    // A remote embedder never reads the output: refused before any question.
    let remote = ScriptedEmbedder::new(EmbedderLocality::ThirdParty);
    let ladder = ScriptedLadder::new(Vec::new(), Some(remote.clone() as Arc<dyn Embedder>));
    let refused =
        judge(&owner_memory(&f), campaign.judge(), &ladder).expect_err("a remote embedder");
    assert!(refused.contains("not on it"), "{refused}");
    assert_eq!(remote.calls(), 0, "the remote embedder read nothing");
    assert!(ladder.asked().is_empty());
    assert_eq!(producers(&f), before);
    // The pinned embedder on this device: no placement question, one score.
    let local = ScriptedEmbedder::new(EmbedderLocality::OnDevice);
    let ladder = ScriptedLadder::new(
        vec![quality(&f, 0.6, 0.95)],
        Some(local.clone() as Arc<dyn Embedder>),
    );
    let judged = judge(&owner_memory(&f), campaign.judge(), &ladder).expect("judged");
    assert_eq!(local.calls(), 1, "the output was embedded once");
    assert_eq!(ladder.asked(), [ArchiveJudgeQuestion::Score]);
    let CampaignArchivePlacement::Embedding {
        model_revision,
        embedding,
        ..
    } = &judged.placement
    else {
        panic!("an embedding placement, not {:?}", judged.placement);
    };
    assert_eq!(model_revision, EMBEDDER_SPACE);
    assert_eq!(embedding.len(), 2);
    let view = record(&f, &campaign, judged).expect("record takes the judge's receipts");
    assert_eq!(view.best.len(), 1);
    assert_eq!(
        view.best[0].cell,
        ArchiveCell::Cluster { index: 0 },
        "the formal output's nearest center"
    );
}

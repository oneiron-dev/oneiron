//! The Coach's output-archive axes job (ARM05 P2; ARCH-0053 #output-archive:
//! "For each task, the Coach proposes two or three axes from the goal and
//! sample outputs ... Embedding clusters are the fallback"). The campaign's
//! controller queues a request with `vault.research.archive.propose_axes`,
//! which wakes the host's Coach; the Coach's job answers it through
//! `Vault::run_coach_archive_axes` on a scripted host (its model seat's text
//! and its embedder), and `vault.research.archive.proposal` reads the state
//! back. A proposed state's receipt is the Coach's own producer record, so
//! install accepts it; a one-bin or malformed answer falls to clusters on an
//! on-device embedder, or ends "none", never a forged descriptor. A
//! non-controller cannot queue, and a re-proposal of an unbunched archive is
//! refused when it is asked.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_axes_job`.
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::authority::MachineRole;
use oneiron::autoreason_campaign::archive::{
    ArchiveAxesBrief, ArchiveAxesHost, ArchiveAxesMethod, ArchiveAxesProposal, ArchiveAxesReply,
    ArchiveDescriptor, ArchiveOutputRef, ArchiveQualityMetric, CampaignArchiveInstall,
    CampaignArchiveProposalRequest, CampaignArchiveProposalState, CampaignArchiveProposeAxes,
    CampaignArchiveView,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
};
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{
    research_archive_install, research_archive_proposal, research_archive_propose_axes,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The Coach host queue's lease owner and budget line
/// (`oneiron-server/src/ai_host/coach_heal.rs:67`, `coach_host.rs:96`).
const COACH_HOST: &str = "coach.host";
/// The facet of the axes job.
const ARCHIVE_AXES_FACET: &str = "coach.archive_axes";
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
    let agent = define_agent(&vault, "archive-research-target").expect("the root's agent");
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
fn bound_root(f: &Fixture, intent_key: &str, campaign_id: &str) -> EntityId {
    let owner = owner_memory(f);
    let created = invoke(
        &owner,
        "vault.research.create_root",
        json!({
            "agent": f.agent.to_hex(),
            "intent_key": intent_key,
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

/// The host the Coach's job borrows, scripted: the recipe's answer text (or
/// no seat) and the embedder (or none). It keeps every brief it was given.
struct ScriptedHost {
    reply: Option<String>,
    embedder: Option<Arc<dyn Embedder>>,
    briefs: RefCell<Vec<ArchiveAxesBrief>>,
}

impl ScriptedHost {
    fn new(reply: Option<&str>, embedder: Option<Arc<dyn Embedder>>) -> Self {
        Self {
            reply: reply.map(str::to_owned),
            embedder,
            briefs: RefCell::new(Vec::new()),
        }
    }
}

impl ArchiveAxesHost for ScriptedHost {
    fn recipe(&self, brief: &ArchiveAxesBrief) -> oneiron::Result<Option<ArchiveAxesReply>> {
        self.briefs.borrow_mut().push(brief.clone());
        Ok(self.reply.clone().map(|text| ArchiveAxesReply {
            text,
            model: "scripted-model".into(),
            recipe_revision: "scripted-recipe".into(),
        }))
    }

    fn embedder(&self) -> Option<Arc<dyn Embedder>> {
        self.embedder.clone()
    }
}

/// An embedder that maps a sample's text to a fixed vector: "formal" texts
/// near one point, "casual" texts near another. It counts its calls.
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
                    if text.contains("long") {
                        vec![1.0, 0.1]
                    } else {
                        vec![1.0, 0.0]
                    }
                }
                PendingEmbeddingPayload::SummaryText(text) if text.contains("long") => {
                    vec![0.0, 1.1]
                }
                _ => vec![0.0, 1.0],
            })
            .collect())
    }
}

const TWO_AXES: &str = r#"Here are the axes:
```json
{"axes":[{"name":"tone","bins":["formal","casual"]},{"name":"length","bins":["short","long"]}]}
```"#;

/// A campaign root, its task and four samples, ready for a request.
struct Campaign {
    root: EntityId,
    task: EntityId,
    samples: Vec<ArchiveOutputRef>,
}

fn campaign(f: &Fixture, intent_key: &str) -> Campaign {
    let root = bound_root(f, intent_key, intent_key);
    let task = task(f, "answer the customer's request");
    let samples = vec![
        artifact(f, &format!("{intent_key}-a.txt"), "a formal, short answer"),
        artifact(f, &format!("{intent_key}-b.txt"), "a formal, long answer"),
        artifact(f, &format!("{intent_key}-c.txt"), "a casual, short answer"),
        artifact(f, &format!("{intent_key}-d.txt"), "a casual, long answer"),
    ];
    Campaign {
        root,
        task,
        samples,
    }
}

fn first_request(f: &Fixture, campaign: &Campaign) -> CampaignArchiveProposeAxes {
    CampaignArchiveProposeAxes::First {
        root: campaign.root,
        task: campaign.task,
        project: f.project,
        goal_ref: f.goal_ref,
        quality_metric: f.ruler.clone(),
        sample_outputs: campaign.samples.clone(),
    }
}

fn propose(memory: &Memory<'_>, input: CampaignArchiveProposeAxes) -> Result<EntityId, String> {
    research_archive_propose_axes(memory, input)
        .map(|queued| queued.request)
        .map_err(|error| format!("{error:?}"))
}

fn proposal_state(f: &Fixture, request: EntityId) -> CampaignArchiveProposalState {
    research_archive_proposal(&owner_memory(f), CampaignArchiveProposalRequest { request })
        .expect("the owner reads the request's state")
}

/// The next Coach host job, leased as the host's round leases it.
fn admit(f: &Fixture) -> Option<DreamerAdmittedAttempt> {
    match DreamerRunnerStore::new(&f.vault)
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now: f.vault.now_recorded_at(),
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })
        .expect("the Coach host queue admits")
    {
        DreamerAdmissionOutcome::Admitted(admitted) => Some(admitted),
        _ => None,
    }
}

/// Leases the queued axes job and runs it on `host`, as the host's Coach
/// round does.
fn run_job(f: &Fixture, host: &ScriptedHost) -> CampaignArchiveProposalState {
    let admitted = admit(f).expect("the request queued the Coach's job");
    assert_eq!(admitted.status.payload.attempt_type, ARCHIVE_AXES_FACET);
    f.vault
        .run_coach_archive_axes(&admitted, host)
        .expect("the Coach's job runs")
}

/// Whether the Coach host's wake holds a permit, taken without waiting.
fn woken(f: &Fixture) -> bool {
    let wake = f.vault.coach_host_wake();
    let mut notified = std::pin::pin!(wake.notified());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    notified.as_mut().poll(&mut context).is_ready()
}

fn install(
    f: &Fixture,
    campaign: &Campaign,
    proposal: ArchiveAxesProposal,
) -> Result<CampaignArchiveView, String> {
    research_archive_install(
        &owner_memory(f),
        CampaignArchiveInstall {
            root: campaign.root,
            task: campaign.task,
            project: f.project,
            goal_ref: f.goal_ref,
            quality_metric: f.ruler.clone(),
            sample_outputs: campaign.samples.clone(),
            proposal,
        },
    )
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn the_coach_answers_a_queued_request_with_a_proposal_install_accepts() {
    let f = fixture();
    let campaign = campaign(&f, "axes-recipe");
    assert!(!woken(&f), "nothing woke the Coach host before the request");
    let request = propose(&owner_memory(&f), first_request(&f, &campaign))
        .expect("the owner queues the request");
    assert!(woken(&f), "the request wakes the Coach host at once");
    assert_eq!(
        proposal_state(&f, request),
        CampaignArchiveProposalState::Pending
    );
    let host = ScriptedHost::new(Some(TWO_AXES), None);
    let state = run_job(&f, &host);
    let briefs = host.briefs.borrow();
    assert_eq!(briefs.len(), 1, "the recipe ran once");
    assert!(
        briefs[0].goal.contains("customer requests"),
        "the recipe read the campaign's goal"
    );
    let mut texts: Vec<&str> = briefs[0].samples.iter().map(|s| s.text.as_str()).collect();
    texts.sort_unstable();
    assert_eq!(
        texts,
        [
            "a casual, long answer",
            "a casual, short answer",
            "a formal, long answer",
            "a formal, short answer"
        ],
        "the recipe read each sample at its revision"
    );
    let CampaignArchiveProposalState::Proposed { proposal, method } = state.clone() else {
        panic!("the Coach proposed: {state:?}");
    };
    assert_eq!(
        method,
        ArchiveAxesMethod::CoachRecipe {
            recipe_revision: "scripted-recipe".into(),
            model: "scripted-model".into(),
        }
    );
    assert!(matches!(&proposal.descriptor, ArchiveDescriptor::Axes { axes } if axes.len() == 2));
    assert_eq!(proposal_state(&f, request), state, "the state reads back");
    let receipt = proposal.receipt;
    let view = install(&f, &campaign, proposal).expect("install accepts the Coach's proposal");
    assert_eq!(view.pin.proposal_receipt(), receipt);
    // An answered request is left as it is.
    assert!(admit(&f).is_none(), "the job was the only one queued");
}

#[test]
fn a_non_controller_cannot_queue_a_request() {
    let f = fixture();
    let campaign = campaign(&f, "axes-outsider");
    let outsider = f.vault.memory(f.agent, EdgeActorClass::Agent);
    let refused = propose(&outsider, first_request(&f, &campaign))
        .expect_err("an agent not running the root's attempt cannot queue");
    assert!(
        refused.contains("only the campaign's controller"),
        "refused by the controller gate: {refused}"
    );
    assert!(!woken(&f), "a refused request wakes nothing");
    assert!(admit(&f).is_none(), "a refused request queues no job");
    // The owner, the controller, queues the same request.
    propose(&owner_memory(&f), first_request(&f, &campaign)).expect("the owner queues it");
    assert!(admit(&f).is_some(), "the owner's request queued the job");
}

#[test]
fn a_one_bin_answer_falls_to_clusters_on_the_device_embedder() {
    let f = fixture();
    let campaign = campaign(&f, "axes-clusters");
    let request = propose(&owner_memory(&f), first_request(&f, &campaign)).expect("queued");
    let embedder = ScriptedEmbedder::new(EmbedderLocality::OnDevice);
    let host = ScriptedHost::new(
        Some(
            r#"{"axes":[{"name":"tone","bins":["formal"]},{"name":"length","bins":["short","long"]}]}"#,
        ),
        Some(embedder.clone() as Arc<dyn Embedder>),
    );
    let state = run_job(&f, &host);
    assert_eq!(
        embedder.calls(),
        1,
        "the fallback embedded the samples once"
    );
    let CampaignArchiveProposalState::Proposed { proposal, method } = state else {
        panic!("the fallback proposed clusters: {state:?}");
    };
    assert_eq!(method, ArchiveAxesMethod::EmbeddingClusters);
    let ArchiveDescriptor::EmbeddingClusters {
        model_revision,
        centers,
    } = &proposal.descriptor
    else {
        panic!("clusters, not {:?}", proposal.descriptor);
    };
    assert_eq!(
        model_revision, EMBEDDER_SPACE,
        "the clusters pin the embedder's space"
    );
    assert_eq!(centers.len(), 2, "four samples make two clusters");
    assert!(
        matches!(
            proposal_state(&f, request),
            CampaignArchiveProposalState::Proposed { .. }
        ),
        "the state reads back"
    );
    install(&f, &campaign, proposal).expect("install accepts the Coach's clusters");
}

#[test]
fn a_malformed_answer_with_no_device_embedder_ends_none() {
    let f = fixture();
    let campaign = campaign(&f, "axes-none");
    // A remote embedder is no fallback: the samples' words stay on the device.
    let remote = ScriptedEmbedder::new(EmbedderLocality::ThirdParty);
    let request = propose(&owner_memory(&f), first_request(&f, &campaign)).expect("queued");
    let host = ScriptedHost::new(
        Some("tone and length, I think"),
        Some(remote.clone() as Arc<dyn Embedder>),
    );
    let state = run_job(&f, &host);
    assert!(
        matches!(state, CampaignArchiveProposalState::NoDescriptor { .. }),
        "no descriptor was forged: {state:?}"
    );
    assert_eq!(remote.calls(), 0, "the remote embedder read no sample");
    assert_eq!(proposal_state(&f, request), state, "the state reads back");
    // No seat at all, and no embedder: none again.
    let request = propose(&owner_memory(&f), first_request(&f, &campaign)).expect("queued");
    let state = run_job(&f, &ScriptedHost::new(None, None));
    assert!(matches!(
        state,
        CampaignArchiveProposalState::NoDescriptor { .. }
    ));
    assert_eq!(proposal_state(&f, request), state);
}

#[test]
fn a_reproposal_of_an_unbunched_archive_is_refused_when_asked() {
    let f = fixture();
    let campaign = campaign(&f, "axes-installed");
    propose(&owner_memory(&f), first_request(&f, &campaign)).expect("queued");
    let CampaignArchiveProposalState::Proposed { proposal, .. } =
        run_job(&f, &ScriptedHost::new(Some(TWO_AXES), None))
    else {
        panic!("the Coach proposed");
    };
    install(&f, &campaign, proposal).expect("installed");
    let next = bound_root(&f, "axes-next", "axes-next");
    let refused = propose(
        &owner_memory(&f),
        CampaignArchiveProposeAxes::Reproposal {
            root: next,
            from: campaign.root,
        },
    )
    .expect_err("an archive with no scores has not bunched");
    assert!(
        refused.contains("a re-proposal follows a bunched archive"),
        "refused for the unbunched archive: {refused}"
    );
    assert!(admit(&f).is_none(), "a refused re-proposal queues no job");
    // A first request for a root that already holds an archive is refused too.
    let refused = propose(&owner_memory(&f), first_request(&f, &campaign))
        .expect_err("the root's archive is installed");
    assert!(refused.contains("immutable"), "{refused}");
}

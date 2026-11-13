//! The read shape a run woke under reaches the run (census L9-37 PR 2;
//! ARCH-0051 #decision-r9-bench): the run's self brief names it, the
//! graph_fs mount reads a leased run makes log its attempt (so a mount-shaped
//! run's reads count toward its pick, as its search runs do), and the run's
//! spend scope records the tokens it settled on its stamp, for the reward's
//! token cost term.
//!
//! On the PR 1 head this file does not compile: there is no
//! `Memory::with_dispatch_attempt`, no `BriefReadShape` and no
//! `SelfBriefState::read_shape`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test read_shape_run_wiring`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use oneiron::context_board::{
    BriefReadShape, BriefWorkingSet, CommunicationLimits, SelfBriefState, SessionReadSet,
};
use oneiron::edge::EdgeActorClass;
use oneiron::graph_fs::GraphFsReference;
use oneiron::llm::ModelId;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::memory::graph_fs_doors::{GraphFsGrepRequest, GraphFsLsRequest, GraphFsMountRequest};
use oneiron::store::{ReadShape, ReadShapePick, ReadShapeTier, RetrievalAction};
use oneiron::test_doors::spend::reserve_child_scope;
use oneiron::{EntityId, Vault, VaultConfig};

const KIND: &str = "test.read_shape_wiring";
const NOW: u64 = 1_700_000_000;

/// A vault that captures retrieval telemetry, with its embedded owner.
fn capturing_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    (dir, vault, owner)
}

fn enqueue(vault: &Vault) -> AttemptId {
    let outcome = AttemptQueue::new(vault)
        .enqueue(EnqueueAttempt {
            kind: KIND.to_owned(),
            payload: b"run".to_vec(),
            dedupe_key: None,
            run_id: None,
            now: NOW,
        })
        .expect("enqueue");
    let EnqueueOutcome::Enqueued(record) = outcome else {
        panic!("a fresh row is enqueued");
    };
    record.id
}

fn live_head() -> GraphFsMountRequest {
    GraphFsMountRequest {
        reference: GraphFsReference::LiveHead,
        page_byte_cap: None,
        max_entries: None,
    }
}

/// The dispatch attempt of each graph_fs coreutils run the vault logged.
fn mount_run_attempts(vault: &Vault) -> Vec<Option<AttemptId>> {
    vault
        .retrieval_runs(64)
        .expect("read the retrieval runs")
        .into_iter()
        .filter(|run| run.action == RetrievalAction::GraphFsCoreutils)
        .map(|run| run.dispatch_attempt)
        .collect()
}

#[test]
fn mount_reads_of_a_leased_run_name_its_attempt() {
    let (_dir, vault, owner) = capturing_vault();
    let attempt = enqueue(&vault);

    // A handle no host bound to a run logs its read with no attempt.
    vault
        .memory(owner, EdgeActorClass::Human)
        .graph_fs_ls(GraphFsLsRequest {
            mount: live_head(),
            path: "/".to_owned(),
            cursor: None,
            by_time: false,
        })
        .expect("an unbound ls");
    assert_eq!(mount_run_attempts(&vault), vec![None]);

    let run = vault
        .memory(owner, EdgeActorClass::Human)
        .with_dispatch_attempt(Some(attempt));
    run.graph_fs_ls(GraphFsLsRequest {
        mount: live_head(),
        path: "/".to_owned(),
        cursor: None,
        by_time: false,
    })
    .expect("the run's ls");
    run.graph_fs_grep(GraphFsGrepRequest {
        mount: live_head(),
        path: "/claims".to_owned(),
        pattern: "amberlantern".to_owned(),
        recursive: true,
        cursor: None,
    })
    .expect("the run's grep");

    let mut attempts = mount_run_attempts(&vault);
    attempts.sort();
    assert_eq!(
        attempts,
        vec![None, Some(attempt), Some(attempt)],
        "each of the run's mount reads names its attempt; the unbound read names none"
    );
}

#[test]
fn a_settled_run_records_its_tokens_on_its_read_shape_stamp() {
    let (_dir, vault, _owner) = capturing_vault();
    let dispatcher = AgentDispatcher::new(&vault);
    let root = SpendScopeId::launch("owen-read-shape-root").expect("launch id");
    dispatcher
        .open_root_spend_scope(
            root.clone(),
            DeclaredMaximum {
                units: 1_000,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 12_000 }),
            12,
        )
        .expect("the root opens");
    let model = ModelId::new("test/model-a@r1").expect("model id");

    let stamped = enqueue(&vault);
    let unstamped = enqueue(&vault);
    for attempt in [stamped, unstamped] {
        let scope = reserve_child_scope(&vault, &root, &attempt, 400, 13).expect("carve");
        dispatcher
            .charge(&scope.scope, 120)
            .expect("the run spends");
    }
    vault
        .stamp_read_shape(
            stamped,
            &model,
            ReadShapePick {
                shape: ReadShape::Mount,
                tier: ReadShapeTier::Explore,
            },
        )
        .expect("the wake's stamp");

    let settled = dispatcher
        .settle_child(&stamped, 14)
        .expect("settle")
        .expect("the run was metered");
    assert_eq!(settled.spent_units, 120);
    let stamp = vault
        .read_shape_stamp(stamped)
        .expect("read the stamp")
        .expect("the run's stamp");
    assert_eq!(
        stamp.model_units,
        Some(120),
        "the settlement records the run's tokens"
    );
    assert_eq!(
        stamp.shape,
        ReadShape::Mount,
        "the settlement keeps the pick"
    );

    // Settling again moves nothing and keeps the total.
    let again = dispatcher
        .settle_child(&stamped, 15)
        .expect("settle again")
        .expect("the run was metered");
    assert!(again.already_settled);
    assert_eq!(
        vault
            .read_shape_stamp(stamped)
            .expect("read the stamp")
            .and_then(|stamp| stamp.model_units),
        Some(120)
    );

    // A run that woke under no stamp settles as before and gains none.
    let plain = dispatcher
        .settle_child(&unstamped, 14)
        .expect("settle the unstamped run")
        .expect("the run was metered");
    assert_eq!(plain.spent_units, 120);
    assert_eq!(
        vault.read_shape_stamp(unstamped).expect("read the stamp"),
        None
    );
}

fn brief_state(read_shape: Option<BriefReadShape>) -> SelfBriefState {
    SelfBriefState {
        self_ref: EntityId::now(),
        principal: None,
        grants: None,
        run_ceiling: None,
        credential_ceiling: None,
        parent_ceiling: None,
        communication: CommunicationLimits {
            reach: None,
            credential_ceiling: None,
        },
        ceilings: None,
        class_verdicts: None,
        budget_lease_id: None,
        budget: None,
        read_shape,
        clock_ms: 1,
        skill_index: Vec::new(),
        working_set: BriefWorkingSet {
            scratchpad: None,
            pins: None,
            replay: None,
        },
    }
}

/// The rendered brief and its unavailable line.
fn render(vault: &Vault, read_shape: Option<BriefReadShape>) -> (String, String) {
    let text = brief_state(read_shape)
        .describe(vault, &SessionReadSet::default(), None)
        .expect("describe the brief")
        .render();
    let unavailable = text
        .lines()
        .find(|line| line.starts_with("unavailable (no producer yet): "))
        .expect("the brief names what no host produced")
        .to_owned();
    (text, unavailable)
}

#[test]
fn the_self_brief_names_the_read_shape_its_run_woke_under() {
    let (_dir, vault, _owner) = capturing_vault();

    let (mount, unavailable) = render(&vault, Some(BriefReadShape::new(ReadShape::Mount)));
    assert!(
        mount.contains(
            r#""read_shape":{"shape":"mount","read_through":"read memory through the graph_fs mount at / with graph_fs.ls, graph_fs.find, graph_fs.grep, graph_fs.cat, graph_fs.head and graph_fs.wc; the typed memory verbs stay open too"}"#
        ),
        "a mount-shaped run's brief names the mount: {mount}"
    );
    assert!(!unavailable.contains("read shape"), "{unavailable}");

    let (verbs, unavailable) = render(&vault, Some(BriefReadShape::new(ReadShape::Verbs)));
    assert!(
        verbs.contains(
            r#""read_shape":{"shape":"verbs","read_through":"read memory through the typed memory verbs; the graph_fs mount stays open too"}"#
        ),
        "a verbs-shaped run's brief names the verbs: {verbs}"
    );
    assert!(!unavailable.contains("read shape"), "{unavailable}");

    let (none, unavailable) = render(&vault, None);
    assert!(!none.contains("\"read_shape\""), "{none}");
    assert!(
        unavailable.contains("read shape"),
        "a brief with no stamp names the read shape unavailable: {unavailable}"
    );
}

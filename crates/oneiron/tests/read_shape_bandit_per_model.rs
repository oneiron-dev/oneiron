//! The read shape a model works through is one arm family of the one bandit,
//! picked per model (census L9-37; ARCH-0051 #decision-r9-bench: "The typed
//! verbs are the seeded default and the mount is one arm the bandit may pick
//! per model"). The seed is the verbs; the exploration share sends a model
//! with too little mount evidence to the mount; at sleep each stamped
//! attempt's gated retrieval reward, less its token cost, is one pull for its
//! model and shape; an owner pin beats the evidence.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test read_shape_bandit_per_model`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::learning_setting::{SettingMode, SettingRow, put_setting_row};
use oneiron::llm::ModelId;
use oneiron::memory::Memory;
use oneiron::model_binding::ModelRole;
use oneiron::store::read_shape_policy::READ_SHAPE_EXPLORE_SHARE;
use oneiron::store::{
    ReadShape, ReadShapePick, ReadShapeTier, RetrievalAction, RetrievalBlendSignal,
    RetrievalEndOutcome, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalScoreComponent, RetrievalSignal, RetrievalState, RetrievalTurn,
};
use oneiron::test_doors::retrieval_policy_default_floor::record_retrieval_run;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{
    EmptyRequest, ReadShapeModelRow, ReadShapePinRequest, RetrievalPolicyPinRequest,
    RetrievalPolicyTrainRequest, RetrievalPolicyView, retrieval_policy_get_as_owner,
    retrieval_policy_pin_as_owner, retrieval_policy_update_as_owner,
};
use oneiron::write_envelope::WriteActor;
use rand::SeedableRng;
use rand::rngs::StdRng;

const KIND: &str = "test.read_shape";
const WORKER: &str = "worker:read-shape";
const NOW: u64 = 1_700_000_000;

fn setup() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary read-shape vault");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    (dir, vault, owner)
}

fn owner_memory<'v>(vault: &'v Vault, owner: &AuthenticatedOwner) -> Memory<'v> {
    vault.memory(
        owner.actor_for_read(vault).expect("owner actor"),
        EdgeActorClass::Human,
    )
}

fn model(name: &str) -> ModelId {
    ModelId::new(format!("test/{name}@r1")).expect("model id")
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

/// One attempt whose run woke under `shape` for `model`.
fn stamped_attempt(vault: &Vault, model: &ModelId, shape: ReadShape) -> AttemptId {
    let attempt = enqueue(vault);
    let stamp = vault
        .stamp_read_shape(
            attempt,
            model,
            ReadShapePick {
                shape,
                tier: ReadShapeTier::Seed,
            },
        )
        .expect("stamp the attempt's read shape");
    assert_eq!(stamp.shape, shape);
    attempt
}

fn run(turn: RetrievalTurn, attempt: Option<AttemptId>) -> RetrievalRunRecord {
    let result_id = [0x41; 16];
    RetrievalRunRecord {
        version: 0,
        run_id: RetrievalRunId::now(),
        action: RetrievalAction::Pipeline,
        started_at: 100,
        elapsed_us: 10,
        state: RetrievalState {
            result_count: 1,
            ..Default::default()
        },
        policy_trace: None,
        replay_inputs: None,
        turn: Some(turn),
        query_expander_id: None,
        dispatch_attempt: attempt,
        policy_manifest_ref: None,
        policy_manifest_body_hash: None,
        reranker_id: None,
        signals: vec![RetrievalSignal::Text],
        result_ids: vec![result_id],
        score_breakdown: vec![RetrievalScoreBreakdown {
            result_id,
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Relevance,
                rank: 1,
                score: 1.0,
            }],
            access_factor: None,
        }],
        total_in_scope: 1,
        claims_suppressed: 0,
        empty_reason: None,
        trace: None,
        quality: None,
        degradation: Vec::new(),
        confidence_adjustment: None,
    }
}

/// Records one labelled retrieval run for `attempt` through the ordinary
/// telemetry writer and the gated end-outcome writer. A hit earns the gated
/// reward 1 (mapped 1.0); a miss pays a latency cost of -1 (mapped 0.0).
fn label(vault: &Vault, turn_index: u8, attempt: Option<AttemptId>, hit: bool) {
    let turn = RetrievalTurn {
        turn_id: [turn_index; 16],
        episode_id: [0x80; 16],
        turn_idx: 0,
    };
    let run = run(turn, attempt);
    record_retrieval_run(vault, &run).expect("record a labelled run");
    vault
        .record_retrieval_end_outcome(RetrievalEndOutcome {
            retrieval_run_ids: vec![run.run_id],
            key: "terminal".to_owned(),
            turn_id: turn.turn_id,
            gate_score: 1.0,
            confirmed_fact_hit: hit,
            latency_scale_us: 10,
            cost_weight: if hit { 0.0 } else { 1.0 },
            metadata: BTreeMap::new(),
        })
        .expect("record the gated outcome");
}

/// Four Mount and four Verbs attempts for `model`, each with one labelled
/// run: the favoured shape's runs hit, the other's miss.
fn favour(vault: &Vault, model: &ModelId, favoured: ReadShape, turns: &mut u8) {
    for shape in [ReadShape::Verbs, ReadShape::Mount] {
        for _ in 0..4 {
            let attempt = stamped_attempt(vault, model, shape);
            *turns += 1;
            label(vault, *turns, Some(attempt), shape == favoured);
        }
    }
}

fn update(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> RetrievalPolicyView {
    retrieval_policy_update_as_owner(memory, owner, RetrievalPolicyTrainRequest::default())
        .expect("declared retrieval policy update")
        .view
}

fn row<'a>(view: &'a RetrievalPolicyView, model: &ModelId) -> &'a ReadShapeModelRow {
    view.read_shapes
        .iter()
        .find(|row| row.model == *model)
        .expect("the model's read-shape row")
}

fn picks(vault: &Vault, model: &ModelId, draws: usize) -> Vec<ReadShapePick> {
    let mut rng = StdRng::seed_from_u64(7);
    (0..draws)
        .map(|_| vault.pick_read_shape(model, &mut rng).expect("pick"))
        .collect()
}

fn pin_explore_share(vault: &Vault, value: f64) {
    let owner = WriteActor::new(
        vault.ensure_embedded_owner_actor().expect("owner"),
        EdgeActorClass::Human,
    );
    put_setting_row(
        vault,
        &owner,
        &SettingRow {
            key: READ_SHAPE_EXPLORE_SHARE.key.to_owned(),
            mode: SettingMode::Pin,
            value,
            weight_runs: None,
            at: 10,
            why: "no exploration in this vault".to_owned(),
        },
    )
    .expect("the owner's pin on the exploration share");
}

#[test]
fn read_shape_seed_is_verbs_for_a_model_with_no_evidence() {
    let (_dir, vault, _owner) = setup();
    pin_explore_share(&vault, 0.0);
    let model = model("model-a");
    for pick in picks(&vault, &model, 200) {
        assert_eq!(
            pick,
            ReadShapePick {
                shape: ReadShape::Verbs,
                tier: ReadShapeTier::Seed,
            }
        );
    }
}

#[test]
fn read_shape_explores_the_mount_at_the_shipped_share() {
    let (_dir, vault, _owner) = setup();
    let model = model("model-a");
    let picks = picks(&vault, &model, 400);
    let explored = picks
        .iter()
        .filter(|pick| {
            **pick
                == ReadShapePick {
                    shape: ReadShape::Mount,
                    tier: ReadShapeTier::Explore,
                }
        })
        .count();
    let seeded = picks
        .iter()
        .filter(|pick| {
            **pick
                == ReadShapePick {
                    shape: ReadShape::Verbs,
                    tier: ReadShapeTier::Seed,
                }
        })
        .count();
    assert_eq!(
        explored + seeded,
        400,
        "only the seed or an exploration pick"
    );
    // The shipped share is 0.05: about 20 of 400 wakes try the mount.
    assert!(
        (1..=60).contains(&explored),
        "explored {explored} of 400 wakes"
    );
}

#[test]
fn read_shape_picks_mount_for_the_model_whose_attempts_favour_it() {
    let (_dir, vault, owner) = setup();
    let memory = owner_memory(&vault, &owner);
    let (model_a, model_b) = (model("model-a"), model("model-b"));
    let mut turns = 0;
    favour(&vault, &model_a, ReadShape::Mount, &mut turns);
    favour(&vault, &model_b, ReadShape::Verbs, &mut turns);
    let view = update(&memory, &owner);
    assert_eq!(view.read_shapes_labeled_attempts, 16);
    for model in [&model_a, &model_b] {
        let row = row(&view, model);
        assert_eq!((row.verbs_pulls, row.mount_pulls), (4, 4));
        assert_eq!(row.pinned, None);
    }
    let a = picks(&vault, &model_a, 200);
    let a_mount = a
        .iter()
        .filter(|pick| pick.shape == ReadShape::Mount && pick.tier == ReadShapeTier::Model)
        .count();
    assert!(
        a_mount >= 180,
        "model A read through the mount {a_mount} of 200 times"
    );
    let b = picks(&vault, &model_b, 200);
    let b_verbs = b
        .iter()
        .filter(|pick| pick.shape == ReadShape::Verbs && pick.tier == ReadShapeTier::Model)
        .count();
    assert!(
        b_verbs >= 180,
        "model B read through the verbs {b_verbs} of 200 times"
    );
}

#[test]
fn read_shape_rebuild_is_idempotent_and_skips_unattributed_runs() {
    let (_dir, vault, owner) = setup();
    let memory = owner_memory(&vault, &owner);
    let model_a = model("model-a");
    let mut turns = 0;
    favour(&vault, &model_a, ReadShape::Mount, &mut turns);
    // A labelled run that names no attempt, and one whose attempt woke under
    // no read-shape stamp: neither is a pull.
    label(&vault, 200, None, true);
    let unstamped = enqueue(&vault);
    label(&vault, 201, Some(unstamped), true);
    let first = update(&memory, &owner);
    let second = update(&memory, &owner);
    assert_eq!(first.read_shapes_labeled_attempts, 8);
    assert_eq!(second.read_shapes_labeled_attempts, 8);
    let (first, second) = (row(&first, &model_a), row(&second, &model_a));
    assert_eq!((first.verbs_pulls, first.mount_pulls), (4, 4));
    assert_eq!(
        (
            second.verbs_pulls,
            second.mount_pulls,
            second.verbs_mean,
            second.mount_mean
        ),
        (
            first.verbs_pulls,
            first.mount_pulls,
            first.verbs_mean,
            first.mount_mean
        ),
    );
}

#[test]
fn read_shape_owner_pin_beats_evidence() {
    let (_dir, vault, owner) = setup();
    let memory = owner_memory(&vault, &owner);
    let model_a = model("model-a");
    let mut turns = 0;
    favour(&vault, &model_a, ReadShape::Mount, &mut turns);
    update(&memory, &owner);
    let pin = |shape| RetrievalPolicyPinRequest {
        signal: None,
        value: None,
        read_shape: Some(ReadShapePinRequest {
            model: model_a.clone(),
            shape,
        }),
    };
    let pinned = retrieval_policy_pin_as_owner(&memory, &owner, pin(Some(ReadShape::Verbs)))
        .expect("pin model A to the verbs");
    assert_eq!(row(&pinned, &model_a).pinned, Some(ReadShape::Verbs));
    for pick in picks(&vault, &model_a, 50) {
        assert_eq!(
            pick,
            ReadShapePick {
                shape: ReadShape::Verbs,
                tier: ReadShapeTier::Pinned,
            }
        );
    }
    let cleared = retrieval_policy_pin_as_owner(&memory, &owner, pin(None)).expect("clear the pin");
    assert_eq!(row(&cleared, &model_a).pinned, None);
    assert!(
        picks(&vault, &model_a, 50)
            .iter()
            .all(|pick| pick.tier == ReadShapeTier::Model)
    );
    // A request names one blend signal or one read shape, never both.
    let both = RetrievalPolicyPinRequest {
        signal: Some(RetrievalBlendSignal::Recency),
        value: Some(0.25),
        read_shape: pin(Some(ReadShape::Mount)).read_shape,
    };
    assert!(retrieval_policy_pin_as_owner(&memory, &owner, both).is_err());
    let view = retrieval_policy_get_as_owner(&memory, &owner, EmptyRequest {}).expect("read");
    assert_eq!(row(&view, &model_a).pinned, None);
    assert!(view.pins.is_empty());
}

#[test]
fn read_shape_token_cost_lowers_an_attempt_that_spent_past_its_models_median() {
    let (_dir, vault, owner) = setup();
    let memory = owner_memory(&vault, &owner);
    let model_c = model("model-c");
    // Four mount hits; two settled 100 units, two 300 (median 200). Each
    // 300-unit attempt pays λ · (300 / 200 - 1) = 0.25 · 0.5 of its reward.
    for (index, units) in [100_u64, 100, 300, 300].into_iter().enumerate() {
        let attempt = stamped_attempt(&vault, &model_c, ReadShape::Mount);
        vault
            .record_read_shape_units(attempt, units)
            .expect("record settled units");
        if index == 3 {
            // A smaller later report keeps the larger settled total.
            vault
                .record_read_shape_units(attempt, 150)
                .expect("record a smaller report");
            let stamp = vault
                .read_shape_stamp(attempt)
                .expect("read")
                .expect("stamp");
            assert_eq!(stamp.model_units, Some(300));
        }
        label(&vault, 10 + index as u8, Some(attempt), true);
    }
    let view = update(&memory, &owner);
    let row = row(&view, &model_c);
    assert_eq!((row.verbs_pulls, row.mount_pulls), (0, 4));
    assert_eq!(row.verbs_mean, None);
    // successes 1 + 1 + 0.875 + 0.875 = 3.75, failures 0.25, uniform prior.
    let mean = row.mount_mean.expect("mount mean");
    assert!((mean - 4.75 / 6.0).abs() < 1e-9, "mount mean {mean}");
}

#[test]
fn read_shape_stamp_keeps_the_first_wake_and_refuses_another_model() {
    let (_dir, vault, _owner) = setup();
    let (model_a, model_b) = (model("model-a"), model("model-b"));
    let attempt = enqueue(&vault);
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(record) = queue
        .claim_kind(
            KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: NOW + 100,
            },
        )
        .expect("claim")
    else {
        panic!("the ready row is claimed");
    };
    assert_eq!(record.id, attempt);
    queue
        .set_executor_stamp(
            attempt,
            WORKER,
            record.attempt_count,
            model_a.as_str(),
            model_a.as_str(),
            ModelRole::GenerativeReasoner,
        )
        .expect("executor stamp");
    let explored = ReadShapePick {
        shape: ReadShape::Mount,
        tier: ReadShapeTier::Explore,
    };
    let seeded = ReadShapePick {
        shape: ReadShape::Verbs,
        tier: ReadShapeTier::Seed,
    };
    // Another model than the attempt's executor is refused.
    assert!(vault.stamp_read_shape(attempt, &model_b, seeded).is_err());
    let first = vault
        .stamp_read_shape(attempt, &model_a, explored)
        .expect("first wake's stamp");
    assert_eq!(
        (first.shape, first.tier, first.model_units),
        (ReadShape::Mount, ReadShapeTier::Explore, None)
    );
    // A re-leased attempt's later wake keeps the first wake's shape.
    let again = vault
        .stamp_read_shape(attempt, &model_a, seeded)
        .expect("later wake's stamp");
    assert_eq!(again, first);
    assert_eq!(vault.read_shape_stamp(attempt).expect("read"), Some(first));
    // An unknown attempt holds no stamp and takes none.
    let unknown = AttemptId::now();
    assert!(vault.stamp_read_shape(unknown, &model_a, seeded).is_err());
    assert!(vault.record_read_shape_units(unknown, 10).is_err());
    assert_eq!(vault.read_shape_stamp(unknown).expect("read"), None);
}

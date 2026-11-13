//! Default retrieval-policy updates keep tiny trials as offers; only an
//! explicit owner reward floor admits the same not-worse evidence.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::store::{
    GateDecisionId, RetrievalAction, RetrievalBlendSignal, RetrievalEndOutcome,
    RetrievalPolicyCandidate, RetrievalPolicyVerdict, RetrievalRunId, RetrievalRunRecord,
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalState,
    RetrievalTurn,
};
use oneiron::test_doors::retrieval_policy_default_floor::record_retrieval_run;
use oneiron::verbs::{
    EmptyRequest, RetrievalPolicyDisposition, RetrievalPolicyPinRequest,
    RetrievalPolicyTrainRequest, RetrievalPolicyView, retrieval_policy_get_as_owner,
    retrieval_policy_pin_as_owner, retrieval_policy_update_as_owner,
};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use std::collections::BTreeMap;

fn setup() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary retrieval-policy vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::device()).expect("open retrieval-policy vault");
    let id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");
    assert_eq!(owner.revalidate(&vault).expect("read owner binding"), id);
    (dir, vault, owner)
}

fn blend_run(turn: RetrievalTurn) -> RetrievalRunRecord {
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
        dispatch_attempt: None,
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

fn record_tiny_trial(vault: &Vault) {
    let turn = RetrievalTurn {
        turn_id: [7; 16],
        episode_id: [8; 16],
        turn_idx: 0,
    };
    // Of five identical accepted runs, the newest judges the other four.
    // Positive relevance credit therefore improves the held-out score too.
    let mut run_ids = Vec::new();
    for _ in 0..5 {
        let run = blend_run(turn);
        record_retrieval_run(vault, &run).expect("record finalized blend run");
        assert_eq!(
            vault.retrieval_run(run.run_id).expect("read run"),
            Some(run.clone()),
        );
        run_ids.push(run.run_id);
    }
    let label = RetrievalEndOutcome {
        retrieval_run_ids: run_ids.clone(),
        key: "terminal".to_owned(),
        turn_id: turn.turn_id,
        gate_score: 1.0,
        confirmed_fact_hit: true,
        latency_scale_us: 1,
        cost_weight: 0.0,
        metadata: BTreeMap::new(),
    };
    vault
        .record_retrieval_end_outcome(label.clone())
        .expect("record gated terminal rewards");
    for run_id in run_ids {
        let outcomes = vault.retrieval_outcomes(run_id).expect("read rewards");
        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(outcome.run_id, run_id);
        assert_eq!(outcome.key, label.key);
        assert_eq!(outcome.reward, Some(1.0));
        assert_eq!(outcome.accepted, Some(true));
        assert_eq!(outcome.metadata, label.metadata);
        let evidence = outcome.reward_evidence.as_ref().expect("gated evidence");
        assert_eq!(evidence.retrieval_run_ids, label.retrieval_run_ids);
        assert_eq!(evidence.turn_id, label.turn_id);
        assert_eq!(evidence.gate_score, label.gate_score);
        assert_eq!(evidence.confirmed_fact_hit, label.confirmed_fact_hit);
        assert_eq!(evidence.latency_scale_us, label.latency_scale_us);
        assert_eq!(evidence.cost_weight, label.cost_weight);
    }
}

fn pin_and_read_policy(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> RetrievalPolicyView {
    let pinned = retrieval_policy_pin_as_owner(
        memory,
        owner,
        RetrievalPolicyPinRequest {
            signal: Some(RetrievalBlendSignal::Recency),
            value: Some(0.25),
            read_shape: None,
        },
    )
    .expect("pin recency weight");
    let before = retrieval_policy_get_as_owner(memory, owner, EmptyRequest {})
        .expect("read served policy before update");
    assert_eq!(before.active.weights, pinned.active.weights);
    assert_eq!(before.pins, pinned.pins);
    assert_eq!(before.pins.len(), 1);
    assert_eq!(before.pins[0].signal, RetrievalBlendSignal::Recency);
    assert_eq!(before.pins[0].value, 0.25);
    before
}

fn assert_tiny_not_worse_evidence(candidate: &RetrievalPolicyCandidate) {
    assert_eq!(candidate.training_reward_count, 4);
    assert_eq!(candidate.held_out.reward_count, 1);
    assert_eq!(candidate.ungated_outcomes_skipped, 0);
    assert!(candidate.held_out.candidate_score > candidate.held_out.active_score);
}

#[test]
fn retrieval_policy_update_keeps_a_tiny_default_trial_as_an_offer() {
    let (_dir, vault, owner) = setup();
    record_tiny_trial(&vault);
    let memory = vault.memory(
        owner.actor_for_read(&vault).expect("owner actor"),
        EdgeActorClass::Human,
    );
    let before = pin_and_read_policy(&memory, &owner);

    let receipt =
        retrieval_policy_update_as_owner(&memory, &owner, RetrievalPolicyTrainRequest::default())
            .expect("offer tiny default trial");
    assert_tiny_not_worse_evidence(&receipt.candidate);
    assert_eq!(
        receipt.disposition,
        RetrievalPolicyDisposition::Offered,
        "default reward floor must keep a tiny trial as an offer",
    );
    assert_eq!(
        receipt.candidate.held_out.verdict,
        RetrievalPolicyVerdict::Insufficient,
    );
    assert_eq!(
        receipt.reason.as_deref(),
        Some("retrieval policy candidate lacks held-out evidence for admission"),
    );
    assert_ne!(receipt.candidate.weights, before.active.weights);
    assert_eq!(receipt.view.active.weights, before.active.weights);
    assert_eq!(receipt.view.pins, before.pins);
    let after = retrieval_policy_get_as_owner(&memory, &owner, EmptyRequest {})
        .expect("read served policy after offer");
    assert_eq!(after.active.weights, before.active.weights);
    assert_eq!(after.pins, before.pins);
}

#[test]
fn retrieval_policy_update_applies_a_tiny_trial_when_the_owner_lowers_the_floor() {
    let (_dir, vault, owner) = setup();
    record_tiny_trial(&vault);
    let memory = vault.memory(
        owner.actor_for_read(&vault).expect("owner actor"),
        EdgeActorClass::Human,
    );
    let before = pin_and_read_policy(&memory, &owner);

    let receipt = retrieval_policy_update_as_owner(
        &memory,
        &owner,
        RetrievalPolicyTrainRequest {
            min_reward_count: Some(1),
            ..Default::default()
        },
    )
    .expect("apply tiny owner-approved trial");
    assert_tiny_not_worse_evidence(&receipt.candidate);
    assert_eq!(receipt.disposition, RetrievalPolicyDisposition::Applied);
    assert_eq!(receipt.reason, None);
    assert_eq!(
        receipt.candidate.held_out.verdict,
        RetrievalPolicyVerdict::NotWorse,
    );
    assert_ne!(receipt.candidate.weights, before.active.weights);
    assert_eq!(receipt.view.active.weights, receipt.candidate.weights);
    assert_eq!(receipt.view.pins, before.pins);
    let after = retrieval_policy_get_as_owner(&memory, &owner, EmptyRequest {})
        .expect("read served policy after admission");
    assert_eq!(after.active.weights, receipt.candidate.weights);
    assert_eq!(after.pins, before.pins);
}

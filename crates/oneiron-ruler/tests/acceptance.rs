use std::collections::BTreeMap;

use oneiron_ruler::axes::{AxisComparison, AxisDirection, AxisError, AxisRole, axis_value};
use oneiron_ruler::bootstrap::{
    AxisBound, BootstrapError, SplitMix64, bootstrap_axis, paired_differences, paired_lower_bound,
    seed_from_pack_digest,
};
use oneiron_ruler::pack::Slice;
use oneiron_ruler::proposal::{
    HeldOutProposal, PROPOSAL_CONTRACT, ProposalError, ProposalStatus, ProposalStore,
    SEALED_OUTCOME_CONTRACT, SealedCheck, SealedOutcome, SealedVerdict, judge_sealed, proposal_id,
};
use oneiron_ruler::ruler_paths::{RulerPaths, RulerPathsError, SHIPPED_RULER_PATHS};
use oneiron_ruler::scorecard::{
    CategoryMin, Latency, Metrics, QueryScore, SCORECARD_CONTRACT, Scorecard,
};
use oneiron_ruler::sealed::{
    ExperimentIdentity, SealedError, claim_incumbent_once, claim_sealed_once,
};

fn card(
    slice: Slice,
    engine_commit: &str,
    params_digest: &str,
    pack_digest: &str,
    per_query: Vec<QueryScore>,
) -> Scorecard {
    Scorecard {
        contract: SCORECARD_CONTRACT.to_owned(),
        engine_commit: engine_commit.to_owned(),
        params_digest: params_digest.to_owned(),
        pack_id: "pack".to_owned(),
        revision: "1".to_owned(),
        pack_digest: pack_digest.to_owned(),
        slice,
        model_id: "model".to_owned(),
        budget_rows: 10,
        repeats: 1,
        query_count: per_query.len() as u32,
        metrics: Metrics {
            ndcg_at_10: 0.5,
            mrr: 0.5,
            recall_at_5: 0.5,
            recall_at_20: 0.5,
            recall_at_budget: 0.5,
            abstention_f1: 0.5,
        },
        per_category: BTreeMap::new(),
        per_category_min: BTreeMap::new(),
        latency: Latency {
            search_p50_us: 100,
            search_p95_us: 200,
            aa_p95_spread_us: None,
        },
        repeat_digest_equal: true,
        per_query,
    }
}

fn qs(id: &str, ndcg: Option<f64>) -> QueryScore {
    QueryScore {
        query_id: id.to_owned(),
        category: "cat".to_owned(),
        expect_empty: ndcg.is_none(),
        returned: 3,
        ndcg_at_10: ndcg,
        mrr: ndcg,
        recall_at_5: ndcg,
        recall_at_20: ndcg,
        recall_at_budget: ndcg,
        ranked_digest: None,
    }
}

fn identity(engine_commit: &str, params_digest: &str, pack_digest: &str) -> ExperimentIdentity {
    ExperimentIdentity {
        engine_commit: engine_commit.to_owned(),
        params_digest: params_digest.to_owned(),
        pack_digest: pack_digest.to_owned(),
    }
}

fn held_out(
    campaign_id: &str,
    incumbent: &ExperimentIdentity,
    candidate: &ExperimentIdentity,
) -> HeldOutProposal {
    HeldOutProposal {
        contract: PROPOSAL_CONTRACT.to_owned(),
        proposal_id: proposal_id(campaign_id, incumbent, candidate).expect("proposal id"),
        campaign_id: campaign_id.to_owned(),
        incumbent: incumbent.clone(),
        candidate: candidate.clone(),
        candidate_params: serde_json::json!({"budget_rows": 10}),
        incumbent_scorecard_sha256: "e".repeat(64),
        candidate_scorecard_sha256: "f".repeat(64),
        axes: vec![AxisComparison {
            axis: "ndcg_at_10".to_owned(),
            role: AxisRole::Primary,
            direction: AxisDirection::Higher,
            tolerance: 0.01,
            incumbent: 0.5,
            candidate: 0.6,
        }],
        bootstrap: vec![AxisBound {
            axis: "ndcg_at_10".to_owned(),
            pairs: 30,
            mean_difference: 0.1,
            lower_bound: 0.05,
        }],
        decided_at: 1_700_000_000,
    }
}

#[test]
fn splitmix64_seed_zero_gives_the_reference_first_output() {
    assert_eq!(SplitMix64::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
}

#[test]
fn thirty_wins_of_thirty_give_a_lower_bound_above_zero() {
    let mut differences = Vec::new();
    for i in 0..30_u32 {
        differences.push(0.01 * f64::from(1 + i % 5));
    }
    let bound = paired_lower_bound(&differences, 2000, 7).unwrap();
    assert!(bound > 0.0, "bound {bound}");
}

#[test]
fn one_lucky_query_of_thirty_gives_no_lower_bound_above_zero() {
    let mut differences = vec![0.0; 30];
    differences[29] = 1.0;
    let bound = paired_lower_bound(&differences, 2000, 7).unwrap();
    assert!(bound <= 0.0, "bound {bound}");
}

#[test]
fn the_bound_is_reproducible_and_seeded_from_the_pack_digest() {
    let differences = vec![0.1, -0.05, 0.2, 0.0, 0.15];
    let first = paired_lower_bound(&differences, 2000, 42).unwrap();
    let second = paired_lower_bound(&differences, 2000, 42).unwrap();
    assert_eq!(first.to_bits(), second.to_bits());
    let digest = "0123456789abcdef".to_owned() + &"0".repeat(48);
    assert_eq!(
        seed_from_pack_digest(&digest).unwrap(),
        0x0123_4567_89AB_CDEF
    );
    let upper = "0123456789ABCDEF".to_owned() + &"0".repeat(48);
    assert!(matches!(
        seed_from_pack_digest(&upper),
        Err(BootstrapError::BadDigest)
    ));
    assert!(matches!(
        seed_from_pack_digest(&"0".repeat(63)),
        Err(BootstrapError::BadDigest)
    ));
}

#[test]
fn paired_differences_pair_by_query_id_and_skip_abstention() {
    let incumbent = vec![qs("a", Some(0.2)), qs("b", None), qs("c", Some(0.4))];
    let candidate = vec![qs("c", Some(0.5)), qs("a", Some(0.3)), qs("b", None)];
    let differences = paired_differences(&incumbent, &candidate, "ndcg_at_10").unwrap();
    assert_eq!(differences.len(), 2);
    assert!((differences[0] - 0.1).abs() < 1e-12);
    assert!((differences[1] - 0.1).abs() < 1e-12);
    let extra = vec![
        qs("c", Some(0.5)),
        qs("a", Some(0.3)),
        qs("b", None),
        qs("d", Some(0.1)),
    ];
    assert!(matches!(
        paired_differences(&incumbent, &extra, "ndcg_at_10"),
        Err(BootstrapError::QuerySetMismatch { .. })
    ));
    let presence = vec![qs("c", Some(0.5)), qs("a", Some(0.3)), qs("b", Some(0.1))];
    assert!(matches!(
        paired_differences(&incumbent, &presence, "ndcg_at_10"),
        Err(BootstrapError::MetricPresenceMismatch { .. })
    ));
}

#[test]
fn bootstrap_axis_refuses_two_packs_and_the_sealed_slice() {
    let pack_a = "a".repeat(64);
    let pack_b = "b".repeat(64);
    let params = "c".repeat(64);
    let incumbent = card(
        Slice::HeldOut,
        "eng",
        &params,
        &pack_a,
        vec![qs("a", Some(0.2))],
    );
    let candidate = card(
        Slice::HeldOut,
        "eng",
        &params,
        &pack_b,
        vec![qs("a", Some(0.3))],
    );
    assert!(matches!(
        bootstrap_axis(&incumbent, &candidate, "ndcg_at_10"),
        Err(BootstrapError::PackMismatch)
    ));
    let sealed = card(
        Slice::Sealed,
        "eng",
        &params,
        &pack_a,
        vec![qs("a", Some(0.3))],
    );
    assert!(matches!(
        bootstrap_axis(&incumbent, &sealed, "ndcg_at_10"),
        Err(BootstrapError::NotHeldOut)
    ));
    let same_pack = card(
        Slice::HeldOut,
        "eng",
        &params,
        &pack_a,
        vec![qs("a", Some(0.3))],
    );
    assert!(matches!(
        bootstrap_axis(&incumbent, &same_pack, "abstention_f1"),
        Err(BootstrapError::NotPerQueryAxis { .. })
    ));
}

#[test]
fn a_second_sealed_claim_of_one_identity_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let id1 = identity("eng", &"a".repeat(64), &"b".repeat(64));
    let claim = claim_sealed_once(temp.path(), &id1).unwrap();
    let text = std::fs::read_to_string(&claim.path).unwrap();
    assert!(text.contains("\"spent\""));
    assert!(matches!(
        claim_sealed_once(temp.path(), &id1),
        Err(SealedError::AlreadySpent { .. })
    ));
    let id2 = identity("eng", &"c".repeat(64), &"b".repeat(64));
    assert!(claim_sealed_once(temp.path(), &id2).is_ok());
}

#[test]
fn a_campaign_measures_its_incumbent_on_sealed_once() {
    let temp = tempfile::tempdir().unwrap();
    let id1 = identity("eng", &"a".repeat(64), &"b".repeat(64));
    let id2 = identity("eng", &"c".repeat(64), &"b".repeat(64));
    assert!(claim_incumbent_once(temp.path(), "c1", &id1).is_ok());
    assert!(matches!(
        claim_incumbent_once(temp.path(), "c1", &id2),
        Err(SealedError::IncumbentAlreadyMeasured { .. })
    ));
    assert!(claim_incumbent_once(temp.path(), "c2", &id2).is_ok());
}

#[test]
fn ruler_paths_match_directories_by_prefix_and_files_exactly() {
    let ruler = RulerPaths::parse(SHIPPED_RULER_PATHS).unwrap();
    assert_eq!(
        ruler.entries(),
        &[
            "crates/oneiron-ruler/".to_owned(),
            "crates/oneiron-bench/src/scorecard/".to_owned(),
            "crates/oneiron/src/pipeline/builder_eval.rs".to_owned(),
            "crates/oneiron/src/autoreason_campaign/general.rs".to_owned(),
        ]
    );
    assert!(ruler.matches("crates/oneiron-ruler/src/pack.rs"));
    assert!(ruler.matches("crates/oneiron-bench/src/scorecard/run.rs"));
    assert!(!ruler.matches("crates/oneiron/src/pipeline/builder_eval.rs.orig"));
    assert!(!ruler.matches("crates/oneiron-bench/src/main.rs"));
    assert!(!ruler.matches("crates/oneiron-rulerx/a.rs"));
    let hits = ruler.touched(&[
        "crates/oneiron-bench/src/main.rs",
        "crates/oneiron-bench/src/scorecard/run.rs",
        "crates/oneiron-bench/src/scorecard/run.rs",
        "crates/oneiron/src/autoreason_campaign/general.rs",
    ]);
    assert_eq!(
        hits,
        vec![
            "crates/oneiron-bench/src/scorecard/run.rs".to_owned(),
            "crates/oneiron/src/autoreason_campaign/general.rs".to_owned(),
        ]
    );
    assert!(matches!(
        RulerPaths::parse("/abs\n"),
        Err(RulerPathsError::BadEntry { .. })
    ));
    assert!(matches!(
        RulerPaths::parse("a/../b\n"),
        Err(RulerPathsError::BadEntry { .. })
    ));
    assert!(matches!(
        RulerPaths::parse("# only a comment\n\n"),
        Err(RulerPathsError::Empty)
    ));
}

#[test]
fn axis_values_read_the_scorecard() {
    let params = "c".repeat(64);
    let pack = "d".repeat(64);
    let mut scorecard = card(Slice::HeldOut, "eng", &params, &pack, Vec::new());
    scorecard.metrics.ndcg_at_10 = 0.75;
    assert!((axis_value(&scorecard, "ndcg_at_10").unwrap() - 0.75).abs() < 1e-12);
    assert!((axis_value(&scorecard, "repeat_digest_equal").unwrap() - 1.0).abs() < 1e-12);
    scorecard.repeat_digest_equal = false;
    assert!((axis_value(&scorecard, "repeat_digest_equal").unwrap() - 0.0).abs() < 1e-12);
    scorecard.per_category_min.insert(
        "ndcg_at_10".to_owned(),
        CategoryMin {
            category: "cat".to_owned(),
            value: 0.25,
        },
    );
    assert!((axis_value(&scorecard, "min_ndcg_at_10").unwrap() - 0.25).abs() < 1e-12);
    assert!((axis_value(&scorecard, "search_p95_us").unwrap() - 200.0).abs() < 1e-12);
    assert!(matches!(
        axis_value(&scorecard, "min_mrr"),
        Err(AxisError::MissingCategoryMin { .. })
    ));
    assert!(matches!(
        axis_value(&scorecard, "nope"),
        Err(AxisError::UnknownAxis { .. })
    ));
}

#[test]
fn the_sealed_check_withdraws_only_on_a_primary_or_floor_loss_beyond_tolerance() {
    let loss = AxisComparison {
        axis: "ndcg_at_10".to_owned(),
        role: AxisRole::Primary,
        direction: AxisDirection::Higher,
        tolerance: 0.01,
        incumbent: 0.5,
        candidate: 0.48,
    };
    let (verdict, losses, reason) = judge_sealed(&[loss]).unwrap();
    assert!(matches!(verdict, SealedVerdict::Withdrawn));
    assert_eq!(losses.len(), 1);
    assert!(reason.as_ref().unwrap().contains("ndcg_at_10"));
    let loose = AxisComparison {
        axis: "ndcg_at_10".to_owned(),
        role: AxisRole::Primary,
        direction: AxisDirection::Higher,
        tolerance: 0.05,
        incumbent: 0.5,
        candidate: 0.48,
    };
    let (verdict, losses, reason) = judge_sealed(&[loose]).unwrap();
    assert!(matches!(verdict, SealedVerdict::Passed));
    assert!(losses.is_empty());
    assert!(reason.is_none());
    let cost = AxisComparison {
        axis: "search_p95_us".to_owned(),
        role: AxisRole::Cost,
        direction: AxisDirection::Lower,
        tolerance: 0.0,
        incumbent: 100.0,
        candidate: 300.0,
    };
    let (verdict, _, reason) = judge_sealed(&[cost]).unwrap();
    assert!(matches!(verdict, SealedVerdict::Passed));
    assert!(reason.is_none());
    let floor = AxisComparison {
        axis: "min_mrr".to_owned(),
        role: AxisRole::Floor,
        direction: AxisDirection::Lower,
        tolerance: 1.0,
        incumbent: 100.0,
        candidate: 200.0,
    };
    let (verdict, losses, _) = judge_sealed(&[floor]).unwrap();
    assert!(matches!(verdict, SealedVerdict::Withdrawn));
    assert_eq!(losses.len(), 1);
}

#[test]
fn a_withdrawn_proposal_stays_listed_and_a_stamp_records_the_override() {
    let temp = tempfile::tempdir().unwrap();
    let store = ProposalStore::open(temp.path()).unwrap();
    let pack = "d".repeat(64);
    let incumbent = identity("eng1", &"a".repeat(64), &pack);
    let candidate = identity("eng2", &"b".repeat(64), &pack);
    let proposal = held_out("campaign", &incumbent, &candidate);
    let id = proposal.proposal_id.clone();
    store.put_held_out(&proposal).unwrap();
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(matches!(listed[0].status, ProposalStatus::AwaitingSealed));
    let incumbent_sealed = card(
        Slice::Sealed,
        "eng1",
        &incumbent.params_digest,
        &pack,
        Vec::new(),
    );
    let candidate_sealed = card(
        Slice::Sealed,
        "eng2",
        &candidate.params_digest,
        &pack,
        Vec::new(),
    );
    let loss = AxisComparison {
        axis: "ndcg_at_10".to_owned(),
        role: AxisRole::Primary,
        direction: AxisDirection::Higher,
        tolerance: 0.01,
        incumbent: 0.5,
        candidate: 0.47,
    };
    let (verdict, losses, reason) = judge_sealed(&[loss]).unwrap();
    assert!(matches!(verdict, SealedVerdict::Withdrawn));
    let outcome = SealedOutcome {
        contract: SEALED_OUTCOME_CONTRACT.to_owned(),
        proposal_id: id.clone(),
        verdict,
        reason,
        losses,
        incumbent_sealed: incumbent_sealed.clone(),
        candidate_sealed: candidate_sealed.clone(),
        judged_at: 1_700_000_001,
    };
    store.put_sealed(&outcome).unwrap();
    let listing = store.get(&id).unwrap();
    assert!(matches!(listing.status, ProposalStatus::Withdrawn));
    assert!(listing.reason.is_some());
    let sealed = listing.sealed.as_ref().unwrap();
    assert_eq!(sealed.incumbent_sealed, incumbent_sealed);
    assert_eq!(sealed.candidate_sealed, candidate_sealed);
    assert!(matches!(
        store.put_sealed(&outcome),
        Err(ProposalError::SealedOutcomeExists { .. })
    ));
    let stamp = store
        .put_stamp(&id, 1_700_000_002, "owner override")
        .unwrap();
    assert!(matches!(stamp.sealed_check, SealedCheck::Overridden));
    assert!(matches!(
        store.put_stamp(&id, 1_700_000_003, "again"),
        Err(ProposalError::StampExists { .. })
    ));
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].stamp.is_some());
}

#[test]
fn a_stamp_before_the_sealed_run_records_not_run_and_a_passed_check_records_passed() {
    let temp = tempfile::tempdir().unwrap();
    let store = ProposalStore::open(temp.path()).unwrap();
    let pack = "d".repeat(64);
    let incumbent = identity("eng1", &"a".repeat(64), &pack);
    let early_candidate = identity("eng2", &"b".repeat(64), &pack);
    let passed_candidate = identity("eng2", &"c".repeat(64), &pack);
    let early = held_out("campaign", &incumbent, &early_candidate);
    let passed = held_out("campaign", &incumbent, &passed_candidate);
    store.put_held_out(&early).unwrap();
    store.put_held_out(&passed).unwrap();
    let stamp = store
        .put_stamp(&early.proposal_id, 1_700_000_000, "early")
        .unwrap();
    assert!(matches!(stamp.sealed_check, SealedCheck::NotRun));
    let outcome = SealedOutcome {
        contract: SEALED_OUTCOME_CONTRACT.to_owned(),
        proposal_id: passed.proposal_id.clone(),
        verdict: SealedVerdict::Passed,
        reason: None,
        losses: Vec::new(),
        incumbent_sealed: card(
            Slice::Sealed,
            "eng1",
            &incumbent.params_digest,
            &pack,
            Vec::new(),
        ),
        candidate_sealed: card(
            Slice::Sealed,
            "eng2",
            &passed_candidate.params_digest,
            &pack,
            Vec::new(),
        ),
        judged_at: 1_700_000_001,
    };
    store.put_sealed(&outcome).unwrap();
    let stamp = store
        .put_stamp(&passed.proposal_id, 1_700_000_002, "after sealed")
        .unwrap();
    assert!(matches!(stamp.sealed_check, SealedCheck::Passed));
}

#[test]
fn the_store_refuses_a_wrong_identity_and_a_bad_id() {
    let temp = tempfile::tempdir().unwrap();
    let store = ProposalStore::open(temp.path()).unwrap();
    let pack = "d".repeat(64);
    let incumbent = identity("eng1", &"a".repeat(64), &pack);
    let candidate = identity("eng2", &"b".repeat(64), &pack);
    let proposal = held_out("campaign", &incumbent, &candidate);
    store.put_held_out(&proposal).unwrap();
    let outcome = SealedOutcome {
        contract: SEALED_OUTCOME_CONTRACT.to_owned(),
        proposal_id: proposal.proposal_id.clone(),
        verdict: SealedVerdict::Passed,
        reason: None,
        losses: Vec::new(),
        incumbent_sealed: card(
            Slice::Sealed,
            "eng1",
            &incumbent.params_digest,
            &pack,
            Vec::new(),
        ),
        candidate_sealed: card(Slice::Sealed, "eng2", &"9".repeat(64), &pack, Vec::new()),
        judged_at: 1_700_000_001,
    };
    assert!(matches!(
        store.put_sealed(&outcome),
        Err(ProposalError::IdentityMismatch { .. })
    ));
    let mut bad = proposal;
    bad.proposal_id = "0".repeat(64);
    assert!(matches!(
        store.put_held_out(&bad),
        Err(ProposalError::ProposalIdMismatch)
    ));
    assert!(matches!(
        store.get("../x"),
        Err(ProposalError::BadProposalId)
    ));
}

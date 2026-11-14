//! An interrupted record write (a full disk, a crash) leaves the proposal readable and the write retryable
//! (#7794 review round 1). One test in this binary: the file-size limit and the SIGXFSZ disposition it changes are
//! process-wide.
#![cfg(unix)]

use std::collections::BTreeMap;

use oneiron_ruler::axes::{AxisComparison, AxisDirection, AxisRole};
use oneiron_ruler::bootstrap::AxisBound;
use oneiron_ruler::pack::Slice;
use oneiron_ruler::proposal::{
    HeldOutProposal, PROPOSAL_CONTRACT, ProposalError, ProposalStatus, ProposalStore,
    SEALED_OUTCOME_CONTRACT, SealedCheck, SealedOutcome, SealedVerdict, judge_sealed, proposal_id,
};
use oneiron_ruler::scorecard::{Latency, Metrics, SCORECARD_CONTRACT, Scorecard};
use oneiron_ruler::sealed::ExperimentIdentity;

fn identity(engine_commit: &str, params_digest: &str, pack_digest: &str) -> ExperimentIdentity {
    ExperimentIdentity {
        engine_commit: engine_commit.to_owned(),
        params_digest: params_digest.to_owned(),
        pack_digest: pack_digest.to_owned(),
    }
}

fn sealed_card(engine_commit: &str, params_digest: &str, pack_digest: &str) -> Scorecard {
    Scorecard {
        contract: SCORECARD_CONTRACT.to_owned(),
        engine_commit: engine_commit.to_owned(),
        params_digest: params_digest.to_owned(),
        pack_id: "pack".to_owned(),
        revision: "1".to_owned(),
        pack_digest: pack_digest.to_owned(),
        slice: Slice::Sealed,
        model_id: "model".to_owned(),
        budget_rows: 10,
        repeats: 1,
        query_count: 0,
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
        per_query: Vec::new(),
    }
}

fn held_out(incumbent: &ExperimentIdentity, candidate: &ExperimentIdentity) -> HeldOutProposal {
    HeldOutProposal {
        contract: PROPOSAL_CONTRACT.to_owned(),
        proposal_id: proposal_id("campaign", incumbent, candidate).expect("proposal id"),
        campaign_id: "campaign".to_owned(),
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

/// Runs `write` with RLIMIT_FSIZE lowered to `limit` bytes and SIGXFSZ ignored, so a write past `limit` fails with
/// EFBIG part way through, as on a full disk. The saved limit is restored before this returns.
fn with_file_size_limit<T>(limit: libc::rlim_t, write: impl FnOnce() -> T) -> T {
    let mut saved = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit through a valid pointer to a local.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut saved) };
    assert_eq!(read, 0, "getrlimit");
    // SAFETY: SIG_IGN is a valid disposition for SIGXFSZ, and this binary installs no SIGXFSZ handler of its own.
    let previous = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    assert_ne!(previous, libc::SIG_ERR, "ignore SIGXFSZ");
    let lowered = libc::rlimit {
        rlim_cur: limit.min(saved.rlim_max),
        rlim_max: saved.rlim_max,
    };
    // SAFETY: setrlimit reads one rlimit through a valid pointer to a local; the soft limit stays at or under the
    // unchanged hard limit.
    let lower = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &lowered) };
    assert_eq!(lower, 0, "lower RLIMIT_FSIZE");
    let out = write();
    // SAFETY: as above; the saved soft limit is at or under the unchanged hard limit.
    let restore = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &saved) };
    assert_eq!(restore, 0, "restore RLIMIT_FSIZE");
    out
}

#[test]
fn an_interrupted_sealed_write_leaves_the_proposal_readable_and_the_write_retryable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProposalStore::open(temp.path()).expect("open the store");
    let pack = "d".repeat(64);
    let incumbent = identity("eng1", &"a".repeat(64), &pack);
    let candidate = identity("eng2", &"b".repeat(64), &pack);
    let proposal = held_out(&incumbent, &candidate);
    let id = proposal.proposal_id.clone();
    store.put_held_out(&proposal).expect("store held_out");
    let (verdict, losses, reason) = judge_sealed(&[AxisComparison {
        axis: "ndcg_at_10".to_owned(),
        role: AxisRole::Primary,
        direction: AxisDirection::Higher,
        tolerance: 0.01,
        incumbent: 0.5,
        candidate: 0.47,
    }])
    .expect("judge");
    assert_eq!(verdict, SealedVerdict::Withdrawn);
    let outcome = SealedOutcome {
        contract: SEALED_OUTCOME_CONTRACT.to_owned(),
        proposal_id: id.clone(),
        verdict,
        reason,
        losses,
        incumbent_sealed: sealed_card("eng1", &incumbent.params_digest, &pack),
        candidate_sealed: sealed_card("eng2", &candidate.params_digest, &pack),
        judged_at: 1_700_000_001,
    };

    // The record (two whole scorecards) is far over 64 bytes: the write stops part way.
    let interrupted = with_file_size_limit(64, || store.put_sealed(&outcome));
    assert!(
        matches!(interrupted, Err(ProposalError::Io { .. })),
        "the interrupted write fails: {interrupted:?}"
    );
    let listing = store
        .get(&id)
        .expect("the proposal still reads after the interrupted write");
    assert_eq!(listing.status, ProposalStatus::AwaitingSealed);
    assert!(listing.sealed.is_none());
    assert_eq!(store.list().expect("the owner's list still reads").len(), 1);

    store
        .put_sealed(&outcome)
        .expect("the sealed write can be retried");
    let listing = store.get(&id).expect("read after the retry");
    assert_eq!(listing.status, ProposalStatus::Withdrawn);
    assert_eq!(listing.sealed.as_ref(), Some(&outcome));
    let stamp = store
        .put_stamp(&id, 1_700_000_002, "owner override")
        .expect("the owner's stamp is stored");
    assert_eq!(stamp.sealed_check, SealedCheck::Overridden);

    // Neither the failed write nor the retry leaves a temporary file beside the records.
    let mut names: Vec<String> = std::fs::read_dir(temp.path().join(&id))
        .expect("read the proposal directory")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["held_out.json", "sealed.json", "stamp.json"]);
}

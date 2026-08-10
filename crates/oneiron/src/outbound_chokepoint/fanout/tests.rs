//! Fan-out admission tests. Everything here is pure: no vault, no transport,
//! and a recording executor that proves nothing downstream ever runs before
//! admission says it may.

use std::cell::Cell;

use super::*;

const NOW_MS: u64 = 1_770_000_000_000;

fn plan_with(mode: FanoutApprovalMode, edges: &[(&str, &str, u32)]) -> FanoutPlan {
    FanoutPlan {
        plan_ref: "plan-1".to_owned(),
        brief_ref: "brief-1".to_owned(),
        actor_ref: "actor-1".to_owned(),
        mode,
        edges: edges
            .iter()
            .map(|(from, to, count)| FanoutPlanEdge {
                from_peer_ref: (*from).to_owned(),
                to_peer_ref: (*to).to_owned(),
                count: *count,
            })
            .collect(),
    }
}

/// A plan whose total is exactly `total`, spread over one edge.
fn plan_of_total(mode: FanoutApprovalMode, total: u32) -> FanoutPlan {
    if total == 0 {
        return plan_with(mode, &[]);
    }
    plan_with(mode, &[("peer_a", "peer_b", total)])
}

/// A star plan: one actor consulting `width` distinct peers once each.
fn star_plan(mode: FanoutApprovalMode, width: u32) -> FanoutPlan {
    let refs: Vec<(String, String)> = (0..width)
        .map(|index| ("peer_hub".to_owned(), format!("peer_{index:03}")))
        .collect();
    let edges: Vec<(&str, &str, u32)> = refs
        .iter()
        .map(|(from, to)| (from.as_str(), to.as_str(), 1))
        .collect();
    plan_with(mode, &edges)
}

#[derive(Default)]
struct RecordingSink {
    rows: Vec<FanoutApprovalRow>,
    receipts: Vec<ReceiptRecord>,
    blank_row_ref: bool,
}

impl FanoutSurfaceSink for RecordingSink {
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String> {
        self.rows.push(row.clone());
        if self.blank_row_ref {
            return Ok(String::new());
        }
        Ok(format!("durable:{}", row.row_ref))
    }

    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String> {
        self.receipts.push(receipt.clone());
        Ok(format!("receipt:{}", receipt.receipt_id))
    }
}

/// `answer: None` models a missing or failing classifier.
struct RecordingDecider {
    answer: Option<FanoutAutoDisposition>,
    calls: Cell<usize>,
}

impl RecordingDecider {
    fn allow() -> Self {
        Self {
            answer: Some(FanoutAutoDisposition::Allow),
            calls: Cell::new(0),
        }
    }

    fn surface() -> Self {
        Self {
            answer: Some(FanoutAutoDisposition::SurfaceHuman),
            calls: Cell::new(0),
        }
    }

    fn failing() -> Self {
        Self {
            answer: None,
            calls: Cell::new(0),
        }
    }
}

impl FanoutAutoDecider for RecordingDecider {
    fn decide(
        &self,
        _plan: &FanoutPlan,
        _estimate: &FanoutEstimate,
    ) -> Result<FanoutAutoDisposition> {
        self.calls.set(self.calls.get() + 1);
        self.answer
            .ok_or_else(|| Error::InvalidConfig("classifier unavailable".to_owned()))
    }
}

/// Stands in for everything downstream of admission — per-peer TASK creation
/// and transport alike. It runs only through the two doors admission opens.
#[derive(Default)]
struct RecordingExecutor {
    started: Vec<String>,
}

impl RecordingExecutor {
    fn run_admitted(&mut self, plan: &FanoutPlan, admission: &FanoutAdmission) {
        if matches!(admission, FanoutAdmission::Proceed { .. }) {
            self.started.push(plan.plan_ref.clone());
        }
    }

    fn run_resumed(&mut self, plan: &FanoutPlan, resume: Option<&FanoutResume>) {
        if resume.is_some() {
            self.started.push(plan.plan_ref.clone());
        }
    }
}

fn paused_row(admission: &FanoutAdmission) -> &FanoutApprovalRow {
    match admission {
        FanoutAdmission::Paused { row, .. } => row,
        FanoutAdmission::Proceed { .. } => panic!("expected a paused fan-out admission"),
    }
}

fn action_id_for(row: &FanoutApprovalRow, choice: &FanoutApprovalChoice) -> String {
    row.actions
        .iter()
        .find(|action| action.choice == *choice)
        .expect("the row offers every choice")
        .action_id
        .clone()
}

/// The pinned preimage, rebuilt by hand: domain, four length-prefixed scalars,
/// the peer-set length plus length-prefixed peers, then the edge-list length
/// plus length-prefixed endpoints with a fixed-width count.
fn expected_digest(
    plan_ref: &str,
    brief_ref: &str,
    actor_ref: &str,
    mode_token: &str,
    peers: &[&str],
    edges: &[(&str, &str, u32)],
) -> [u8; 32] {
    let mut preimage: Vec<u8> = Vec::new();
    preimage.extend_from_slice(b"oneiron.fanout.plan.v1\0");
    for scalar in [plan_ref, brief_ref, actor_ref, mode_token] {
        preimage.extend_from_slice(&(scalar.len() as u64).to_be_bytes());
        preimage.extend_from_slice(scalar.as_bytes());
    }
    preimage.extend_from_slice(&(peers.len() as u64).to_be_bytes());
    for peer in peers {
        preimage.extend_from_slice(&(peer.len() as u64).to_be_bytes());
        preimage.extend_from_slice(peer.as_bytes());
    }
    preimage.extend_from_slice(&(edges.len() as u64).to_be_bytes());
    for (from, to, count) in edges {
        preimage.extend_from_slice(&(from.len() as u64).to_be_bytes());
        preimage.extend_from_slice(from.as_bytes());
        preimage.extend_from_slice(&(to.len() as u64).to_be_bytes());
        preimage.extend_from_slice(to.as_bytes());
        preimage.extend_from_slice(&count.to_be_bytes());
    }
    *blake3::hash(&preimage).as_bytes()
}

#[test]
fn fanout_estimate_is_deterministic_total_plus_per_peer() {
    let ordered = plan_with(
        FanoutApprovalMode::Auto,
        &[
            ("peer_a", "peer_b", 2),
            ("peer_a", "peer_c", 3),
            ("peer_b", "peer_c", 1),
        ],
    );
    let shuffled = plan_with(
        FanoutApprovalMode::Auto,
        &[
            ("peer_b", "peer_c", 1),
            ("peer_a", "peer_c", 3),
            ("peer_a", "peer_b", 2),
        ],
    );

    let estimate = fanout_estimate(&ordered).expect("ordered plan meters");
    let shuffled_estimate = fanout_estimate(&shuffled).expect("shuffled plan meters");
    assert_eq!(estimate, shuffled_estimate);
    assert_eq!(estimate.total_count, 6);
    assert_eq!(
        estimate.per_peer,
        BTreeMap::from([("peer_b".to_owned(), 2), ("peer_c".to_owned(), 4)]),
        "the breakdown is keyed by the receiving peer and sums to the total"
    );
    assert_eq!(
        estimate.total_count,
        estimate.per_peer.values().sum::<u32>()
    );

    // The fixture locks the length-prefixed scalar/peer/edge preimage.
    assert_eq!(
        estimate.plan_digest,
        expected_digest(
            "plan-1",
            "brief-1",
            "actor-1",
            "auto",
            &["peer_a", "peer_b", "peer_c"],
            &[
                ("peer_a", "peer_b", 2),
                ("peer_a", "peer_c", 3),
                ("peer_b", "peer_c", 1),
            ],
        )
    );
    assert_eq!(
        fanout_plan_digest(&shuffled).expect("digest"),
        estimate.plan_digest
    );

    // Malformed and overflowing plans fail before admission: no metering
    // answer, no surface row, no classifier call.
    let overflow = plan_with(
        FanoutApprovalMode::Auto,
        &[("peer_a", "peer_b", u32::MAX), ("peer_a", "peer_c", 1)],
    );
    let zero_count = plan_with(FanoutApprovalMode::Auto, &[("peer_a", "peer_b", 0)]);
    let blank_ref = plan_with(FanoutApprovalMode::Auto, &[("peer_a", "   ", 1)]);
    for malformed in [&overflow, &zero_count, &blank_ref] {
        assert!(fanout_estimate(malformed).is_err());
        assert!(fanout_plan_digest(malformed).is_err());

        let mut sink = RecordingSink::default();
        let decider = RecordingDecider::allow();
        let executor = RecordingExecutor::default();
        let admission = admit_fanout_plan(malformed, None, &[], &decider, &mut sink, NOW_MS);
        assert!(admission.is_err(), "malformed plan data is never admitted");
        assert!(sink.rows.is_empty());
        assert_eq!(decider.calls.get(), 0);
        assert!(executor.started.is_empty());
        drop(executor);
    }
}

#[test]
fn fanout_at_or_below_default_25_is_silent() {
    assert_eq!(DEFAULT_FANOUT_APPROVAL_THRESHOLD, 25);

    for total in 0..=DEFAULT_FANOUT_APPROVAL_THRESHOLD {
        // Manual mode would surface if the ladder were reached at all.
        let plan = plan_of_total(FanoutApprovalMode::Manual, total);
        let mut sink = RecordingSink::default();
        let decider = RecordingDecider::surface();
        let admission = admit_fanout_plan(&plan, None, &[], &decider, &mut sink, NOW_MS)
            .expect("silent fan-out admits");
        match admission {
            FanoutAdmission::Proceed { estimate } => {
                assert_eq!(estimate.total_count, total);
                assert_eq!(estimate.per_peer.values().sum::<u32>(), total);
                assert!(!estimate.plan_digest.is_empty());
            }
            FanoutAdmission::Paused { .. } => panic!("{total} is at or below the threshold"),
        }
        assert!(sink.rows.is_empty(), "a silent fan-out writes no row");
        assert_eq!(decider.calls.get(), 0);
    }

    let over = plan_of_total(FanoutApprovalMode::Manual, 26);
    let mut sink = RecordingSink::default();
    let decider = RecordingDecider::surface();
    let admission = admit_fanout_plan(&over, None, &[], &decider, &mut sink, NOW_MS)
        .expect("over-threshold fan-out admits");
    assert!(matches!(admission, FanoutAdmission::Paused { .. }));
    assert_eq!(sink.rows.len(), 1, "26 enters the ladder");
}

#[test]
fn r5v2_modes_are_exact_and_auto_is_default() {
    assert_eq!(FanoutApprovalMode::Manual.as_str(), "manual");
    assert_eq!(FanoutApprovalMode::FullAccess.as_str(), "full-access");
    assert_eq!(FanoutApprovalMode::Auto.as_str(), "auto");
    assert_eq!(FanoutApprovalMode::default(), FanoutApprovalMode::Auto);
    for mode in [
        FanoutApprovalMode::Auto,
        FanoutApprovalMode::FullAccess,
        FanoutApprovalMode::Manual,
    ] {
        assert_eq!(FanoutApprovalMode::parse(mode.as_str()), Some(mode));
        assert_eq!(
            serde_json::to_string(&mode).expect("mode serializes"),
            format!("\"{}\"", mode.as_str())
        );
    }
    assert_eq!(FanoutApprovalMode::parse("full_access"), None);

    let over = 26;
    let mut full_sink = RecordingSink::default();
    let full = admit_fanout_plan(
        &plan_of_total(FanoutApprovalMode::FullAccess, over),
        None,
        &[],
        &RecordingDecider::surface(),
        &mut full_sink,
        NOW_MS,
    )
    .expect("full-access admits");
    assert!(matches!(full, FanoutAdmission::Proceed { .. }));
    assert!(full_sink.rows.is_empty());

    let mut manual_sink = RecordingSink::default();
    let manual = admit_fanout_plan(
        &plan_of_total(FanoutApprovalMode::Manual, over),
        None,
        &[],
        &RecordingDecider::allow(),
        &mut manual_sink,
        NOW_MS,
    )
    .expect("manual admits");
    assert!(matches!(manual, FanoutAdmission::Paused { .. }));
    assert_eq!(manual_sink.rows.len(), 1);
    assert_eq!(paused_row(&manual).mode, FanoutApprovalMode::Manual);

    for (decider, pauses) in [
        (RecordingDecider::allow(), false),
        (RecordingDecider::surface(), true),
    ] {
        let mut sink = RecordingSink::default();
        let admission = admit_fanout_plan(
            &plan_of_total(FanoutApprovalMode::Auto, over),
            None,
            &[],
            &decider,
            &mut sink,
            NOW_MS,
        )
        .expect("auto admits");
        assert_eq!(decider.calls.get(), 1, "auto asks the injected classifier");
        assert_eq!(
            matches!(admission, FanoutAdmission::Paused { .. }),
            pauses,
            "auto follows the injected disposition"
        );
    }
}

#[test]
fn auto_failure_escalates_instead_of_allowing_or_killing() {
    let plan = plan_of_total(FanoutApprovalMode::Auto, 40);
    let mut sink = RecordingSink::default();
    let decider = RecordingDecider::failing();
    let mut executor = RecordingExecutor::default();

    let admission = admit_fanout_plan(&plan, None, &[], &decider, &mut sink, NOW_MS)
        .expect("a classifier failure is not an admission error");
    executor.run_admitted(&plan, &admission);

    assert_eq!(decider.calls.get(), 1);
    assert!(matches!(admission, FanoutAdmission::Paused { .. }));
    assert_eq!(sink.rows.len(), 1, "exactly one paused surface row");
    assert!(sink.receipts.is_empty());
    assert!(
        executor.started.is_empty(),
        "a failed classifier neither allows nor kills"
    );
}

#[test]
fn consult_cycle_pauses_before_threshold_logic() {
    // Total 3 — far below the threshold — and full-access mode, so only
    // pathology can pause this.
    let plan = plan_with(
        FanoutApprovalMode::FullAccess,
        &[
            ("peer_b", "peer_c", 1),
            ("peer_c", "peer_a", 1),
            ("peer_a", "peer_b", 1),
        ],
    );
    let mut sink = RecordingSink::default();
    let decider = RecordingDecider::allow();
    let mut executor = RecordingExecutor::default();

    let admission = admit_fanout_plan(&plan, None, &[], &decider, &mut sink, NOW_MS)
        .expect("a cycle pauses rather than erroring");
    executor.run_admitted(&plan, &admission);

    let row = paused_row(&admission);
    assert_eq!(row.estimate.total_count, 3);
    assert_eq!(
        row.pathology,
        Some(FanoutPathology::ConsultCycle {
            peer_path: vec![
                "peer_a".to_owned(),
                "peer_b".to_owned(),
                "peer_c".to_owned(),
                "peer_a".to_owned(),
            ],
        }),
        "the row names the concrete peer path"
    );
    assert_eq!(decider.calls.get(), 0, "pathology runs before ladder logic");
    assert!(executor.started.is_empty(), "no plan edge executes");

    // A self-consult is the degenerate cycle, and it is caught too.
    let mut self_sink = RecordingSink::default();
    let self_plan = plan_with(FanoutApprovalMode::FullAccess, &[("peer_a", "peer_a", 1)]);
    let self_admission = admit_fanout_plan(
        &self_plan,
        None,
        &[],
        &RecordingDecider::allow(),
        &mut self_sink,
        NOW_MS,
    )
    .expect("self-consult pauses");
    assert_eq!(
        paused_row(&self_admission).pathology,
        Some(FanoutPathology::ConsultCycle {
            peer_path: vec!["peer_a".to_owned(), "peer_a".to_owned()],
        })
    );
}

#[test]
fn per_peer_rate_spike_pauses_with_evidence() {
    let plan = plan_with(FanoutApprovalMode::FullAccess, &[("peer_a", "peer_b", 5)]);
    let snapshot = PeerRateSnapshot {
        peer_ref: "peer_b".to_owned(),
        window_secs: 3_600,
        observed_count: 8,
        spike_at: 10,
    };
    let mut sink = RecordingSink::default();
    let mut executor = RecordingExecutor::default();

    let admission = admit_fanout_plan(
        &plan,
        None,
        std::slice::from_ref(&snapshot),
        &RecordingDecider::allow(),
        &mut sink,
        NOW_MS,
    )
    .expect("a rate spike pauses rather than erroring");
    executor.run_admitted(&plan, &admission);

    assert_eq!(
        paused_row(&admission).pathology,
        Some(FanoutPathology::PerPeerRateSpike {
            peer_ref: "peer_b".to_owned(),
            projected_count: 13,
            spike_at: 10,
            window_secs: 3_600,
        }),
        "the row surfaces projected, threshold, and window values"
    );
    assert!(executor.started.is_empty());
    assert!(
        sink.receipts.is_empty(),
        "detection pauses for judgment; it charges nothing and refuses nothing"
    );

    // No snapshot invents no cap: the same 5-per-peer plan, and a far larger
    // one, proceed on rate evidence alone.
    let mut silent_sink = RecordingSink::default();
    let unspiked = admit_fanout_plan(
        &plan,
        None,
        &[],
        &RecordingDecider::allow(),
        &mut silent_sink,
        NOW_MS,
    )
    .expect("no evidence admits");
    assert!(matches!(unspiked, FanoutAdmission::Proceed { .. }));
    assert!(silent_sink.rows.is_empty());

    let heavy = plan_with(FanoutApprovalMode::FullAccess, &[("peer_a", "peer_b", 400)]);
    let mut heavy_sink = RecordingSink::default();
    let heavy_admission = admit_fanout_plan(
        &heavy,
        None,
        &[],
        &RecordingDecider::allow(),
        &mut heavy_sink,
        NOW_MS,
    )
    .expect("no evidence admits");
    assert!(matches!(heavy_admission, FanoutAdmission::Proceed { .. }));

    // Snapshots naming peers the plan never touches are simply unused.
    let unrelated = PeerRateSnapshot {
        peer_ref: "peer_z".to_owned(),
        window_secs: 60,
        observed_count: 900,
        spike_at: 1,
    };
    let mut unrelated_sink = RecordingSink::default();
    let unrelated_admission = admit_fanout_plan(
        &plan,
        None,
        std::slice::from_ref(&unrelated),
        &RecordingDecider::allow(),
        &mut unrelated_sink,
        NOW_MS,
    )
    .expect("an unrelated snapshot admits");
    assert!(matches!(
        unrelated_admission,
        FanoutAdmission::Proceed { .. }
    ));
}

#[test]
fn pathology_never_silent_kills_and_resumes_on_approve() {
    let cycle = plan_with(
        FanoutApprovalMode::FullAccess,
        &[("peer_a", "peer_b", 1), ("peer_b", "peer_a", 1)],
    );
    let spike = plan_with(FanoutApprovalMode::FullAccess, &[("peer_a", "peer_b", 5)]);
    let spike_rates = [PeerRateSnapshot {
        peer_ref: "peer_b".to_owned(),
        window_secs: 900,
        observed_count: 0,
        spike_at: 5,
    }];

    for (plan, rates) in [
        (&cycle, &[][..]),
        (&spike, &spike_rates[..]),
    ] {
        let mut sink = RecordingSink::default();
        let mut executor = RecordingExecutor::default();
        let admission = admit_fanout_plan(
            plan,
            None,
            rates,
            &RecordingDecider::allow(),
            &mut sink,
            NOW_MS,
        )
        .expect("pathology pauses");
        executor.run_admitted(plan, &admission);
        let row = paused_row(&admission);
        assert!(row.pathology.is_some());
        assert!(
            executor.started.is_empty(),
            "the plan stays paused until a matching approval arrives"
        );

        let approve_once = FanoutApprovalChoice::ApproveOnce;
        let action_id = action_id_for(row, &approve_once);
        let resume = approve_and_resume_fanout(
            plan,
            row,
            approve_once,
            &action_id,
            "owner-1",
            &mut sink,
            NOW_MS + 1_000,
        )
        .expect("a matching plan-digest approval resumes")
        .expect("approve-once releases the plan");
        assert_eq!(resume.plan_digest, row.plan_digest);
        executor.run_resumed(plan, Some(&resume));
        assert_eq!(executor.started.len(), 1, "it resumes exactly once");
        assert_eq!(sink.receipts.len(), 1);
    }
}

#[test]
fn approval_choices_are_receipted_and_persistable() {
    let plan = plan_of_total(FanoutApprovalMode::Manual, 40);
    let mut sink = RecordingSink::default();
    let admission = admit_fanout_plan(
        &plan,
        None,
        &[],
        &RecordingDecider::allow(),
        &mut sink,
        NOW_MS,
    )
    .expect("manual pauses");
    let row = paused_row(&admission).clone();

    let once_action = action_id_for(&row, &FanoutApprovalChoice::ApproveOnce);
    let once = approve_and_resume_fanout(
        &plan,
        &row,
        FanoutApprovalChoice::ApproveOnce,
        &once_action,
        "owner-1",
        &mut sink,
        NOW_MS,
    )
    .expect("approve-once resumes")
    .expect("approve-once releases");
    assert!(
        once.grant_mint_intent.is_none(),
        "approve-once is receipt-only"
    );
    assert_eq!(sink.receipts.len(), 1);
    assert_eq!(sink.receipts[0].outcome, "approved_once");
    assert_eq!(
        once.choice_receipt_ref,
        format!("receipt:{}", sink.receipts[0].receipt_id)
    );

    let remember_action =
        action_id_for(&row, &FanoutApprovalChoice::ApproveAndRememberBriefVerb);
    let remembered = approve_and_resume_fanout(
        &plan,
        &row,
        FanoutApprovalChoice::ApproveAndRememberBriefVerb,
        &remember_action,
        "owner-1",
        &mut sink,
        NOW_MS,
    )
    .expect("remembered approval resumes")
    .expect("remembered approval releases");
    assert_eq!(sink.receipts.len(), 2);
    let intent = remembered
        .grant_mint_intent
        .as_ref()
        .expect("a remembered approval carries a grant intent");
    assert_eq!(
        intent.scope,
        GrantMintIntentScope::BriefVerbClass {
            brief_ref: "brief-1".to_owned(),
            verb_class: "consult".to_owned(),
        }
    );
    assert_eq!(intent.principal_ref, "owner-1");
    assert_eq!(intent.origin_component_id, row.component_id);
    assert_eq!(intent.origin_action_id, remember_action);
    assert_eq!(
        intent.origin_receipt_ref.as_deref(),
        Some(remembered.choice_receipt_ref.as_str())
    );
    // It is persistable as the existing standing grant, unchanged.
    assert!(
        crate::outbound_grant::StandingOutboundGrantScope::from_grant_mint_scope(&intent.scope)
            .is_ok()
    );

    let keep_action = action_id_for(&row, &FanoutApprovalChoice::KeepPaused);
    let kept = approve_and_resume_fanout(
        &plan,
        &row,
        FanoutApprovalChoice::KeepPaused,
        &keep_action,
        "owner-1",
        &mut sink,
        NOW_MS,
    )
    .expect("keep-paused is a ruling, not a failure");
    assert!(kept.is_none(), "keep-paused leaves the row live");
    assert_eq!(sink.receipts.len(), 3, "every choice is receipted");
    assert_eq!(sink.receipts[2].outcome, "kept_paused");

    // An action the row never offered is refused before anything is written.
    assert!(
        approve_and_resume_fanout(
            &plan,
            &row,
            FanoutApprovalChoice::ApproveOnce,
            "fanout_keep_paused",
            "owner-1",
            &mut sink,
            NOW_MS,
        )
        .is_err()
    );
    assert_eq!(sink.receipts.len(), 3);
}

#[test]
fn fanout_times_are_milliseconds_end_to_end() {
    let plan = plan_with(FanoutApprovalMode::Manual, &[("peer_a", "peer_b", 40)]);
    let rates = [PeerRateSnapshot {
        peer_ref: "peer_b".to_owned(),
        window_secs: 3_600,
        observed_count: 0,
        spike_at: 10,
    }];
    let mut sink = RecordingSink::default();
    let admission = admit_fanout_plan(
        &plan,
        None,
        &rates,
        &RecordingDecider::allow(),
        &mut sink,
        NOW_MS,
    )
    .expect("admission");
    let row = paused_row(&admission).clone();
    assert_eq!(row.created_at_ms, NOW_MS);
    assert_eq!(sink.rows[0].created_at_ms, NOW_MS);
    assert_eq!(
        row.pathology,
        Some(FanoutPathology::PerPeerRateSpike {
            peer_ref: "peer_b".to_owned(),
            projected_count: 40,
            spike_at: 10,
            // Explicit durations stay in seconds.
            window_secs: 3_600,
        })
    );

    let decided_at_ms = NOW_MS + 5_000;
    let action_id = action_id_for(&row, &FanoutApprovalChoice::ApproveOnce);
    approve_and_resume_fanout(
        &plan,
        &row,
        FanoutApprovalChoice::ApproveOnce,
        &action_id,
        "owner-1",
        &mut sink,
        decided_at_ms,
    )
    .expect("resume")
    .expect("released");

    let receipt = &sink.receipts[0];
    assert_eq!(receipt.occurred_at, decided_at_ms);
    assert_eq!(
        receipt.fields.get("decided_at_ms"),
        Some(&decided_at_ms.to_string())
    );
    assert_eq!(
        receipt.fields.get("surfaced_at_ms"),
        Some(&NOW_MS.to_string())
    );
    assert!(
        receipt.receipt_id.ends_with(&decided_at_ms.to_string()),
        "the receipt identity carries the same millisecond clock"
    );
}

#[test]
fn changed_plan_cannot_reuse_approval() {
    let plan = plan_with(
        FanoutApprovalMode::Manual,
        &[("peer_a", "peer_b", 30), ("peer_a", "peer_c", 10)],
    );
    let mut sink = RecordingSink::default();
    let admission = admit_fanout_plan(
        &plan,
        None,
        &[],
        &RecordingDecider::allow(),
        &mut sink,
        NOW_MS,
    )
    .expect("manual pauses");
    let row = paused_row(&admission).clone();
    let frozen = fanout_plan_digest(&plan).expect("digest");
    assert_eq!(row.plan_digest, frozen);

    let mut changed_count = plan.clone();
    changed_count.edges[0].count = 31;
    let mut changed_peer = plan.clone();
    changed_peer.edges[1].to_peer_ref = "peer_d".to_owned();
    let mut extra_edge = plan.clone();
    extra_edge.edges.push(FanoutPlanEdge {
        from_peer_ref: "peer_a".to_owned(),
        to_peer_ref: "peer_b".to_owned(),
        count: 1,
    });
    let mut changed_actor = plan.clone();
    changed_actor.actor_ref = "actor-2".to_owned();
    let mut changed_brief = plan.clone();
    changed_brief.brief_ref = "brief-2".to_owned();
    let mut changed_mode = plan.clone();
    changed_mode.mode = FanoutApprovalMode::FullAccess;

    for mutated in [
        &changed_count,
        &changed_peer,
        &extra_edge,
        &changed_actor,
        &changed_brief,
        &changed_mode,
    ] {
        assert_ne!(
            fanout_plan_digest(mutated).expect("digest"),
            frozen,
            "every plan axis moves the digest"
        );

        let action_id = action_id_for(&row, &FanoutApprovalChoice::ApproveOnce);
        let result = approve_and_resume_fanout(
            mutated,
            &row,
            FanoutApprovalChoice::ApproveOnce,
            &action_id,
            "owner-1",
            &mut sink,
            NOW_MS,
        );
        assert!(matches!(
            result,
            Err(FanoutApprovalError::StalePlanDigest)
        ));
        assert!(
            sink.receipts.is_empty(),
            "a stale approval writes no receipt and mints no intent"
        );
    }

    // The unchanged plan still resumes under the same row.
    let action_id = action_id_for(&row, &FanoutApprovalChoice::ApproveOnce);
    assert!(
        approve_and_resume_fanout(
            &plan,
            &row,
            FanoutApprovalChoice::ApproveOnce,
            &action_id,
            "owner-1",
            &mut sink,
            NOW_MS,
        )
        .expect("the frozen plan resumes")
        .is_some()
    );
}

#[test]
fn large_real_work_has_no_hard_cap() {
    for width in [150_u32, 300] {
        let mut full_sink = RecordingSink::default();
        let full = admit_fanout_plan(
            &star_plan(FanoutApprovalMode::FullAccess, width),
            None,
            &[],
            &RecordingDecider::surface(),
            &mut full_sink,
            NOW_MS,
        )
        .expect("full-access admits");
        match full {
            FanoutAdmission::Proceed { estimate } => assert_eq!(estimate.total_count, width),
            FanoutAdmission::Paused { .. } => panic!("full-access has no total clamp"),
        }

        let mut auto_sink = RecordingSink::default();
        let auto = admit_fanout_plan(
            &star_plan(FanoutApprovalMode::Auto, width),
            None,
            &[],
            &RecordingDecider::allow(),
            &mut auto_sink,
            NOW_MS,
        )
        .expect("auto admits");
        assert!(matches!(auto, FanoutAdmission::Proceed { .. }));

        // And the same size proceeds through a human approval.
        let manual_plan = star_plan(FanoutApprovalMode::Manual, width);
        let mut manual_sink = RecordingSink::default();
        let mut executor = RecordingExecutor::default();
        let manual = admit_fanout_plan(
            &manual_plan,
            None,
            &[],
            &RecordingDecider::surface(),
            &mut manual_sink,
            NOW_MS,
        )
        .expect("manual pauses");
        let row = paused_row(&manual);
        assert_eq!(row.estimate.total_count, width);
        assert_eq!(row.estimate.per_peer.len() as u32, width);
        let action_id = action_id_for(row, &FanoutApprovalChoice::ApproveOnce);
        let resume = approve_and_resume_fanout(
            &manual_plan,
            row,
            FanoutApprovalChoice::ApproveOnce,
            &action_id,
            "owner-1",
            &mut manual_sink,
            NOW_MS,
        )
        .expect("approval resumes")
        .expect("approval releases");
        executor.run_resumed(&manual_plan, Some(&resume));
        assert_eq!(executor.started.len(), 1);
    }
}

#[test]
fn pause_is_before_effect_creation() {
    let over = 40;
    let cycle_rates: [PeerRateSnapshot; 0] = [];
    let spike_rates = [PeerRateSnapshot {
        peer_ref: "peer_b".to_owned(),
        window_secs: 60,
        observed_count: 1,
        spike_at: 2,
    }];
    let manual = plan_of_total(FanoutApprovalMode::Manual, over);
    let auto_surface = plan_of_total(FanoutApprovalMode::Auto, over);
    let auto_error = plan_of_total(FanoutApprovalMode::Auto, over);
    let cycle = plan_with(
        FanoutApprovalMode::FullAccess,
        &[("peer_a", "peer_b", 1), ("peer_b", "peer_a", 1)],
    );
    let spike = plan_with(FanoutApprovalMode::FullAccess, &[("peer_a", "peer_b", 1)]);

    let branches: [(&FanoutPlan, RecordingDecider, &[PeerRateSnapshot]); 5] = [
        (&manual, RecordingDecider::allow(), &cycle_rates),
        (&auto_surface, RecordingDecider::surface(), &cycle_rates),
        (&auto_error, RecordingDecider::failing(), &cycle_rates),
        (&cycle, RecordingDecider::allow(), &cycle_rates),
        (&spike, RecordingDecider::allow(), &spike_rates),
    ];

    for (plan, decider, rates) in branches {
        let mut sink = RecordingSink::default();
        let mut executor = RecordingExecutor::default();
        let admission = admit_fanout_plan(plan, None, rates, &decider, &mut sink, NOW_MS)
            .expect("every branch pauses rather than erroring");
        executor.run_admitted(plan, &admission);
        let row = paused_row(&admission).clone();
        assert_eq!(sink.rows.len(), 1);
        assert!(
            executor.started.is_empty(),
            "no TASK or transport call happens on a paused branch"
        );

        let action_id = action_id_for(&row, &FanoutApprovalChoice::ApproveOnce);
        let resume = approve_and_resume_fanout(
            plan,
            &row,
            FanoutApprovalChoice::ApproveOnce,
            &action_id,
            "owner-1",
            &mut sink,
            NOW_MS,
        )
        .expect("resume")
        .expect("released");
        executor.run_resumed(plan, Some(&resume));
        assert_eq!(executor.started.len(), 1, "one call only after approval");
    }

    // A sink that cannot durably surface the pause is an error, never a
    // proceed: there is no path where a pause degrades into execution.
    let mut blank = RecordingSink {
        blank_row_ref: true,
        ..RecordingSink::default()
    };
    let mut executor = RecordingExecutor::default();
    assert!(
        admit_fanout_plan(
            &manual,
            None,
            &[],
            &RecordingDecider::allow(),
            &mut blank,
            NOW_MS,
        )
        .is_err()
    );
    assert!(executor.started.is_empty());
    executor.started.clear();
}

/// The four types the downstream classifier lane binds to are reachable at the
/// `outbound_chokepoint` path, not only inside this private submodule.
#[test]
fn fanout_contract_types_are_reexported_by_the_chokepoint() {
    use crate::outbound_chokepoint::{
        FanoutAutoDecider as ReexportedDecider, FanoutAutoDisposition as ReexportedDisposition,
        FanoutEstimate as ReexportedEstimate, FanoutPlan as ReexportedPlan,
    };

    let plan: ReexportedPlan = plan_of_total(FanoutApprovalMode::Auto, 1);
    let estimate: ReexportedEstimate = fanout_estimate(&plan).expect("estimate");
    let decider = RecordingDecider::allow();
    let disposition: ReexportedDisposition = (&decider as &dyn ReexportedDecider)
        .decide(&plan, &estimate)
        .expect("decision");
    assert_eq!(disposition, ReexportedDisposition::Allow);
}

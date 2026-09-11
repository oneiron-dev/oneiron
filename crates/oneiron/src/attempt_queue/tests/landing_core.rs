//! Landing codec and projection, soft-request handoff, hard force, and the reserve.

use super::*;
use crate::error::ArtifactError;

// ─── ONE-1896 · two-rung graceful cancel, landing, and reserve ──────────
//
// Termination is a worker-participating transition. Rung 1 (`cancel.request`)
// is a QUESTION any actor with standing may ask and the worker may refuse;
// rung 2 (`cancel.force`) is an unrefusable, runtime-authored stop only the
// owner, lease expiry, or criticality can reach. Between them sits LANDING: a
// durable, non-completed state that owns the lease long enough to finish, spend
// a held-back reserve, and record where a successor picks up.

/// Proof 1: `landing` survives the wire, is shape-validated, and no read
/// surface calls it completed.
#[test]
fn landing_round_trips_on_the_wire_and_never_projects_as_completed() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:landing-wire")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;

    // Durable and byte-stable through the row codec.
    let reread = queue.get(leased.id)?.expect("landing row");
    assert_eq!(reread, landing);
    assert_eq!(reread.state, AttemptState::Landing);
    assert_eq!(AttemptState::Landing.as_str(), "landing");
    assert_eq!(
        reread.landing().expect("landing record").trigger,
        LandingTrigger::CancelRequest
    );
    assert_eq!(
        reread.landing().expect("landing record").status.as_deref(),
        Some("green + pushed + packet-only")
    );
    assert_eq!(
        reread.landing().expect("landing record").requested_by,
        "peer-1",
        "the landing names the requester it answered"
    );

    // Append-only state ordering: `Landing` is the newest variant, so every
    // older row's encoded index is unchanged.
    let encoded_scheduled = rmp_serde::to_vec_named(&AttemptState::Scheduled).expect("encode");
    let encoded_landing = rmp_serde::to_vec_named(&AttemptState::Landing).expect("encode");
    assert_ne!(encoded_scheduled, encoded_landing);
    assert_eq!(
        rmp_serde::from_slice::<AttemptState>(&encoded_scheduled).expect("decode"),
        AttemptState::Scheduled,
        "appending Landing did not re-map an existing variant"
    );

    // A landing row must keep the lease that buys it the time to finish.
    let mut malformed = reread.clone();
    malformed.lease_owner = None;
    let encoded = rmp_serde::to_vec_named(&malformed).expect("encode");
    let mut raw = vec![super::types::ATTEMPT_RECORD_VERSION];
    raw.extend(encoded);
    assert!(matches!(
        decode_record(&raw, malformed.id).expect_err("landing without a lease is refused"),
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_LANDING_WITHOUT_LEASE
    ));

    // A landing record may not ride a row that is not landing or landed.
    let mut misplaced = reread.clone();
    misplaced.state = AttemptState::Leased;
    let encoded = rmp_serde::to_vec_named(&misplaced).expect("encode");
    let mut raw = vec![super::types::ATTEMPT_RECORD_VERSION];
    raw.extend(encoded);
    assert!(matches!(
        decode_record(&raw, misplaced.id).expect_err("misplaced landing record is refused"),
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_LANDING_RECORD_MISPLACED
    ));

    // Projections: still running, never completed, never cancelled.
    assert_eq!(
        crate::run_tree::RunTreeStatus::from(AttemptState::Landing),
        crate::run_tree::RunTreeStatus::Running
    );
    let a2a = crate::run_tree::project_attempt_to_a2a(&reread);
    assert_eq!(a2a.state, crate::consult_ladder::A2aBaseTaskState::Working);
    assert_eq!(a2a.extensions.cancel_mode.as_deref(), Some("landing"));
    assert_eq!(
        a2a.extensions.landing_trigger.as_deref(),
        Some("cancel_request")
    );

    // An operator interrupt may leave an audit event on a landing row, but it
    // is not a lease heartbeat: only accepting the landing starts its one
    // bounded finishing window.
    let interrupted = queue.intervene(InterveneAttempt {
        id: leased.id,
        kind: AttemptInterventionKind::Interrupt,
        actor: "operator".to_owned(),
        note: Some("observed landing".to_owned()),
        now: 100,
    })?;
    assert_eq!(interrupted.effect, AttemptInterventionEffect::Interrupted);
    assert_eq!(
        interrupted.record.updated_at, landing.updated_at,
        "an interrupt must not extend a landing lease"
    );

    // And the queue itself refuses to call it completed.
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                now: 14,
            })
            .expect_err("a landing attempt is never completed"),
        "complete",
        "landing",
    );
    Ok(())
}

/// Proof 2: standing asks, the worker lands with an exact resume point, and the
/// handoff carries that point to a claimable successor.
#[test]
fn soft_request_lands_with_a_resume_point_a_successor_resumes_from() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:landing-handoff")?;

    let CancelRequestOutcome::Requested { record, pressure } =
        queue.request_cancel(soft_request(leased.id, "healer-1", CancelStanding::Healer))?
    else {
        panic!("an actor with standing may ask");
    };
    assert_eq!(
        record.state,
        AttemptState::Leased,
        "asking never terminates"
    );
    assert_eq!(pressure.requests, 1);
    assert_eq!(pressure.pending, 1);
    let request_receipt = record.cancel_receipts().last().expect("request receipt");
    assert_eq!(
        request_receipt.kind,
        AttemptCancelReceiptKind::SoftRequested
    );
    assert_eq!(request_receipt.standing, Some(CancelStanding::Healer));
    assert_eq!(request_receipt.trigger, Some(LandingTrigger::CancelRequest));

    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;
    assert_eq!(landing.cancel_pressure().pending, 0, "the ask was answered");

    // A landing is not claimable as ordinary queued work.
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 14,
        })?,
        ClaimOutcome::Empty
    ));

    let with_point = queue.record_resume_point(RecordAttemptResumePoint {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        resume_point: AttemptResumePoint::new("step-7/of-12", 15)
            .with_artifact_ref("artifact:checkpoint"),
        now: 15,
    })?;
    assert_eq!(
        with_point.resume_point().expect("resume point").marker,
        "step-7/of-12"
    );

    // The landing is fenced like any other lease transition: a stranger cannot
    // end it early and strand the work the worker had not finished.
    assert_invalid_transition(
        queue
            .finish_landing(FinishAttemptLanding {
                id: leased.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: leased.attempt_count,
                hand_off: true,
                scheduled_at: None,
                now: 16,
            })
            .expect_err("only the landing worker finishes its landing"),
        "finish_landing",
        "leased_by_other",
    );

    let FinishLandingOutcome::HandedOff { landed, successor } =
        queue.finish_landing(FinishAttemptLanding {
            id: leased.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: leased.attempt_count,
            hand_off: true,
            scheduled_at: None,
            now: 16,
        })?
    else {
        panic!("expected a handoff");
    };

    assert_eq!(landed.state, AttemptState::Cancelled);
    let cancellation = landed.cancellation().expect("terminal cancellation");
    assert_eq!(cancellation.mode, CancelMode::Landed);
    assert_eq!(cancellation.grounds, None);
    assert_eq!(cancellation.trigger, Some(LandingTrigger::CancelRequest));
    assert_eq!(cancellation.actor, "worker-a");
    assert_eq!(
        landed
            .cancel_receipts()
            .iter()
            .filter(|receipt| receipt.kind == AttemptCancelReceiptKind::Landed)
            .count(),
        1
    );

    // The successor carries the EXACT point and is claimable; the landed row
    // is superseded history and can never be completed.
    assert_eq!(successor.state, AttemptState::Queued);
    assert_eq!(successor.retry_of, Some(landed.id));
    let successor_point = successor.resume_point().expect("successor resume point");
    assert_eq!(successor_point.marker, "step-7/of-12");
    assert_eq!(
        successor_point.artifact_ref.as_deref(),
        Some("artifact:checkpoint")
    );
    let ClaimOutcome::Claimed(resumed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 17,
    })?
    else {
        panic!("the successor is ordinary claimable work");
    };
    assert_eq!(resumed.id, successor.id);
    assert_eq!(
        resumed
            .resume_point()
            .expect("point survives the claim")
            .marker,
        "step-7/of-12"
    );
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: landed.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: landed.attempt_count,
                now: 18,
            })
            .expect_err("a landed row cannot also complete"),
        "complete",
        "cancelled",
    );
    Ok(())
}

/// Proof 3: refusal is structured, append-only, and repeated refusal becomes an
/// observable pathology that still cannot stop the worker by itself.
#[test]
fn repeated_soft_rejection_stays_nonterminal_and_becomes_observable_pathology() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:stubborn")?;

    let mut pathology = false;
    for round in 0..SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD {
        queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
        let rejection = queue.reject_cancel(RejectAttemptCancel {
            id: leased.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: leased.attempt_count,
            reason: "mid-write; landing now would corrupt the packet".to_owned(),
            status: Some("red + unpushed".to_owned()),
            request_sequence: None,
            now: 20 + u64::from(round),
        })?;
        assert_eq!(
            rejection.record.state,
            AttemptState::Leased,
            "a refusal never terminates the attempt"
        );
        assert_eq!(rejection.pressure.rejections, round + 1);
        assert_eq!(rejection.pressure.pending, 0);
        pathology = rejection.pathology;
    }
    assert!(
        pathology,
        "repeated refusal is observable, not silently tolerated"
    );

    let stubborn = queue.get(leased.id)?.expect("row");
    assert!(stubborn.soft_cancel_pathology());
    let rejections: Vec<_> = stubborn
        .cancel_receipts()
        .iter()
        .filter(|receipt| receipt.kind == AttemptCancelReceiptKind::SoftRejected)
        .collect();
    assert_eq!(
        rejections.len(),
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD as usize,
        "every refusal is kept; evidence is append-only"
    );
    assert_eq!(
        rejections[0].reason.as_deref(),
        Some("mid-write; landing now would corrupt the packet")
    );
    assert_eq!(rejections[0].status.as_deref(), Some("red + unpushed"));
    assert_eq!(
        rejections[0].trigger,
        Some(LandingTrigger::CancelRequest),
        "a refusal preserves the trigger it answered"
    );
    let sequences: Vec<u64> = stubborn
        .cancel_receipts()
        .iter()
        .map(|receipt| receipt.sequence)
        .collect();
    assert!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "receipt sequence is strictly increasing"
    );
    let a2a = crate::run_tree::project_attempt_to_a2a(&stubborn);
    assert_eq!(a2a.state, crate::consult_ladder::A2aBaseTaskState::Working);
    assert_eq!(a2a.extensions.cancel_mode.as_deref(), Some("rejected"));
    assert_eq!(
        a2a.extensions.cancel_rejections,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );

    // Only the hard rung ends it, and the refusal history survives the stop.
    let ForceCancelOutcome::Cancelled(forced) = queue.force_cancel(ForceAttemptCancel {
        id: leased.id,
        authority: ForceCancelAuthority::owner("owner-1").expect("verified owner forces"),
        reason: Some("refused to land three times".to_owned()),
        now: 30,
    })?
    else {
        panic!("authority forces");
    };
    assert_eq!(forced.state, AttemptState::Cancelled);
    assert_eq!(
        forced.cancel_pressure().rejections,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );
    Ok(())
}

/// Proof 4: no standing, no ask — and the attempt is byte-identical afterwards.
#[test]
fn soft_request_without_standing_changes_nothing() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:no-standing")?;
    let before = queue.get(leased.id)?.expect("row");

    let CancelRequestOutcome::NoStanding(unchanged) =
        queue.request_cancel(soft_request(leased.id, "stranger", CancelStanding::None))?
    else {
        panic!("an actor without standing may not ask");
    };
    assert_eq!(unchanged, before);
    assert_eq!(queue.get(leased.id)?.expect("row"), before);
    assert_eq!(before.cancel_pressure().requests, 0);
    assert!(before.cancel_receipts().is_empty());

    // Nor may a requester borrow the runtime's identity to look authoritative.
    assert!(matches!(
        queue
            .request_cancel(soft_request(
                leased.id,
                ATTEMPT_RUNTIME_ACTOR,
                CancelStanding::PeerAgent
            ))
            .expect_err("the runtime identity is reserved"),
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_CANCEL_ACTOR_IS_RUNTIME
    ));
    assert_eq!(queue.get(leased.id)?.expect("row"), before);

    // A worker may answer only an outstanding request; an unsolicited refusal
    // cannot manufacture pathology evidence.
    assert_invalid_transition(
        queue
            .reject_cancel(RejectAttemptCancel {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                reason: "nothing to answer".to_owned(),
                status: None,
                request_sequence: None,
                now: 13,
            })
            .expect_err("a refusal without a request is invalid"),
        "cancel_reject",
        "no_request",
    );
    Ok(())
}

/// Proof 5: the hard rung is authority-only, runtime-authored, and unforgeable.
#[test]
fn hard_force_is_authority_only_and_runtime_authored() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    // Standing is the SOFT rung's currency and buys nothing here: there is no
    // constructor that turns a `CancelStanding` into force authority, so an
    // unauthorized force is impossible to express, not merely refused. What a
    // non-authority actor CAN do is ask, and that door stays open.
    for standing in [
        CancelStanding::PeerAgent,
        CancelStanding::Healer,
        CancelStanding::Automation,
    ] {
        assert!(standing.may_request(), "{} may ask", standing.as_str());
    }
    // Even the verified-owner mint refuses a malformed identity BEFORE it can
    // reach a durable row (ONE-1896 §7).
    for forged in ["", ATTEMPT_RUNTIME_ACTOR, &"o".repeat(129)] {
        assert!(
            ForceCancelAuthority::owner(forged).is_err(),
            "an unreadable or runtime-impersonating owner cannot mint authority"
        );
    }

    // Owner grounds: terminal, with the authority's own actor on the receipt.
    let owned = leased_attempt(&queue, "turn:force-owner")?;
    // A malformed owner identity cannot reach the row at all: the mint fails,
    // so no half-written terminal receipt (which `decode_record` would then
    // refuse to read back) is ever persisted.
    let before = queue.get(owned.id)?.expect("row");
    assert!(ForceCancelAuthority::owner("").is_err());
    assert_eq!(
        queue.get(owned.id)?.expect("row"),
        before,
        "a refused authority leaves the record byte-identical"
    );
    queue.append_manifest_entry(
        owned.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.cancel", "v1", 12),
    )?;
    let ForceCancelOutcome::Cancelled(forced) = queue.force_cancel(ForceAttemptCancel {
        id: owned.id,
        authority: ForceCancelAuthority::owner("owner-1").expect("verified owner"),
        reason: Some("owner reclaimed the machine".to_owned()),
        now: 20,
    })?
    else {
        panic!("authority forces");
    };
    let cancellation = forced.cancellation().expect("cancellation receipt");
    assert_eq!(cancellation.mode, CancelMode::Forced);
    assert_eq!(cancellation.grounds, Some(ForceCancelGrounds::Owner));
    assert_eq!(cancellation.actor, "owner-1");
    assert_eq!(forced.lease_owner, None, "a forced stop releases the lease");
    assert_eq!(
        forced.last_error, None,
        "a cancelled row is not a failed one; the reason rides the receipt"
    );
    assert_eq!(
        cancellation.reason.as_deref(),
        Some("owner reclaimed the machine")
    );
    let pack_receipt = crate::receipt::attempt_pack_receipt(
        &vault,
        &crate::receipt::attempt_pack_receipt_id(&owned.id),
    )?
    .expect("hard cancellation stamps the accumulated pack manifest");
    assert_eq!(pack_receipt.outcome, "cancelled");
    // Terminal is terminal: the worker cannot report a second success.
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: owned.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: owned.attempt_count,
                now: 21,
            })
            .expect_err("completion after a force is refused"),
        "complete",
        "cancelled",
    );
    let ForceCancelOutcome::AlreadyCancelled(replay) = queue.force_cancel(ForceAttemptCancel {
        id: owned.id,
        authority: ForceCancelAuthority::criticality(),
        reason: None,
        now: 22,
    })?
    else {
        panic!("a second force is an idempotent replay");
    };
    assert_eq!(
        replay.cancellation().expect("receipt").actor,
        "owner-1",
        "the first authority's receipt is not overwritten"
    );

    // Criticality grounds: runtime-authored, whatever the worker holds.
    let critical = leased_attempt(&queue, "turn:force-critical")?;
    let ForceCancelOutcome::Cancelled(stopped) = queue.force_cancel(ForceAttemptCancel {
        id: critical.id,
        authority: ForceCancelAuthority::criticality(),
        reason: None,
        now: 23,
    })?
    else {
        panic!("criticality forces");
    };
    assert_eq!(
        stopped.cancellation().expect("receipt").actor,
        ATTEMPT_RUNTIME_ACTOR
    );
    assert_eq!(
        stopped.cancellation().expect("receipt").grounds,
        Some(ForceCancelGrounds::Criticality)
    );

    // Lease-expiry grounds: a landing whose lease died is force-cancelled by
    // cleanup, not requeued as ordinary work, and the warning rung is a
    // DIFFERENT, non-terminal thing.
    let expiring = leased_attempt(&queue, "turn:force-expiry")?;
    assert!(matches!(
        queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: expiring.id,
            lease_timeout_secs: 100,
            now: 12,
        })?,
        LeaseWarningOutcome::NotDue(_)
    ));
    let LeaseWarningOutcome::LandingRequested(warned) =
        queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: expiring.id,
            lease_timeout_secs: 100,
            now: 100,
        })?
    else {
        panic!("inside the warning window the runtime asks");
    };
    assert_eq!(warned.state, AttemptState::Leased, "a warning never stops");
    let warning = warned.cancel_receipts().last().expect("warning receipt");
    assert_eq!(warning.actor, ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(warning.trigger, Some(LandingTrigger::LeaseWarning));
    assert!(
        matches!(
            queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
                id: expiring.id,
                lease_timeout_secs: 100,
                now: 101,
            })?,
            LeaseWarningOutcome::AlreadyRequested(_)
        ),
        "polling the warning records one row, not a hundred"
    );

    let landing = accept_landing_at(&queue, &expiring, LandingTrigger::LeaseWarning, 102)?;
    assert_eq!(landing.state, AttemptState::Landing);
    assert_eq!(
        landing.updated_at, 102,
        "accepting buys ONE fresh bounded window"
    );
    queue
        .dial_landing_reserve(DialLandingReserve {
            id: expiring.id,
            limit_units: 100,
            reserve_percent: None,
            now: 103,
        })
        .expect_err("a landing row is not re-dialed");
    let busy = queue.record_resume_point(RecordAttemptResumePoint {
        id: expiring.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: expiring.attempt_count,
        resume_point: AttemptResumePoint::new("still-going", 300),
        now: 300,
    })?;
    assert_eq!(
        busy.updated_at, 102,
        "landing work does not extend the window by looking busy"
    );
    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 400,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(report.landing_force_cancelled, 1);
    assert_eq!(report.stale_requeued, 0, "a landing is never requeued");
    let expired = queue.get(expiring.id)?.expect("row");
    assert_eq!(expired.state, AttemptState::Cancelled);
    let cancellation = expired.cancellation().expect("receipt");
    assert_eq!(cancellation.grounds, Some(ForceCancelGrounds::LeaseExpiry));
    assert_eq!(cancellation.actor, ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(cancellation.trigger, Some(LandingTrigger::LeaseWarning));
    assert_eq!(
        crate::run_tree::project_attempt_to_a2a(&expired)
            .extensions
            .cancel_mode
            .as_deref(),
        Some("forced")
    );
    Ok(())
}

/// Proof 6: the reserve is unreachable outside landing, exact inside it, and
/// every trigger enters the same landing path with typed provenance.
#[test]
fn landing_reserve_is_landing_only_bounded_and_reports_exhaustion() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:reserve")?;

    let dialed = queue.dial_landing_reserve(DialLandingReserve {
        id: leased.id,
        limit_units: 10_000,
        reserve_percent: None,
        now: 12,
    })?;
    let reserve = dialed.landing_reserve();
    assert_eq!(reserve.limit_units, 10_000);
    assert_eq!(
        reserve.reserve_units,
        10_000 * LANDING_RESERVE_PERCENT / 100,
        "the dial is the named constant, in integer units"
    );
    assert_eq!(
        dialed.ordinary_budget_limit_units(),
        9_000,
        "the ordinary meter is built without the reserve, so normal work \
         cannot reach it"
    );

    // Out of landing mode the spend door fails closed.
    assert_invalid_transition(
        queue
            .spend_landing_reserve(SpendAttemptLandingReserve {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                units: 1,
                now: 13,
            })
            .expect_err("running work may not spend the landing reserve"),
        "spend_landing_reserve",
        "leased",
    );

    // Budget warning is a first-class trigger into the same landing path.
    accept_landing_at(&queue, &leased, LandingTrigger::BudgetWarning, 14)?;
    let landing = queue.get(leased.id)?.expect("row");
    assert_eq!(
        landing.landing().expect("landing").trigger,
        LandingTrigger::BudgetWarning
    );

    let spend = |units: u64, now: u64| SpendAttemptLandingReserve {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        units,
        now,
    };
    let LandingReserveSpendOutcome::Spent {
        remaining_units, ..
    } = queue.spend_landing_reserve(spend(600, 15))?
    else {
        panic!("landing may spend its reserve");
    };
    assert_eq!(remaining_units, 400);

    // Over the remaining reserve spends NOTHING and reports exhaustion.
    let LandingReserveSpendOutcome::Exhausted {
        record,
        requested_units,
        remaining_units,
    } = queue.spend_landing_reserve(spend(401, 16))?
    else {
        panic!("the reserve is bounded at the dialed amount");
    };
    assert_eq!(requested_units, 401);
    assert_eq!(remaining_units, 400);
    assert_eq!(
        record.landing_reserve().spent_units,
        600,
        "a refused spend moves no units"
    );

    let LandingReserveSpendOutcome::Spent {
        record,
        remaining_units,
    } = queue.spend_landing_reserve(spend(400, 17))?
    else {
        panic!("the exact remainder is spendable");
    };
    assert_eq!(remaining_units, 0);
    assert!(record.landing_reserve().is_exhausted());

    // A landing that cannot say where to resume may not hand off.
    assert!(matches!(
        queue
            .finish_landing(FinishAttemptLanding {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                hand_off: true,
                scheduled_at: None,
                now: 18,
            })
            .expect_err("a handoff without a resume point is refused"),
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_HANDOFF_WITHOUT_RESUME_POINT
    ));

    let FinishLandingOutcome::Landed(landed) = queue.finish_landing(FinishAttemptLanding {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        hand_off: false,
        scheduled_at: None,
        now: 19,
    })?
    else {
        panic!("a landing may end without a successor");
    };
    let cancellation = landed.cancellation().expect("receipt");
    assert_eq!(cancellation.reserve_units, 1_000);
    assert_eq!(
        cancellation.reserve_spent_units, 1_000,
        "the terminal receipt reports the landing's accounting"
    );
    assert_eq!(cancellation.trigger, Some(LandingTrigger::BudgetWarning));

    // Re-dialing a settled row is refused, so the accounting cannot be rewritten.
    assert_invalid_transition(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: leased.id,
                limit_units: 1,
                reserve_percent: None,
                now: 20,
            })
            .expect_err("a settled row is not re-dialed"),
        "dial_landing_reserve",
        "cancelled",
    );
    Ok(())
}

/// Proof 7: the sticky-executor completion law is unchanged for non-landing
/// work, and the cancel doors carry the same lease-generation fence.
#[test]
fn sticky_completion_and_cancel_doors_share_one_lease_fence() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:fence")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;

    // Wrong owner and stale generation are refused on every worker-facing door.
    assert_invalid_transition(
        queue
            .accept_landing(AcceptAttemptLanding {
                id: leased.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: leased.attempt_count,
                trigger: LandingTrigger::CancelRequest,
                status: None,
                resume_point: None,
                request_sequence: None,
                now: 13,
            })
            .expect_err("a stranger cannot land someone else's attempt"),
        "accept_landing",
        "leased_by_other",
    );
    assert_invalid_transition(
        queue
            .reject_cancel(RejectAttemptCancel {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count + 1,
                reason: "still working".to_owned(),
                status: None,
                request_sequence: None,
                now: 13,
            })
            .expect_err("a stale lease generation cannot answer"),
        "cancel_reject",
        "stale_attempt",
    );

    // The unchanged sticky law: the bound owner and generation still complete.
    let CompleteOutcome::Completed(done) = queue.complete(CompleteAttempt {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        now: 14,
    })?
    else {
        panic!("an executor with standing still completes its own attempt");
    };
    assert_eq!(done.state, AttemptState::Completed);
    assert_eq!(
        done.cancel_receipts().len(),
        1,
        "the outstanding request stays as evidence on the completed row"
    );

    // A settled attempt is reported, never re-asked or re-killed.
    assert!(matches!(
        queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?,
        CancelRequestOutcome::AlreadySettled(_)
    ));
    assert!(matches!(
        queue.force_cancel(ForceAttemptCancel {
            id: leased.id,
            authority: ForceCancelAuthority::owner("owner-1").expect("verified owner"),
            reason: None,
            now: 15,
        })?,
        ForceCancelOutcome::AlreadySettled(_)
    ));
    assert_eq!(
        queue.get(leased.id)?.expect("row").state,
        AttemptState::Completed,
        "a completed attempt is not retroactively cancelled"
    );
    Ok(())
}

/// Proof 8: a soft request is only ever recorded where a worker can answer it.
///
/// A pre-lease row has no response door at all — `accept_landing` and
/// `reject_cancel` both demand the lease — so a pending ask against one would
/// be an obligation nobody holds, and its permanent `pending` would read as a
/// worker refusing to answer.
#[test]
fn a_soft_request_is_refused_where_no_worker_can_answer() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    // Claim FIRST, while nothing else is ready, so the lease lands on this row.
    let leased = leased_attempt(&queue, "turn:pre-lease-lease")?;
    let RetryOutcome::Retried(scheduled) = queue.retry(RetryAttempt {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        backoff_until: 5_000,
        last_error: None,
        now: 12,
    })?;
    assert_eq!(scheduled.state, AttemptState::Scheduled);

    let EnqueueOutcome::Enqueued(queued) =
        queue.enqueue(enqueue("sync", Some("turn:pre-lease-queued"), 13))?
    else {
        panic!("a fresh dedupe key enqueues");
    };
    let EnqueueOutcome::Enqueued(to_pause) =
        queue.enqueue(enqueue("sync", Some("turn:pre-lease-paused"), 14))?
    else {
        panic!("a fresh dedupe key enqueues");
    };
    let paused = queue
        .intervene(InterveneAttempt {
            id: to_pause.id,
            kind: AttemptInterventionKind::Pause,
            actor: "operator".to_owned(),
            note: None,
            now: 15,
        })?
        .record;
    assert_eq!(paused.state, AttemptState::Paused);

    for id in [queued.id, paused.id, scheduled.id] {
        let before = queue.get(id)?.expect("row");
        let CancelRequestOutcome::NotRunning(unchanged) =
            queue.request_cancel(soft_request(id, "peer-1", CancelStanding::PeerAgent))?
        else {
            panic!(
                "a {} attempt has no worker to answer",
                before.state.as_str()
            );
        };
        assert_eq!(unchanged, before);
        assert_eq!(
            queue.get(id)?.expect("row"),
            before,
            "a request nobody can answer leaves no durable trace"
        );
        assert_eq!(before.cancel_pressure(), AttemptCancelPressure::default());
        assert!(before.cancel_receipts().is_empty());
    }

    // The pre-lease lane keeps its OWN stop: queue cancellation, which needs no
    // worker because there is none.
    let cancelled = queue.intervene(InterveneAttempt {
        id: queued.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "owner".to_owned(),
        note: None,
        now: 16,
    })?;
    assert_eq!(cancelled.effect, AttemptInterventionEffect::Cancelled);
    assert_eq!(cancelled.record.state, AttemptState::Cancelled);
    Ok(())
}

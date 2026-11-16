//! CAL-06 and CAL-07 plan their host wakes as the supervisor contract's own
//! `WakeEntry` (ARCH-0060 [CAL-06], [CAL-07]).
//!
//! The T-45 prep wake and the post-end check-in wake are exact instants the
//! engine computes and the host delivers. Main planned both as engine-side
//! images (`PrepWake`, `OutcomeCheckInWake`) that only described the contract
//! shape; here each planner returns `oneiron_vault_contract::WakeEntry` on the
//! `Schedule::Exact` arm, so the entry passes the contract's own bounds check
//! and serialises to the wire shape the supervisor reads. Main cannot build
//! this file: the planners return the images, not the contract type.
#![cfg(feature = "test-support")]

use oneiron::EntityId;
use oneiron::calendar::outcome::{
    MeetingClassSignals, OUTCOME_CHECK_IN_REASON_TAG, plan_outcome_check_in,
};
use oneiron::calendar::prep::{
    DEFAULT_PREP_LEAD_SECS, PREP_WAKE_REASON_TAG, PrepEvent, PrepHomeNodeJob, PrepPolicy,
    plan_prep_wake, prep_wake_id,
};
use oneiron_vault_contract::{Schedule, WakeEntry};

const EVENT_START: u64 = 1_800_000_000;
const EVENT_END: u64 = EVENT_START + 3_600;
const GRACE_SECS: u64 = 1_800;

/// Fixture ids under their own prefix, as in `tests/family_claim_facet.rs`.
fn entity(seed: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7f;
    bytes[15] = seed;
    EntityId::from_bytes(bytes).expect("fixture id")
}

fn external_meeting(event_ref: EntityId) -> PrepEvent {
    PrepEvent {
        event_ref,
        start_utc: EVENT_START,
        end_utc: EVENT_END,
        attendee_refs: Vec::new(),
        external_attendee_count: 1,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

fn meeting_signals() -> MeetingClassSignals {
    MeetingClassSignals {
        external_attendee_count: 1,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

#[test]
fn prep_wake_is_an_exact_contract_wake_entry_at_t45() {
    let event_ref = entity(0x41);
    let fire_at = EVENT_START - DEFAULT_PREP_LEAD_SECS;
    let wake: WakeEntry = plan_prep_wake(
        prep_wake_id(&event_ref),
        &external_meeting(event_ref),
        PrepPolicy::default(),
    )
    .expect("an external meeting arms prep");

    assert_eq!(wake.at, Schedule::Exact { at: fire_at });
    assert_eq!(wake.id, prep_wake_id(&event_ref));
    assert_eq!(wake.reason_tag, PREP_WAKE_REASON_TAG);
    wake.validate()
        .expect("the wake passes the contract's bounds check");
    assert_eq!(
        serde_json::to_value(&wake).expect("wake serialises"),
        serde_json::json!({
            "id": prep_wake_id(&event_ref),
            "at": {"kind": "exact", "at": fire_at},
            "reason_tag": PREP_WAKE_REASON_TAG,
        }),
        "the supervisor reads the contract's wire shape"
    );

    let job = PrepHomeNodeJob::from_wake(&event_ref, &wake).expect("an exact wake binds a job");
    assert_eq!(job.event_ref, event_ref.to_hex());
    assert_eq!(job.scheduled_for, fire_at);
    assert_eq!(job.wake_id, wake.id);

    // A window names no instant a prep job could be due at.
    let window = WakeEntry {
        at: Schedule::Window {
            start: fire_at,
            end: EVENT_START,
        },
        ..wake
    };
    assert_eq!(PrepHomeNodeJob::from_wake(&event_ref, &window), None);
}

#[test]
fn check_in_wake_is_an_exact_contract_wake_entry_after_grace() {
    let wake_id = format!("{OUTCOME_CHECK_IN_REASON_TAG}:{}", entity(0x42).to_hex());
    let wake: WakeEntry =
        plan_outcome_check_in(wake_id.clone(), EVENT_END, meeting_signals(), GRACE_SECS)
            .expect("a meeting-class EVENT arms the check-in");

    assert_eq!(
        wake.at,
        Schedule::Exact {
            at: EVENT_END + GRACE_SECS
        }
    );
    assert_eq!(wake.id, wake_id);
    assert_eq!(wake.reason_tag, OUTCOME_CHECK_IN_REASON_TAG);
    wake.validate()
        .expect("the wake passes the contract's bounds check");

    // An ambient item is never asked about.
    let ambient = MeetingClassSignals {
        external_attendee_count: 0,
        ..meeting_signals()
    };
    assert_eq!(
        plan_outcome_check_in(wake_id, EVENT_END, ambient, GRACE_SECS),
        None
    );
}

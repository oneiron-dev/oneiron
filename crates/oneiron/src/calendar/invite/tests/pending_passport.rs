//! A pending `calendar.passport` never picks the EVENT an invite binds to.

use super::*;
use crate::calendar::claims::{
    CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    PREDICATE_CALENDAR_PASSPORT,
};
use crate::calendar::passport::{
    encode_passport_value, event_ref_for_indexed_uid, live_passports_for_event,
    resolve_event_by_uid,
};

/// Files a feed passport carrying the invite's UID on `event_ref`.
fn passport(vault: &Vault, seed: u8, event_ref: EntityId, approval: ClaimApprovalStatus) {
    let value = CalendarPassportValue {
        system: "fixture.feed".to_owned(),
        uid: UID.to_owned(),
        last_sequence: 0,
        content_hash: [seed; 32],
        direction: CalendarPassportDirection::Inbound,
        last_seen_at: NOW,
        presence: CalendarPassportPresence::Live,
    };
    let body = ClaimBody::new(
        PREDICATE_CALENDAR_PASSPORT,
        ClaimSubject::Entity(event_ref),
        encode_passport_value(&value),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .put_claim(
            &crate::test_util::entity(seed),
            &body,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("put passport claim");
}

/// An EVENT the UID index does not name. Seed 0x40 sorts before the fixture's
/// 0x52, so a scan for the UID reaches it first.
fn bare_event(vault: &Vault, seed: u8) -> EntityId {
    let id = crate::test_util::entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: NOW,
                end: NOW + 3_600,
            },
            NOW,
            b"passport fixture event",
        )
        .expect("put event");
    id
}

/// The outbound iMIP passports an invite commit left on `event_ref`.
fn outbound(vault: &Vault, event_ref: &EntityId) -> usize {
    live_passports_for_event(vault, event_ref)
        .expect("passports")
        .iter()
        .filter(|(_, value)| value.system == CALENDAR_INVITE_PASSPORT_SYSTEM)
        .count()
}

/// On a node with no UID cache, the scan used to take the lexicographically
/// first EVENT with any live passport for the UID, pending or not.
#[test]
fn a_pending_passport_never_steers_an_invite_off_the_admitted_event() {
    let (_dir, vault) = open_calendar_vault();
    let actor_ref = actor(&vault);
    let event_ref = bare_event(&vault, 0x52);
    passport(&vault, 0x43, event_ref, ClaimApprovalStatus::Approved);
    let pending = bare_event(&vault, 0x40);
    passport(&vault, 0x44, pending, ClaimApprovalStatus::Proposed);
    identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
    prior_thread(&vault, 0x60, "guest@example.test");
    let blob_ref = blob(
        &vault,
        0x54,
        actor_ref,
        &emit(0, CalendarInviteMethod::Request),
    );

    let admission =
        admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).expect("admit");
    assert_eq!(admission.event_ref(), event_ref);
    commit_admission(&vault, &admission, NOW).expect("commit");
    assert_eq!(outbound(&vault, &event_ref), 1);
    assert_eq!(
        outbound(&vault, &pending),
        0,
        "no Approved passport was minted on the pending EVENT"
    );
}

/// The ingest still resolves the UID through the pending passport, but that
/// never moves the index off the EVENT the UID was minted with.
#[test]
fn the_uid_index_repair_never_points_at_a_pending_passport() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    let pending = bare_event(&vault, 0x40);
    passport(&vault, 0x44, pending, ClaimApprovalStatus::Proposed);

    assert_eq!(resolve_event_by_uid(&vault, UID).unwrap(), Some(pending));
    assert_eq!(
        event_ref_for_indexed_uid(&vault, UID).unwrap(),
        Some(event_ref)
    );
    let admission =
        admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).expect("admit");
    assert_eq!(admission.event_ref(), event_ref);
}

/// No admitted passport carries the UID yet, so the first confirm binds through
/// the raw index, and a pending passport elsewhere does not outrank it.
#[test]
fn a_first_invite_binds_through_the_raw_index_past_a_pending_passport() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    let pending = bare_event(&vault, 0x40);
    passport(&vault, 0x44, pending, ClaimApprovalStatus::Proposed);

    let admission =
        admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).expect("admit");
    assert_eq!(admission.event_ref(), event_ref);
    assert_eq!(admission.state_change(), CalendarInviteStateChange::MintUid);
    commit_admission(&vault, &admission, NOW).expect("commit");
    assert_eq!(outbound(&vault, &event_ref), 1);
    assert_eq!(outbound(&vault, &pending), 0);
}

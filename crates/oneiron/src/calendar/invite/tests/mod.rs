mod faceted_sender;

use super::*;
use crate::calendar::ics::{ImipEmitRequest, emit_imip_ics, persist_imip_blob};
use crate::calendar::test_support::open_calendar_vault;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityBinding};
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use crate::write_envelope::WriteActor;

const NOW: u64 = 1_800_000_000;
const UID: &str = "one-1786@oneiron.test";

fn actor(vault: &Vault) -> EntityId {
    let id = crate::test_util::entity(0x51);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"cal-04 actor",
        )
        .expect("put actor");
    id
}

fn event(vault: &Vault) -> EntityId {
    let id = crate::test_util::entity(0x52);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: NOW,
                end: NOW + 3_600,
            },
            NOW,
            b"cal-04 event",
        )
        .expect("put event");
    crate::calendar::passport::index_passport_uid(vault, UID, &id).expect("index uid");
    id
}

fn identity(vault: &Vault, seed: u8, actor: EntityId, channel: &str, address: &str) {
    let id = crate::test_util::entity(seed);
    let mut identity = ChannelIdentity::requested(
        channel,
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(actor),
        NOW,
    );
    identity.state = ChannelIdentityState::Active;
    vault
        .create_channel_identity(&id, &identity)
        .expect("create identity");
}

fn attendee(vault: &Vault, seed: u8, event_ref: EntityId, who: &str) {
    let claim_id = crate::test_util::entity(seed);
    vault
        .put_claim(
            &claim_id,
            &ClaimBody::new(
                PREDICATE_CALENDAR_ATTENDEE,
                ClaimSubject::Entity(event_ref),
                rmpv::Value::Map(vec![
                    (rmpv::Value::from("who"), rmpv::Value::from(who)),
                    (
                        rmpv::Value::from("role"),
                        rmpv::Value::from("REQ-PARTICIPANT"),
                    ),
                    (rmpv::Value::from("partstat"), rmpv::Value::from("ACCEPTED")),
                ]),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("put attendee claim");
}

fn emit(sequence: u32, method: CalendarInviteMethod) -> Vec<u8> {
    emit_imip_ics(&ImipEmitRequest {
        method,
        uid: UID.to_owned(),
        sequence,
        organizer: "me@primary.test".to_owned(),
        attendees: vec!["guest@example.test".to_owned()],
        summary: "Design review".to_owned(),
        starts_at_utc: 1_800_003_600,
        ends_at_utc: 1_800_007_200,
        tz_label: "Europe/Warsaw".to_owned(),
        dtstamp_utc: NOW,
    })
    .expect("emit")
}

fn blob(vault: &Vault, seed: u8, actor: EntityId, bytes: &[u8]) -> String {
    let artifact = crate::test_util::entity(seed);
    persist_imip_blob(
        vault,
        &artifact,
        "one-1786 invite",
        bytes,
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        WriteActor::new(actor, EdgeActorClass::Human),
        NOW,
    )
    .expect("persist blob")
}

/// Prior-thread evidence written the way the comm projector writes it, but
/// without depending on a projector pass: `comm.last_touch` on the party.
fn prior_thread(vault: &Vault, seed: u8, party: &str) {
    let party_ref = crate::comm::resolve_or_create_comm_party(vault, party).expect("party");
    let body = crate::comm::CommClaimValue::LastTouch {
        party_ref,
        channel_class: "email".to_owned(),
        occurred_at: NOW,
    }
    .claim_body();
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
        .expect("put last_touch claim");
}

/// The whole point of the pre-seam: CAL-09's surface constants and CAL-04's
/// registration constants are the SAME strings, or the branch is dead.
#[test]
fn verb_and_channel_match_the_cal_09_surface_constants() {
    assert_eq!(
        CALENDAR_INVITE_VERB,
        crate::memory::CALENDAR_INVITE_OUTBOUND_VERB
    );
    assert_eq!(
        CALENDAR_INVITE_CHANNEL,
        crate::memory::CALENDAR_INVITE_OUTBOUND_CHANNEL
    );
    assert_eq!(CalendarInviteMethod::Request.as_str(), "REQUEST");
    assert_eq!(CalendarInviteMethod::Cancel.as_str(), "CANCEL");
    assert_eq!(
        CalendarInviteMethod::parse("REQUEST"),
        Some(CalendarInviteMethod::Request)
    );
    assert_eq!(CalendarInviteMethod::parse("request"), None);
}

#[test]
fn calendar_invite_payload_is_exact_five_field_contract() {
    let payload = CalendarInvitePayload {
        method: CalendarInviteMethod::Request,
        uid: UID.to_owned(),
        sequence: 0,
        ics_blob_ref: "blob:c0ffee".to_owned(),
        recipient: "guest@example.test".to_owned(),
    };
    let wire = serde_json::to_value(&payload).expect("serialize");
    let object = wire.as_object().expect("object");
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["ics_blob_ref", "method", "recipient", "sequence", "uid"],
    );
    assert_eq!(object["method"], serde_json::json!("REQUEST"));

    // A forged hygiene assertion is a decode failure, not an ignored extra:
    // there is no channel by which a caller can hand the engine consent.
    let forged = serde_json::json!({
        "method": "REQUEST",
        "uid": UID,
        "sequence": 0,
        "ics_blob_ref": "blob:c0ffee",
        "recipient": "guest@example.test",
        "has_consent": true,
    });
    assert!(serde_json::from_value::<CalendarInvitePayload>(forged).is_err());

    // And a lowercase method is rejected rather than defaulted.
    let lowercased = serde_json::json!({
        "method": "request",
        "uid": UID,
        "sequence": 0,
        "ics_blob_ref": "blob:c0ffee",
        "recipient": "guest@example.test",
    });
    assert!(serde_json::from_value::<CalendarInvitePayload>(lowercased).is_err());
}

#[test]
fn calendar_invite_frozen_body_references_blob_not_raw_ics() {
    let payload = CalendarInvitePayload {
        method: CalendarInviteMethod::Request,
        uid: UID.to_owned(),
        sequence: 0,
        ics_blob_ref: "blob:c0ffee".to_owned(),
        recipient: "guest@example.test".to_owned(),
    };
    let frozen = serde_json::to_vec(&serde_json::json!({
        "verb": CALENDAR_INVITE_VERB,
        "calendar_invite": payload,
    }))
    .expect("freeze");
    let text = String::from_utf8(frozen.clone()).expect("utf-8");
    assert!(
        !text.contains("BEGIN:VCALENDAR"),
        "frozen body carried raw ICS: {text}"
    );
    assert!(text.contains("blob:c0ffee"));
    assert_eq!(
        decode_frozen_calendar_invite(&frozen).expect("decode"),
        payload
    );

    // Fail closed: a calendar.invite frozen call with no invite sidecar is
    // refused rather than treated as a generic send.
    let bare =
        serde_json::to_vec(&serde_json::json!({"verb": CALENDAR_INVITE_VERB})).expect("freeze");
    assert!(decode_frozen_calendar_invite(&bare).is_err());
}

/// One vault with everything a lawful REQUEST needs.
fn admitted_fixture() -> (tempfile::TempDir, Vault, EntityId, EntityId, String) {
    let (dir, vault) = open_calendar_vault();
    let actor = actor(&vault);
    let event_ref = event(&vault);
    identity(&vault, 0x53, actor, "email", "me@primary.test");
    prior_thread(&vault, 0x60, "guest@example.test");
    let blob_ref = blob(&vault, 0x54, actor, &emit(0, CalendarInviteMethod::Request));
    (dir, vault, actor, event_ref, blob_ref)
}

fn request(sequence: u32, blob_ref: &str) -> CalendarInvitePayload {
    CalendarInvitePayload {
        method: CalendarInviteMethod::Request,
        uid: UID.to_owned(),
        sequence,
        ics_blob_ref: blob_ref.to_owned(),
        recipient: "guest@example.test".to_owned(),
    }
}

#[test]
fn calendar_invite_first_confirm_mints_uid_once() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    let payload = request(0, &blob_ref);
    let admission =
        admit_calendar_invite(&vault, actor_ref, &payload, NOW).expect("first confirm admits");
    assert_eq!(admission.state_change(), CalendarInviteStateChange::MintUid);
    assert_eq!(admission.event_ref(), event_ref);
    assert_eq!(
        admission.hygiene().consent_basis(),
        Some(&CalendarInviteConsentBasis::PriorThread)
    );

    commit_admission(&vault, &admission, NOW).expect("commit passport");

    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].1.uid, UID);
    assert_eq!(live[0].1.last_sequence, 0);
    assert_eq!(live[0].1.direction, CalendarPassportDirection::Outbound);

    // A byte-identical re-admission is a replay: no second UID, no bump.
    let replay = admit_calendar_invite(&vault, actor_ref, &payload, NOW).expect("replay admits");
    assert_eq!(replay.state_change(), CalendarInviteStateChange::Replay);
    assert!(!replay.moves_state());
}

#[test]
fn calendar_invite_update_reuses_uid_and_increments_sequence() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    commit(&vault, actor_ref, &request(0, &blob_ref));

    let update_blob = blob(
        &vault,
        0x55,
        actor_ref,
        &emit(1, CalendarInviteMethod::Request),
    );
    let update = request(1, &update_blob);
    let admission = admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("update");
    assert_eq!(
        admission.state_change(),
        CalendarInviteStateChange::BumpSequence { from: 0 }
    );
    commit(&vault, actor_ref, &update);

    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1, "one live passport per (system x UID)");
    assert_eq!(live[0].1.uid, UID, "the UID is reused, never regenerated");
    assert_eq!(live[0].1.last_sequence, 1);

    // A regression is refused: a same-or-lower SEQUENCE is silently
    // ignored by real clients, so shipping one is an invisible failure.
    let stale = request(0, &blob_ref);
    assert!(matches!(
        admit_calendar_invite(&vault, actor_ref, &stale, NOW),
        Err(CalendarError::InviteRefused { .. })
    ));
}

#[test]
fn calendar_invite_cancel_reuses_uid_and_increments_sequence() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    commit(&vault, actor_ref, &request(0, &blob_ref));

    // Cancel needs the recipient already bound to the invite.
    attendee(&vault, 0x56, event_ref, "mailto:guest@example.test");
    let cancel_blob = blob(
        &vault,
        0x57,
        actor_ref,
        &emit(1, CalendarInviteMethod::Cancel),
    );
    let cancel = CalendarInvitePayload {
        method: CalendarInviteMethod::Cancel,
        uid: UID.to_owned(),
        sequence: 1,
        ics_blob_ref: cancel_blob,
        recipient: "guest@example.test".to_owned(),
    };
    let admission = admit_calendar_invite(&vault, actor_ref, &cancel, NOW).expect("cancel");
    assert_eq!(
        admission.state_change(),
        CalendarInviteStateChange::BumpSequence { from: 0 }
    );
    commit(&vault, actor_ref, &cancel);

    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1, "one live passport per (system x UID)");
    assert_eq!(
        live[0].1.uid, UID,
        "a CANCEL rides the SAME UID it invited on"
    );
    assert_eq!(live[0].1.last_sequence, 1);

    // The SEQUENCE the cancel consumed is spent: a later revision claiming
    // it — even a REQUEST with different content — is the regression real
    // clients silently ignore, so it is refused rather than sent.
    assert!(matches!(
        admit_calendar_invite(&vault, actor_ref, &request(1, &blob_ref), NOW),
        Err(CalendarError::InviteRefused { .. })
    ));
}

fn commit(vault: &Vault, actor_ref: EntityId, payload: &CalendarInvitePayload) {
    let admission = admit_calendar_invite(vault, actor_ref, payload, NOW).expect("admit");
    commit_admission(vault, &admission, NOW).expect("commit");
}

/// The retry lane never re-enters admission, so it cannot mint or bump
/// anything: it re-sends the FROZEN bytes, and the document it resolves
/// from them is the same document by reference rather than by re-rendering.
#[test]
fn calendar_invite_retry_replays_frozen_payload_without_sequence_bump() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    let payload = request(0, &blob_ref);
    commit(&vault, actor_ref, &payload);

    // Shaped like what the dispatch pipeline freezes beside the intent.
    let frozen = serde_json::to_vec(&serde_json::json!({
        "intent": {"channel": CALENDAR_INVITE_CHANNEL, "verb": CALENDAR_INVITE_VERB},
        "calendar_invite": payload,
    }))
    .expect("freeze");

    let first = decode_frozen_calendar_invite(&frozen).expect("decode");
    let retried = decode_frozen_calendar_invite(&frozen).expect("re-decode");
    assert_eq!(first, payload);
    assert_eq!(retried, payload, "a retry decodes the SAME five fields");

    let part = build_calendar_invite_mime_part(&vault, &first).expect("part");
    let retry_part = build_calendar_invite_mime_part(&vault, &retried).expect("retry part");
    assert_eq!(part, retry_part, "byte-identical, not merely equivalent");
    assert_eq!(
        part.ics,
        emit(0, CalendarInviteMethod::Request),
        "the retry resolved the stored document, it did not re-render one"
    );

    // Re-admitting the identical frozen revision is a Replay that writes
    // nothing, so even the path a retry does NOT take moves no state.
    let replay = admit_calendar_invite(&vault, actor_ref, &retried, NOW).expect("replay");
    assert_eq!(replay.state_change(), CalendarInviteStateChange::Replay);
    assert!(!replay.moves_state());
    commit_admission(&vault, &replay, NOW).expect("a replay commit writes nothing");

    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1, "no second UID");
    assert_eq!(live[0].1.uid, UID);
    assert_eq!(live[0].1.last_sequence, 0, "a retry never bumps a SEQUENCE");
}

/// No bumped SEQUENCE survives without its frozen intent.
///
/// Production applies the passport head inside the SAME write transaction
/// that enqueues the ready attempt and writes the connector TASK. This test
/// injects the failure of that durable commit — the exact window in which an
/// orphaned bump could otherwise survive — and pins that the passport is
/// left exactly where the last committed revision put it.
#[test]
fn calendar_invite_sequence_and_intent_commit_atomically() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    commit(&vault, actor_ref, &request(0, &blob_ref));

    let update_blob = blob(
        &vault,
        0x55,
        actor_ref,
        &emit(1, CalendarInviteMethod::Request),
    );
    let update = request(1, &update_blob);
    let admission = admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("update admits");
    assert_eq!(
        admission.state_change(),
        CalendarInviteStateChange::BumpSequence { from: 0 }
    );

    // Stage the head, then fail the transaction that would have carried the
    // attempt and the TASK with it.
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    admission
        .commit_in_txn(&vault, &mut wtxn, NOW)
        .expect("stage the passport head");
    wtxn.abort();

    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1, "the aborted head left no second passport");
    assert_eq!(live[0].1.uid, UID);
    assert_eq!(
        live[0].1.last_sequence, 0,
        "a failed durable commit leaves no orphaned SEQUENCE bump"
    );

    // The SEQUENCE was not consumed either: the same update still admits as
    // the same move and commits cleanly on the next pass.
    let retried =
        admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("re-admits unchanged");
    assert_eq!(
        retried.state_change(),
        CalendarInviteStateChange::BumpSequence { from: 0 }
    );
    commit_admission(&vault, &retried, NOW).expect("commit");
    let live =
        super::super::passport::live_passports_for_event(&vault, &event_ref).expect("passports");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].1.last_sequence, 1);
}

#[test]
fn calendar_invite_request_denies_without_consent_basis() {
    let (_dir, vault) = open_calendar_vault();
    let actor_ref = actor(&vault);
    let event_ref = event(&vault);
    identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
    let blob_ref = blob(
        &vault,
        0x54,
        actor_ref,
        &emit(0, CalendarInviteMethod::Request),
    );

    let refusal = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
        .expect_err("a cold invite never attaches an .ics");
    assert!(matches!(refusal, CalendarError::InviteRefused { .. }));

    // Nothing was minted behind the refusal: a cold invite leaves no UID.
    assert!(
        super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports")
            .is_empty()
    );
}

/// The first of the two bases that satisfy the no-cold-invite row, and the
/// only one that can exist before BK-03 (ONE-1814) mints the booking-page
/// standing grant.
#[test]
fn calendar_invite_prior_thread_satisfies_no_cold_invite() {
    let (_dir, vault) = open_calendar_vault();
    let actor_ref = actor(&vault);
    event(&vault);
    identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
    let blob_ref = blob(
        &vault,
        0x54,
        actor_ref,
        &emit(0, CalendarInviteMethod::Request),
    );
    // Cold to begin with: the very same caller bytes are refused while the
    // vault carries no evidence of a thread.
    assert!(admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).is_err());

    // One live `comm.last_touch` on email is a real prior thread.
    prior_thread(&vault, 0x60, "guest@example.test");
    let admission = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
        .expect("prior thread satisfies no-cold-invite");
    assert_eq!(
        admission.hygiene().consent_basis(),
        Some(&CalendarInviteConsentBasis::PriorThread)
    );
    assert_eq!(admission.state_change(), CalendarInviteStateChange::MintUid);
}

#[test]
fn calendar_invite_confirmed_booking_grant_satisfies_no_cold_invite() {
    let (_dir, vault) = open_calendar_vault();
    let actor_ref = actor(&vault);
    event(&vault);
    identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
    let blob_ref = blob(
        &vault,
        0x54,
        actor_ref,
        &emit(0, CalendarInviteMethod::Request),
    );
    assert!(admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).is_err());

    // CAL-04 VERIFIES the grant; BK-03 mints it. This is the mint door the
    // booking lane will use, driven here only to prove verification works.
    let grant_id = crate::test_util::entity(0x58);
    vault
        .mint_standing_outbound_grant(
            &grant_id,
            &crate::genui::GrantMintIntent {
                principal_ref: actor_ref.to_hex(),
                origin_component_id: "one_1786_test".to_owned(),
                origin_action_id: "confirm_booking".to_owned(),
                origin_receipt_ref: None,
                scope: crate::genui::GrantMintIntentScope::Contact {
                    contact_ref: "guest@example.test".to_owned(),
                },
            },
            NOW,
        )
        .expect("mint booking grant");

    let admission = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
        .expect("a confirmed booking grant satisfies no-cold-invite");
    assert_eq!(
        admission.hygiene().consent_basis(),
        Some(&CalendarInviteConsentBasis::ConfirmedBookingGrant {
            grant_ref: grant_id
        })
    );
}

#[test]
fn calendar_invite_cancel_requires_existing_recipient_binding() {
    let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
    commit(&vault, actor_ref, &request(0, &blob_ref));
    let cancel_blob = blob(
        &vault,
        0x57,
        actor_ref,
        &emit(1, CalendarInviteMethod::Cancel),
    );
    let cancel = CalendarInvitePayload {
        method: CalendarInviteMethod::Cancel,
        uid: UID.to_owned(),
        sequence: 1,
        ics_blob_ref: cancel_blob,
        recipient: "stranger@example.test".to_owned(),
    };
    let refusal = admit_calendar_invite(&vault, actor_ref, &cancel, NOW)
        .expect_err("cancel to an unbound recipient is a cold ping");
    assert!(matches!(refusal, CalendarError::InviteRefused { .. }));

    attendee(&vault, 0x59, event_ref, "stranger@example.test");
    // The binding alone is not enough for a stranger: consent still rules.
    prior_thread(&vault, 0x61, "stranger@example.test");
    let admission = admit_calendar_invite(&vault, actor_ref, &cancel, NOW)
        .expect("a bound recipient may be cancelled");
    assert_eq!(admission.event_ref(), event_ref);
    assert!(matches!(
        admission.state_change(),
        CalendarInviteStateChange::BumpSequence { from: 0 },
    ));
}

#[test]
fn calendar_invite_denies_non_primary_sender_domain() {
    let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
    // A calendar-channel identity on a different domain now carries the
    // send: sequencer-class infrastructure, not the primary calendar domain.
    identity(
        &vault,
        0x5A,
        actor_ref,
        CALENDAR_INVITE_CHANNEL,
        "bulk@sequencer.test",
    );
    let refusal = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
        .expect_err("an off-domain sender never carries a real invite");
    assert!(matches!(refusal, CalendarError::InviteRefused { .. }));
}

#[test]
fn calendar_invite_ignores_caller_hygiene_bools_and_rehydrates_from_vault() {
    let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
    let payload = request(0, &blob_ref);
    let from_vault =
        admit_calendar_invite(&vault, actor_ref, &payload, NOW).expect("admits on real evidence");

    // There is no API by which a caller supplies hygiene: the only public
    // input is the five-field payload. Changing stored sender evidence
    // flips the verdict without changing that payload.
    assert!(matches!(
        from_vault.hygiene().consent_basis(),
        Some(CalendarInviteConsentBasis::PriorThread),
    ));
    assert!(matches!(
        from_vault.state_change(),
        CalendarInviteStateChange::MintUid,
    ));
    identity(
        &vault,
        0x5A,
        actor_ref,
        CALENDAR_INVITE_CHANNEL,
        "bulk@sequencer.test",
    );
    assert!(matches!(
        admit_calendar_invite(&vault, actor_ref, &payload, NOW),
        Err(CalendarError::InviteRefused { .. }),
    ));

    let (_dir2, bare) = open_calendar_vault();
    let bare_actor = actor(&bare);
    event(&bare);
    identity(&bare, 0x53, bare_actor, "email", "me@primary.test");
    let bare_blob = blob(
        &bare,
        0x54,
        bare_actor,
        &emit(0, CalendarInviteMethod::Request),
    );
    assert!(
        matches!(
            admit_calendar_invite(&bare, bare_actor, &request(0, &bare_blob), NOW),
            Err(CalendarError::InviteRefused { .. }),
        ),
        "the same caller bytes must refuse when the vault carries no consent",
    );
}

#[test]
fn connector_send_builds_text_calendar_method_part() {
    let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
    let payload = request(0, &blob_ref);
    let part = build_calendar_invite_mime_part(&vault, &payload).expect("mime part");
    assert_eq!(
        part.content_type,
        "text/calendar; method=REQUEST; charset=utf-8"
    );
    assert_eq!(part.filename, CALENDAR_INVITE_PART_FILENAME);
    let text = String::from_utf8(part.ics).expect("utf-8");
    assert!(text.starts_with("BEGIN:VCALENDAR\r\n"));
    assert!(text.contains("METHOD:REQUEST\r\n"));
    assert!(text.contains(&format!("UID:{UID}\r\n")));

    let cancel_blob = blob(
        &vault,
        0x5B,
        actor_ref,
        &emit(1, CalendarInviteMethod::Cancel),
    );
    let cancel = CalendarInvitePayload {
        method: CalendarInviteMethod::Cancel,
        uid: UID.to_owned(),
        sequence: 1,
        ics_blob_ref: cancel_blob,
        recipient: "guest@example.test".to_owned(),
    };
    let part = build_calendar_invite_mime_part(&vault, &cancel).expect("cancel part");
    assert_eq!(
        part.content_type,
        "text/calendar; method=CANCEL; charset=utf-8"
    );
}

#[test]
fn tool_descriptor_keeps_the_invite_effectful_and_idempotent() {
    assert_eq!(CALENDAR_INVITE_TOOL_DESCRIPTOR.read_only_hint, Some(false));
    assert_eq!(
        CALENDAR_INVITE_TOOL_DESCRIPTOR.idempotency_supported_hint,
        Some(true)
    );
}

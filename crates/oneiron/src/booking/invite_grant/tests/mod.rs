//! Lane tests for the booking page's standing invite grant.

mod faceted_sender;

use super::*;

use rmpv::Value;
use serde::Serialize;

use crate::booking::constraint::EventTypeKey;
use crate::booking::lifecycle::{BOOKING_PASSPORT_SYSTEM, CalendarRevision, OpaqueLifecycleToken};
use crate::calendar::{CALENDAR_INVITE_MEDIA_TYPE, CalendarInviteConsentBasis, index_passport_uid};
use crate::campaign::claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use crate::channel_identity::{ChannelIdentity, SelfHeldShape};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::outbound_consent::DataClass;
use crate::outbound_grant::{
    decode_standing_outbound_grant_body, encode_standing_outbound_grant_body,
};
use crate::outbound_intent_ledger::IntentLedgerRecord;
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

/// This module's own bytes, read back so the ownership oracles below can
/// assert what booking does NOT contain.
const SOURCE: &str = concat!(
    include_str!("../mod.rs"),
    include_str!("../types.rs"),
    include_str!("../authorization.rs"),
    include_str!("../mint.rs"),
    include_str!("../dispatch.rs"),
    include_str!("../codec.rs"),
    include_str!("mod.rs"),
    include_str!("faceted_sender.rs"),
);

const NOW: u64 = 1_800_000_000;
const RECIPIENT: &str = "booker@example.test";
const STRANGER: &str = "stranger@example.test";
const SENDER: &str = "host@primary.test";
const EVENT_TYPE: &str = "intro";
const SLOT_START: u64 = NOW + 3_600;
const SLOT_END: u64 = NOW + 7_200;

// ── fixtures ────────────────────────────────────────────────────────

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    page: EntityId,
    booking: EntityId,
    uid: String,
}

impl Fixture {
    fn grant(&self) -> EntityId {
        mint_publish_page_invite_grant(
            &self.vault,
            &PublishBookingPageGrantRequest {
                page_ref: self.page,
                publisher_principal: self.actor,
                issued_at: crate::unix_seconds_now(),
            },
        )
        .expect("publish mints the page grant");
        page_invite_grant_id(&self.page).expect("page grant id")
    }
}

/// The OF-336 manifest shape the outbound spine's own tests use: an `auto`
/// ceiling for this actor plus a scoped grant for the exact verb. Without
/// a manifest the gate has no policy version and denies every effect, so
/// this is what makes an ALLOW decidable in a test vault.
fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
    let scoped_grants = verbs
        .iter()
        .map(|verb| {
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{verb}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("one-1814-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("actor_ref"), Value::from(actor_ref)),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
                // Class-wide rows so post-manifest fixture writes clear the
                // ceiling axis: public `Vault::put_claim` carries no envelope
                // (gate sees `first_party`, no ref) and blob persists ride a
                // `Human` edge actor. Mirrors the engine default manifest
                // (gate/default_manifest.rs first_party + human auto rows);
                // omitting `actor_ref` is the established class-wide spelling
                // (gate/decode.rs `parse_actor_ceilings` optional_string).
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("first_party")),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("human")),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
            ]),
        ),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn person(vault: &Vault, seed: u8, body: &[u8]) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            body,
        )
        .expect("put person");
    id
}

fn event(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(EVENT_TYPE))]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: SLOT_START,
                end: SLOT_END - 1,
            },
            NOW,
            &body,
        )
        .expect("put booking event");
    id
}

fn claim_value<T: Serialize>(value: &T) -> Value {
    let bytes = rmp_serde::to_vec_named(value).expect("encode claim value");
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.as_slice()))
        .expect("decode claim value")
}

/// The four exact claims ONE-1813's confirm commits, written the way it
/// writes them: engine-recorded, `Auto` approval, `Observed` source.
fn put_booking_claims(
    vault: &Vault,
    base_seed: u8,
    booking: EntityId,
    page: EntityId,
    booker: EntityId,
    status: BookingStatus,
) {
    let values = [
        (
            BOOKING_EVENT_TYPE_REF_PREDICATE,
            claim_value(&BookingEventTypeRefValue {
                event_type: EventTypeKey(EVENT_TYPE.to_owned()),
            }),
        ),
        (
            BOOKING_BOOKER_CONTACT_PREDICATE,
            claim_value(&BookingBookerContactValue {
                contact_ref: booker,
            }),
        ),
        (
            BOOKING_SOURCE_PAGE_PREDICATE,
            claim_value(&BookingSourcePageValue { page_ref: page }),
        ),
        (
            BOOKING_STATUS_PREDICATE,
            claim_value(&BookingStatusValue {
                status,
                recorded_at: NOW,
            }),
        ),
    ];
    for (index, (predicate, value)) in values.into_iter().enumerate() {
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(booking),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        body.valid_from = Some(NOW);
        let seed = base_seed
            .checked_add(u8::try_from(index).expect("claim index"))
            .expect("claim seed");
        vault
            .put_claim(
                &entity(seed),
                &body,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("put booking claim");
    }
}

fn identity(vault: &Vault, seed: u8, actor: EntityId, channel: &str, address: &str) {
    let mut identity = ChannelIdentity::requested(
        channel,
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(actor),
        NOW,
    );
    identity.state = ChannelIdentityState::Active;
    vault
        .create_channel_identity(&entity(seed), &identity)
        .expect("create sending identity");
}

fn ics_blob(vault: &Vault, seed: u8, actor: EntityId, uid: &str, sequence: u32) -> String {
    let ics = emit_imip_ics(&ImipEmitRequest {
        method: CalendarInviteMethod::Request,
        uid: uid.to_owned(),
        sequence,
        organizer: SENDER.to_owned(),
        attendees: vec![RECIPIENT.to_owned()],
        summary: EVENT_TYPE.to_owned(),
        starts_at_utc: SLOT_START,
        ends_at_utc: SLOT_END,
        tz_label: CONFIRM_INVITE_TZ_LABEL.to_owned(),
        dtstamp_utc: NOW,
    })
    .expect("emit invite document");
    persist_imip_blob(
        vault,
        &entity(seed),
        "one-1814 invite",
        &ics,
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(actor, EdgeActorClass::Human),
        NOW,
    )
    .expect("persist invite blob")
}

fn build(with_sender: bool) -> Fixture {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let actor = person(&vault, 0x71, b"one-1814 actor");
    let page = entity(0x72);
    let booker = person(&vault, 0x73, RECIPIENT.as_bytes());
    let booking = event(&vault, 0x74);
    put_booking_claims(
        &vault,
        0x75,
        booking,
        page,
        booker,
        BookingStatus::Confirmed,
    );
    if with_sender {
        identity(&vault, 0x79, actor, "email", SENDER);
    }
    let uid = format!("{}@{BOOKING_PASSPORT_SYSTEM}", booking.to_hex());
    index_passport_uid(&vault, &uid, &booking).expect("index booking uid");
    // Seeded BEFORE any mint: the grant binds to the policy floor in
    // effect when it was minted, and a floor that moves afterwards would
    // make it inert at the gate.
    put_policy_manifest_bytes(
        &vault,
        entity(0x7A),
        &policy_manifest(
            &actor.to_hex(),
            CALENDAR_INVITE_CHANNEL,
            &[CALENDAR_INVITE_VERB],
        ),
    )
    .expect("seed policy manifest");
    Fixture {
        _dir: dir,
        vault,
        actor,
        page,
        booking,
        uid,
    }
}

fn fixture() -> Fixture {
    build(true)
}

#[derive(Default)]
struct SpySink {
    calls: usize,
    invite_methods: Vec<Option<CalendarInviteMethod>>,
}

impl OutboundExecutionSink for SpySink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        self.invite_methods
            .push(request.calendar_invite.as_ref().map(|part| part.method));
        OutboundExecutionOutcome::delivered_to_channel("provider:invite:one")
    }
}

fn payload_for(fixture: &Fixture, blob_ref: &str, recipient: &str) -> CalendarInvitePayload {
    CalendarInvitePayload {
        method: CalendarInviteMethod::Request,
        uid: fixture.uid.clone(),
        sequence: 0,
        ics_blob_ref: blob_ref.to_owned(),
        recipient: recipient.to_owned(),
    }
}

fn invite_ledger_records(vault: &Vault) -> Vec<IntentLedgerRecord> {
    intent_ledger_records(vault)
        .expect("intent ledger")
        .into_iter()
        .filter(|record| record.tool == CALENDAR_INVITE_VERB)
        .collect()
}

fn frozen_invite(vault: &Vault, intent_id: IntentId) -> CalendarInvitePayload {
    let record = invite_ledger_records(vault)
        .into_iter()
        .find(|record| record.id == intent_id)
        .expect("the returned intent id names a ledger record");
    decode_frozen_calendar_invite(record.payload()).expect("frozen five-field body")
}

fn live_booking_page_grants(vault: &Vault) -> Vec<EntityId> {
    vault
        .entities_by_type(ENTITY_TYPE_OUTBOUND_GRANT)
        .expect("grants")
        .into_iter()
        .filter(|id| {
            vault
                .get_standing_outbound_grant(id)
                .expect("grant")
                .is_some_and(|grant| {
                    grant.status == StandingOutboundGrantStatus::Active
                        && matches!(
                            grant.scope,
                            StandingOutboundGrantScope::BookingPageInvites { .. }
                        )
                })
        })
        .collect()
}

fn seed_do_not_contact(vault: &Vault, seed: u8, party: &str) {
    let party_ref = crate::comm::resolve_or_create_comm_party(vault, party).expect("party");
    vault
        .put_claim(
            &entity(seed),
            &ClaimBody::new(
                PREDICATE_COMM_DO_NOT_CONTACT,
                ClaimSubject::Entity(party_ref),
                encode_do_not_contact_value(&CommDoNotContactValue {
                    channel: Some(CALENDAR_INVITE_CHANNEL.to_owned()),
                    scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
                }),
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
        .expect("put do-not-contact head");
}

fn context<'a>(
    booking: EntityId,
    verb: &'a str,
    recipient: &'a str,
) -> BookingPageInviteContext<'a> {
    BookingPageInviteContext {
        booking_ref: booking,
        verb_kind: verb,
        requested_recipient: recipient,
    }
}

// ── codec ───────────────────────────────────────────────────────────

fn grant_with(scope: StandingOutboundGrantScope) -> StandingOutboundGrant {
    StandingOutboundGrant {
        principal_ref: "owner".to_owned(),
        origin_component_id: "one-1814".to_owned(),
        origin_action_id: "publish_booking_page".to_owned(),
        origin_receipt_ref: None,
        scope,
        status: StandingOutboundGrantStatus::Active,
        created_at: 10,
        revoked_at: None,
        last_used_at: None,
        binding_diff_handle: vec![0xA5; 32],
        read_frontier_hash: [0xB6; 32],
    }
}

/// Number of pairs the encoded body's nested `scope` map carries.
fn scope_pairs(encoded: &[u8]) -> usize {
    let body =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).expect("decode grant body");
    let Value::Map(entries) = body else {
        panic!("grant body must be a map");
    };
    let scope = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("scope"))
        .map(|(_, value)| value)
        .expect("scope field");
    let Value::Map(pairs) = scope else {
        panic!("scope must be a map");
    };
    pairs.len()
}

#[test]
fn booking_page_invite_scope_round_trips_without_retagging_existing_scopes() {
    let page = entity(0x72);
    let scopes = [
        StandingOutboundGrantScope::Contact {
            contact_ref: "contact:one".to_owned(),
        },
        StandingOutboundGrantScope::VerbClass {
            verb_class: "send".to_owned(),
        },
        StandingOutboundGrantScope::Channel {
            channel: "email".to_owned(),
        },
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: "brief:one".to_owned(),
            verb_class: "send".to_owned(),
        },
        StandingOutboundGrantScope::ScopedMcp {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        StandingOutboundGrantScope::BookingPageInvites { page_ref: page },
    ];
    for scope in scopes {
        let is_new = matches!(scope, StandingOutboundGrantScope::BookingPageInvites { .. });
        let grant = grant_with(scope);
        let encoded = encode_standing_outbound_grant_body(&grant).expect("encode");
        let decoded = decode_standing_outbound_grant_body(&encoded).expect("decode");
        assert_eq!(decoded, grant, "a round trip must not retag a scope");
        assert_eq!(decoded.scope.dial_label(), grant.scope.dial_label());
        // Discriminating: a Nil tenth pair on the old scopes would move
        // their encoded bytes, which is exactly what append-only forbids.
        assert_eq!(
            scope_pairs(&encoded),
            if is_new { 10 } else { 9 },
            "only the booking-page scope carries the tenth key"
        );
    }
}

#[test]
fn booking_page_invite_scope_without_its_page_fails_closed() {
    let grant = grant_with(StandingOutboundGrantScope::BookingPageInvites {
        page_ref: entity(0x72),
    });
    let encoded = encode_standing_outbound_grant_body(&grant).expect("encode");
    let mut body =
        rmpv::decode::read_value(&mut std::io::Cursor::new(&encoded)).expect("decode grant body");
    let Value::Map(entries) = &mut body else {
        panic!("grant body must be a map");
    };
    let scope = &mut entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scope"))
        .expect("scope field")
        .1;
    let Value::Map(pairs) = scope else {
        panic!("scope must be a map");
    };
    pairs.retain(|(key, _)| key.as_str() != Some("page_ref"));
    let mut stripped = Vec::new();
    rmpv::encode::write_value(&mut stripped, &body).expect("re-encode");
    assert!(
        decode_standing_outbound_grant_body(&stripped).is_err(),
        "a booking-page row that names no page must authorize nothing"
    );
}

// ── mint ────────────────────────────────────────────────────────────

#[test]
fn publish_page_mints_one_live_booking_page_invite_grant() {
    let fixture = fixture();
    let request = PublishBookingPageGrantRequest {
        page_ref: fixture.page,
        publisher_principal: fixture.actor,
        issued_at: NOW,
    };
    let first =
        mint_publish_page_invite_grant(&fixture.vault, &request).expect("first publish mints");
    let second =
        mint_publish_page_invite_grant(&fixture.vault, &request).expect("second publish reuses");
    assert_eq!(first, second, "publishing twice must not mint twice");
    assert_eq!(
        first.scope,
        StandingOutboundGrantScope::BookingPageInvites {
            page_ref: fixture.page
        }
    );
    assert_eq!(first.status, StandingOutboundGrantStatus::Active);
    assert_eq!(
        live_booking_page_grants(&fixture.vault).len(),
        1,
        "exactly one live grant per page"
    );
}

// ── authorize / deny matrix ─────────────────────────────────────────

#[test]
fn page_grant_authorizes_calendar_invite_for_confirmed_booker() {
    let fixture = fixture();
    let scope = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: fixture.page,
    };
    assert!(
        booking_page_invites_authorizes(
            &fixture.vault,
            &scope,
            &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
        )
        .expect("authorize")
    );
}

#[test]
fn page_grant_denies_different_page() {
    let fixture = fixture();
    let scope = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: entity(0x7B),
    };
    assert!(
        !booking_page_invites_authorizes(
            &fixture.vault,
            &scope,
            &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
        )
        .expect("authorize")
    );
    assert!(
        !booking_page_grant_covers_recipient(&fixture.vault, &entity(0x7B), RECIPIENT)
            .expect("covers")
    );
}

#[test]
fn page_grant_denies_different_recipient() {
    let fixture = fixture();
    let scope = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: fixture.page,
    };
    assert!(
        !booking_page_invites_authorizes(
            &fixture.vault,
            &scope,
            &context(fixture.booking, CALENDAR_INVITE_VERB, STRANGER),
        )
        .expect("authorize")
    );
    assert!(
        !booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, STRANGER)
            .expect("covers")
    );
}

#[test]
fn page_grant_denies_non_calendar_verb() {
    let fixture = fixture();
    let scope = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: fixture.page,
    };
    for verb in ["send", "send_media", "push", "calendar.invite.v2"] {
        assert!(
            !booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(fixture.booking, verb, RECIPIENT),
            )
            .expect("authorize"),
            "the page grant must authorize exactly one verb, not {verb}"
        );
    }
}

#[test]
fn page_grant_denies_unbound_recipient_without_consent_basis() {
    let fixture = fixture();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
    // No prior thread and no verified grant: the REQUEST is cold.
    assert!(
        admit_calendar_invite(
            &fixture.vault,
            fixture.actor,
            &payload_for(&fixture, &blob, RECIPIENT),
            NOW,
        )
        .is_err(),
        "an unbound recipient with no consent basis must refuse"
    );
    // A live grant for a DIFFERENT page changes nothing: it binds no
    // booking on this page and therefore no recipient.
    mint_publish_page_invite_grant(
        &fixture.vault,
        &PublishBookingPageGrantRequest {
            page_ref: entity(0x7B),
            publisher_principal: fixture.actor,
            issued_at: NOW,
        },
    )
    .expect("mint an unrelated page grant");
    assert!(
        admit_calendar_invite(
            &fixture.vault,
            fixture.actor,
            &payload_for(&fixture, &blob, RECIPIENT),
            NOW,
        )
        .is_err(),
        "a grant for another page never binds this recipient"
    );
}

#[test]
fn confirmed_booking_grant_satisfies_no_cold_invite_for_bound_booker() {
    let fixture = fixture();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
    let payload = payload_for(&fixture, &blob, RECIPIENT);
    assert!(
        admit_calendar_invite(&fixture.vault, fixture.actor, &payload, NOW).is_err(),
        "the same caller bytes refuse while the vault carries no grant"
    );

    let grant_ref = fixture.grant();
    let admission = admit_calendar_invite(&fixture.vault, fixture.actor, &payload, NOW)
        .expect("the page grant satisfies the no-cold-invite row");
    assert_eq!(
        admission.hygiene().consent_basis(),
        Some(&CalendarInviteConsentBasis::ConfirmedBookingGrant { grant_ref })
    );
}

#[test]
fn forged_invite_hygiene_context_cannot_pass() {
    let fixture = fixture();
    let grant_ref = fixture.grant();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);

    // There is nowhere to put a caller-asserted consent: a sixth key is a
    // decode failure, not an ignored extra.
    let forged = serde_json::json!({
        "method": "REQUEST",
        "uid": fixture.uid,
        "sequence": 0,
        "ics_blob_ref": blob,
        "recipient": RECIPIENT,
        "has_consent": true,
    });
    assert!(serde_json::from_value::<CalendarInvitePayload>(forged).is_err());

    // And naming a different recipient does not borrow this page's grant:
    // the binding comes from the booking's claims, not from the payload.
    assert!(
        admit_calendar_invite(
            &fixture.vault,
            fixture.actor,
            &payload_for(&fixture, &blob, STRANGER),
            NOW,
        )
        .is_err(),
        "a forged recipient cannot ride a live page grant"
    );
    assert!(
        !booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, STRANGER)
            .expect("covers")
    );

    // The dispatch seam refuses the same way, and it refuses BEFORE any
    // outbound work: the grant it was handed does not cover the booking's
    // persisted booker under a forged page.
    let mut sink = SpySink::default();
    assert!(
        enqueue_confirm_invite(
            &fixture.vault,
            fixture.actor,
            grant_ref,
            &ConfirmedBookingInvite {
                booking_ref: entity(0x7D),
                uid: &fixture.uid,
                sequence: 0,
                ics_blob_ref: &blob,
            },
            &mut sink,
            NOW,
        )
        .is_err()
    );
    assert_eq!(sink.calls, 0);
    assert!(invite_ledger_records(&fixture.vault).is_empty());
}

#[test]
fn authorization_resolves_page_and_recipient_from_vault_claims() {
    let fixture = fixture();
    let scope = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: fixture.page,
    };
    assert!(
        booking_page_invites_authorizes(
            &fixture.vault,
            &scope,
            &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
        )
        .expect("authorize")
    );
    assert!(
        booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, RECIPIENT)
            .expect("covers")
    );

    // An EVENT carrying no booking claims binds nobody.
    let bare = event(&fixture.vault, 0x7D);
    assert!(
        !booking_page_invites_authorizes(
            &fixture.vault,
            &scope,
            &context(bare, CALENDAR_INVITE_VERB, RECIPIENT),
        )
        .expect("authorize")
    );

    // A booking whose recorded booker contact resolves to no stored
    // identity binds nobody either: absent evidence denies.
    let ghost_page = entity(0x7E);
    let ghost = event(&fixture.vault, 0x7F);
    put_booking_claims(
        &fixture.vault,
        0x81,
        ghost,
        ghost_page,
        entity(0x85),
        BookingStatus::Confirmed,
    );
    assert!(
        !booking_page_grant_covers_recipient(&fixture.vault, &ghost_page, RECIPIENT)
            .expect("covers")
    );

    // A CANCELLED booking is not a confirmed one: its page binds nobody.
    let cancelled_page = entity(0x86);
    let cancelled = event(&fixture.vault, 0x87);
    put_booking_claims(
        &fixture.vault,
        0x88,
        cancelled,
        cancelled_page,
        person(&fixture.vault, 0x8C, RECIPIENT.as_bytes()),
        BookingStatus::Cancelled,
    );
    assert!(
        !booking_page_grant_covers_recipient(&fixture.vault, &cancelled_page, RECIPIENT)
            .expect("covers")
    );
}

// ── dispatch ────────────────────────────────────────────────────────

#[test]
fn confirm_invite_uses_frozen_calendar_payload_contract() {
    let fixture = fixture();
    let grant_ref = fixture.grant();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
    let mut sink = SpySink::default();
    let intent_id = enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        grant_ref,
        &ConfirmedBookingInvite {
            booking_ref: fixture.booking,
            uid: &fixture.uid,
            sequence: 0,
            ics_blob_ref: &blob,
        },
        &mut sink,
        NOW,
    )
    .expect("the invite dispatches");

    let frozen = frozen_invite(&fixture.vault, intent_id);
    assert_eq!(frozen.method, CalendarInviteMethod::Request);
    assert_eq!(frozen.uid, fixture.uid);
    assert_eq!(frozen.sequence, 0);
    assert_eq!(frozen.ics_blob_ref, blob);
    assert_eq!(frozen.recipient, RECIPIENT);
    assert_eq!(frozen, payload_for(&fixture, &blob, RECIPIENT));

    // The frozen body carries the blob REFERENCE, never the document.
    let record = invite_ledger_records(&fixture.vault)
        .into_iter()
        .find(|record| record.id == intent_id)
        .expect("ledger record");
    assert!(
        !String::from_utf8_lossy(record.payload()).contains("BEGIN:VCALENDAR"),
        "the frozen body must reference the document, not carry it"
    );
}

#[test]
fn confirm_invite_uses_once_minted_uid_and_current_sequence() {
    let fixture = fixture();
    fixture.grant();
    let receipt = ConfirmReceipt {
        calendar: CalendarRevision {
            event_ref: fixture.booking,
            uid: fixture.uid.clone(),
            sequence: 0,
        },
        reschedule_token: OpaqueLifecycleToken("reschedule".to_owned()),
        cancel_token: OpaqueLifecycleToken("cancel".to_owned()),
    };
    let mut sink = SpySink::default();
    let first =
        dispatch_confirm_booking_invite(&fixture.vault, fixture.actor, &receipt, &mut sink, NOW)
            .expect("the first confirm emits one REQUEST");
    let frozen = frozen_invite(&fixture.vault, first);
    assert_eq!(
        frozen.uid, receipt.calendar.uid,
        "the UID is reused, never re-minted"
    );
    assert_eq!(frozen.sequence, receipt.calendar.sequence);

    // An idempotent confirm replay answers with the intent the first pass
    // recorded: no second UID, no second REQUEST, no bumped SEQUENCE.
    let second =
        dispatch_confirm_booking_invite(&fixture.vault, fixture.actor, &receipt, &mut sink, NOW)
            .expect("a replay resolves to the recorded intent");
    assert_eq!(first, second);
    assert_eq!(sink.calls, 1, "one booking earns one REQUEST");
    assert_eq!(invite_ledger_records(&fixture.vault).len(), 1);
}

#[test]
fn confirm_invite_calls_gate_before_ledger_and_connector() {
    // Denied: the gate refuses before anything is frozen, so there is no
    // ledger record to replay and the connector is never reached.
    let denied = fixture();
    let denied_grant = denied.grant();
    let denied_blob = ics_blob(&denied.vault, 0x7C, denied.actor, &denied.uid, 0);
    seed_do_not_contact(&denied.vault, 0x8A, RECIPIENT);
    let mut denied_sink = SpySink::default();
    assert!(
        enqueue_confirm_invite(
            &denied.vault,
            denied.actor,
            denied_grant,
            &ConfirmedBookingInvite {
                booking_ref: denied.booking,
                uid: &denied.uid,
                sequence: 0,
                ics_blob_ref: &denied_blob,
            },
            &mut denied_sink,
            NOW,
        )
        .is_err(),
        "a gate denial must not become an invite"
    );
    assert_eq!(denied_sink.calls, 0, "no connector call behind a denial");
    assert!(
        invite_ledger_records(&denied.vault).is_empty(),
        "no intent is frozen behind a denial"
    );

    // Allowed: exactly one frozen intent, then exactly one connector call
    // whose invitation part was resolved from those frozen bytes.
    let allowed = fixture();
    let allowed_grant = allowed.grant();
    let allowed_blob = ics_blob(&allowed.vault, 0x7C, allowed.actor, &allowed.uid, 0);
    let mut allowed_sink = SpySink::default();
    enqueue_confirm_invite(
        &allowed.vault,
        allowed.actor,
        allowed_grant,
        &ConfirmedBookingInvite {
            booking_ref: allowed.booking,
            uid: &allowed.uid,
            sequence: 0,
            ics_blob_ref: &allowed_blob,
        },
        &mut allowed_sink,
        NOW,
    )
    .expect("the invite dispatches");
    assert_eq!(invite_ledger_records(&allowed.vault).len(), 1);
    assert_eq!(allowed_sink.calls, 1);
    assert_eq!(
        allowed_sink.invite_methods,
        vec![Some(CalendarInviteMethod::Request)],
        "the connector received the part resolved from the frozen ref"
    );
}

#[test]
fn standing_grant_removes_ping_not_gate() {
    let fixture = fixture();
    let grant_ref = fixture.grant();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
    let mut sink = SpySink::default();
    enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        grant_ref,
        &ConfirmedBookingInvite {
            booking_ref: fixture.booking,
            uid: &fixture.uid,
            sequence: 0,
            ics_blob_ref: &blob,
        },
        &mut sink,
        NOW,
    )
    .expect("a live page grant needs no per-send prompt");
    // No owner ping: the send completed in ONE pass, with no pending
    // decision left for anyone to answer.
    assert_eq!(sink.calls, 1);
    // Every rail still ran: the ledger has its record...
    assert_eq!(invite_ledger_records(&fixture.vault).len(), 1);
    // ...and the passport head moved with it, which only the admitted
    // path writes.
    assert_eq!(
        crate::calendar::live_passports_for_event(&fixture.vault, &fixture.booking)
            .expect("passports")
            .len(),
        1
    );

    // Hygiene hydration still runs with a live grant: the same call with
    // no active sending identity in the vault refuses.
    let bare = build(false);
    let bare_grant = bare.grant();
    let bare_blob = ics_blob(&bare.vault, 0x7C, bare.actor, &bare.uid, 0);
    let mut bare_sink = SpySink::default();
    assert!(
        enqueue_confirm_invite(
            &bare.vault,
            bare.actor,
            bare_grant,
            &ConfirmedBookingInvite {
                booking_ref: bare.booking,
                uid: &bare.uid,
                sequence: 0,
                ics_blob_ref: &bare_blob,
            },
            &mut bare_sink,
            NOW,
        )
        .is_err(),
        "a standing grant never skips vault-only hygiene hydration"
    );
    assert_eq!(bare_sink.calls, 0);
}

#[test]
fn gate_denial_prevents_invite_even_with_live_page_grant() {
    let fixture = fixture();
    let grant_ref = fixture.grant();
    let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
    // The grant is live and the recipient IS the persisted booker — and
    // the opt-out still wins.
    assert!(
        booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, RECIPIENT)
            .expect("covers")
    );
    seed_do_not_contact(&fixture.vault, 0x8A, RECIPIENT);
    let mut sink = SpySink::default();
    assert!(
        enqueue_confirm_invite(
            &fixture.vault,
            fixture.actor,
            grant_ref,
            &ConfirmedBookingInvite {
                booking_ref: fixture.booking,
                uid: &fixture.uid,
                sequence: 0,
                ics_blob_ref: &blob,
            },
            &mut sink,
            NOW,
        )
        .is_err(),
        "opt-out denial outranks a live standing grant"
    );
    assert_eq!(sink.calls, 0);
    assert!(invite_ledger_records(&fixture.vault).is_empty());
    // Nothing moved behind the denial: no passport head, no spent SEQUENCE.
    assert!(
        crate::calendar::live_passports_for_event(&fixture.vault, &fixture.booking)
            .expect("passports")
            .is_empty()
    );
}

// ── ownership ───────────────────────────────────────────────────────

#[test]
fn calendar_invite_types_are_owned_by_cal04() {
    for forbidden in [
        concat!("struct ", "CalendarInvite"),
        concat!("enum ", "CalendarInvite"),
        concat!("struct ", "InvitePayload"),
        concat!("enum ", "InviteConsent"),
        concat!("struct ", "InviteHygiene"),
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "booking must import CAL-04's shapes, not define `{forbidden}`"
        );
    }
    assert!(SOURCE.contains("use crate::calendar::"));
    // CAL-04 registered the verb exactly once, and booking adds none.
    assert_eq!(
        crate::outbound::COMMON_OUTBOUND_VERB_KINDS
            .iter()
            .filter(|kind| kind.starts_with("calendar."))
            .count(),
        1
    );
    assert_eq!(CALENDAR_INVITE_VERB, "calendar.invite");
}

#[test]
fn connector_owns_calendar_mime_assembly() {
    for forbidden in [
        concat!("text/", "calendar"),
        concat!("build_calendar_invite", "_mime_part"),
        concat!("CalendarInvite", "MimePart"),
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "booking must never assemble `{forbidden}`"
        );
    }
    // The media type is CAL-04's, and only its builder puts it on the wire.
    assert_eq!(CALENDAR_INVITE_MEDIA_TYPE, concat!("text/", "calendar"));
}

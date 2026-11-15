//! A passport replay of a confirm invite retries a still-Pending transport
//! through dispatch (FIX-LIST row 351).
//!
//! The first pass of a confirm invite dispatches through the ordinary outbound
//! door and records its intent. When that pass's transport fails definitely,
//! the intent stays Pending, queued for retry. A replay of the exact revision
//! (same UID, same SEQUENCE, same bytes) must route that retry through
//! dispatch again; main answered with the recorded intent without dispatching,
//! so the invite stayed Pending forever. A replay of a settled send still
//! answers with the recorded intent and sends nothing new: one booking earns
//! one REQUEST.
//!
//! The fixture is the invite-grant lane fixture
//! (`src/booking/invite_grant/tests/mod.rs`) rebuilt on public paths: a
//! confirmed booking's four claims, a sending identity, the OF-336 policy
//! manifest shape, the minted page grant, the indexed booking UID, and the
//! rendered invite blob. Only public paths, so main plus this file builds for
//! the red run.
#![cfg(feature = "test-support")]

mod common;

use oneiron::blob_artifact::BlobVersionProvenance;
use oneiron::booking::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_PASSPORT_SYSTEM,
    BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE, BookingBookerContactValue,
    BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus, BookingStatusValue,
    ConfirmedBookingInvite, EventTypeKey, PublishBookingPageGrantRequest, enqueue_confirm_invite,
    mint_publish_page_invite_grant,
};
use oneiron::calendar::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_VERB, CalendarInviteMethod, ImipEmitRequest,
    emit_imip_ics, index_passport_uid, persist_imip_blob,
};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::outbound_intent_ledger::{IntentState, intent_ledger_records};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeActorClass,
    EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

const NOW: u64 = 1_800_000_000;
const RECIPIENT: &str = "booker@example.test";
const SENDER: &str = "host@primary.test";
const EVENT_TYPE: &str = "intro";
const SLOT_START: u64 = NOW + 3_600;
const SLOT_END: u64 = NOW + 7_200;

const ACTOR_SEED: u8 = 0x71;
const PAGE_SEED: u8 = 0x72;
const BOOKER_SEED: u8 = 0x73;
const BOOKING_SEED: u8 = 0x74;
const CLAIM_SEED: u8 = 0x75;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7A;
const BLOB_SEED: u8 = 0x7C;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    booking: EntityId,
    uid: String,
    blob: String,
    grant_ref: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let actor = person(&vault, ACTOR_SEED, b"fix-351 actor");
        let page = common::entity(PAGE_SEED);
        let booker = person(&vault, BOOKER_SEED, RECIPIENT.as_bytes());
        let booking = event(&vault, BOOKING_SEED);
        put_booking_claims(&vault, booking, page, booker);
        let identity = common::self_held_identity_in_state(
            "email",
            SENDER,
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(actor),
            ChannelIdentityState::Active,
            NOW,
        );
        vault
            .create_channel_identity(&common::entity(IDENTITY_SEED), &identity)
            .expect("create sending identity");
        let uid = format!("{}@{BOOKING_PASSPORT_SYSTEM}", booking.to_hex());
        index_passport_uid(&vault, &uid, &booking).expect("index booking uid");
        // Seeded BEFORE the mint: the grant binds to the policy floor in
        // effect when it was minted.
        put_policy_manifest(&vault, actor);
        let grant = mint_publish_page_invite_grant(
            &vault,
            &PublishBookingPageGrantRequest {
                page_ref: page,
                publisher_principal: actor,
                issued_at: NOW,
            },
        )
        .expect("mint the page grant");
        let blob = ics_blob(&vault, actor, &uid);
        Self {
            _dir: dir,
            vault,
            actor,
            booking,
            uid,
            blob,
            grant_ref: grant.id,
        }
    }

    fn invite(&self) -> ConfirmedBookingInvite<'_> {
        ConfirmedBookingInvite {
            booking_ref: self.booking,
            uid: &self.uid,
            sequence: 0,
            ics_blob_ref: &self.blob,
        }
    }
}

fn person(vault: &Vault, seed: u8, body: &[u8]) -> EntityId {
    let id = common::entity(seed);
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
    let id = common::entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("name"),
            rmpv::Value::from(EVENT_TYPE),
        )]),
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

fn claim_value<T: serde::Serialize>(value: &T) -> rmpv::Value {
    let bytes = rmp_serde::to_vec_named(value).expect("encode claim value");
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.as_slice()))
        .expect("decode claim value")
}

/// The four exact claims a confirm commits, written the way it writes them:
/// engine-recorded, `Auto` approval, `Observed` source.
fn put_booking_claims(vault: &Vault, booking: EntityId, page: EntityId, booker: EntityId) {
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
                status: BookingStatus::Confirmed,
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
        )
        .expect("claim body");
        body.source = Some(ClaimSource::Observed);
        body.valid_from = Some(NOW);
        let seed = CLAIM_SEED
            .checked_add(u8::try_from(index).expect("claim index"))
            .expect("claim seed");
        vault
            .put_claim(
                &common::entity(seed),
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

/// The OF-336 manifest shape the outbound spine's own tests use: an `auto`
/// ceiling for this actor plus a scoped grant for the exact verb. Without
/// a manifest the gate has no policy version and denies every effect, so
/// this is what makes an ALLOW decidable in a test vault.
fn put_policy_manifest(vault: &Vault, actor: EntityId) {
    let effect_scope = oneiron::test_support::effect_preset();
    let policy = rmp_serde::to_vec_named(&serde_json::json!({
        "schema_version": "1.2", "pack_id": "fix-351-tests", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
        "actor_ceilings": [
            { "actor_class": "agent", "actor_ref": actor.to_hex(), "ceiling": "auto" },
            { "actor_class": "first_party", "ceiling": "auto" },
            { "actor_class": "human", "ceiling": "auto" }
        ],
        "scoped_grants": [
            { "actor_ref": actor.to_hex(), "effector": format!("external:{CALENDAR_INVITE_VERB}"),
              "scope": effect_scope, "selectors": { "channel": CALENDAR_INVITE_CHANNEL } }
        ]
    }))
    .expect("encode the policy manifest");
    oneiron::test_support::put_policy_manifest_bytes(vault, common::entity(POLICY_SEED), &policy)
        .expect("put the policy manifest");
}

fn ics_blob(vault: &Vault, actor: EntityId, uid: &str) -> String {
    let ics = emit_imip_ics(&ImipEmitRequest {
        method: CalendarInviteMethod::Request,
        uid: uid.to_owned(),
        sequence: 0,
        organizer: SENDER.to_owned(),
        attendees: vec![RECIPIENT.to_owned()],
        summary: EVENT_TYPE.to_owned(),
        starts_at_utc: SLOT_START,
        ends_at_utc: SLOT_END,
        tz_label: "UTC".to_owned(),
        dtstamp_utc: NOW,
    })
    .expect("emit invite document");
    persist_imip_blob(
        vault,
        &common::entity(BLOB_SEED),
        "fix-351 invite",
        &ics,
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(actor, EdgeActorClass::Human),
        NOW,
    )
    .expect("persist invite blob")
}

/// A transport whose first delivery fails definitely and whose later ones land.
#[derive(Default)]
struct FailFirstDelivery {
    calls: usize,
}

impl OutboundExecutionSink for FailFirstDelivery {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        if self.calls == 1 {
            OutboundExecutionOutcome::failed("definite fixture non-delivery")
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:invite:fixture")
        }
    }
}

#[derive(Default)]
struct DeliveringSink {
    calls: usize,
}

impl OutboundExecutionSink for DeliveringSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        OutboundExecutionOutcome::delivered_to_channel("provider:invite:fixture")
    }
}

fn invite_records(vault: &Vault) -> Vec<oneiron::outbound_intent_ledger::IntentLedgerRecord> {
    intent_ledger_records(vault)
        .expect("intent ledger")
        .into_iter()
        .filter(|record| record.tool == CALENDAR_INVITE_VERB)
        .collect()
}

fn invite_state(vault: &Vault, id: [u8; 32]) -> IntentState {
    invite_records(vault)
        .into_iter()
        .find(|record| record.id == id)
        .expect("the returned intent names a ledger row")
        .state
}

#[test]
fn pending_invite_replay_retries_its_transport_through_dispatch() {
    let fixture = Fixture::open();
    let mut sink = FailFirstDelivery::default();
    let first = enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        fixture.grant_ref,
        &fixture.invite(),
        &mut sink,
        NOW,
    )
    .expect("the first pass records the intent");
    assert_eq!(sink.calls, 1, "the first pass reaches transport");
    assert_eq!(
        invite_state(&fixture.vault, first),
        IntentState::Pending,
        "the definite failure leaves the send queued for retry"
    );

    let second = enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        fixture.grant_ref,
        &fixture.invite(),
        &mut sink,
        NOW,
    )
    .expect("the replay answers with the recorded intent");
    assert_eq!(
        first, second,
        "one booking earns one REQUEST: the replay reuses the recorded intent"
    );
    assert_eq!(
        invite_records(&fixture.vault).len(),
        1,
        "the replay records no second intent"
    );
    assert_eq!(
        sink.calls, 2,
        "the replay retries the still-Pending transport through dispatch"
    );
    assert_eq!(
        invite_state(&fixture.vault, second),
        IntentState::Done,
        "the retried transport delivered"
    );
}

#[test]
fn delivered_invite_replay_sends_nothing_new() {
    let fixture = Fixture::open();
    let mut sink = DeliveringSink::default();
    let first = enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        fixture.grant_ref,
        &fixture.invite(),
        &mut sink,
        NOW,
    )
    .expect("the first pass delivers");
    assert_eq!(
        invite_state(&fixture.vault, first),
        IntentState::Done,
        "the first pass settles the send"
    );

    let second = enqueue_confirm_invite(
        &fixture.vault,
        fixture.actor,
        fixture.grant_ref,
        &fixture.invite(),
        &mut sink,
        NOW,
    )
    .expect("the replay answers with the recorded intent");
    assert_eq!(
        first, second,
        "one booking earns one REQUEST: the replay reuses the recorded intent"
    );
    assert_eq!(sink.calls, 1, "a settled replay reaches no transport");
    assert_eq!(
        invite_records(&fixture.vault).len(),
        1,
        "the replay records no second intent"
    );
}

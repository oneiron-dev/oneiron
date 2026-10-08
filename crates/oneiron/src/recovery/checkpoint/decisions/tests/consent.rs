//! Census cases for consent and standing the engine grants from restored
//! rows.
use super::Case;
use crate::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignDocument, EsignItem, EsignRecipient, RecipientRole,
    SigningAutonomy, SigningPrincipal,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingError, BookingEventTypeClaimValue,
    BookingLandingContent, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingPagePublication, BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmReceipt,
    ConfirmSpec, ConstraintFieldConfig, EventTypeCard, EventTypeConfig, EventTypeKey,
    HoldLeaseSpec, HoldSpec, HostAvailabilityConfig, PublicBookingAvailability, RankedSlot,
    RoutingMode, SessionKey, SlotHostBinding, SlotOracle, SolveRequest, SolveResult, ThemeTokens,
    WeeklyWallWindow, booking_config_hash, encode_event_type_claim_value, enqueue_booking_verb,
    run_booking_lifecycle_once,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::comm::CommClaimValue;
use crate::delivery_window::{
    DELIVERY_WINDOW_SCHEMA_VERSION, DeliveryWindowAppliesTo, PREDICATE_DELIVERY_WINDOW_QUIET,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::federation::CoreferenceStatus;
use crate::identity_reputation::{
    IdentityAttestationTier, IdentityReputation, IdentityWarmupStage,
    PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
};
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use crate::outbound_grant::BookingPageInviteGrantMintIntent;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use crate::test_util::entity;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

fn config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// A vault with no policy manifest but the ones a case writes.
fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(config())
}

/// A vault as a host opens one, with its seeded policy manifest.
fn open_seeded() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config())?;
    Ok((dir, vault))
}

const AT: TimeRange = TimeRange { start: 1, end: 1 };

fn person(vault: &Vault, seed: u8) -> Result<EntityId> {
    let id = entity(seed);
    vault.put_entity(&id, ENTITY_TYPE_PERSON, AT, 1, b"person")?;
    Ok(id)
}

/// A person the backup does not hold, which no decision reads anything about.
fn new_person(vault: &Vault) -> Result<()> {
    person(vault, 0x5E).map(drop)
}

fn invalid(error: impl std::fmt::Debug) -> Error {
    Error::InvalidConfig(format!("{error:?}"))
}

/// An observed complaint rate for `sender`.
fn complaint_rate(vault: &Vault, sender: EntityId, id: EntityId, rate: f64) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
        ClaimSubject::Entity(sender),
        Value::F64(rate),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    vault.put_claim(&id, &body, TimeRange { start: 20, end: 20 }, 20)
}

/// A native-mail sender earns the offer of cold-recipient autonomy only
/// while every current reputation head is healthy. A complaint rate over
/// the policy's ceiling observed since the backup is one a restore would
/// drop; a healthy one changes nothing.
pub(super) fn mail_reputation() -> Result<Case> {
    let (dir, vault) = open_vault();
    let sender = entity(0x3A);
    crate::test_util::put_native_mail_sender(&vault, sender, entity(0x3B), &[])?;
    let healthy = IdentityReputation {
        complaint_rate: 0.0,
        bounce_rate: 0.0,
        spam_label_observations: 0,
        attestation_tier: IdentityAttestationTier::A,
        warmup_stage: IdentityWarmupStage::Established,
        updated_at: 10,
    };
    for (seed, body) in (0x60..).zip(healthy.claim_bodies(sender)?) {
        vault.put_claim(&entity(seed), &body, TimeRange { start: 10, end: 10 }, 10)?;
    }
    Case::after_backup(
        "sender reputation offers",
        (dir, vault),
        move |vault| complaint_rate(vault, sender, entity(0x6A), 0.0),
        move |vault| complaint_rate(vault, sender, entity(0x6B), 0.5),
    )
}

/// A coreference link is exported into a pact while a local consent names
/// it and the link stands. A link deleted since the backup, its consent left
/// in place, is one a restore would make shareable again.
pub(super) fn shared_coreference() -> Result<Case> {
    let (dir, vault) = open_vault();
    let actor = WriteActor::new(person(&vault, 0x71)?, EdgeActorClass::Human);
    let (sora, rin) = (person(&vault, 0x72)?, person(&vault, 0x73)?);
    crate::federation::put_coreference_link(
        &vault,
        &actor,
        sora,
        rin,
        CoreferenceStatus::Confirmed,
        AT,
        1,
    )?;
    crate::federation::coreference_share_consent(
        &vault,
        &actor,
        sora,
        rin,
        &[0x5C; crate::claim::COREFERENCE_PACT_ID_LEN],
        AT,
        2,
    )?;
    Case::after_backup(
        "shared coreference links",
        (dir, vault),
        new_person,
        move |vault| vault.delete_edge(&sora, EdgeKind::SameAs, &rin).map(drop),
    )
}

/// A delivery-window restriction reaches a send through its claim's
/// `claim_of` edge to the subject it names. One whose edge was put back
/// since the backup, its body unchanged, is one a restore would lift off
/// that subject's sends; one that only repeats a restriction the backup
/// already holds, under another source (Astra R4-6), lifts nothing.
pub(super) fn delivery_windows() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (sora, rin) = (person(&vault, 0x72)?, person(&vault, 0x73)?);
    let (stated, observed, quiet) = (entity(0x7A), entity(0x7B), entity(0x7C));
    quiet_window(&vault, stated, sora, ClaimSource::UserStated)?;
    quiet_window(&vault, observed, sora, ClaimSource::Observed)?;
    quiet_window(&vault, quiet, rin, ClaimSource::UserStated)?;
    vault.delete_edge(&observed, EdgeKind::ClaimOf, &sora)?;
    vault.delete_edge(&quiet, EdgeKind::ClaimOf, &rin)?;
    Case::after_backup(
        "delivery-window restrictions",
        (dir, vault),
        move |vault| vault.put_edge(&observed, EdgeKind::ClaimOf, &sora, 1.0),
        move |vault| vault.put_edge(&quiet, EdgeKind::ClaimOf, &rin, 1.0),
    )
}

/// A quiet window from 22:00 to 08:00 on `subject`'s interrupts, from
/// `source`.
fn quiet_window(vault: &Vault, id: EntityId, subject: EntityId, source: ClaimSource) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(subject),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("tz"), Value::from("user-local")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    vault.put_claim(&id, &body, AT, 1)
}

/// One event type's configuration, with `buffer` free minutes before each
/// booking.
fn event_type(buffer: u16) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro".to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: buffer,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: entity(0x86),
            calendar_refs: vec![entity(0x87)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 0,
                end_minute: 1_440,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// An ordinary configuration claim `id` for `config` on `page`.
fn put_event_type(
    vault: &Vault,
    id: EntityId,
    page: EntityId,
    config: EventTypeConfig,
) -> Result<()> {
    let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config,
    })
    .map_err(invalid)?;
    let body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(&id, &body, AT, 1)
}

/// A public booking page is served while every event configuration is the
/// one its publication pinned. A configuration that wins since the backup,
/// the publication left as it was, is one a restore would take back,
/// serving the page again.
pub(super) fn booking_publications() -> Result<Case> {
    let (dir, vault) = open_seeded()?;
    let page = entity(0x81);
    vault.put_entity(&page, ENTITY_TYPE_ASSET, AT, 1, b"page")?;
    let owner = person(&vault, 0x82)?;
    put_event_type(&vault, entity(0x85), page, event_type(0))?;
    let key = EventTypeKey("intro".to_owned());
    let publication = BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        owner_display: "Owner".to_owned(),
        event_types: vec![EventTypeCard {
            key: key.clone(),
            title: "Intro".to_owned(),
            duration_min: 30,
            description: String::new(),
        }],
        event_config_hashes: [(key.0.clone(), booking_config_hash(&event_type(0))?)].into(),
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(serde_json::Value::Null),
        landing: BookingLandingContent::default(),
        initial_availability: PublicBookingAvailability {
            event_type: key,
            start_after_secs: 10,
            window_secs: 3_600,
            visitor_tz: "UTC".to_owned(),
        },
    };
    vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&crate::memory::ClaimInput {
            id: None,
            predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
            subject_ref: page.to_hex(),
            value: serde_json::to_value(publication).map_err(invalid)?,
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: Some(4_102_444_800),
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .map_err(invalid)?;
    Case::after_backup(
        "public booking publications",
        (dir, vault),
        new_person,
        // A lower id wins the configuration read.
        move |vault| put_event_type(vault, entity(0x83), page, event_type(15)),
    )
}

/// An automated principal signs on its own only while every policy that
/// resolves to its identity grants it. Two principals merged since the
/// backup, one of which grants nothing, are ones a restore would split
/// again, giving the other its autonomy back.
pub(super) fn principal_autonomy() -> Result<Case> {
    let (dir, vault) = open_vault();
    let owner = person(&vault, 0x71)?;
    let (sora, rin) = (person(&vault, 0x72)?, person(&vault, 0x73)?);
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let policy = |principal: EntityId, autonomy: SigningAutonomy, sign: bool| SigningPrincipal {
        principal_ref: principal.to_hex(),
        autonomy,
        automated_sign_action: sign,
    };
    vault.set_signing_principals(
        &owner,
        &[
            policy(sora, SigningAutonomy::AutonomousInEnvelope, true),
            policy(rin, SigningAutonomy::Draft, false),
        ],
    )?;
    Case::after_backup(
        "signing principal autonomy",
        (dir, vault),
        new_person,
        move |vault| {
            vault
                .apply_identity_topology_op(
                    &IdentityTopologyOp::Merge(MergeOp {
                        sources: vec![rin],
                        survivor: sora,
                        evidence: IdentityOpEvidence {
                            refs: Vec::new(),
                            rationale: "same person".to_owned(),
                        },
                        survivorship_plan: SurvivorshipPlan::ReadThrough,
                    }),
                    &IdentityOpWrite::auto(ClaimSource::Inferred),
                    20,
                )
                .map(drop)
        },
    )
}

/// A signing ceremony folds from the event claims its document's `claim_of`
/// edges reach. An expiry whose edge was put back since the backup, its
/// body and audit row unchanged, is one a restore would take off, opening
/// the draft to be sent again.
pub(super) fn esign_ceremonies() -> Result<Case> {
    let (dir, vault) = open_seeded()?;
    let owner = person(&vault, 0x71)?;
    let document = entity(0x91);
    vault.put_blob_artifact(
        &document,
        &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        AT,
        1,
    )?;
    vault.append_blob_artifact_version(
        &document,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
        )),
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(owner, EdgeActorClass::Human),
        AT,
        1,
    )?;
    vault.create_esign_document(
        document,
        &EsignDocument {
            schema_version: 1,
            kind: DocumentKind::Document,
            title: "Agreement".into(),
            sequential: true,
            expires_at: 1_000,
            items: vec![EsignItem {
                artifact_ref: document.to_hex(),
                original_version: 1,
            }],
            recipients: vec![EsignRecipient {
                id: entity(0x92).to_hex(),
                email: "signer@example.test".into(),
                name: "Signer".into(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at: 1_000,
                principal_ref: None,
                automated: false,
            }],
            fields: Vec::new(),
            full_trail_appendix: true,
            lifecycle: None,
        },
        EsignAuditActor {
            actor: "owner".into(),
            ip: None,
            user_agent: None,
        },
        2,
    )?;
    vault.sweep_esign_expiry(&[document], 1_000)?;
    let expiry = {
        let txn = vault.store.env.read_txn()?;
        vault
            .claims_with_predicate_in_txn(&txn, "esign.expired")?
            .into_iter()
            .map(|(id, _)| id)
            .next()
            .ok_or(Error::EntityNotFound)?
    };
    vault.delete_edge(&expiry, EdgeKind::ClaimOf, &document)?;
    Case::after_backup(
        "e-sign ceremony states",
        (dir, vault),
        new_person,
        move |vault| vault.put_edge(&expiry, EdgeKind::ClaimOf, &document, 1.0),
    )
}

/// The census row for whom a calendar invitation may reach.
const INVITATION_CONSENT: &str = "calendar invitation consent";

/// When the invitation cases book, cancel and touch, in seconds.
const NOW: u64 = 1_772_409_600;

/// Two recipients' addresses.
const ADA: &str = "ada@example.test";
const BEN: &str = "ben@example.test";

/// Fails unless `vault` holds a consent basis for a calendar invitation to
/// `recipient` exactly when `expected`.
fn invitable(vault: &Vault, recipient: &str, expected: bool) -> Result<()> {
    let basis =
        crate::calendar::invite::resolve_consent_basis(vault, recipient).map_err(invalid)?;
    if basis.is_some() == expected {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "{recipient} has invitation consent {basis:?}"
    )))
}

/// The one slot a booking page offers, on the host `event_type` names: only
/// the availability answer is a fixture, and the booking lifecycle writes
/// the EVENT, its claims, tokens and passport.
struct Offered(TimeRange);

impl SlotOracle for Offered {
    fn solve(&self, _: &SolveRequest) -> std::result::Result<SolveResult, BookingError> {
        Ok(SolveResult {
            slots: vec![RankedSlot {
                start_utc: self.0.start,
                end_utc: self.0.end,
                rank: 1.0,
            }],
            flex_used: false,
            host_bindings: vec![SlotHostBinding {
                start_utc: self.0.start,
                end_utc: self.0.end,
                host_refs: vec![entity(0x86).to_hex()],
                host_zones: vec!["UTC".to_owned()],
            }],
        })
    }
}

/// Runs `request` through the booking lifecycle on this node, the home node.
fn turn(vault: &Vault, request: BookingVerbRequest, slot: TimeRange) -> Result<BookingVerbReceipt> {
    enqueue_booking_verb(vault, request, NOW).map_err(invalid)?;
    let consumer = BookingLifecycleConsumerInput {
        local_node_id: crate::identity::load_or_mint_client_id(vault)?,
        lease_owner: "census".to_owned(),
        now_utc: NOW,
    };
    match run_booking_lifecycle_once(vault, |_| Ok(Offered(slot)), &consumer).map_err(invalid)? {
        BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
        other => Err(invalid(other)),
    }
}

/// A booking of the half hour from `start` on `page`, held and confirmed by
/// `booker`.
fn book(vault: &Vault, page: EntityId, booker: EntityId, start: u64) -> Result<ConfirmReceipt> {
    let slot = TimeRange {
        start,
        end: start + 1_800,
    };
    let session = SessionKey::derive(&start.to_be_bytes());
    let hold = HoldSpec {
        page_ref: page,
        event_type: EventTypeKey("intro".to_owned()),
        slot,
        session_key: session,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        lease: HoldLeaseSpec::Ordinary,
        idempotency_key: None,
    };
    let held = match turn(vault, BookingVerbRequest::Hold(hold), slot)? {
        BookingVerbReceipt::Held(held) => held,
        other => return Err(invalid(other)),
    };
    let confirm = ConfirmSpec {
        hold_token: held.token,
        session_key: session,
        booker_contact: booker,
        intake: Vec::new(),
        idempotency_key: None,
    };
    match turn(vault, BookingVerbRequest::Confirm(confirm), slot)? {
        BookingVerbReceipt::Confirmed(confirmed) => Ok(confirmed),
        other => Err(invalid(other)),
    }
}

/// Cancels `booking` with its own cancel token, keeping its EVENT.
fn cancel(vault: &Vault, booking: &ConfirmReceipt) -> Result<()> {
    crate::booking::lifecycle::execute_cancel(
        vault,
        &CancelSpec {
            token: booking.cancel_token.clone(),
            idempotency_key: None,
        },
        NOW + 60,
        None,
    )
    .map(drop)
    .map_err(invalid)
}

/// A booker `id` whose person row carries `address`, as a booking page's
/// booker's does.
fn booker(vault: &Vault, id: EntityId, address: &str) -> Result<EntityId> {
    vault.put_entity(&id, ENTITY_TYPE_PERSON, AT, 1, address.as_bytes())?;
    Ok(id)
}

/// A booking page grant lets a calendar invitation reach whoever booked a
/// confirmed booking on its page. A booking cancelled since the backup, its
/// booker holding no other on the page, is one a restore would confirm
/// again, letting the invitation through (Astra R4-4); one cancelled on a
/// page no grant covers, or beside another the same booker holds on the
/// granted page, lets no one through.
pub(super) fn calendar_invitation_consent() -> Result<Case> {
    let (dir, vault) = open_seeded()?;
    let owner = person(&vault, 0x86)?;
    let (granted, ungranted) = (entity(0xB1), entity(0xB2));
    for (page, claim) in [(granted, entity(0xB3)), (ungranted, entity(0xB4))] {
        vault.put_entity(&page, ENTITY_TYPE_ASSET, AT, 1, b"page")?;
        put_event_type(&vault, claim, page, event_type(0))?;
    }
    {
        let runner = crate::DreamerRunnerStore::new(&vault);
        runner.elect_home_node(&[runner.local_home_node_candidate(true, true, true)?], 1)?;
    }
    let ada = booker(&vault, entity(0xB5), ADA)?;
    let ben = booker(&vault, entity(0xB6), BEN)?;
    let kept = book(&vault, granted, ada, NOW + 3_600)?;
    let spare = book(&vault, granted, ada, NOW + 7_200)?;
    let elsewhere = book(&vault, ungranted, ben, NOW + 10_800)?;
    // Minted after the bookings, so no confirm sends an invitation.
    vault.mint_booking_page_invite_outbound_grant(
        &entity(0xB7),
        &BookingPageInviteGrantMintIntent {
            page_ref: granted,
            publisher_principal: owner,
        },
        NOW,
    )?;
    invitable(&vault, ADA, true)?;
    invitable(&vault, BEN, false)?;
    Case::after_backup(
        INVITATION_CONSENT,
        (dir, vault),
        move |vault| {
            cancel(vault, &elsewhere)?;
            cancel(vault, &spare)?;
            invitable(vault, ADA, true)?;
            invitable(vault, BEN, false)
        },
        move |vault| {
            cancel(vault, &kept)?;
            invitable(vault, ADA, false)
        },
    )
}

/// A standing `comm.last_touch` `id` with `party` on `channel_class`.
fn last_touch(vault: &Vault, id: EntityId, party: EntityId, channel_class: &str) -> Result<()> {
    let body = CommClaimValue::LastTouch {
        party_ref: party,
        channel_class: channel_class.to_owned(),
        occurred_at: NOW,
    }
    .claim_body()?;
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )
}

/// A prior thread lets a calendar invitation reach a recipient no grant
/// covers. A last touch on email whose `claim_of` edge was deleted since the
/// backup, its body and party left in place, is one a restore would reach
/// again; a touch since on a channel an invitation does not ride changes
/// nothing.
fn prior_thread() -> Result<Case> {
    let (dir, vault) = open_vault();
    let party = crate::comm::resolve_or_create_comm_party(&vault, ADA).map_err(invalid)?;
    let touch = entity(0xC1);
    last_touch(&vault, touch, party, "email")?;
    invitable(&vault, ADA, true)?;
    Case::after_backup(
        INVITATION_CONSENT,
        (dir, vault),
        move |vault| {
            last_touch(vault, entity(0xC2), party, "telegram")?;
            invitable(vault, ADA, true)
        },
        move |vault| {
            if !vault.delete_edge(&touch, EdgeKind::ClaimOf, &party)? {
                return Err(Error::EntityNotFound);
            }
            invitable(vault, ADA, false)
        },
    )
}

/// Astra R4-4: a prior thread a cold calendar invitation stood on, its last
/// touch's `claim_of` edge deleted since the backup, came back with a
/// restore that kept live authority.
#[test]
fn a_restore_does_not_reattach_a_prior_thread_an_invitation_stands_on() {
    assert_eq!(super::run(prior_thread), Ok(INVITATION_CONSENT));
}

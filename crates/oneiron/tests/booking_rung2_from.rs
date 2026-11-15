//! INBOX-RESIDUE PR-3b-1: rung 2 gets its FROM (ARCH-0062:145-147,
//! ARCH-0063:48; Engine RULING RUNG2-NO-SENDER = A, 15 Nov).
//!
//! When no slot fits, the page's own agent continues over email. The owner
//! names that agent on the page's front at publish, and the email's FROM is
//! the identity the selection law picks for scheduling among the agent's
//! email identities: the agent's named work address. The law never falls
//! through to another face, so a page whose agent holds no live named address
//! offers no rung 2: its answer is the owner's no-fit line with no control,
//! and it asks for no email.
//!
//! Red on main: `oneiron::booking::rung2`, the front's `agent_ref` and
//! `constraint_no_fit` do not exist there, so this file does not build.
//! `cargo test --locked -p oneiron --all-features --test booking_rung2_from`.

#![cfg(feature = "test-support")]

use std::collections::BTreeMap;

use oneiron::booking::agent_front::{ConstraintFrontConfig, constraint_no_fit};
use oneiron::booking::rung2::{
    BOOKING_RUNG2_SEND_REF_PREFIX, Rung2Offer, Rung2Sender, Rung2Unavailable, rung2_send_ref,
};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingEventTypeClaimValue, BookingLandingContent,
    BookingPagePublication, ConstraintFieldConfig, EventTypeCard, EventTypeConfig, EventTypeKey,
    HostAvailabilityConfig, PublicBookingAvailability, RoutingMode, ThemeTokens, WeeklyWallWindow,
    booking_config_hash, encode_event_type_claim_value,
};
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
    ChannelIdentityStep, SelfHeldShape,
};
use oneiron::channel_identity_selection::ChannelIdentityFace;
use oneiron::lens::{LensAtom, LensText};
use oneiron::memory::ClaimInput;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::test_support::{bind_host_owner, test_host_issuer};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const AT: u64 = 1_800_000_000;
/// The publication stands for one day from `AT`.
const UNTIL: u64 = AT + 86_400;
/// A read inside the publication's life.
const NOW: u64 = AT + 600;
const EVENT_TYPE: &str = "intro";
const SESSION: &str = "visitor-session-1";
const NO_FIT_LINE: &str = "None of those times work for the host.";
/// The page agent's own named work address.
const NAMED_ADDRESS: &str = "scheduling@example.com";
/// The same agent's campaign sender on a side domain.
const SIDE_DOMAIN_ADDRESS: &str = "outreach@example-outreach.net";

/// A rooted vault, its owner, one booking page and the page's agent. The
/// vault closes before its directory.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    page: EntityId,
    agent: EntityId,
    /// The faces the host gave the identities it provisioned.
    faces: BTreeMap<EntityId, ChannelIdentityFace>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        bind_host_owner(&vault, &test_host_issuer(), owner).map_err(at("root the owner"))?;
        let page = EntityId::now();
        vault
            .put_entity(
                &page,
                ENTITY_TYPE_ASSET,
                TimeRange { start: AT, end: AT },
                AT,
                b"booking page",
            )
            .map_err(at("the booking page"))?;
        let mut config = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            encode_event_type_claim_value(&BookingEventTypeClaimValue {
                schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                page_ref: page,
                config: event_type_config(),
            })
            .map_err(at("encode the event type"))?,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .map_err(at("the event type claim"))?;
        // The page is not a PERSON: its configuration takes the vault's
        // default facet.
        config.scope_facet = vault.default_facet().map_err(at("default facet"))?;
        vault
            .put_claim(
                &EntityId::now(),
                &config,
                TimeRange { start: AT, end: AT },
                AT,
            )
            .map_err(at("put the event type"))?;
        let agent = EntityId::now();
        vault
            .put_entity(
                &agent,
                ENTITY_TYPE_PERSON,
                TimeRange { start: AT, end: AT },
                AT,
                b"scheduling agent",
            )
            .map_err(at("seat the page's agent"))?;
        Ok(Self {
            vault,
            owner,
            page,
            agent,
            faces: BTreeMap::new(),
            _dir: dir,
        })
    }

    /// The owner publishes the page, its front naming `agent_ref`.
    fn publish(&self, constraint_front: Option<ConstraintFrontConfig>) -> TestResult {
        let publication = BookingPagePublication {
            schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
            published: true,
            owner_display: "Owen".to_owned(),
            event_types: vec![EventTypeCard {
                key: EventTypeKey(EVENT_TYPE.to_owned()),
                title: "Intro call".to_owned(),
                duration_min: 30,
                description: "A first call.".to_owned(),
            }],
            event_config_hashes: [(
                EVENT_TYPE.to_owned(),
                booking_config_hash(&event_type_config()).map_err(at("config hash"))?,
            )]
            .into(),
            constraint_field: ConstraintFieldConfig {
                enabled: true,
                placeholder: "Any constraints?".to_owned(),
            },
            constraint_front,
            theme: ThemeTokens(serde_json::json!({})),
            landing: BookingLandingContent::default(),
            initial_availability: PublicBookingAvailability {
                event_type: EventTypeKey(EVENT_TYPE.to_owned()),
                start_after_secs: 3_600,
                window_secs: 86_400,
                visitor_tz: "UTC".to_owned(),
            },
            sponsor: None,
        };
        let input = ClaimInput {
            id: None,
            predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
            subject_ref: self.page.to_hex(),
            value: serde_json::to_value(publication)?,
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(AT),
            valid_to: Some(UNTIL),
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        };
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        let receipt = owner
            .claim_upsert(&input)
            .map_err(at("the owner's publication write"))?;
        if receipt.approval == "proposed" {
            owner
                .confirm_booking_publication(&receipt.claim_short_id, NOW)
                .map_err(at("the owner confirms the publication"))?;
        }
        Ok(())
    }

    /// A live email identity of the page's agent, which the host classifies
    /// as `face`.
    fn agent_address(
        &mut self,
        address: &str,
        face: ChannelIdentityFace,
        live: bool,
    ) -> TestResult<EntityId> {
        let id = EntityId::now();
        let requested = ChannelIdentity::requested(
            "email",
            address,
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(self.agent),
            AT,
        );
        self.vault
            .create_channel_identity(&id, &requested)
            .map_err(at("birth the address"))?;
        if live {
            self.vault
                .step_channel_identity(
                    &id,
                    ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                    AT + 10,
                )
                .map_err(at("bind the address"))?;
            let active = self
                .vault
                .step_channel_identity(&id, ChannelIdentityStep::Fulfill, AT + 20)
                .map_err(at("fulfill the address"))?;
            assert_eq!(active.state(), ChannelIdentityState::Active);
        }
        self.faces.insert(id, face);
        Ok(id)
    }

    /// The page's rung-2 offer, with the host's faces.
    fn offer(&self, now: u64) -> TestResult<Rung2Offer> {
        let faces = &self.faces;
        Ok(self
            .vault
            .booking_rung2_offer(self.page, now, &mut |id, _| Ok(faces.get(id).copied()))
            .map_err(at("the rung-2 offer"))?)
    }
}

fn event_type_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(EVENT_TYPE.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: EntityId::from_bytes([0x73; 16]).expect("host id"),
            calendar_refs: vec![EntityId::from_bytes([0x74; 16]).expect("calendar id")],
            host_tz: "UTC".to_owned(),
            working_hours: (0..7)
                .map(|weekday| WeeklyWallWindow {
                    weekday,
                    start_minute: 0,
                    end_minute: 1_440,
                })
                .collect(),
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// The owner's front copy and dials, naming `agent_ref`.
fn front(agent_ref: Option<EntityId>) -> ConstraintFrontConfig {
    ConstraintFrontConfig {
        speaker: "Scheduling".to_owned(),
        slots_line: "These times work.".to_owned(),
        no_fit_line: NO_FIT_LINE.to_owned(),
        off_topic_line: "I can only help with scheduling.".to_owned(),
        max_turns: 4,
        max_model_calls: 4,
        agent_ref,
    }
}

#[test]
fn the_page_agents_named_address_is_the_rung2_from() -> TestResult {
    let mut fixture = Fixture::open()?;
    let side_domain = fixture.agent_address(
        SIDE_DOMAIN_ADDRESS,
        ChannelIdentityFace::SideDomainAddress,
        true,
    )?;
    let named =
        fixture.agent_address(NAMED_ADDRESS, ChannelIdentityFace::AgentNamedAddress, true)?;
    fixture.publish(Some(front(Some(fixture.agent))))?;

    let offer = fixture.offer(NOW)?;
    assert_eq!(
        offer,
        Rung2Offer::Offered(Rung2Sender {
            page_ref: fixture.page,
            agent_ref: fixture.agent,
            identity_ref: named,
            facet_ref: None,
            face: ChannelIdentityFace::AgentNamedAddress,
        }),
        "the agent's named address, never its side-domain sender {side_domain:?}"
    );
    Ok(())
}

#[test]
fn an_agent_without_a_live_named_address_offers_no_rung2_and_no_other_face() -> TestResult {
    let mut fixture = Fixture::open()?;
    fixture.agent_address(
        SIDE_DOMAIN_ADDRESS,
        ChannelIdentityFace::SideDomainAddress,
        true,
    )?;
    fixture.publish(Some(front(Some(fixture.agent))))?;
    assert_eq!(
        fixture.offer(NOW)?,
        Rung2Offer::NotOffered(Rung2Unavailable::NoNamedAddress),
        "a live side-domain sender is no fall-through FROM"
    );

    // A named address that is not live yet is no sender either.
    fixture.agent_address(NAMED_ADDRESS, ChannelIdentityFace::AgentNamedAddress, false)?;
    assert_eq!(
        fixture.offer(NOW)?,
        Rung2Offer::NotOffered(Rung2Unavailable::NoNamedAddress)
    );
    Ok(())
}

#[test]
fn a_page_that_names_no_agent_offers_no_rung2() -> TestResult {
    let mut fixture = Fixture::open()?;
    fixture.agent_address(NAMED_ADDRESS, ChannelIdentityFace::AgentNamedAddress, true)?;

    assert_eq!(
        fixture.offer(NOW)?,
        Rung2Offer::NotOffered(Rung2Unavailable::PageNotLive),
        "an unpublished page"
    );
    fixture.publish(None)?;
    assert_eq!(
        fixture.offer(NOW)?,
        Rung2Offer::NotOffered(Rung2Unavailable::NoConstraintFront)
    );
    fixture.publish(Some(front(None)))?;
    assert_eq!(
        fixture.offer(NOW)?,
        Rung2Offer::NotOffered(Rung2Unavailable::NoPageAgent)
    );
    fixture.publish(Some(front(Some(fixture.agent))))?;
    assert!(matches!(fixture.offer(NOW)?, Rung2Offer::Offered(_)));
    assert_eq!(
        fixture.offer(UNTIL)?,
        Rung2Offer::NotOffered(Rung2Unavailable::PageNotLive),
        "the publication's life is half-open"
    );
    Ok(())
}

#[test]
fn the_rung2_send_ref_is_stable_across_retries() {
    let page = EntityId::from_bytes([0x71; 16]).expect("page id");
    let other_page = EntityId::from_bytes([0x72; 16]).expect("page id");
    let first = rung2_send_ref(&page, SESSION);
    assert_eq!(first, rung2_send_ref(&page, SESSION), "a retry sends once");
    assert_eq!(
        first,
        format!("{BOOKING_RUNG2_SEND_REF_PREFIX}{}:{SESSION}", page.to_hex())
    );
    assert_ne!(first, rung2_send_ref(&page, "visitor-session-2"));
    assert_ne!(first, rung2_send_ref(&other_page, SESSION));
}

#[test]
fn the_no_fit_answer_is_the_owners_line_with_no_control() -> TestResult {
    let answer =
        constraint_no_fit(SESSION, &front(None).copy()).map_err(at("the no-fit answer"))?;
    assert!(answer.card.actions.is_empty(), "it declares no action");
    let root = answer.card.tree.root();
    assert!(root.children.is_empty(), "it carries no control");
    let LensAtom::VoiceLine(voice) = &root.atom else {
        panic!("the answer is one voice line");
    };
    assert_eq!(voice.text, LensText::new(NO_FIT_LINE)?);
    Ok(())
}

//! PACK-SETTINGS-ALL W1: each of four owner choices defaults to today's behaviour,
//! and an owner value changes it.
//!
//! - B07: `ConstraintFrontConfig.max_offered_slots` (shipped 3) sizes the Slots
//!   card one agent-front turn renders; 0 is refused.
//! - B08: the public page's first view shows the resolved conversion policy's
//!   `max_visible_slots` (shipped 5); a preview that is not the mask's ranked
//!   prefix is refused.
//! - B11: `EventTypeConfig.flex_with_ordinary` (shipped false) keeps the flex
//!   windows a fallback; true offers them beside ordinary hours.
//! - B12: the companion preset row's `max_choices` (shipped 5) sizes the
//!   curated shortlist; 0 is refused.
//!
//! Main cannot build this file: the fields, the `BookingPageModel::new` policy
//! argument and the `booking_slot_preview` count argument are new here, so its
//! red is the missing items. Public `oneiron::` paths only.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test pack_keys_booking`.
#![cfg(feature = "test-support")]

use oneiron::booking::agent_front::{
    BOOKING_SLOT_BUTTON_ACTION, ConstraintFrontConfig, ConstraintFrontOutcome, ConstraintSlotReply,
    ConstraintTurnRequest, DEFAULT_MAX_OFFERED_SLOTS, run_constraint_turn,
};
use oneiron::booking::companion_preset::DEFAULT_PROPOSAL_MAX_CHOICES;
use oneiron::booking::constraint::{
    BookingDecisions, CONSTRAINT_SCHEMA_VERSION, ConstraintParseConfig, ConstraintSessionState,
};
use oneiron::booking::{
    BookingConversionPolicy, BookingError, BookingLandingContent, BookingPageModel,
    BookingPageModelError, BookingSlotPreview, BookingSolver, CompanionPresetRow,
    CompanionProposal, CompanionProposalCreation, ConstraintFieldConfig,
    DEFAULT_INTRO_DURATION_MIN, DisclosureRung, EventTypeCard, EventTypeConfig, EventTypeKey,
    HostAvailabilityConfig, RankedSlot, RoutingMode, RungProjection, SlotOracle, SolveRequest,
    SolveResult, SurfaceClass, ThemeTokens, VaultActiveHoldSource, WeeklyWallWindow,
    create_companion_proposal, friend_hangout_preset, load_companion_preset, project_at_rung,
    slot_mask, validate_booking_page_model,
};
use oneiron::llm::{
    BudgetLease, CallPurpose, ContentPart, FatalLlmError, FinishReason, LlmBackend, LlmCapability,
    LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage,
    LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef,
    TierPrecedence, UnsupportedCapability,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{CalendarSel, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00 that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const BUSY_SEED: u8 = 0x61;
const OWNER_SEED: u8 = 0x71;
const COMPANION_SEED: u8 = 0x72;
const HANGOUT_HOST_SEED: u8 = 0x73;
const HANGOUT_CALENDAR_SEED: u8 = 0x74;
const PRINCIPAL_SEED: u8 = 0xA1;

/// `[seed; 16]`, as the booking integration fixtures build it.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

/// Drives one async turn on a current-thread runtime.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

// ---------------------------------------------------------------------
// B07: the agent front's offered-slot count
// ---------------------------------------------------------------------

/// The owner's front as stored JSON, with or without the choice.
fn front_json(max_offered_slots: Option<u16>) -> serde_json::Value {
    let mut value = serde_json::json!({
        "speaker": "Owen",
        "slots_line": "These times are open.",
        "no_fit_line": "Nothing fits.",
        "off_topic_line": "That is outside scheduling.",
        "max_turns": 4,
        "max_model_calls": 4,
    });
    if let Some(count) = max_offered_slots {
        value
            .as_object_mut()
            .expect("front JSON is an object")
            .insert("max_offered_slots".to_owned(), serde_json::json!(count));
    }
    value
}

/// An oracle that offers six ranked slots.
struct SixSlotOracle;

impl SlotOracle for SixSlotOracle {
    fn solve(&self, _req: &SolveRequest) -> Result<SolveResult, BookingError> {
        Ok(SolveResult {
            slots: vec![
                half_hour_slot(9, 0.2),
                half_hour_slot(10, 0.9),
                half_hour_slot(11, 0.4),
                half_hour_slot(12, 0.8),
                half_hour_slot(13, 0.1),
                half_hour_slot(14, 0.7),
            ],
            flex_used: false,
            host_bindings: Vec::new(),
        })
    }
}

fn half_hour_slot(hour: u64, rank: f32) -> RankedSlot {
    RankedSlot {
        start_utc: MONDAY + hour * 3_600,
        end_utc: MONDAY + hour * 3_600 + 1_800,
        rank,
    }
}

/// A backend that answers the off-topic read "no" and the extraction with one
/// scheduling constraint. The ladder read's turn names its question id, so the
/// answer echoes that id back; the extraction is recognised by elimination.
struct ParseBackend;

impl LlmBackend for ParseBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let text = last_user_text(&request);
        let body = if text.contains("questions") {
            ladder_no(&text)
        } else {
            extraction_body()
        };
        Box::pin(async move { Ok(backend_response(body)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn last_user_text(request: &LlmRequest) -> String {
    let message = request
        .messages
        .iter()
        .rev()
        .find(|message| matches!(message.role, LlmMessageRole::User))
        .expect("the front sends a user turn");
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// A "no" to the turn's own question: the sentence is a scheduling
/// preference, not something else.
fn ladder_no(turn: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(turn).expect("the ladder turn is JSON");
    let id = parsed["questions"][0]["id"]
        .as_str()
        .expect("the ladder turn names its question");
    let mut weights = serde_json::Map::new();
    weights.insert("yes".to_owned(), serde_json::Value::from(0.0));
    weights.insert("no".to_owned(), serde_json::Value::from(1.0));
    let mut reply = serde_json::Map::new();
    reply.insert(id.to_owned(), serde_json::Value::Object(weights));
    serde_json::Value::Object(reply).to_string()
}

fn extraction_body() -> String {
    serde_json::json!({
        "object": {
            "schema_version": CONSTRAINT_SCHEMA_VERSION,
            "weekdays": [],
            "local_time_windows": [],
            "utc_window": null,
            "allow_flex_pool": true,
        },
        "visitor_tz_override": null,
    })
    .to_string()
}

fn backend_response(body: String) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: body,
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 3,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 5,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

fn parse_config() -> ConstraintParseConfig {
    ConstraintParseConfig {
        model: ModelId::new("test/model@r1").expect("model id"),
        locality: ModelLocality::OwnServer,
        tier: TierPrecedence::for_purpose(
            &CallPurpose::Consolidation,
            ModelTierRef("default".into()),
        ),
        max_input_bytes: 1024,
        decisions: BookingDecisions::shipped(test_id(PRINCIPAL_SEED)),
    }
}

fn run_one_turn(config: &ConstraintFrontConfig) -> ConstraintSlotReply {
    let oracle = SixSlotOracle;
    let backend = ParseBackend;
    let lease = BudgetLease::for_test("pack-keys-booking-b07");
    let parse = parse_config();
    let caps = config.caps();
    let mut state = ConstraintSessionState::default();
    let copy = config.copy();
    let request = ConstraintTurnRequest {
        session_ref: "owen-visit-1".to_owned(),
        event_type: EventTypeKey("intro-call".to_owned()),
        window: TimeRange {
            start: NOW,
            end: NOW + 7 * 86_400,
        },
        detected_visitor_tz: "UTC".to_owned(),
        free_text: "tomorrow morning".to_owned(),
    };
    let outcome = block_on(run_constraint_turn(
        &oracle, &backend, &lease, &parse, &caps, &mut state, &copy, request,
    ))
    .expect("the front answers with slots");
    match outcome {
        ConstraintFrontOutcome::Slots(reply) => reply,
        ConstraintFrontOutcome::ContinueByEmail(_) => {
            panic!("six offered slots never continue by email")
        }
        ConstraintFrontOutcome::Deflect(_) => panic!("an on-topic sentence never deflects"),
    }
}

#[test]
fn b07_agent_front_offers_three_slots_by_default_and_the_pages_count_when_set() {
    let raw = front_json(None);
    let config: ConstraintFrontConfig =
        serde_json::from_value(raw.clone()).expect("the front without the choice parses");
    assert_eq!(
        config.max_offered_slots, DEFAULT_MAX_OFFERED_SLOTS,
        "the front without the choice takes the shipped count"
    );
    assert_eq!(
        config.max_offered_slots, 3,
        "today's front renders three slot buttons"
    );
    assert_eq!(
        serde_json::to_value(&config).expect("the front encodes"),
        raw,
        "the shipped count stays off the wire"
    );
    config.validate().expect("the default front validates");
    assert_eq!(
        config.caps().max_offered_slots,
        DEFAULT_MAX_OFFERED_SLOTS,
        "the caps carry the shipped count"
    );
    let reply = run_one_turn(&config);
    assert_eq!(
        reply.solve_result.slots.len(),
        6,
        "the card renders a prefix; the solve result stays whole"
    );
    assert_eq!(
        reply.card.actions.len(),
        3,
        "the default renders today's three buttons"
    );
    for declaration in &reply.card.actions {
        assert_eq!(
            declaration.action.command.as_str(),
            BOOKING_SLOT_BUTTON_ACTION,
            "every rendered button commits a slot"
        );
    }

    let owner: ConstraintFrontConfig =
        serde_json::from_value(front_json(Some(5))).expect("the front with the choice parses");
    assert_eq!(owner.max_offered_slots, 5, "the owner's count parses");
    owner.validate().expect("the owner's front validates");
    assert_eq!(
        owner.caps().max_offered_slots,
        5,
        "the caps carry the owner's count"
    );
    let owner_reply = run_one_turn(&owner);
    assert_eq!(
        owner_reply.card.actions.len(),
        5,
        "the owner's count sizes the card"
    );
    for declaration in &owner_reply.card.actions {
        assert_eq!(
            declaration.action.command.as_str(),
            BOOKING_SLOT_BUTTON_ACTION,
            "every rendered button commits a slot"
        );
    }

    let refused: ConstraintFrontConfig =
        serde_json::from_value(front_json(Some(0))).expect("the front naming no slot parses");
    assert!(
        matches!(refused.validate(), Err(BookingError::InvalidConfig(_))),
        "offering no slot is refused"
    );
}

// ---------------------------------------------------------------------
// B08: the first view's visible-slot count
// ---------------------------------------------------------------------

fn eight_slots() -> Vec<RankedSlot> {
    (0..8)
        .map(|i| RankedSlot {
            start_utc: 100 + i * 600,
            end_utc: 700 + i * 600,
            rank: 0.5,
        })
        .collect()
}

fn page_model(policy: &BookingConversionPolicy) -> BookingPageModel {
    let request = SolveRequest {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: 100,
            end: 4_900,
        },
        constraint: None,
        visitor_tz: "UTC".to_owned(),
    };
    let mask = slot_mask(
        &request,
        SolveResult {
            slots: eight_slots(),
            flex_used: false,
            host_bindings: Vec::new(),
        },
    );
    BookingPageModel::new(
        "Owen".to_owned(),
        vec![EventTypeCard {
            key: request.event_type,
            title: "Introduction".to_owned(),
            duration_min: 10,
            description: "Fixture description".to_owned(),
        }],
        project_at_rung(&[], DisclosureRung::Full, SurfaceClass::Public, Some(&mask))
            .expect("the public clamp keeps the mask"),
        ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        ThemeTokens(serde_json::json!({"mode": "fixture"})),
        BookingLandingContent::default(),
        "UTC".to_owned(),
        policy,
    )
    .expect("the page model assembles")
}

#[test]
fn b08_first_view_shows_five_by_default_and_the_policys_count_when_narrower() {
    let shipped = BookingConversionPolicy::default();
    assert_eq!(
        shipped.max_visible_slots, 5,
        "today's first view shows five slots"
    );
    let model = page_model(&shipped);
    assert_eq!(model.preview.visible.len(), 5);
    assert_eq!(model.preview.remaining_count, 3);
    let RungProjection::Slots(mask) = &model.slots else {
        panic!("the page carries a slots mask");
    };
    assert_eq!(
        model.preview.visible,
        mask.slots[..5].to_vec(),
        "the first view is the mask's ranked prefix"
    );
    validate_booking_page_model(&model).expect("today's first view validates");

    let narrow = BookingConversionPolicy {
        max_visible_slots: 2,
        ..shipped
    };
    let narrowed = page_model(&narrow);
    assert_eq!(narrowed.preview.visible.len(), 2);
    assert_eq!(narrowed.preview.remaining_count, 6);
    let RungProjection::Slots(narrow_mask) = &narrowed.slots else {
        panic!("the page carries a slots mask");
    };
    assert_eq!(
        narrowed.preview.visible,
        narrow_mask.slots[..2].to_vec(),
        "the narrower first view is the mask's first two"
    );
    validate_booking_page_model(&narrowed).expect("the narrower first view validates");

    let mut broken = narrowed;
    let RungProjection::Slots(broken_mask) = &broken.slots else {
        panic!("the page carries a slots mask");
    };
    let off_prefix = broken_mask.slots[1..4].to_vec();
    broken.preview = BookingSlotPreview {
        visible: off_prefix,
        recommended_start_utc: broken.preview.recommended_start_utc,
        remaining_count: broken.preview.remaining_count,
    };
    assert!(
        matches!(
            validate_booking_page_model(&broken),
            Err(BookingPageModelError::InvalidPreview)
        ),
        "a preview that is not the ranked prefix is refused"
    );
}

// ---------------------------------------------------------------------
// B11: flex windows as a fallback or beside ordinary hours
// ---------------------------------------------------------------------

/// A trimmed copy of the `booking_feed_move.rs` solver fixture: the vault, the
/// page and the host it solves for. The lifecycle turns, the feed poll and the
/// home-node election are trimmed: this test only solves.
struct SolverFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
}

impl SolverFixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let page = test_id(PAGE_SEED);
        vault
            .put_entity(
                &page,
                ENTITY_TYPE_ASSET,
                TimeRange { start: 1, end: 1 },
                1,
                b"booking page",
            )
            .expect("put booking page");
        vault
            .put_entity(
                &test_id(HOST_SEED),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"owen",
            )
            .expect("put host");
        Self {
            _dir: dir,
            vault,
            page,
        }
    }

    fn solve(&self, flex_with_ordinary: bool) -> SolveResult {
        let calendars = vec![(test_id(HOST_SEED), vec![CalendarSel { system: None }])];
        let holds = VaultActiveHoldSource::new(&self.vault);
        BookingSolver {
            vault: &self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(solver_config(flex_with_ordinary)),
        }
        .solve(&SolveRequest {
            event_type: EventTypeKey("intro-call".to_owned()),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        })
        .expect("the fixture day solves")
    }
}

/// The `booking_feed_move.rs` fixture configuration, plus a Monday 16:00-17:00
/// flex window outside the 09:00-14:00 working hours, in the host's own zone.
fn solver_config(flex_with_ordinary: bool) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro-call".to_owned()),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: test_id(HOST_SEED),
            calendar_refs: vec![test_id(BUSY_SEED)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 14 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_with_ordinary,
        flex_windows: vec![WeeklyWallWindow {
            weekday: 0,
            start_minute: 16 * 60,
            end_minute: 17 * 60,
        }],
    }
}

#[test]
fn b11_flex_windows_stay_a_fallback_by_default_and_join_ordinary_hours_when_set() {
    let fixture = SolverFixture::open();
    let fallback = fixture.solve(false);
    assert!(!fallback.flex_used, "flex stays a fallback by default");
    assert!(
        !fallback.slots.is_empty(),
        "the fixture day offers ordinary slots"
    );
    for slot in &fallback.slots {
        assert!(
            (MONDAY + 9 * 3_600..MONDAY + 14 * 3_600).contains(&slot.start_utc),
            "a default solve stays in working hours"
        );
    }

    let widened = fixture.solve(true);
    assert!(widened.flex_used, "the widened solve marks flex used");
    let flex_start = MONDAY + 16 * 3_600;
    let flex_end = MONDAY + 17 * 3_600;
    assert!(
        widened
            .slots
            .iter()
            .any(|slot| (flex_start..flex_end).contains(&slot.start_utc)),
        "the widened solve offers the flex window"
    );
}

// ---------------------------------------------------------------------
// B12: the companion proposal's choice count
// ---------------------------------------------------------------------

/// A trimmed copy of the `companion_preset/tests.rs` fixture: the vault and
/// the companion row that creates the proposal.
struct CompanionFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

impl CompanionFixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        vault
            .put_entity(
                &test_id(COMPANION_SEED),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"owen",
            )
            .expect("put companion");
        Self { _dir: dir, vault }
    }

    fn propose(
        &self,
        oracle: &dyn SlotOracle,
        preset: &CompanionPresetRow,
    ) -> CompanionProposalCreation {
        create_companion_proposal(
            &self
                .vault
                .memory(test_id(COMPANION_SEED), EdgeActorClass::Agent),
            oracle,
            test_id(OWNER_SEED),
            preset,
            TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            None,
            "UTC".to_owned(),
            2,
            NOW + 3_600,
        )
        .expect("the companion proposes")
    }
}

/// The `companion_preset/tests.rs` synthetic configuration.
fn companion_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("friend-hangout".to_owned()),
        duration_min: 60,
        slot_step_min: 60,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 14 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: test_id(HANGOUT_HOST_SEED),
            calendar_refs: vec![test_id(HANGOUT_CALENDAR_SEED)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 17 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_with_ordinary: false,
        flex_windows: vec![WeeklyWallWindow {
            weekday: 5,
            start_minute: 10 * 60,
            end_minute: 22 * 60,
        }],
    }
}

/// An oracle that offers eight ranked slots.
struct EightSlotOracle;

impl SlotOracle for EightSlotOracle {
    fn solve(&self, _req: &SolveRequest) -> Result<SolveResult, BookingError> {
        Ok(SolveResult {
            slots: vec![
                hour_slot(9, 0.5),
                hour_slot(10, 0.9),
                hour_slot(11, 0.1),
                hour_slot(12, 0.8),
                hour_slot(13, 0.2),
                hour_slot(14, 0.7),
                hour_slot(15, 0.3),
                hour_slot(16, 0.6),
            ],
            flex_used: false,
            host_bindings: Vec::new(),
        })
    }
}

fn hour_start(hour: u64) -> u64 {
    MONDAY + hour * 3_600
}

fn hour_slot(hour: u64, rank: f32) -> RankedSlot {
    RankedSlot {
        start_utc: hour_start(hour),
        end_utc: hour_start(hour) + 3_600,
        rank,
    }
}

fn choice_starts(proposal: &CompanionProposal) -> Vec<u64> {
    proposal
        .choices
        .iter()
        .map(|choice| choice.slot.start_utc)
        .collect()
}

/// A preset manifest in the friend-hangout shape, naming Yuki's hangout.
fn preset_json(max_choices: Option<u16>) -> Vec<u8> {
    let mut preset = serde_json::json!({
        "id": "booking.companion.yuki_hangout.v1",
        "carrier": "message_link",
        "confirmation": "soft_via_companion",
        "personal_hours": true,
        "generous_flex": true,
        "email_otp_enabled": false,
        "group_intersection": true,
    });
    if let Some(count) = max_choices {
        preset
            .as_object_mut()
            .expect("preset JSON is an object")
            .insert("max_choices".to_owned(), serde_json::json!(count));
    }
    serde_json::json!({ "version": 1, "preset": preset })
        .to_string()
        .into_bytes()
}

#[test]
fn b12_a_companion_proposal_offers_five_choices_by_default_and_the_presets_count_when_set() {
    let fixture = CompanionFixture::open();
    let oracle = EightSlotOracle;
    let row = friend_hangout_preset(companion_config()).expect("the friend-hangout row loads");
    assert_eq!(
        row.max_choices, DEFAULT_PROPOSAL_MAX_CHOICES,
        "the friend-hangout row takes the shipped count"
    );
    assert_eq!(row.max_choices, 5, "today's proposal offers five choices");
    let created = fixture.propose(&oracle, &row);
    assert_eq!(created.proposal.choices.len(), 5);
    assert_eq!(
        choice_starts(&created.proposal),
        vec![
            hour_start(10),
            hour_start(12),
            hour_start(14),
            hour_start(16),
            hour_start(9),
        ],
        "the shortlist keeps the five highest-ranked"
    );

    let absent = load_companion_preset(&preset_json(None), companion_config())
        .expect("a preset without the choice loads");
    assert_eq!(
        absent.max_choices, DEFAULT_PROPOSAL_MAX_CHOICES,
        "a preset without the choice takes the shipped count"
    );

    let two_row = load_companion_preset(&preset_json(Some(2)), companion_config())
        .expect("a preset naming two choices loads");
    assert_eq!(two_row.max_choices, 2, "the preset's count parses");
    let two = fixture.propose(&oracle, &two_row);
    assert_eq!(two.proposal.choices.len(), 2);
    assert_eq!(
        choice_starts(&two.proposal),
        vec![hour_start(10), hour_start(12)],
        "the shortlist keeps the two highest-ranked"
    );

    assert!(
        matches!(
            load_companion_preset(&preset_json(Some(0)), companion_config()),
            Err(BookingError::InvalidConfig(_))
        ),
        "a proposal with no choice is refused"
    );
}

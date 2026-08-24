//! CAL-06 prep-pack oracle (ONE-1788).
//!
//! Pins the five laws the prep layer exists to hold, at the public boundary:
//!
//! 1. **The wake is the host's, and it is exact.** T-45 is computed at schedule
//!    time, recomputed when the EVENT moves, and carried on a stable per-EVENT
//!    id so rescheduling REPLACES the entry. The engine starts nothing.
//! 2. **External meetings by default.** An external attendee, a campaign
//!    linkage, or a commitment linkage arms prep on its own; internal-only and
//!    solo events need an explicit opt-in. An imported `VALARM` is neither.
//! 3. **Render time, not nightly.** The pack is assembled from state the vault
//!    had learned at the fire instant — evidence that landed after scheduling
//!    is in, evidence that lands after the fire is out, and nothing is stored
//!    to be replayed later.
//! 4. **Precedence beats recency, and the ceiling is spent top-down.** Prior
//!    commitments precede threads precede dossier delta even when the dossier
//!    row is newest, and the default 250-word ceiling never overruns.
//! 5. **Silence is an answer.** No evidence means no pack and no lens — never
//!    an empty or padded card. Closed-vault delivery enters through exactly one
//!    door, which rechecks eligibility and staleness before it renders.
//!
//! ## Known hole this file inherits (NOT owned by CAL-06)
//!
//! `gate::default_policy_manifest()` has no `calendar.` rule, so under the
//! shipped default every calendar claim write is gate-pending — the hole
//! `calendar_claims_are_gate_pending_under_the_default_policy_manifest`
//! (tests/calendar_surface_oracle.rs, CAL-09) already pins, whose fix lives in
//! `crates/oneiron/src/gate.rs`, a lane-wide CAL non-claim. These oracles
//! therefore run on an unseeded vault, exactly like the CAL-07 outcome oracle:
//! the subject here is the prep layer's own laws, not the policy manifest's.

mod common;

use std::path::Path;

use common::entity as test_id;
use oneiron::calendar::ics::parse_ics_feed;
use oneiron::calendar::prep::{
    DEFAULT_PREP_LEAD_SECS, DEFAULT_PREP_MAX_WORDS, PREP_WAKE_REASON_TAG, PREP_WAKE_SCHEDULE_KIND,
    PrepBuildRequest, PrepEvent, PrepHomeNodeJob, PrepLensCopy, PrepPack, PrepPolicy,
    PrepSectionKind, build_prep_pack, plan_prep_wake, prep_is_eligible, prep_wake_id,
    render_prep_lens, run_due_home_node_prep,
};
use oneiron::edge::EdgeKind;
use oneiron::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

/// Contract wire bounds (`oneiron_vault_contract::MAX_WAKE_ID` /
/// `MAX_REASON_TAG`), restated as numbers because `crates/oneiron` carries no
/// dependency on the contract crate at this commit — the same reason
/// `calendar::prep::PrepWake` is the engine-side image of `WakeEntry`.
const CONTRACT_MAX_WAKE_ID: usize = 128;
const CONTRACT_MAX_REASON_TAG: usize = 64;

/// Fixture seeds. All outside `PINNED_ID_BYTES`.
const EVENT_SEED: u8 = 0x51;
const SECOND_EVENT_SEED: u8 = 0x52;
const PERSON_SEED: u8 = 0x53;
const TURN_SEED: u8 = 0x54;
const SUMMARY_SEED: u8 = 0x55;
const LATE_TURN_SEED: u8 = 0x56;
const BULK_SEED_BASE: u8 = 0x60;

const EVENT_START: u64 = 1_754_400_000;
const EVENT_END: u64 = EVENT_START + 3_600;
/// The instant the host reports the T-45 wake as due.
const FIRE_AT: u64 = EVENT_START - DEFAULT_PREP_LEAD_SECS;
/// The wake was planned a day ahead of the meeting.
const PLANNED_AT: u64 = EVENT_START - 86_400;

/// Learned instants: the commitment predates scheduling, the thread and the
/// dossier row both land between scheduling and T-45 (the dossier row LAST, so
/// recency alone would put it first), and the late turn lands after the fire.
const COMMITMENT_AT: u64 = PLANNED_AT - 1_000;
const THREAD_AT: u64 = FIRE_AT - 600;
const DOSSIER_AT: u64 = FIRE_AT - 60;
const LATE_AT: u64 = FIRE_AT + 600;

// Compile-time checks of the fixture invariants the ordering tests rely on.
const _: () = assert!(THREAD_AT > PLANNED_AT && THREAD_AT < FIRE_AT);
const _: () = assert!(DOSSIER_AT > THREAD_AT && THREAD_AT > COMMITMENT_AT);

const COMMITMENT_TEXT: &str = "owes the counterparty a revised quote";
const THREAD_TEXT: &str = "counterparty asked about the revised quote";
const DOSSIER_TEXT: &str = "counterparty moved to a new employer";
const LATE_TEXT: &str = "arrived after the wake fired";

/// An unseeded vault: keeps the claim write door open without a policy fixture,
/// so these oracles measure CAL-06's laws rather than the missing `calendar.`
/// rule in the default policy manifest (see the module note).
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A one-key MessagePack body, the shape `context_pack` hydration decodes into
/// the `fields` map the prep layer reads its text from.
fn text_body(key: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(vec![(Value::from(key), Value::from(text))]),
    )
    .expect("encode body");
    out
}

/// Claim ids keyed `(0xB5, seed, index)` so no fixture claim aliases a generic
/// `entity(seed)` id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB5_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

fn put_event(vault: &Vault, seed: u8, start: u64, end: u64) -> EntityId {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange { start, end },
            PLANNED_AT,
            &text_body("name", "quarterly review"),
        )
        .expect("put event");
    id
}

fn put_text_entity(
    vault: &Vault,
    seed: u8,
    entity_type: u8,
    key: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            entity_type,
            at(learned_at),
            learned_at,
            &text_body(key, text),
        )
        .expect("put text entity");
    id
}

/// Writes one surfaceable claim through the ordinary public claim door.
fn put_claim(
    vault: &Vault,
    id: EntityId,
    predicate: &str,
    subject: EntityId,
    value: Value,
    learned_at: u64,
) {
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&id, &body, at(learned_at), learned_at)
        .expect("put claim");
}

/// CAL-00's `calendar.attendee` row: the only attendee evidence the ENGINE owns
/// (vendor strings, never entity refs), and what the due-time recheck counts.
fn put_attendee(vault: &Vault, index: u8, event_ref: EntityId, who: &str) {
    put_claim(
        vault,
        claim_id(EVENT_SEED, index),
        "calendar.attendee",
        event_ref,
        Value::Map(vec![
            (Value::from("who"), Value::from(who)),
            (Value::from("role"), Value::from("REQ-PARTICIPANT")),
            (Value::from("partstat"), Value::from("ACCEPTED")),
        ]),
        PLANNED_AT,
    );
}

fn cancel_event(vault: &Vault, index: u8, event_ref: EntityId) {
    put_claim(
        vault,
        claim_id(EVENT_SEED, index),
        "calendar.status",
        event_ref,
        Value::Map(vec![
            (Value::from("status"), Value::from("cancelled")),
            (Value::from("basis"), Value::from("imported_absence")),
            (Value::from("recorded_at"), Value::from(FIRE_AT)),
        ]),
        FIRE_AT,
    );
}

/// One meeting with a counterparty, a prior commitment, a recent thread, a
/// dossier delta, and one row that arrives too late to be seen at T-45.
struct PrepFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    event_ref: EntityId,
    person_ref: EntityId,
    commitment_ref: EntityId,
    turn_ref: EntityId,
    summary_ref: EntityId,
    late_turn_ref: EntityId,
}

impl PrepFixture {
    fn event(&self) -> PrepEvent {
        PrepEvent {
            event_ref: self.event_ref,
            start_utc: EVENT_START,
            end_utc: EVENT_END,
            attendee_refs: vec![self.person_ref],
            external_attendee_count: 1,
            has_campaign_linkage: false,
            has_commitment_linkage: false,
            internal_meeting_opt_in: false,
        }
    }

    fn request(&self, fired_at: u64) -> PrepBuildRequest {
        PrepBuildRequest {
            event: self.event(),
            fired_at,
            policy: PrepPolicy::default(),
        }
    }
}

fn seeded_prep_vault() -> PrepFixture {
    let (dir, vault) = temp_vault();
    let event_ref = put_event(&vault, EVENT_SEED, EVENT_START, EVENT_END);
    let person_ref = put_text_entity(
        &vault,
        PERSON_SEED,
        ENTITY_TYPE_PERSON,
        "name",
        "counterparty",
        PLANNED_AT,
    );
    put_attendee(&vault, 0, event_ref, "mailto:counterparty@example.com");

    let commitment_ref = claim_id(PERSON_SEED, 1);
    put_claim(
        &vault,
        commitment_ref,
        "prep.commitment",
        person_ref,
        Value::from(COMMITMENT_TEXT),
        COMMITMENT_AT,
    );
    let turn_ref = put_text_entity(
        &vault,
        TURN_SEED,
        ENTITY_TYPE_TURN,
        "txt",
        THREAD_TEXT,
        THREAD_AT,
    );
    let summary_ref = put_text_entity(
        &vault,
        SUMMARY_SEED,
        ENTITY_TYPE_SUMMARY,
        "text",
        DOSSIER_TEXT,
        DOSSIER_AT,
    );
    let late_turn_ref = put_text_entity(
        &vault,
        LATE_TURN_SEED,
        ENTITY_TYPE_TURN,
        "txt",
        LATE_TEXT,
        LATE_AT,
    );

    vault
        .batch()
        .edge(&event_ref, EdgeKind::ParticipatesIn, &person_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &commitment_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &turn_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &summary_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &late_turn_ref, 1.0)
        .commit()
        .expect("fixture edges commit");

    PrepFixture {
        _dir: dir,
        vault,
        event_ref,
        person_ref,
        commitment_ref,
        turn_ref,
        summary_ref,
        late_turn_ref,
    }
}

/// A meeting with one external attendee and nothing else set.
fn external_event(event_ref: EntityId, start: u64) -> PrepEvent {
    PrepEvent {
        event_ref,
        start_utc: start,
        end_utc: start + 3_600,
        attendee_refs: Vec::new(),
        external_attendee_count: 1,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

/// A solo/internal meeting: nobody outside the house, no linkage, no opt-in.
fn solo_event(event_ref: EntityId, start: u64) -> PrepEvent {
    PrepEvent {
        event_ref,
        start_utc: start,
        end_utc: start + 3_600,
        attendee_refs: Vec::new(),
        external_attendee_count: 0,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

/// Distinctive caller copy: every one of these strings must reach the card, and
/// none of them may exist in engine Rust.
fn copy() -> PrepLensCopy {
    PrepLensCopy {
        title: "ZZ-TITLE-before-you-walk-in".to_owned(),
        commitment_heading: "ZZ-HEADING-you-owe-them".to_owned(),
        thread_heading: "ZZ-HEADING-recent-threads".to_owned(),
        dossier_heading: "ZZ-HEADING-what-changed".to_owned(),
    }
}

fn prep_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/calendar/prep.rs");
    std::fs::read_to_string(path).expect("read prep source")
}

/// Flattens a pack into `(kind, text)` rows in rendered order.
fn rows(pack: &PrepPack) -> Vec<(PrepSectionKind, String)> {
    pack.sections
        .iter()
        .flat_map(|section| {
            section
                .items
                .iter()
                .map(|item| (section.kind, item.text.clone()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Law 1 — the wake is the host's, and it is exact.
// ---------------------------------------------------------------------------

#[test]
fn prep_wake_is_host_schedule_exact_at_t45() {
    let event_ref = test_id(EVENT_SEED);
    let event = external_event(event_ref, EVENT_START);
    let wake = plan_prep_wake(prep_wake_id(&event_ref), &event, PrepPolicy::default())
        .expect("an external meeting arms the wake");

    // T-45, to the second, computed from the EVENT start.
    assert_eq!(DEFAULT_PREP_LEAD_SECS, 45 * 60);
    assert_eq!(wake.at_utc, EVENT_START - DEFAULT_PREP_LEAD_SECS);
    assert_eq!(wake.reason_tag, PREP_WAKE_REASON_TAG);

    // Exact, never a window: CAL plans one instant and recomputes it, so the
    // host has nothing to jitter. This is the `Schedule::Exact` wire arm.
    assert_eq!(PREP_WAKE_SCHEDULE_KIND, "exact");

    // The contract's wake bounds hold without the contract crate present.
    assert!(!wake.id.is_empty());
    assert!(wake.id.len() <= CONTRACT_MAX_WAKE_ID);
    assert!(wake.reason_tag.len() <= CONTRACT_MAX_REASON_TAG);
    assert!(!wake.id.bytes().any(|byte| byte < 0x20));
    assert!(!wake.reason_tag.bytes().any(|byte| byte < 0x20));

    // A start inside the first 45 minutes of the epoch has no representable
    // T-45. That is no wake at all, never a wake saturated to 1970.
    let unrepresentable = external_event(event_ref, 60);
    assert!(
        plan_prep_wake(
            prep_wake_id(&event_ref),
            &unrepresentable,
            PrepPolicy::default()
        )
        .is_none()
    );
}

#[test]
fn prep_wake_is_recomputed_when_event_start_moves() {
    let event_ref = test_id(EVENT_SEED);
    let mut event = external_event(event_ref, EVENT_START);
    let policy = PrepPolicy::default();

    let first = plan_prep_wake(prep_wake_id(&event_ref), &event, policy).expect("first wake");
    event.start_utc += 3_600;
    event.end_utc += 3_600;
    let second = plan_prep_wake(prep_wake_id(&event_ref), &event, policy).expect("second wake");

    // The instant moves with the meeting...
    assert_ne!(first.at_utc, second.at_utc);
    assert_eq!(second.at_utc, first.at_utc + 3_600);
    // ...and the id does NOT, so the host replaces one entry instead of
    // accumulating a wake per reschedule.
    assert_eq!(first.id, second.id);
    assert_eq!(first.id, prep_wake_id(&event_ref));
    assert_eq!(first.reason_tag, second.reason_tag);

    // Stability is per EVENT and per purpose, not global.
    assert_ne!(
        prep_wake_id(&event_ref),
        prep_wake_id(&test_id(SECOND_EVENT_SEED))
    );
}

#[test]
fn prep_module_starts_no_timer_or_cron() {
    let source = prep_source();
    // No clock is read, nothing is started, nothing repeats, and no recurrence
    // primitive is minted. The engine describes a wake and returns.
    for forbidden in [
        "std::thread",
        "thread::spawn",
        "std::time",
        "SystemTime",
        "Instant",
        "sleep",
        "tokio",
        "async ",
        "loop {",
        "while ",
        "cron",
        "interval(",
        "set_timeout",
        // No new recurrence primitive either: expansion stays in CAL-03.
        "RRULE",
        "rrule",
        "super::series",
        "expand_window",
    ] {
        assert!(
            !source.contains(forbidden),
            "calendar/prep.rs must not contain {forbidden:?}"
        );
    }
}

#[test]
fn prep_persists_nothing_and_adds_no_type_byte() {
    let source = prep_source();
    // Render time means render time: no write door is opened here at all, so
    // there is no prep entity, no prep claim, and no stale artifact to serve.
    // No new type byte or edge kind either — this layer allocates nothing.
    for forbidden in [
        "put_entity",
        "put_claim",
        "put_blob_artifact",
        "with_write_txn",
        "write_txn",
        ".batch()",
        "supersede",
        "pub const ENTITY_TYPE_",
        "ENTITY_TYPE_REGISTRY",
        "EdgeKind",
        // Home-node election and lease storage stay host-owned (CAL-06
        // non-claim: no edit to and no copy of `src/sync/lease.rs`).
        "crate::sync",
        "sync::lease",
        "LeaseManager",
        // Delivery uses host surfaces outside this ticket.
        "outbound",
    ] {
        assert!(
            !source.contains(forbidden),
            "calendar/prep.rs must not contain {forbidden:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Law 2 — external meetings by default.
// ---------------------------------------------------------------------------

#[test]
fn external_meeting_arms_by_default() {
    let event_ref = test_id(EVENT_SEED);
    let event = external_event(event_ref, EVENT_START);
    let policy = PrepPolicy::default();

    assert!(policy.external_only, "external-only is the shipped default");
    assert_eq!(policy.max_words, DEFAULT_PREP_MAX_WORDS);
    assert_eq!(policy.lead_secs, DEFAULT_PREP_LEAD_SECS);

    assert!(prep_is_eligible(&event, policy));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &event, policy).is_some());
}

#[test]
fn campaign_or_commitment_linkage_arms_without_external_attendee() {
    let event_ref = test_id(EVENT_SEED);
    let policy = PrepPolicy::default();

    let mut campaign = solo_event(event_ref, EVENT_START);
    campaign.has_campaign_linkage = true;
    assert!(prep_is_eligible(&campaign, policy));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &campaign, policy).is_some());

    let mut commitment = solo_event(event_ref, EVENT_START);
    commitment.has_commitment_linkage = true;
    assert!(prep_is_eligible(&commitment, policy));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &commitment, policy).is_some());
}

#[test]
fn internal_and_solo_events_require_explicit_opt_in() {
    let event_ref = test_id(EVENT_SEED);
    let policy = PrepPolicy::default();

    // Solo: nobody outside the house, no linkage, no opt-in.
    let solo = solo_event(event_ref, EVENT_START);
    assert!(!prep_is_eligible(&solo, policy));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &solo, policy).is_none());

    // Internal-only with colleagues present is still internal-only: only the
    // external count arms by default, and it is zero.
    let mut internal = solo_event(event_ref, EVENT_START);
    internal.attendee_refs = vec![test_id(PERSON_SEED)];
    assert!(!prep_is_eligible(&internal, policy));

    // Two doors, both explicit: per event...
    let mut opted_in = internal.clone();
    opted_in.internal_meeting_opt_in = true;
    assert!(prep_is_eligible(&opted_in, policy));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &opted_in, policy).is_some());

    // ...or vault-wide, by clearing the external-only default.
    let wide = PrepPolicy {
        external_only: false,
        ..PrepPolicy::default()
    };
    assert!(prep_is_eligible(&internal, wide));
}

#[test]
fn imported_valarm_does_not_arm_prep_or_reminder() {
    let feed = concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:valarm-only@example.com\r\n",
        "DTSTAMP:20260805T100000Z\r\n",
        "DTSTART:20260806T140000Z\r\n",
        "DTEND:20260806T150000Z\r\n",
        "SEQUENCE:0\r\n",
        "SUMMARY:solo focus block\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT45M\r\n",
        "DESCRIPTION:imported reminder\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\nEND:VCALENDAR"
    );
    let parsed = parse_ics_feed(feed.as_bytes()).expect("feed with a VALARM parses");
    let vevent = parsed.events.first().expect("one VEVENT");

    // The alarm reaches no engine-side surface a prep signal could be read
    // from: `ParsedVEvent` has no alarm field and the canonical component
    // excludes nested components outright.
    let component = String::from_utf8(vevent.raw_component.clone()).expect("utf8 component");
    assert!(!component.contains("VALARM"));
    assert!(!component.contains("TRIGGER"));

    // The imported event is solo, so it stays disarmed. The VALARM does not
    // arm prep, and it does not mint a reminder either — there is no door here
    // that turns a feed alarm into a wake.
    let event_ref = test_id(EVENT_SEED);
    let start = vevent.starts_at_utc.expect("DTSTART converts");
    let imported = solo_event(event_ref, start);
    assert!(!prep_is_eligible(&imported, PrepPolicy::default()));
    assert!(plan_prep_wake(prep_wake_id(&event_ref), &imported, PrepPolicy::default()).is_none());
}

// ---------------------------------------------------------------------------
// Law 3 — render time, not nightly.
// ---------------------------------------------------------------------------

#[test]
fn pack_is_built_from_state_visible_at_fire_time() {
    let fixture = seeded_prep_vault();

    let at_fire = build_prep_pack(&fixture.vault, &fixture.request(FIRE_AT))
        .expect("build succeeds")
        .expect("the meeting has evidence");
    let texts: Vec<String> = rows(&at_fire).into_iter().map(|(_, text)| text).collect();

    // Landed AFTER the wake was planned, BEFORE it fired: in.
    assert!(texts.iter().any(|text| text.contains(THREAD_TEXT)));
    // Landed after the fire instant: out. A pack precomputed at scheduling
    // time could not know it; a pack built at fire time must not use it.
    assert!(!texts.iter().any(|text| text.contains(LATE_TEXT)));
    assert_eq!(at_fire.built_at, FIRE_AT);
    assert_eq!(at_fire.event_ref, fixture.event_ref.to_hex());

    // Nothing was stored: assembling again at a later instant legitimately
    // sees more, which is only possible because there is no saved artifact.
    let later = build_prep_pack(&fixture.vault, &fixture.request(LATE_AT + 1))
        .expect("build succeeds")
        .expect("the meeting still has evidence");
    let later_texts: Vec<String> = rows(&later).into_iter().map(|(_, text)| text).collect();
    assert!(later_texts.iter().any(|text| text.contains(LATE_TEXT)));

    // And a pack assembled before ANY evidence landed is empty, not a
    // pre-baked copy of a later one.
    assert!(
        build_prep_pack(&fixture.vault, &fixture.request(COMMITMENT_AT - 1))
            .expect("build succeeds")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Law 4 — precedence beats recency; the ceiling is spent top-down.
// ---------------------------------------------------------------------------

#[test]
fn prior_commitments_precede_threads_and_dossier_delta() {
    let fixture = seeded_prep_vault();
    let pack = build_prep_pack(&fixture.vault, &fixture.request(FIRE_AT))
        .expect("build succeeds")
        .expect("the meeting has evidence");

    let kinds: Vec<PrepSectionKind> = pack.sections.iter().map(|section| section.kind).collect();
    assert_eq!(
        kinds,
        vec![
            PrepSectionKind::PriorCommitment,
            PrepSectionKind::AttendeeThread,
            PrepSectionKind::DossierDelta,
        ],
        "sections rank by precedence, never by recency"
    );

    let ordered = rows(&pack);
    let position = |needle: &str| {
        ordered
            .iter()
            .position(|(_, text)| text.contains(needle))
            .unwrap_or_else(|| panic!("{needle} is missing from the pack"))
    };
    let commitment = position(COMMITMENT_TEXT);
    let thread = position(THREAD_TEXT);
    let dossier = position(DOSSIER_TEXT);

    // The dossier row is the NEWEST thing in the pack and still ranks last;
    // the commitment is the OLDEST and still ranks first.
    assert!(commitment < thread, "commitments precede threads");
    assert!(thread < dossier, "threads precede dossier delta");

    // Each row names the vault row it came from.
    let backing: Vec<String> = pack
        .sections
        .iter()
        .flat_map(|section| section.items.iter())
        .flat_map(|item| item.source_refs.clone())
        .collect();
    for expected in [
        fixture.commitment_ref,
        fixture.turn_ref,
        fixture.summary_ref,
    ] {
        assert!(backing.contains(&expected.to_hex()));
    }
    assert!(!backing.contains(&fixture.late_turn_ref.to_hex()));
    // The EVENT and its attendee are seeds, not evidence about themselves.
    assert!(!backing.contains(&fixture.event_ref.to_hex()));
    assert!(!backing.contains(&fixture.person_ref.to_hex()));
}

#[test]
fn prep_pack_never_exceeds_default_250_words() {
    let (_dir, vault) = temp_vault();
    let event_ref = put_event(&vault, EVENT_SEED, EVENT_START, EVENT_END);
    let person_ref = put_text_entity(
        &vault,
        PERSON_SEED,
        ENTITY_TYPE_PERSON,
        "name",
        "counterparty",
        PLANNED_AT,
    );

    // Six rows of a hundred words each: six hundred words of evidence against
    // a two-hundred-and-fifty-word ceiling, spread across all three sections.
    let long_text = (0..100)
        .map(|index| format!("w{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut refs = Vec::new();
    for offset in 0..6_u8 {
        let seed = BULK_SEED_BASE + offset;
        let learned_at = COMMITMENT_AT + u64::from(offset);
        let id = if offset % 3 == 0 {
            let id = claim_id(seed, 0);
            put_claim(
                &vault,
                id,
                "prep.commitment",
                person_ref,
                Value::from(long_text.as_str()),
                learned_at,
            );
            id
        } else if offset % 3 == 1 {
            put_text_entity(
                &vault,
                seed,
                ENTITY_TYPE_TURN,
                "txt",
                &long_text,
                learned_at,
            )
        } else {
            put_text_entity(
                &vault,
                seed,
                ENTITY_TYPE_SUMMARY,
                "text",
                &long_text,
                learned_at,
            )
        };
        refs.push(id);
    }

    let mut batch = vault
        .batch()
        .edge(&event_ref, EdgeKind::ParticipatesIn, &person_ref, 1.0);
    for id in &refs {
        batch = batch.edge(&person_ref, EdgeKind::About, id, 1.0);
    }
    batch.commit().expect("bulk fixture edges commit");

    let request = PrepBuildRequest {
        event: PrepEvent {
            event_ref,
            start_utc: EVENT_START,
            end_utc: EVENT_END,
            attendee_refs: vec![person_ref],
            external_attendee_count: 1,
            has_campaign_linkage: false,
            has_commitment_linkage: false,
            internal_meeting_opt_in: false,
        },
        fired_at: FIRE_AT,
        policy: PrepPolicy::default(),
    };
    let pack = build_prep_pack(&vault, &request)
        .expect("build succeeds")
        .expect("the meeting has evidence");

    let counted: usize = pack
        .sections
        .iter()
        .flat_map(|section| section.items.iter())
        .map(|item| item.text.split_whitespace().count())
        .sum();
    assert_eq!(
        pack.word_count, counted,
        "the reported count is the real one"
    );
    assert!(
        counted <= DEFAULT_PREP_MAX_WORDS,
        "pack carried {counted} words against a {DEFAULT_PREP_MAX_WORDS}-word ceiling"
    );
    // The budget is spent top-down: the highest-ranked section survives the
    // cut, so truncation never promotes lower-ranked material.
    assert_eq!(
        pack.sections.first().expect("a surviving section").kind,
        PrepSectionKind::PriorCommitment
    );

    // A zero budget is silence, not an empty card.
    let starved = PrepBuildRequest {
        policy: PrepPolicy {
            max_words: 0,
            ..PrepPolicy::default()
        },
        ..request
    };
    assert!(
        build_prep_pack(&vault, &starved)
            .expect("build succeeds")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Law 5 — silence is an answer; one door for closed-vault delivery.
// ---------------------------------------------------------------------------

#[test]
fn no_useful_context_returns_none_and_renders_nothing() {
    let (_dir, vault) = temp_vault();
    let event_ref = put_event(&vault, EVENT_SEED, EVENT_START, EVENT_END);
    put_attendee(&vault, 0, event_ref, "mailto:counterparty@example.com");

    let request = PrepBuildRequest {
        event: external_event(event_ref, EVENT_START),
        fired_at: FIRE_AT,
        policy: PrepPolicy::default(),
    };
    // Eligible, and still nothing to say: an armed meeting with no evidence.
    assert!(prep_is_eligible(&request.event, request.policy));
    let pack = build_prep_pack(&vault, &request).expect("build succeeds");
    assert!(
        pack.is_none(),
        "no evidence means no pack, not an empty one"
    );

    // The due door agrees, and emits no lens at all — not an empty card, not a
    // padded one.
    let wake = plan_prep_wake(prep_wake_id(&event_ref), &request.event, request.policy)
        .expect("wake is planned");
    let job = PrepHomeNodeJob::from_wake(&event_ref, &wake);
    let rendered = run_due_home_node_prep(&vault, &job, FIRE_AT, request.policy, &copy())
        .expect("due run succeeds");
    assert!(rendered.is_none());
}

#[test]
fn closed_vault_due_payload_runs_only_through_home_node_job_entrypoint() {
    let source = prep_source();
    // Exactly one function takes the due payload. There is no second door a
    // closed-vault wake could enter through.
    assert_eq!(
        source.matches("job: &PrepHomeNodeJob").count(),
        1,
        "the due payload must be accepted by exactly one entrypoint"
    );
    assert_eq!(source.matches("pub fn run_due_home_node_prep").count(), 1);
    // The payload stays small and deterministic: three scalars, no context.
    for field in [
        "pub event_ref: String",
        "pub scheduled_for: u64",
        "pub wake_id: String",
    ] {
        assert!(source.contains(field), "due payload must carry {field}");
    }

    // And the door works when the host says it holds the election.
    let fixture = seeded_prep_vault();
    let wake = plan_prep_wake(
        prep_wake_id(&fixture.event_ref),
        &fixture.event(),
        PrepPolicy::default(),
    )
    .expect("wake is planned");
    let job = PrepHomeNodeJob::from_wake(&fixture.event_ref, &wake);
    assert_eq!(job.event_ref, fixture.event_ref.to_hex());
    assert_eq!(job.scheduled_for, FIRE_AT);
    assert_eq!(job.wake_id, wake.id);
    // Serializable, and byte-identical for the same wake.
    let encoded = serde_json::to_string(&job).expect("payload serializes");
    let decoded: PrepHomeNodeJob = serde_json::from_str(&encoded).expect("payload round-trips");
    assert_eq!(decoded, job);

    assert!(
        run_due_home_node_prep(
            &fixture.vault,
            &job,
            FIRE_AT,
            PrepPolicy::default(),
            &copy()
        )
        .expect("due run succeeds")
        .is_some()
    );
}

#[test]
fn due_job_rechecks_event_eligibility_and_staleness() {
    let fixture = seeded_prep_vault();
    let policy = PrepPolicy::default();
    let wake = plan_prep_wake(prep_wake_id(&fixture.event_ref), &fixture.event(), policy)
        .expect("wake is planned");
    let job = PrepHomeNodeJob::from_wake(&fixture.event_ref, &wake);

    // Baseline: the live EVENT still agrees with the payload.
    assert!(
        run_due_home_node_prep(&fixture.vault, &job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_some()
    );

    // Stale by payload: a fire instant the live EVENT never implied.
    let stale = PrepHomeNodeJob {
        scheduled_for: job.scheduled_for + 1,
        ..job.clone()
    };
    assert!(
        run_due_home_node_prep(&fixture.vault, &stale, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_none()
    );

    // Stale by reschedule: the EVENT moved, so THIS payload is the old one.
    // The replacement wake carries the same id, which is what lets the host
    // overwrite rather than accumulate.
    put_event(
        &fixture.vault,
        EVENT_SEED,
        EVENT_START + 7_200,
        EVENT_END + 7_200,
    );
    assert!(
        run_due_home_node_prep(&fixture.vault, &job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_none()
    );
    put_event(&fixture.vault, EVENT_SEED, EVENT_START, EVENT_END);
    assert!(
        run_due_home_node_prep(&fixture.vault, &job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_some()
    );

    // Ineligible by cancellation: CAL-00's `calendar.status` is the home that
    // law lives in, and a prep card for a called-off meeting is noise.
    cancel_event(&fixture.vault, 9, fixture.event_ref);
    assert!(
        run_due_home_node_prep(&fixture.vault, &job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_none()
    );

    // Ineligible by attendance: an EVENT the engine can read no attendee row
    // for never arms, however the payload was minted.
    let bare_event = put_event(&fixture.vault, SECOND_EVENT_SEED, EVENT_START, EVENT_END);
    let bare_job = PrepHomeNodeJob {
        event_ref: bare_event.to_hex(),
        scheduled_for: FIRE_AT,
        wake_id: prep_wake_id(&bare_event),
    };
    assert!(
        run_due_home_node_prep(&fixture.vault, &bare_job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_none()
    );

    // Missing EVENT: stale work, not an error the host has to special-case.
    let absent_job = PrepHomeNodeJob {
        event_ref: test_id(0x7E).to_hex(),
        scheduled_for: FIRE_AT,
        wake_id: prep_wake_id(&test_id(0x7E)),
    };
    assert!(
        run_due_home_node_prep(&fixture.vault, &absent_job, FIRE_AT, policy, &copy())
            .expect("due run succeeds")
            .is_none()
    );
}

#[test]
fn lens_uses_caller_supplied_copy_and_contains_source_backing() {
    let fixture = seeded_prep_vault();
    let pack = build_prep_pack(&fixture.vault, &fixture.request(FIRE_AT))
        .expect("build succeeds")
        .expect("the meeting has evidence");
    let copy = copy();
    let lens = render_prep_lens(&pack, &copy).expect("lens renders");
    let rendered = serde_json::to_string(&lens).expect("lens serializes");

    // Every word of chrome on the card is the caller's.
    for supplied in [
        copy.title.as_str(),
        copy.commitment_heading.as_str(),
        copy.thread_heading.as_str(),
        copy.dossier_heading.as_str(),
    ] {
        assert!(
            rendered.contains(supplied),
            "the card must carry the caller's copy {supplied:?}"
        );
    }
    // And none of it is in engine Rust.
    let source = prep_source();
    for supplied in [
        copy.title.as_str(),
        copy.commitment_heading.as_str(),
        copy.thread_heading.as_str(),
        copy.dossier_heading.as_str(),
    ] {
        assert!(!source.contains(supplied));
    }

    // The evidence is the pack's, and every row names its backing vault ids.
    assert!(rendered.contains(COMMITMENT_TEXT));
    assert!(rendered.contains(&fixture.event_ref.to_hex()));
    for backing in [
        fixture.commitment_ref,
        fixture.turn_ref,
        fixture.summary_ref,
    ] {
        assert!(
            rendered.contains(&backing.to_hex()),
            "the card must carry source backing for {}",
            backing.to_hex()
        );
    }

    // Empty caller copy is a caller error, not a silently blank card.
    let blank = PrepLensCopy {
        title: String::new(),
        ..copy
    };
    assert!(render_prep_lens(&pack, &blank).is_err());
}

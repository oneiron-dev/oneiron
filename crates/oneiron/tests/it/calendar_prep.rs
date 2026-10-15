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

use std::path::Path;

use crate::common::entity as test_id;
use oneiron::calendar::prep::{
    DEFAULT_PREP_LEAD_SECS, PrepBuildRequest, PrepEvent, PrepHomeNodeJob, PrepLensCopy, PrepPack,
    PrepPolicy, PrepSectionKind, build_prep_pack, plan_prep_wake, prep_is_eligible, prep_wake_id,
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

/// Fixture seeds. All outside `PINNED_ID_BYTES`.
const EVENT_SEED: u8 = 0x51;
const PERSON_SEED: u8 = 0x53;
const TURN_SEED: u8 = 0x54;
const SUMMARY_SEED: u8 = 0x55;
const LATE_TURN_SEED: u8 = 0x56;

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
    let origin = claim_id(seed, 0xFE);
    let has_origin = vault.get_claim(&origin).expect("origin lookup").is_some();
    let mut fields = vec![(Value::from("name"), Value::from("quarterly review"))];
    if has_origin {
        fields.push((Value::from("origin"), Value::from("native")));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(fields)).expect("encode event");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange { start, end },
            PLANNED_AT,
            &body,
        )
        .expect("put event");
    if !has_origin {
        put_claim(
            vault,
            origin,
            "calendar.origin",
            id,
            Value::from("native"),
            PLANNED_AT,
        );
    }
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
    )
    .expect("claim body");
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
    // `prep` is a directory module, so the guard reads every child: a forbidden
    // primitive must not be smuggled in by adding a new file next to `mod.rs`.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/calendar/prep");
    let mut children = std::fs::read_dir(&dir)
        .expect("read prep module directory")
        .map(|entry| entry.expect("prep module entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect::<Vec<_>>();
    children.sort();
    assert!(!children.is_empty(), "prep module has no Rust children");
    children
        .iter()
        .map(|path| std::fs::read_to_string(path).expect("read prep source"))
        .collect::<Vec<_>>()
        .join("\n")
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

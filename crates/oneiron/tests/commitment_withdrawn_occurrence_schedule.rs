//! FIX 23511 (COMMITMENT-WITHDRAWN-SCHEDULE-HISTORY): a withdrawn occurrence
//! is closed for its schedule, and its series goes on past it.
//!
//! A generic `retract_claim` on a scheduled instance withdraws it (FIX 22383):
//! its claim closes while its promise still says Open. Before the fix the
//! schedule read that promise as an open occurrence, and the withdrawal ran no
//! successor policy, so a quota week holding a withdrawn slot never rolled and
//! an interval series stopped at its withdrawn occurrence, while the series
//! claim stayed Open. A withdrawn occurrence is never minted again.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_withdrawn_occurrence_schedule`.

use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    FulfillmentSource,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, QuotaWindow, Schedule};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance, fulfill_commitment_from,
};
use rmpv::Value;

const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;
const QUOTA_CLOSED_LAST_SERIES: u8 = 0x91;
const QUOTA_WITHDRAWN_LAST_SERIES: u8 = 0x92;
const INTERVAL_SERIES: u8 = 0x93;

/// The zone the quota weeks are counted in (the schedule unit tests' zone).
const TZ: &str = "America/New_York";
/// Monday 16 Nov 2026 00:00 in [`TZ`] (EST, UTC-5).
const WEEK_START: u64 = 1_794_805_200;
/// Monday 23 Nov 2026 00:00 in [`TZ`]: the following week opens.
const NEXT_WEEK_START: u64 = 1_795_410_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
/// The series are written an hour into the week.
const WRITTEN_AT: u64 = WEEK_START + HOUR;
/// The interval series' first occurrence: Monday noon.
const INTERVAL_ANCHOR: u64 = WEEK_START + 12 * HOUR;
const LEAD_SECS: u64 = HOUR;

fn party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn instant(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// The parties a commitment write needs and the engine's MACHINE writers
/// (the projector mints instances as one). Returns the owner's envelope.
fn seed_world(vault: &Vault) -> WriteEnvelope {
    for seed in [OBLIGOR, BENEFICIARY] {
        vault
            .put_entity(
                &party(seed),
                ENTITY_TYPE_PERSON,
                instant(1),
                1,
                b"fix 23511 person",
            )
            .expect("seed person");
    }
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
    WriteEnvelope::new(
        WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fix 23511 fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    )
}

fn open_vault() -> (tempfile::TempDir, Vault, WriteEnvelope) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let envelope = seed_world(&vault);
    (dir, vault, envelope)
}

/// Writes and indexes a series at [`WRITTEN_AT`].
fn put_series(vault: &Vault, envelope: &WriteEnvelope, series: u8, schedule: Schedule) {
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
        party(BENEFICIARY),
        CommitmentContent::new("ring the beneficiary", None).expect("content"),
        CommitmentSchedulePayload::series(schedule, Some(LEAD_SECS))
            .encode()
            .expect("series payload"),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:fix-23511")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    vault
        .put_commitment_series(
            &party(series),
            &record,
            envelope,
            TimeRange {
                start: WEEK_START,
                end: NEXT_WEEK_START + 30 * DAY,
            },
            WRITTEN_AT,
        )
        .expect("series indexes");
}

/// Two slots a week, counted in [`TZ`].
fn two_a_week() -> Schedule {
    Schedule::Quota {
        count: 2,
        window: QuotaWindow::IsoWeek { tz: TZ.to_owned() },
    }
}

/// Runs the projector at `now` and returns what it minted.
fn project(vault: &Vault, now: u64) -> Vec<EntityId> {
    vault
        .reconcile_commitment_schedule(now)
        .expect("projection pass")
        .minted_instances
}

/// The instant a minted instance is owed, from its stored payload.
fn due_at(vault: &Vault, instance: &EntityId) -> u64 {
    let record = vault
        .get_commitment_claim(instance)
        .expect("commitment read")
        .expect("the instance is stored");
    CommitmentSchedulePayload::decode(&record.schedule)
        .expect("instance payload")
        .occurrence
        .expect("an instance names its occurrence")
        .due_at
}

/// The week's two slots, minted by the first pass of the week.
fn this_weeks_slots(vault: &Vault) -> (EntityId, EntityId) {
    let minted = project(vault, WRITTEN_AT + HOUR);
    assert_eq!(minted.len(), 2, "the week's two slots are minted");
    (minted[0], minted[1])
}

fn withdraw(vault: &Vault, instance: &EntityId, at: u64) {
    vault
        .retract_claim(instance, at)
        .expect("the owner withdraws the occurrence");
}

fn fulfil(vault: &Vault, envelope: &WriteEnvelope, instance: &EntityId, at: u64) {
    fulfill_commitment_from(vault, instance, FulfillmentSource::UserDone, envelope, at)
        .expect("the owner marks the occurrence done");
}

#[test]
fn a_quota_week_with_a_withdrawn_slot_rolls_when_its_last_slot_closes() {
    let (_dir, vault, envelope) = open_vault();
    put_series(&vault, &envelope, QUOTA_CLOSED_LAST_SERIES, two_a_week());
    let (withdrawn, kept) = this_weeks_slots(&vault);

    withdraw(&vault, &withdrawn, WEEK_START + DAY);
    fulfil(&vault, &envelope, &kept, WEEK_START + 2 * DAY);

    let next_week = project(&vault, NEXT_WEEK_START + HOUR);
    assert_eq!(
        (
            next_week.len(),
            next_week.contains(&withdrawn) || next_week.contains(&kept)
        ),
        (2, false),
        "every slot of the week is closed (one withdrawn, one fulfilled), so the next week's \
         two slots are minted, and no slot of the closed week is minted again \
         (minted: {next_week:?})"
    );
}

#[test]
fn a_quota_week_rolls_when_its_last_open_slot_is_withdrawn() {
    let (_dir, vault, envelope) = open_vault();
    put_series(&vault, &envelope, QUOTA_WITHDRAWN_LAST_SERIES, two_a_week());
    let (kept, withdrawn) = this_weeks_slots(&vault);

    fulfil(&vault, &envelope, &kept, WEEK_START + DAY);
    withdraw(&vault, &withdrawn, WEEK_START + 2 * DAY);

    let next_week = project(&vault, NEXT_WEEK_START + HOUR);
    assert_eq!(
        (
            next_week.len(),
            next_week.contains(&withdrawn) || next_week.contains(&kept)
        ),
        (2, false),
        "the withdrawal closes the week's last open slot, so the next week's two slots are \
         minted, and no slot of the closed week is minted again (minted: {next_week:?})"
    );
}

#[test]
fn an_interval_series_goes_on_past_a_withdrawn_occurrence() {
    let (_dir, vault, envelope) = open_vault();
    put_series(
        &vault,
        &envelope,
        INTERVAL_SERIES,
        Schedule::Interval {
            period: DAY,
            anchor: INTERVAL_ANCHOR,
        },
    );
    let first = project(&vault, INTERVAL_ANCHOR - LEAD_SECS);
    assert_eq!(first.len(), 1, "the first occurrence is minted");
    let withdrawn = first[0];

    withdraw(&vault, &withdrawn, INTERVAL_ANCHOR - LEAD_SECS / 2);

    let next = project(&vault, INTERVAL_ANCHOR + DAY - LEAD_SECS);
    let next_due: Vec<u64> = next.iter().map(|id| due_at(&vault, id)).collect();
    assert_eq!(
        (next_due, next.contains(&withdrawn)),
        (vec![INTERVAL_ANCHOR + DAY], false),
        "the occurrence one period after the withdrawn one is minted, and the withdrawn one \
         is not minted again (minted: {next:?})"
    );
    assert!(
        project(&vault, INTERVAL_ANCHOR + DAY).is_empty(),
        "a later pass mints nothing more"
    );
}

//! Acceptance tests for CMT-2 (ONE-1539): the pure schedule evaluator, the
//! strict payload codec, the durable due index, and the projection/close hooks.
//!
//! Every instant in this file is a literal. The whole point of the layer is
//! that a commitment's clock belongs to the OWNER, so a test that read the host
//! clock — or the host's zone — would prove nothing about the thing under test.
//! The ISO-week constants below were derived from the IANA rules the calendar
//! border already speaks and are pinned here so a DST regression shows up as a
//! failing equality rather than as a plausible-looking week.

use rmpv::Value;

use super::*;
use crate::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStrength, commitment_claim_candidate,
};
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::store::{
    COMMITMENT_DUE_INDEX_VERSION, commitment_due_primary_key, decode_commitment_due_row,
};
use crate::vault::Vault;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
    WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
};

/// The owner's zone for every quota fixture: it has both DST transitions and a
/// Monday-midnight that never lands in a gap.
const TZ_NY: &str = "America/New_York";
/// A zone with no DST at all — the control for the 167/168/169-hour weeks.
const TZ_TOKYO: &str = "Asia/Tokyo";
/// The other DST zone the calendar border's own fixtures already cover.
const TZ_LONDON: &str = "Europe/London";

/// `2026-03-02T05:00:00Z` .. `2026-03-08T03:59:59Z` — the New York ISO week
/// that springs forward on 2026-03-08. 167 hours long.
const NY_SPRING_WEEK: TimeRange = TimeRange {
    start: 1_772_427_600,
    end: 1_773_028_799,
};
/// The week after [`NY_SPRING_WEEK`]: an ordinary 168-hour week.
const NY_WEEK_2: TimeRange = TimeRange {
    start: 1_773_028_800,
    end: 1_773_633_599,
};
/// The week after [`NY_WEEK_2`]. Never back-filled by a late close.
const NY_WEEK_3: TimeRange = TimeRange {
    start: 1_773_633_600,
    end: 1_774_238_399,
};
/// The week three rollovers past [`NY_SPRING_WEEK`], where a very late close
/// lands.
const NY_WEEK_4: TimeRange = TimeRange {
    start: 1_774_238_400,
    end: 1_774_843_199,
};
/// `2026-10-26T04:00:00Z` .. `2026-11-02T04:59:59Z` — the New York ISO week
/// that falls back on 2026-11-01. 169 hours long.
const NY_FALL_WEEK: TimeRange = TimeRange {
    start: 1_792_987_200,
    end: 1_793_595_599,
};
/// The Tokyo ISO week covering the same civil days as [`NY_SPRING_WEEK`].
const TOKYO_WEEK: TimeRange = TimeRange {
    start: 1_772_377_200,
    end: 1_772_981_999,
};
/// The London ISO week that springs forward on 2026-03-29. 167 hours long.
const LONDON_SPRING_WEEK: TimeRange = TimeRange {
    start: 1_774_224_000,
    end: 1_774_825_199,
};

const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), vault_config())?;
    Ok((dir, vault))
}

const fn time(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

/// The valid-time a series claim covers. Wide on purpose: the due index, not
/// the claim's validity, is what decides when an occurrence is owed.
fn span(now: u64) -> TimeRange {
    time(now, now.saturating_add(400 * DAY))
}

/// Seeds the two human parties AND the projector's pinned System actor.
///
/// The last one is load-bearing rather than decorative: the claim-candidate
/// door resolves `envelope.actor()` against a stored entity and validates its
/// class, so a vault that expects the projector to mint anything must carry the
/// derived actor as a MACHINE entity.
fn seed_world(vault: &Vault) -> Result<(EntityId, EntityId)> {
    let obligor = crate::test_util::entity(0x71);
    let beneficiary = crate::test_util::entity(0x72);
    for id in [obligor, beneficiary] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
    }
    vault.put_entity(
        &commitment_projection_actor().entity_ref(),
        ENTITY_TYPE_MACHINE,
        time(1, 1),
        1,
        b"commitment projector",
    )?;
    Ok((obligor, beneficiary))
}

fn user_envelope(actor: EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("test commitment write"))?,
        ClaimApprovalStatus::Auto,
    ))
}

fn encode_series(schedule: Schedule, lead: Option<u64>) -> Result<Value> {
    Ok(CommitmentSchedulePayload::series(schedule, lead).encode()?)
}

fn series_record(
    obligor: EntityId,
    beneficiary: EntityId,
    schedule: Value,
    strength: CommitmentStrength,
) -> Result<CommitmentRecord> {
    record_with_text(obligor, beneficiary, schedule, strength, "file the report")
}

fn record_with_text(
    obligor: EntityId,
    beneficiary: EntityId,
    schedule: Value,
    strength: CommitmentStrength,
    text: &str,
) -> Result<CommitmentRecord> {
    CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        beneficiary,
        CommitmentContent::new(text, Some("payload:doc-1".to_owned()))?,
        schedule,
        strength,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:turn-7")?,
    )
}

/// One party pair plus its envelope, so a test body reads as schedule work.
struct Parties {
    obligor: EntityId,
    beneficiary: EntityId,
    envelope: WriteEnvelope,
}

fn parties(vault: &Vault) -> Result<Parties> {
    let (obligor, beneficiary) = seed_world(vault)?;
    Ok(Parties {
        obligor,
        beneficiary,
        envelope: user_envelope(obligor)?,
    })
}

impl Parties {
    fn record(&self, schedule: Value) -> Result<CommitmentRecord> {
        series_record(
            self.obligor,
            self.beneficiary,
            schedule,
            CommitmentStrength::Commitment,
        )
    }

    fn put_series(
        &self,
        vault: &Vault,
        id: &EntityId,
        schedule: Schedule,
        lead: Option<u64>,
        now: u64,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        let record = self.record(encode_series(schedule, lead)?)?;
        vault.put_commitment_series(id, &record, &self.envelope, span(now), now)
    }
}

fn history_entry(due_at: u64, status: CommitmentStatus) -> ScheduleHistoryEntry {
    ScheduleHistoryEntry {
        instance_ref: crate::test_util::entity(0x33),
        due_at,
        window: time(due_at, due_at),
        ordinal: 0,
        status,
    }
}

fn quota_history(
    window: TimeRange,
    ordinal: u32,
    status: CommitmentStatus,
) -> ScheduleHistoryEntry {
    ScheduleHistoryEntry {
        instance_ref: crate::test_util::entity(0x34_u8.saturating_add(
            u8::try_from(ordinal).expect("test quota ordinals stay inside a byte"),
        )),
        due_at: window.end,
        window,
        ordinal,
        status,
    }
}

fn rows(vault: &Vault) -> Result<Vec<CommitmentDueEntry>> {
    vault.commitment_entries_through(u64::MAX)
}

fn rows_in_phase(vault: &Vault, phase: CommitmentDuePhase) -> Result<Vec<CommitmentDueEntry>> {
    Ok(rows(vault)?
        .into_iter()
        .filter(|entry| entry.phase == phase)
        .collect())
}

fn instance_rows(vault: &Vault, instance: &EntityId) -> Result<Vec<CommitmentDueEntry>> {
    Ok(rows(vault)?
        .into_iter()
        .filter(|entry| entry.instance_ref == Some(*instance))
        .collect())
}

/// The durable series-membership rows — the evaluator's `history`. Read
/// directly because the point of several tests is that membership OUTLIVES the
/// timed rows a close consumes.
fn members(vault: &Vault, series: &EntityId) -> Result<Vec<(CommitmentOccurrence, EntityId)>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .commitment_due_series_members_in_txn(&rtxn, series)
}

/// Writes a terminal status onto an existing commitment claim WITHOUT calling
/// the close hook.
///
/// Two jobs. CMT-1 ships fulfil/release/supersede verbs but no `lapse` verb, so
/// a lapsed instance can only be produced this way; and the crash-repair cases
/// need exactly this shape — the status write landed, the due rows did not
/// move.
fn set_status(
    vault: &Vault,
    id: &EntityId,
    status: CommitmentStatus,
    envelope: &WriteEnvelope,
    at: u64,
) -> Result<()> {
    let mut record = vault
        .get_commitment_claim(id)?
        .expect("commitment claim exists");
    record.status = status;
    let body = vault.get_claim(id)?.expect("claim body");
    let valid = time(
        body.valid_from.unwrap_or(at),
        body.valid_to
            .unwrap_or(at)
            .max(body.valid_from.unwrap_or(at)),
    );
    let candidate =
        commitment_claim_candidate(&record)?.with_validity(Some(valid.start), Some(valid.end));
    vault
        .batch()
        .claim_candidate(id, candidate, envelope, valid, at)
        .commit()
}

/// Drives one instance to a terminal status through whichever door owns it,
/// then runs the close hook and reports its successors.
fn close(
    vault: &Vault,
    instance: &EntityId,
    outcome: CommitmentInstanceOutcome,
    envelope: &WriteEnvelope,
    at: u64,
) -> ScheduleResult<Vec<EntityId>> {
    match outcome {
        CommitmentInstanceOutcome::Fulfilled => {
            vault.fulfill_commitment(instance, envelope, at)?;
        }
        CommitmentInstanceOutcome::Released => {
            vault.release_commitment(instance, envelope, at)?;
        }
        CommitmentInstanceOutcome::Superseded => {
            vault.supersede_commitment(instance, envelope, at)?;
        }
        // No CMT-1 verb writes `lapsed`; the hook still refuses to invent it.
        CommitmentInstanceOutcome::Lapsed => {
            set_status(vault, instance, CommitmentStatus::Lapsed, envelope, at)?;
        }
    }
    vault.on_instance_closed(instance, outcome, envelope, at)
}

fn evidence_entry<'a>(evidence: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = evidence else {
        panic!("expected write envelope evidence map, got {evidence:?}");
    };
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .unwrap_or_else(|| panic!("missing evidence key {key:?}"))
}

/// The on-disk value bytes for one due row: `version ‖ due_at ‖ window.start ‖
/// window.end ‖ ordinal`, all big-endian.
fn raw_due_value(occurrence: &CommitmentOccurrence) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + 8 + 8 + 8 + 4);
    value.push(COMMITMENT_DUE_INDEX_VERSION);
    value.extend_from_slice(&occurrence.due_at.to_be_bytes());
    value.extend_from_slice(&occurrence.window.start.to_be_bytes());
    value.extend_from_slice(&occurrence.window.end.to_be_bytes());
    value.extend_from_slice(&occurrence.ordinal.to_be_bytes());
    value
}

fn quota(count: u32, tz: &str) -> Schedule {
    Schedule::Quota {
        count,
        window: QuotaWindow::IsoWeek { tz: tz.to_owned() },
    }
}

/// The deterministic ids of one quota window's slots, in ordinal order.
fn slot_ids(series: &EntityId, window: TimeRange, count: u32) -> Vec<EntityId> {
    (0..count)
        .map(|ordinal| {
            let occurrence = CommitmentOccurrence::new(window.end, window, ordinal)
                .expect("quota slot occurrence is well formed");
            commitment_instance_id(series, &occurrence)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Once
// ---------------------------------------------------------------------------

#[test]
fn once_due_is_single_use() -> Result<()> {
    // PURE: an overdue single promise is still owed.
    assert_eq!(next_due(&Schedule::Once { due: 500 }, 100, &[])?, Some(500));
    assert_eq!(
        next_due(&Schedule::Once { due: 500 }, 9_000, &[])?,
        Some(500),
        "a Once that has already passed is still owed, never silently dropped"
    );
    // Any materialized occurrence — in any status — ends the series.
    for status in [
        CommitmentStatus::Open,
        CommitmentStatus::Fulfilled,
        CommitmentStatus::Lapsed,
        CommitmentStatus::Released,
        CommitmentStatus::Superseded,
    ] {
        assert_eq!(
            next_due(
                &Schedule::Once { due: 500 },
                100,
                &[history_entry(500, status)]
            )?,
            None,
            "Once is single use regardless of how its one occurrence ended"
        );
    }

    // DURABLE: the mint path fires exactly once.
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x81);
    let outcome =
        parties.put_series(&vault, &series, Schedule::Once { due: 500 }, Some(100), 10)?;
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: 400,
            next_due: 500,
        }
    );

    let first = vault.reconcile_commitment_schedule(400)?;
    assert_eq!(first.projected_series, 1);
    assert_eq!(first.minted_instances.len(), 1);
    assert!(first.already_present_instances.is_empty());
    let instance = first.minted_instances[0];
    assert_eq!(
        instance,
        commitment_instance_id(&series, &CommitmentOccurrence::new(500, time(500, 500), 0)?),
        "the minted id is derived from the series and the occurrence, nothing else"
    );

    // The Project row was spent by the first pass, so a second reconcile has
    // nothing to consume and mints nothing.
    let second = vault.reconcile_commitment_schedule(600)?;
    assert_eq!(second, CommitmentProjectionReport::default());
    assert_eq!(members(&vault, &series)?.len(), 1, "never duplicated");

    // Even a Project row replanted by a crash-resumed writer cannot produce a
    // second occurrence: the evaluator reads the membership row as history and
    // answers `None`.
    let replanted = CommitmentDueEntry {
        at: 400,
        phase: CommitmentDuePhase::Project,
        series_ref: series,
        instance_ref: None,
        occurrence: CommitmentOccurrence::new(500, time(500, 500), 0)?,
    };
    vault.with_write_txn(|wtxn| vault.store.commitment_due_put_in_txn(wtxn, &replanted))?;
    let third = vault.reconcile_commitment_schedule(600)?;
    assert_eq!(third.projected_series, 1);
    assert!(third.minted_instances.is_empty());
    assert_eq!(members(&vault, &series)?.len(), 1);
    assert!(vault.get_commitment_claim(&instance)?.is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Interval
// ---------------------------------------------------------------------------

#[test]
fn interval_retainer_cycle_anchors_successor_to_last_due() -> Result<()> {
    let fortnight = 14 * DAY;
    let schedule = Schedule::Interval {
        period: fortnight,
        anchor: 1_000_000,
    };

    // PURE: with no history the answer is the first grid point at or after now.
    assert_eq!(next_due(&schedule, 10, &[])?, Some(1_000_000));
    assert_eq!(next_due(&schedule, 1_000_000, &[])?, Some(1_000_000));
    assert_eq!(
        next_due(&schedule, 1_000_001, &[])?,
        Some(1_000_000 + fortnight),
        "ceil-division onto the anchor grid, never a walk"
    );
    // With history the successor hangs off the LAST due instant.
    assert_eq!(
        next_due(
            &schedule,
            9_999_999,
            &[history_entry(
                1_000_000 + fortnight,
                CommitmentStatus::Fulfilled
            )]
        )?,
        Some(1_000_000 + 2 * fortnight)
    );
    // A stored occurrence off the grid is refused, never quietly re-based.
    let drifted = next_due(
        &schedule,
        10,
        &[history_entry(
            1_000_000 + fortnight + 37,
            CommitmentStatus::Fulfilled,
        )],
    )
    .expect_err("a non-congruent occurrence must be refused");
    assert!(matches!(drifted, ScheduleError::Invalid(reason)
            if reason == "interval occurrence is not on the schedule grid"));

    // DURABLE: every terminal outcome earns exactly one successor, on the grid.
    for (index, outcome) in [
        CommitmentInstanceOutcome::Fulfilled,
        CommitmentInstanceOutcome::Lapsed,
        CommitmentInstanceOutcome::Released,
        CommitmentInstanceOutcome::Superseded,
    ]
    .into_iter()
    .enumerate()
    {
        let (_dir, vault) = temp_vault()?;
        let parties = parties(&vault)?;
        let series = crate::test_util::entity(
            0x90_u8.saturating_add(u8::try_from(index).expect("four outcomes")),
        );
        parties.put_series(&vault, &series, schedule.clone(), Some(DAY), 10)?;
        let minted = vault
            .reconcile_commitment_schedule(1_000_000 - DAY)?
            .minted_instances;
        assert_eq!(minted.len(), 1);
        let first = minted[0];

        // The close lands LATE. The grid must not move with it.
        let late = 1_000_000 + 3 * DAY;
        let successors = close(&vault, &first, outcome, &parties.envelope, late)?;
        assert_eq!(successors.len(), 1, "exactly one successor per close");
        let expected = commitment_instance_id(
            &series,
            &CommitmentOccurrence::new(
                1_000_000 + fortnight,
                time(1_000_000 + fortnight, 1_000_000 + fortnight),
                0,
            )?,
        );
        assert_eq!(
            successors[0], expected,
            "the successor is prior_due + period, never close_time + period"
        );

        // Retrying the hook reports the same successor and writes nothing new.
        let retry = vault.on_instance_closed(&first, outcome, &parties.envelope, late + 99)?;
        assert_eq!(retry, successors);
        assert_eq!(
            members(&vault, &series)?.len(),
            2,
            "a retried close never duplicates the successor"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. ISO weeks across DST
// ---------------------------------------------------------------------------

#[test]
fn quota_iso_week_uses_user_timezone_across_dst() -> Result<()> {
    // Spring forward: the week loses an hour but still runs local Monday to
    // local Monday.
    let inside_spring = NY_SPRING_WEEK.start + 3 * DAY;
    assert_eq!(iso_week_window(inside_spring, TZ_NY)?, NY_SPRING_WEEK);
    assert_eq!(NY_SPRING_WEEK.end + 1 - NY_SPRING_WEEK.start, 167 * HOUR);
    // Every instant in the window agrees on the window, including its borders.
    assert_eq!(
        iso_week_window(NY_SPRING_WEEK.start, TZ_NY)?,
        NY_SPRING_WEEK
    );
    assert_eq!(iso_week_window(NY_SPRING_WEEK.end, TZ_NY)?, NY_SPRING_WEEK);
    assert_eq!(
        iso_week_window(NY_SPRING_WEEK.end + 1, TZ_NY)?,
        NY_WEEK_2,
        "the inclusive end is one second before the next local Monday"
    );

    // Fall back: the same construction yields a 169-hour week.
    let inside_fall = NY_FALL_WEEK.start + 3 * DAY;
    assert_eq!(iso_week_window(inside_fall, TZ_NY)?, NY_FALL_WEEK);
    assert_eq!(NY_FALL_WEEK.end + 1 - NY_FALL_WEEK.start, 169 * HOUR);

    // A zone without DST is the 168-hour control, and an ordinary New York week
    // is 168 hours too — the shear is the transition, not the zone.
    assert_eq!(iso_week_window(inside_spring, TZ_TOKYO)?, TOKYO_WEEK);
    assert_eq!(TOKYO_WEEK.end + 1 - TOKYO_WEEK.start, 168 * HOUR);
    assert_eq!(NY_WEEK_2.end + 1 - NY_WEEK_2.start, 168 * HOUR);

    // London's own spring-forward week, so the property is not a New York
    // accident.
    assert_eq!(
        iso_week_window(LONDON_SPRING_WEEK.start + DAY, TZ_LONDON)?,
        LONDON_SPRING_WEEK
    );
    assert_eq!(
        LONDON_SPRING_WEEK.end + 1 - LONDON_SPRING_WEEK.start,
        167 * HOUR
    );

    // NEVER `now / 604_800`: that stride starts on a Thursday in UTC and
    // ignores the owner's zone entirely.
    for (at, tz) in [
        (inside_spring, TZ_NY),
        (inside_fall, TZ_NY),
        (inside_spring, TZ_TOKYO),
    ] {
        let epoch_stride = at - at % 604_800;
        assert_ne!(iso_week_window(at, tz)?.start, epoch_stride);
        assert_ne!(iso_week_window(at, tz)?.end, at);
    }

    // An unknown zone is refused at the calendar border, never defaulted to UTC.
    let unknown = iso_week_window(inside_spring, "Mars/Olympus").expect_err("unknown zone");
    assert!(matches!(unknown, ScheduleError::Calendar(_)));
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Rrule
// ---------------------------------------------------------------------------

#[test]
fn rrule_reports_cal_expand_window_route() -> Result<()> {
    let schedule = Schedule::Rrule {
        rrule_string: "FREQ=WEEKLY;BYDAY=MO".to_owned(),
        tz: TZ_LONDON.to_owned(),
    };

    // It DECODES. v1 refuses to evaluate it; it never refuses to store it.
    let encoded = encode_series(schedule.clone(), Some(600))?;
    let decoded = CommitmentSchedulePayload::decode(&encoded)?;
    assert_eq!(decoded.schedule, schedule);
    assert!(decoded.is_series());
    assert_eq!(decoded.lead_seconds(), 600);

    let refusal = next_due(&schedule, 10, &[]).expect_err("rrule never evaluates in v1");
    assert!(
        matches!(refusal, ScheduleError::RruleNotImplemented { route } if route == CAL_RRULE_ROUTE)
    );
    assert_eq!(CAL_RRULE_ROUTE, "oneiron::calendar::expand_window");

    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x82);
    let outcome = parties.put_series(&vault, &series, schedule, Some(600), 10)?;
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::StoredRrule {
            route: CAL_RRULE_ROUTE
        }
    );

    // The claim committed durably...
    let stored = vault
        .get_commitment_claim(&series)?
        .expect("rrule series claim is stored verbatim");
    assert_eq!(stored.status, CommitmentStatus::Open);
    assert!(CommitmentSchedulePayload::decode(&stored.schedule)?.is_series());
    // ...and produced ZERO due rows.
    assert_eq!(vault.commitment_due_index_snapshot()?.next_due_at(), None);
    assert!(rows(&vault)?.is_empty());
    assert_eq!(
        vault.reconcile_commitment_schedule(u64::MAX / 2)?,
        CommitmentProjectionReport::default()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Quota
// ---------------------------------------------------------------------------

/// Puts a `count`-per-ISO-week quota series and materializes its first window.
fn mint_quota_window(
    vault: &Vault,
    parties: &Parties,
    series: &EntityId,
    count: u32,
    now: u64,
) -> ScheduleResult<Vec<EntityId>> {
    parties.put_series(vault, series, quota(count, TZ_NY), Some(HOUR), now)?;
    let report = vault.reconcile_commitment_schedule(now)?;
    assert_eq!(report.projected_series, 1);
    assert!(report.already_present_instances.is_empty());
    Ok(report.minted_instances)
}

#[test]
fn quota_three_per_iso_week_two_fulfilled_yields_one_lapse_and_next_window() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x83);
    let now = NY_SPRING_WEEK.start + HOUR;

    // The Project row sits at the target window's LOCAL Monday 00:00.
    let outcome = parties.put_series(&vault, &series, quota(3, TZ_NY), Some(HOUR), now)?;
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: NY_SPRING_WEEK.start,
            next_due: NY_SPRING_WEEK.end,
        }
    );

    // Three slots, one shared due instant (the window's inclusive end),
    // ordinals 0..2.
    let minted = vault.reconcile_commitment_schedule(now)?.minted_instances;
    assert_eq!(minted, slot_ids(&series, NY_SPRING_WEEK, 3));
    for (ordinal, id) in minted.iter().enumerate() {
        let record = vault.get_commitment_claim(id)?.expect("slot claim");
        let payload = CommitmentSchedulePayload::decode(&record.schedule)?;
        let occurrence = payload.occurrence.expect("slot payload is an INSTANCE");
        assert_eq!(payload.series_ref, Some(series));
        assert_eq!(occurrence.due_at, NY_SPRING_WEEK.end);
        assert_eq!(occurrence.window, NY_SPRING_WEEK);
        assert_eq!(
            occurrence.ordinal,
            u32::try_from(ordinal).expect("three ordinals")
        );
    }

    // Two fulfilled INSIDE the window: the window still owes a slot, so nothing
    // rolls and no replacement is minted for the completed ones.
    let inside = NY_SPRING_WEEK.start + 2 * DAY;
    for id in &minted[..2] {
        assert!(
            close(
                &vault,
                id,
                CommitmentInstanceOutcome::Fulfilled,
                &parties.envelope,
                inside,
            )?
            .is_empty(),
            "a quota never rolls per completion"
        );
    }

    // The one open slot becomes an overdue candidate only once its LifecycleDue
    // instant is strictly in the past.
    assert!(
        vault
            .overdue_commitment_instances(NY_SPRING_WEEK.end)?
            .is_empty(),
        "at == now is excluded"
    );
    assert_eq!(
        vault.overdue_commitment_instances(NY_SPRING_WEEK.end + 1)?,
        vec![minted[2]]
    );

    // Lapse it after the local rollover instant: the quota skips forward to the
    // week the close actually happened in.
    let rollover_at = NY_SPRING_WEEK.end + 1;
    let successors = close(
        &vault,
        &minted[2],
        CommitmentInstanceOutcome::Lapsed,
        &parties.envelope,
        rollover_at,
    )?;
    assert_eq!(successors, slot_ids(&series, NY_WEEK_2, 3));
    for id in &successors {
        let record = vault.get_commitment_claim(id)?.expect("fresh slot claim");
        assert_eq!(record.status, CommitmentStatus::Open);
        let occurrence = CommitmentSchedulePayload::decode(&record.schedule)?
            .occurrence
            .expect("fresh slot is an INSTANCE");
        assert_eq!(occurrence.window, NY_WEEK_2);
        assert_eq!(occurrence.due_at, NY_WEEK_2.end);
    }

    // Idempotent on repeat: the same three ids come back, nothing is re-minted.
    let repeat = vault.on_instance_closed(
        &minted[2],
        CommitmentInstanceOutcome::Lapsed,
        &parties.envelope,
        rollover_at + 5,
    )?;
    assert_eq!(repeat, successors);
    assert_eq!(members(&vault, &series)?.len(), 6);

    // SECOND CASE: a very late close, and the non-fulfilment outcomes.
    quota_late_close_skips_every_missed_week()
}

/// The other half of the quota story: closing the last slot of a window three
/// weeks after it ended reopens the quota in the week the CLOSE happened in,
/// and every week in between stays empty forever.
fn quota_late_close_skips_every_missed_week() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x84);
    let now = NY_SPRING_WEEK.start + HOUR;
    let minted = mint_quota_window(&vault, &parties, &series, 3, now)?;
    assert_eq!(minted.len(), 3);

    // Released and superseded close their slots WITHOUT counting as
    // completions, and neither earns a replacement inside the window.
    assert!(
        !CommitmentInstanceOutcome::Released.completes_slot()
            && !CommitmentInstanceOutcome::Superseded.completes_slot()
            && !CommitmentInstanceOutcome::Lapsed.completes_slot()
            && CommitmentInstanceOutcome::Fulfilled.completes_slot()
    );
    let inside = NY_SPRING_WEEK.start + 2 * DAY;
    for (id, outcome) in [
        (minted[0], CommitmentInstanceOutcome::Released),
        (minted[1], CommitmentInstanceOutcome::Superseded),
    ] {
        assert!(close(&vault, &id, outcome, &parties.envelope, inside)?.is_empty());
        assert!(instance_rows(&vault, &id)?.is_empty(), "slot rows closed");
    }

    // The final slot closes THREE weeks late. The quota reopens in the week the
    // close happened in — the skipped weeks are never back-filled.
    let very_late = NY_WEEK_4.end;
    let successors = close(
        &vault,
        &minted[2],
        CommitmentInstanceOutcome::Fulfilled,
        &parties.envelope,
        very_late,
    )?;
    assert_eq!(successors, slot_ids(&series, NY_WEEK_4, 3));

    let windows: Vec<u64> = members(&vault, &series)?
        .into_iter()
        .map(|(occurrence, _)| occurrence.window.start)
        .collect();
    for skipped in [NY_WEEK_2, NY_WEEK_3] {
        assert!(
            !windows.contains(&skipped.start),
            "no slot may exist for a week the owner never saw"
        );
    }
    assert_eq!(
        windows
            .iter()
            .filter(|start| **start == NY_WEEK_4.start)
            .count(),
        3,
        "exactly `count` fresh slots in the close-hook's own ISO week"
    );

    // PURE cross-check: the evaluator rolls exactly one week when every slot of
    // a window is terminal, and stays put while any slot is open.
    let schedule = quota(3, TZ_NY);
    let all_terminal = [
        quota_history(NY_SPRING_WEEK, 0, CommitmentStatus::Fulfilled),
        quota_history(NY_SPRING_WEEK, 1, CommitmentStatus::Released),
        quota_history(NY_SPRING_WEEK, 2, CommitmentStatus::Lapsed),
    ];
    assert_eq!(
        next_due(&schedule, NY_SPRING_WEEK.start + DAY, &all_terminal)?,
        Some(NY_WEEK_2.end)
    );
    let one_open = [
        quota_history(NY_SPRING_WEEK, 0, CommitmentStatus::Fulfilled),
        quota_history(NY_SPRING_WEEK, 1, CommitmentStatus::Fulfilled),
        quota_history(NY_SPRING_WEEK, 2, CommitmentStatus::Open),
    ];
    assert_eq!(
        next_due(&schedule, NY_SPRING_WEEK.start + DAY, &one_open)?,
        Some(NY_SPRING_WEEK.end)
    );
    // The count bound is load-bearing: one window's worth of slots is one
    // transaction.
    assert!(validate_quota_count(0).is_err());
    assert!(validate_quota_count(COMMITMENT_QUOTA_MAX_COUNT).is_ok());
    assert!(validate_quota_count(COMMITMENT_QUOTA_MAX_COUNT + 1).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Series edit
// ---------------------------------------------------------------------------

#[test]
fn series_edit_supersedes_series_without_killing_instances() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let old = crate::test_util::entity(0x85);
    let new = crate::test_util::entity(0x86);
    let schedule = Schedule::Interval {
        period: 7 * DAY,
        anchor: 1_000_000,
    };

    parties.put_series(&vault, &old, schedule, Some(DAY), 10)?;
    let instance = vault
        .reconcile_commitment_schedule(1_000_000 - DAY)?
        .minted_instances[0];
    // A second, still-pending Project row exists for the old series only after
    // a close; what matters here is the edit path, so index the replacement.
    let edited = Schedule::Interval {
        period: 30 * DAY,
        anchor: 1_000_000,
    };
    let record = parties.record(encode_series(edited, Some(DAY))?)?;
    let outcome = vault.supersede_commitment_series(
        &new,
        &old,
        &record,
        &parties.envelope,
        span(1_000_100),
        1_000_100,
    )?;
    assert!(matches!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed { .. }
    ));

    // The canonical lifecycle edge is new -> old, and only that direction.
    assert!(vault.edge_exists(&new, EdgeKind::Supersedes, &old)?);
    assert!(!vault.edge_exists(&old, EdgeKind::Supersedes, &new)?);
    assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);

    // The old series' pending projection died with the old head; the
    // replacement owns the only Project row.
    let project = rows_in_phase(&vault, CommitmentDuePhase::Project)?;
    assert_eq!(project.len(), 1);
    assert_eq!(project[0].series_ref, new);

    // The already-minted occurrence survives the edit and is still readable.
    let stored = vault
        .get_commitment_claim(&instance)?
        .expect("minted instance outlives the series edit");
    assert_eq!(stored.status, CommitmentStatus::Open);

    // Closing it cannot mint a successor: the series it belongs to is gone.
    let successors = close(
        &vault,
        &instance,
        CommitmentInstanceOutcome::Fulfilled,
        &parties.envelope,
        1_000_200,
    )?;
    assert!(
        successors.is_empty(),
        "closing an instance of a superseded series must not revive it"
    );
    assert_eq!(members(&vault, &old)?.len(), 1);
    assert!(members(&vault, &new)?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Phase rows
// ---------------------------------------------------------------------------

#[test]
fn due_index_projects_at_lead_and_removes_on_close() -> Result<()> {
    let (dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let once = crate::test_util::entity(0x87);
    let interval = crate::test_util::entity(0x88);
    let lead = 6 * HOUR;

    parties.put_series(
        &vault,
        &once,
        Schedule::Once { due: 900_000 },
        Some(lead),
        10,
    )?;
    parties.put_series(
        &vault,
        &interval,
        Schedule::Interval {
            period: 7 * DAY,
            anchor: 800_000,
        },
        Some(lead),
        10,
    )?;
    let project: Vec<u64> = rows_in_phase(&vault, CommitmentDuePhase::Project)?
        .into_iter()
        .map(|entry| entry.at)
        .collect();
    assert_eq!(project, vec![800_000 - lead, 900_000 - lead]);

    let instance = vault
        .reconcile_commitment_schedule(800_000 - lead)?
        .minted_instances[0];
    let phases: Vec<(CommitmentDuePhase, u64)> = instance_rows(&vault, &instance)?
        .into_iter()
        .map(|entry| (entry.phase, entry.at))
        .collect();
    assert_eq!(
        phases,
        vec![
            (CommitmentDuePhase::Lead, 800_000 - lead),
            (CommitmentDuePhase::Due, 800_000),
            (CommitmentDuePhase::LifecycleDue, 800_000),
        ]
    );

    close(
        &vault,
        &instance,
        CommitmentInstanceOutcome::Fulfilled,
        &parties.envelope,
        800_100,
    )?;
    assert!(
        instance_rows(&vault, &instance)?.is_empty(),
        "a close removes every active phase row for the occurrence"
    );
    // The successor of an interval takes its place; membership keeps BOTH.
    assert_eq!(members(&vault, &interval)?.len(), 2);
    let snapshot = vault.commitment_due_index_snapshot()?;
    assert_eq!(
        snapshot.phase_minimum(CommitmentDuePhase::Lead),
        Some(800_000 + 7 * DAY - lead)
    );

    // The membership row is durable, not a cache of live phase rows.
    drop(vault);
    let vault = Vault::open(dir.path(), vault_config())?;
    let reopened = members(&vault, &interval)?;
    assert_eq!(reopened.len(), 2);
    assert!(
        reopened
            .iter()
            .any(|(occurrence, id)| *id == instance && occurrence.due_at == 800_000),
        "a closed occurrence is still an occurrence after a reopen"
    );
    assert!(instance_rows(&vault, &instance)?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Quota projection instant
// ---------------------------------------------------------------------------

#[test]
fn quota_projects_at_local_window_start() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x89);
    let lead = 5 * HOUR;
    let now = NY_SPRING_WEEK.start + HOUR;

    // INITIAL: the Project row is the window's local Monday 00:00, NOT
    // `due_at - lead`.
    let outcome = parties.put_series(&vault, &series, quota(3, TZ_NY), Some(lead), now)?;
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: NY_SPRING_WEEK.start,
            next_due: NY_SPRING_WEEK.end,
        }
    );
    assert_ne!(NY_SPRING_WEEK.start, NY_SPRING_WEEK.end - lead);

    let minted = vault.reconcile_commitment_schedule(now)?.minted_instances;
    assert_eq!(minted.len(), 3);

    // ROLLOVER: every slot closes INSIDE the window, so the next week is
    // PROJECTED (not minted early) and its row sits at the next local Monday.
    let inside = NY_SPRING_WEEK.start + 3 * DAY;
    for (index, id) in minted.iter().enumerate() {
        let successors = close(
            &vault,
            id,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            inside,
        )?;
        assert!(
            successors.is_empty(),
            "slot {index} must not mint the next window early"
        );
    }
    let project = rows_in_phase(&vault, CommitmentDuePhase::Project)?;
    assert_eq!(project.len(), 1);
    assert_eq!(project[0].at, NY_WEEK_2.start);
    assert_eq!(project[0].series_ref, series);
    assert_eq!(project[0].occurrence.window, NY_WEEK_2);
    assert_eq!(project[0].occurrence.due_at, NY_WEEK_2.end);
    assert_ne!(project[0].at, NY_WEEK_2.end - lead);

    // And the projected week materializes on time, not before.
    assert!(
        vault
            .reconcile_commitment_schedule(NY_WEEK_2.start - 1)?
            .minted_instances
            .is_empty()
    );
    assert_eq!(
        vault
            .reconcile_commitment_schedule(NY_WEEK_2.start)?
            .minted_instances,
        slot_ids(&series, NY_WEEK_2, 3)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 9 & 10. Lead arithmetic
// ---------------------------------------------------------------------------

#[test]
fn lead_exceeding_due_projects_immediately() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let once = crate::test_util::entity(0x8a);
    let interval = crate::test_util::entity(0x8b);
    let quota_series = crate::test_util::entity(0x8c);

    // A lead longer than the due instant's distance from the epoch means
    // "visible immediately" — saturating, never an overflow refusal.
    for (id, schedule, due) in [
        (once, Schedule::Once { due: 500 }, 500),
        (
            interval,
            Schedule::Interval {
                period: 300,
                anchor: 600,
            },
            600,
        ),
    ] {
        let outcome = parties.put_series(&vault, &id, schedule, Some(u64::MAX), 100)?;
        assert_eq!(
            outcome,
            CommitmentSeriesWriteOutcome::Indexed {
                project_at: 0,
                next_due: due,
            }
        );
    }
    // Both Project rows are already actionable and are consumed by one pass.
    let report = vault.reconcile_commitment_schedule(100)?;
    assert_eq!(report.projected_series, 2);
    assert_eq!(report.minted_instances.len(), 2);
    assert!(rows_in_phase(&vault, CommitmentDuePhase::Project)?.is_empty());
    assert_eq!(
        vault
            .commitment_due_index_snapshot()?
            .phase_minimum(CommitmentDuePhase::Lead),
        Some(0),
        "a saturated lead is immediately visible"
    );

    // A quota slot with the maximum lead saturates the same way.
    let now = NY_SPRING_WEEK.start + HOUR;
    parties.put_series(&vault, &quota_series, quota(2, TZ_NY), Some(u64::MAX), now)?;
    let minted = vault.reconcile_commitment_schedule(now)?.minted_instances;
    assert_eq!(minted.len(), 2);
    for id in &minted {
        let lead_rows: Vec<u64> = instance_rows(&vault, id)?
            .into_iter()
            .filter(|entry| entry.phase == CommitmentDuePhase::Lead)
            .map(|entry| entry.at)
            .collect();
        assert_eq!(lead_rows, vec![0]);
    }
    let wake = vault
        .next_actionable_wake_phase()?
        .expect("a saturated Lead row is actionable now");
    assert_eq!(wake.phase, CommitmentDuePhase::Lead);
    assert_eq!(wake.at, 0);
    Ok(())
}

#[test]
fn schedule_lead_override_beats_default() -> Result<()> {
    assert_eq!(DEFAULT_LEAD, 86_400);
    assert_eq!(
        CommitmentSchedulePayload::series(Schedule::Once { due: 1 }, None).lead_seconds(),
        DEFAULT_LEAD
    );
    assert_eq!(
        CommitmentSchedulePayload::series(Schedule::Once { due: 1 }, Some(0)).lead_seconds(),
        0
    );

    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let defaulted = crate::test_util::entity(0x8d);
    let immediate = crate::test_util::entity(0x8e);

    assert_eq!(
        parties.put_series(
            &vault,
            &defaulted,
            Schedule::Once { due: 1_000_000 },
            None,
            10
        )?,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: 1_000_000 - DEFAULT_LEAD,
            next_due: 1_000_000,
        }
    );
    assert_eq!(
        parties.put_series(
            &vault,
            &immediate,
            Schedule::Once { due: 1_000_000 },
            Some(0),
            10
        )?,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: 1_000_000,
            next_due: 1_000_000,
        }
    );

    // The override travels into the instance: its Lead row uses the same
    // number the series projected with.
    let minted = vault
        .reconcile_commitment_schedule(1_000_000)?
        .minted_instances;
    assert_eq!(minted.len(), 2);
    let lead_instants: Vec<u64> = rows_in_phase(&vault, CommitmentDuePhase::Lead)?
        .into_iter()
        .map(|entry| entry.at)
        .collect();
    assert_eq!(lead_instants, vec![1_000_000 - DEFAULT_LEAD, 1_000_000]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. Snapshot durability
// ---------------------------------------------------------------------------

#[test]
fn next_due_at_reads_persisted_min_after_reopen() -> Result<()> {
    let (dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let pending = crate::test_util::entity(0x8f);
    let minted_series = crate::test_util::entity(0x91);

    parties.put_series(
        &vault,
        &pending,
        Schedule::Once { due: 1_000_000 },
        None,
        10,
    )?;
    parties.put_series(
        &vault,
        &minted_series,
        Schedule::Once { due: 500_000 },
        Some(1_000),
        10,
    )?;
    assert_eq!(
        vault
            .reconcile_commitment_schedule(499_000)?
            .minted_instances
            .len(),
        1
    );

    drop(vault);
    let vault = Vault::open(dir.path(), vault_config())?;
    let snapshot = vault.commitment_due_index_snapshot()?;
    assert_eq!(
        snapshot.next_due_at(),
        Some(499_000),
        "the global minimum is the first key under the prefix"
    );
    assert_eq!(
        snapshot.phase_minima(),
        &[
            Some(1_000_000 - DEFAULT_LEAD),
            Some(499_000),
            Some(500_000),
            Some(500_000),
        ]
    );
    assert_eq!(
        snapshot.next_timer_at(&[CommitmentDuePhase::Project]),
        Some(1_000_000 - DEFAULT_LEAD)
    );
    assert_eq!(
        snapshot.next_timer_at(&[CommitmentDuePhase::Lead, CommitmentDuePhase::Due]),
        Some(499_000),
        "the timer's door names its phases; LifecycleDue can never slip in"
    );
    assert_eq!(
        snapshot.next_timer_at(&[CommitmentDuePhase::LifecycleDue]),
        Some(500_000)
    );
    assert_eq!(snapshot.next_timer_at(&[]), None);

    // A zero instance slot is a legal ABSENCE marker on a Project row and
    // corruption everywhere else.
    let occurrence = CommitmentOccurrence::new(500, time(500, 500), 0)?;
    let value = raw_due_value(&occurrence);
    let mut entry = CommitmentDueEntry {
        at: 10,
        phase: CommitmentDuePhase::Project,
        series_ref: pending,
        instance_ref: None,
        occurrence,
    };
    assert!(decode_commitment_due_row(&commitment_due_primary_key(&entry), &value).is_ok());
    entry.phase = CommitmentDuePhase::Lead;
    let lost = decode_commitment_due_row(&commitment_due_primary_key(&entry), &value)
        .expect_err("a zero instance outside Project is a lost id, not an empty one");
    assert!(matches!(
        lost,
        Error::CorruptedIndex("commitment due index")
    ));

    // A corrupt row is a LOUD failure: "nothing is due" is the one answer a
    // commitment engine must never give.
    vault.corrupt_commitment_due_row_for_test(1)?;
    let err = vault
        .commitment_due_index_snapshot()
        .expect_err("a corrupt row must fail the read");
    assert!(matches!(err, Error::CorruptedIndex("commitment due index")));
    assert!(vault.commitment_entries_through(u64::MAX).is_err());
    assert!(vault.reconcile_commitment_schedule(u64::MAX / 2).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 12. Acknowledge
// ---------------------------------------------------------------------------

#[test]
fn acknowledge_commitment_due_rejects_owner_phases() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x92);
    parties.put_series(
        &vault,
        &series,
        Schedule::Once { due: 500_000 },
        Some(1_000),
        10,
    )?;

    let project = rows_in_phase(&vault, CommitmentDuePhase::Project)?
        .into_iter()
        .next()
        .expect("series Project row");
    let refusal = vault
        .acknowledge_commitment_due(&project)
        .expect_err("Project is owner-managed");
    assert!(matches!(
        refusal,
        Error::InvariantViolation("commitment due phase is owner-managed")
    ));
    assert_eq!(
        rows_in_phase(&vault, CommitmentDuePhase::Project)?.len(),
        1,
        "a refused acknowledge erases nothing"
    );

    let instance = vault
        .reconcile_commitment_schedule(499_000)?
        .minted_instances[0];
    for entry in instance_rows(&vault, &instance)? {
        match entry.phase {
            CommitmentDuePhase::Lead | CommitmentDuePhase::Due => {
                assert!(entry.phase.is_acknowledgeable());
                assert!(vault.acknowledge_commitment_due(&entry)?, "row removed");
                assert!(
                    !vault.acknowledge_commitment_due(&entry)?,
                    "a second acknowledge of the same row is a no-op"
                );
            }
            _ => {
                assert!(!entry.phase.is_acknowledgeable());
                let err = vault
                    .acknowledge_commitment_due(&entry)
                    .expect_err("LifecycleDue is owner-managed");
                assert!(matches!(
                    err,
                    Error::InvariantViolation("commitment due phase is owner-managed")
                ));
            }
        }
    }

    // Only the lapse marker is left, and it never reaches the wake feed.
    let remaining = instance_rows(&vault, &instance)?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].phase, CommitmentDuePhase::LifecycleDue);
    assert_eq!(vault.next_actionable_wake_phase()?, None);
    Ok(())
}

// ---------------------------------------------------------------------------
// 13. Instance identity
// ---------------------------------------------------------------------------

#[test]
fn instance_id_collision_requires_full_copied_identity() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x93);
    let now = NY_SPRING_WEEK.start + HOUR;

    // Determinism: the same series and occurrence name the same id, always.
    let occurrence = CommitmentOccurrence::new(NY_SPRING_WEEK.end, NY_SPRING_WEEK, 0)?;
    let derived = commitment_instance_id(&series, &occurrence);
    assert_eq!(derived, commitment_instance_id(&series, &occurrence));
    let other = CommitmentOccurrence::new(NY_SPRING_WEEK.end, NY_SPRING_WEEK, 1)?;
    assert_ne!(derived, commitment_instance_id(&series, &other));

    let minted = mint_quota_window(&vault, &parties, &series, 2, now)?;
    assert_eq!(minted[0], derived);

    // The pinned envelope evidence the projector stamps.
    let body = vault.get_claim(&derived)?.expect("minted instance claim");
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(body.source, Some(ClaimSource::Generated));
    let evidence = body.evidence.as_ref().expect("envelope evidence");
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        &Value::Binary(
            commitment_projection_actor()
                .entity_ref()
                .as_bytes()
                .to_vec()
        )
    );
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).as_u64(),
        Some(EdgeActorClass::System as u64)
    );
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY).as_str(),
        Some(COMMITMENT_PROJECTION_PROVENANCE)
    );
    // A mint materializes an obligation the owner already consented to, so it
    // opens no new consent question.
    assert!(
        vault
            .pending_gate_consents(32)?
            .iter()
            .all(|row| row.claim_id != *derived.as_bytes()),
        "a projected instance must not queue a consent row"
    );

    // A repeat of identical work COALESCES: same ids, reported already-present.
    let replant = CommitmentDueEntry {
        at: NY_SPRING_WEEK.start,
        phase: CommitmentDuePhase::Project,
        series_ref: series,
        instance_ref: None,
        occurrence,
    };
    vault.with_write_txn(|wtxn| vault.store.commitment_due_put_in_txn(wtxn, &replant))?;
    let retry = vault.reconcile_commitment_schedule(now)?;
    assert!(retry.minted_instances.is_empty());
    assert_eq!(retry.already_present_instances, minted);

    // A DIFFERENT identity wearing the derived id of an unminted occurrence is
    // a refusal, never a silent overwrite.
    let collided = crate::test_util::entity(0x94);
    let clash_occurrence = CommitmentOccurrence::new(NY_WEEK_2.end, NY_WEEK_2, 0)?;
    let clash_id = commitment_instance_id(&collided, &clash_occurrence);
    let impostor = record_with_text(
        parties.obligor,
        parties.beneficiary,
        CommitmentSchedulePayload::instance(
            quota(2, TZ_NY),
            Some(HOUR),
            collided,
            clash_occurrence,
        )
        .encode()?,
        CommitmentStrength::Commitment,
        "a different promise entirely",
    )?;
    vault.put_commitment_claim(
        &clash_id,
        &impostor,
        &parties.envelope,
        NY_WEEK_2,
        NY_WEEK_2.start,
    )?;
    parties.put_series(
        &vault,
        &collided,
        quota(2, TZ_NY),
        Some(HOUR),
        NY_WEEK_2.start + HOUR,
    )?;
    let err = vault
        .reconcile_commitment_schedule(NY_WEEK_2.start + HOUR)
        .expect_err("a mismatched occupant is a collision");
    assert!(matches!(err, ScheduleError::InstanceIdentityCollision));
    Ok(())
}

// ---------------------------------------------------------------------------
// 15. Stored-but-unindexed
// ---------------------------------------------------------------------------

#[test]
fn generic_writer_schedule_payload_is_stored_but_unindexed() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x95);
    let instance = crate::test_util::entity(0x96);
    let orphan_series = crate::test_util::entity(0x97);

    // A strict typed SERIES payload written through CMT-1's generic door.
    let series_claim = parties.record(encode_series(Schedule::Once { due: 500 }, Some(50))?)?;
    vault.put_commitment_claim(
        &series,
        &series_claim,
        &parties.envelope,
        time(100, 900),
        100,
    )?;
    let stored = vault.get_commitment_claim(&series)?.expect("series claim");
    assert!(CommitmentSchedulePayload::decode(&stored.schedule)?.is_series());

    // Stored faithfully, indexed not at all.
    assert_eq!(vault.commitment_due_index_snapshot()?.next_due_at(), None);
    assert!(rows(&vault)?.is_empty());
    assert_eq!(
        vault.reconcile_commitment_schedule(10_000)?,
        CommitmentProjectionReport::default()
    );
    // The close hook still refuses to treat a SERIES as an occurrence; that
    // refusal is the same one `close_hook_ignores_plain_commitments_but_rejects_series`
    // pins, and it is a REFUSAL rather than corruption.
    let refusal = vault
        .on_instance_closed(
            &series,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            1_000,
        )
        .expect_err("a series is not an instance");
    assert!(matches!(refusal, ScheduleError::Invalid(reason)
            if reason == "close hook requires commitment instance"));

    // The same for a strict typed INSTANCE payload written generically: it is
    // ordinary data, and closing it is clean and successor-free.
    let occurrence = CommitmentOccurrence::new(700, time(600, 800), 0)?;
    let instance_record = parties.record(
        CommitmentSchedulePayload::instance(
            Schedule::Once { due: 700 },
            Some(50),
            orphan_series,
            occurrence,
        )
        .encode()?,
    )?;
    vault.put_commitment_claim(
        &instance,
        &instance_record,
        &parties.envelope,
        time(600, 800),
        600,
    )?;
    assert_eq!(vault.commitment_due_index_snapshot()?.next_due_at(), None);
    assert_eq!(
        vault.reconcile_commitment_schedule(10_000)?,
        CommitmentProjectionReport::default()
    );
    assert!(members(&vault, &orphan_series)?.is_empty());
    assert_eq!(
        close(
            &vault,
            &instance,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            900,
        )?,
        Vec::new(),
        "an unindexed instance closes without reviving a series nobody wrote"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 16. Close-hook grounding
// ---------------------------------------------------------------------------

#[test]
fn close_hook_ignores_plain_commitments_but_rejects_series() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;

    // A plain CMT-1 commitment carries an OPAQUE schedule the codec never
    // claims. Finding one is legitimate, not corruption.
    let plain_id = crate::test_util::entity(0x98);
    let plain_schedule = Value::Map(vec![
        (Value::from("kind"), Value::from("once")),
        (Value::from("due"), Value::from(10_000_u64)),
    ]);
    vault.put_commitment_claim(
        &plain_id,
        &parties.record(plain_schedule)?,
        &parties.envelope,
        time(100, 900),
        100,
    )?;
    assert_eq!(
        vault.on_instance_closed(
            &plain_id,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            200
        )?,
        Vec::new()
    );

    // An indexed SERIES is a refusal.
    let series = crate::test_util::entity(0x99);
    parties.put_series(
        &vault,
        &series,
        Schedule::Once { due: 500_000 },
        Some(50),
        10,
    )?;
    let not_instance = vault
        .on_instance_closed(
            &series,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            200,
        )
        .expect_err("a series is not an instance");
    assert!(matches!(not_instance, ScheduleError::Invalid(reason)
            if reason == "close hook requires commitment instance"));

    // A still-OPEN instance means the status write this hook reacts to never
    // landed. So does a terminal status that contradicts the caller.
    let instance = vault
        .reconcile_commitment_schedule(499_950)?
        .minted_instances[0];
    let open = vault
        .on_instance_closed(
            &instance,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            500_000,
        )
        .expect_err("the hook never writes the status");
    assert!(matches!(open, ScheduleError::Invalid(reason)
            if reason == "close hook requires terminal instance status"));
    vault.fulfill_commitment(&instance, &parties.envelope, 500_001)?;
    let mismatch = vault
        .on_instance_closed(
            &instance,
            CommitmentInstanceOutcome::Lapsed,
            &parties.envelope,
            500_002,
        )
        .expect_err("a contradicted outcome is refused");
    assert!(matches!(mismatch, ScheduleError::Invalid(reason)
            if reason == "close hook requires terminal instance status"));
    assert_eq!(
        instance_rows(&vault, &instance)?.len(),
        3,
        "a refused close leaves the occurrence's rows exactly where they were"
    );

    // Rows that outlived their claim are the crash this hook repairs.
    let ghost_series = crate::test_util::entity(0x9a);
    let ghost = crate::test_util::entity(0x9b);
    let occurrence = CommitmentOccurrence::new(700, time(700, 700), 0)?;
    vault.with_write_txn(|wtxn| {
        for phase in CommitmentDuePhase::INSTANCE_PHASES {
            vault.store.commitment_due_put_in_txn(
                wtxn,
                &CommitmentDueEntry {
                    at: 700,
                    phase,
                    series_ref: ghost_series,
                    instance_ref: Some(ghost),
                    occurrence,
                },
            )?;
        }
        Ok(())
    })?;
    assert_eq!(instance_rows(&vault, &ghost)?.len(), 3);
    assert_eq!(
        vault.on_instance_closed(
            &ghost,
            CommitmentInstanceOutcome::Fulfilled,
            &parties.envelope,
            800
        )?,
        Vec::new()
    );
    assert!(instance_rows(&vault, &ghost)?.is_empty());

    // All four matching outcomes sweep the same three rows.
    for (index, outcome) in [
        CommitmentInstanceOutcome::Fulfilled,
        CommitmentInstanceOutcome::Lapsed,
        CommitmentInstanceOutcome::Released,
        CommitmentInstanceOutcome::Superseded,
    ]
    .into_iter()
    .enumerate()
    {
        let id = crate::test_util::entity(
            0xB0_u8.saturating_add(u8::try_from(index).expect("four outcomes")),
        );
        parties.put_series(&vault, &id, Schedule::Once { due: 600_000 }, Some(50), 10)?;
        let minted = vault
            .reconcile_commitment_schedule(599_950)?
            .minted_instances;
        let target = *minted.last().expect("one occurrence per Once series");
        assert_eq!(instance_rows(&vault, &target)?.len(), 3);
        assert_eq!(
            close(&vault, &target, outcome, &parties.envelope, 600_100)?,
            Vec::new(),
            "a Once series is finished, however it ended"
        );
        assert!(instance_rows(&vault, &target)?.is_empty());
        assert_eq!(
            members(&vault, &id)?.len(),
            1,
            "membership survives a close"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 17. Overdue reader
// ---------------------------------------------------------------------------

#[test]
fn overdue_reader_returns_closed_dirty_rows_strictly_before_now() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let due = 700_000;

    // Four instances, one per terminal status, each closed by a STATUS write
    // whose close hook never ran: the crash this reader repairs.
    let mut dirty = Vec::new();
    for (index, status) in [
        CommitmentStatus::Fulfilled,
        CommitmentStatus::Lapsed,
        CommitmentStatus::Released,
        CommitmentStatus::Superseded,
    ]
    .into_iter()
    .enumerate()
    {
        let series = crate::test_util::entity(
            0xC0_u8.saturating_add(u8::try_from(index).expect("four statuses")),
        );
        parties.put_series(&vault, &series, Schedule::Once { due }, Some(1_000), 10)?;
        let instance = vault
            .reconcile_commitment_schedule(due - 1_000)?
            .minted_instances
            .pop()
            .expect("one occurrence");
        set_status(&vault, &instance, status, &parties.envelope, due + 1)?;
        assert_eq!(
            vault
                .get_commitment_claim(&instance)?
                .expect("claim")
                .status,
            status
        );
        assert_eq!(
            instance_rows(&vault, &instance)?.len(),
            3,
            "the hook never ran, so the rows are still there"
        );
        dirty.push(instance);
    }
    dirty.sort_unstable_by_key(|id| *id.as_bytes());

    // Status does not matter; only the LifecycleDue instant does.
    assert!(
        vault.overdue_commitment_instances(due)?.is_empty(),
        "at == now is excluded: the window has not closed yet"
    );
    assert!(
        vault.overdue_commitment_instances(due - 1)?.is_empty(),
        "a future LifecycleDue is not overdue"
    );
    let mut overdue = vault.overdue_commitment_instances(due + 1)?;
    overdue.sort_unstable_by_key(|id| *id.as_bytes());
    assert_eq!(overdue, dirty);

    // A still-open occurrence whose window has closed shows up on the very same
    // feed — the reader classifies, it does not filter.
    let open_series = crate::test_util::entity(0xC8);
    parties.put_series(
        &vault,
        &open_series,
        Schedule::Once { due: due + 10 },
        Some(1_000),
        10,
    )?;
    let still_open = vault
        .reconcile_commitment_schedule(due + 10 - 1_000)?
        .minted_instances
        .pop()
        .expect("one occurrence");
    assert!(
        vault
            .overdue_commitment_instances(due + 11)?
            .contains(&still_open)
    );

    // Running the hook is what clears the row.
    vault.on_instance_closed(
        &dirty[0],
        vault
            .get_commitment_claim(&dirty[0])?
            .map(|record| match record.status {
                CommitmentStatus::Fulfilled => CommitmentInstanceOutcome::Fulfilled,
                CommitmentStatus::Lapsed => CommitmentInstanceOutcome::Lapsed,
                CommitmentStatus::Released => CommitmentInstanceOutcome::Released,
                _ => CommitmentInstanceOutcome::Superseded,
            })
            .expect("dirty claim"),
        &parties.envelope,
        due + 2,
    )?;
    assert!(
        !vault
            .overdue_commitment_instances(due + 1)?
            .contains(&dirty[0])
    );
    Ok(())
}

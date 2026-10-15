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
    CommitmentObligorKind, CommitmentRecord, CommitmentStrength,
};
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
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
/// The last one is load-bearing rather than decorative: the projector is a
/// MACHINE, so it mints only with the host-held key the host provisions at
/// bootstrap (ONE-1634).
fn seed_world(vault: &Vault) -> Result<(EntityId, EntityId)> {
    let obligor = crate::test_util::entity(0x71);
    let beneficiary = crate::test_util::entity(0x72);
    for id in [obligor, beneficiary] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
    }
    crate::test_util::provision_engine_machines(vault);
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
    // A status update, not a birth: the public `commitment_claim_candidate`
    // enforces Open-at-birth, so the write is composed here from the same
    // pieces CMT-1's own status writer uses, carrying every metadata axis of
    // the claim it replaces.
    let mut candidate = crate::write_envelope::ClaimCandidate::new(
        crate::commitment::PREDICATE_COMMITMENT_RECORD,
        crate::claim::ClaimSubject::Entity(record.obligor.entity_ref),
        crate::commitment::encode_commitment_value(&record)?,
        body.confidence,
    )
    .with_validity(Some(valid.start), Some(valid.end));
    if let Some(salience) = body.salience {
        candidate = candidate.with_salience(salience);
    }
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    if body.stale {
        candidate = candidate.with_stale(true);
    }
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

    // An absent instance is legal only for Project.
    let occurrence = CommitmentOccurrence::new(500, time(500, 500), 0)?;
    let value = raw_due_value(&occurrence);
    let mut entry = CommitmentDueEntry {
        at: 10,
        phase: CommitmentDuePhase::Project,
        series_ref: pending,
        instance_ref: None,
        occurrence,
    };
    let decoded = decode_commitment_due_row(&commitment_due_primary_key(&entry), &value)?;
    assert_eq!(decoded.phase, CommitmentDuePhase::Project);
    assert_eq!(decoded.series_ref, pending);
    assert_eq!(decoded.instance_ref, None);
    entry.phase = CommitmentDuePhase::Lead;
    let lost = decode_commitment_due_row(&commitment_due_primary_key(&entry), &value)
        .expect_err("a zero instance outside Project is a lost id, not an empty one");
    assert!(matches!(lost, Error::CorruptedIndex(_)));

    // Corruption must never be interpreted as an empty index.
    vault.corrupt_commitment_due_row_for_test(1)?;
    let err = vault
        .commitment_due_index_snapshot()
        .expect_err("a corrupt row must fail the read");
    assert!(matches!(err, Error::CorruptedIndex(_)));
    assert!(matches!(
        vault.commitment_entries_through(u64::MAX),
        Err(Error::CorruptedIndex(_))
    ));
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
    assert!(matches!(refusal, Error::InvariantViolation(_)));
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
                assert!(matches!(err, Error::InvariantViolation(_)));
            }
        }
    }

    // Only the lapse marker remains, outside the wake feed.
    let remaining = instance_rows(&vault, &instance)?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].phase, CommitmentDuePhase::LifecycleDue);
    assert!(vault.next_actionable_wake_phase()?.is_none());
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
    let derived = commitment_instance_id(&series, &occurrence)?;
    assert_eq!(derived, commitment_instance_id(&series, &occurrence)?);
    let other = CommitmentOccurrence::new(NY_SPRING_WEEK.end, NY_SPRING_WEEK, 1)?;
    assert_ne!(derived, commitment_instance_id(&series, &other)?);

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
            commitment_projection_actor()?
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
    let clash_id = commitment_instance_id(&collided, &clash_occurrence)?;
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
// 16. Close-hook grounding
// ---------------------------------------------------------------------------

#[test]
fn close_hook_ignores_plain_commitments_but_rejects_series() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;

    // Legacy opaque schedules are legitimate, not corruption.
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
            200,
        )?,
        Vec::new()
    );

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
    assert!(matches!(not_instance, ScheduleError::Invalid(_)));

    // Neither an open instance nor a contradictory terminal outcome is accepted.
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
    assert!(matches!(open, ScheduleError::Invalid(_)));
    vault.fulfill_commitment(&instance, &parties.envelope, 500_001)?;
    let mismatch = vault
        .on_instance_closed(
            &instance,
            CommitmentInstanceOutcome::Lapsed,
            &parties.envelope,
            500_002,
        )
        .expect_err("a contradicted outcome is refused");
    assert!(matches!(mismatch, ScheduleError::Invalid(_)));
    assert_eq!(
        instance_rows(&vault, &instance)?.len(),
        3,
        "a refused close leaves the occurrence's rows exactly where they were"
    );

    // Rows that outlived their claim are repaired by the hook.
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
            800,
        )?,
        Vec::new()
    );
    assert!(instance_rows(&vault, &ghost)?.is_empty());

    // All four matching outcomes consume timed rows but retain membership.
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

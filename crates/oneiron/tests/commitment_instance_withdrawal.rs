//! FIX 22383 (COMMITMENT-INSTANCE): a commitment instance withdrawn by a
//! generic retraction neither wakes nor blocks the lapse sweep.
//!
//! A generic `retract_claim` closes the instance's claim and leaves its
//! promise's status Open. Before the fix its due phases stayed live, so its
//! Lead phase still enqueued a wake, and the sweep selected it for the lapse
//! batch, which then failed whole with `ClaimAlreadyClosed`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_instance_withdrawal`.

use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, CommitmentWakeDue, CommitmentWakeFireOutcome, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    fire_due_commitment_wake, lapse_overdue_commitments,
};
use rmpv::Value;

const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;
const WITHDRAWN_SERIES: u8 = 0x83;

const LEAD_SECS: u64 = 100;
const DUE_AT: u64 = 1_000;
/// The projector mints an occurrence a lead ahead of its due instant.
const PROJECT_AT: u64 = DUE_AT - LEAD_SECS;
/// After the projection, before the Lead phase fires.
const RETRACT_AT: u64 = PROJECT_AT + 50;

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
                b"fix 22383 person",
            )
            .expect("seed person");
    }
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
    WriteEnvelope::new(
        WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fix 22383 fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    )
}

/// Indexes a `Once` series due at [`DUE_AT`] and mints its one occurrence;
/// returns the instance.
fn project_instance(
    vault: &Vault,
    envelope: &WriteEnvelope,
    series: u8,
    content: &str,
) -> EntityId {
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
        party(BENEFICIARY),
        CommitmentContent::new(content, None).expect("content"),
        CommitmentSchedulePayload::series(Schedule::Once { due: DUE_AT }, Some(LEAD_SECS))
            .encode()
            .expect("series payload"),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:fix-22383")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    vault
        .put_commitment_series(
            &party(series),
            &record,
            envelope,
            TimeRange {
                start: 1,
                end: DUE_AT + 10_000,
            },
            1,
        )
        .expect("series indexes");
    let report = vault
        .reconcile_commitment_schedule(PROJECT_AT)
        .expect("projection mints the occurrence");
    assert_eq!(
        report.minted_instances.len(),
        1,
        "one occurrence per series"
    );
    report.minted_instances[0]
}

/// Fires every actionable wake phase due at or before `now`, in index order,
/// and returns the instances that enqueued a wake.
fn fire_due_phases(vault: &Vault, now: u64) -> Vec<EntityId> {
    let mut woken = Vec::new();
    // Two phases exist at most (Lead and Due of one instance); the bound only
    // stops a broken index from looping.
    for _ in 0..16 {
        let Some(entry) = vault.next_actionable_wake_phase().expect("wake read") else {
            break;
        };
        if entry.at > now {
            break;
        }
        let due = CommitmentWakeDue::from_due_entry(&entry)
            .expect("typed wake due")
            .expect("an actionable phase is Lead or Due");
        let instance = due.instance_id;
        let outcome = fire_due_commitment_wake(vault, due, now).expect("fire door");
        if matches!(
            outcome,
            CommitmentWakeFireOutcome::Enqueued { .. } | CommitmentWakeFireOutcome::Existing { .. }
        ) {
            woken.push(instance);
        }
    }
    woken
}

#[test]
fn retracted_commitment_instance_does_not_fire_or_block_lapse_repair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let envelope = seed_world(&vault);
    let withdrawn = project_instance(
        &vault,
        &envelope,
        WITHDRAWN_SERIES,
        "ring the beneficiary back",
    );

    vault
        .retract_claim(&withdrawn, RETRACT_AT)
        .expect("the owner withdraws the instance");

    let woken = fire_due_phases(&vault, DUE_AT);
    let lapse = lapse_overdue_commitments(&vault, DUE_AT + 1, &envelope)
        .map(|report| (report.lapsed, report.repaired_close_hooks))
        .map_err(|error| format!("{error:?}"));
    assert_eq!(
        (woken.contains(&withdrawn), lapse),
        (false, Ok((Vec::new(), Vec::new()))),
        "the withdrawn instance must not wake (woken: {woken:?}), and the sweep must neither \
         select it nor fail on it"
    );

    // Withdrawal invents no status: the promise still says what it said.
    let record = vault
        .get_commitment_claim(&withdrawn)
        .expect("commitment read")
        .expect("the withdrawn instance is still stored");
    assert_eq!(record.status, CommitmentStatus::Open);
}

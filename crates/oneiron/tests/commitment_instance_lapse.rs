//! FIX LAPSE-PROJECTED-INSTANCE-MACHINE-PROOF: a commitment instance the
//! schedule projection mints is a MACHINE-born claim whose validity window is
//! its due instant. Its signed history refuses a close that moves that end
//! later, so the lapse sweep, a fulfilment and a retraction after the due
//! instant each failed with `InvalidMachineClaimProof`. Each now closes the
//! instance inside its own window: it keeps the due instant as its end.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_instance_lapse`.

use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, CommitmentWakeDue, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance, fire_due_commitment_wake,
    lapse_overdue_commitments,
};
use rmpv::Value;

const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;
const SERIES: u8 = 0x83;

const LEAD_SECS: u64 = 100;
const DUE_AT: u64 = 1_000;
const PROJECT_AT: u64 = DUE_AT - LEAD_SECS;
const AFTER_DUE: u64 = DUE_AT + 1;

fn party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn instant(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

/// Two people and the engine's MACHINE actors; the owner's envelope.
fn seed_world(vault: &Vault) -> WriteEnvelope {
    for seed in [OBLIGOR, BENEFICIARY] {
        vault
            .put_entity(
                &party(seed),
                ENTITY_TYPE_PERSON,
                instant(1),
                1,
                b"fixture person",
            )
            .expect("seed person");
    }
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
    WriteEnvelope::new(
        WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("commitment instance lapse fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    )
}

/// Indexes a Once series due at [`DUE_AT`] and lets the projection mint its
/// one instance at its lead.
fn project_once_instance(vault: &Vault, envelope: &WriteEnvelope) -> EntityId {
    let payload =
        CommitmentSchedulePayload::series(Schedule::Once { due: DUE_AT }, Some(LEAD_SECS))
            .encode()
            .expect("series payload");
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
        party(BENEFICIARY),
        CommitmentContent::new("send the signed lease", None).expect("content"),
        payload,
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:lapse-fixture")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    vault
        .put_commitment_series(
            &party(SERIES),
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
    assert_eq!(report.minted_instances.len(), 1, "one occurrence");
    report.minted_instances[0]
}

/// Fires every wake phase due by `now` (the instance's Lead and Due).
fn fire_due_phases(vault: &Vault, now: u64) {
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
        fire_due_commitment_wake(vault, due, now).expect("fire door");
    }
}

/// The closed instance's lifecycle and validity end.
fn closed(vault: &Vault, instance: &EntityId) -> (ClaimLifecycleStatus, Option<u64>) {
    let body = vault
        .get_claim(instance)
        .expect("claim read")
        .expect("the instance is stored");
    (body.lifecycle, body.valid_to)
}

#[test]
fn projected_instance_lapses_after_its_due_instant() {
    let (_dir, vault) = open_vault();
    let envelope = seed_world(&vault);
    let instance = project_once_instance(&vault, &envelope);
    fire_due_phases(&vault, DUE_AT);
    let lapsed = lapse_overdue_commitments(&vault, AFTER_DUE, &envelope)
        .map(|report| report.lapsed)
        .map_err(|error| format!("{error:?}"));
    assert_eq!(lapsed, Ok(vec![instance]));
    assert_eq!(
        closed(&vault, &instance),
        (ClaimLifecycleStatus::Superseded, Some(DUE_AT)),
        "the lapse closes the instance at its own end"
    );
}

#[test]
fn projected_instance_fulfils_after_its_due_instant() {
    let (_dir, vault) = open_vault();
    let envelope = seed_world(&vault);
    let instance = project_once_instance(&vault, &envelope);
    let fulfilled = vault
        .fulfill_commitment(&instance, &envelope, AFTER_DUE)
        .map_err(|error| format!("{error:?}"));
    assert_eq!(fulfilled, Ok(()));
    assert_eq!(
        closed(&vault, &instance),
        (ClaimLifecycleStatus::Superseded, Some(DUE_AT)),
        "the fulfilment closes the instance at its own end"
    );
}

#[test]
fn projected_instance_retracts_after_its_due_instant() {
    let (_dir, vault) = open_vault();
    let envelope = seed_world(&vault);
    let instance = project_once_instance(&vault, &envelope);
    let retracted = vault
        .retract_claim(&instance, AFTER_DUE)
        .map_err(|error| format!("{error:?}"));
    assert_eq!(retracted, Ok(()));
    assert_eq!(
        closed(&vault, &instance),
        (ClaimLifecycleStatus::Retracted, Some(DUE_AT)),
        "the retraction closes the instance at its own end"
    );
}

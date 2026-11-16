//! L9-42 (ARCH-0005a #housekeeping-open; Engine ruling L9-42-LAPSE-WRITER =
//! A): the housekeeping pass lapses an overdue commitment instance as the
//! engine's commitment lapse writer, a System MACHINE, not as the owner. The
//! pass lapses because a due time passed, which is no person's act.
//!
//! - A vault with the shipped policy and provisioned engine writers lapses
//!   under the writer: the lapse claim's evidence names the writer and class
//!   `system`. Before the writer the lapse named the owner and class `human`.
//! - A vault whose stored policy names no ceiling for the writer (an
//!   owner-authored manifest written before the row) still lapses as the
//!   owner, class `human`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_lapse_writer`.

use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::edge::EdgeActorClass;
use oneiron::housekeeping::{HousekeepingBudget, HousekeepingSweep, SweepOutcome, SweepWork};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::write_envelope::commitment_transition::lapse_claim_id;
use oneiron::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;

const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;
const SERIES: u8 = 0x3D;

const DAY: u64 = 24 * 60 * 60;
/// The first occurrence's due instant; the pass runs one second after it, so
/// the strict `due < now` boundary selects it.
const DUE_AT: u64 = 1_000_000;
const NOW: u64 = DUE_AT + 1;

/// The shipped policy pack's id on its stored manifest.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";
/// The derived-id domain of the commitment lapse writer, pinned here so a
/// moved domain shows as a failure of this test.
const COMMITMENT_LAPSE_ACTOR: &[u8] = b"oneiron.commitment.lapse.actor.v1";

fn party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn instant(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn lapse_writer() -> EntityId {
    EntityId::derive(COMMITMENT_LAPSE_ACTOR, &[]).expect("the lapse writer's derived id")
}

/// A vault on a manual clock at [`NOW`], its parties seeded and its host's
/// engine MACHINE writers provisioned, as a host does at bootstrap.
fn open(dir: &tempfile::TempDir) -> Vault {
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    for seed in [OBLIGOR, BENEFICIARY] {
        vault
            .put_entity(
                &party(seed),
                ENTITY_TYPE_PERSON,
                instant(1),
                1,
                b"l9-42 person",
            )
            .expect("seed person");
    }
    let _issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
}

/// Indexes a weekly series whose first occurrence is due at [`DUE_AT`] and
/// mints that occurrence; returns the instance.
fn overdue_instance(vault: &Vault) -> EntityId {
    let envelope = WriteEnvelope::new(
        WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("l9-42 fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
        party(BENEFICIARY),
        CommitmentContent::new("send the signed document", None).expect("content"),
        CommitmentSchedulePayload::series(
            Schedule::Interval {
                period: 7 * DAY,
                anchor: DUE_AT,
            },
            Some(DAY),
        )
        .encode()
        .expect("series payload"),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:l9-42")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    vault
        .put_commitment_series(
            &party(SERIES),
            &record,
            &envelope,
            TimeRange {
                start: 10,
                end: DUE_AT + 400 * DAY,
            },
            10,
        )
        .expect("series indexes");
    let report = vault
        .reconcile_commitment_schedule(DUE_AT - DAY)
        .expect("projection mints the first occurrence");
    assert_eq!(report.minted_instances.len(), 1, "one occurrence minted");
    report.minted_instances[0]
}

/// Runs the housekeeping pass and requires its lapse sweep to lapse one
/// instance.
fn run_lapse_sweep(vault: &Vault) {
    let report = vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");
    assert!(
        matches!(
            report.sweep(HousekeepingSweep::CommitmentLapse),
            Some(SweepOutcome::Ran {
                work: SweepWork::Commitments { lapsed: 1, .. },
                ..
            })
        ),
        "the lapse sweep lapses the overdue instance: {report:#?}"
    );
}

/// The actor and class the lapse claim of `instance` was written under.
fn lapse_author(vault: &Vault, instance: &EntityId) -> (EntityId, u64) {
    let lapse = lapse_claim_id(instance).expect("lapse claim id");
    let body = vault
        .get_claim(&lapse)
        .expect("lapse claim read")
        .expect("the lapse claim is stored");
    let Some(Value::Map(evidence)) = body.evidence else {
        panic!("the lapse claim carries its write envelope evidence");
    };
    let field = |name: &str| {
        evidence
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value.clone())
    };
    let actor = match field(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
        Some(Value::Binary(bytes)) => {
            EntityId::from_bytes(bytes.as_slice().try_into().expect("16-byte actor ref"))
                .expect("actor ref")
        }
        other => panic!("the lapse claim names its actor: {other:?}"),
    };
    let class = field(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
        .and_then(|value| value.as_u64())
        .expect("the lapse claim names its actor class");
    (actor, class)
}

/// Rewrites the stored shipped manifest without any actor-ceiling row bound
/// to `actor`, as an owner-authored manifest written before the row reads.
fn drop_actor_ceiling_rows(vault: &Vault, actor: EntityId) {
    let actor_ref = actor.to_hex();
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
    {
        let Some(bytes) = vault.get(&id).expect("manifest read") else {
            continue;
        };
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("manifest decodes");
        if manifest["pack_id"] != SHIPPED_POLICY_PACK {
            continue;
        }
        manifest["actor_ceilings"]
            .as_array_mut()
            .expect("the shipped manifest has actor ceilings")
            .retain(|row| row["actor_ref"].as_str() != Some(actor_ref.as_str()));
        oneiron::test_support::put_policy_manifest_bytes(
            vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("manifest encodes"),
        )
        .expect("manifest rewritten");
        return;
    }
    panic!("the vault holds no shipped policy manifest");
}

#[test]
fn the_housekeeping_pass_lapses_as_the_commitment_lapse_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let instance = overdue_instance(&vault);

    run_lapse_sweep(&vault);

    let (actor, class) = lapse_author(&vault, &instance);
    assert_eq!(
        (actor, class),
        (lapse_writer(), EdgeActorClass::System as u64),
        "a host-run lapse is the commitment lapse writer's System act, not the owner's Human one"
    );
    assert_eq!(
        vault.get_entity_type(&actor).expect("writer read"),
        Some(ENTITY_TYPE_MACHINE),
        "the lapse writer is a MACHINE"
    );
}

#[test]
fn a_policy_without_the_writer_row_keeps_the_owner_lapse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let instance = overdue_instance(&vault);
    drop_actor_ceiling_rows(&vault, lapse_writer());

    run_lapse_sweep(&vault);

    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault owner actor");
    assert_eq!(
        lapse_author(&vault, &instance),
        (owner, EdgeActorClass::Human as u64),
        "a policy that names no ceiling for the writer keeps the owner's Human lapse"
    );
}

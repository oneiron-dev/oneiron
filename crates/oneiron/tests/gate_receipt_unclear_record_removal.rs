//! A writer that removes an amended Gate decision's record, or makes it its
//! retention skeleton without erasing a claim, takes the unclear row filed
//! under its receipt (FIX [GATE-RECEIPT-UNCLEAR-ROW-OUTLIVES-RECORD-REMOVAL]).
//!
//! A MACHINE writes a Proposed CLAIM, the gate holds it for the owner, and
//! the owner's own same-id revision lands as an `approved_amended` decision
//! with its Δ (FIX [OWNER-REVISION-AMEND-DELTA-UNCAPTURED]). The host records
//! the amendment's routing facts with no cause, so the judge holds the whole
//! amendment `unclear` ("cause unsettled") and files an unclear row under the
//! receipt `gate:<hex>`, the Dreamer's clustering inlet. On main two writers
//! left that row with nothing behind it: the retention sweep, which removes
//! the record once it ages past the owner's horizon, and the owner's discard
//! of a world copy, which leaves the claim's decision as its retention
//! skeleton. With the fix each takes the row in its own write, and a receipt
//! the writer did not touch keeps its row.
//!
//! Round 2 of the review of #10051 kept three more cases. The discard is local,
//! so it leaves a label proposal that copied the row's note where it is,
//! where the withdrawal erased it and staged its sync tombstone. A legal hold
//! on such a proposal stops no retention sweep, where its refusal rolled back
//! the whole sweep. And a side restore that drops the record whose key the
//! sweep retired takes the row the image carried, where it came back.
//!
//! The discard is reached through a test door that runs its bundle write on a
//! set of claims, without a world fixture:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_receipt_unclear_record_removal`.
// `bind_host_owner` exists only under `test-support`; the door only under the
// cfg, and the discard only under `sync`.
#![cfg(all(feature = "test-support", feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::edit_distance::attribution::{
    AmendmentEvidence, judge_amendment, record_amendment_evidence,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::skill_attribution::{AttributionLane, unclear_attributions};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::gate_receipt_unclear as door;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"gate-receipt-unclear-record-removal-test-owner";
const MACHINE_NOTE: &str = "a machine note";
const REVISED_NOTE: &str = "the owner's revised note";
const SCOPE: &str = "outbound";
/// The vault clock's time while the fixture writes: no wall time, no sleeps.
const NOW: u64 = 1_700_000_000;
/// The owner's retention horizon, in seconds.
const HORIZON: u64 = 60;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "person" })).expect("body");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(NOW), NOW, &body)
        .expect("FIXTURE: a PERSON");
    id
}

/// A rooted vault on a manual clock, with an enrolled MACHINE and a bound
/// owner. The vault closes before its directory goes.
struct Seeded {
    vault: Vault,
    clock: Arc<ManualClock>,
    machine: EntityId,
    signing: SigningKey,
    owner: EntityId,
    dir: tempfile::TempDir,
}

fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("fresh vault");
    enrol(dir, vault, clock)
}

/// [`seed`] in a vault this process owns, with a device keystore and a vault
/// key, so it snapshots and restores, and the retention sweep retires the
/// key of a claim whose decisions all went.
fn seed_restorable() -> Seeded {
    let dir = oneiron::test_support::restore_tempdir();
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(dir.path().join("vault"), config).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.ensure_vault_key().expect("FIXTURE: the vault key");
    enrol(dir, vault, clock)
}

fn enrol(dir: tempfile::TempDir, vault: Vault, clock: Arc<ManualClock>) -> Seeded {
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(NOW), NOW, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[231; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [23; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    Seeded {
        vault,
        clock,
        machine,
        signing,
        owner,
        dir,
    }
}

/// A CLAIM the MACHINE writes Proposed about a new PERSON, held for the
/// owner: Active and Proposed, a claim waiting on its owner. Returns the
/// claim and its subject.
fn held_machine_claim(seeded: &Seeded) -> (EntityId, EntityId) {
    let vault = &seeded.vault;
    let subject = person(vault);
    let target = EntityId::now();
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(MACHINE_NOTE),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(seeded.machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::from("machine output")).expect("provenance"),
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault
        .machine_claim_transcript(&target, &candidate, &envelope)
        .expect("FIXTURE: machine transcript");
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: seeded.signing.verifying_key().to_bytes(),
        signature: seeded.signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, at(NOW), NOW)
        .commit()
        .expect("FIXTURE: the machine birth");
    (target, subject)
}

/// [`held_machine_claim`], then revised by the owner: an `approved_amended`
/// decision with its Δ. Returns the claim and the decision's receipt id.
fn owner_amended_claim(seeded: &Seeded) -> (EntityId, String) {
    let vault = &seeded.vault;
    let (target, subject) = held_machine_claim(seeded);
    let successor = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(REVISED_NOTE),
        1.0,
    );
    let revision = WriteEnvelope::new(
        WriteActor::new(seeded.owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("person")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(&target, successor, &revision, at(NOW), NOW)
        .commit()
        .expect("FIXTURE: the owner's own revision of the held machine claim lands");
    let amended = vault
        .gate_decisions(1_000)
        .expect("ledger read")
        .into_iter()
        .find(|record| {
            record.claim_id == Some(*target.as_bytes()) && record.outcome == "approved_amended"
        })
        .expect("FIXTURE: the owner's revision records its amended approval");
    (target, receipt_of(amended.decision_id))
}

fn receipt_of(decision: GateDecisionId) -> String {
    format!("gate:{}", decision.to_hex())
}

/// The host's routing facts for the amendment under `receipt`, with no
/// cause recorded, and the judge's settlement: the whole amendment held
/// `unclear`, its note "cause unsettled", filed in the unclear ledger.
fn judge_unsettled(seeded: &Seeded, receipt: &str) {
    let evidence = AmendmentEvidence::new(receipt, seeded.machine, SCOPE).at(NOW);
    record_amendment_evidence(&seeded.vault, &evidence).expect("FIXTURE: the amendment evidence");
    judge_amendment(&seeded.vault, receipt)
        .expect("FIXTURE: the judging pass")
        .expect("FIXTURE: the judge settles the amendment");
}

/// Whether the unclear ledger keeps an amendment row under `receipt`.
fn unclear_kept(vault: &Vault, receipt: &str) -> bool {
    unclear_attributions(vault)
        .expect("unclear ledger read")
        .iter()
        .any(|row| row.lane == AttributionLane::Amendment && row.reference == receipt)
}

/// Whether the Gate ledger still holds the decision under `receipt`, and
/// whether it is a retention skeleton: `None` when the row is gone.
fn decision_state(vault: &Vault, receipt: &str) -> Option<bool> {
    vault
        .gate_decisions(1_000)
        .expect("ledger read")
        .into_iter()
        .find(|record| receipt_of(record.decision_id) == receipt)
        .map(|record| record.redacted_at.is_some())
}

/// Whether `claim` still reads: a label proposal no writer erased.
fn claim_kept(vault: &Vault, claim: EntityId) -> bool {
    matches!(vault.get_claim(&claim), Ok(Some(_)))
}

fn owner_proof(seeded: &Seeded) -> AuthenticatedOwner {
    seeded
        .vault
        .authenticate_owner(
            seeded.owner,
            &seeded.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("FIXTURE: the owner's proof")
}

/// The owner sets a retention horizon of [`HORIZON`] seconds.
fn set_horizon(seeded: &Seeded) {
    seeded
        .vault
        .set_gate_decision_retention_secs(&owner_proof(seeded), Some(HORIZON))
        .expect("FIXTURE: the owner's retention horizon");
}

/// A label proposal waiting on its owner that the Coach filed quoting the
/// note of the unclear row under `receipt`.
fn label_proposal(seeded: &Seeded, receipt: &str) -> EntityId {
    let (proposal, _) = held_machine_claim(seeded);
    door::file_label_proposal(&seeded.vault, receipt, proposal)
        .expect("FIXTURE: the Coach files a label proposal quoting the receipt's note");
    assert!(
        claim_kept(&seeded.vault, proposal),
        "FIXTURE: the label proposal waits on its owner"
    );
    proposal
}

#[test]
fn a_retention_sweep_that_removes_an_amended_record_leaves_no_unclear_row() {
    let seeded = seed();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    assert!(
        unclear_kept(&seeded.vault, &receipt),
        "FIXTURE: the unsettled amendment files its unclear row under the receipt"
    );
    set_horizon(&seeded);

    seeded.clock.set(NOW + 10 * HORIZON);
    seeded
        .vault
        .maintain_gate_decision_retention()
        .expect("the retention pass");

    assert_eq!(
        decision_state(&seeded.vault, &receipt),
        None,
        "FIXTURE: the amended record aged past the horizon and the sweep removed it"
    );
    assert!(
        !unclear_kept(&seeded.vault, &receipt),
        "the sweep that removed the amended record leaves no unclear row under its receipt"
    );
}

#[test]
fn a_retention_sweep_inside_the_horizon_keeps_the_unclear_row() {
    let seeded = seed();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    set_horizon(&seeded);

    seeded.clock.set(NOW + HORIZON / 2);
    seeded
        .vault
        .maintain_gate_decision_retention()
        .expect("the retention pass");

    assert_eq!(
        decision_state(&seeded.vault, &receipt),
        Some(false),
        "FIXTURE: the amended record stays whole inside the horizon"
    );
    assert!(
        unclear_kept(&seeded.vault, &receipt),
        "a sweep that keeps the record keeps the unclear row under its receipt"
    );
}

#[test]
fn an_owner_discard_that_skeletons_an_amended_decision_leaves_no_unclear_row() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    let (_, other_receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &other_receipt);
    assert!(
        unclear_kept(&seeded.vault, &receipt) && unclear_kept(&seeded.vault, &other_receipt),
        "FIXTURE: both unsettled amendments file their unclear rows"
    );

    door::discard_claims_gate_payload(&seeded.vault, &BTreeSet::from([target]))
        .expect("the discard's write over the claim");

    assert_eq!(
        decision_state(&seeded.vault, &receipt),
        Some(true),
        "FIXTURE: the discard leaves the amended decision as its retention skeleton"
    );
    assert!(
        unclear_kept(&seeded.vault, &other_receipt),
        "a discard of another claim keeps this receipt's unclear row"
    );
    assert!(
        !unclear_kept(&seeded.vault, &receipt),
        "the discard that made the amended decision a skeleton leaves no unclear row under its \
         receipt"
    );
}

#[test]
fn an_owner_discard_leaves_the_label_proposal_that_quoted_the_unclear_row() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    let proposal = label_proposal(&seeded, &receipt);

    door::discard_claims_gate_payload(&seeded.vault, &BTreeSet::from([target]))
        .expect("the discard's write over the claim");

    assert!(
        !unclear_kept(&seeded.vault, &receipt),
        "FIXTURE: the discard leaves no unclear row under the receipt"
    );
    assert!(
        claim_kept(&seeded.vault, proposal),
        "the owner's discard, which is local, leaves the label proposal that quoted the receipt's \
         note where it is: no erase and no sync tombstone"
    );
}

#[test]
fn a_legal_hold_on_a_label_proposal_stops_no_retention_sweep() {
    let seeded = seed();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    let (_, unrelated) = owner_amended_claim(&seeded);
    let proposal = label_proposal(&seeded, &receipt);
    seeded
        .vault
        .place_legal_hold(
            &owner_proof(&seeded),
            vec![LegalHoldTarget::Record(proposal)],
            None,
        )
        .expect("FIXTURE: the owner holds the label proposal");
    set_horizon(&seeded);

    seeded.clock.set(NOW + 10 * HORIZON);
    let swept = seeded.vault.maintain_gate_decision_retention();

    assert!(
        swept.is_ok(),
        "a hold on a label proposal refuses no retention pass: {:?}",
        swept.err()
    );
    assert_eq!(
        decision_state(&seeded.vault, &unrelated),
        None,
        "the sweep removes an unrelated record past the horizon"
    );
    assert_eq!(
        decision_state(&seeded.vault, &receipt),
        None,
        "and the amended record whose note the held proposal quoted"
    );
    assert!(
        !unclear_kept(&seeded.vault, &receipt),
        "and the unclear row under its receipt"
    );
    assert!(
        claim_kept(&seeded.vault, proposal),
        "the held label proposal stays"
    );
}

#[test]
fn a_restore_that_drops_a_retired_amended_record_leaves_no_unclear_row() {
    let seeded = seed_restorable();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge_unsettled(&seeded, &receipt);
    set_horizon(&seeded);
    let key = seeded
        .vault
        .checkpoint_key()
        .expect("FIXTURE: the checkpoint key");
    let image = seeded.dir.path().join("image");
    seeded
        .vault
        .snapshot_checkpoint(&image, NOW)
        .expect("FIXTURE: the checkpoint holds the unclear row");

    seeded.clock.set(NOW + 10 * HORIZON);
    seeded
        .vault
        .maintain_gate_decision_retention()
        .expect("FIXTURE: the retention pass");
    assert_eq!(
        decision_state(&seeded.vault, &receipt),
        None,
        "FIXTURE: the sweep removed the amended record and retired its claim's key"
    );

    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &seeded.dir.path().join("restored"),
        VaultConfig::device(),
        &seeded.vault,
        NOW + 10 * HORIZON,
    )
    .expect("the side restore");

    assert_eq!(
        decision_state(&copy, &receipt),
        None,
        "FIXTURE: the restore drops the record whose key the sweep retired"
    );
    assert!(
        !unclear_kept(&copy, &receipt),
        "the restore that dropped the amended record leaves no unclear row under its receipt"
    );
}

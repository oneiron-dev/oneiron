//! An erase of an owner-amended claim takes the amendment attribution kept
//! under its Gate decision's receipt with the decision's content (FIX
//! [GATE-RECEIPT-ATTRIBUTION-ROWS-OUTLIVE-SKELETON]).
//!
//! A MACHINE writes a Proposed CLAIM, the gate holds it for the owner, and
//! the owner's own same-id revision lands as an `approved_amended` decision
//! with its Δ (FIX [OWNER-REVISION-AMEND-DELTA-UNCAPTURED]). The host then
//! records the amendment's routing facts and the judge settles it: the
//! receipt `gate:<hex>` keys an evidence row, a judgment, a preference note
//! and a cause row. The owner's hard delete leaves the decision as its
//! retention skeleton, which keeps the receipt id and outcome. On main the
//! skeleton lost its Δ but kept all four rows, naming the MACHINE the
//! skeleton no longer names. With the fix none is left, and an erase of
//! another claim leaves this receipt's rows as they were.
//!
//! The cause rows have no public read that shows a row whose judgment is
//! gone, so they are counted through a test door:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_amendment_attribution_erase`.
// `bind_host_owner` exists only under `test-support`; the door only under the cfg.
#![cfg(all(feature = "test-support", oneiron_test_support))]

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::HostSlipIssuer;
use oneiron::edit_distance::attribution::{
    AmendmentCause, AmendmentEvidence, amendment_evidence, amendment_judgments, judge_amendment,
    pending_preference_proposals, record_amendment_evidence,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::test_doors::gate_amendment_attribution as door;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, DeleteReason, EdgeActorClass,
    EntityId, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"gate-amendment-attribution-erase-test-owner";
const MACHINE_NOTE: &str = "a machine note";
const REVISED_NOTE: &str = "the owner's revised note";
const SCOPE: &str = "outbound";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, now: u64) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "person" })).expect("body");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("FIXTURE: a PERSON");
    id
}

/// A rooted vault with this install's keystore, an enrolled MACHINE and a
/// bound owner.
struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    signing: SigningKey,
    owner: EntityId,
    now: u64,
}

fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    // The owner's hard delete signs its receipt with this install's key, so
    // the keystore goes in as a host installs it after each open. Without it
    // the erase is refused at setup (proof9967, the owner-revision erase test).
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: this install's signing keys");
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[229; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [19; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    Seeded {
        _dir: dir,
        vault,
        machine,
        signing,
        owner,
        now,
    }
}

/// A CLAIM the MACHINE writes Proposed about a new PERSON, held for the
/// owner, then revised by the owner: an `approved_amended` decision with its
/// Δ. Returns the claim and the decision's receipt id.
fn owner_amended_claim(seeded: &Seeded) -> (EntityId, String) {
    let vault = &seeded.vault;
    let now = seeded.now;
    let subject = person(vault, now);
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
        .claim_candidate(&target, candidate, &signed, at(now), now)
        .commit()
        .expect("FIXTURE: the machine birth");

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
        .claim_candidate(&target, successor, &revision, at(now), now)
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
    (target, format!("gate:{}", amended.decision_id.to_hex()))
}

/// The host's routing facts for the amendment under `receipt`, and the
/// judge's settlement: the decider wanted it otherwise, so the judgment is
/// one `preference_shift` share with its preference note and cause row.
fn judge(seeded: &Seeded, receipt: &str) {
    let evidence = AmendmentEvidence::new(receipt, seeded.machine, SCOPE)
        .at(seeded.now)
        .with_cause(AmendmentCause::DeciderPreference);
    record_amendment_evidence(&seeded.vault, &evidence).expect("FIXTURE: the amendment evidence");
    judge_amendment(&seeded.vault, receipt)
        .expect("FIXTURE: the judging pass")
        .expect("FIXTURE: the judge settles the amendment");
}

/// The amendment rows the vault keeps under `receipt`, by name.
fn rows_kept(vault: &Vault, receipt: &str) -> Vec<&'static str> {
    let mut kept = Vec::new();
    if amendment_evidence(vault, receipt)
        .expect("evidence read")
        .is_some()
    {
        kept.push("evidence");
    }
    if amendment_judgments(vault)
        .expect("judgment read")
        .iter()
        .any(|judgment| judgment.receipt_id == receipt)
    {
        kept.push("judgment");
    }
    if pending_preference_proposals(vault)
        .expect("preference read")
        .iter()
        .any(|note| note.receipt_id == receipt)
    {
        kept.push("preference");
    }
    let (causes, attempts) = door::amendment_cause_rows(vault, receipt).expect("cause rows read");
    if causes > 0 {
        kept.push("cause");
    }
    if attempts > 0 {
        kept.push("attempt index");
    }
    kept
}

#[test]
fn an_erase_of_an_owner_amended_claim_leaves_no_attribution_under_its_receipt() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &receipt);
    assert_eq!(
        rows_kept(&seeded.vault, &receipt),
        vec!["evidence", "judgment", "preference", "cause"],
        "FIXTURE: the settled amendment keeps its rows under the receipt before the erase"
    );

    seeded
        .vault
        .delete_entity_with_reason(&target, DeleteReason::UserHardDelete)
        .expect("the owner's erase of the claim");

    let skeleton = seeded
        .vault
        .gate_decisions(1_000)
        .expect("ledger read after the erase")
        .into_iter()
        .find(|record| format!("gate:{}", record.decision_id.to_hex()) == receipt)
        .expect("the erase keeps the amended approval as its retention skeleton");
    assert!(
        skeleton.redacted_at.is_some() && skeleton.actor_ref.is_none(),
        "the erase redacts the amended approval: {skeleton:?}"
    );
    let kept = rows_kept(&seeded.vault, &receipt);
    assert!(
        kept.is_empty(),
        "the erase leaves no amendment attribution under the skeleton's receipt: {kept:?}"
    );
}

#[test]
fn an_erase_of_another_claim_keeps_the_amended_receipts_attribution() {
    let seeded = seed();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &receipt);
    let (other, other_receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &other_receipt);

    seeded
        .vault
        .delete_entity_with_reason(&other, DeleteReason::UserHardDelete)
        .expect("the owner's erase of the other claim");

    assert_eq!(
        rows_kept(&seeded.vault, &receipt),
        vec!["evidence", "judgment", "preference", "cause"],
        "an erase of another claim leaves this receipt's rows as they were"
    );
}

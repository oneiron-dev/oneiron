//! The vault owner's own same-id revision of a held MACHINE claim answers the
//! question the claim asked (MACHINE-BIRTH-HELD-QUESTION-OWNER-SUCCESSOR = A,
//! Engine 21 Nov 03:24; FIX [MACHINE-BIRTH-HELD-QUESTION-OWNER-SUCCESSOR-STALE]).
//!
//! A MACHINE writes a Proposed CLAIM T, and the gate holds it for the owner:
//! a tray row bound to the birth's body. The owner then writes an ordinary
//! same-id successor of T (UserStated, Auto, another value). That revision
//! is the owner's answer. It lands, the tray row goes, and the ledger records
//! an `approved_amended` decision for the row, the outcome the inbox's
//! approve-with-edit records. On main the owner's Allow write redeemed the
//! row against its own body and was refused `Gate(GateConsentStale)`.
//!
//! The amended approval also records its Δ, from the body the row showed to
//! the owner's revision, as the inbox's does (FIX
//! [OWNER-REVISION-AMEND-DELTA-UNCAPTURED]).
//!
//! Only the owner's own write answers. A human the host key binds who is not
//! the vault's owner, and an agent, still land nothing, and the machine's
//! question stays open.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! owner_revision_answers_held_machine_claim`.
// `bind_host_owner` and `bind_host_actor` exist only under `test-support`.
#![cfg(feature = "test-support")]

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::HostSlipIssuer;
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"owner-revision-answers-held-machine-claim-test-owner";
const MACHINE_NOTE: &str = "a machine note";
const REVISED_NOTE: &str = "the owner's revised note";
const OWNER_REVISION_AMEND: &str = "gate.consent.owner_revision_amend";

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

/// A rooted vault whose enrolled MACHINE wrote T Proposed: the gate holds
/// T for its owner.
struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    subject: EntityId,
    target: EntityId,
    now: u64,
}

fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let subject = person(&vault, now);
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[227; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [18; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");

    let target = EntityId::now();
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(MACHINE_NOTE),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::from("machine output")).expect("provenance"),
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault
        .machine_claim_transcript(&target, &candidate, &envelope)
        .expect("FIXTURE: machine transcript");
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, at(now), now)
        .commit()
        .expect("FIXTURE: the machine birth");
    Seeded {
        _dir: dir,
        vault,
        issuer,
        subject,
        target,
        now,
    }
}

/// The content binding of the tray row that holds `target` for its owner,
/// if one does.
fn held_row(vault: &Vault, target: EntityId) -> Option<Vec<u8>> {
    vault
        .pending_gate_consents(1_000)
        .expect("tray read")
        .into_iter()
        .find(|row| row.claim_id == *target.as_bytes())
        .map(|row| row.diff_handle)
}

/// `writer`'s ordinary same-id successor of T: another value, Auto.
fn revise(seeded: &Seeded, writer: WriteActor, source: ClaimSource) -> oneiron::Result<()> {
    let successor = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(seeded.subject),
        rmpv::Value::from(REVISED_NOTE),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        writer,
        source,
        WriteProvenance::new(rmpv::Value::from("person")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    seeded
        .vault
        .batch()
        .claim_candidate(
            &seeded.target,
            successor,
            &envelope,
            at(seeded.now),
            seeded.now,
        )
        .commit()
}

fn stored_note(seeded: &Seeded) -> rmpv::Value {
    seeded
        .vault
        .get_claim(&seeded.target)
        .expect("claim read")
        .expect("T is stored")
        .value
}

/// The writer's revision is refused, T keeps the machine's body, and the
/// machine's question is still the row the birth held.
fn assert_question_stays_open(seeded: &Seeded, outcome: oneiron::Result<()>, held: &[u8]) {
    let refusal = outcome.expect_err("a revision by anyone but the owner does not land");
    assert_eq!(
        stored_note(seeded),
        rmpv::Value::from(MACHINE_NOTE),
        "T keeps the machine's body after the refusal ({refusal:?})"
    );
    let row = held_row(&seeded.vault, seeded.target)
        .expect("the machine's question stays open after a refused revision");
    assert_eq!(
        row, held,
        "the open question still shows the body the machine proposed"
    );
}

#[test]
fn an_owner_revision_of_a_held_machine_claim_lands_as_the_owners_amended_approval() {
    let seeded = seed();
    let owner = seeded
        .vault
        .ensure_embedded_owner_actor()
        .expect("vault owner");
    bind_host_owner(&seeded.vault, &seeded.issuer, owner).expect("FIXTURE: owner binding");
    let held = held_row(&seeded.vault, seeded.target)
        .expect("FIXTURE: the gate holds the machine's proposal for its owner");

    revise(
        &seeded,
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
    )
    .expect("the owner's own revision of the held machine claim lands");

    let stored = seeded
        .vault
        .get_claim(&seeded.target)
        .expect("claim read")
        .expect("T is stored");
    assert_eq!(stored.value, rmpv::Value::from(REVISED_NOTE));
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert!(
        held_row(&seeded.vault, seeded.target).is_none(),
        "the owner's revision answers the machine's question: no tray row is left"
    );
    let amended: Vec<_> = seeded
        .vault
        .gate_decisions(1_000)
        .expect("ledger read")
        .into_iter()
        .filter(|record| {
            record.claim_id == Some(*seeded.target.as_bytes())
                && record.outcome == "approved_amended"
        })
        .collect();
    assert_eq!(
        amended.len(),
        1,
        "one amended approval answers the held row: {amended:?}"
    );
    assert_eq!(
        amended[0].reason_codes,
        vec![OWNER_REVISION_AMEND.to_owned()]
    );
    assert_eq!(
        amended[0].diff_handle, held,
        "the amended approval answers the row the machine's birth held"
    );
    let receipt_id = format!("gate:{}", amended[0].decision_id.to_hex());
    let delta = oneiron::edit_distance::delta::amendment_delta(&seeded.vault, &receipt_id)
        .expect("amendment delta read")
        .expect("the amended approval records its Δ to the owner's revision");
    assert_ne!(
        delta.proposed_ref, delta.final_ref,
        "the Δ runs from the revision the row showed to the owner's revision"
    );
    assert!(delta.d_norm > 0.0, "the owner rewrote the note: {delta:?}");
}

#[test]
fn a_non_owner_human_revision_of_a_held_machine_claim_lands_nothing() {
    let seeded = seed();
    let stranger = person(&seeded.vault, seeded.now);
    bind_host_actor(&seeded.vault, &seeded.issuer, stranger, "human")
        .expect("FIXTURE: a bound human who is not the vault's owner");
    let held = held_row(&seeded.vault, seeded.target)
        .expect("FIXTURE: the gate holds the machine's proposal for its owner");

    let outcome = revise(
        &seeded,
        WriteActor::new(stranger, EdgeActorClass::Human),
        ClaimSource::UserStated,
    );
    assert_question_stays_open(&seeded, outcome, &held);
}

#[test]
fn an_agent_revision_of_a_held_machine_claim_lands_nothing() {
    let seeded = seed();
    let agent = person(&seeded.vault, seeded.now);
    bind_host_actor(&seeded.vault, &seeded.issuer, agent, "agent").expect("FIXTURE: a bound agent");
    let held = held_row(&seeded.vault, seeded.target)
        .expect("FIXTURE: the gate holds the machine's proposal for its owner");

    let outcome = revise(
        &seeded,
        WriteActor::new(agent, EdgeActorClass::Agent),
        ClaimSource::Observed,
    );
    assert_question_stays_open(&seeded, outcome, &held);
}

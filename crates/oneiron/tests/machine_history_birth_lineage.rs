//! A machine birth control reads as the signed body it embeds (FIX
//! MACHINE-HISTORY-SOURCE-LINEAGE-SUBJECT-MOVE; Engine ANSWER 20 Nov 20:44:
//! "the history control's source audience and word sources follow the
//! birth's recorded subject and sources (the signed initial body), not the
//! live subject").
//!
//! Every control of a machine CLAIM T names T, and its birth control embeds
//! T's signed initial body. The owner's ordinary same-id successor may move T
//! to another subject (the subject is no part of the record-scope stamp), so a
//! source walk that went control -> T -> T's live subject judged the birth by
//! a subject its words never came from.
//!
//! The vault holds T, born from a machine about S with a secret word W, then
//! re-put by the vault owner as a successor about a free PERSON P without W,
//! and a Member grant for M. S is either a row bound to a source audience M is
//! not in (`test_doors::source_audience_binding::bound_row`) or a free PERSON.
//! - Test 1 (red on main): with S bound, M's `machine_history_page` of T is
//!   refused and no row of it holds W. On main the walk reached only P, so the
//!   page served the birth holding W.
//! - Test 2 (red on main): with S bound, M's selector window still carries
//!   the live T but no row holding W. On main it carried T's birth control
//!   holding W.
//! - Guard 3: with S a free PERSON, M's page serves T's whole history, the
//!   birth included, and M's window carries T and the birth: the fix refuses
//!   only what the birth's own subject binds.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test machine_history_birth_lineage`.
// `put_selector_test_federation_grant` exists only under `test-hooks`,
// `bind_host_owner` only under `test-support`, and the source-audience door
// only under the cfg flag.
#![cfg(all(oneiron_test_support, feature = "test-hooks", feature = "test-support"))]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::HostSlipIssuer;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::sync::residence::{MachineHistoryPage, machine_history_page};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::test_doors::source_audience_binding::bound_row;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"machine-history-birth-lineage-test-owner";
/// The word T's birth holds and its successor drops.
const BIRTH_WORD: &str = "zxqw-bound-birth-lineage-quixotic-61";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, id: EntityId, now: u64) {
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "person" })).expect("body");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("FIXTURE: a PERSON");
}

fn read_authority() -> Scope {
    let mut authority = Scope::top();
    authority.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    authority
}

/// A MACHINE enrolled under `issuer`'s host root writes T (`target`) about
/// `subject`, holding [`BIRTH_WORD`]: a Proposed machine birth.
fn seed_machine_birth(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    subject: EntityId,
    target: EntityId,
    now: u64,
) {
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[226; 32]);
    vault
        .enroll_machine_identity(
            issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [17; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");

    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(format!("a machine note {BIRTH_WORD}")),
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
}

/// What T's birth is about.
#[derive(Clone, Copy)]
enum BirthSubject {
    /// A row bound to a source audience whose only reader is not the member.
    Bound,
    /// A PERSON nothing binds.
    Free,
}

struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    selector: SyncSelector,
    target: EntityId,
    now: u64,
}

/// The vault, the member's selector and T: a machine birth of T about the
/// subject `birth`, holding [`BIRTH_WORD`], then the owner's ordinary
/// successor about a free PERSON without it, and a Member grant.
fn seed(birth: BirthSubject) -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let member = EntityId::now();
    let mailbox_reader = EntityId::now();
    let successor_subject = EntityId::now();
    person(&vault, member, now);
    person(&vault, mailbox_reader, now);
    person(&vault, successor_subject, now);
    let birth_subject = match birth {
        BirthSubject::Bound => {
            bound_row(&vault, mailbox_reader)
                .expect("FIXTURE: a row bound to the mailbox reader's source audience")
                .0
        }
        BirthSubject::Free => {
            let subject = EntityId::now();
            person(&vault, subject, now);
            subject
        }
    };
    let target = EntityId::now();
    seed_machine_birth(&vault, &issuer, birth_subject, target, now);

    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    let successor = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(successor_subject),
        rmpv::Value::from("a successor note"),
        1.0,
    );
    let owner_envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("person")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(&target, successor, &owner_envelope, at(now), now)
        .commit()
        .expect("FIXTURE: the owner's successor about another subject lands");
    let live = vault
        .get_claim(&target)
        .expect("FIXTURE: claim read")
        .expect("FIXTURE: T is stored");
    assert_eq!(
        live.subject,
        ClaimSubject::Entity(successor_subject),
        "FIXTURE: the successor moved T to its new subject"
    );

    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        own_device_residence_scope(),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_authority();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("FIXTURE: the member grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    Seeded {
        _dir: dir,
        vault,
        selector,
        target,
        now,
    }
}

fn holds_word(raw: &[u8]) -> bool {
    raw.windows(BIRTH_WORD.len())
        .any(|window| window == BIRTH_WORD.as_bytes())
}

/// The member's page of T's whole history.
fn member_page(seeded: &Seeded) -> MachineHistoryPage {
    machine_history_page(
        &seeded.vault,
        own_device_residence_scope(),
        &seeded.selector,
        seeded.target,
        None,
    )
    .expect("the member's history page")
}

/// Every row of `doc`'s entities map, by id, with its bytes.
fn entity_rows(doc: &LoroDoc) -> Vec<(EntityId, Vec<u8>)> {
    let mut rows = Vec::new();
    doc.get_map("entities").for_each(|key, value| {
        let id = EntityId::from_hex(key).expect("an entity key");
        let bytes = match value {
            ValueOrContainer::Value(LoroValue::Binary(blob)) => blob.to_vec(),
            _ => Vec::new(),
        };
        rows.push((id, bytes));
    });
    rows
}

/// The packed source window of the seed's moment and the member's selector
/// window filtered from it, each as its rows.
struct Windows {
    packed: Vec<(EntityId, Vec<u8>)>,
    carried: Vec<(EntityId, Vec<u8>)>,
}

/// [`Windows`] of the seed, after checking that the packed source holds T.
fn member_window(seeded: &Seeded) -> Windows {
    let key = WindowKey::from_timestamp(seeded.now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&seeded.vault, &source, &key).expect("FIXTURE: the window pack");
    let packed = entity_rows(&source);
    assert!(
        packed.iter().any(|(id, _)| *id == seeded.target),
        "FIXTURE: the packed window holds T"
    );
    let selected = filtered_window_doc(
        &seeded.vault,
        &source,
        &key,
        own_device_residence_scope(),
        &seeded.selector,
    )
    .expect("the member's selector window");
    Windows {
        packed,
        carried: entity_rows(&selected),
    }
}

#[test]
fn a_birth_about_a_bound_row_serves_the_member_no_history_page() {
    let seeded = seed(BirthSubject::Bound);
    match member_page(&seeded) {
        MachineHistoryPage::Refused => {}
        MachineHistoryPage::Rows { rows, .. } => {
            let leaked = rows.iter().any(|(_, raw)| holds_word(raw));
            panic!(
                "LEAK: the member's page served {} rows of T's history (birth word present: \
                 {leaked}); the birth's own subject is bound to a source audience the member \
                 is not in",
                rows.len()
            );
        }
        MachineHistoryPage::Pending => {
            panic!("FIXTURE: T's history resolves here, the page is not pending")
        }
    }
}

#[test]
fn a_birth_about_a_bound_row_leaves_the_member_window_without_the_birth() {
    let seeded = seed(BirthSubject::Bound);
    let windows = member_window(&seeded);
    assert!(
        windows.carried.iter().any(|(id, _)| *id == seeded.target),
        "FIXTURE: the member's selector window carries the live T, whose successor is about a \
         free PERSON"
    );
    let leaked: Vec<String> = windows
        .carried
        .iter()
        .filter(|(_, raw)| holds_word(raw))
        .map(|(id, _)| id.to_hex())
        .collect();
    assert!(
        leaked.is_empty(),
        "LEAK: the member's selector window carries rows holding the birth's word {leaked:?} \
         (T's birth control); the birth's own subject is bound to a source audience the member \
         is not in"
    );
}

#[test]
fn a_birth_about_a_free_row_still_serves_the_member_whole_history() {
    let seeded = seed(BirthSubject::Free);
    let (rows, more) = match member_page(&seeded) {
        MachineHistoryPage::Rows { rows, more, .. } => (rows, more),
        other => panic!("the member's page serves T's history, got {other:?}"),
    };
    assert!(
        rows.len() >= 2 && !more,
        "one page holds T's whole history of at least two controls (the birth and its \
         handoff), got {} rows, more {more}",
        rows.len()
    );
    assert!(
        rows.iter().any(|(_, raw)| holds_word(raw)),
        "the member's page holds the free birth"
    );
    let windows = member_window(&seeded);
    let births: Vec<EntityId> = windows
        .packed
        .iter()
        .filter(|(_, raw)| holds_word(raw))
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        births.len(),
        1,
        "FIXTURE: one packed row, T's free birth control, holds the birth's word"
    );
    assert!(
        windows.carried.iter().any(|(id, _)| *id == seeded.target),
        "the member's selector window carries T"
    );
    assert!(
        windows.carried.iter().any(|(id, _)| *id == births[0]),
        "the member's selector window carries T's free birth control"
    );
}

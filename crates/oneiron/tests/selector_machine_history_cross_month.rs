//! A selector export over month M ships a machine CLAIM transitioned in M+1
//! together with its out-of-window signed controls (FIX
//! SELECTOR-MACHINE-HISTORY-CROSS-MONTH-TARGET-WITHHELD).
//!
//! A machine CLAIM T learned in August keeps August's window when its
//! September decay re-puts it, but the decay's event and handoff controls
//! are learned in September, so August's window never carries them and the
//! export's incomplete-target check withholds T. The export packs the absent
//! controls from stored truth into its detached copy before judging any row,
//! so the whole per-row judgement sees them and T ships with every control.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_machine_history_cross_month`.
#![cfg(all(oneiron_test_support, feature = "test-hooks", feature = "test-support"))]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::sync::residence::{MachineHistoryPage, machine_history_page};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, filtered_window_doc, filtered_window_doc_for_peer,
    put_selector_test_federation_grant,
};
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::write_envelope::claim_body::{ClaimDemotionAction, ClaimDemotionRung};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"selector-machine-history-cross-month-test-owner";

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
/// `subject` at `learned`: a Proposed machine birth on a non-critical
/// predicate, so no critical-confirm hold applies.
fn seed_machine_birth(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    subject: EntityId,
    target: EntityId,
    learned: u64,
) {
    let machine = EntityId::now();
    vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            at(learned),
            learned,
            b"machine",
        )
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
        rmpv::Value::from("a machine note"),
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
        .claim_candidate(&target, candidate, &signed, at(learned), learned)
        .commit()
        .expect("FIXTURE: the machine birth");
}

struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    selector: SyncSelector,
    target: EntityId,
    august: WindowKey,
    september: WindowKey,
}

/// The vault, the member's selector and T: a machine birth of T in August,
/// decayed in September, and a Member grant. Both writes carry fixed past
/// times inside their months; the wall clock is never read.
fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let august = WindowKey::new("2026-08");
    let september = WindowKey::new("2026-09");
    let born = august.start_timestamp().expect("August starts") + 10 * 86_400;
    let decayed = september.start_timestamp().expect("September starts") + 10 * 86_400;

    let member = EntityId::now();
    let subject = EntityId::now();
    person(&vault, member, born);
    person(&vault, subject, born);
    let target = EntityId::now();
    seed_machine_birth(&vault, &issuer, subject, target, born);

    let demotion = vault
        .apply_claim_demotion(
            &target,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.4,
            },
            decayed,
        )
        .expect("FIXTURE: the September decay lands");
    assert_eq!(
        demotion.rung,
        ClaimDemotionRung::Decayed,
        "FIXTURE: T is stored decayed"
    );

    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        own_device_residence_scope(),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_authority();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, decayed)
        .expect("FIXTURE: the member grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    Seeded {
        _dir: dir,
        vault,
        selector,
        target,
        august,
        september,
    }
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

fn has(rows: &[(EntityId, Vec<u8>)], id: EntityId) -> bool {
    rows.iter().any(|(row, _)| *row == id)
}

/// The cold-packed source window of `key`: no live mirror, no sleeps.
fn packed_window(seeded: &Seeded, key: &WindowKey) -> Vec<(EntityId, Vec<u8>)> {
    let source = create_window_doc("selector", key);
    reverse_rematerialize(&seeded.vault, &source, key).expect("FIXTURE: the window pack");
    entity_rows(&source)
}

/// Every control id of T's stored history: the birth, the decay event and
/// both handoffs, from the member's history page of stored truth.
fn control_ids(seeded: &Seeded) -> Vec<EntityId> {
    match machine_history_page(
        &seeded.vault,
        own_device_residence_scope(),
        &seeded.selector,
        seeded.target,
        None,
    )
    .expect("the member's history page")
    {
        MachineHistoryPage::Rows { rows, more, .. } => {
            assert!(
                !more,
                "FIXTURE: one page holds T's whole history of one birth and one decay"
            );
            rows.into_iter().map(|(id, _)| id).collect()
        }
        other => panic!("FIXTURE: T's history resolves here, got {other:?}"),
    }
}

/// What it proves: the August export ships the September-decayed claim with
/// every control, packing the out-of-month event and handoff beside it.
///
/// Red on main 54f7ce11c55b: the out doc lacks T (the incomplete-target
/// check withholds it for the September controls August never carries).
#[test]
fn august_export_ships_a_september_decayed_claim_with_its_controls() {
    let seeded = seed();
    let controls = control_ids(&seeded);
    assert_eq!(
        controls.len(),
        4,
        "FIXTURE: T's history is the birth, one decay event and two handoffs"
    );
    let august_rows = packed_window(&seeded, &seeded.august);
    let september_rows = packed_window(&seeded, &seeded.september);
    assert!(
        has(&august_rows, seeded.target),
        "FIXTURE: the August source holds T, still learned in August"
    );
    assert!(
        !has(&september_rows, seeded.target),
        "FIXTURE: the September source lacks T"
    );
    let august_controls: Vec<EntityId> = controls
        .iter()
        .copied()
        .filter(|id| has(&august_rows, *id))
        .collect();
    let september_controls: Vec<EntityId> = controls
        .iter()
        .copied()
        .filter(|id| has(&september_rows, *id))
        .collect();
    assert_eq!(
        august_controls.len(),
        2,
        "FIXTURE: the August source holds the birth event and the genesis handoff"
    );
    assert_eq!(
        september_controls.len(),
        2,
        "FIXTURE: the September source holds the September event and handoff"
    );
    assert!(
        september_controls.iter().all(|id| !has(&august_rows, *id)),
        "FIXTURE: the August source lacks the September event and handoff"
    );

    let source = create_window_doc("selector", &seeded.august);
    reverse_rematerialize(&seeded.vault, &source, &seeded.august).expect("the August pack");
    let out = filtered_window_doc(
        &seeded.vault,
        &source,
        &seeded.august,
        own_device_residence_scope(),
        &seeded.selector,
    )
    .expect("the August export");
    let carried = entity_rows(&out);
    assert!(
        has(&carried, seeded.target),
        "the August export ships the September-decayed claim"
    );
    for id in &controls {
        assert!(
            has(&carried, *id),
            "the August export ships every control of T's history, missing {}",
            id.to_hex()
        );
    }
}

/// What it proves: the September export still ships the September controls
/// as ordinary rows of their own month, and never T, which is not in that
/// window.
///
/// Green on main (guard).
#[test]
fn september_export_still_ships_the_controls_in_their_own_month() {
    let seeded = seed();
    let controls = control_ids(&seeded);
    let september_rows = packed_window(&seeded, &seeded.september);
    let september_controls: Vec<EntityId> = controls
        .iter()
        .copied()
        .filter(|id| has(&september_rows, *id))
        .collect();
    assert_eq!(
        september_controls.len(),
        2,
        "FIXTURE: the September source holds the September event and handoff"
    );

    let source = create_window_doc("selector", &seeded.september);
    reverse_rematerialize(&seeded.vault, &source, &seeded.september).expect("the September pack");
    let out = filtered_window_doc(
        &seeded.vault,
        &source,
        &seeded.september,
        own_device_residence_scope(),
        &seeded.selector,
    )
    .expect("the September export");
    let carried = entity_rows(&out);
    assert!(
        !has(&carried, seeded.target),
        "the September export never ships T, which is not in that window"
    );
    for id in &september_controls {
        assert!(
            has(&carried, *id),
            "the September export ships its own controls as ordinary rows, missing {}",
            id.to_hex()
        );
    }
}

/// What it proves: another vault's export of the August window is unchanged:
/// it still withholds the machine CLAIM, packing nothing for a reader whose
/// admission quarantines machine CLAIMs anyway.
///
/// Green on main (guard).
#[test]
fn another_vault_export_still_withholds_the_machine_claim() {
    let seeded = seed();
    let august_rows = packed_window(&seeded, &seeded.august);
    assert!(
        has(&august_rows, seeded.target),
        "FIXTURE: the August source holds T"
    );

    let source = create_window_doc("selector", &seeded.august);
    reverse_rematerialize(&seeded.vault, &source, &seeded.august).expect("the August pack");
    let out = filtered_window_doc_for_peer(
        &seeded.vault,
        &source,
        &seeded.august,
        own_device_residence_scope(),
        &seeded.selector,
        PeerMachine::Unknown,
    )
    .expect("another vault's export");
    let carried = entity_rows(&out);
    assert!(
        !has(&carried, seeded.target),
        "another vault's export still withholds the machine CLAIM"
    );
}

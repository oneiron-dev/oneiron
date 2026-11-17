//! A machine-history page resolves its target's history once (FIX
//! MACHINE-HISTORY-PAGE-PER-CONTROL-RESOLVE).
//!
//! A page judges every control of the history (RULING
//! SECREAD-HOME-MACHINE-HISTORY = A). Each control's causal check and its
//! disclosure scope rest on the target's verified history, which is the same
//! for every control of one target in one read. So one page folds that
//! history once, not once or twice per control: with N controls a page was
//! O(N^2) and a full paged fetch about N^3/128.
//!
//! The vault holds a public machine-born CLAIM T, re-put by the vault owner as
//! an ordinary same-id successor, as the server test
//! `machine_history_page_controls` builds it (its guard 4). A member whose
//! grant reads every control pages T's history straight through
//! `machine_history_page`, on the test's own thread. The cfg door
//! `history_resolutions` counts each fold of T's history on this thread; the
//! page must add exactly one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test machine_history_page_resolutions`.
// `put_selector_test_federation_grant` exists only under `test-hooks`, and
// `bind_host_owner` only under `test-support`.
#![cfg(all(oneiron_test_support, feature = "test-hooks", feature = "test-support"))]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::HostSlipIssuer;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::sync::residence::{MachineHistoryPage, machine_history_page};
use oneiron::sync::{SyncSelector, SyncSelectorWorld, put_selector_test_federation_grant};
use oneiron::test_doors::machine_history::history_resolutions;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"machine-history-page-resolutions-test-owner";

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

/// The vault, the member's selector and T: a public machine birth of T, then
/// the owner's ordinary successor, and a Member grant that reads every row.
fn seed() -> (tempfile::TempDir, Vault, SyncSelector, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let member = EntityId::now();
    let subject = EntityId::now();
    person(&vault, member, now);
    person(&vault, subject, now);
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[226; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [17; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");

    let target = EntityId::now();
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("a public machine note"),
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

    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    let successor = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("a public successor note"),
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
        .expect("FIXTURE: the public successor lands");

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
    (dir, vault, selector, target)
}

#[test]
fn a_history_page_resolves_its_target_history_once() {
    let (_dir, vault, selector, target) = seed();
    let before = history_resolutions(target);
    let page = machine_history_page(
        &vault,
        own_device_residence_scope(),
        &selector,
        target,
        None,
    )
    .expect("the member's history page");
    let resolutions = history_resolutions(target) - before;
    let (rows, more) = match page {
        MachineHistoryPage::Rows { rows, more, .. } => (rows, more),
        other => panic!("FIXTURE: the member's page serves T's history, got {other:?}"),
    };
    assert!(
        rows.len() >= 2 && !more,
        "FIXTURE: one page holds T's whole history of at least two controls (the birth and \
         its handoff), got {} rows, more {more}",
        rows.len()
    );
    assert_eq!(
        resolutions,
        1,
        "a page of {} controls resolved T's history {resolutions} times: it must resolve it \
         once, not once or more per control",
        rows.len()
    );
}

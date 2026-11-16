//! ROLES-CHECKIN P2.5, row 2k3b (ARCH-0082 #act-table "Key recovery (C)"
//! and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39): the
//! custody member drain doors, in the 2j apply shape.
//!
//! - `vault.custody.members.drain.begin`, `.drain.commit`, `.drain.folder`
//!   and `vault.custody.members.reenrol` take `check_in_ref`. An Owner's own
//!   act is never gated: its answer records the Owner's own-proof decision.
//! - With `check_in_ref` the Owner applies another asker's approved
//!   check-in for that door's exact effect on their own proof: it is spent
//!   before the custody journal acts (the journal is no vault writer), the
//!   answer names the asker as requester, and it applies once. A check-in
//!   for another member, or asked for another door, does nothing and stays
//!   unspent.
//! - The ticket and ack protocol is unchanged: an approved begin answers the
//!   ticket a retry answers, and the member's ack still commits the drain.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner, as in `check_in_erase_effects`. One
//! device-only secret gives this install a custody journal, and one
//! publication pass puts a folder member and a declared hosted member in its
//! required set.
//!
//! On the base (0eea18eac0d) this file does not build: the four requests
//! have no `check_in_ref`, their answers no `check_in`, and the two effect
//! digests do not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_custody_drain_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::path::{Path, PathBuf};

use oneiron::check_in::{ActClass, custody_drain_effect_digest, custody_reenrol_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::store::custody_protocol::{DeletionEvidence, EvidenceKind, TargetId, TargetSpec};
use oneiron::verbs::{
    CustodyDrainCommitRequest, CustodyMemberReenrolRequest, CustodyMemberRef,
    custody_folder_member_drain_as, custody_member_drain_begin_as, custody_member_drain_commit_as,
    custody_member_reenrol_as,
};
use oneiron::{EntityId, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const BEGIN: &str = "vault.custody.members.drain.begin";
const COMMIT: &str = "vault.custody.members.drain.commit";
const FOLDER_DRAIN: &str = "vault.custody.members.drain.folder";
const REENROL: &str = "vault.custody.members.reenrol";
const HOSTED: &str = "s3:offsite";
const CUSTODY_AT: u64 = 1_780_000_000;

/// The declared hosted member.
fn hosted() -> TargetSpec {
    TargetSpec::declared(HOSTED).expect("a declared hosted member")
}

/// Puts one device-only secret in custody, so this install keeps a custody
/// journal, and runs one publication pass: the folder member `root/custody`
/// and the hosted member join the required set. The folder.
fn custody_set(vault: &Vault, owner_proof: &AuthenticatedOwner, root: &Path) -> PathBuf {
    vault
        .register_secret_as_owner(
            owner_proof,
            &OwnerSecretRegistration {
                name: "deploy-key",
                class: CustodyClass::CustodyPortable,
                device_only: true,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"fixture-value",
            },
            CUSTODY_AT,
        )
        .expect("the owner registers a secret");
    let folder = root.join("custody");
    std::fs::create_dir_all(&folder).expect("the custody folder");
    vault
        .publish_custody(&folder, &[hosted()], None)
        .expect("one publication pass");
    folder
}

/// The ref of member `target_id`, applying `check_in_ref` when given.
fn member(target_id: &str, check_in_ref: Option<EntityId>) -> CustodyMemberRef {
    CustodyMemberRef {
        target_id: target_id.to_owned(),
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_folder_drain_and_reenrolment_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let custody = tempfile::tempdir().expect("tempdir");
    let folder = custody_set(&vault, &owner_proof, custody.path());
    let folder_id = TargetId::of_folder(&folder);
    let reenrol = |folder: &Path, check_in_ref: Option<EntityId>| {
        custody_member_reenrol_as(
            &vault,
            &owner_proof,
            CustodyMemberReenrolRequest {
                target_id: None,
                folder: Some(folder.to_string_lossy().into_owned()),
                scope: None,
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };

    let own =
        custody_folder_member_drain_as(&vault, &owner_proof, member(folder_id.as_str(), None))
            .expect("the owner drains the folder member on their own proof");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::KeyRecovery, None, None)),
        "the Owner's own drain records their own proof"
    );

    let digest = custody_reenrol_effect_digest(&TargetSpec::of_folder(folder.clone()));
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        REENROL,
        ActClass::KeyRecovery,
        &digest,
    );
    let other_folder = reenrol(&custody.path().join("elsewhere"), Some(asked));
    assert!(
        other_folder.is_err(),
        "an ask for another member re-enrols nothing: {other_folder:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");
    let back = reenrol(&folder, Some(asked)).expect("the owner applies the approved re-enrolment");
    assert!(back.revision > own.revision, "the member is back: {back:?}");
    assert_eq!(
        back.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the re-enrolment spent the check-in");

    let digest = custody_drain_effect_digest(folder_id.as_str());
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        FOLDER_DRAIN,
        ActClass::KeyRecovery,
        &digest,
    );
    let drained = custody_folder_member_drain_as(
        &vault,
        &owner_proof,
        member(folder_id.as_str(), Some(asked)),
    )
    .expect("the owner applies the approved drain");
    assert!(
        drained.revision > back.revision,
        "drained again: {drained:?}"
    );
    assert_eq!(
        drained.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the drain spent the check-in");
    let again = custody_folder_member_drain_as(
        &vault,
        &owner_proof,
        member(folder_id.as_str(), Some(asked)),
    );
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn the_owner_applies_an_approved_hosted_drain_begin_and_commit() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let custody = tempfile::tempdir().expect("tempdir");
    custody_set(&vault, &owner_proof, custody.path());
    let hosted = hosted();
    let digest = custody_drain_effect_digest(HOSTED);

    let own = custody_member_drain_begin_as(&vault, &owner_proof, member(HOSTED, None))
        .expect("the owner begins the drain on their own proof");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::KeyRecovery, None, None)),
        "the Owner's own begin records their own proof"
    );
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        BEGIN,
        ActClass::KeyRecovery,
        &digest,
    );
    let begun = custody_member_drain_begin_as(&vault, &owner_proof, member(HOSTED, Some(asked)))
        .expect("the owner applies the approved begin");
    assert_eq!(
        (begun.set_revision, &begun.operation_id),
        (own.set_revision, &own.operation_id),
        "a begin before the set changes answers the same ticket"
    );
    assert_eq!(
        begun.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the begin spent the check-in");

    let ticket = vault
        .begin_custody_member_drain_as(&owner_proof, hosted.id())
        .expect("the same ticket");
    let ack = ticket
        .ack(
            &hosted,
            DeletionEvidence {
                kind: EvidenceKind::ObjectVersionSweep,
                superseded_removed: 0,
                remaining_heads: 0,
                inventory_digest: "00".repeat(32),
            },
        )
        .expect("the member's ack");
    let commit = |check_in_ref: Option<EntityId>| {
        custody_member_drain_commit_as(
            &vault,
            &owner_proof,
            CustodyDrainCommitRequest {
                ack: ack.clone(),
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };
    let (begin_ask, _) = approved(
        &vault,
        owner,
        &owner_proof,
        BEGIN,
        ActClass::KeyRecovery,
        &digest,
    );
    let crossed = commit(Some(begin_ask));
    assert!(
        crossed.is_err(),
        "a begin's ask commits no drain: {crossed:?}"
    );
    assert!(!spent(&vault, &begin_ask), "a refused apply spends nothing");

    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        COMMIT,
        ActClass::KeyRecovery,
        &digest,
    );
    let committed = commit(Some(asked)).expect("the owner applies the approved commit");
    assert!(
        committed.revision > own.set_revision,
        "the member left the set: {committed:?}"
    );
    assert_eq!(
        committed.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the commit spent the check-in");
}

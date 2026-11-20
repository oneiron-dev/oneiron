//! Fix list row WHOLE-VAULT-RESTORE-CLAIM-AND-NOTE-SAME-AS (Engine ANSWER
//! CLAIM-NOTE-SAME-AS-RESTORE-PROOF = A, 20 Nov 10:11). A source vault's
//! Dreamer applied a `same_as` between two consolidated CLAIMs under the
//! owner's standing nightly-link grant, with the link's proposed status
//! claim. The owner's whole-vault restore installed the archived grant only
//! after the edge passes, so the link stayed out (counted in
//! `unrestored_same_as_links`) and its status claim stayed archive data
//! (`ClaimSubjectEdgeNotRestored`). Now the owner's restore installs its
//! archived standing grants before any row or link, and the link comes back
//! with its status claim when both CLAIMs and an active status claim come
//! back and a live grant of a live owner of this vault lets the Dreamer
//! apply it here.
//!
//! * `owner_restore_brings_a_granted_claim_pair_link_back`: the link and its
//!   proposed status claim come back; no link stays out.
//! * `owner_restore_keeps_a_claim_pair_link_out_once_its_grant_is_revoked`:
//!   the source's owner revoked the grant before the export; the revoked row
//!   comes back as inert history, so the link stays out, counted, and its
//!   status claim stays archive data.
//! * `actorless_import_keeps_a_claim_pair_link_out`: only the owner's restore
//!   installs an archived grant; the link stays out, counted.
//! * `the_owners_restore_keeps_a_diary_pair_link_out`: a link between two
//!   diary NOTEs proves only its residents' own submission
//!   (`Memory::link_diary_coreference`), and an imported diary has no local
//!   author here, so the link stays out, counted, on the owner's restore too.
//!
//! Red on 28685d83e78 (#9687's head, the base of this fix):
//! `owner_restore_brings_a_granted_claim_pair_link_back` finds no restored
//! link. The other three pass there and on the fix: they pin the doors and
//! cases the ruling keeps out.
//!
//! FIX OWNER-RESTORE-OF-GRANTED-CLAIM-PAIR-LINK-ABORTS (after-merge proof of
//! the fix above, 20 Nov): on the merged head the owner's restore in
//! `owner_restore_brings_a_granted_claim_pair_link_back` aborted whole with
//! `EntityNotFound`: the link's status claim was put with its link read in
//! the Surfaceable mode, which admits no proposed claim, and both restored
//! CLAIMs come back proposed. It runs red at the tests-only commit on main
//! and green at the fix, which reads that link in the Recorded mode on the
//! owner's restore of a proven CLAIM pair. The diary test's source is now a
//! rooted vault whose owner holds the root owner binding `grant_diary_read`
//! asks for; on a plain device vault it failed in its fixture at every head.
//! `owner_restore_brings_a_claim_about_a_granted_claim_pair_link_back`
//! (REVIEW-9744 P1): the source's owner also puts an ordinary claim about
//! the link; the owner's restore completes and brings the link and that
//! claim back. It runs red at 7674fd3a789, which reads only the status
//! claim's link in the Recorded mode, so the restore aborts at the other
//! claim, and green at the fix.
//!
//! Vaults in tempdirs. The CLAIM-pair source opens through
//! `test_doors::consolidation::open_dreamer_vault` and lands the link through
//! the Dreamer's derive door, as `derive_links.rs` does; every other step
//! goes through public doors. Each destination installs a keystore and this
//! install's signing keys, so its policy manifest is trusted and the write
//! gate runs, and opens at least one wall-clock second after its source
//! (sleep 1100 ms), as in `whole_vault_restore_seeds.rs`. The receipt's
//! count and omission reasons are read by their debug text.
//!
//! Needs the doors: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test
//! whole_vault_restore_claim_pair_same_as`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Cursor;

use oneiron::authority::MachineRole;
use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::claim::{COREFERENCE_STATUS_PROPOSED, PREDICATE_COREFERENCE_STATUS};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, SameAs, commit, commit_claims, mint_nightly_links, same_as_edge,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::json;

/// A fresh destination with this install's keystore and signing keys,
/// opened at least one wall-clock second after its source.
fn open_destination() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn export(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// Whether `archive` carries a `same_as` between `a` and `b`, either way.
fn archive_carries_link(vault: &Vault, archive: &[u8], a: EntityId, b: EntityId) -> bool {
    vault
        .read_whole_vault_archive(archive)
        .expect("read the archive back")
        .evidence_ledger
        .edges
        .iter()
        .any(|edge| {
            edge.kind == EdgeKind::SameAs as u8
                && ((edge.source == a.to_hex() && edge.target == b.to_hex())
                    || (edge.source == b.to_hex() && edge.target == a.to_hex()))
        })
}

/// Whether `vault` holds a `same_as` between `a` and `b`, either way.
fn holds_link(vault: &Vault, a: EntityId, b: EntityId) -> bool {
    vault
        .edge_exists(&a, EdgeKind::SameAs, &b)
        .expect("read the link")
        || vault
            .edge_exists(&b, EdgeKind::SameAs, &a)
            .expect("read the link")
}

/// The receipt's `unrestored_same_as_links`, read from its debug text.
fn unrestored_same_as_links(receipt: &WholeVaultImportReceipt) -> Option<usize> {
    let text = format!("{receipt:?}");
    let rest = text.split("unrestored_same_as_links: ").nth(1)?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// The reason the receipt's `destination_omissions` gives for `id`, by its
/// debug name.
fn omission_reason(receipt: &WholeVaultImportReceipt, id: EntityId) -> Option<String> {
    receipt
        .destination_omissions
        .iter()
        .find(|kept| kept.entity_id == id.to_hex())
        .map(|kept| format!("{:?}", kept.reason))
}

/// A source vault whose Dreamer landed two claims about one person, each
/// citing a TURN, and then a `same_as` between them, applied under the
/// owner's nightly-link grant.
struct ClaimPairSource {
    _dir: tempfile::TempDir,
    vault: Vault,
    first: EntityId,
    second: EntityId,
    status_claim: EntityId,
}

fn claim_pair_source() -> ClaimPairSource {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("the Dreamer's vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&BTreeMap::from([("role", "user")])).expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    let claim = |local, value| Claim {
        local,
        predicate: "preference.coffee",
        subject: Named::Stored(person),
        value: json!(value),
        evidence: vec![Named::Stored(turn)],
    };
    let committed = commit_claims(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-claims",
        &[
            claim("first", "an oat milk flat white"),
            claim("second", "a flat white with oat milk"),
        ],
    )
    .expect("the claims commit");
    let [first, second] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(first.landed && second.landed, "{:?}", committed.items);
    let (first, second) = (first.rows[0], second.rows[0]);
    mint_nightly_links(&vault).expect("the owner's grant");
    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-links",
        &[Derived::SameAs(SameAs {
            local: "same_as",
            source: Named::Stored(first),
            target: Named::Stored(second),
        })],
    )
    .expect("the link commits");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the link lands: {:?}", item.reasons);
    let [status_claim] = item.rows.as_slice() else {
        panic!("one status claim: {:?}", item.rows);
    };
    assert!(
        same_as_edge(&vault, first, second).expect("read the link"),
        "precondition: the owner's grant applies the link"
    );
    ClaimPairSource {
        _dir: dir,
        vault,
        first,
        second,
        status_claim: *status_claim,
    }
}

/// The source's archive, which carries the link.
fn claim_pair_archive(source: &ClaimPairSource) -> Vec<u8> {
    let archive = export(&source.vault);
    assert!(
        archive_carries_link(&source.vault, &archive, source.first, source.second),
        "precondition: the archive carries the claim-pair link"
    );
    archive
}

/// The link stays out of `dest`, counted, and its status claim stays archive
/// data, named in the receipt.
fn assert_claim_pair_link_out(
    dest: &Vault,
    receipt: &WholeVaultImportReceipt,
    source: &ClaimPairSource,
) {
    assert!(
        !holds_link(dest, source.first, source.second),
        "the claim-pair link stays out"
    );
    assert!(
        dest.get_claim(&source.status_claim)
            .expect("read the status claim")
            .is_none(),
        "its status claim stays archive data"
    );
    assert_eq!(
        unrestored_same_as_links(receipt),
        Some(1),
        "the receipt counts the link left out"
    );
}

#[test]
fn owner_restore_brings_a_granted_claim_pair_link_back() {
    let source = claim_pair_source();
    let archive = claim_pair_archive(&source);
    let (_dir, dest) = open_destination();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect("the owner's restore completes");
    assert!(
        dest.edge_exists(&source.first, EdgeKind::SameAs, &source.second)
            .expect("read the restored link"),
        "the claim-pair link comes back: unrestored {:?}, omissions {:?}",
        unrestored_same_as_links(&receipt),
        receipt.destination_omissions
    );
    let status = dest
        .get_claim(&source.status_claim)
        .expect("read the restored status claim")
        .expect("the link's status claim comes back");
    assert_eq!(status.predicate, PREDICATE_COREFERENCE_STATUS);
    assert_eq!(
        status.subject,
        ClaimSubject::Edge {
            source: source.first,
            kind: EdgeKind::SameAs,
            target: source.second,
        },
        "the restored status is about the restored link"
    );
    assert_eq!(
        status.value.as_str(),
        Some(COREFERENCE_STATUS_PROPOSED),
        "the status comes back proposed"
    );
    assert_eq!(status.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        omission_reason(&receipt, source.status_claim),
        None,
        "the status claim is not kept out"
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(0),
        "no link stays out"
    );
}

#[test]
fn owner_restore_brings_a_claim_about_a_granted_claim_pair_link_back() {
    let source = claim_pair_source();
    let annotation = EntityId::now();
    let at = source.vault.now_recorded_at();
    source
        .vault
        .put_claim(
            &annotation,
            &ClaimBody::new(
                "relationship.context",
                ClaimSubject::Edge {
                    source: source.first,
                    kind: EdgeKind::SameAs,
                    target: source.second,
                },
                rmpv::Value::from("both name one coffee order"),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("a claim body about the link"),
            TimeRange { start: at, end: at },
            at,
        )
        .expect("FIXTURE: the source's owner puts a claim about the claim-pair link");
    let archive = claim_pair_archive(&source);
    let (_dir, dest) = open_destination();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect("the owner's restore completes");
    assert!(
        dest.edge_exists(&source.first, EdgeKind::SameAs, &source.second)
            .expect("read the restored link"),
        "the claim-pair link comes back: unrestored {:?}, omissions {:?}",
        unrestored_same_as_links(&receipt),
        receipt.destination_omissions
    );
    let restored = dest
        .get_claim(&annotation)
        .expect("read the restored claim about the link")
        .expect("the claim about the link comes back");
    assert_eq!(
        restored.subject,
        ClaimSubject::Edge {
            source: source.first,
            kind: EdgeKind::SameAs,
            target: source.second,
        },
        "the restored claim is about the restored link"
    );
}

#[test]
fn owner_restore_keeps_a_claim_pair_link_out_once_its_grant_is_revoked() {
    let source = claim_pair_source();
    let proof = owner_proof(&source.vault);
    // The nightly-link grant among them: the owner revokes every live grant.
    let revoked: Vec<String> = source
        .vault
        .active_standing_consent_grants()
        .expect("read the live grants")
        .iter()
        .map(|grant| grant.bound().digest().to_hex())
        .collect();
    assert!(
        !revoked.is_empty(),
        "precondition: the source holds a grant"
    );
    for grant_ref in &revoked {
        source
            .vault
            .revoke_consent_grant(&proof, grant_ref)
            .expect("the owner revokes the grant");
    }
    assert!(
        same_as_edge(&source.vault, source.first, source.second).expect("read the link"),
        "precondition: the revoke leaves the applied link"
    );
    let archive = claim_pair_archive(&source);
    let (_dir, dest) = open_destination();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect("the owner's restore completes");
    assert_claim_pair_link_out(&dest, &receipt, &source);
    assert_eq!(
        omission_reason(&receipt, source.status_claim).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the status claim: {:?}",
        receipt.destination_omissions
    );
    assert!(
        dest.active_standing_consent_grants()
            .expect("read the live grants")
            .iter()
            .all(|grant| !revoked.contains(&grant.bound().digest().to_hex())),
        "a revoked grant comes back revoked"
    );
}

#[test]
fn actorless_import_keeps_a_claim_pair_link_out() {
    let source = claim_pair_source();
    let archive = claim_pair_archive(&source);
    let (_dir, dest) = open_destination();
    let receipt = dest
        .import_whole_vault_archive(&archive)
        .expect("the actorless import completes");
    assert_claim_pair_link_out(&dest, &receipt, &source);
}

fn put_diary(vault: &Vault, author: EntityId, markdown: &str) -> EntityId {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: author },
            markdown: markdown.into(),
            source_revision_ref: [0x7a; 16],
            mask: None,
        })
        .expect("author a private diary note");
    EntityId::from_hex(&receipt.id_hex).expect("the diary receipt's note id")
}

#[test]
fn the_owners_restore_keeps_a_diary_pair_link_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A rooted source whose embedded owner holds the active root owner
    // binding `grant_diary_read` asks for, as `context_board_rows_shown.rs`
    // roots its vault.
    let source = Vault::open_owned(dir.path(), VaultConfig::device()).expect("open the source");
    source.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    source
        .prepare_install_signing()
        .expect("load the source's signing keys");
    let issuer = source
        .bootstrap_host_slip_issuer()
        .expect("the source's host issuer");
    source
        .ensure_host_root_slip(&issuer)
        .expect("root the source under its host");
    source
        .provision_engine_machine_identities(&issuer)
        .expect("the source's engine machine identities");
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the source's serving install profile");
    let proof = owner_proof(&source);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source's owner");
    let other = put(&source, ENTITY_TYPE_PERSON, b"other diary author");
    let owner_diary = put_diary(&source, owner, "the owner's private thought");
    let other_diary = put_diary(&source, other, "the other author's private thought");
    let as_owner = source.memory(owner, EdgeActorClass::Human);
    as_owner
        .grant_diary_read(
            &proof,
            WriteActor::new(owner, EdgeActorClass::Human),
            other,
            &[],
        )
        .expect("the owner may read, and so export, the other author's diary");
    as_owner
        .link_diary_coreference(owner_diary, other_diary)
        .expect("the owner links the diary pair");
    assert!(
        holds_link(&source, owner_diary, other_diary),
        "precondition: the source holds the diary pair link"
    );
    let archive = export(&source);
    assert!(
        archive_carries_link(&source, &archive, owner_diary, other_diary),
        "precondition: the archive carries the diary pair link"
    );
    let (_dest_dir, dest) = open_destination();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner's restore completes");
    assert!(
        dest.entity_exists(&owner_diary).expect("read the diary")
            && dest.entity_exists(&other_diary).expect("read the diary"),
        "both diary entries come back, as imported notes"
    );
    assert!(
        !holds_link(&dest, owner_diary, other_diary),
        "the diary pair link stays out"
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(1),
        "the receipt counts the diary pair link left out"
    );
}

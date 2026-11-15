//! A removal archive's spool file is the caller's, and
//! `Vault::import_removal_archive` reads it three times: once for its digest,
//! once through the indexed archive reader, and once to stage the bytes it
//! keeps. On main nothing ties the staged bytes back to the checked digest,
//! so a file rewritten after the digest pass to another valid archive of the
//! same source vault is validated and kept as that archive while the import
//! records the first archive's digest (REMOVAL-IMPORT-KEPT-BODY-UNBOUND).
//! This test rewrites the spool deterministically between the digest pass and
//! the indexed read, through the `after_digest_pass` hook the import fires
//! there, and checks the rewritten delivery is refused and keeps nothing.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test removal_import_kept_body_unbound`.
#![cfg(oneiron_test_support)]

use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::authority::MachineRole;
use oneiron::batch::export::VAULT_ARCHIVE_FORMAT;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, REMOVAL_EXPORT_RETAIN_SECS,
    RemovalExportCopy, RemovalExportFile,
};
use oneiron::memory::MemoryExport;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::removal_import_kept_digest::{
    clear_after_digest_pass, kept_removal_archive_digest, set_after_digest_pass,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

/// The shared vault the fixture roots and shares.
const SHARED: u64 = 42;
/// Filler records between the two exports, so the two archives differ.
const FILLER_RECORDS: usize = 8;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted vault shared with its owner as its only Owner: rooted as a host
/// starts one (as in `check_in/owner_apply_fixture.rs`), then shared (as in
/// `shared_act_family_actor_erase.rs`). Its directory, the vault, its owner.
fn rooted_and_shared() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    let members = vec![InitialSharedMember { member_ref: owner, role: Some(Role::Owner) }];
    vault
        .initialize_shared_vault(&owner_proof, SHARED, None, &members, 1)
        .expect("a shared vault");
    assert!(
        vault
            .authority_vault_id()
            .expect("read the vault id")
            .is_some(),
        "the vault is rooted"
    );
    assert_eq!(
        vault
            .shared_vault_creation()
            .expect("read the creation")
            .expect("a creation")
            .vault_id,
        SHARED,
        "the creation names the shared vault"
    );
    (dir, vault, owner)
}

/// BLAKE3 of `bytes`, lowercase hex, as an archive digest names it.
fn digest_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The wall clock in seconds, as the store clock reads it.
fn wall_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |past| past.as_secs())
}

/// A removal copy of `digest` for `receipt`, delivered now to `owner` from
/// the shared vault. A receiver leaves the copy's inline archive empty.
fn removal_copy(
    receipt: EntityId,
    owner: EntityId,
    digest: &str,
    delivered_at: u64,
    expires_at: u64,
) -> RemovalExportCopy {
    RemovalExportCopy {
        receipt_id: receipt.to_hex(),
        vault_id: SHARED,
        member: owner.to_hex(),
        delivered_at,
        expires_at,
        export: MemoryExport {
            format: VAULT_ARCHIVE_FORMAT.to_owned(),
            archive: Vec::new(),
            digest: digest.to_owned(),
            holder_requests: Vec::new(),
            notices: Vec::new(),
        },
    }
}

/// The digest of the archive kept for `receipt`, once the import took it in.
fn kept_digest(vault: &Vault, owner: EntityId, receipt: EntityId, now: u64) -> String {
    let read = kept_removal_archive_digest(vault, owner, receipt, now)
        .expect("read the kept archive");
    let receipt_hex = receipt.to_hex();
    let Some(digest) = read else {
        panic!("the import took {receipt_hex} in but keeps nothing for it")
    };
    digest
}

#[test]
fn a_spool_rewritten_to_another_archive_after_the_digest_pass_is_refused_and_keeps_nothing() {
    let (_dir, vault, owner) = rooted_and_shared();
    let before = vault
        .export_whole_vault(true)
        .expect("the first archive")
        .bytes()
        .to_vec();
    for _ in 0..FILLER_RECORDS {
        let id = EntityId::now();
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, TimeRange { start: 1, end: 1 }, 1, b"human")
            .expect("a filler record");
    }
    let after = vault
        .export_whole_vault(true)
        .expect("the second archive")
        .bytes()
        .to_vec();
    let digest_before = digest_of(&before);
    let digest_after = digest_of(&after);
    assert_ne!(digest_before, digest_after, "the two archives differ");
    assert!(!before.is_empty() && !after.is_empty(), "neither archive is empty");

    let delivered_at = wall_now();
    let expires_at = delivered_at + REMOVAL_EXPORT_RETAIN_SECS;
    let spool_dir = tempfile::tempdir().expect("spool dir");
    let spool_path = spool_dir.path().join("removal-copy.spool");

    // The copy names the first archive's digest and its spool holds the
    // first archive; the hook overwrites the spool with the second archive
    // once the digest pass has checked the first, as a caller rewriting the
    // file between the import's passes would.
    std::fs::write(&spool_path, &before).expect("spool the first archive");
    let receipt = EntityId::now();
    let copy = removal_copy(receipt, owner, &digest_before, delivered_at, expires_at);
    // Read and write: the hook rewrites the spool through this same handle.
    let archive = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&spool_path)
        .expect("open the spool");
    let mut file = RemovalExportFile::received(copy, archive);
    set_after_digest_pass(move |spool: &mut std::fs::File| {
        spool.set_len(after.len() as u64)?;
        spool.seek(SeekFrom::Start(0))?;
        spool.write_all(&after)?;
        spool.sync_all()?;
        spool.seek(SeekFrom::Start(0))?;
        Ok(())
    });
    let outcome = vault.import_removal_archive(owner, &mut file);
    clear_after_digest_pass();
    match outcome {
        Err(error) => assert!(
            error.to_string().contains("is not the bytes its digest names"),
            "the refusal names the digest mismatch, got {error}"
        ),
        Ok(answer) => panic!(
            "a spool rewritten after the digest pass is refused, got Ok({answer:?})"
        ),
    }
    assert_eq!(
        kept_removal_archive_digest(&vault, owner, receipt, delivered_at)
            .expect("read the kept archive"),
        None,
        "a refused delivery keeps nothing"
    );

    // Guard: the same import with no hook armed succeeds and keeps the
    // checked bytes, so the refusal above is caused by the rewrite.
    std::fs::write(&spool_path, &before).expect("spool the first archive");
    let receipt = EntityId::now();
    let copy = removal_copy(receipt, owner, &digest_before, delivered_at, expires_at);
    let archive = std::fs::File::open(&spool_path).expect("open the spool");
    let mut file = RemovalExportFile::received(copy, archive);
    let taken = vault
        .import_removal_archive(owner, &mut file)
        .expect("the unhooked import succeeds");
    assert!(taken.is_some(), "the unhooked delivery is taken in");
    assert_eq!(
        kept_digest(&vault, owner, receipt, delivered_at),
        digest_before,
        "the unhooked import keeps the checked bytes"
    );
}

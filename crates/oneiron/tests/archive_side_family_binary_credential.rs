//! [ARCHIVE-SIDE-FAMILY-BINARY-CREDENTIAL]: a tree-form side row whose short
//! binary payload holds a credential is withheld from the archive, while a
//! safe one still ships.
//!
//! * `a_short_binary_credential_withholds_its_side_row`: a blob head row
//!   whose 32-byte content hash is a Stripe-shaped test key stays home, and
//!   the manifest names it as held out for a credential. On main the row
//!   ships, its payload written as hex the nulling pass never reads.
//! * `a_safe_binary_side_row_still_ships`: the same row with
//!   credential-free bytes still ships, unnamed in the manifest's held-out
//!   list. A control against over-withholding; green on main too.
//!
//! Needs the door (green only: the door and the payload scan are new):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test archive_side_family_binary_credential`.
#![cfg(oneiron_test_support)]

use oneiron::batch::export::{ArchiveSideFamily, ArchiveSideWithheldReason};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::test_doors::archive_side_binary_credential::plant_blob_head_row;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A Stripe-shaped test key, exactly the 32 bytes of a blob content hash:
/// `sk_live_` plus a 24-character body, so the binary payload is itself the
/// credential. Not a live key; built from parts, as the scan's own tests
/// build theirs, so the source holds no key shape.
fn credential_hash() -> [u8; 32] {
    let key = ["sk", "_live_", "ABCD1234EFGH5678IJKL9012"].concat();
    key.as_bytes().try_into().expect("a 32-byte fixture key")
}

/// 32 credential-free bytes for the control row.
const SAFE_HASH: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

fn plant_artifact(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"fixture artifact",
        )
        .expect("artifact row");
}

#[test]
fn a_short_binary_credential_withholds_its_side_row() {
    let (_dir, vault) = open_vault();
    let artifact = EntityId::now();
    plant_artifact(&vault, &artifact);
    plant_blob_head_row(&vault, &artifact, credential_hash()).expect("head row");
    let export = vault.export_whole_vault(true).expect("whole-vault export");
    export.manifest().validate().expect("manifest validates");
    let document = vault
        .read_whole_vault_archive(export.bytes())
        .expect("archive reads back");
    let owner = artifact.to_hex();
    assert!(
        !document.side_tables.iter().any(|row| {
            row.family == ArchiveSideFamily::BlobHead
                && row.owner.as_deref() == Some(owner.as_str())
        }),
        "a side row whose short binary payload holds a credential stays home"
    );
    let held_out = &document.manifest.side_rows_withheld;
    assert!(
        held_out.iter().any(|withheld| {
            withheld.family == ArchiveSideFamily::BlobHead
                && withheld.owner.as_deref() == Some(owner.as_str())
                && withheld.reason == ArchiveSideWithheldReason::Credential
        }),
        "the manifest names the held-out row and why: {held_out:?}"
    );
}

#[test]
fn a_safe_binary_side_row_still_ships() {
    let (_dir, vault) = open_vault();
    let artifact = EntityId::now();
    plant_artifact(&vault, &artifact);
    plant_blob_head_row(&vault, &artifact, SAFE_HASH).expect("head row");
    let export = vault.export_whole_vault(true).expect("whole-vault export");
    export.manifest().validate().expect("manifest validates");
    let document = vault
        .read_whole_vault_archive(export.bytes())
        .expect("archive reads back");
    let owner = artifact.to_hex();
    assert!(
        document.side_tables.iter().any(|row| {
            row.family == ArchiveSideFamily::BlobHead
                && row.owner.as_deref() == Some(owner.as_str())
        }),
        "a side row whose binary payload holds no credential still ships"
    );
    let held_out = &document.manifest.side_rows_withheld;
    assert!(
        !held_out.iter().any(|withheld| {
            withheld.family == ArchiveSideFamily::BlobHead
                && withheld.owner.as_deref() == Some(owner.as_str())
        }),
        "no hold-out names the safe row: {held_out:?}"
    );
}

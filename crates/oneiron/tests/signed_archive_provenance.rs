//! L2-23: an archive's contents manifest is signed by the exporting install's
//! machine key, and the vault it is offered to judges that key on its own
//! fold. Only the owner's own device proves provenance (Engine RULING
//! L2-23-SIGNER = B): its signed archive of this vault reads
//! `ByteFaithfulOwnerRestore`, a machine of this vault in any other answered
//! role signs an archive that reads `ForeignAuthorityChain`, and an edited
//! manifest, a key this vault does not profile, an unanswered install's key
//! or a storage manifest alone proves nothing.
//!
//! Public doors only:
//! `cargo test --locked -p oneiron --all-features --test signed_archive_provenance`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::Signer;
use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::batch::export::{
    VaultImportClassification, VaultImportMismatch, VaultImportReceipt, WholeVaultDocumentManifest,
    archive_provenance_transcript,
};
use oneiron::deletion::parse_hex;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);

/// A personal vault rooted under its host, with a device keystore, and this
/// install profiled in `role`: the exporting machine whose key signs.
fn profiled_vault(
    directory: &Path,
    host_secret: &[u8],
    role: MachineRole,
) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(host_secret)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, role)?;
    let machine = vault
        .local_machine()?
        .expect("FIXTURE: this install has a machine once it is profiled");
    assert!(
        machine.profile.is_some(),
        "FIXTURE: the install is profiled"
    );
    assert_eq!(
        machine.mine,
        role == YOURS,
        "FIXTURE: only a `Yours` profile is the owner's own device here ({role:?})"
    );
    Ok(vault)
}

/// The vault's own archive manifest, as its export writes it.
fn own_archive_manifest(vault: &Vault) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let export = vault.export_whole_vault(true)?;
    assert!(
        export.manifest().provenance.is_some(),
        "the export signs its archive's manifest with this install's machine key"
    );
    Ok(export.manifest_json()?)
}

fn assert_verdict(
    receipt: &VaultImportReceipt,
    classification: VaultImportClassification,
    mismatches: &[VaultImportMismatch],
) {
    assert_eq!(receipt.classification, classification, "{receipt:?}");
    assert_eq!(receipt.mismatches, mismatches, "{receipt:?}");
    assert_eq!(
        receipt.byte_faithful,
        classification == VaultImportClassification::ByteFaithfulOwnerRestore,
        "{receipt:?}"
    );
}

#[test]
fn own_device_signed_archive_classifies_byte_faithful_owner_restore() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(directory.path(), b"signed archive provenance own", YOURS)?;
    let manifest = own_archive_manifest(&vault)?;

    let receipt = vault.classify_vault_archive_manifest(&manifest, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ByteFaithfulOwnerRestore,
        &[],
    );
    Ok(())
}

/// The signature binds every member's digest: a member swapped under it
/// (another archive's rows under the owner's signed manifest) proves nothing.
#[test]
fn an_edited_archive_manifest_proves_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(directory.path(), b"signed archive provenance edit", YOURS)?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&own_archive_manifest(&vault)?)?;
    assert!(
        manifest["records"]
            .as_array()
            .is_some_and(|records| !records.is_empty()),
        "FIXTURE: the archive has a member"
    );
    let other_member = blake3::hash(b"another archive's rows").to_hex().to_string();
    assert_ne!(manifest["records"][0]["blake3"], other_member.as_str());
    manifest["records"][0]["blake3"] = other_member.into();

    let receipt = vault.classify_vault_archive_manifest(&serde_json::to_vec(&manifest)?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ReviewRequired,
        &[VaultImportMismatch::UnauthenticatedProvenance],
    );
    Ok(())
}

/// A valid signature over this vault's own manifest, by a key no machine of
/// this vault holds, under this install's own machine id.
#[test]
fn a_signature_by_a_key_this_vault_does_not_profile_proves_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(directory.path(), b"signed archive provenance forge", YOURS)?;
    let mut manifest: WholeVaultDocumentManifest =
        serde_json::from_slice(&own_archive_manifest(&vault)?)?;
    let vault_id: [u8; 32] = parse_hex(
        manifest
            .source_vault
            .vault_id
            .as_deref()
            .expect("a rooted vault's archive"),
    )
    .expect("hex vault id");
    let mut provenance = manifest.provenance.clone().expect("a signed archive");
    let machine = EntityId::from_hex(&provenance.machine)?;
    let forger = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    let forged_key = forger.verifying_key().to_bytes();
    let transcript = archive_provenance_transcript(&vault_id, machine, &forged_key, &manifest)?;
    provenance.machine_key = hex(&forged_key);
    provenance.signature = hex(&forger.sign(&transcript).to_bytes());
    manifest.provenance = Some(provenance);

    let receipt = vault.classify_vault_archive_manifest(&serde_json::to_vec(&manifest)?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ReviewRequired,
        &[VaultImportMismatch::UnauthenticatedProvenance],
    );
    Ok(())
}

#[test]
fn another_vaults_signed_archive_is_foreign() -> TestResult {
    let (local_directory, other_directory) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let local = profiled_vault(
        local_directory.path(),
        b"signed archive provenance local",
        YOURS,
    )?;
    let other = profiled_vault(
        other_directory.path(),
        b"signed archive provenance other",
        YOURS,
    )?;

    let receipt = local.classify_vault_archive_manifest(&own_archive_manifest(&other)?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ForeignAuthorityChain,
        &[VaultImportMismatch::AuthorityVaultId],
    );
    Ok(())
}

/// The storage door's contract: a storage manifest names no content, so it
/// never proves provenance, even when it came from the owner's own signed
/// archive.
#[test]
fn a_storage_manifest_alone_proves_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(
        directory.path(),
        b"signed archive provenance storage",
        YOURS,
    )?;
    let export = vault.export_whole_vault(true)?;
    assert!(export.manifest().provenance.is_some());

    let receipt =
        vault.classify_vault_import_manifest(&export.manifest().storage.to_json_pretty()?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ReviewRequired,
        &[VaultImportMismatch::UnauthenticatedProvenance],
    );
    Ok(())
}

/// Engine RULING L2-23-SIGNER = B: an export signed by a hosted, execution,
/// rented, or work or school machine of this vault reads foreign. A host's
/// signature is never the owner saying so.
#[test]
fn a_signed_export_by_a_machine_not_the_owners_device_reads_foreign() -> TestResult {
    for role in [
        MachineRole::HostedNode,
        MachineRole::ExecutionNode,
        MachineRole::Owned(MachineOwnership::Rented),
        MachineRole::Owned(MachineOwnership::WorkSchool),
    ] {
        let directory = tempfile::tempdir()?;
        let vault = profiled_vault(directory.path(), b"signed archive provenance host", role)?;

        let receipt =
            vault.classify_vault_archive_manifest(&own_archive_manifest(&vault)?, None)?;

        assert_eq!(
            receipt.classification,
            VaultImportClassification::ForeignAuthorityChain,
            "{role:?}: {receipt:?}"
        );
        assert_eq!(
            receipt.mismatches,
            [VaultImportMismatch::SignerNotOwnerDevice],
            "{role:?}: {receipt:?}"
        );
        assert!(!receipt.byte_faithful, "{role:?}");
    }
    Ok(())
}

/// An install the owner has not answered for reaches as an unprofiled one
/// does (`MachineRole::answered`): its signature proves nothing either way.
#[test]
fn an_unanswered_installs_signed_export_proves_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(
        directory.path(),
        b"signed archive provenance unanswered",
        MachineRole::Unanswered,
    )?;

    let receipt = vault.classify_vault_archive_manifest(&own_archive_manifest(&vault)?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ReviewRequired,
        &[VaultImportMismatch::UnauthenticatedProvenance],
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

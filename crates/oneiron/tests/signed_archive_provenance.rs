//! L2-23: an archive's contents manifest is signed by the exporting install's
//! machine key, and the vault it is offered to judges that key on its own
//! fold. Only the owner's own device proves provenance (Engine RULING
//! L2-23-SIGNER = B): its signed archive of this vault reads
//! `ByteFaithfulOwnerRestore`, a machine of this vault in any other answered
//! role signs an archive that reads `ForeignAuthorityChain`, and an edited
//! manifest, a key this vault does not profile, an unanswered install's key
//! or a storage manifest alone proves nothing.
//!
//! A `Yours` the signer's own install key carried for itself is a carrier's
//! word, not the owner's (Sol r1 P1 on 021b5375), so it proves nothing.
//!
//! Two review findings on the first head (Astra r1, 021ad4e5) are pinned too:
//! the export writes no key state (an install whose keystore slot is empty
//! exports unsigned and keeps its machine id), and a record member rewritten
//! between the reader's digest pass and its row pass is refused, so the
//! signed manifest never vouches for rows it does not bind.
//!
//! The fold's word on who signed a `Yours` is not the signature either (Sol
//! r2 P1 on 2b3c042b): the owner's own device proves an archive only by the
//! signed row of its `Yours` that this install holds. That one test reaches
//! the fold through `test_doors::archive_provenance`; the rest use public
//! doors only. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test signed_archive_provenance`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::Signer;
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::batch::export::{
    VaultImportClassification, VaultImportMismatch, VaultImportReceipt, WholeVaultDocumentManifest,
    archive_provenance_transcript,
};
use oneiron::deletion::parse_hex;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::archive_provenance::classify_archive_with_trusted_entry;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);

/// A personal vault rooted under its host, with a device keystore, and this
/// install profiled in `role`: the exporting machine whose key signs.
fn profiled_vault(
    directory: &Path,
    host_secret: &[u8],
    role: MachineRole,
) -> Result<Vault, Box<dyn std::error::Error>> {
    profiled_vault_with_keystore(
        directory,
        host_secret,
        role,
        Arc::new(MemoryKeystore::default()),
    )
}

/// [`profiled_vault`] whose device keystore is `keystore`.
fn profiled_vault_with_keystore(
    directory: &Path,
    host_secret: &[u8],
    role: MachineRole,
    keystore: Arc<MemoryKeystore>,
) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(host_secret)?;
    vault.install_device_keystore(keystore);
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

/// Sol r1 P1 (HOSTED-CARRIER-FIRST-PIN = D, "a carrier's word is not him
/// saying so"): this install, profiled in `role`, carries the owner's
/// `Yours` answer for itself with its own install key, and then signs its
/// export. The fold trusts that `Yours`, but it rests on the carrier's act
/// alone, which any linked machine can carry for itself, so the archive
/// proves no more than an unsigned one. On 021b5375 it read
/// `ByteFaithfulOwnerRestore`.
fn assert_self_carried_yours_proves_nothing(role: MachineRole, host_secret: &[u8]) -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(directory.path(), host_secret, role)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let machine = vault
        .local_machine()?
        .expect("FIXTURE: this install has a machine once it is profiled")
        .id;
    vault.set_machine_role(&proof, ActSurface::ThisInstall, machine, YOURS, None)?;
    assert!(
        vault
            .local_machine()?
            .expect("FIXTURE: this install keeps its machine")
            .mine,
        "FIXTURE: the fold trusts the `Yours` this install carried for itself ({role:?})"
    );

    let receipt = vault.classify_vault_archive_manifest(&own_archive_manifest(&vault)?, None)?;

    assert_verdict(
        &receipt,
        VaultImportClassification::ReviewRequired,
        &[VaultImportMismatch::UnauthenticatedProvenance],
    );
    Ok(())
}

/// [`assert_self_carried_yours_proves_nothing`] from the role every fresh
/// serving install starts in.
#[test]
fn an_unanswered_install_that_carries_its_own_yours_proves_nothing() -> TestResult {
    assert_self_carried_yours_proves_nothing(
        MachineRole::Unanswered,
        b"signed archive provenance self-carried unanswered",
    )
}

/// [`assert_self_carried_yours_proves_nothing`] from a hosted node: the
/// host's own machine answers `Yours` for itself.
#[test]
fn a_hosted_node_that_carries_its_own_yours_proves_nothing() -> TestResult {
    assert_self_carried_yours_proves_nothing(
        MachineRole::HostedNode,
        b"signed archive provenance self-carried hosted",
    )
}

/// Sol r2 P1 (on 2b3c042b): the fold's word on who signed a `Yours` is not
/// the signature. A checkpoint image the host attests supplies revisions
/// this install never folded, with their signers and classes, under any
/// entry hash. With the trusted revision of the owner's own device naming
/// an entry whose row this install does not hold, or one whose id is the
/// owner's PERSON row, its archive proves no more than an unsigned one. On
/// 2b3c042b both read `ByteFaithfulOwnerRestore`.
#[test]
fn an_owner_yours_whose_signed_row_is_not_held_here_proves_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = profiled_vault(directory.path(), b"signed archive provenance row", YOURS)?;
    let manifest = own_archive_manifest(&vault)?;
    let machine = vault
        .local_machine()?
        .expect("FIXTURE: this install has a machine once it is profiled")
        .id;
    let owner = vault.ensure_embedded_owner_actor()?;
    let mut owner_row = [0_u8; 32];
    owner_row[..16].copy_from_slice(owner.as_bytes());
    assert_verdict(
        &vault.classify_vault_archive_manifest(&manifest, None)?,
        VaultImportClassification::ByteFaithfulOwnerRestore,
        &[],
    );

    for entry in [[0x5e_u8; 32], owner_row] {
        let receipt = classify_archive_with_trusted_entry(&vault, &manifest, machine, entry)?;

        assert_verdict(
            &receipt,
            VaultImportClassification::ReviewRequired,
            &[VaultImportMismatch::UnauthenticatedProvenance],
        );
    }
    Ok(())
}

/// Astra r1 finding 1: the export writes no key state. An install whose
/// keystore slot is empty while the vault holds its device key's public half
/// (a lost keychain, a raw copy on another host) exports unsigned and keeps
/// its machine id. On 021ad4e5 the export's key load forgot that machine,
/// minted another, and signed with it.
#[test]
fn an_export_without_its_signing_seed_goes_out_unsigned_and_keeps_the_machine() -> TestResult {
    let directory = tempfile::tempdir()?;
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = profiled_vault_with_keystore(
        directory.path(),
        b"signed archive provenance seedless",
        YOURS,
        Arc::<MemoryKeystore>::clone(&keystore),
    )?;
    let machine = vault
        .local_machine()?
        .expect("FIXTURE: a profiled install has a machine")
        .id;

    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let export = vault.export_whole_vault(true)?;

    assert_eq!(
        export.manifest().provenance,
        None,
        "an install with no seed for its machine signs nothing"
    );
    vault.install_device_keystore(keystore);
    let after = vault
        .local_machine()?
        .expect("the install still has a machine");
    assert_eq!(
        after.id, machine,
        "the export must not forget this install's machine or mint another"
    );
    assert!(
        after.mine,
        "its own keystore still proves it the owner's own"
    );
    Ok(())
}

/// Astra r1 finding 2: a file-backed import checks each record member's
/// length and BLAKE3 in one pass and spools its rows in a second. A member
/// rewritten in place between the two (same length, same ZIP CRC-32, other
/// text) is refused: the rows read are the bytes the manifest binds, so its
/// signature never vouches for others. On 021ad4e5 the second read went
/// unchecked and the rewritten row was read as the archive's.
#[test]
fn a_record_member_rewritten_after_its_digest_pass_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::default())?;
    let original_name = "b".repeat(96);
    put_person(&vault, &original_name)?;
    let stored = stored_archive(vault.export_whole_vault(true)?.bytes())?;
    let unchanged = vault.read_whole_vault_archive_from(Cursor::new(stored.clone()))?;
    assert!(
        format!("{unchanged:?}").contains(&original_name),
        "FIXTURE: the stored archive reads, with its PERSON row"
    );

    let (rewritten, swap_at) = rewrite_member_keeping_crc(&stored, original_name.as_bytes())?;
    let mut source = RewrittenAfterFirstRead {
        original: stored,
        rewritten,
        position: 0,
        swap_at,
        swapped: false,
    };
    let outcome = vault.read_whole_vault_archive_from(&mut source);

    assert!(source.swapped, "FIXTURE: the digest pass read the member");
    match outcome {
        Err(error) => assert!(
            error.to_string().contains("does not match its digest"),
            "refused for the rewritten member, not another reason: {error}"
        ),
        Ok(document) => panic!(
            "a member rewritten after its digest pass was read as the archive's (the original \
             row still read: {})",
            format!("{document:?}").contains(&original_name)
        ),
    }
    Ok(())
}

fn put_person(vault: &Vault, name: &str) -> TestResult {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )?;
    vault.put_entity(
        &EntityId::now(),
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        &body,
    )?;
    Ok(())
}

/// `archive` with every member stored uncompressed, in the same order, so a
/// member's bytes stand in the file as they read.
fn stored_archive(archive: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut source = zip::ZipArchive::new(Cursor::new(archive))?;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for index in 0..source.len() {
        let mut member = source.by_index(index)?;
        let name = member.name().to_owned();
        let mut data = Vec::new();
        member.read_to_end(&mut data)?;
        writer.start_file(name, options)?;
        writer.write_all(&data)?;
    }
    Ok(writer.finish()?.into_inner())
}

/// `stored` with the first member holding `marker` rewritten: the marker's
/// first byte 'b' made 'z', and bit 0 of some of its later letters flipped
/// ('b' <-> 'c') so the member keeps its length and its ZIP CRC-32. Returns
/// the rewritten archive and the file offset just past the marker.
fn rewrite_member_keeping_crc(
    stored: &[u8],
    marker: &[u8],
) -> Result<(Vec<u8>, u64), Box<dyn std::error::Error>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(stored))?;
    let mut held = None;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index)?;
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes)?;
        if let Some(offset) = find(&bytes, marker) {
            held = Some((bytes, offset));
            break;
        }
    }
    let (data, offset) = held.expect("FIXTURE: a member holds the marker");
    assert_eq!(data[offset], b'b', "FIXTURE: the marker starts with 'b'");
    let free: Vec<usize> = (offset + 16..offset + marker.len()).collect();
    let flips = crc32_flips(&data, offset, b'b' ^ b'z', &free);
    let mut changed = data.clone();
    changed[offset] = b'z';
    for position in flips {
        changed[position] ^= 1;
    }
    assert_eq!(
        crc32(&changed),
        crc32(&data),
        "FIXTURE: the member keeps its CRC-32"
    );
    assert_ne!(changed, data, "FIXTURE: the member's text changed");
    let start = find(stored, &data).expect("FIXTURE: a stored member stands verbatim");
    let mut rewritten = stored.to_vec();
    rewritten[start..start + data.len()].copy_from_slice(&changed);
    Ok((rewritten, (start + offset + marker.len()) as u64))
}

/// The positions among `free` whose bit 0, flipped with `mask` at `changed`,
/// leaves `data`'s CRC-32 as it was. CRC-32 is affine over GF(2) for one
/// length, so each flip adds a fixed 32-bit vector: Gaussian elimination
/// finds the flips whose vectors sum to the change's.
fn crc32_flips(data: &[u8], changed: usize, mask: u8, free: &[usize]) -> Vec<usize> {
    assert!(free.len() <= 128, "FIXTURE: one u128 names the flips");
    let crc = crc32(data);
    let delta = |position: usize, bits: u8| {
        let mut flipped = data.to_vec();
        flipped[position] ^= bits;
        crc32(&flipped) ^ crc
    };
    // Each basis vector with the flips that sum to it; leading bits distinct,
    // kept in descending order.
    let mut basis: Vec<(u32, u128)> = Vec::new();
    for (index, &position) in free.iter().enumerate() {
        let (mut vector, mut flips) = (delta(position, 1), 1_u128 << index);
        for &(pivot, pivot_flips) in &basis {
            if vector ^ pivot < vector {
                vector ^= pivot;
                flips ^= pivot_flips;
            }
        }
        if vector != 0 {
            basis.push((vector, flips));
            basis.sort_by_key(|&(pivot, _)| std::cmp::Reverse(pivot));
        }
    }
    let (mut rest, mut chosen) = (delta(changed, mask), 0_u128);
    for &(pivot, pivot_flips) in &basis {
        if rest ^ pivot < rest {
            rest ^= pivot;
            chosen ^= pivot_flips;
        }
    }
    assert_eq!(rest, 0, "FIXTURE: the free bits reach every CRC-32");
    free.iter()
        .enumerate()
        .filter(|&(index, _)| chosen & (1_u128 << index) != 0)
        .map(|(_, &position)| position)
        .collect()
}

/// A seekable archive file rewritten in place once a read has passed
/// `swap_at`: reads before then see `original`, every later one `rewritten`.
struct RewrittenAfterFirstRead {
    original: Vec<u8>,
    rewritten: Vec<u8>,
    position: u64,
    swap_at: u64,
    swapped: bool,
}

impl Read for RewrittenAfterFirstRead {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let bytes = if self.swapped {
            &self.rewritten
        } else {
            &self.original
        };
        let start = usize::try_from(self.position).map_or(bytes.len(), |p| p.min(bytes.len()));
        let count = out.len().min(bytes.len() - start);
        out[..count].copy_from_slice(&bytes[start..start + count]);
        let before = self.position;
        self.position += count as u64;
        if before < self.swap_at && self.position >= self.swap_at {
            self.swapped = true;
        }
        Ok(count)
    }
}

impl Seek for RewrittenAfterFirstRead {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let len = i128::try_from(self.original.len()).expect("a test archive's length");
        let next = match to {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => len + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "negative seek"))?;
        Ok(self.position)
    }
}

/// CRC-32 (IEEE), the checksum a ZIP member carries.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

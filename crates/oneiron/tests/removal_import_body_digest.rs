//! FIX [REMOVAL-IMPORT-KEPT-BODY-UNBOUND] (Engine ANSWER EXPORTPROOF-NEXT-ROW
//! = A, 16 Nov 22:23): `Vault::import_removal_archive` keeps only the bytes
//! its copy's digest names, and keeps only bytes the whole-vault archive
//! reader read, whatever the caller's file holds later in the call. The door
//! `test_doors::removal_import_passes` rewrites the caller's file between the
//! import's passes over it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test removal_import_body_digest`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, RemovalExportCopy, RemovalExportFile,
    ScopeAxis,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::removal_import_passes::{self, RemovalImportPass};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const SHARED: u64 = 45;

/// Bytes the whole-vault archive reader refuses.
const NOT_AN_ARCHIVE: &[u8] = b"these bytes are not a whole-vault archive";

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// The key the removed person's slip binds; they prove it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// A slip this host mints `who`, holding `read` and `write`.
fn credential(vault: &Vault, issuer: &HostSlipIssuer, who: EntityId) -> CapabilitySlip {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = [0x51; 32];
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("the removed person's slip")
}

/// A holder proof for one request on `vault`'s clock: its timestamp, its
/// signature bytes and its nonce.
fn request(vault: &Vault, slip: &CapabilitySlip) -> (u64, Vec<u8>, String) {
    let proof = holder_proof(slip, &holder_key(), vault.now_recorded_at()).expect("a holder proof");
    let signature = proof["signature"].as_str().expect("a signature");
    let signature = (0..signature.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&signature[at..at + 2], 16).expect("hex"))
        .collect();
    (
        proof["timestamp"].as_u64().expect("a timestamp"),
        signature,
        proof["nonce"].as_str().expect("a nonce").to_owned(),
    )
}

/// An export-first removal at a home, and the removed person's device.
struct Removal {
    _home_dir: tempfile::TempDir,
    _receiver_dir: tempfile::TempDir,
    _held_dir: tempfile::TempDir,
    /// The removed person's device: a vault of its own that holds the
    /// home's authority history, so the archive names its authority as its
    /// source, and that keeps none of the archive yet.
    receiver: Vault,
    removed: EntityId,
    /// The removed person's slip, minted at the home before the removal.
    slip: CapabilitySlip,
    /// The removed person's archive as the home answers it, its archive
    /// taken out of the copy into `archive`.
    copy: RemovalExportCopy,
    archive: Vec<u8>,
    /// Where the caller's file lies: a named file the test may rewrite.
    held: PathBuf,
}

fn removal() -> Removal {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = Vault::open(home_dir.path(), VaultConfig::device()).expect("the home");
    home.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&home);
    home.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = home.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&home, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&home, owner);
    home.initialize_shared_vault(
        &owner_proof,
        SHARED,
        None,
        &[InitialSharedMember {
            member_ref: owner,
            role: Some(Role::Owner),
        }],
        1,
    )
    .expect("a shared vault");
    let removed = person(&home);
    let act = home
        .propose_add_owner(&owner_proof, SHARED, removed)
        .expect("the owner starts add_owner");
    home.execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once");
    let slip = credential(&home, &issuer, removed);
    let act = home
        .propose_remove_owner(&owner_proof, SHARED, removed, None, None, true)
        .expect("the owner starts an export-first remove_owner");
    home.execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("remove_owner runs at once");

    let (timestamp, signature, nonce) = request(&home, &slip);
    let mut answered: Vec<RemovalExportFile> = home
        .removed_owner_exports(
            Some(&issuer),
            &slip,
            timestamp,
            &signature,
            nonce.as_bytes(),
        )
        .expect("the removed person's archives");
    assert_eq!(answered.len(), 1, "one archive for the removed person");
    let mut json = Vec::new();
    answered[0]
        .write_json(&mut json)
        .expect("the archive's copy as JSON");
    let mut copy: RemovalExportCopy = serde_json::from_slice(&json).expect("the copy decodes");
    let archive = std::mem::take(&mut copy.export.archive);
    assert_eq!(
        blake3::hash(&archive).to_hex().as_str(),
        copy.export.digest,
        "the home's archive is its digest's bytes"
    );

    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let receiver = Vault::open(receiver_dir.path(), VaultConfig::device()).expect("the device");
    receiver.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    receiver
        .import_signed_authority_history(
            &home
                .export_signed_authority_history()
                .expect("the home's history"),
            &std::collections::BTreeMap::new(),
        )
        .expect("the device takes the home's history");
    assert_eq!(
        receiver
            .authority_vault_id()
            .expect("the device's authority"),
        home.authority_vault_id().expect("the home's authority"),
        "the device holds the home's authority"
    );
    let held_dir = tempfile::tempdir().expect("tempdir");
    let held = held_dir.path().join("removal-archive");
    Removal {
        _home_dir: home_dir,
        _receiver_dir: receiver_dir,
        _held_dir: held_dir,
        receiver,
        removed,
        slip,
        copy,
        archive,
        held,
    }
}

impl Removal {
    /// The caller's file: `bytes` written at `held`, opened for reading,
    /// with `copy` as the copy that names it.
    fn received(&self, copy: RemovalExportCopy, bytes: &[u8]) -> RemovalExportFile {
        std::fs::write(&self.held, bytes).expect("the caller's file");
        let file = std::fs::File::open(&self.held).expect("the caller's file opens");
        RemovalExportFile::received(copy, file)
    }

    /// Imports `file` while `hook` runs after each of the import's passes.
    fn import_with(
        &self,
        file: &mut RemovalExportFile,
        hook: impl FnMut(RemovalImportPass) + 'static,
    ) -> oneiron::Result<Option<u64>> {
        removal_import_passes::arm(hook);
        let imported = self.receiver.import_removal_archive(self.removed, file);
        removal_import_passes::disarm();
        imported
    }

    /// The digest of the archive the device keeps for the removal, as the
    /// removed person reads it there.
    fn kept_digest(&self) -> String {
        let (timestamp, signature, nonce) = request(&self.receiver, &self.slip);
        self.receiver
            .removed_owner_archive(
                None,
                &self.slip,
                timestamp,
                &signature,
                nonce.as_bytes(),
                &self.copy.receipt_id,
            )
            .expect("the device answers the removed person")
            .expect("the device keeps the archive")
            .digest()
            .to_owned()
    }
}

/// Writes `bytes` over the file at `path` in place: the same file, so a
/// handle opened on it before reads the new bytes.
fn rewrite(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("the caller's file is rewritten");
}

/// The row's case: the caller's file is rewritten after the archive read,
/// before the import stages it. The device keeps the bytes the copy's digest
/// names, never what the file held at staging (main kept the rewritten
/// bytes under the first digest).
#[test]
fn a_file_rewritten_before_staging_keeps_the_digest_bytes() {
    let removal = removal();
    let mut file = removal.received(removal.copy.clone(), &removal.archive);
    let held = removal.held.clone();
    let imported = removal.import_with(&mut file, move |pass| {
        if pass == RemovalImportPass::ArchiveRead {
            rewrite(&held, NOT_AN_ARCHIVE);
        }
    });
    assert!(
        matches!(imported, Ok(Some(_))),
        "the genuine archive is taken in: {imported:?}"
    );
    assert_eq!(
        removal.kept_digest(),
        removal.copy.export.digest,
        "the device keeps the bytes the copy's digest names"
    );
}

/// The file shows a genuine archive to the archive read alone, and the
/// copy's digest names other bytes. Those bytes were never read through the
/// archive reader, so the import refuses them (main kept them unread).
#[test]
fn a_file_shown_as_an_archive_only_to_the_archive_read_is_refused() {
    let removal = removal();
    let mut copy = removal.copy.clone();
    copy.export.digest = blake3::hash(NOT_AN_ARCHIVE).to_hex().to_string();
    let mut file = removal.received(copy, NOT_AN_ARCHIVE);
    let held = removal.held.clone();
    let genuine = removal.archive.clone();
    let imported = removal.import_with(&mut file, move |pass| match pass {
        RemovalImportPass::Digest => rewrite(&held, &genuine),
        RemovalImportPass::ArchiveRead => rewrite(&held, NOT_AN_ARCHIVE),
    });
    assert!(
        imported.is_err(),
        "bytes never read as an archive are refused: {imported:?}"
    );
    assert!(
        !removal
            .receiver
            .removal_archive_imported(
                removal.removed,
                EntityId::from_hex(&removal.copy.receipt_id).expect("a receipt id"),
                removal.copy.delivered_at,
            )
            .expect("the import rows read"),
        "nothing is taken in"
    );
}

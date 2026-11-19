#![cfg(all(oneiron_test_support, feature = "sync"))]
//! A kit restore reads its publisher under the kit's own root (FIX
//! FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES, design 3.2).
//!
//! P pins the owner's kit root K, is Yours only through K's anchor mark, and
//! keeps the bootstrap Unanswered roster head (no answered roster revision).
//! P seals a cadence bundle (no publication request) to K. A fresh install Q,
//! pinning no root, restores it with K's seed.
//!
//! The restore checks the publisher before `restore_world_keys` pins K. Read
//! under Q's own pin (none), no chain answers P, and the restore refuses with
//! "no machine the owner vouched for or asked to publish signed the bundle".
//! Read under the kit's root once the seed gate accepts the seed, K's mark
//! answers P, the restore lands, and Q pins K.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};

use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityVaultId, Destination, HostSlipIssuer,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, MachineOwnership, MachineRole,
    OwnerRootRecord, authority_entry_hash, authority_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::sync::WindowManager;
use oneiron::sync::bridge::Materializer;
use oneiron::world_keys::{KitConfirmation, RecoveryRootSeed, sealed_bundle_slot};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: Vec::new(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

fn vault_id_of(vault: &Vault) -> AuthorityVaultId {
    vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted")
}

/// A self-host vault rooted under the host root before its first serving
/// start: no chain profiles this install yet.
fn unprofiled_self_host() -> (Arc<Vault>, HostSlipIssuer, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    (Arc::new(vault), issuer, dir)
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    /// The owner's PERSON, bound to a live human actor.
    person: EntityId,
    /// This install, the publisher of the bundle below.
    carrier: EntityId,
    _issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let (vault, issuer, dir) = unprofiled_self_host();
        let carrier = vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain")
            .profile
            .machine;
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            person,
            carrier,
            _issuer: issuer,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        vault_id_of(&self.vault)
    }
}

/// The kit's root record, anchor-signed and stored: the stored root a drawn
/// seed's restore needs, since the kit seed gate publishes a drawn root only
/// through its activation. Names the vault's owner.
fn publish_kit_root(vault: &Vault, owner: EntityId, seed: &RecoveryRootSeed) -> AuthorityEntryHash {
    let vault_id = vault_id_of(vault);
    let root = seed.public(&vault_id).expect("the kit root's public half");
    let anchor = seed.anchor();
    let parent = vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner,
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let entry = signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    let root_hash = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the kit's root row is stored");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&root_hash),
        "guard: the kit's root is in valid_entries"
    );
    root_hash
}

/// A fresh install that holds no vault yet: opened, keyed, and owner-proofed,
/// but never rooted, profiled, or pinned. Its vault id and pin are None, so
/// the bundle's authority import sets the vault id and the restore pins K.
fn fresh_unrooted_vault() -> (Arc<Vault>, AuthenticatedOwner, EntityId, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("fresh vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof on the fresh install");
    (Arc::new(vault), owner, person, dir)
}

fn manager_for(vault: Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "kit-restore-test",
    ))
}

/// P pins K, is Yours only via K, and keeps an Unanswered roster head; P
/// seals a cadence bundle to K; fresh Q restores it with K's seed and pins K.
#[test]
fn a_kit_restore_reads_its_publisher_under_the_kits_own_root() {
    let served = ServedVault::self_host();
    let p = served.carrier;
    let vault_id = served.vault_id();
    {
        let fold = served.vault.authority_fold().expect("authority fold");
        assert_eq!(fold.pinned_root, None, "guard: P starts unpinned");
        let folded = fold.machine(p).expect("guard: P is a machine of the vault");
        let roster = folded.roster.as_ref().expect("guard: P has a roster chain");
        assert_eq!(
            roster.profile.role,
            MachineRole::Unanswered,
            "guard: P's roster head is the bootstrap Unanswered"
        );
        assert!(
            !roster.profile.role.answered(),
            "guard: P's roster head is not answered"
        );
        assert!(roster.is_live(), "guard: P's roster chain is live");
        assert!(
            folded
                .roster_trusted
                .as_ref()
                .is_none_or(|trusted| !trusted.profile.role.answered()),
            "guard: P's roster holds no answered revision"
        );
        assert!(
            fold.trusted_machine(p).is_none(),
            "guard: P is not mine before the kit"
        );
    }

    let seed = RecoveryRootSeed::generate().expect("the kit's seed");
    let root = seed.public(&vault_id).expect("the kit root's public half");
    let root_id = root.id;
    let anchor_key = seed.anchor().verifying_key().to_bytes();
    let root_hash = publish_kit_root(&served.vault, served.person, &seed);
    served
        .vault
        .restore_world_keys(
            &served.owner,
            &seed,
            Some(KitConfirmation::Fingerprint(root_id)),
        )
        .expect("P pins K and marks itself Yours under K");

    {
        let fold = served.vault.authority_fold().expect("authority fold");
        assert_eq!(
            fold.pinned_root.map(|pin| pin.id),
            Some(root_id),
            "guard: P pins K"
        );
        assert_eq!(
            fold.pinned_root.map(|pin| pin.anchor_key),
            Some(anchor_key),
            "guard: P pins K's anchor"
        );
        assert!(
            fold.valid_entries.contains(&root_hash),
            "guard: K's root stays valid"
        );
        let folded = fold.machine(p).expect("guard: P is a machine of the vault");
        let roster = folded
            .roster
            .as_ref()
            .expect("guard: P keeps its roster chain");
        assert_eq!(
            roster.profile.role,
            MachineRole::Unanswered,
            "guard: P's roster head stays Unanswered"
        );
        assert!(
            !roster.profile.role.answered(),
            "guard: P's roster head is not answered"
        );
        assert!(
            folded
                .roster_trusted
                .as_ref()
                .is_none_or(|trusted| !trusted.profile.role.answered()),
            "guard: P's roster chain holds no answered revision"
        );
        let chain = folded
            .anchored
            .get(&anchor_key)
            .expect("guard: K's chain holds P");
        assert!(chain.is_live(), "guard: K's chain holds P live");
        assert_eq!(
            chain.profile.role,
            MachineRole::Owned(MachineOwnership::Yours),
            "guard: K's anchor mark answers P Yours"
        );
        assert!(
            chain.profile.role.answered(),
            "guard: K's anchor mark is answered"
        );
        assert_eq!(
            chain.profile.machine_key, roster.profile.machine_key,
            "guard: K's mark names P's machine key"
        );
        assert_eq!(
            chain.profile.encryption_key, roster.profile.encryption_key,
            "guard: K's mark names P's encryption key"
        );
        assert!(
            fold.trusted_machine(p).is_some(),
            "guard: P is mine under K, so it may seal"
        );
    }

    let manager_p = manager_for(Arc::clone(&served.vault));
    let holder = Destination::Machine(p);
    let slot = sealed_bundle_slot(1_700_000_000);
    let upload = manager_p
        .assemble_sealed_bundle(slot, holder, None, None, false)
        .expect("P seals its bundle");
    assert_eq!(
        upload.kit_root,
        Some(root_id),
        "guard: the bundle seals to K"
    );
    {
        let opened = upload
            .bundle
            .open_with_kit(&vault_id, &seed)
            .expect("guard: the bundle opens with K");
        assert_eq!(opened.publisher(), p, "guard: P sealed the bundle");
        assert!(
            opened.request().is_none(),
            "guard: the cadence bundle carries no publication request"
        );
        assert_eq!(
            upload.pads.generation(),
            opened.generation(),
            "guard: the bundle and its pads share a generation"
        );
    }

    let (vault_q, owner_q, person_q, _dir_q) = fresh_unrooted_vault();
    assert_eq!(
        person_q, served.person,
        "guard: the embedded owner is the same person on Q"
    );
    {
        let fold = vault_q.authority_fold().expect("Q authority fold");
        assert_eq!(
            fold.pinned_root, None,
            "guard: Q pins no root before the restore"
        );
        assert_eq!(
            fold.vault_id, None,
            "guard: Q holds no vault before the restore"
        );
    }

    let manager_q = manager_for(Arc::clone(&vault_q));
    let _restored = manager_q
        .restore_sealed_bundle_with_kit(
            &owner_q,
            &vault_id,
            &upload.bundle,
            &upload.pads,
            &seed,
            Some(KitConfirmation::Fingerprint(root_id)),
        )
        .expect("kit restore reads the kit's own root for its publisher (red: no machine the owner vouched for or asked to publish signed the bundle)");

    let fold = vault_q.authority_fold().expect("Q fold after restore");
    assert_eq!(
        fold.vault_id,
        Some(vault_id),
        "Q holds the bundle's vault after the restore"
    );
    assert_eq!(
        fold.pinned_root.map(|pin| pin.id),
        Some(root_id),
        "Q pins K after the restore"
    );
    assert_eq!(
        fold.pinned_root.map(|pin| pin.anchor_key),
        Some(anchor_key),
        "Q pins K's anchor after the restore"
    );
}

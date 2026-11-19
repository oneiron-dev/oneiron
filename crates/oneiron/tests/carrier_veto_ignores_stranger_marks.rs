//! Only the roster's chain admits or removes the install that carries an
//! owner act (FIX [FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES],
//! site S1, and FIX [FOREIGN-ANCHOR-ADMIT-SIDE]; Engine RULINGs
//! FOREIGN-ANCHOR-FOLD-JUDGE-RULE = C, 16 Nov 05:10, and
//! FOREIGN-ANCHOR-ADMIT-SIDE-P1 = B, 05:38).
//!
//! Any fresh key publishes an owner root, and that root's anchor marks any
//! machine in its own chain, owned or removed, under any keys that carry
//! their own machine proof. The one carrier rule (`owner_act_signer_admits`)
//! read every chain: a removal in any chain refused the carrier, and a live
//! chain naming the key admitted it. So one stranger's mark of this install
//! stopped every owner act it carries, at the door (`carrier_in_txn`) and in
//! the fold, which judges the act at its parents once a main-log row names
//! the mark. And a stranger's own mark of a fresh machine under a key it
//! holds made that key a carrier, whose owner answer wrote the machine a
//! roster chain with no owner, roster or honest machine signature. Now the
//! roster's chain alone admits and removes a carrier.
//!
//! Each test serves a self-host vault that pins no root, so this install
//! stands under the roster's chain alone, except the kit test of design 3.4,
//! whose install pins the owner's kit root.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    OwnerRootRecord, PairingPrincipal, PairingRedeemed, authority_entry_hash, authority_transcript,
    machine_possession_transcript, machine_profile_proof_transcript,
    pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::store::GateDecisionId;
use oneiron::world_keys::{KitConfirmation, RecoveryRootSeed};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the machine key a stranger holds for the machine it marks.
const STRANGER_MACHINE_SEED: u8 = 71;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

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

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// The owner's PERSON, bound to a live human actor.
    person: EntityId,
    /// This install, the carrier of every owner act its doors sign.
    carrier: EntityId,
    _issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

/// A self-host vault rooted under the host root before its first serving
/// start: no chain profiles this install yet.
fn unprofiled_self_host() -> (Vault, HostSlipIssuer, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    (vault, issuer, dir)
}

fn vault_id_of(vault: &Vault) -> AuthorityVaultId {
    vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted")
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
        Self::bound(vault, issuer, dir, carrier)
    }

    /// `vault` with this install's profile standing as `carrier`, and the
    /// owner bound and authenticated.
    fn bound(
        vault: Vault,
        issuer: HostSlipIssuer,
        dir: tempfile::TempDir,
        carrier: EntityId,
    ) -> Self {
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

    /// This install's roster head.
    fn carrier_roster(&self) -> oneiron::authority::MachineRevision {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(self.carrier)
            .and_then(|folded| folded.roster.clone())
            .expect("guard: this install has a roster chain")
    }

    /// Another machine's request to join this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.request_for(
            EntityId::from_bytes([0x76; 16]).expect("an id"),
            &signing(JOINING_SEED),
        )
    }

    /// `machine`'s identity under the machine key `node`, with its own proof.
    fn request_for(&self, machine: EntityId, node: &SigningKey) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
        let machine_key = node.verifying_key().to_bytes();
        let device_class = MachineDeviceClass::Computer;
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = node
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
        }
    }

    /// The owner enrols `request` as his own, carried by this install.
    fn enrol(&self, request: &MachineEnrolmentRequest) -> oneiron::Result<()> {
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .map(drop)
    }
}

/// A stranger's root published on one held valid row and stored. Returns its
/// anchor signing key and the root row's hash.
fn publish_stranger_root(vault: &Vault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = vault_id_of(vault);
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
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
        owner: stranger_owner(),
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
        .expect("the stranger's root row is stored");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks this install removed at revision 1 under the
/// install's own keys and machine proof (seq 2, on the root), then joins
/// that mark into the main log beside the install's roster row (seq 3), so
/// the next owner act's parents carry the mark. Returns the mark's and the
/// join's hashes.
fn stranger_removes_the_carrier(
    served: &ServedVault,
    anchor: &SigningKey,
    root: AuthorityEntryHash,
) -> (AuthorityEntryHash, AuthorityEntryHash) {
    let vault_id = served.vault_id();
    let roster = served.carrier_roster();
    let profile = MachineProfile {
        owner: stranger_owner(),
        role: MachineRole::Removed,
        revision: 1,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        ..roster.profile.clone()
    };
    let mark = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark_hash = hash(&mark);
    served
        .vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the stranger's removal mark is stored");
    let mut parents = vec![roster.entry, mark_hash];
    parents.sort_unstable();
    let join = signed(
        vault_id,
        3,
        parents,
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Anchor,
            scope: FrontierJoinScope::Main,
        }),
        anchor,
    );
    let join_hash = hash(&join);
    served
        .vault
        .put_authority_log_entry(&join, AT, 2)
        .expect("the stranger's main-log join is stored");

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark_hash),
        "guard: the stranger's removal mark is in valid_entries"
    );
    assert!(
        fold.valid_entries.contains(&join_hash),
        "guard: the stranger's join of the mark into the main log is in valid_entries"
    );
    let folded = fold
        .machine(served.carrier)
        .expect("guard: this install is a machine of the vault");
    assert!(
        folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.removed),
        "guard: the stranger's chain holds this install removed"
    );
    assert!(
        folded.roster.as_ref().is_some_and(|chain| chain.is_live()),
        "guard: this install's roster chain stays live"
    );
    (mark_hash, join_hash)
}

/// The owner enrols a machine through this install after a stranger's root
/// marked the install removed and joined that mark into the main log. The
/// door signs the answer, and the fold, judging it at parents that carry the
/// mark, keeps it: M stands at roster revision 1, carried by this install.
#[test]
fn a_strangers_removal_mark_of_the_carrier_refuses_no_owner_act() {
    let served = ServedVault::self_host();
    let (anchor, root) = publish_stranger_root(&served.vault);
    let (mark, join) = stranger_removes_the_carrier(&served, &anchor, root);
    let request = served.joining_machine();

    served
        .enrol(&request)
        .expect("the owner's enrolment lands beside a stranger's removal mark of its carrier");

    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain");
    assert!(
        fold.valid_entries.contains(&roster.entry),
        "the answer is in valid_entries"
    );
    assert!(roster.is_live(), "M's roster chain is live");
    assert_eq!(roster.profile.revision, 1, "M stands at revision 1");
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "M stands under its own machine key"
    );
    assert_eq!(
        roster.profile.carrier,
        Some(served.carrier),
        "this install carried the answer"
    );
    for row in [root, mark, join] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root, mark and join stay valid"
        );
    }
}

/// The roster's own removal of the carrier still refuses its acts: the owner
/// removes this install, and its next enrolment is refused and lands nothing.
#[test]
fn a_roster_removal_of_the_carrier_still_refuses_its_owner_acts() {
    let served = ServedVault::self_host();
    served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            served.carrier,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes this install");
    assert!(
        served.carrier_roster().removed,
        "guard: this install's roster chain is removed"
    );
    let request = served.joining_machine();

    assert!(
        served.enrol(&request).is_err(),
        "a carrier the roster removed carried the owner's enrolment"
    );
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .machine(request.machine)
            .is_none(),
        "the refused enrolment landed a row"
    );
}

/// A carrier that only a stranger's chain admits writes no roster chain (the
/// read's Q3 forgery). A stranger's root marks a fresh machine X owned, under
/// a machine key K the stranger holds and K's own proof (seq 2, on the
/// root). K then signs the owner's answer that X is his, carried by X itself
/// (seq 1, on the mark), naming the vault's real owner, with no cosign. On
/// main the fold admits K as X's carrier from the stranger's chain and the
/// answer writes X a roster chain; now it is refused and X has none.
#[test]
fn a_carrier_only_a_strangers_root_admits_writes_no_roster_chain() {
    let served = ServedVault::self_host();
    let vault_id = served.vault_id();
    let (anchor, root) = publish_stranger_root(&served.vault);
    let stranger_key = signing(STRANGER_MACHINE_SEED);
    let machine = EntityId::from_bytes([0x5C; 16]).expect("an id");
    let identity = served.request_for(machine, &stranger_key);
    let profile =
        |owner: EntityId, act: Option<OwnerAct>, carrier: Option<EntityId>| MachineProfile {
            machine,
            owner,
            machine_key: identity.machine_key,
            device_class: identity.device_class,
            encryption_key: identity.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            machine_proof: identity.machine_proof,
            seen_world_edits: BTreeSet::new(),
            carrier,
            act,
        };
    let mark = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile(stranger_owner(), None, None)),
        &anchor,
    );
    let mark_hash = hash(&mark);
    served
        .vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the stranger's mark of X is stored");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark_hash),
        "guard: the stranger's mark of X is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&anchor.verifying_key().to_bytes()))
            .is_some_and(|chain| chain.is_live()),
        "guard: the stranger's chain holds X live under K"
    );

    let act = OwnerAct::by_owner(
        served.person,
        OwnerActKind::MachineAnswer,
        machine,
        ActSurface::ThisInstall,
        [0; 32],
    );
    let answer = signed(
        vault_id,
        1,
        vec![mark_hash],
        AuthorityOp::MachineProfile(profile(served.person, Some(act), Some(machine))),
        &stranger_key,
    );
    let answer_hash = hash(&answer);
    // Storing it is the store's call; a refusal at the door is as safe.
    let _ = served.vault.put_authority_log_entry(&answer, AT, 2);

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&answer_hash),
        "an owner answer carried by a key only a stranger's root admits stood"
    );
    assert!(
        fold.machine(machine)
            .is_none_or(|folded| folded.roster.is_none()),
        "a stranger's carrier wrote X a roster chain"
    );
    for row in [root, mark_hash] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark stay valid"
        );
    }
}

/// A stranger's root marks this install before the roster holds a head of
/// it: live and owned, under the install's own keys and proof (seq 2, on the
/// root). "On the roster yet?" is the roster's question (Fable design pass
/// 29, 3.4; FIX [SERVING-PROFILE-ANCHOR-MARKED-INSTALL-NO-BOOTSTRAP]), so the
/// serving-profile door enrols the install under the host root, and the
/// install then carries the owner's enrolment of another machine. On main
/// the door stands the install on the stranger's chain and writes no roster
/// chain (the `roster` expect fails); at this PR's first head 1ec17eefde8e
/// it refuses SERVING_PROFILE_NOT_LIVE (the door's expect fails).
#[test]
fn a_strangers_mark_of_an_install_the_roster_holds_no_head_of_leaves_its_bootstrap_open() {
    let (vault, issuer, dir) = unprofiled_self_host();
    let vault_id = vault_id_of(&vault);
    let encryption_key = vault
        .machine_encryption_key(vault_id)
        .expect("this install's encryption key");
    let request = vault
        .machine_enrolment_request(vault_id, encryption_key)
        .expect("this install's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .machine(request.machine)
            .is_none(),
        "guard: no chain profiles this install before the stranger's mark"
    );
    let (anchor, root) = publish_stranger_root(&vault);
    let mark = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(MachineProfile {
            machine: request.machine,
            owner: stranger_owner(),
            machine_key: request.machine_key,
            device_class: request.device_class,
            encryption_key: request.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            machine_proof: request.machine_proof,
            seen_world_edits: BTreeSet::new(),
            carrier: None,
            act: None,
        }),
        &anchor,
    );
    let mark_hash = hash(&mark);
    vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the stranger's mark of this install is stored");
    let held = vault
        .authority_fold()
        .expect("authority fold")
        .machine(request.machine)
        .cloned()
        .expect("guard: the install view holds a chain of this install");
    assert!(
        held.roster.is_none(),
        "guard: the roster holds no head of this install"
    );
    assert!(
        held.anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.is_live()),
        "guard: the stranger's chain holds this install live"
    );

    let roster = vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the serving-profile door enrols an install the roster holds no head of")
        .roster
        .expect("the serving-profile door wrote this install a roster chain");
    assert!(roster.is_live(), "this install's roster chain is live");
    assert_eq!(
        roster.profile.revision, 1,
        "this install stands at revision 1"
    );
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "the roster profiles this install under its own machine key"
    );
    let served = ServedVault::bound(vault, issuer, dir, request.machine);
    let joining = served.joining_machine();
    served
        .enrol(&joining)
        .expect("this install carries the owner's enrolment once the roster profiles it");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.machine(joining.machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|chain| chain.is_live() && chain.profile.carrier == Some(request.machine)),
        "the owner's enrolment stands, carried by this install"
    );
    for row in [root, mark_hash] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark stay valid"
        );
    }
}

/// The kit's root record, anchor-signed and stored: `publish_stranger_root`
/// for the owner's own kit seed, naming the vault's owner instead of a
/// stranger. The stored root a drawn seed's restore needs: the kit seed gate
/// publishes a drawn root only through its activation, so the restore below
/// finds this row, marks under it and pins it without publishing.
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

/// The honest case of design 3.4: an install the owner's kit marked before
/// the roster held a head of it. The kit's root is published, this install
/// restores from the kit's seed through the public restore door (which pins
/// the root and marks this install's own request under its anchor), and only
/// then the first serving start runs: it enrols the install under the host
/// root, and the install carries the owner's enrolment of another machine.
/// The owner binds before the first serving start, exactly as
/// `ServedVault::bound` binds (that order needs no profile: the bind writes
/// none, and the restore mints no roster head).
///
/// Green (a18a1518667c): the serving-profile door enrols the install (the
/// roster holds no head of it and the pinned chain agrees) at roster
/// revision 1 under its own keys, and the owner's enrolment of the joining
/// machine stands, carried by this install.
/// Red at main 28a0ed385015: the door's `.expect(..)` passes but the
/// `.roster.expect(..)` fails: the every-chain carrier rule stands the
/// install on the kit's anchor chain, so the door is a no-op and writes no
/// roster chain.
/// Red at 1ec17eefde8e: the door's `.expect(..)` fails with
/// SERVING_PROFILE_NOT_LIVE: the carrier rule reads the roster alone (which
/// holds no head), while the gate still refuses an install any chain
/// profiles instead of enrolling it.
#[test]
fn an_owners_kit_mark_of_an_install_the_roster_holds_no_head_of_leaves_its_bootstrap_open() {
    let (vault, issuer, dir) = unprofiled_self_host();
    let vault_id = vault_id_of(&vault);
    let encryption_key = vault
        .machine_encryption_key(vault_id)
        .expect("this install's encryption key");
    let request = vault
        .machine_enrolment_request(vault_id, encryption_key)
        .expect("this install's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .machine(request.machine)
            .is_none(),
        "guard: no chain profiles this install before the kit's mark"
    );
    let served = ServedVault::bound(vault, issuer, dir, request.machine);
    let seed = RecoveryRootSeed::generate().expect("the kit's seed");
    let root_id = seed
        .public(&vault_id)
        .expect("the kit root's public half")
        .id;
    let root_hash = publish_kit_root(&served.vault, served.person, &seed);
    served
        .vault
        .restore_world_keys(
            &served.owner,
            &seed,
            Some(KitConfirmation::Fingerprint(root_id)),
        )
        .expect("the kit restore pins the kit's root and marks this install under it");

    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(
        fold.pinned_root.map(|pin| pin.id),
        Some(root_id),
        "guard: this install pins the kit's root"
    );
    let held = fold
        .machine(request.machine)
        .expect("guard: the kit's mark profiles this install");
    assert!(
        held.roster.is_none(),
        "guard: the roster holds no head of this install"
    );
    let anchor_key = seed.anchor().verifying_key().to_bytes();
    let chain = held
        .anchored
        .get(&anchor_key)
        .expect("guard: the kit's chain holds this install");
    assert!(
        chain.is_live(),
        "guard: the kit's chain holds this install live"
    );
    assert_eq!(
        chain.profile.role,
        MachineRole::Owned(MachineOwnership::Yours),
        "guard: the kit's mark answers the install"
    );
    assert_eq!(
        chain.profile.machine_key, request.machine_key,
        "guard: the kit's mark names this install's machine key"
    );
    assert_eq!(
        chain.profile.encryption_key, request.encryption_key,
        "guard: the kit's mark names this install's encryption key"
    );

    let roster = served
        .vault
        .ensure_serving_install_profile(&served._issuer, MachineRole::Unanswered)
        .expect("the serving-profile door enrols an install the roster holds no head of")
        .roster
        .expect("the serving-profile door wrote this install a roster chain");
    assert!(roster.is_live(), "this install's roster chain is live");
    assert_eq!(
        roster.profile.revision, 1,
        "this install stands at revision 1"
    );
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "the roster profiles this install under its own machine key"
    );
    let joining = served.joining_machine();
    served
        .enrol(&joining)
        .expect("this install carries the owner's enrolment once the roster profiles it");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(
        fold.pinned_root.map(|pin| pin.id),
        Some(root_id),
        "this install still pins the kit's root"
    );
    assert!(
        fold.machine(joining.machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|chain| chain.is_live() && chain.profile.carrier == Some(request.machine)),
        "the owner's enrolment stands, carried by this install"
    );
    assert!(
        fold.valid_entries.contains(&root_hash),
        "the kit's root stays valid"
    );
}

/// The seed of the connection key a redeemed pairing link binds.
const CONNECTION_SEED: u8 = 73;

/// The owner makes the joining device a machine pairing link that answers
/// `Yours`, and the device redeems it with its request, its connection key's
/// binding signature and its machine key's possession proof over this
/// redemption. OPUS-SPLIT-6's `redeem_machine_link`
/// (`machine_answer_standing_heads.rs` on `14f62bf4c2e7`), adapted to this
/// file's `ServedVault`: the issue needs only the host issuer and the
/// revalidated owner, so it runs on an install the roster never profiled.
fn redeem_machine_link(
    served: &ServedVault,
    request: &MachineEnrolmentRequest,
) -> oneiron::Result<PairingRedeemed> {
    let link = served
        .vault
        .issue_machine_pairing_link(
            &served._issuer,
            &served.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("the owner makes the joining device a machine pairing link");
    let holder = request.machine.to_hex();
    let connection = signing(CONNECTION_SEED);
    let binding_key = connection.verifying_key().to_bytes();
    let binding_transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("the binding transcript of the redemption");
    let binding = connection.sign(&binding_transcript).to_bytes();
    let possession_transcript = machine_possession_transcript(
        &request.vault_id,
        request.machine,
        &request.machine_key,
        &binding_transcript,
    );
    let possession = signing(JOINING_SEED)
        .sign(&possession_transcript)
        .to_bytes();
    served.vault.redeem_pairing_link_with_possession(
        &served._issuer,
        &link.code,
        &holder,
        binding_key,
        &binding,
        Some(request),
        Some(&possession),
    )
}

/// The pairing gate of design 3.4: this install serves with a host root but
/// the roster holds no head of it, while a stranger's root marked it live
/// and answered under its own keys. A pairing link this install issues is
/// redeemed for a joining device: the redemption takes the bootstrap arm and
/// the host root enrols the device.
///
/// NOTE: no serving start runs before the redemption: it would enrol the
/// install and close the gate. The install stays unprofiled on the roster
/// because `unprofiled_self_host` only roots the vault and returns the host
/// issuer, binding the owner writes no machine profile, and the stranger's
/// mark adds only an anchor chain; the link issue needs just the issuer and
/// the revalidated owner.
///
/// Green (a18a1518667c): the redemption enrols the device at roster revision
/// 1 under its own keys with no owner act and no carrier, and it is not the
/// credential-only re-pairing.
/// Red at main 28a0ed385015: the redeem `.expect(..)` fails: the install is
/// not unprofiled (the mark answers) but the door takes the carried arm (the
/// every-chain rule admits the install), and the fold refuses the landed
/// answer at its parents, which never name the unjoined stranger mark.
/// Red at 1ec17eefde8e: the redeem `.expect(..)` fails: not unprofiled, and
/// the roster-only carrier rule finds no head of this install, so the door
/// refuses with no carrier before writing anything.
#[test]
fn the_pairing_bootstrap_stays_open_past_a_strangers_answered_mark_of_this_install() {
    let (vault, issuer, dir) = unprofiled_self_host();
    let vault_id = vault_id_of(&vault);
    let encryption_key = vault
        .machine_encryption_key(vault_id)
        .expect("this install's encryption key");
    let request = vault
        .machine_enrolment_request(vault_id, encryption_key)
        .expect("this install's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .machine(request.machine)
            .is_none(),
        "guard: no chain profiles this install before the stranger's mark"
    );
    let served = ServedVault::bound(vault, issuer, dir, request.machine);
    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(MachineProfile {
            machine: request.machine,
            owner: stranger_owner(),
            machine_key: request.machine_key,
            device_class: request.device_class,
            encryption_key: request.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            machine_proof: request.machine_proof,
            seen_world_edits: BTreeSet::new(),
            carrier: None,
            act: None,
        }),
        &anchor,
    );
    let mark_hash = hash(&mark);
    served
        .vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the stranger's mark of this install is stored");
    let held = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .machine(request.machine)
        .cloned()
        .expect("guard: the install view holds a chain of this install");
    assert!(
        held.roster.is_none(),
        "guard: the roster holds no head of this install"
    );
    let chain = held
        .anchored
        .get(&anchor.verifying_key().to_bytes())
        .expect("guard: the stranger's chain holds this install");
    assert!(
        chain.is_live(),
        "guard: the stranger's chain holds this install live"
    );
    assert!(
        chain.profile.role.answered(),
        "guard: the stranger's mark answers the install"
    );

    let joining = served.joining_machine();
    let redeemed = redeem_machine_link(&served, &joining).expect(
        "the pairing bootstrap arm enrols the joining device past the stranger's answered mark",
    );
    assert!(
        !redeemed.re_paired,
        "the redemption enrols, it is not the credential-only re-pairing"
    );
    let named = redeemed
        .machine
        .as_ref()
        .and_then(|folded| folded.roster.as_ref())
        .expect("the redemption names the device's roster chain");
    assert!(named.is_live(), "the device's roster chain is live");
    assert_eq!(named.profile.revision, 1, "the device stands at revision 1");
    assert_eq!(
        named.profile.machine_key, joining.machine_key,
        "the roster profiles the device under its own machine key"
    );
    assert!(
        named.profile.act.is_none(),
        "the host root enrolled the device with no owner act"
    );
    assert!(
        named.profile.carrier.is_none(),
        "no install carried the bootstrap enrolment"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(joining.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("the device has a roster chain after the redemption");
    assert!(
        fold.valid_entries.contains(&roster.entry),
        "the bootstrap enrolment is in valid_entries"
    );
    assert!(
        roster.profile.act.is_none() && roster.profile.carrier.is_none(),
        "the device's roster head carries no act and no carrier"
    );
    for row in [root, mark_hash] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark stay valid"
        );
    }
}

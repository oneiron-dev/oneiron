//! Pass 27 R4 PR 2 (WAYBACK-R4-FIRST-KEY = B, WAYBACK-R4-NO-PREDECESSOR = A):
//! the kit's activation enrols the root's authority key R in the same write
//! txn, kind `RecoveryAuthority`, predecessor = this install's live owner key
//! or this vault's host root on a self-hosted vault, and hands R's seed out
//! once. A second confirmation keeps one R row. With neither predecessor the
//! activation is refused with the exact words and nothing is written. A
//! device key enrols with kind `Device`. A new kit's activation revokes the
//! owner's earlier R, signed by the same predecessor, so the box's copy of
//! the old R no longer acts (WAYBACK-SECOND-KIT-OLD-ROOT-KEY = A).
//!
//! Red on PR 2's base `1b0ef517a29e`: the file compiles there (only APIs that
//! exist at that head) and fails at runtime, since the activation enrols no
//! R and refuses no predecessor-less confirm. The two second-kit tests are
//! red at `b020a643f8ec`, PR 2 before that ruling: the old R stays live.
//!
//! The predecessor is the deciding owner's own (REVIEW2 #8798 P2-1): a
//! co-Owner's device key this install holds never signs another owner's R,
//! and the host root is the predecessor only of the owner no live `human`
//! binding gives it away from. Both tests are red on PR 2's head before that
//! fix, which took the first held live device key and any live host root.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_activation_enrols_authority_key`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, AuthorityOp, EnrolledOwnerKeyKind,
    HostSlipIssuer, MachineRole, RootMaterial, RootSuccessor, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::world_keys::{
    ConfirmedWorldKit, IssuedWorldKit, RecoveryAuthoritySigner, RecoveryRootSeed,
};
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use zeroize::Zeroizing;

/// The exact refusal when this install holds no predecessor
/// (WAYBACK-R4-NO-PREDECESSOR = A).
const NO_PREDECESSOR: &str =
    "this device's owner key is not enrolled; enrol it, then confirm the kit; nothing was written";

/// The root door's refusal of an R the roster no longer holds live while
/// another root key lives.
const ROOT_KEY_NOT_LIVE: &str = "the recovery root's authority key is not a live owner key on \
                                 this vault's roster, and the roster still holds a live root \
                                 key; nothing was written";

/// The activation's refusal of a kit whose R another owner enrolled
/// (REVIEW-9488 round 2 P1 3).
const NOT_THE_OWNERS_R: &str =
    "this kit's root authority key is enrolled, but not as your recovery key; nothing was written";

/// The co-Owner fixture's shared vault id.
const SHARED: u64 = 28;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A self-hosted vault whose host seed this install holds in its keystore.
struct SelfHosted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
    /// The device keystore, which holds the host seed across a reopen.
    keystore: Arc<oneiron_keystore::MemoryKeystore>,
}

fn self_hosted() -> SelfHosted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    SelfHosted {
        _dir: dir,
        vault,
        issuer,
        person,
        keystore,
    }
}

impl SelfHosted {
    /// The same vault closed and opened again under `posture`, with the
    /// same keystore: this install still holds the host seed.
    fn reopened(self, posture: HostingPrivacyPosture) -> Self {
        let Self {
            _dir: dir,
            vault,
            issuer,
            person,
            keystore,
        } = self;
        drop(vault);
        let mut config = VaultConfig::device();
        config.privacy.posture = posture;
        let vault = Vault::open(dir.path(), config).expect("the vault reopens");
        vault.install_device_keystore(keystore.clone());
        Self {
            _dir: dir,
            vault,
            issuer,
            person,
            keystore,
        }
    }

    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    /// Makes the vault shared and adds a live person as a co-Owner, as
    /// `add_owner` runs at once for its only owner; the co-Owner's id.
    fn add_co_owner(&self) -> EntityId {
        self.vault
            .initialize_shared_vault(
                &self.owner(),
                SHARED,
                None,
                &[InitialSharedMember {
                    member_ref: self.person,
                    role: Some(FederationGrantRole::Owner),
                }],
                1,
            )
            .expect("a shared vault");
        let co_owner = EntityId::now();
        self.vault
            .put_entity(
                &co_owner,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        let act = self
            .vault
            .propose_add_owner(&self.owner(), SHARED, co_owner)
            .expect("the owner starts add_owner");
        self.vault
            .execute_completed_shared_act(&self.owner(), &act.id, Some(&self.issuer))
            .expect("add_owner runs at once");
        co_owner
    }

    fn issue(&self) -> IssuedWorldKit {
        self.issue_as(&self.owner())
    }

    /// A world kit `owner` issues.
    fn issue_as(&self, owner: &AuthenticatedOwner) -> IssuedWorldKit {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        self.vault
            .issue_world_kit(
                owner,
                &KitIssue {
                    vault_id,
                    homes: [
                        PieceHome::RecoveryCode(CodeKeeping::Paper),
                        PieceHome::TrustedPerson,
                        PieceHome::SecurityKey,
                    ],
                    passphrase: None,
                    cost: PassphraseCost::FLOOR,
                    only_machine: false,
                },
            )
            .expect("a kit")
    }

    fn confirm(&self, issued: &IssuedWorldKit) -> oneiron::Result<ConfirmedWorldKit> {
        let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
            issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
    }

    /// R's enrol row's signer, for the enrolled `public_key`.
    fn enrol_signer(&self, public_key: &[u8; 32]) -> AuthorityKey {
        self.vault
            .export_signed_authority_history()
            .expect("the history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .find_map(|row| match &row.op {
                AuthorityOp::OwnerKeyEnroll(enroll)
                    if enroll.device.key == AuthorityKey::Ed25519(*public_key) =>
                {
                    Some(row.signer_key().clone())
                }
                _ => None,
            })
            .expect("R's enrol row is stored")
    }

    /// The live R keys, kind `RecoveryAuthority`.
    fn live_r(&self) -> Vec<AuthorityKey> {
        self.vault
            .enrolled_owner_keys()
            .expect("the list")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .collect()
    }

    /// Whether `key` is on the roster and not revoked.
    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    /// The signer of the `RevokeDevice` row of `key`.
    fn revoke_signer(&self, key: &AuthorityKey) -> AuthorityKey {
        self.vault
            .export_signed_authority_history()
            .expect("the history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .find_map(|row| match &row.op {
                AuthorityOp::RevokeDevice { revoked_key } if revoked_key == key => {
                    Some(row.signer_key().clone())
                }
                _ => None,
            })
            .expect("the key's revoke row is stored")
    }

    /// The box's copy of `confirmed`'s R: the seed its activation handed out
    /// once for the deposit, released as the box releases it.
    fn released(&self, confirmed: &ConfirmedWorldKit) -> RootMaterial {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                Zeroizing::new(*confirmed.activated.authority_seed.bytes()),
                &vault_id,
                confirmed.activated.root,
            )
            .expect("the released key"),
        )
    }

    /// `issued`'s seed, rebuilt from two of its pieces, as a restore
    /// rebuilds it.
    fn seed_of(&self, issued: &IssuedWorldKit) -> RecoveryRootSeed {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        let pieces: Vec<_> = issued.pieces.iter().take(2).collect();
        let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, &pieces, None)
            .expect("two pieces restore the seed");
        RecoveryRootSeed::from_restored_kit(secret).expect("the restored seed")
    }

    /// `owner` enrols `seed`'s R explicitly, under the host root, carried by
    /// this install: the R key.
    fn enrol_r_as(&self, owner: &AuthenticatedOwner, seed: &RecoveryRootSeed) -> AuthorityKey {
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall),
                machine,
                seed,
                &self.issuer,
            )
            .expect("the owner enrols the kit's R");
        AuthorityKey::Ed25519(receipt.public_key)
    }

    /// The person an active `human` binding of `key` names.
    fn bound_human(&self, key: &AuthorityKey) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(key)
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
            })
            .map(|binding| binding.actor_ref)
    }

    /// How many enrol rows the history holds for `public_key`.
    fn enrol_rows(&self, public_key: &[u8; 32]) -> usize {
        self.vault
            .export_signed_authority_history()
            .expect("the history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .filter(|row| match &row.op {
                AuthorityOp::OwnerKeyEnroll(enroll) => {
                    enroll.device.key == AuthorityKey::Ed25519(*public_key)
                }
                _ => false,
            })
            .count()
    }
}

#[test]
fn confirming_the_kit_on_a_self_hosted_vault_enrols_r_under_the_host_root() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the kit confirms");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R, kind RecoveryAuthority");
    assert_eq!(
        fixture.enrol_signer(&live_r[0].public_key),
        fixture.issuer.public_key(),
        "the host root signs R's row"
    );
}

#[test]
fn with_this_installs_device_key_the_row_is_signed_by_that_key() {
    let fixture = self_hosted();
    let device = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the kit confirms");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R");
    assert_eq!(
        fixture.enrol_signer(&live_r[0].public_key),
        AuthorityKey::Ed25519(device.public_key),
        "this install's device key signs R's row, not the host root"
    );
}

#[test]
fn a_second_confirmation_of_the_same_kit_keeps_one_r_row() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the first confirm");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R after the first confirm");

    let again = fixture.confirm(&issued);
    assert!(
        again.is_err(),
        "confirming an already-confirmed kit is refused"
    );
    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "still one live R");
    assert_eq!(
        fixture.enrol_rows(&live_r[0].public_key),
        1,
        "still one R row"
    );
}

#[test]
fn without_a_predecessor_the_activation_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("the hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let owner = proof(&vault, person);

    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let issued = vault
        .issue_world_kit(
            &owner,
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::TrustedPerson,
                    PieceHome::SecurityKey,
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
        )
        .expect("a kit");

    let before_fold = vault.authority_fold().expect("the fold");
    let before_history = vault
        .export_signed_authority_history()
        .expect("the history")
        .len();
    let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
        issued.pieces.iter().take(2).collect();
    let refused = vault
        .confirm_world_kit(&owner, &pieces, None, &BTreeSet::new())
        .expect_err("a confirm with no predecessor is refused");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(NO_PREDECESSOR),
        "the exact words: {refused}"
    );

    let after_fold = vault.authority_fold().expect("the fold");
    assert_eq!(
        after_fold.roster, before_fold.roster,
        "the roster is unchanged"
    );
    assert_eq!(
        after_fold.pinned_root, before_fold.pinned_root,
        "the pin is unchanged"
    );
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the history is unchanged"
    );
}

#[test]
fn a_device_keys_enrolled_kind_is_device() {
    let fixture = self_hosted();
    let receipt = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let listed = fixture
        .vault
        .enrolled_owner_keys()
        .expect("the list")
        .into_iter()
        .find(|key| key.public_key == receipt.public_key)
        .expect("the device key is listed");
    assert_eq!(listed.kind, EnrolledOwnerKeyKind::Device);
    assert!(listed.live);
}

#[test]
fn a_new_kits_activation_revokes_the_earlier_r_under_this_installs_key() {
    let fixture = self_hosted();
    let device = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let device_key = AuthorityKey::Ed25519(device.public_key);
    let first = fixture.confirm(&fixture.issue()).expect("kit A confirms");
    let old_r = fixture.live_r();
    assert_eq!(old_r.len(), 1, "kit A's R is live");
    let old_r = old_r[0].clone();

    fixture.confirm(&fixture.issue()).expect("kit B confirms");

    let refused = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.released(&first),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect_err("the box's copy of kit A's R no longer acts");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(ROOT_KEY_NOT_LIVE),
        "the exact words: {refused}"
    );
    assert!(!fixture.live(&old_r), "kit A's R is revoked");
    let live_r = fixture.live_r();
    assert_eq!(live_r.len(), 1, "one live R: kit B's");
    assert_ne!(live_r[0], old_r);
    assert_eq!(
        fixture.revoke_signer(&old_r),
        device_key,
        "the predecessor that signs kit B's R signs kit A's revocation"
    );
    assert!(fixture.live(&device_key), "the device key stays live");
}

#[test]
fn on_a_self_hosted_vault_the_host_root_revokes_the_earlier_r() {
    let fixture = self_hosted();
    fixture.confirm(&fixture.issue()).expect("kit A confirms");
    let old_r = fixture.live_r();
    assert_eq!(old_r.len(), 1, "kit A's R is live");
    let old_r = old_r[0].clone();

    fixture.confirm(&fixture.issue()).expect("kit B confirms");

    assert!(!fixture.live(&old_r), "kit A's R is revoked");
    let live_r = fixture.live_r();
    assert_eq!(live_r.len(), 1, "one live R: kit B's");
    assert_ne!(live_r[0], old_r);
    assert_eq!(
        fixture.revoke_signer(&old_r),
        fixture.issuer.public_key(),
        "the host root, kit B's predecessor, signs kit A's revocation"
    );
}

/// A co-Owner's device key this install holds never signs another owner's R
/// (REVIEW2 #8798 P2-1): the owner's kit is confirmed with R's row signed by
/// the owner's own host root, not by the co-Owner's live device key.
#[test]
fn a_co_owners_device_key_never_signs_another_owners_r() {
    let fixture = self_hosted();
    let co_owner = fixture.add_co_owner();
    let theirs = fixture
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(proof(&fixture.vault, co_owner), ActSurface::ThisInstall),
            &fixture.issuer,
        )
        .expect("the co-Owner enrols this install's device key");
    let theirs = AuthorityKey::Ed25519(theirs.public_key);
    assert!(
        fixture.live(&theirs),
        "guard: this install holds the co-Owner's live key"
    );

    let issued = fixture.issue();
    fixture
        .confirm(&issued)
        .expect("the owner's kit confirms under the owner's own host root");
    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let owners_r: Vec<_> = enrolled
        .iter()
        .filter(|key| {
            key.kind == EnrolledOwnerKeyKind::RecoveryAuthority
                && key.live
                && key.owner == fixture.person
        })
        .collect();
    assert_eq!(owners_r.len(), 1, "one live R of the owner");
    let signer = fixture.enrol_signer(&owners_r[0].public_key);
    assert_ne!(signer, theirs, "the co-Owner's key signs no R of the owner");
    assert_eq!(
        signer,
        fixture.issuer.public_key(),
        "the owner's own host root signs R's row"
    );
}

/// A co-Owner who holds no owner key of their own here never confirms a kit
/// under the host root a live `human` binding gives the owner (REVIEW2
/// #8798 P2-1, the host root half): refused with the exact words, nothing
/// written.
#[test]
fn a_co_owner_without_a_key_of_their_own_confirms_no_kit_under_the_owners_host_root() {
    let fixture = self_hosted();
    let co_owner = fixture.add_co_owner();
    let theirs = proof(&fixture.vault, co_owner);
    let issued = fixture.issue_as(&theirs);
    let before_fold = fixture.vault.authority_fold().expect("the fold");
    let before_history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history")
        .len();

    let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
        issued.pieces.iter().take(2).collect();
    let refused = fixture
        .vault
        .confirm_world_kit(&theirs, &pieces, None, &BTreeSet::new())
        .expect_err("the owner's host root is not the co-Owner's predecessor");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(NO_PREDECESSOR),
        "the exact words: {refused}"
    );
    let after_fold = fixture.vault.authority_fold().expect("the fold");
    assert_eq!(
        after_fold.roster, before_fold.roster,
        "the roster is unchanged"
    );
    assert_eq!(
        after_fold.pinned_root, before_fold.pinned_root,
        "the pin is unchanged"
    );
    assert_eq!(
        fixture
            .vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the history is unchanged"
    );
}

/// Main's writer rule (Engine ANSWER HOSTED-REFOLD-SELF-HOST-ROOT-CUSTODY =
/// A): an install under the Hosted posture never offers a host root it holds
/// as the owner's proof. A self-hosted vault reopened as Hosted keeps its
/// unstamped root, which the fold still trusts as the owner's, and this
/// install still holds that root's seed; the activation takes no host root
/// there as R's predecessor: refused with the exact words, nothing written.
/// Red at the merge of main 28b2ecb4fcc2 (009a2c92929), where the host root
/// signs R's row.
#[test]
fn a_self_hosted_vault_reopened_as_hosted_takes_no_host_root_as_rs_predecessor() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    let fixture = fixture.reopened(HostingPrivacyPosture::Hosted);
    let before_fold = fixture.vault.authority_fold().expect("the fold");
    assert!(
        before_fold
            .roster
            .get(&fixture.issuer.public_key())
            .is_some_and(|device| !device.revoked),
        "guard: the self-host root is still live on the hosted fold"
    );
    let before_history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history")
        .len();

    let refused = fixture
        .confirm(&issued)
        .expect_err("a hosted install takes no host root as R's predecessor");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(NO_PREDECESSOR),
        "the exact words: {refused}"
    );
    assert!(fixture.live_r().is_empty(), "no R is enrolled");
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_fold.roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture
            .vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the history is unchanged"
    );
}

/// A kit whose R another owner enrolled is never this owner's (REVIEW-9488
/// round 2 P1 3): the owner enrols the R of a kit the co-Owner issued, then
/// the co-Owner, with a live device key of their own here, confirms that
/// kit. The activation refuses with the exact words and writes nothing; the
/// owner's R stays live and theirs. Red at 24c6aa90f805, where the
/// activation took the owner's live row as the co-Owner's R and confirmed
/// the kit.
#[test]
fn a_kit_whose_r_another_owner_enrolled_is_refused() {
    let fixture = self_hosted();
    let co_owner = fixture.add_co_owner();
    let theirs = proof(&fixture.vault, co_owner);
    fixture
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(theirs.clone(), ActSurface::ThisInstall),
            &fixture.issuer,
        )
        .expect("the co-Owner enrols this install's device key");
    let issued = fixture.issue_as(&theirs);
    let r = fixture.enrol_r_as(&fixture.owner(), &fixture.seed_of(&issued));
    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    assert!(
        enrolled.iter().any(|key| {
            AuthorityKey::Ed25519(key.public_key) == r
                && key.kind == EnrolledOwnerKeyKind::RecoveryAuthority
                && key.live
                && key.owner == fixture.person
        }),
        "guard: the kit's R is the owner's live R"
    );
    let before_fold = fixture.vault.authority_fold().expect("the fold");
    let before_history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history")
        .len();

    let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
        issued.pieces.iter().take(2).collect();
    let refused = fixture
        .vault
        .confirm_world_kit(&theirs, &pieces, None, &BTreeSet::new())
        .expect_err("the owner's R is not the co-Owner's kit");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(NOT_THE_OWNERS_R),
        "the exact words: {refused}"
    );
    let after_fold = fixture.vault.authority_fold().expect("the fold");
    assert_eq!(
        after_fold.roster, before_fold.roster,
        "the roster is unchanged"
    );
    assert_eq!(
        after_fold.pinned_root, before_fold.pinned_root,
        "the pin is unchanged"
    );
    assert_eq!(
        fixture
            .vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the history is unchanged"
    );
    assert!(fixture.live(&r), "the owner's R stays live");
}

/// An R enrolled before its kit's activation still binds its owner when the
/// activation revokes the R that held their only `human` binding
/// (REVIEW-9488 round 2 P1 4): on a self-hosted vault the co-Owner's first
/// key, R1, binds them; then their device key and kit 2's R2 enrol while that
/// binding stands; kit 2's activation, signed by the device key, revokes R1
/// and binds the co-Owner to R2. Red at 24c6aa90f805, where the activation
/// bound only an R it enrolled itself, so the co-Owner kept no binding.
#[test]
fn a_pre_enrolled_r_binds_its_owner_when_the_revoked_r_held_the_binding() {
    let fixture = self_hosted();
    let co_owner = fixture.add_co_owner();
    let theirs = proof(&fixture.vault, co_owner);
    let r1 = fixture.enrol_r_as(&theirs, &fixture.seed_of(&fixture.issue_as(&theirs)));
    assert_eq!(
        fixture.bound_human(&r1),
        Some(co_owner),
        "guard: the co-Owner's first key, R1, binds them"
    );
    fixture
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(theirs.clone(), ActSurface::ThisInstall),
            &fixture.issuer,
        )
        .expect("the co-Owner enrols this install's device key");
    let kit = fixture.issue_as(&theirs);
    let r2 = fixture.enrol_r_as(&theirs, &fixture.seed_of(&kit));
    assert_eq!(
        fixture.bound_human(&r2),
        None,
        "guard: R2 enrols while R1's binding stands, so it binds no one"
    );

    let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> = kit.pieces.iter().take(2).collect();
    fixture
        .vault
        .confirm_world_kit(&theirs, &pieces, None, &BTreeSet::new())
        .expect("the co-Owner confirms kit 2 under their device key");

    assert!(!fixture.live(&r1), "kit 2's activation revokes R1");
    assert!(fixture.live(&r2), "R2 stays live");
    assert_eq!(
        fixture.bound_human(&r2),
        Some(co_owner),
        "R2 binds the co-Owner, whose binding R1 held"
    );
}

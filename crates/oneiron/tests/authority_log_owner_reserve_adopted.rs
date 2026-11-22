//! FIX [OWNER-RESERVE-ADOPTED-OWNER-WORK] (Astra owner-reserve r3 F1): past
//! the owner reserve of [AUTHORITY-LOG-SIGNER-FLOOD], a result this install
//! signs lands as the owner's work only when the request it answers is: one
//! the owner signed, or one this install carries under its own key. The
//! pickup takes its requests from the fold, and on a vault that adopted a
//! checkpoint image that fold holds requests the image covers with no raw
//! row here. The reserve read the stored row alone, so it took such a
//! request as another machine's, and the pickup left it pending past the
//! reserve though this install carried it. Now it reads the body the image
//! carries of that covered row when no row is stored, and judges it the same
//! way.
//!
//! The fixture: a rooted install carries an owner work request under its own
//! key, and builds, attests and pins a checkpoint image over it. A fresh
//! install of the same vault, the same machine on the same keystore (the
//! machine id given by a test door), adopts that image and holds no row of
//! the request. An admitted machine floods the log there to the reserve, and
//! the pickup answers the request: refused, since its world does not exist.
//! Red where the reserve reads the stored row alone (main f75de13f): the
//! request stays pending.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_adopted`.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityEntryStatus,
    AuthorityKey, AuthorityLogEntry, AuthorityObservationPolicy, AuthorityOp, AuthoritySignature,
    AuthorityVaultId, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, OwnerAct, OwnerActKind, OwnerWorkBody, OwnerWorkRequest, WorldKeyMode,
    WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::adopted_owner_work::{take_machine_identity, this_install_machine_key};
use oneiron::{EntityId, ErrorKind, OpenOptions, TimeRange, Vault, VaultConfig, VaultStorageId};

/// The test's memory floor, as in `authority_log_owner_reserve.rs`: the
/// fixture's own log folds well under it (asserted), and about ninety
/// chained rows pass it.
const FLOOR_BYTES: u64 = 4 * 1024 * 1024;

/// The most flood rows the test signs before it gives up.
const FLOOD_CAP: u64 = 400;

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A machine the owner admitted, whose install key the test holds: no owner
/// key, no slip issuer, and not this install's key.
struct Flooder {
    machine: EntityId,
    signing: SigningKey,
    /// The entry that carried its admission.
    admission: AuthorityEntryHash,
}

fn admit_flooder(vault: &Vault, proof: &AuthenticatedOwner, vault_id: AuthorityVaultId) -> Flooder {
    let signing = SigningKey::from_bytes(&[0xF1; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
        restored_from: None,
    };
    let folded = vault
        .enroll_machine(
            proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine")
        .into_standing()
        .expect("the owner's admission stands");
    let admission = folded
        .chains()
        .map(|(_, head)| head)
        .max_by_key(|head| head.profile.revision)
        .expect("the admission's revision")
        .entry;
    Flooder {
        machine,
        signing,
        admission,
    }
}

/// `op` signed by `signing` at `seq` on `parents`.
fn row_signed_by(
    vault_id: AuthorityVaultId,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: parents,
        op,
        overlay_seed,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn set_floor(vault: &Vault, floor_bytes: u64) {
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(floor_bytes),
            ..AuthorityObservationPolicy::default()
        })
        .expect("the floor row");
}

/// How a flood ended.
#[derive(Debug)]
enum FloodEnd {
    /// The door held this row: the log reached its owner reserve.
    Waited(Box<AuthorityLogEntry>),
    /// Every row landed and the fold passed its memory floor.
    PastFloor,
    /// Every row landed, and the fold stayed under its floor.
    Cap,
}

/// The flooder signs one chain of its own world edits on `parent` from
/// sequence `first`, until the door holds a row, the fold passes its floor,
/// or [`FLOOD_CAP`] rows landed. Returns the rows that landed.
fn flood_on(
    vault: &Vault,
    (vault_id, owner): (AuthorityVaultId, EntityId),
    flooder: &Flooder,
    parent: AuthorityEntryHash,
    first: u64,
) -> (u64, FloodEnd) {
    let world = EntityId::now();
    let mut parent = parent;
    for landed in 0..FLOOD_CAP {
        let seq = first + landed;
        let edit = AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            world,
            act: OwnerAct::by_owner(
                owner,
                OwnerActKind::WorldPrivacy,
                world,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine: flooder.machine,
            settings: WorldPrivacy::default(),
        });
        let row = row_signed_by(vault_id, &flooder.signing, seq, vec![parent], edit);
        match vault.put_authority_log_entry(&row, AT, 1) {
            Ok(_) => parent = authority_entry_hash(&row).expect("hash"),
            Err(error) if error.kind() == ErrorKind::AuthorityLogFull => {
                return (landed, FloodEnd::Waited(Box::new(row)));
            }
            Err(error) => panic!("flood row {seq} was refused, not held: {error}"),
        }
        if vault
            .authority_fold()
            .expect("the fold")
            .authority_log_past_bound()
        {
            return (landed + 1, FloodEnd::PastFloor);
        }
    }
    (FLOOD_CAP, FloodEnd::Cap)
}

fn stored_history(vault: &Vault) -> Vec<Vec<u8>> {
    vault
        .export_signed_authority_history()
        .expect("the install's history")
}

/// The source install carries a request that this install, `here`, do key
/// work for a world that does not exist, under its own machine key, and
/// builds an attested image over it. A fresh install of the vault, the same
/// machine on the same keystore, adopts the image: it holds the request only
/// through the image. Its log is then flooded to the reserve. The request is
/// the owner's work there, as on the source, so the pickup answers it (its
/// answer is the refusal the missing world gives) and the fold stays under
/// its floor. Red at f75de13f: the reserve finds no stored row of the
/// request, takes it as another machine's, and the pickup leaves it pending.
#[test]
fn a_request_this_install_carried_that_an_adopted_image_holds_is_answered_past_the_reserve() {
    let keys = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let source_dir = tempfile::tempdir().expect("tempdir");
    let source = Vault::open(source_dir.path(), VaultConfig::device()).expect("the source install");
    source.install_device_keystore(keys.clone());
    let issuer = oneiron::test_support::provision_engine_machines(&source);
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the source install's live machine profile");
    let owner = source.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&source, &issuer, owner).expect("the owner's binding");
    let proof = source
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = source
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    let here = source
        .local_machine()
        .expect("the source install")
        .expect("the source install's machine")
        .id;
    source
        .set_machine_role(
            &proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks the source install yours");
    let flooder = admit_flooder(&source, &proof, vault_id);

    let install_key = this_install_machine_key(&source).expect("the source install's machine key");
    let carrier = AuthorityKey::Ed25519(install_key.verifying_key().to_bytes());
    let seq = stored_history(&source)
        .iter()
        .map(|body| decode_authority_log_entry_body(body).expect("a stored row"))
        .filter(|row| *row.signer_key() == carrier)
        .map(|row| row.seq)
        .max()
        .expect("FIXTURE: the source install signed the owner's answers it carried")
        + 1;
    let world = EntityId::now();
    let request = row_signed_by(
        vault_id,
        &install_key,
        seq,
        vec![flooder.admission],
        AuthorityOp::OwnerWorkRequest(OwnerWorkRequest {
            carrier: here,
            act: OwnerAct::by_owner(
                owner,
                OwnerActKind::WorldKeyRequest,
                world,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            executor: here,
            work: OwnerWorkBody::WorldKey {
                mode: WorldKeyMode::Ensure,
            },
            privacy_basis: None,
        }),
    );
    source
        .put_authority_log_entry(&request, AT, 1)
        .expect("the source install stores the request it carries");
    let request_hash = authority_entry_hash(&request).expect("hash");

    let image_id = source
        .write_authority_checkpoint_v2(&issuer)
        .expect("the source install builds and attests its image");
    let pin = source
        .authority_checkpoint_pin([7; 32])
        .expect("the pin")
        .expect("FIXTURE: the source install's image reached quorum");
    assert_eq!(pin.checkpoint, image_id, "FIXTURE: the pin names the image");
    let bundle = source
        .authority_checkpoint_bundle(&image_id)
        .expect("the bundle")
        .expect("FIXTURE: the source install keeps the image");
    let image = source
        .authority_checkpoint_v2(&image_id)
        .expect("the image")
        .expect("FIXTURE: the source install keeps the image");
    assert!(
        image
            .rows
            .get(&request_hash)
            .is_some_and(|row| row.body.is_some()),
        "FIXTURE: the image covers the request and carries its body"
    );

    let adopter_dir = tempfile::tempdir().expect("tempdir");
    let adopter = Vault::open_owned_with(
        adopter_dir.path(),
        VaultConfig::device(),
        OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(&pin)),
    )
    .expect("the adopting install");
    adopter.install_device_keystore(keys);
    take_machine_identity(&adopter, here).expect("FIXTURE: the adopting install takes the machine");
    assert_eq!(
        adopter.prepare_install_signing().expect("its keys load"),
        here,
        "FIXTURE: the adopting install is the source install's machine"
    );
    // The pairing door, or, for an image built under a pin, the recovery door
    // that pins its root first on an install that holds none.
    let adopted = match image.building_pin {
        Some(root) => adopter.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().expect("the pin's digest"),
            root,
        ),
        None => adopter.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    };
    assert_eq!(
        adopted.expect("the adopting install adopts the source install's image"),
        image_id
    );
    assert!(
        matches!(
            adopter
                .authority_log_entry_status(&request_hash)
                .expect("the request's status"),
            AuthorityEntryStatus::CoveredAttested { .. }
        ),
        "FIXTURE: the adopting install holds the request through the image alone, no raw row"
    );

    set_floor(&adopter, FLOOR_BYTES);
    let fold = adopter.authority_fold().expect("the fold");
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "FIXTURE: the adopted log folds under the test's floor"
    );
    let (landed, end) = flood_on(&adopter, (vault_id, owner), &flooder, request_hash, 1);
    let FloodEnd::Waited(_) = end else {
        panic!(
            "after {landed} flood rows the flood ended {end:?}: no row waited at the owner \
             reserve"
        );
    };

    let drain = adopter
        .run_pending_owner_work(|| true)
        .expect("the pickup runs");
    assert_eq!(
        (drain.enacted, drain.refused, drain.pending, drain.failed),
        (0, 1, 0, 0),
        "the pickup left the request this install carried pending past the reserve: the reserve \
         took a request the adopted image holds as another machine's: {drain:?}"
    );
    let fold = adopter.authority_fold().expect("the fold");
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
    let again = adopter
        .run_pending_owner_work(|| true)
        .expect("the pickup runs again");
    assert_eq!(
        (again.enacted, again.refused, again.pending, again.failed),
        (0, 0, 0, 0),
        "the answer stands: no work is left for this install: {again:?}"
    );
}

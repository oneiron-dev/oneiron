//! A carried act's owner key proof, which buys only room past another
//! install's owner reserve, is no signature the revocation fence reads (row
//! OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, REVIEW-9946 P1). Since #9892
//! a carried act may carry one owner key's proof beside its carrier's
//! install signature, and since #9904 the owner's own acts do. The fence of a
//! revocation (`authority/retired_signers.rs`) holds the revoked key: a row
//! that key signs on a branch the revocation never saw stands nowhere. Read
//! for the cosign as well, the fence would drop the owner's act whose proof
//! that key gave, where the same act carried unproven stands: a residence
//! result would vanish and its directive run again.
//!
//! A host-rooted vault, as a host starts one. The owner enrols two owner
//! signing keys through the owner key enrollment door, O and K, and install
//! A holds K, so the owner's acts A carries carry K's proof. The owner sets a
//! federation grant's travel on A: the choice T carries K's cosign. K then
//! signs a federation confirmation C of its own on T. O revokes K in R,
//! naming the heads before T, so R never saw T or C.
//!
//! Red at main 94477453 (the fence reads every cosign): the fold refuses T
//! as `RetiredSigner`. Green at the head: T stands; C, which K signs itself,
//! stays refused, and K is revoked.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_cosign_fence`.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineRole,
    OwnerKeyEnrollment, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::share_travel::{BornWithField, TravelChoice};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A company vault no fixture opens: the inquiry edge mints before any pact.
const UNOPENED_COMPANY: AuthorityVaultId = [0xac; 32];

/// A rooted vault as a host starts one: the owner bound under the host root
/// and this install profiled, so it carries the owner's acts.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        issuer,
        proof,
        vault_id,
    }
}

/// A machine the owner admits through the door, its key from `seed`.
fn admit_machine(rooted: &Rooted, seed: u8) -> EntityId {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &rooted.vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
        restored_from: None,
    };
    rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner admits the machine");
    machine
}

/// The owner enrols `signing` as an owner key held on `machine`, through
/// the public owner key enrollment door.
fn enrol_owner_key(rooted: &Rooted, machine: EntityId, signing: &SigningKey) {
    let authority = ActAuthority::Owner(rooted.proof.clone(), ActSurface::ThisInstall);
    let public_key = signing.verifying_key().to_bytes();
    let challenge = rooted
        .vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("FIXTURE: the enrollment's challenge");
    rooted
        .vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: signing.sign(&challenge).to_bytes().to_vec(),
            },
            &rooted.issuer,
        )
        .expect("FIXTURE: the owner enrols the key");
}

/// An owner key install A holds, as a device holds its enrolled owner
/// signing key: it proves every owner act A carries.
struct HeldOwnerKey(SigningKey);

impl oneiron::authority::CheckpointRootSigner for HeldOwnerKey {
    fn root(&self) -> AuthorityKey {
        key_of(&self.0)
    }

    fn sign_checkpoint_statement(
        &self,
        _vault: &Vault,
        statement: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(statement).to_bytes().to_vec())
    }

    fn sign_owner_proof(
        &self,
        _vault: &Vault,
        _fold: &AuthorityFold,
        transcript: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }

    fn sign_ask_word_proof(
        &self,
        _vault: &Vault,
        _fold: &AuthorityFold,
        transcript: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `op` signed by `signing` alone at `seq` on `parents`.
fn row_signed_by(
    rooted: &Rooted,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let key = key_of(signing);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op,
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

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

/// Every row A stores, decoded.
fn stored_rows(rooted: &Rooted) -> Vec<AuthorityLogEntry> {
    rooted
        .vault
        .export_signed_authority_history()
        .expect("A's history")
        .iter()
        .map(|body| decode_authority_log_entry_body(body).expect("a stored row"))
        .collect()
}

/// The heads of A's history: every row no other row names as a parent.
fn heads(rooted: &Rooted) -> Vec<AuthorityEntryHash> {
    let rows = stored_rows(rooted);
    let named: BTreeSet<AuthorityEntryHash> = rows
        .iter()
        .flat_map(|row| row.parent_hashes.iter().copied())
        .collect();
    let mut heads: Vec<AuthorityEntryHash> = rows
        .iter()
        .map(hash_of)
        .filter(|hash| !named.contains(hash))
        .collect();
    heads.sort_unstable();
    heads
}

fn is_live(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles != 0)
}

/// The put door's outcome for `row`, as text for the assertion messages.
fn put(rooted: &Rooted, row: &AuthorityLogEntry) -> String {
    match rooted.vault.put_authority_log_entry(row, AT, 1) {
        Ok(_) => "stored".to_owned(),
        Err(error) => format!("refused: {:?}", error.kind()),
    }
}

#[test]
fn a_revoked_cosign_key_leaves_the_owners_carried_act_standing() {
    let rooted = rooted();
    let holder = admit_machine(&rooted, 0xA1);
    let revoker = SigningKey::from_bytes(&[0x4F; 32]);
    let proved_with = SigningKey::from_bytes(&[0x4B; 32]);
    enrol_owner_key(&rooted, holder, &revoker);
    enrol_owner_key(&rooted, holder, &proved_with);
    rooted
        .vault
        .hold_checkpoint_root_signer(Arc::new(HeldOwnerKey(proved_with.clone())));
    let edge = rooted
        .vault
        .mint_inquiry_edge(
            &rooted.proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_COMPANY, "Acme"),
        )
        .expect("FIXTURE: the owner mints a federation grant on A");
    let before_the_act = heads(&rooted);

    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Why]),
    };
    rooted
        .vault
        .set_federation_grant_travel_as(
            &rooted.proof,
            ActSurface::ThisInstall,
            &edge.grant,
            Some(choice),
            None,
            rooted.vault.now_recorded_at(),
        )
        .expect("the owner sets the grant's travel on A");
    let acts: Vec<AuthorityLogEntry> = stored_rows(&rooted)
        .into_iter()
        .filter(|row| matches!(row.op, AuthorityOp::GrantTravelSet(_)))
        .collect();
    let [act] = acts.as_slice() else {
        panic!("A carried the owner's travel choice once: {acts:?}");
    };
    assert_eq!(
        act.cosigns
            .iter()
            .map(|cosign| &cosign.public_key)
            .collect::<Vec<_>>(),
        vec![&key_of(&proved_with)],
        "FIXTURE: the travel choice carries K's proof beside A's install key"
    );
    let act_hash = hash_of(act);

    let own_row = row_signed_by(
        &rooted,
        &proved_with,
        1,
        vec![act_hash],
        AuthorityOp::FederationConfirm(AuthorityConfirmAction {
            kind: AuthorityConfirmKind::Accept,
            confirm_id: [0x33; 32],
            peer_vault_id: [0x77; 32],
            epoch: 1,
            nonce: [0x33; 16],
        }),
    );
    assert_eq!(
        put(&rooted, &own_row),
        "stored",
        "FIXTURE: A stores the confirmation K signs on the travel choice"
    );
    let revocation = row_signed_by(
        &rooted,
        &revoker,
        1,
        before_the_act,
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&proved_with),
        },
    );
    assert_eq!(
        put(&rooted, &revocation),
        "stored",
        "FIXTURE: A stores O's revocation of K"
    );

    let fold = rooted.vault.authority_fold().expect("A's fold");
    assert!(
        fold.valid_entries.contains(&hash_of(&revocation))
            && !is_live(&fold, &key_of(&proved_with)),
        "FIXTURE: O's revocation stands and K is revoked; issues {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&act_hash),
        "the owner's travel choice stands though the key of its proof is revoked on a branch that \
         never saw it, as it stands unproven; issues {:?}",
        fold.issues
    );
    let own_hash = hash_of(&own_row);
    assert!(
        !fold.valid_entries.contains(&own_hash)
            && fold
                .issues
                .contains(&AuthorityFoldIssue::RetiredSigner(own_hash)),
        "the confirmation K signs itself outside its revocation stays fenced; issues {:?}",
        fold.issues
    );
}

//! F1 (R1, review #8845 P1-1): a Grant withdrawal on a branch settlement drops
//! still ends the Grant's line, so the Grant's row put back stands for nothing.
//!
//! Expected: red at e007af107094 (and 9c2869976776), where a dropped owner's
//! revoke proves nothing, so the put-back row stands; green at 986a4738563a
//! (and 62a0b0981c43), where its proof ends the line.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_review_dropped_end`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerKeyEnrollment,
    authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_grant_act};
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A rooted vault as a host starts one: the owner bound under the host root
/// and this install profiled, so it carries the owner's answers.
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

/// A machine the owner admitted, whose keystore holds the owner keys the
/// test enrols.
fn admit_machine(rooted: &Rooted) -> EntityId {
    let signing = SigningKey::from_bytes(&[0xA1; 32]);
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
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine");
    assert!(folded.is_mine(None), "the admitted machine is the owner's");
    machine
}

/// The owner enrols `signing` as an owner key held on `machine`, through
/// the public owner key enrollment door; returns the enrollment's entry.
fn enrol_owner_key(rooted: &Rooted, machine: EntityId, signing: &SigningKey) -> AuthorityEntryHash {
    let authority = ActAuthority::Owner(rooted.proof.clone(), ActSurface::ThisInstall);
    let public_key = signing.verifying_key().to_bytes();
    let challenge = rooted
        .vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the enrollment's challenge");
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
        .expect("the owner enrols the key")
        .entry
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `op` signed by `signing` at `seq` on `parents`.
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

/// The put door's outcome for `row`, as text for the assertion messages.
fn put(rooted: &Rooted, row: &AuthorityLogEntry) -> String {
    match rooted.vault.put_authority_log_entry(row, AT, 1) {
        Ok(_) => "stored".to_owned(),
        Err(error) => format!("refused: {:?}", error.kind()),
    }
}

/// A federation confirmation with `confirm_id` and `nonce`.
fn confirmation(confirm_id: [u8; 32], nonce: [u8; 16]) -> AuthorityOp {
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: [0x77; 32],
        epoch: 1,
        nonce,
    })
}

/// The first confirmation `signing` signs with `confirm_id` at `seq` on
/// `parents` whose hash is below `below`. Its nonce starts 0xC0, which no
/// other row's nonce here does, so it collides only through `confirm_id`.
/// About one try in two lands below.
fn colliding_below(
    rooted: &Rooted,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    confirm_id: [u8; 32],
    below: AuthorityEntryHash,
) -> AuthorityLogEntry {
    (0..=u64::MAX)
        .map(|counter| {
            let mut nonce = [0xC0; 16];
            nonce[8..].copy_from_slice(&counter.to_be_bytes());
            row_signed_by(
                rooted,
                signing,
                seq,
                parents.clone(),
                confirmation(confirm_id, nonce),
            )
        })
        .find(|row| hash_of(row) < below)
        .expect("a nonce whose confirmation hashes below the one it collides with")
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The entry hash an act reference names (its hex).
fn unhex(text: &str) -> AuthorityEntryHash {
    assert_eq!(
        text.len(),
        64,
        "an act reference is 32 bytes of hex: {text}"
    );
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex act ref");
    }
    bytes
}

/// Puts `body` at `id` as another of the owner's devices would send it: own-device replay,
/// which judges no standing.
fn put_from_own_device(vault: &Vault, id: EntityId, body: &[u8]) {
    let now = vault.now_recorded_at();
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
    .expect("own-device replay lands the row");
}

/// K enrolled (its enrollment is the head P); C = K's confirmation at K's sequence 1 on P;
/// the owner's revoke of G lands on C; B = K's confirmation with C's id at K's sequence 2 on
/// P, with a hash below C's. Settlement drops C with the revoke; the revoke's proof must
/// still end G's line, so G's row put back stands for nothing.
#[test]
fn a_dropped_owner_revoke_still_ends_its_grants_line() {
    let rooted = rooted();
    let agent = rooted
        .vault
        .ensure_agent_principal("dropped-end-agent")
        .expect("a named agent principal");
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &rooted.vault,
        &rooted.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    let grant = minted.grant.grant_ref;
    let act = minted.act_ref;
    assert!(minted.grant.confers, "precondition: the Grant is live");
    let body = grant_row(&rooted.vault, grant)
        .expect("grant row read")
        .expect("the minted row is live");
    let now = rooted.vault.now_recorded_at();
    assert_eq!(
        grant_line(&rooted.vault, grant)
            .expect("grant line")
            .map(|(given, ended)| (given.map(hex), ended)),
        Some((Some(act.clone()), false)),
        "precondition: the line gives the Grant on the owner's mint",
    );
    assert_eq!(
        standing_grant_act(&rooted.vault, grant, now)
            .expect("standing read")
            .map(hex),
        Some(act.clone()),
        "precondition: the minted row stands on the owner's mint",
    );
    let machine = admit_machine(&rooted);
    let colliding = SigningKey::from_bytes(&[0x4B; 32]);
    let enrolled = enrol_owner_key(&rooted, machine, &colliding);
    let confirm_id = [0x31; 32];
    let confirmed = row_signed_by(
        &rooted,
        &colliding,
        1,
        vec![enrolled],
        confirmation(confirm_id, [0x01; 16]),
    );
    let put_confirmed = put(&rooted, &confirmed);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert_eq!(
        put_confirmed, "stored",
        "the confirmation is stored; issues {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&hash_of(&confirmed)),
        "setup: before the collision C is valid; issues {:?}",
        fold.issues
    );
    let revoked = revoke_agent_grant_as(
        &rooted.vault,
        &rooted.proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant,
            seen: None,
        },
    )
    .expect("owner revokes the Grant");
    assert!(revoked.changed, "precondition: the revoke landed an act");
    let revoke_act = unhex(
        revoked
            .act_ref
            .as_deref()
            .expect("precondition: the revoke names its act"),
    );
    assert!(
        rooted
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&revoke_act),
        "setup: before the collision the revoke's act is valid",
    );
    assert_eq!(
        grant_row(&rooted.vault, grant).expect("row read"),
        None,
        "precondition: the revoke deleted the row",
    );
    assert_eq!(
        grant_line(&rooted.vault, grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(true),
        "setup: before the collision the revoke ends the Grant's line",
    );
    let collision = colliding_below(
        &rooted,
        &colliding,
        2,
        vec![enrolled],
        confirm_id,
        hash_of(&confirmed),
    );
    let arrival = put(&rooted, &collision);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert_eq!(
        arrival, "stored",
        "the colliding confirmation is stored; issues {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&hash_of(&collision))
            && !fold.valid_entries.contains(&hash_of(&confirmed))
            && !fold.valid_entries.contains(&revoke_act),
        "setup: the lower-hash confirmation wins the collision and the revoke goes with C; \
         issues {:?}",
        fold.issues
    );
    assert_eq!(
        grant_line(&rooted.vault, grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(true),
        "a dropped end still ends its Grant's line; issues {:?}",
        fold.issues,
    );
    put_from_own_device(&rooted.vault, grant, &body);
    assert_eq!(
        grant_row(&rooted.vault, grant).expect("row read"),
        Some(body),
        "precondition: the put-back row is live at the Grant's id",
    );
    let now = rooted.vault.now_recorded_at();
    assert_eq!(
        standing_grant_act(&rooted.vault, grant, now).expect("standing read"),
        None,
        "grant={grant:?}; expected the put-back row to stand for nothing",
    );
}

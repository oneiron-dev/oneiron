//! A revoked key's later fork never undoes its revocation, on any install
//! (OPUS-SECREAD-A's cold read of #8449, N1 P1; Engine ASK
//! SEQ-FLOOR-FORK-ROLLBACK, 16 Nov 01:35).
//!
//! The owner enrols a second owner device K. K signs a granting row X. The
//! owner, from its first device, revokes K on X, as a client that parents on
//! its heads does. Later K's holder signs Y: K's next sequence, on X's
//! parent, so Y does not descend from X. Y arrives after the install already
//! holds X and the revocation. K must stay revoked, and X and the revocation
//! must stay valid: a fork of a key never takes back what an install already
//! counted, and never undoes the owner's revocation of that key.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityFold,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER,
    authority_entry_hash, authority_transcript, genesis_vault_id,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 2, end: 2 };
fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent: Option<&AuthorityLogEntry>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parent
            .map(|parent| vec![authority_entry_hash(parent).expect("parent hash")])
            .unwrap_or_default(),
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
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// The owner's genesis and the vault it founds.
fn genesis(owner: &SigningKey, nonce: u8) -> (AuthorityLogEntry, AuthorityVaultId) {
    let genesis = signed(
        None,
        0,
        None,
        AuthorityOp::Genesis {
            device: device(key_of(owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [nonce; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        owner,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    (genesis, vault_id)
}

/// `signer` enrols the agent key `enrolled` on `parent` at `seq`.
fn enrolment(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    enrolled: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        Some(vault_id),
        seq,
        Some(parent),
        AuthorityOp::EnrollDevice {
            device: device(key_of(enrolled), ROLE_AGENT),
        },
        signer,
    )
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

fn applied(fold: &AuthorityFold) -> BTreeSet<AuthorityEntryHash> {
    fold.valid_entries.iter().copied().collect()
}

fn is_live(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles != 0)
}

/// A fresh install that receives `rows` one at a time, in the order given,
/// through the authority write door, and folds its log after the last.
/// Returns each put's outcome and that fold.
fn install_receiving(rows: &[&AuthorityLogEntry]) -> (Vec<String>, AuthorityFold) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let mut puts = Vec::new();
    for row in rows {
        puts.push(match vault.put_authority_log_entry(row, AT, 2) {
            Ok(_) => "stored".to_owned(),
            Err(error) => format!("refused: {:?}", error.kind()),
        });
    }
    let fold = vault.authority_fold().expect("the install folds its log");
    (puts, fold)
}

/// Genesis by owner device O (sequence 0); O enrols a second owner device K
/// (1) and agent U (2); K binds U to an actor (K's sequence 1), a granting
/// row; O revokes K on that binding (3). Later K signs Y, its sequence 2, an
/// enrolment of agent W on U's enrolment, the binding's parent: Y does not
/// descend from the binding. The install received the binding and the
/// revocation before Y.
#[test]
fn a_revoked_keys_later_fork_never_undoes_its_revocation() {
    let owner = SigningKey::from_bytes(&[251; 32]);
    let second_owner = SigningKey::from_bytes(&[252; 32]);
    let agent = SigningKey::from_bytes(&[253; 32]);
    let fork_agent = SigningKey::from_bytes(&[254; 32]);
    let (genesis, vault_id) = genesis(&owner, 250);
    let enrol_second_owner = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        AuthorityOp::EnrollDevice {
            device: device(key_of(&second_owner), ROLE_OWNER | ROLE_ADMIN),
        },
        &owner,
    );
    let enrol_agent = enrolment(vault_id, &enrol_second_owner, &owner, 2, &agent);
    let binding = signed(
        Some(vault_id),
        1,
        Some(&enrol_agent),
        AuthorityOp::BindActor {
            authority_key: key_of(&agent),
            actor_ref: EntityId::now(),
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
        &second_owner,
    );
    let revocation = signed(
        Some(vault_id),
        3,
        Some(&binding),
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&second_owner),
        },
        &owner,
    );
    let fork = enrolment(vault_id, &enrol_agent, &second_owner, 2, &fork_agent);

    // The setup alone: without the fork, the binding and the revocation are
    // valid and K is revoked. A failure here is the test's setup, not the
    // finding.
    let before_fork = [
        &genesis,
        &enrol_second_owner,
        &enrol_agent,
        &binding,
        &revocation,
    ];
    let (puts, fold) = install_receiving(&before_fork);
    assert_eq!(
        applied(&fold),
        before_fork
            .into_iter()
            .map(hash_of)
            .collect::<BTreeSet<_>>(),
        "setup: before the fork every row is valid; puts {puts:?}, issues {:?}",
        fold.issues
    );
    assert!(
        !is_live(&fold, &key_of(&second_owner)),
        "setup: before the fork K is revoked; issues {:?}",
        fold.issues
    );

    let with_fork = [
        &genesis,
        &enrol_second_owner,
        &enrol_agent,
        &binding,
        &revocation,
        &fork,
    ];
    let (puts, fold) = install_receiving(&with_fork);
    assert!(
        !is_live(&fold, &key_of(&second_owner)),
        "K's fork after its revocation must not make K live again; puts {puts:?}, issues {:?}",
        fold.issues
    );
    let kept = [&binding, &revocation]
        .into_iter()
        .map(hash_of)
        .collect::<BTreeSet<_>>();
    assert!(
        kept.is_subset(&applied(&fold)),
        "the binding and the revocation the install already counted stay valid after K's \
         fork; puts {puts:?}, issues {:?}",
        fold.issues
    );
}

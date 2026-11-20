//! A row that only takes away lands on every install that holds it, whatever
//! order its rows arrive in ([SEQUENCE-FLOOR-DELIVERY-ORDER], root FIX-LIST;
//! Engine RULING SEQ-FLOOR-SHAPE = A, 15 Nov 16:37).
//!
//! A row's sequence floor is the highest sequence among its signer's rows in
//! its scope that do not descend from it, and a row below its floor forks its
//! signer's sequence: no install counts what it grants. A row that only takes
//! away is never floored, so a fork never keeps a revocation from an install.
//! Before, the floor was the highest sequence the install had received from
//! the signer before the row arrived: an install that received a later
//! sibling of the revocation first refused the revocation, and the revoked
//! actor stayed bound there alone.
//!
//! Each install folds its log after every row it receives, as an install
//! that reads its authority between deliveries does, so each fold after the
//! first may resume past the one before it. Each of those folds must equal
//! the fold of a fresh install that holds the same rows.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityFold,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER,
    actor_binding_is_active, authority_entry_hash, authority_transcript, genesis_vault_id,
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

/// One install: a fresh vault that receives `rows` one at a time, in the
/// order given, each through the authority write door on its own, as rows
/// that sync delivers in that order arrive, and that folds its log after
/// each one. Returns each put's outcome and the fold after each put.
struct Install {
    _dir: tempfile::TempDir,
    puts: Vec<String>,
    folds: Vec<AuthorityFold>,
}

fn install_folding_after_each(rows: &[&AuthorityLogEntry]) -> Install {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let mut puts = Vec::new();
    let mut folds = Vec::new();
    for row in rows {
        puts.push(match vault.put_authority_log_entry(row, AT, 2) {
            Ok(_) => "stored".to_owned(),
            Err(error) => format!("refused: {:?}", error.kind()),
        });
        folds.push(vault.authority_fold().expect("the install folds its log"));
    }
    Install {
        _dir: dir,
        puts,
        folds,
    }
}

/// The fold of a fresh install that receives `rows` in the order given and
/// folds its log once, after the last.
fn folded_once(rows: &[&AuthorityLogEntry]) -> AuthorityFold {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    for row in rows {
        // A refused put leaves the row out, as it does on the install that
        // folds after each row; the folds compare what each install holds.
        let _ = vault.put_authority_log_entry(row, AT, 2);
    }
    vault.authority_fold().expect("the install folds its log")
}

/// The owner enrols agent U (sequence 1), binds U to an actor on that row
/// (2), and revokes the binding on it (3); as a sibling of the revocation,
/// on the binding, it enrols agent W (4). The enrolment of W does not
/// descend from the revocation, so the revocation sits below its floor on
/// every install. It only takes away, so it lands on every install: install
/// I receives the rows in that order, install J receives W's enrolment
/// before the revocation, and both hold U's binding revoked. No roster row
/// names the revocation, so no roster row vouches for it on J.
#[test]
fn an_actor_revocation_below_its_floor_lands_in_either_arrival_order() {
    let owner = SigningKey::from_bytes(&[241; 32]);
    let revoked_agent = SigningKey::from_bytes(&[242; 32]);
    let later_agent = SigningKey::from_bytes(&[243; 32]);
    let (genesis, vault_id) = genesis(&owner, 244);
    let actor = EntityId::now();
    let enrol_revoked = enrolment(vault_id, &genesis, &owner, 1, &revoked_agent);
    let binding = signed(
        Some(vault_id),
        2,
        Some(&enrol_revoked),
        AuthorityOp::BindActor {
            authority_key: key_of(&revoked_agent),
            actor_ref: actor,
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
        &owner,
    );
    let revocation = signed(
        Some(vault_id),
        3,
        Some(&binding),
        AuthorityOp::RevokeActor {
            authority_key: key_of(&revoked_agent),
            epoch: 1,
        },
        &owner,
    );
    let enrol_later = enrolment(vault_id, &binding, &owner, 4, &later_agent);

    let in_order = [
        &genesis,
        &enrol_revoked,
        &binding,
        &revocation,
        &enrol_later,
    ];
    let sibling_first = [
        &genesis,
        &enrol_revoked,
        &binding,
        &enrol_later,
        &revocation,
    ];
    let all = in_order.into_iter().map(hash_of).collect::<BTreeSet<_>>();

    for (name, rows) in [
        ("I (revocation first)", &in_order),
        ("J (W's enrolment first)", &sibling_first),
    ] {
        let install = install_folding_after_each(rows);
        for received in 1..=rows.len() {
            let fold = &install.folds[received - 1];
            let fresh = folded_once(&rows[..received]);
            assert_eq!(
                applied(fold),
                applied(&fresh),
                "install {name} after {received} rows: its fold after each row must equal the \
                 fold of a fresh install holding the same rows; puts {:?}, issues {:?}, fresh \
                 issues {:?}",
                install.puts,
                fold.issues,
                fresh.issues
            );
        }
        let fold = install.folds.last().expect("a fold per row");
        assert_eq!(
            applied(fold),
            all,
            "install {name} holds every row as valid, the revocation below its floor too; \
             puts {:?}, issues {:?}",
            install.puts,
            fold.issues
        );
        assert!(
            !actor_binding_is_active(fold, &actor, "agent"),
            "install {name} must hold U's binding revoked; puts {:?}, issues {:?}",
            install.puts,
            fold.issues
        );
        assert!(
            is_live(fold, &key_of(&later_agent)),
            "install {name} holds the later agent; issues {:?}",
            fold.issues
        );
    }
}

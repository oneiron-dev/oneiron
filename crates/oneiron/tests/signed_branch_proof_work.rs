//! The fold proves each restriction (an actor or device revocation, a
//! machine removal, a dropped slip withdrawal) on its own signed branch. Row
//! [REVOKE-PROOF-BRANCH-REFOLD-CUBIC]: each proof re-folded its whole branch
//! in passes over the rows in hash order until its row folded, about one
//! chain row a pass, so a chain of owner-signed revocations cost about n^3
//! row transitions (a 751-row chain: 459 s of fold against 0.12 s for its
//! per-row state pass, job 1117-090217-f045). The proofs must try each row a
//! bounded number of times, whatever the number of restrictions above it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test signed_branch_proof_work`.

// The test door is compiled only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId,
    DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, authority_entry_hash,
    authority_transcript, genesis_vault_id,
};
use oneiron::test_doors::authority_signed_branch as door;

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// The `n`th key of the family `tag`.
fn numbered_key(tag: u8, n: usize) -> SigningKey {
    let mut seed = [tag; 32];
    seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

fn numbered_id(tag: u8, n: usize) -> EntityId {
    let mut bytes = [tag; 16];
    bytes[8..].copy_from_slice(&(n as u64).to_be_bytes());
    EntityId::from_bytes(bytes).expect("entity id")
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

/// `signer`'s row `op` at `seq` on `parents`, cosigned by `cosigner`.
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigner: Option<&SigningKey>,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
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
    if let Some(cosigner) = cosigner {
        let key = key_of(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        });
    }
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    if let Some(cosigner) = cosigner {
        entry.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// One chain, each row on the one before: the owner's genesis, `agents`
/// agent key enrolments, then for each agent the owner's binding of it to
/// an actor (cosigned by the agent's key) and the owner's revocation of it.
/// Every row counts, and each revocation is a restriction the fold proves on
/// the whole chain below it.
fn revocation_chain(agents: usize) -> (Vec<AuthorityLogEntry>, Vec<AuthorityKey>) {
    let owner = numbered_key(0x91, 0);
    let genesis = signed(
        None,
        0,
        Vec::new(),
        AuthorityOp::Genesis {
            device: device(key_of(&owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [0x91; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        &owner,
        None,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    let mut head = authority_entry_hash(&genesis).expect("genesis hash");
    let mut entries = vec![genesis];
    let mut seq = 0;
    let mut push =
        |entries: &mut Vec<AuthorityLogEntry>, op: AuthorityOp, cosigner: Option<&SigningKey>| {
            seq += 1;
            let entry = signed(Some(vault_id), seq, vec![head], op, &owner, cosigner);
            head = authority_entry_hash(&entry).expect("row hash");
            entries.push(entry);
        };
    let agent_keys: Vec<SigningKey> = (0..agents).map(|n| numbered_key(0xA8, n)).collect();
    for agent in &agent_keys {
        push(
            &mut entries,
            AuthorityOp::EnrollDevice {
                device: device(key_of(agent), ROLE_AGENT),
            },
            None,
        );
    }
    for (n, agent) in agent_keys.iter().enumerate() {
        push(
            &mut entries,
            AuthorityOp::BindActor {
                authority_key: key_of(agent),
                actor_ref: numbered_id(0x76, n),
                actor_class: "system".to_owned(),
                epoch: 1,
            },
            Some(agent),
        );
        push(
            &mut entries,
            AuthorityOp::RevokeActor {
                authority_key: key_of(agent),
                epoch: 1,
            },
            None,
        );
    }
    (entries, agent_keys.iter().map(key_of).collect())
}

/// The row transitions the fold's restriction proofs tried on a revocation
/// chain of `agents` agents, per row of the chain, after checking that every
/// row counts and every agent key ends revoked.
fn proof_tries_per_row(agents: usize) -> f64 {
    let (entries, agent_keys) = revocation_chain(agents);
    let (fold, tries) = door::fold_counting_proof_tries(&entries);
    assert_eq!(
        fold.valid_entries.len(),
        entries.len(),
        "every row of the {agents}-agent chain counts"
    );
    for key in &agent_keys {
        assert!(
            fold.revoked_actor_keys.contains(key),
            "the {agents}-agent chain revokes every agent key"
        );
    }
    eprintln!(
        "REVOKE-PROOF-WORK agents={agents} rows={} proof_tries={tries}",
        entries.len()
    );
    tries as f64 / entries.len() as f64
}

#[test]
fn a_revocation_chain_proves_in_work_linear_in_its_rows() {
    // A chain four times as long holds four times the revocations, each on
    // a branch about four times as long. Work linear in the rows tries each
    // row about as often in both; the per-branch passes tried each row of
    // the longer chain about sixteen times as often.
    let short = proof_tries_per_row(10);
    let long = proof_tries_per_row(40);
    assert!(
        long <= 2.0 * short,
        "the restriction proofs try each row of a 121-row chain {long:.1} times, \
         against {short:.1} times on a 31-row chain: their work grows faster than the log"
    );
}

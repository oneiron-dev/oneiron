//! The fold's per-row states hold persistent maps and sets since row
//! [ROSTER-KEY-LOG-FLOOD] PR 2, where they held `BTreeMap` and `BTreeSet`.
//! The PR is Stored change: keep, so a checkpoint image's states must encode
//! to the bytes the base wrote, and the bytes the base wrote must decode and
//! re-encode to themselves.
//!
//! `seeded_logs_fold_to_states_that_reencode_to_the_same_bytes` folds logs
//! built from fixed seeds (every key, id and nonce is a function of its row
//! number) and prints one `FOLD-ENCODING` line per log: the sha256 of every
//! row's state bytes, of the merged state's bytes and of the whole vault
//! fold's bytes. Op families (each row adds one entry to a per-row state
//! map): `confirm` (federation confirms), `critical` (critical write
//! confirms and their nonces), `enroll` (roster), `residence` (residence
//! directives) in `chain`, `star` and `grid` shapes; `agents` (enrol, then
//! bind) and `revoke` (enrol, bind, revoke the binding, revoke the device)
//! as chains. 100 rows a log takes the chains' maps past the persistent
//! form's 64-entry small limit. The proof is a run at the base and a run at
//! the head with the same lines: the base run's lines are the golden.
//!
//! `a_rooted_vaults_image_and_row_states_reencode_to_the_same_bytes` builds
//! a vault from its own doors (the host root, the engine's machines, this
//! install marked the owner's, two worlds kept here, two admitted machines,
//! one of them removed), then checks that its checkpoint image decodes and
//! re-encodes to its own bytes, and that every row's state of its log does.
//! Its ids are random, so it compares within one build.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fold_state_encoding -- --nocapture`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityCheckpointV2,
    AuthorityConfirmAction, AuthorityConfirmKind, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId,
    CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION, CriticalWriteConfirmAction,
    CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod, DeviceAuthority,
    GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, ReadLocation, ResidenceAct,
    ResidenceDirective, WorldPrivacy, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, fold_authority_log_with_seen_times, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_fold_encoding::{StateEncodings, reencoded, state_encodings};
use oneiron::{EntityId, Vault, VaultConfig};
use sha2::{Digest, Sha256};

/// Rows a seeded log holds after its genesis.
const ROWS: usize = 100;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// The `n`th key of the family `tag`.
fn numbered_key(tag: u8, n: usize) -> SigningKey {
    let mut seed = [tag; 32];
    seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

/// `n` in the last eight bytes of `WIDTH` bytes of `tag`.
fn numbered<const WIDTH: usize>(tag: u8, n: usize) -> [u8; WIDTH] {
    let mut bytes = [tag; WIDTH];
    bytes[WIDTH - 8..].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

fn numbered_id(tag: u8, n: usize) -> EntityId {
    EntityId::from_bytes(numbered(tag, n)).expect("entity id")
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

/// Row `n`'s op of `family`, and the key that cosigns it.
fn family_op(family: &str, n: usize) -> (AuthorityOp, Option<SigningKey>) {
    match family {
        "confirm" => (
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: numbered(0xC0, n),
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: numbered(0xC1, n),
            }),
            None,
        ),
        "critical" => (
            AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
                schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                confirm_id: numbered(0xC2, n),
                gate_decision_id: numbered(0xC3, n),
                claim_id: numbered_id(0x72, n),
                effect_digest: [0xE1; 32],
                read_frontier_hash: [0xF1; 32],
                nonce: numbered(0xC4, n),
                expires_at: 4_000_000_000,
                disposition: CriticalWriteConfirmDisposition::Clear,
                method: CriticalWriteConfirmMethod::TokenReauth,
            }),
            None,
        ),
        "enroll" => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA7, n)), ROLE_AGENT),
            },
            None,
        ),
        "residence" => (
            AuthorityOp::ResidenceDirective(ResidenceDirective {
                id: numbered_id(0x73, n),
                machine: numbered_id(0x74, 1),
                owner: numbered_id(0x75, 1),
                issued_at: 1,
                act: ResidenceAct::SyncAll,
            }),
            None,
        ),
        "agents" => agent_op(0xA6, n / 2, n % 2),
        "revoke" => agent_op(0xA5, n / 4, n % 4),
        other => panic!("unknown family {other}"),
    }
}

/// Step `step` of agent `agent`'s life in the family `tag`: enrol its
/// device, bind its actor (cosigned by the agent), revoke the binding,
/// revoke the device.
fn agent_op(tag: u8, agent: usize, step: usize) -> (AuthorityOp, Option<SigningKey>) {
    let signing = numbered_key(tag, agent);
    match step {
        0 => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&signing), ROLE_AGENT),
            },
            None,
        ),
        1 => (
            AuthorityOp::BindActor {
                authority_key: key_of(&signing),
                actor_ref: numbered_id(tag ^ 0x0F, agent),
                actor_class: "system".to_owned(),
                epoch: 1,
            },
            Some(signing),
        ),
        2 => (
            AuthorityOp::RevokeActor {
                authority_key: key_of(&signing),
                epoch: 1,
            },
            None,
        ),
        _ => (
            AuthorityOp::RevokeDevice {
                revoked_key: key_of(&signing),
            },
            None,
        ),
    }
}

/// Genesis, then `rows` rows of `family` that the owner signs, in `shape`.
fn seeded_log(family: &str, shape: &str, rows: usize) -> Vec<AuthorityLogEntry> {
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
    let root = authority_entry_hash(&genesis).expect("genesis hash");
    let side = (1..).find(|side| side * side >= rows).unwrap_or(1);
    let mut hashes: Vec<AuthorityEntryHash> = Vec::with_capacity(rows);
    let mut entries = vec![genesis];
    for n in 0..rows {
        let parents = match shape {
            "chain" => vec![hashes.last().copied().unwrap_or(root)],
            "star" => vec![root],
            "grid" => {
                let mut parents = Vec::new();
                if n % side > 0 {
                    parents.push(hashes[n - 1]);
                }
                if n >= side {
                    parents.push(hashes[n - side]);
                }
                if parents.is_empty() {
                    parents.push(root);
                }
                parents
            }
            other => panic!("unknown shape {other}"),
        };
        let (op, cosigner) = family_op(family, n);
        let entry = signed(
            Some(vault_id),
            n as u64 + 1,
            parents,
            op,
            &owner,
            cosigner.as_ref(),
        );
        hashes.push(authority_entry_hash(&entry).expect("row hash"));
        entries.push(entry);
    }
    entries
}

/// Asserts that every row's state bytes and the merged state's bytes decode
/// and re-encode to themselves, and returns the sha256 of every row's hash,
/// length and bytes in hash order.
fn assert_reencode(log: &str, encodings: &StateEncodings) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (hash, bytes) in &encodings.rows {
        assert_eq!(
            &reencoded(bytes),
            bytes,
            "{log}: row {} state re-encodes to its own bytes",
            hex(hash)
        );
        digest.update(hash);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    assert_eq!(
        reencoded(&encodings.merged),
        encodings.merged,
        "{log}: the merged state re-encodes to its own bytes"
    );
    let mut sum = [0; 32];
    sum.copy_from_slice(&digest.finalize());
    sum
}

#[test]
fn seeded_logs_fold_to_states_that_reencode_to_the_same_bytes() {
    let mut logs: Vec<(&str, &str)> = Vec::new();
    for family in ["confirm", "critical", "enroll", "residence"] {
        for shape in ["chain", "star", "grid"] {
            logs.push((family, shape));
        }
    }
    logs.push(("agents", "chain"));
    logs.push(("revoke", "chain"));
    let mut all = Sha256::new();
    for (family, shape) in logs {
        let entries = seeded_log(family, shape, ROWS);
        let log = format!("{family}:{shape}");
        let encodings = state_encodings(&entries);
        let states = assert_reencode(&log, &encodings);
        let first_seen: BTreeMap<AuthorityEntryHash, u64> = entries
            .iter()
            .map(|entry| (authority_entry_hash(entry).expect("row hash"), 1))
            .collect();
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, 2);
        let fold_bytes = rmp_serde::to_vec_named(&fold).expect("the fold encodes");
        let line = format!(
            "FOLD-ENCODING family={family} shape={shape} rows={} folded={} valid={} \
             merged_entries={} merged_bytes={} states={} merged={} fold={}",
            entries.len(),
            encodings.rows.len(),
            fold.valid_entries.len(),
            encodings.merged_entries,
            encodings.merged.len(),
            hex(&states),
            hex(&Sha256::digest(&encodings.merged)),
            hex(&Sha256::digest(&fold_bytes)),
        );
        println!("{line}");
        all.update(line.as_bytes());
        all.update(b"\n");
    }
    println!("FOLD-ENCODING-ALL sha256={}", hex(&all.finalize()));
}

struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
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
    // The host root cosigns the owner's machine answers, as a serving host's
    // does, so the machine the owner marks theirs stands instead of being held
    // for an owner device (row CARRIER-OWNER-PROOF). `test_host_issuer` is the
    // same root `issuer` is.
    vault.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
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
        proof,
        vault_id,
    }
}

/// The owner admits a machine whose install key the test holds, and returns
/// its id.
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
        .expect("the owner admits the machine");
    machine
}

#[test]
fn a_rooted_vaults_image_and_row_states_reencode_to_the_same_bytes() {
    let rooted = rooted();
    let here = rooted
        .vault
        .local_machine()
        .expect("this install")
        .expect("this install's machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks this install yours");
    for name in ["Kept here", "Also kept here"] {
        let world = rooted
            .vault
            .create_world(&rooted.proof, name, rooted.vault.now_recorded_at())
            .expect("the owner's world");
        rooted
            .vault
            .set_world_privacy_as(
                &rooted.proof,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::OneMachine(here),
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the owner keeps the world on this install");
    }
    let removed = admit_machine(&rooted, 0xA1);
    admit_machine(&rooted, 0xA2);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            removed,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the first machine");

    let image = rooted
        .vault
        .build_authority_checkpoint_v2()
        .expect("the vault's checkpoint image");
    let bytes = image.encode().expect("the image encodes");
    let decoded = AuthorityCheckpointV2::decode(&bytes).expect("the image decodes");
    assert_eq!(
        decoded.encode().expect("the decoded image encodes"),
        bytes,
        "the image re-encodes to its own bytes"
    );

    let entries: Vec<AuthorityLogEntry> = rooted
        .vault
        .export_signed_authority_history()
        .expect("the vault's history")
        .iter()
        .map(|body| decode_authority_log_entry_body(body).expect("a stored row"))
        .collect();
    let encodings = state_encodings(&entries);
    assert_reencode("rooted", &encodings);
    println!(
        "IMAGE-ENCODING image_bytes={} rows={} folded={} merged_bytes={}",
        bytes.len(),
        entries.len(),
        encodings.rows.len(),
        encodings.merged.len()
    );
}

//! The authority-internal half of the FIX 22381 integration-test door.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};

use super::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActBy, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    ROLE_ADMIN, ROLE_OWNER, ReadLocation, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash,
    authority_transcript, fold_authority_log, genesis_vault_id, machine_profile_proof_transcript,
};
use crate::entity_id::EntityId;

/// Folds three concurrent agent edits, then projects the requested Grant refusals.
pub(crate) fn concurrent_agent_world_edits_read(refused: &[usize]) -> String {
    let owner_key = ed_key(114);
    let genesis = genesis_entry(114, 1);
    let vault_id = genesis_vault_id(&genesis).expect("the signed fixture genesis has a vault id");
    // Stable machine ids make the complete conflicted Debug text reproducible.
    let machines = [1, 2, 3].map(|byte| {
        EntityId::from_bytes([byte; 16]).expect("fixture machine ids are not reserved sentinels")
    });
    let keys = [ed_key(116), ed_key(117), ed_key(118)];
    let first_mark = mark(&genesis, &owner_key, 1, machines[0], &keys[0], vault_id);
    let second_mark = mark(&first_mark, &owner_key, 2, machines[1], &keys[1], vault_id);
    let last_mark = mark(&second_mark, &owner_key, 3, machines[2], &keys[2], vault_id);
    let parents = vec![entry_hash(&last_mark)];
    let owner = EntityId::now();
    let world = EntityId::now();
    let edit = |machine, key: &SigningKey, read| {
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                parents.clone(),
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: OwnerAct {
                        by: ActBy::Agent {
                            agent: EntityId::now(),
                            grant: EntityId::now(),
                        },
                        ..owner_act(owner, world)
                    },
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(key),
                2,
            ),
            key,
        )
    };
    let edits = [
        edit(machines[0], &keys[0], ReadLocation::OneMachine(machines[0])),
        edit(machines[1], &keys[1], ReadLocation::OneMachine(machines[1])),
        edit(machines[2], &keys[2], ReadLocation::MyMachines),
    ];
    let hashes = edits.each_ref().map(entry_hash);
    let mut entries = vec![genesis, first_mark, second_mark, last_mark];
    entries.extend(edits);
    let mut fold = fold_authority_log(&entries);
    let Some(folded) = fold.worlds.get(&world) else {
        return "fixture error: the world did not fold".to_owned();
    };
    if folded.live.len() != 3
        || fold.agent_carried_acts.len() != 3
        || hashes.iter().any(|hash| {
            !fold.valid_entries.contains(hash)
                || !folded.live.contains_key(hash)
                || !fold.agent_carried_acts.contains_key(hash)
                || fold.install.held_back.contains(hash)
                || fold.refused_world_edits.contains(hash)
        })
    {
        return "fixture error: all three agent edits must be valid, live and counted".to_owned();
    }
    let Some(refused_hashes) = refused
        .iter()
        .map(|&index| hashes.get(index).copied())
        .collect::<Option<Vec<_>>>()
    else {
        return "fixture error: refused index is outside the three edits".to_owned();
    };
    super::carried_act::hold_back_agent_acts(&mut fold, &refused_hashes);
    format!("{:?}", fold.world_privacy(world).read)
}

/// Folds two agent edits of one world in sequence under one Grant, the second
/// on the first, then projects the requested Grant refusals.
pub(crate) fn sequential_agent_world_edits_read(refused: &[usize]) -> String {
    let owner_key = ed_key(114);
    let genesis = genesis_entry(114, 1);
    let vault_id = genesis_vault_id(&genesis).expect("the signed fixture genesis has a vault id");
    // A stable machine id makes the OneMachine Debug text reproducible.
    let machine =
        EntityId::from_bytes([1; 16]).expect("fixture machine ids are not reserved sentinels");
    let key = ed_key(116);
    let profile = mark(&genesis, &owner_key, 1, machine, &key, vault_id);
    let owner = EntityId::now();
    let world = EntityId::now();
    let by = ActBy::Agent {
        agent: EntityId::now(),
        grant: EntityId::now(),
    };
    let edit = |seq, parents, seen, read, ts| {
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: OwnerAct {
                        by,
                        seen,
                        ..owner_act(owner, world)
                    },
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(&key),
                ts,
            ),
            &key,
        )
    };
    let first = edit(
        1,
        vec![entry_hash(&profile)],
        [0; 32],
        ReadLocation::MyMachines,
        2,
    );
    let first_hash = entry_hash(&first);
    let mut entries = vec![genesis, profile, first];
    // The second edit names the world's revision after the first, as an
    // agent's surface shows it.
    let seen = fold_authority_log(&entries).world_policy_revision(world).0;
    let second = edit(
        2,
        vec![first_hash],
        seen,
        ReadLocation::OneMachine(machine),
        3,
    );
    let hashes = [first_hash, entry_hash(&second)];
    entries.push(second);
    let mut fold = fold_authority_log(&entries);
    let Some(folded) = fold.worlds.get(&world) else {
        return "fixture error: the world did not fold".to_owned();
    };
    if folded.live.len() != 1
        || !folded.live.contains_key(&hashes[1])
        || fold.agent_carried_acts.len() != 2
        || hashes.iter().any(|hash| {
            !fold.valid_entries.contains(hash)
                || !fold.agent_carried_acts.contains_key(hash)
                || fold.install.held_back.contains(hash)
                || fold.refused_world_edits.contains(hash)
        })
    {
        return "fixture error: both agent edits must be valid and counted, the second live"
            .to_owned();
    }
    let Some(refused_hashes) = refused
        .iter()
        .map(|&index| hashes.get(index).copied())
        .collect::<Option<Vec<_>>>()
    else {
        return "fixture error: refused index is outside the two edits".to_owned();
    };
    super::carried_act::hold_back_agent_acts(&mut fold, &refused_hashes);
    format!("{:?}", fold.world_privacy(world).read)
}

// Copied from authority/tests/support.rs: the minimal Ed25519 entry and owner-act helpers.
fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn authority_key_from_ed(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

fn unsigned_entry(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer_key: AuthorityKey,
    ts: u64,
) -> AuthorityLogEntry {
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts,
    }
}

fn sign_ed(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
    let transcript =
        authority_transcript(&entry).expect("the fixture entry has a valid transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

fn owner_act(owner: EntityId, world: EntityId) -> OwnerAct {
    OwnerAct::by_owner(
        owner,
        OwnerActKind::WorldPrivacy,
        world,
        ActSurface::ThisInstall,
        [0; 32],
    )
}

fn genesis_entry(seed: u8, ts: u64) -> AuthorityLogEntry {
    let signing = ed_key(seed);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: DeviceAuthority {
            key: key.clone(),
            transport_key_binding: [7; 32],
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_OWNER | ROLE_ADMIN,
        },
        genesis_nonce: [seed.wrapping_add(10); 32],
        recovery: GenesisRecoveryStep::Saved([1; 32]),
    };
    sign_ed(unsigned_entry(None, 0, Vec::new(), op, key, ts), &signing)
}

fn entry_hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("the fixture entry has a canonical hash")
}

// Copied from authority/tests/machine_identity.rs: request_for and its encryption-key fixture.
fn request_for(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    key: &SigningKey,
) -> MachineEnrolmentRequest {
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = key
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

// Copied from authority/tests/world_race.rs: a_holder_going_stale_never_accepts_a_refused_edit's mark.
fn mark(
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    machine: EntityId,
    key: &SigningKey,
    vault_id: AuthorityVaultId,
) -> AuthorityLogEntry {
    let request = request_for(vault_id, machine, key);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![entry_hash(parent)],
            AuthorityOp::MachineProfile(MachineProfile {
                machine,
                owner: EntityId::now(),
                machine_key: request.machine_key,
                device_class: request.device_class,
                encryption_key: request.encryption_key,
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 1,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
                carrier: None,
                act: None,
            }),
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

// Copied from authority/tests/world_privacy.rs: settings.
fn settings(read: ReadLocation) -> WorldPrivacy {
    WorldPrivacy {
        read,
        ..WorldPrivacy::default()
    }
}

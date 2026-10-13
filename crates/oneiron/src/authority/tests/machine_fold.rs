//! World privacy P1 acceptance in the authority fold: who may answer for a
//! machine, and which other authority facts take a machine's standing away
//! in every arrival order.
use super::machine_identity::{Host, host, request_for};
use super::support::{authority_key_from_ed, device, ed_key, sign_ed, unsigned_entry};
use super::*;
use crate::registry::ENTITY_TYPE_MACHINE;

/// A hosted vault's cloud root registers its own node, but only a key the
/// owner holds answers "yours": a custodian never vouches for the owner.
#[test]
fn a_cloud_root_never_vouches_for_a_machine() {
    let signing = ed_key(81);
    let key = authority_key_from_ed(&signing);
    let genesis = sign_ed(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                    AuthorityTier::CloudCustodial,
                ),
                genesis_nonce: [82; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key.clone(),
            1,
        ),
        &signing,
    );
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let mut entries = vec![genesis];
    let mut machines = Vec::new();
    for (seq, role) in [
        MachineRole::HostedNode,
        MachineRole::Owned(MachineOwnership::Yours),
    ]
    .into_iter()
    .enumerate()
    {
        let machine = EntityId::now();
        let request = request_for(vault_id, machine, &ed_key(83 + seq as u8));
        let parent = authority_entry_hash(entries.last().unwrap()).unwrap();
        entries.push(sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq as u64 + 1,
                vec![parent],
                AuthorityOp::MachineProfile(MachineProfile {
                    machine,
                    owner: EntityId::now(),
                    machine_key: request.machine_key,
                    encryption_key: request.encryption_key,
                    role,
                    revision: 1,
                    machine_proof: request.machine_proof,
                }),
                key.clone(),
                seq as u64 + 2,
            ),
            &signing,
        ));
        machines.push(machine);
    }
    let fold = fold_authority_log_for_posture(
        &entries,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        crate::HostingPrivacyPosture::Hosted,
    );
    let node = fold
        .machine(machines[0])
        .expect("the custodian registers its node");
    assert!(node.is_live() && !node.is_mine());
    assert!(fold.machine(machines[1]).is_none());
}

/// On a hosted vault the host's root is the provider's key: it registers its
/// own node, but it never answers "yours" for the owner, whatever its labels.
/// A self-hosted root is the owner's own process, and a peer reading that
/// vault's log keeps its answer and everything after it.
#[test]
fn a_hosted_host_root_never_vouches_for_a_machine() {
    let host = host();
    let node = request_for(host.vault_id, EntityId::now(), &ed_key(86));
    let yours = request_for(host.vault_id, EntityId::now(), &ed_key(87));
    let later = request_for(host.vault_id, EntityId::now(), &ed_key(88));
    for (request, role) in [
        (&node, MachineRole::HostedNode),
        (&yours, MachineRole::Owned(MachineOwnership::Yours)),
        (&later, MachineRole::ExecutionNode),
    ] {
        host.vault
            .enroll_machine(&host.issuer, &host.owner, request, role)
            .unwrap();
    }
    let entries: Vec<_> = {
        let txn = host.vault.store.env.read_txn().unwrap();
        authority_log_rows_in_txn(&host.vault.store, &txn)
            .unwrap()
            .into_iter()
            .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
            .collect()
    };
    let fold = |posture| {
        fold_authority_log_for_posture(&entries, &BTreeMap::new(), 10, &BTreeMap::new(), posture)
    };
    for own in [
        fold(crate::HostingPrivacyPosture::SelfHostLocal),
        fold_peer_authority_log(&entries),
    ] {
        assert!(
            own.machine(yours.machine)
                .is_some_and(FoldedMachine::is_mine)
        );
        assert!(
            own.machine(later.machine)
                .is_some_and(FoldedMachine::is_live)
        );
    }
    let hosted = fold(crate::HostingPrivacyPosture::Hosted);
    assert!(
        hosted
            .machine(node.machine)
            .is_some_and(|folded| folded.is_live() && !folded.is_mine())
    );
    assert!(hosted.machine(yours.machine).is_none());
}

/// A key the host's root re-roots to stays in the host's custody whatever
/// labels it carries: a provider never launders its root into an owner-held
/// key that answers "yours".
#[test]
fn a_hosted_roots_successor_never_vouches_for_a_machine() {
    let host = host();
    let successor = ed_key(89);
    let fold = host.vault.authority_fold().unwrap();
    let re_root = host_entry(
        &host,
        fold.append_sequences[&host.issuer.public_key()] + 1,
        &fold.append_heads,
        AuthorityOp::ReRoot {
            new_device: device(
                authority_key_from_ed(&successor),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        None,
    );
    let re_root_hash = authority_entry_hash(&re_root).unwrap();
    let machine = EntityId::now();
    let yours = sign_ed(
        unsigned_entry(
            Some(host.vault_id),
            1,
            vec![re_root_hash],
            profile_op(&host, machine, &ed_key(90)),
            authority_key_from_ed(&successor),
            3,
        ),
        &successor,
    );
    let mut entries: Vec<_> = {
        let txn = host.vault.store.env.read_txn().unwrap();
        authority_log_rows_in_txn(&host.vault.store, &txn)
            .unwrap()
            .into_iter()
            .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
            .collect()
    };
    entries.extend([re_root, yours]);
    let fold = |posture| {
        fold_authority_log_for_posture(&entries, &BTreeMap::new(), 10, &BTreeMap::new(), posture)
    };
    let self_hosted = fold(crate::HostingPrivacyPosture::SelfHostLocal);
    assert!(self_hosted.valid_entries.contains(&re_root_hash));
    assert!(
        self_hosted
            .machine(machine)
            .is_some_and(FoldedMachine::is_mine)
    );
    let hosted = fold(crate::HostingPrivacyPosture::Hosted);
    assert!(hosted.valid_entries.contains(&re_root_hash));
    assert!(hosted.machine(machine).is_none());
}

/// An issuer-signed entry on `parents`, cosigned by `cosigner` when given.
fn host_entry(
    host: &Host,
    seq: u64,
    parents: &BTreeSet<AuthorityEntryHash>,
    op: AuthorityOp,
    cosigner: Option<&SigningKey>,
) -> AuthorityLogEntry {
    let mut entry = host
        .issuer
        .sign_entry(
            Some(host.vault_id),
            seq,
            parents.iter().copied().collect(),
            op,
            2,
        )
        .unwrap();
    if let Some(key) = cosigner {
        entry.cosigns.push(AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: authority_key_from_ed(key),
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&entry).unwrap();
        entry.cosigns[0].signature = key.sign(&transcript).to_bytes().to_vec();
        host.issuer.resign_entry(&mut entry).unwrap();
    }
    entry
}

fn profile_op(host: &Host, machine: EntityId, key: &SigningKey) -> AuthorityOp {
    let request = request_for(host.vault_id, machine, key);
    AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key,
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
    })
}

/// A row an agent key was bound to on any branch is an actor's, even when
/// the binding merge keeps another branch's row: it is never a machine.
#[test]
fn a_row_bound_as_an_actor_on_any_branch_is_never_mine() {
    for (machine, other) in [([0x70; 16], [0x10; 16]), ([0x10; 16], [0x70; 16])] {
        let host = host();
        let (machine, other) = (
            EntityId::from_bytes(machine).unwrap(),
            EntityId::from_bytes(other).unwrap(),
        );
        let agent = ed_key(91);
        let fold = host.vault.authority_fold().unwrap();
        let enroll = host_entry(
            &host,
            fold.append_sequences[&host.issuer.public_key()] + 1,
            &fold.append_heads,
            AuthorityOp::EnrollDevice {
                device: DeviceAuthority {
                    key: authority_key_from_ed(&agent),
                    transport_key_binding: [8; 32],
                    attestation: AuthorityAttestation {
                        kind: "SoftwareArgon2id".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_AGENT,
                },
            },
            None,
        );
        let at = TimeRange { start: 2, end: 2 };
        host.vault
            .put_authority_log_entries(&[(enroll.clone(), at, 2)])
            .unwrap();
        let seq = enroll.seq;
        let parents = BTreeSet::from([authority_entry_hash(&enroll).unwrap()]);
        let bind = |actor_ref| AuthorityOp::BindActor {
            authority_key: authority_key_from_ed(&agent),
            actor_ref,
            actor_class: "system".into(),
            epoch: 1,
        };
        let branches = [
            host_entry(
                &host,
                seq + 1,
                &parents,
                profile_op(&host, machine, &ed_key(92)),
                None,
            ),
            host_entry(&host, seq + 2, &parents, bind(machine), Some(&agent)),
            host_entry(&host, seq + 3, &parents, bind(other), Some(&agent)),
        ];
        let rows: Vec<_> = branches
            .iter()
            .map(|entry| (entry.clone(), at, 2))
            .collect();
        host.vault.put_authority_log_entries(&rows).unwrap();
        let fold = host.vault.authority_fold().unwrap();
        for entry in &branches {
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(entry).unwrap())
            );
        }
        assert!(
            fold.machine(machine)
                .is_some_and(|folded| !folded.is_live() && !folded.is_mine())
        );
    }
}

/// A signed withdrawal of an actor's key lands even on top of a profile the
/// fold refused: a refused grant never shields a binding from its revoke.
#[test]
fn a_refused_profile_never_blocks_an_actor_revoke() {
    let host = host();
    let writer = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    host.vault
        .put_entity(&writer, ENTITY_TYPE_MACHINE, at, 1, b"writer")
        .unwrap();
    let writer_key = ed_key(93);
    host.vault
        .enroll_machine_identity(
            &host.issuer,
            writer,
            writer_key.verifying_key().to_bytes(),
            [9; 32],
            |transcript| Ok(writer_key.sign(transcript).to_bytes()),
        )
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let refused = host_entry(
        &host,
        seq + 1,
        &fold.append_heads,
        profile_op(&host, writer, &ed_key(94)),
        None,
    );
    let revoke = host_entry(
        &host,
        seq + 2,
        &BTreeSet::from([authority_entry_hash(&refused).unwrap()]),
        AuthorityOp::RevokeActor {
            authority_key: authority_key_from_ed(&writer_key),
            epoch: 1,
        },
        None,
    );
    host.vault
        .put_authority_log_entries(&[(refused.clone(), at, 2), (revoke, at, 2)])
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&refused).unwrap())
    );
    assert!(fold.machine(writer).is_none());
    assert_eq!(
        fold.actor_bindings[&authority_key_from_ed(&writer_key)].status,
        ActorBindingStatus::Revoked
    );
}

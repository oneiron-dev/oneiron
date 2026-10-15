//! World privacy P1 acceptance in the authority fold: who may answer for a
//! machine, and which other authority facts take a machine's standing away
//! in every arrival order.
use super::history_transfer::re_root_entry;
use super::machine_identity::{Host, host, request_for};
use super::support::{
    RosterChain, authority_key_from_ed, cosign_ed, device, ed_key, genesis_entry, sign_ed,
    unsigned_entry,
};
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
                    seen_world_edits: BTreeSet::new(),
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
    assert!(node.roster_chain().is_live() && !node.is_mine(None));
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
                .is_some_and(|folded| folded.is_mine(None))
        );
        assert!(
            own.machine(later.machine)
                .is_some_and(|folded| folded.roster_chain().is_live())
        );
    }
    let hosted = fold(crate::HostingPrivacyPosture::Hosted);
    assert!(
        hosted
            .machine(node.machine)
            .is_some_and(|folded| folded.roster_chain().is_live() && !folded.is_mine(None))
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
            .is_some_and(|folded| folded.is_mine(None))
    );
    let hosted = fold(crate::HostingPrivacyPosture::Hosted);
    assert!(hosted.valid_entries.contains(&re_root_hash));
    assert!(hosted.machine(machine).is_none());
}

/// An issuer-signed entry on `parents`, cosigned by `cosigner` when given.
pub(super) fn host_entry(
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

pub(super) fn profile_op(host: &Host, machine: EntityId, key: &SigningKey) -> AuthorityOp {
    let request = request_for(host.vault_id, machine, key);
    AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key,
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
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
                .is_some_and(|folded| !folded.roster_chain().is_live() && !folded.is_mine(None))
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

fn entries_of(host: &Host) -> Vec<AuthorityLogEntry> {
    let txn = host.vault.store.env.read_txn().unwrap();
    authority_log_rows_in_txn(&host.vault.store, &txn)
        .unwrap()
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
        .collect()
}

/// A removal signed after a mark that one fold refuses still removes there:
/// a refused grant never shields a withdrawal, nor does a slip minted on top
/// of it, nor a retired ceiling, which changes nothing (Wonder #1423 r2 W2,
/// Sol #1423 r9).
#[test]
fn a_removal_crosses_a_refused_mark() {
    for interposed in ["nothing", "a slip mint", "a retired ceiling"] {
        let host = host();
        let node = request_for(host.vault_id, EntityId::now(), &ed_key(92));
        let yours = request_for(host.vault_id, EntityId::now(), &ed_key(93));
        host.vault
            .enroll_machine(&host.issuer, &host.owner, &node, MachineRole::ExecutionNode)
            .unwrap();
        // A hosted fold refuses this mark: there the host's root never answers
        // "yours". The removal below descends from it.
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &yours,
                MachineRole::Owned(MachineOwnership::Yours),
            )
            .unwrap();
        let entries = match interposed {
            "a retired ceiling" => {
                // The door refuses a new ceiling; signed history still carries one.
                let fold = host.vault.authority_fold().unwrap();
                let seq = fold.append_sequences[&host.issuer.public_key()];
                let ceiling = host_entry(
                    &host,
                    seq + 1,
                    &fold.append_heads,
                    AuthorityOp::RetiredCeiling {
                        authority_key: host.issuer.public_key(),
                        actor_class: "agent".into(),
                        ceiling: 0,
                    },
                    None,
                );
                let removal = host_entry(
                    &host,
                    seq + 2,
                    &BTreeSet::from([authority_entry_hash(&ceiling).unwrap()]),
                    AuthorityOp::MachineProfile(MachineProfile {
                        role: MachineRole::Removed,
                        revision: 2,
                        ..fold
                            .machine(node.machine)
                            .unwrap()
                            .roster_chain()
                            .profile
                            .clone()
                    }),
                    None,
                );
                let mut entries = entries_of(&host);
                entries.extend([ceiling, removal]);
                entries
            }
            _ => {
                if interposed == "a slip mint" {
                    let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
                    let mut claims = root.claims.clone();
                    claims.slip_id = [96; 32];
                    claims.parent_id = Some(root.claims.slip_id);
                    claims.ttl_secs = 60;
                    claims.expires_at = claims.issued_at + 60;
                    host.vault
                        .mint_capability_slip(&host.issuer, claims)
                        .unwrap();
                }
                host.vault
                    .set_machine_role(
                        &host.issuer,
                        &host.owner,
                        node.machine,
                        MachineRole::Removed,
                    )
                    .unwrap();
                entries_of(&host)
            }
        };
        for posture in [
            crate::HostingPrivacyPosture::SelfHostLocal,
            crate::HostingPrivacyPosture::Hosted,
        ] {
            let fold = fold_authority_log_for_posture(
                &entries,
                &BTreeMap::new(),
                10,
                &BTreeMap::new(),
                posture,
            );
            assert!(
                fold.machine(node.machine).is_some_and(
                    |folded| folded.roster_chain().removed && !folded.roster_chain().is_live()
                ),
                "{interposed}, {posture:?}"
            );
        }
    }
}

/// A root a handoff retired signs no machine standing outside the handoff's
/// line (#1410's fence): neither a mark nor a removal on history from before
/// its retirement stands, while the machines the move carried keep their
/// standing under the new root past the stale-roster window.
#[test]
fn a_retired_root_signs_no_machine_standing() {
    let host = host();
    let kept = request_for(host.vault_id, EntityId::now(), &ed_key(94));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &kept,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let before = host.vault.authority_fold().unwrap();
    let next = HostSlipIssuer::from_secret(b"successor self-host root").unwrap();
    let moved = host.vault.re_root_host(&host.issuer, &next).unwrap();
    assert_eq!(moved.machines_carried, 1);

    let forged = EntityId::now();
    let removal = AuthorityOp::MachineProfile(MachineProfile {
        role: MachineRole::Removed,
        revision: 2,
        ..before
            .machine(kept.machine)
            .unwrap()
            .roster_chain()
            .profile
            .clone()
    });
    let seq = before.append_sequences[&host.issuer.public_key()];
    let replayed = [
        host_entry(
            &host,
            seq + 1,
            &before.append_heads,
            profile_op(&host, forged, &ed_key(95)),
            None,
        ),
        host_entry(&host, seq + 2, &before.append_heads, removal, None),
    ];
    // The door refuses them, and a fold that holds them anyway does too.
    for entry in &replayed {
        assert!(
            host.vault
                .put_authority_log_entries(&[(entry.clone(), TimeRange { start: 3, end: 3 }, 3)])
                .is_err()
        );
    }
    let mut entries = entries_of(&host);
    entries.extend(replayed.iter().cloned());
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
        .collect();
    for now in [100, 100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1] {
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, now);
        assert!(replayed.iter().all(|entry| {
            !fold
                .valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        }));
        assert!(fold.machine(forged).is_none());
        assert!(
            fold.machine(kept.machine)
                .is_some_and(|folded| folded.is_mine(None))
        );
    }
}

/// A mark the root signed before its handoff rests on a key the handoff
/// revoked. Unless the new root signs that standing again, as `re_root_host`
/// does, the machine stands only for the stale-roster window, while the new
/// root's own marks keep their standing.
#[test]
fn an_uncarried_mark_never_outlives_the_stale_window() {
    let old = ed_key(96);
    let next = ed_key(97);
    let genesis = genesis_entry(96, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let mark = |parent: &AuthorityLogEntry, signer: &SigningKey, seq, machine, key: u8| {
        let request = request_for(id, machine, &ed_key(key));
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::MachineProfile(MachineProfile {
                    machine,
                    owner: EntityId::now(),
                    machine_key: request.machine_key,
                    encryption_key: request.encryption_key,
                    role: MachineRole::Owned(MachineOwnership::Yours),
                    revision: 1,
                    machine_proof: request.machine_proof,
                    seen_world_edits: BTreeSet::new(),
                }),
                authority_key_from_ed(signer),
                2,
            ),
            signer,
        )
    };
    let (stale, kept) = (EntityId::now(), EntityId::now());
    let stale_mark = mark(&genesis, &old, 1, stale, 98);
    let handoff = re_root_entry(id, &stale_mark, &old, 2, &next);
    let kept_mark = mark(&handoff, &next, 1, kept, 99);
    let entries = [kept_mark, handoff, stale_mark, genesis];
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
        .collect();
    let within = fold_authority_log_with_seen_times(&entries, &first_seen, 100);
    assert!(
        within
            .machine(stale)
            .is_some_and(|folded| folded.is_mine(None))
    );
    let after = fold_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1,
    );
    assert!(
        after
            .machine(stale)
            .is_some_and(|folded| folded.roster_chain().stale && !folded.is_mine(None))
    );
    assert!(
        after
            .machine(kept)
            .is_some_and(|folded| folded.is_mine(None))
    );
}

/// Custody is sticky: on a hosted vault a cloud root that hands the vault to
/// a key labelled owner-held never answers "yours" through that successor
/// (Astra #1423 F1). The bootstrap fold of the vault's own log judges it the
/// same way.
#[test]
fn a_custodians_successor_never_vouches_for_a_machine() {
    let cloud = ed_key(104);
    let key = authority_key_from_ed(&cloud);
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
                genesis_nonce: [105; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key,
            1,
        ),
        &cloud,
    );
    let id = genesis_vault_id(&genesis).unwrap();
    let successor = ed_key(106);
    let handoff = re_root_entry(id, &genesis, &cloud, 1, &successor);
    let machine = EntityId::now();
    let mark = owned_mark(id, &handoff, &successor, 1, machine, 107);
    let entries = [genesis, handoff.clone(), mark];
    for fold in [
        fold_authority_log_for_posture(
            &entries,
            &BTreeMap::new(),
            10,
            &BTreeMap::new(),
            crate::HostingPrivacyPosture::Hosted,
        ),
        super::super::fold_engine::fold_own_authority_log(
            &entries,
            crate::HostingPrivacyPosture::Hosted,
            None,
        ),
    ] {
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&handoff).unwrap())
        );
        assert!(!fold.roster[&authority_key_from_ed(&successor)].revoked);
        assert!(fold.machine(machine).is_none());
    }
}

/// Custody passes along every admission whichever branch carried the mark:
/// the root enrols one key twice, once marked for the cloud, and the keys
/// that key's other enrolment led to never answer "yours" on a hosted fold,
/// whether they mark the machine after the branches meet or before (Sol P1
/// rounds 5 and 6).
#[test]
fn custody_marked_on_another_branch_reaches_the_successor() {
    let root = ed_key(114);
    let genesis = genesis_entry(114, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (custodied, admitted, successor) = (ed_key(115), ed_key(116), ed_key(117));
    let ordinary = |key: &SigningKey| {
        device(
            authority_key_from_ed(key),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        )
    };
    let entry = |seq,
                 parents: &[&AuthorityLogEntry],
                 op,
                 signer: &SigningKey,
                 cosigner: Option<&SigningKey>| {
        let mut parents: Vec<_> = parents
            .iter()
            .map(|parent| authority_entry_hash(parent).unwrap())
            .collect();
        parents.sort();
        let unsigned = unsigned_entry(Some(id), seq, parents, op, authority_key_from_ed(signer), 2);
        match cosigner {
            Some(cosigner) => cosign_ed(unsigned, signer, cosigner),
            None => sign_ed(unsigned, signer),
        }
    };
    let plain = entry(
        1,
        &[&genesis],
        AuthorityOp::EnrollDevice {
            device: ordinary(&custodied),
        },
        &root,
        None,
    );
    let marked = entry(
        2,
        &[&genesis],
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&custodied),
                ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
        },
        &root,
        None,
    );
    let enrolled = entry(
        1,
        &[&plain],
        AuthorityOp::EnrollDevice {
            device: ordinary(&admitted),
        },
        &custodied,
        Some(&root),
    );
    let handoff = entry(
        1,
        &[&marked, &enrolled],
        AuthorityOp::ReRoot {
            new_device: ordinary(&successor),
        },
        &admitted,
        Some(&root),
    );
    let hosted = |entries: &[&AuthorityLogEntry]| {
        let entries: Vec<_> = entries.iter().map(|entry| (*entry).clone()).collect();
        fold_authority_log_for_posture(
            &entries,
            &BTreeMap::new(),
            10,
            &BTreeMap::new(),
            crate::HostingPrivacyPosture::Hosted,
        )
    };
    let machine = EntityId::now();
    let mark = owned_mark(id, &handoff, &successor, 1, machine, 118);
    let fold = hosted(&[&genesis, &plain, &marked, &enrolled, &handoff, &mark]);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&handoff).unwrap())
    );
    assert!(!fold.roster[&authority_key_from_ed(&successor)].revoked);
    assert!(fold.machine(machine).is_none());

    // The admitted key marks a machine before the branches meet, on a branch
    // the cloud enrolment never reached; the handoff then joins them.
    let early = EntityId::now();
    let early_mark = owned_mark(id, &enrolled, &admitted, 1, early, 119);
    let joining = entry(
        2,
        &[&marked, &early_mark],
        AuthorityOp::ReRoot {
            new_device: ordinary(&successor),
        },
        &admitted,
        Some(&root),
    );
    let fold = hosted(&[&genesis, &plain, &marked, &enrolled, &early_mark, &joining]);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&joining).unwrap())
    );
    let folded = fold.machine(early).unwrap();
    assert_eq!(folded.roster_chain().signer_class, SignerClass::Custodial);
    assert!(!folded.roster_chain().is_live() && !folded.is_mine(None));
}

/// `signer` marks `machine` "yours" on `parent`, with the install key `key`.
fn owned_mark(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    machine: EntityId,
    key: u8,
) -> AuthorityLogEntry {
    let request = request_for(id, machine, &ed_key(key));
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::MachineProfile(MachineProfile {
                machine,
                owner: EntityId::now(),
                machine_key: request.machine_key,
                encryption_key: request.encryption_key,
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 1,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
            }),
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

/// A fork of the root's handoff retires the root and installs neither
/// successor. The roster then has no settled root, so the machines it
/// admitted have no standing at once, and say why; the stale-roster window
/// is for a handoff that settled (Astra #1423 F2).
#[test]
fn a_forked_handoff_leaves_no_machine_standing() {
    let root = ed_key(108);
    let genesis = genesis_entry(108, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let machine = EntityId::now();
    let mark = owned_mark(id, &genesis, &root, 1, machine, 109);
    let left = re_root_entry(id, &mark, &root, 2, &ed_key(110));
    let right = re_root_entry(id, &mark, &root, 3, &ed_key(111));
    let fold = |entries: &[&AuthorityLogEntry]| {
        let entries: Vec<_> = entries.iter().map(|entry| (*entry).clone()).collect();
        let first_seen: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
            .collect();
        fold_authority_log_with_seen_times(&entries, &first_seen, 100)
    };
    let settled = fold(&[&genesis, &mark, &left]);
    assert!(
        settled
            .machine(machine)
            .is_some_and(|folded| folded.is_mine(None))
    );
    for entries in [
        [&genesis, &mark, &left, &right],
        [&right, &left, &mark, &genesis],
    ] {
        let forked = fold(&entries);
        for handoff in [&left, &right] {
            assert!(
                !forked
                    .valid_entries
                    .contains(&authority_entry_hash(handoff).unwrap())
            );
        }
        let folded = forked.machine(machine).unwrap();
        assert!(
            folded.roster_chain().admitter_unsettled
                && !folded.roster_chain().is_live()
                && !folded.is_mine(None)
        );
        assert!(!folded.roster_chain().removed);
    }
}

/// A removal stands on every replica, whichever of its signer's rows arrived
/// first: a sibling stored before it leaves the removal under this vault's
/// sequence floor, and the removal still removes (Astra #1423 F3). The two
/// may also share the merge of two rows at one sequence, which the fold
/// accepts, so the removal's proof does too (Astra #1423b).
#[test]
fn a_removal_holds_whichever_sibling_arrived_first() {
    for merged in [false, true] {
        let host = host();
        let removed = request_for(host.vault_id, EntityId::now(), &ed_key(112));
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &removed,
                MachineRole::Owned(MachineOwnership::Yours),
            )
            .unwrap();
        let hosted_node = |seq, parents: &BTreeSet<AuthorityEntryHash>, key| {
            let AuthorityOp::MachineProfile(profile) =
                profile_op(&host, EntityId::now(), &ed_key(key))
            else {
                unreachable!()
            };
            host_entry(
                &host,
                seq,
                parents,
                AuthorityOp::MachineProfile(MachineProfile {
                    role: MachineRole::HostedNode,
                    ..profile
                }),
                None,
            )
        };
        let store = |vault: &crate::Vault, entry: &AuthorityLogEntry| {
            vault
                .put_authority_log_entries(&[(entry.clone(), TimeRange { start: 3, end: 3 }, 3)])
                .unwrap();
        };
        let before = host.vault.authority_fold().unwrap();
        let mut seq = before.append_sequences[&host.issuer.public_key()];
        let mut parents = before.append_heads.clone();
        if merged {
            seq += 1;
            let pair = [
                hosted_node(seq, &parents, 114),
                hosted_node(seq, &parents, 115),
            ];
            for entry in &pair {
                store(&host.vault, entry);
            }
            parents = pair
                .iter()
                .map(|entry| authority_entry_hash(entry).unwrap())
                .collect();
        }
        let removal = host_entry(
            &host,
            seq + 1,
            &parents,
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::Removed,
                revision: 2,
                ..before
                    .machine(removed.machine)
                    .unwrap()
                    .roster_chain()
                    .profile
                    .clone()
            }),
            None,
        );
        let sibling = hosted_node(seq + 2, &parents, 113);
        let AuthorityOp::MachineProfile(MachineProfile { machine: node, .. }) = sibling.op else {
            unreachable!()
        };
        let dir = tempfile::tempdir().unwrap();
        let replica = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        replica
            .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
            .unwrap();
        for (vault, order) in [
            (&host.vault, [&removal, &sibling]),
            (&replica, [&sibling, &removal]),
        ] {
            for entry in order {
                store(vault, entry);
            }
            let fold = vault.authority_fold().unwrap();
            assert!(
                fold.machine(removed.machine).is_some_and(
                    |folded| folded.roster_chain().removed && !folded.roster_chain().is_live()
                ),
                "merged: {merged}"
            );
            assert!(
                fold.machine(node)
                    .is_some_and(|folded| folded.roster_chain().is_live())
            );
        }
    }
}

/// A removal over another withdrawal of the same signer, another removal or
/// an actor revoke, stands on every replica too: both arriving under a later
/// sibling's floor leaves the removal standing, proved over its own branch
/// (Sol #1423 r8 and r9).
#[test]
fn a_removal_holds_over_a_withdrawal_that_arrived_late() {
    for actor_revoke in [false, true] {
        let host = host();
        let [yours, node] =
            [112, 113].map(|key| request_for(host.vault_id, EntityId::now(), &ed_key(key)));
        for (request, role) in [
            (&yours, MachineRole::Owned(MachineOwnership::Yours)),
            (&node, MachineRole::HostedNode),
        ] {
            host.vault
                .enroll_machine(&host.issuer, &host.owner, request, role)
                .unwrap();
        }
        let writer = EntityId::now();
        let writer_key = ed_key(115);
        host.vault
            .put_entity(
                &writer,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                b"writer",
            )
            .unwrap();
        host.vault
            .enroll_machine_identity(
                &host.issuer,
                writer,
                writer_key.verifying_key().to_bytes(),
                [9; 32],
                |transcript| Ok(writer_key.sign(transcript).to_bytes()),
            )
            .unwrap();
        let before = host.vault.authority_fold().unwrap();
        let seq = before.append_sequences[&host.issuer.public_key()];
        let removal = |machine| {
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::Removed,
                revision: 2,
                ..before
                    .machine(machine)
                    .unwrap()
                    .roster_chain()
                    .profile
                    .clone()
            })
        };
        let first = host_entry(
            &host,
            seq + 1,
            &before.append_heads,
            if actor_revoke {
                AuthorityOp::RevokeActor {
                    authority_key: authority_key_from_ed(&writer_key),
                    epoch: 1,
                }
            } else {
                removal(node.machine)
            },
            None,
        );
        let second = host_entry(
            &host,
            seq + 2,
            &BTreeSet::from([authority_entry_hash(&first).unwrap()]),
            removal(yours.machine),
            None,
        );
        let AuthorityOp::MachineProfile(profile) = profile_op(&host, EntityId::now(), &ed_key(114))
        else {
            unreachable!()
        };
        let sibling = host_entry(
            &host,
            seq + 3,
            &before.append_heads,
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::HostedNode,
                ..profile
            }),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let replica = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        replica
            .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
            .unwrap();
        for (vault, order) in [
            (&host.vault, [&first, &second, &sibling]),
            (&replica, [&sibling, &first, &second]),
        ] {
            for entry in order {
                vault
                    .put_authority_log_entries(&[(
                        (*entry).clone(),
                        TimeRange { start: 3, end: 3 },
                        3,
                    )])
                    .unwrap();
            }
            let fold = vault.authority_fold().unwrap();
            let removed = |machine| {
                fold.machine(machine).is_some_and(|folded| {
                    folded.roster_chain().removed && !folded.roster_chain().is_live()
                })
            };
            assert!(removed(yours.machine), "actor revoke: {actor_revoke}");
            assert_eq!(removed(node.machine), !actor_revoke);
        }
    }
}

/// A removal never stands below the sequence of a row it descends from, even
/// a row its proof crosses without applying: sequences rise along the
/// ancestry in the proof as in the fold (Sol #1423 r9).
#[test]
fn a_removal_never_proves_below_its_ancestrys_sequence() {
    // A slip mint the removal names as its parent, at a higher sequence,
    // stored in both orders around a later sibling.
    let host = host();
    let yours = request_for(host.vault_id, EntityId::now(), &ed_key(116));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &yours,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [97; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.ttl_secs = 60;
    claims.expires_at = claims.issued_at + 60;
    let before = host.vault.authority_fold().unwrap();
    let seq = before.append_sequences[&host.issuer.public_key()];
    let mint = host_entry(
        &host,
        seq + 2,
        &before.append_heads,
        AuthorityOp::SlipMint(SlipMintAction { claims }),
        None,
    );
    let removal = host_entry(
        &host,
        seq + 1,
        &BTreeSet::from([authority_entry_hash(&mint).unwrap()]),
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..before
                .machine(yours.machine)
                .unwrap()
                .roster_chain()
                .profile
                .clone()
        }),
        None,
    );
    let AuthorityOp::MachineProfile(profile) = profile_op(&host, EntityId::now(), &ed_key(117))
    else {
        unreachable!()
    };
    let sibling = host_entry(
        &host,
        seq + 3,
        &before.append_heads,
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::HostedNode,
            ..profile
        }),
        None,
    );
    let dir = tempfile::tempdir().unwrap();
    let replica = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    for (vault, order) in [
        (&host.vault, [&mint, &removal, &sibling]),
        (&replica, [&sibling, &mint, &removal]),
    ] {
        for entry in order {
            vault
                .put_authority_log_entries(&[((*entry).clone(), TimeRange { start: 3, end: 3 }, 3)])
                .unwrap();
        }
        assert!(
            vault
                .authority_fold()
                .unwrap()
                .machine(yours.machine)
                .is_some_and(|folded| folded.is_mine(None))
        );
    }

    // A removal at the sequence of the mark one fold refuses, which the
    // proof crosses there.
    let host = super::machine_identity::host();
    let node = request_for(host.vault_id, EntityId::now(), &ed_key(118));
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &node, MachineRole::ExecutionNode)
        .unwrap();
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request_for(host.vault_id, EntityId::now(), &ed_key(119)),
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    let mut entries = entries_of(&host);
    entries.push(host_entry(
        &host,
        fold.append_sequences[&host.issuer.public_key()],
        &fold.append_heads,
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..fold
                .machine(node.machine)
                .unwrap()
                .roster_chain()
                .profile
                .clone()
        }),
        None,
    ));
    for posture in [
        crate::HostingPrivacyPosture::SelfHostLocal,
        crate::HostingPrivacyPosture::Hosted,
    ] {
        let fold = fold_authority_log_for_posture(
            &entries,
            &BTreeMap::new(),
            10,
            &BTreeMap::new(),
            posture,
        );
        assert!(
            fold.machine(node.machine).is_some_and(
                |folded| !folded.roster_chain().removed && folded.roster_chain().is_live()
            ),
            "{posture:?}"
        );
    }
}

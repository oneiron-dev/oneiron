//! Composition of signed revoke proof across independent ancestry invalidations.

use super::support::*;
use super::*;

#[derive(Clone, Copy, Debug)]
enum Chain {
    Invalid,
    Frozen,
    FrozenThenInvalid,
}

#[derive(Clone, Copy, Debug)]
enum Loss {
    Equivocation,
    Confirmation,
}

fn confirm_entry(
    parent: AuthorityEntryHash,
    vault: AuthorityVaultId,
    owner: &SigningKey,
    consent: &SigningKey,
    seq: u64,
    id: u8,
) -> AuthorityLogEntry {
    let owner_key = authority_key_from_ed(owner);
    cosign_ed(
        unsigned_entry(
            Some(vault),
            seq,
            vec![parent],
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: [id; 32],
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: [93; 16],
            }),
            owner_key,
            4,
        ),
        owner,
        consent,
    )
}

#[test]
fn restrictive_facts_compose_across_ancestry_matrix() {
    for chain in [Chain::Invalid, Chain::Frozen, Chain::FrozenThenInvalid] {
        for signer_lost in [true, false] {
            for loss in [Loss::Equivocation, Loss::Confirmation] {
                let label = format!("{chain:?} signer_lost={signer_lost} {loss:?}");
                let owner = ed_key(100);
                let consent = ed_key(101);
                let signer = ed_key(102);
                let owner_key = authority_key_from_ed(&owner);
                let consent_key = authority_key_from_ed(&consent);
                let signer_key = authority_key_from_ed(&signer);
                let genesis = genesis_entry(100, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
                let vault = genesis_vault_id(&genesis).unwrap();
                let enroll_consent = enroll_device_entry(
                    vault,
                    &genesis,
                    &owner,
                    EnrollSpec {
                        seed: 101,
                        roles: ROLE_OWNER | ROLE_ADMIN,
                        tier: AuthorityTier::Software,
                        seq: 1,
                        ts: 2,
                    },
                );
                let actor = scope_entity(0x76);
                let bind = cosign_ed(
                    unsigned_entry(
                        Some(vault),
                        1,
                        vec![authority_entry_hash(&enroll_consent).unwrap()],
                        bind_op(&consent_key, actor, "human", 1),
                        consent_key.clone(),
                        3,
                    ),
                    &consent,
                    &owner,
                );
                let bind_hash = authority_entry_hash(&bind).unwrap();
                let mut entries = vec![genesis, enroll_consent, bind];
                let (loser, sibling) = match loss {
                    Loss::Equivocation => {
                        let enroll = |seed| {
                            cosign_ed(
                                unsigned_entry(
                                    Some(vault),
                                    2,
                                    vec![bind_hash],
                                    AuthorityOp::EnrollDevice {
                                        device: device(
                                            authority_key_from_ed(&ed_key(seed)),
                                            ROLE_AGENT,
                                            AuthorityTier::Software,
                                        ),
                                    },
                                    owner_key.clone(),
                                    5,
                                ),
                                &owner,
                                &consent,
                            )
                        };
                        let b = enroll(102);
                        let d = enroll(103);
                        // Choose the key on the higher-hash losing branch.
                        if authority_entry_hash(&b).unwrap() > authority_entry_hash(&d).unwrap() {
                            (b, d)
                        } else {
                            // Swap signing keys for this fixture; 103 is the loser.
                            (d, b)
                        }
                    }
                    Loss::Confirmation => {
                        let first = confirm_entry(bind_hash, vault, &owner, &consent, 2, 155);
                        let first_hash = authority_entry_hash(&first).unwrap();
                        let replay = (1..=u8::MAX)
                            .map(|id| confirm_entry(bind_hash, vault, &owner, &consent, 4, id))
                            .find(|entry| authority_entry_hash(entry).unwrap() < first_hash)
                            .unwrap();
                        let first_enroll = cosign_ed(
                            unsigned_entry(
                                Some(vault),
                                3,
                                vec![first_hash],
                                AuthorityOp::EnrollDevice {
                                    device: device(
                                        signer_key.clone(),
                                        ROLE_AGENT,
                                        AuthorityTier::Software,
                                    ),
                                },
                                owner_key.clone(),
                                5,
                            ),
                            &owner,
                            &consent,
                        );
                        entries.push(first);
                        (first_enroll, replay)
                    }
                };
                let loser_hash = authority_entry_hash(&loser).unwrap();
                let actual_signer = if let Loss::Equivocation = loss {
                    let AuthorityOp::EnrollDevice { device } = &loser.op else {
                        unreachable!()
                    };
                    if device.key == signer_key {
                        signer.clone()
                    } else {
                        ed_key(103)
                    }
                } else {
                    signer.clone()
                };
                let actual_key = authority_key_from_ed(&actual_signer);
                entries.push(loser);
                let mut parent = loser_hash;
                let mut seq = if signer_lost { 1 } else { 2 };
                let now = 10_000_000;
                let mut deferred = BTreeSet::new();
                let sign_chain = |parent, seq, op, ts| {
                    if signer_lost {
                        cosign_ed(
                            unsigned_entry(
                                Some(vault),
                                seq,
                                vec![parent],
                                op,
                                actual_key.clone(),
                                ts,
                            ),
                            &actual_signer,
                            &consent,
                        )
                    } else {
                        cosign_ed(
                            unsigned_entry(
                                Some(vault),
                                seq,
                                vec![parent],
                                op,
                                consent_key.clone(),
                                ts,
                            ),
                            &consent,
                            &actual_signer,
                        )
                    }
                };
                if !matches!(chain, Chain::Invalid) {
                    let widen = sign_chain(
                        parent,
                        seq,
                        AuthorityOp::EnrollDevice {
                            device: device(
                                authority_key_from_ed(&ed_key(104)),
                                ROLE_AGENT,
                                AuthorityTier::Software,
                            ),
                        },
                        6,
                    );
                    parent = authority_entry_hash(&widen).unwrap();
                    deferred.insert(parent);
                    entries.push(widen);
                    seq += 1;
                }
                let grant = sign_chain(
                    parent,
                    seq,
                    if matches!(chain, Chain::Frozen) {
                        rebind_op(&consent_key, actor, "human", 10)
                    } else {
                        bind_op(&consent_key, scope_entity(0x77), "human", 10)
                    },
                    7,
                );
                parent = authority_entry_hash(&grant).unwrap();
                deferred.insert(parent);
                entries.push(grant);
                seq += 1;
                let revoke = sign_chain(parent, seq, revoke_actor_op(&consent_key, 11), 8);
                let revoke_hash = authority_entry_hash(&revoke).unwrap();
                deferred.insert(revoke_hash);
                entries.push(revoke);
                let mut first_seen = BTreeMap::new();
                for entry in &entries {
                    let hash = authority_entry_hash(entry).unwrap();
                    first_seen.insert(hash, if deferred.contains(&hash) { now } else { 1 });
                }
                first_seen.insert(authority_entry_hash(&sibling).unwrap(), 1);
                let before = fold_authority_log_with_seen_times(&entries, &first_seen, now);
                assert_eq!(
                    folded_status(&before, &consent_key),
                    Some(ActorBindingStatus::Revoked),
                    "before {label}: {:?}",
                    before.issues
                );
                entries.push(sibling);
                let after = fold_authority_log_with_seen_times(&entries, &first_seen, now);
                assert!(!after.valid_entries.contains(&loser_hash), "{label}");
                assert!(!after.valid_entries.contains(&parent), "{label}");
                assert!(!after.valid_entries.contains(&revoke_hash), "{label}");
                assert_eq!(
                    folded_status(&after, &consent_key),
                    Some(ActorBindingStatus::Revoked),
                    "after {label}: {:?}",
                    after.issues
                );
                assert_eq!(
                    after.actor_write_disposition(&actor, "human", None),
                    CausalWriteDisposition::Quarantined,
                    "{label}"
                );
                // The ancestry exception never forgives an invalid revoke's
                // primary/co-signature, vault, signer, or missing signed branch.
                let revoke_index = entries.len() - 2;
                for signature in ["primary", "cosign"] {
                    let mut tampered = entries.clone();
                    if signature == "primary" {
                        tampered[revoke_index].signer.signature[0] ^= 1;
                    } else {
                        tampered[revoke_index].cosigns[0].signature[0] ^= 1;
                    }
                    let invalid = fold_authority_log_with_seen_times(&tampered, &first_seen, now);
                    assert_eq!(
                        folded_status(&invalid, &consent_key),
                        Some(ActorBindingStatus::Active),
                        "{label} {signature}"
                    );
                }
                let missing: Vec<_> = entries
                    .iter()
                    .filter(|entry| authority_entry_hash(entry).unwrap() != loser_hash)
                    .cloned()
                    .collect();
                assert_eq!(
                    folded_status(
                        &fold_authority_log_with_seen_times(&missing, &first_seen, now),
                        &consent_key
                    ),
                    Some(ActorBindingStatus::Active),
                    "{label} missing ancestry"
                );
                let wrong_vault = unsigned_entry(
                    Some([0x88; 32]),
                    seq,
                    vec![parent],
                    revoke_actor_op(&consent_key, 11),
                    if signer_lost {
                        actual_key.clone()
                    } else {
                        consent_key.clone()
                    },
                    8,
                );
                let wrong_vault = if signer_lost {
                    cosign_ed(wrong_vault, &actual_signer, &consent)
                } else {
                    cosign_ed(wrong_vault, &consent, &actual_signer)
                };
                let mut wrong = entries.clone();
                wrong[revoke_index] = wrong_vault;
                assert_eq!(
                    folded_status(
                        &fold_authority_log_with_seen_times(&wrong, &first_seen, now),
                        &consent_key
                    ),
                    Some(ActorBindingStatus::Active),
                    "{label} wrong vault"
                );
                let outsider = ed_key(108);
                let unauthorized = cosign_ed(
                    unsigned_entry(
                        Some(vault),
                        1,
                        vec![parent],
                        revoke_actor_op(&consent_key, 11),
                        authority_key_from_ed(&outsider),
                        8,
                    ),
                    &outsider,
                    &consent,
                );
                let mut wrong_signer = entries.clone();
                wrong_signer[revoke_index] = unauthorized;
                assert_eq!(
                    folded_status(
                        &fold_authority_log_with_seen_times(&wrong_signer, &first_seen, now),
                        &consent_key
                    ),
                    Some(ActorBindingStatus::Active),
                    "{label} unauthorized signer"
                );
                entries.reverse();
                assert_eq!(
                    fold_authority_log_with_seen_times(&entries, &first_seen, now),
                    after,
                    "{label}"
                );
                if !matches!(chain, Chain::Invalid) {
                    // The pending grant may later mature (and in the mixed
                    // chain, become intrinsically invalid). Neither transition
                    // can erase the revoke fact in the complete signed log.
                    let matured = now + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
                    let later = fold_authority_log_with_seen_times(&entries, &first_seen, matured);
                    assert_eq!(
                        folded_status(&later, &consent_key),
                        Some(ActorBindingStatus::Revoked),
                        "matured {label}: {:?}",
                        later.issues
                    );
                    assert!(
                        !later.valid_entries.contains(&loser_hash),
                        "matured {label}"
                    );
                    assert!(!later.valid_entries.contains(&parent), "matured {label}");
                    entries.reverse();
                    assert_eq!(
                        fold_authority_log_with_seen_times(&entries, &first_seen, matured),
                        later,
                        "matured order {label}"
                    );
                }
            }
        }
    }
}

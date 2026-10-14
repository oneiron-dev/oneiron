//! Oracle comparison: the queued scheduler folds exactly as the full rescan
//! it replaced (H72), on random logs with ties, waits, invalid rows and the
//! stalled-withdrawal pass.
use super::support::*;
use super::*;
use crate::authority::ancestry_evaluator::{EvaluationPhase, evaluate_entry};
use crate::authority::fold_schedule::fold_entry_states;
use rand::Rng;

/// The scheduler as it was: rescan every pending entry after each transition.
fn rescan_entry_states(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> BTreeMap<AuthorityEntryHash, FoldState> {
    let mut states = BTreeMap::new();
    let mut rejected_retired = BTreeSet::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash.keys().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let mut hashes: Vec<_> = pending.iter().copied().collect();
        hashes.sort_by_key(|hash| {
            (
                !matches!(
                    by_hash[hash].op,
                    AuthorityOp::RevokeActor { .. } | AuthorityOp::RevokeDevice { .. }
                ),
                *hash,
            )
        });
        for hash in hashes {
            if progressed {
                break;
            }
            let entry = &by_hash[&hash];
            match evaluate_entry(
                entry,
                hash,
                by_hash,
                &states,
                context,
                EvaluationPhase::Normal,
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(issue) => {
                    if matches!(entry.op, AuthorityOp::EnrollDevice { .. })
                        && entry_is_retired(entry, hash, context)
                    {
                        rejected_retired.insert(hash);
                    }
                    issues.push(issue);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
            }
        }
        if !progressed && !rejected_retired.is_empty() {
            let crossable: BTreeSet<_> = rejected_retired
                .iter()
                .copied()
                .filter(|hash| {
                    matches!(
                        fold_entry_state(
                            &by_hash[hash],
                            *hash,
                            &states,
                            FoldContext {
                                pre_handoff_entries: None,
                                ..context
                            },
                        ),
                        EntryFold::Ready(_)
                    )
                })
                .collect();
            let stalled: Vec<_> = pending.iter().copied().collect();
            for hash in stalled {
                if let EntryFold::Ready(state) = evaluate_entry(
                    &by_hash[&hash],
                    hash,
                    by_hash,
                    &states,
                    context,
                    EvaluationPhase::Stalled(&crossable),
                ) {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
            }
        }
    }
    for hash in pending {
        issues.push(AuthorityFoldIssue::InvalidAncestry(hash));
    }
    states
}

/// A random log over one genesis: confirmations that collide, agent and
/// retired owner enrollments, revocations, slip withdrawals, rows by a key no
/// one enrolled, sequences that repeat, and parents that never arrive.
fn random_log(rng: &mut StdRng) -> Vec<AuthorityLogEntry> {
    let owner = ed_key(40);
    let genesis = genesis_entry(40, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let agents: Vec<_> = (41..44).map(ed_key).collect();
    let stranger = ed_key(45);
    let mut entries = vec![genesis];
    for n in 0..rng.gen_range(4..28_u64) {
        let mut parents =
            vec![authority_entry_hash(&entries[rng.gen_range(0..entries.len())]).unwrap()];
        if rng.gen_bool(0.3) {
            parents.push(authority_entry_hash(&entries[rng.gen_range(0..entries.len())]).unwrap());
        }
        if rng.gen_bool(0.08) {
            parents.push([0xEE; 32]);
        }
        parents.sort();
        parents.dedup();
        let agent = &agents[rng.gen_range(0..agents.len())];
        let op = match rng.gen_range(0..7) {
            0 | 1 => {
                let id = rng.gen_range(0..6_u8);
                AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                    kind: AuthorityConfirmKind::Accept,
                    confirm_id: [id + 1; 32],
                    peer_vault_id: [77; 32],
                    epoch: 1,
                    nonce: [rng.gen_range(1..8_u8); 16],
                })
            }
            2 => AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(agent),
                    ROLE_AGENT,
                    AuthorityTier::Software,
                ),
            },
            3 => AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(agent),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            4 => AuthorityOp::RevokeDevice {
                revoked_key: authority_key_from_ed(agent),
            },
            5 => AuthorityOp::RevokeActor {
                authority_key: authority_key_from_ed(agent),
                epoch: 1,
            },
            _ => AuthorityOp::SlipRevoke {
                slip_id: [rng.gen_range(1..4_u8); 32],
            },
        };
        let signer = match rng.gen_range(0..10) {
            0 => &stranger,
            1 => agent,
            _ => &owner,
        };
        let seq = if rng.gen_bool(0.15) { 1 } else { n + 1 };
        entries.push(sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                parents,
                op,
                authority_key_from_ed(signer),
                2,
            ),
            signer,
        ));
    }
    entries
}

#[test]
fn the_queued_scheduler_folds_as_the_full_rescan_did() {
    let storage = LocalFoldContext::default();
    let no_handoffs = BTreeSet::new();
    let mut retired_runs = 0;
    for seed in 0..400_u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let entries = random_log(&mut rng);
        let by_hash: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (authority_entry_hash(entry).unwrap(), entry.clone()))
            .collect();
        for retired in [false, true] {
            let context = FoldContext {
                pre_handoff_entries: retired.then_some(&no_handoffs),
                ..storage.context()
            };
            let mut expected_issues = Vec::new();
            let expected = rescan_entry_states(&by_hash, context, &mut expected_issues);
            let mut issues = Vec::new();
            let states = fold_entry_states(&by_hash, context, &mut issues);
            assert_eq!(states, expected, "seed {seed} retired {retired}");
            assert_eq!(issues, expected_issues, "seed {seed} retired {retired}");
            retired_runs += usize::from(
                retired
                    && by_hash.iter().any(|(hash, entry)| {
                        matches!(entry.op, AuthorityOp::EnrollDevice { .. })
                            && entry_is_retired(entry, *hash, context)
                    }),
            );
        }
    }
    assert!(
        retired_runs > 50,
        "{retired_runs} logs held a retired enrollment"
    );
}

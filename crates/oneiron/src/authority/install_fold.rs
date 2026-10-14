//! The strict fold as this install reads it, once its handoffs settle: its
//! own sequence floors, the stale-roster window, and only the machines it
//! counts.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::{FoldLocalInputs, fold_authority_log_once};
use super::machine_standing::InstallCounted;
use super::*;

pub(super) fn fold_as_install(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> AuthorityFold {
    let sequence_floors = local
        .observations
        .map(|observations| &observations.sequence_floors);
    let stale_roster_window_secs = local
        .observations
        .map_or(DEFAULT_STALE_ROSTER_WINDOW_SECS, |local| {
            local.policy.stale_roster_window_secs
        });
    let standing = local
        .machine_standing
        .unwrap_or(&super::machine_standing::every_chain);
    let no_vouch = NoVouch::of(
        entries,
        first_seen_at_secs,
        now_secs,
        peer_consent_roots,
        consent_arm,
        local,
    );
    let context = FoldContext {
        sequence_floors,
        floor_vouched: local
            .observations
            .filter(|observations| !observations.unvouched)
            .map(|observations| &observations.vouched),
        install_held: no_vouch.as_ref().map(|no_vouch| &no_vouch.held),
        entry_ancestors: None,
        peer_consent_roots,
        consent_arm,
        hosted: local.hosted,
        machine_standing: standing,
        pre_handoff_entries: local.pre_handoff_entries,
        pin: local.pin,
    };
    // Staleness is this install's own projection, which the structural fold
    // never sees, and so is a roster left with no settled root. A machine
    // stale here, or one such a roster admitted, is one this install does not
    // count, so fold again without it: its world edits then only narrow. Both
    // rest on valid entries alone and counting changes no entry's validity, so
    // the second fold finds the same machines. So does a machine the fold with
    // no vouch does not count as this one would. Each is a chain of a machine,
    // not the machine: a chain held here does not veto another live chain
    // that admitted the machine on its own (the Engine's held-chain ruling).
    let mut uncounted = BTreeSet::<(crate::EntityId, MachineAdmitter)>::new();
    let mut fold = loop {
        let counted = |machine: crate::EntityId, admitter: MachineAdmitter| {
            !uncounted.contains(&(machine, admitter)) && standing(machine, admitter)
        };
        let fold = apply_stale_roster_window(
            entries,
            fold_authority_log_once(
                entries,
                FoldContext {
                    machine_standing: &counted,
                    ..context
                },
                local.handoff_candidates,
            ),
            first_seen_at_secs,
            now_secs,
            stale_roster_window_secs,
        );
        // The pin counts only while the fold holds its root: the pinned anchor
        // signed that id here.
        let mut fold = fold;
        fold.pinned_root = local.pin.copied().filter(|pin| {
            fold.root_anchors
                .get(&pin.anchor_key)
                .is_some_and(|ids| ids.contains(&pin.id))
        });
        let mut now_uncounted = BTreeSet::new();
        for (id, machine) in &fold.machines {
            if machine
                .roster
                .iter()
                .chain(&machine.roster_trusted)
                .any(|chain| chain.stale || chain.admitter_unsettled)
            {
                now_uncounted.insert((*id, MachineAdmitter::Roster));
            }
            if let Some(no_vouch) = &no_vouch {
                now_uncounted.extend(
                    no_vouch
                        .uncounted(&fold, *id, machine)
                        .into_iter()
                        .map(|admitter| (*id, admitter)),
                );
            }
        }
        if fold.worlds.is_empty() || now_uncounted.is_subset(&uncounted) {
            break fold;
        }
        uncounted = now_uncounted;
    };
    if let Some(no_vouch) = &no_vouch {
        no_vouch.cap(&mut fold);
    }
    fold.append_heads = super::world_privacy::main_log_heads(entries, &fold.valid_entries);
    for entry in entries {
        // Advance beyond even a signed rejected local entry. A new local write
        // never reuses a sequence, though independently received siblings may.
        fold.append_sequences
            .entry(entry.signer.public_key.clone())
            .and_modify(|seq| *seq = (*seq).max(entry.seq))
            .or_insert(entry.seq);
    }
    fold
}

/// [`fold_authority_log`] as an install that counts only some of the
/// machines' chains the roster rule admits.
#[cfg(test)]
pub(super) fn fold_authority_log_with_machine_standing(
    entries: &[AuthorityLogEntry],
    standing: InstallCounted<'_>,
) -> AuthorityFold {
    super::fold_engine::fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs {
            machine_standing: Some(standing),
            ..FoldLocalInputs::VAULT_DOOR
        },
    )
}

/// The fold with no vouch at all, which bounds what this install reads (the
/// Engine's rulings on Sol P2 rounds 17-18). A vouch, a handoff's for its
/// line or a removal's for its branch, decides only which rows stand, which
/// handoff wins and settles, and what the roster view shows. This install
/// reads no destination, machine or world wider than the fold with no vouch,
/// which runs its own handoff probes and pre-handoff permissions, except
/// through a fresh grant after a candidate handoff. With no vouched row a
/// floor would refuse, the vouch changes nothing, and nothing is bounded.
struct NoVouch {
    fold: AuthorityFold,
    /// The candidate handoffs, and the rows they precede.
    handoffs: BTreeSet<AuthorityEntryHash>,
    after: BTreeSet<AuthorityEntryHash>,
    /// The machine revisions and world edits that land restriction only
    /// here: each one that fold holds back or only the vouch admits, unless
    /// a candidate handoff precedes it. A fresh row after a handoff is judged
    /// here alone, on its own floors; while a candidate stays in conflict no
    /// machine counts here at all.
    held: BTreeSet<AuthorityEntryHash>,
    /// The first still-future second at which that fold changes.
    deadline: Option<u64>,
}

impl NoVouch {
    fn of(
        entries: &[AuthorityLogEntry],
        first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
        now_secs: Option<u64>,
        peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
        consent_arm: fn(&FoldedDevice) -> bool,
        local: FoldLocalInputs<'_>,
    ) -> Option<Self> {
        let (Some(observations), Some(handoffs)) = (local.observations, local.handoff_candidates)
        else {
            return None;
        };
        if observations.unvouched {
            return None;
        }
        let by_hash: BTreeMap<_, _> = entries
            .iter()
            .filter_map(|entry| authority_entry_hash(entry).ok().map(|hash| (hash, entry)))
            .collect();
        // Only a row a floor would refuse needs a vouch. A removal vouches for
        // its own branch, whichever rows that holds.
        let refused = |hash: &AuthorityEntryHash| {
            by_hash
                .get(hash)
                .zip(observations.sequence_floors.get(hash))
                .is_some_and(|(entry, floor)| {
                    entry.seq < *floor
                        && !super::entry_transition::lands_restriction_only(&entry.op)
                })
        };
        let removal = by_hash
            .values()
            .any(|entry| super::revoke_proof::removes_machine(&entry.op));
        let rescues = observations.vouched.iter().any(refused)
            || (removal && observations.sequence_floors.keys().any(refused));
        if !rescues {
            return None;
        }
        let unvouched = observations.without_vouch();
        let fold = super::fold_engine::fold_authority_log_inner(
            entries,
            first_seen_at_secs,
            now_secs,
            peer_consent_roots,
            consent_arm,
            FoldLocalInputs {
                observations: Some(&unvouched),
                retire_device_ops: true,
                pre_handoff_entries: None,
                handoff_candidates: None,
                ..local
            },
        );
        let after = after_handoffs(&by_hash, handoffs);
        let held = by_hash
            .iter()
            .filter(|(hash, entry)| {
                super::entry_transition::lands_restriction_only(&entry.op)
                    && !fold.valid_entries.contains(*hash)
            })
            .map(|(hash, _)| hash)
            .chain(&fold.install.held_back)
            .filter(|hash| !after.contains(*hash))
            .copied()
            .collect();
        let deadline = now_secs.and_then(|now| {
            next_stale_roster_deadline(
                entries,
                &fold,
                first_seen_at_secs,
                now,
                observations.policy.stale_roster_window_secs,
            )
        });
        Some(Self {
            fold,
            handoffs: handoffs.clone(),
            after,
            held,
            deadline,
        })
    }

    /// Whether `row` comes after a handoff that settled in `fold`. While a
    /// candidate stays in conflict no root settles, and nothing is fresh (the
    /// Engine's pin on the exemption).
    fn fresh(&self, fold: &AuthorityFold, row: &AuthorityEntryHash) -> bool {
        self.after.contains(row)
            && self
                .handoffs
                .iter()
                .all(|handoff| fold.valid_entries.contains(handoff))
    }

    /// The chains of a machine this install does not count. Per chain, P2's
    /// rule: a chain counts only when the fold with no vouch has it live under
    /// the same head, or a revision after a settled handoff heads it (Wonder
    /// P2 round 12, W2). Per machine, the output bound: the machine counts
    /// only when the fold with no vouch counts it, through some chain, with
    /// the same keys, unless its trusted chain's head is such a fresh revision
    /// (the Engine's held-chain ruling, guard 3). Otherwise every chain is held.
    fn uncounted(
        &self,
        fold: &AuthorityFold,
        id: crate::EntityId,
        machine: &FoldedMachine,
    ) -> BTreeSet<MachineAdmitter> {
        let theirs = self.fold.machines.get(&id);
        let heads = |folded: &'_ FoldedMachine| {
            folded
                .chains()
                .chain(
                    folded
                        .roster_trusted
                        .iter()
                        .map(|chain| (MachineAdmitter::Roster, chain)),
                )
                .map(|(admitter, head)| (admitter, head.clone()))
                .collect::<Vec<_>>()
        };
        let counted_there = theirs.map(heads).unwrap_or_default();
        let mut held: BTreeSet<_> = heads(machine)
            .into_iter()
            .filter(|(admitter, head)| {
                !self.fresh(fold, &head.entry)
                    && !counted_there.iter().any(|(other, counted)| {
                        other == admitter && counted.entry == head.entry && counted.is_live()
                    })
            })
            .map(|(admitter, _)| admitter)
            .collect();
        let mut ours = machine.clone();
        for admitter in &held {
            ours.hold(admitter);
        }
        let bound = ours
            .trusted(fold.pinned_root.as_ref())
            .is_some_and(|trusted| {
                let fresh = ours
                    .trust_head(&trusted.chain)
                    .is_some_and(|head| self.fresh(fold, &head.entry));
                !fresh
                    && !theirs
                        .and_then(|theirs| theirs.trusted(self.fold.pinned_root.as_ref()))
                        .is_some_and(|counted| {
                            counted.profile.machine_key == trusted.profile.machine_key
                                && counted.profile.encryption_key == trusted.profile.encryption_key
                        })
            });
        if bound {
            held.extend(machine.chains().map(|(admitter, _)| admitter));
        }
        held
    }

    /// Holds every chain this install does not count, and reads each world
    /// as the meet of both folds' settings, a world no edit reaches here
    /// included, unless only edits after a settled handoff stand in it.
    fn cap(&self, fold: &mut AuthorityFold) {
        fold.install.no_vouch_deadline = self.deadline;
        let uncounted: Vec<_> = fold
            .machines
            .iter()
            .map(|(id, machine)| (*id, self.uncounted(fold, *id, machine)))
            .collect();
        for (id, admitters) in uncounted {
            if let Some(machine) = fold.machines.get_mut(&id) {
                for admitter in &admitters {
                    machine.hold(admitter);
                }
            }
        }
        let worlds: BTreeSet<_> = fold
            .worlds
            .keys()
            .chain(self.fold.worlds.keys())
            .copied()
            .collect();
        let fresh: BTreeSet<_> = worlds
            .iter()
            .filter(|world| {
                fold.worlds.get(*world).is_some_and(|folded| {
                    !folded.live.is_empty() && folded.live.keys().all(|edit| self.fresh(fold, edit))
                })
            })
            .copied()
            .collect();
        for world in worlds.difference(&fresh) {
            let folded = fold.worlds.entry(*world).or_insert_with(|| FoldedWorld {
                live: BTreeMap::new(),
                effective: EffectiveWorldPrivacy::default(),
                roster_read: EffectiveWorldPrivacy::default().read,
                anchor_reads: BTreeMap::new(),
            });
            folded.effective = super::world_privacy::meet_effective(
                &folded.effective,
                &self.fold.world_privacy(*world),
            );
        }
    }
}

/// The rows a handoff in `handoffs` precedes.
fn after_handoffs(
    by_hash: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    handoffs: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut children = BTreeMap::<_, Vec<_>>::new();
    for (hash, entry) in by_hash {
        for parent in &entry.parent_hashes {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut after = BTreeSet::new();
    let mut stack: Vec<_> = handoffs.iter().copied().collect();
    while let Some(hash) = stack.pop() {
        for child in children.get(&hash).into_iter().flatten() {
            if after.insert(*child) {
                stack.push(*child);
            }
        }
    }
    after
}

/// The machine revisions and world edits `state` holds back on this install.
pub(super) fn held_back(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> InstallBound {
    let mut held_back = BTreeSet::new();
    super::machine_standing::held_revisions(state, &mut held_back);
    super::world_privacy::held_edits(state, pin, counted, &mut held_back);
    InstallBound {
        held_back,
        no_vouch_deadline: None,
    }
}

//! The strict fold as this install reads it, once its handoffs settle: its
//! own sequence floors, the stale-roster window, and only the machines it
//! counts.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::{FoldLocalInputs, fold_authority_log_once};
use super::machine_standing::{InstallCounted, InstallHold};
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
    // This install's floors with no vouch and no hold: the context in which
    // causal ancestry clears what it can before any vouch is judged.
    let bare = FoldContext {
        sequence_floors,
        floor_vouched: None,
        install_held: None,
        entry_ancestors: None,
        peer_consent_roots,
        consent_arm,
        hosted: local.hosted,
        machine_standing: standing,
        pre_handoff_entries: local.pre_handoff_entries,
        memory_floor_bytes: super::log_budget::fold_memory_floor(
            local.observations.map(|observations| &observations.policy),
        ),
        pin: local.pin,
    };
    let no_vouch = NoVouch::of(entries, first_seen_at_secs, now_secs, local, bare);
    let context = FoldContext {
        floor_vouched: local
            .observations
            .filter(|observations| !observations.unvouched)
            .map(|observations| &observations.vouched),
        install_held: no_vouch.as_ref().map(|no_vouch| &no_vouch.held),
        ..bare
    };
    // Staleness is this install's own projection, which the structural fold
    // never sees, and so is a roster left with no settled root. A machine
    // stale here, or one such a roster admitted, is one this install does not
    // count, so fold again without it: its world edits then only narrow. Both
    // rest on valid entries alone and counting changes no entry's validity, so
    // the second fold finds the same machines. So does a machine the fold with
    // no vouch does not count as this one would. Each is a chain of a machine,
    // not the machine: a chain held here does not veto another live chain
    // that admitted the machine on its own (the Engine's held-chain ruling),
    // and a stale one vetoes nothing (Sol code-R3 S3-F3).
    let mut stale = BTreeSet::<(crate::EntityId, MachineAdmitter)>::new();
    let mut held = BTreeSet::<(crate::EntityId, MachineAdmitter)>::new();
    let mut rounds = 0_usize;
    let mut fold = loop {
        rounds += 1;
        let counted = |machine: crate::EntityId, admitter: MachineAdmitter| {
            let outer = standing(machine, admitter);
            InstallHold {
                held: outer.held || held.contains(&(machine, admitter)),
                stale: outer.stale || stale.contains(&(machine, admitter)),
            }
        };
        let fold = install_view(
            entries,
            fold_authority_log_once(
                entries,
                FoldContext {
                    machine_standing: &counted,
                    ..context
                },
                local.handoff_candidates,
                local.capture,
            ),
            first_seen_at_secs,
            now_secs,
            stale_roster_window_secs,
            local.pin,
        );
        let now_stale = stale_chains(&fold);
        let mut now_held = BTreeSet::new();
        for (id, machine) in &fold.machines {
            if let Some(no_vouch) = &no_vouch {
                now_held.extend(
                    no_vouch
                        .uncounted(&fold, *id, machine)
                        .into_iter()
                        .map(|admitter| (*id, admitter)),
                );
            }
        }
        // Counting reaches only world edits and key records, and a key record
        // counts only for a world an edit made private (an unedited world
        // reads everywhere): with no edited world, nothing rests on it.
        if fold.worlds.is_empty() || (now_stale.is_subset(&stale) && now_held.is_subset(&held)) {
            break fold;
        }
        stale = now_stale;
        held = now_held;
    };
    if let Some(no_vouch) = &no_vouch {
        no_vouch.cap(&mut fold);
    }
    // A resumed fold reproduces only one round with no vouch to bound it.
    if let Some(capture) = local.capture
        && (rounds > 1 || no_vouch.is_some())
    {
        capture.spoil();
    }
    finish_install_fold(entries, &mut fold);
    fold
}

/// A once fold as this install reads it: its stale-roster window, and the
/// pin while the fold holds its root (the pinned anchor signed that id here).
pub(super) fn install_view<E: std::borrow::Borrow<AuthorityLogEntry>>(
    entries: &[E],
    once: AuthorityFold,
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    stale_roster_window_secs: u64,
    pin: Option<&PinnedRoot>,
) -> AuthorityFold {
    let mut fold = apply_stale_roster_window(
        entries,
        once,
        first_seen_at_secs,
        now_secs,
        stale_roster_window_secs,
    );
    fold.pinned_root = pin.copied().filter(|pin| {
        fold.root_anchors
            .get(&pin.anchor_key)
            .is_some_and(|ids| ids.contains(&pin.id))
    });
    fold
}

/// The machines whose roster chain is stale here, or left with no settled
/// root: chains this install does not count.
pub(super) fn stale_chains(fold: &AuthorityFold) -> BTreeSet<(crate::EntityId, MachineAdmitter)> {
    fold.machines
        .iter()
        .filter(|(_, machine)| {
            machine
                .roster
                .iter()
                .chain(&machine.roster_trusted)
                .any(|chain| chain.stale || chain.admitter_unsettled)
        })
        .map(|(id, _)| (*id, MachineAdmitter::Roster))
        .collect()
}

/// The heads, scope heads and next sequences of an install's fold.
pub(super) fn finish_install_fold(entries: &[AuthorityLogEntry], fold: &mut AuthorityFold) {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| super::fold_resume::RowMeta::of(authority_entry_hash(entry).ok(), entry))
        .collect();
    finish_install_fold_of(&rows, fold);
}

/// [`finish_install_fold`] over the rows' metadata, all it reads of them.
pub(super) fn finish_install_fold_of(
    rows: &[super::fold_resume::RowMeta<'_>],
    fold: &mut AuthorityFold,
) {
    (fold.append_heads, fold.anchor_heads) = super::world_privacy::main_log_heads(
        rows,
        &fold.valid_entries,
        &fold.anchor_entries,
        fold.pinned_root.map(|pin| pin.anchor_key),
    );
    for row in rows {
        // Advance beyond even a signed rejected local entry. A new local write
        // never reuses a sequence, though independently received siblings may.
        fold.append_sequences
            .entry(row.signer.clone())
            .and_modify(|seq| *seq = (*seq).max(row.seq))
            .or_insert(row.seq);
        if let Some(world) = row.world
            && let Some(hash) = row.hash
            && fold.valid_entries.contains(&hash)
        {
            let head = fold
                .scope_heads
                .entry((row.signer.clone(), world))
                .or_insert((row.seq, hash));
            if row.seq > head.0 {
                *head = (row.seq, hash);
            }
        }
    }
}

/// [`fold_authority_log`] as an install that counts only some of the
/// machines' chains the roster rule admits: it holds the rest.
#[cfg(test)]
pub(super) fn fold_authority_log_with_machine_standing(
    entries: &[AuthorityLogEntry],
    counts: &dyn Fn(crate::EntityId, MachineAdmitter) -> bool,
) -> AuthorityFold {
    fold_pinned_with_machine_standing(entries, None, counts)
}

/// The same, on an install pinned to `pin`.
#[cfg(test)]
pub(super) fn fold_pinned_with_machine_standing(
    entries: &[AuthorityLogEntry],
    pin: Option<&PinnedRoot>,
    counts: &dyn Fn(crate::EntityId, MachineAdmitter) -> bool,
) -> AuthorityFold {
    let standing = |machine, admitter| InstallHold {
        held: !counts(machine, admitter),
        stale: false,
    };
    super::fold_engine::fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs {
            machine_standing: Some(&standing),
            pin,
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
    /// `bare` is this install's fold context with no vouch and no hold.
    fn of(
        entries: &[AuthorityLogEntry],
        first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
        now_secs: Option<u64>,
        local: FoldLocalInputs<'_>,
        bare: FoldContext<'_>,
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
        // its own branch, whichever rows that holds. A row causal ancestry
        // already admits needs none, so the floors are the ones the fold keeps
        // once later rows of the same signer and scope vouch for what they
        // can (Astra #1422c F1). Clearing only drops floors, so the receipts
        // alone rule out most folds first.
        let removal = by_hash
            .values()
            .any(|entry| super::revoke_proof::removes_machine(&entry.op));
        let rescues = |floors: &BTreeMap<AuthorityEntryHash, u64>| {
            let refused = |hash: &AuthorityEntryHash| {
                by_hash
                    .get(hash)
                    .zip(floors.get(hash))
                    .is_some_and(|(entry, floor)| {
                        entry.seq < *floor
                            && !super::entry_transition::lands_restriction_only(&entry.op)
                    })
            };
            observations.vouched.iter().any(refused) || (removal && floors.keys().any(refused))
        };
        if !rescues(&observations.sequence_floors)
            || !super::fold_engine::causal_floors_of(entries, bare)
                .is_some_and(|floors| rescues(&floors))
        {
            return None;
        }
        let unvouched = observations.without_vouch();
        let fold = super::fold_engine::fold_authority_log_inner(
            entries,
            first_seen_at_secs,
            now_secs,
            bare.peer_consent_roots,
            bare.consent_arm,
            FoldLocalInputs {
                observations: Some(&unvouched),
                retire_device_ops: true,
                pre_handoff_entries: None,
                handoff_candidates: None,
                capture: None,
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
    /// A chain both folds end in one removal is not held: the removal lands
    /// alike in both, and a hold would reach back into every earlier state,
    /// where the machine's own records were counted (Astra #1422c F1).
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
                        other == admitter
                            && counted.entry == head.entry
                            && (counted.is_live() || (counted.removed && head.removed))
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
                local_read: EffectiveWorldPrivacy::default().read,
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

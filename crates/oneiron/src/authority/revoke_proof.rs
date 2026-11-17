//! Log-derived, typed restrictive facts (actor and device revocations, slip
//! withdrawals, a Grant's slip withdrawals, slip burns and machine removals),
//! independent of roster survivors.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// One fully verified restrictive fact. Scratch ancestry is proof only; it
/// never enters `valid_entries`, the roster, or the permissive merged state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct VerifiedRestriction {
    vault_id: AuthorityVaultId,
    entry_hash: AuthorityEntryHash,
    kind: Restriction,
    /// The rows its proven branch folded through an owner anchor's branch.
    routed: BTreeSet<AuthorityEntryHash>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum Restriction {
    Actor {
        authority_key: AuthorityKey,
        epoch: u64,
    },
    /// A verified `SlipRevoke`: the withdrawn id.
    SlipRevoke([u8; 32]),
    /// A verified `SlipGrantRevoke`: the Grant, in hex as a slip's claims
    /// name it, whose every slip is withdrawn.
    SlipGrantRevoke(String),
    /// A verified membership execution record (FIX 12335): each Grant it
    /// names, in hex as a slip's claims name it, whose every slip is
    /// withdrawn.
    GrantsWithdrawn(BTreeSet<String>),
    /// A verified `SlipConsume` or `RemovalArchiveConsume`: every id its
    /// proven branch had burnt, the single-use ancestors a `SlipConsume`
    /// spent among them.
    SlipBurn(BTreeSet<[u8; 32]>),
    /// A verified machine removal: the removing admitter's chain on the
    /// removal's own branch, whose head is the terminal revision. Only the
    /// removal itself travels: nothing else that branch held.
    MachineRemoval {
        machine: EntityId,
        admitter: MachineAdmitter,
        chain: Box<MachineChain>,
    },
    /// A verified `RevokeDevice`: the revoked key (FIX
    /// [CONFIRM-COLLISION-SUBTREE-ROLLBACK]). The fold can refuse a
    /// revocation whose ancestry holds a permissive row it refused
    /// (InvalidAncestry); the proof crosses that row (`skippable_permissive`),
    /// so the key stays revoked. A confirmation collision refuses no row
    /// (RULING COLLISION-SETTLEMENT-SHAPE = A).
    DeviceRevoke(AuthorityKey),
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct RevokeFacts {
    by_hash: BTreeMap<AuthorityEntryHash, VerifiedRestriction>,
}

impl RevokeFacts {
    /// Join only restrictions scoped to the surviving vault. The ordinary
    /// transition and this projection use the same max/union implementation:
    /// every set here only grows, so a restriction proved on its own signed
    /// branch stays applied whichever sibling wins the projection.
    pub(super) fn apply_to(&self, state: &mut FoldState) {
        let vault_id = state.vault_id;
        for fact in self
            .by_hash
            .values()
            .filter(|fact| fact.vault_id == vault_id)
        {
            match &fact.kind {
                Restriction::Actor {
                    authority_key,
                    epoch,
                } => record_actor_revoke(state, authority_key, *epoch, fact.entry_hash),
                Restriction::SlipRevoke(slip_id) => {
                    state.slips.revoked.insert(*slip_id);
                    state.slips.explicit_revoked.insert(*slip_id);
                }
                Restriction::SlipGrantRevoke(grant_ref) => {
                    state.slips.revoke_grant(grant_ref.clone());
                }
                Restriction::GrantsWithdrawn(grants) => {
                    for grant in grants {
                        state.slips.revoke_grant(grant.clone());
                    }
                }
                Restriction::SlipBurn(burnt) => {
                    state.slips.consumed.extend(burnt.iter().copied());
                }
                Restriction::MachineRemoval {
                    machine,
                    admitter,
                    chain,
                } => {
                    super::machine_profile::merge_machine_chain(state, *machine, *admitter, chain);
                }
                Restriction::DeviceRevoke(key) => super::op_apply::revoke_key(state, key),
            }
        }
    }

    /// The rows of the verified device revocations scoped to `vault_id`. A
    /// fact stands where its row may not (a revocation above a refused
    /// permissive row), so the stale-roster window times a revoked key's
    /// approvals from these rows as from a valid revocation (Sol review F1
    /// on #8608).
    pub(super) fn device_revocations(
        &self,
        vault_id: AuthorityVaultId,
    ) -> BTreeSet<AuthorityEntryHash> {
        self.by_hash
            .values()
            .filter(|fact| {
                fact.vault_id == vault_id && matches!(fact.kind, Restriction::DeviceRevoke(_))
            })
            .map(|fact| fact.entry_hash)
            .collect()
    }

    /// Adds each device revocation a whole fold proves in `tail`, an adopted
    /// image's tail that folded past it with every covered row in each
    /// revocation's causal past (FIX 11760). One the tail folds to a state in
    /// `states` folded on a branch whose every row folds, where the whole
    /// fold's proof ([`verify_signed_branch`]) is its ordinary state: it takes
    /// its fact on that state's vault and owner-anchor rows, as
    /// [`derive_revoke_facts`] takes it on the proof's (FIX
    /// [CONFIRM-COLLISION-SUBTREE-ROLLBACK]). One with no state adds none: on
    /// a parent with no state either, the adopted fold leaves it to the whole
    /// history, whose proof crosses rejected permissive rows to it.
    pub(super) fn add_serial_device_revokes(
        &mut self,
        tail: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        for (hash, entry) in tail {
            let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
                continue;
            };
            let Some(state) = states.get(hash) else {
                continue;
            };
            self.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind: Restriction::DeviceRevoke(revoked_key.clone()),
                    routed: state.anchor_entries.clone(),
                },
            );
        }
    }

    /// The rows these facts were proved on, for a test that compares two
    /// images built over the same rows.
    #[cfg(oneiron_test_support)]
    pub(super) fn rows_for_test(&self) -> BTreeSet<AuthorityEntryHash> {
        self.by_hash.keys().copied().collect()
    }
}

#[doc(hidden)]
pub(super) use oneiron_records::authority::revoke_proof::{
    removes_machine, restrictive_withdrawal,
};

/// Every candidate comes from the already signature-filtered entry graph.
/// The proof uses the same `fold_entry_state` and shared stalled-ancestor
/// evaluator as the ordinary fold, with only global winner selection removed.
/// Neither input arrival order nor a persisted node-local marker is involved.
pub(super) fn derive_revoke_facts(
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &AncestorIndex,
    context: FoldContext<'_>,
) -> RevokeFacts {
    let mut facts = RevokeFacts::default();
    for (hash, entry) in entries {
        let removal = match &entry.op {
            AuthorityOp::RevokeActor { .. } | AuthorityOp::RevokeDevice { .. } => false,
            op if removes_machine(op) => true,
            _ => continue,
        };
        // A removal is terminal on every replica. It vouches for its own
        // signed branch as a handoff vouches for its line: a local floor only
        // records which of a signer's rows this vault saw first, so the proof
        // applies none inside the branch and accepts what the fold accepts
        // when the branch arrives on its own, siblings at one sequence
        // included (Astra #1423b, Sol #1423 r8 and r9). A row of it past its
        // floor still lands restriction only: the proof's copy acknowledges
        // nothing the ordinary fold's copy does not (Astra #1430b). The fold
        // with no vouch (`floor_vouched: None`) vouches for no branch either
        // (Sol P2 round 18, F2).
        let removal_vouch = removal && context.floor_vouched.is_some();
        let branch: BTreeSet<_> = if removal_vouch {
            ancestors
                .get(hash)
                .into_iter()
                .flat_map(|past| past.iter_unordered())
                .chain([hash])
                .copied()
                .collect()
        } else {
            BTreeSet::new()
        };
        let context = if removal_vouch {
            FoldContext {
                floor_vouched: Some(&branch),
                ..context
            }
        } else {
            context
        };
        // Every revocation's proof follows the fold on two entries of one
        // signer at one sequence: the fold admits such siblings, so the
        // revoked key could otherwise sign two of them under the owner's
        // revocation and leave it with no fact once a floor refuses them
        // (Astra T1 on #8608; [REVOKE-ACTOR-EQUAL-SEQUENCE-SIBLINGS]).
        let Some(state) = verify_signed_branch(*hash, entries, ancestors, context) else {
            continue;
        };
        let (vault_id, routed) = (state.vault_id, state.anchor_entries.clone());
        let kind = match &entry.op {
            AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } => Restriction::Actor {
                authority_key: authority_key.clone(),
                epoch: *epoch,
            },
            AuthorityOp::RevokeDevice { revoked_key } => {
                Restriction::DeviceRevoke(revoked_key.clone())
            }
            AuthorityOp::MachineProfile(profile) => {
                let Some((admitter, chain)) = state
                    .machines
                    .get(&profile.machine)
                    .into_iter()
                    .flatten()
                    .find(|(_, chain)| chain.head.entry == *hash)
                else {
                    continue;
                };
                Restriction::MachineRemoval {
                    machine: profile.machine,
                    admitter: *admitter,
                    chain: Box::new(MachineChain {
                        head: chain.head.clone(),
                        owner_held: chain.owner_held.clone().filter(|held| held.entry == *hash),
                        owner_held_removals: chain
                            .owner_held_removals
                            .iter()
                            .filter(|(_, removal)| removal.entry == *hash)
                            .map(|(signer, removal)| (signer.clone(), removal.clone()))
                            .collect(),
                        // The removal's own revision, past its floor here
                        // still: the proof never erases that mark (Astra
                        // #1430b).
                        revisions: chain
                            .revisions
                            .iter()
                            .filter(|(revision, _)| *revision == hash)
                            .map(|(revision, held)| (*revision, std::sync::Arc::clone(held)))
                            .collect(),
                    }),
                }
            }
            _ => continue,
        };
        facts.by_hash.insert(
            *hash,
            VerifiedRestriction {
                vault_id,
                entry_hash: *hash,
                kind,
                routed,
            },
        );
    }
    facts
}

impl RevokeFacts {
    /// Adds the slip withdrawals and burns the projection dropped. Settling a
    /// handoff removes a fenced row or an unsettled handoff and every entry
    /// after it, a `SlipRevoke`, `SlipConsume` or membership execution
    /// record's Grant withdrawals (FIX 12335) among them, and a revoked or
    /// spent slip would live again. An entry in `survivors` already applied
    /// its restriction through the ordinary fold; each dropped one is proved
    /// on its own signed branch, as an actor revocation is.
    pub(super) fn add_dropped_slip_restrictions(
        &mut self,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
        context: FoldContext<'_>,
        survivors: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        for (hash, entry) in entries {
            if survivors.contains_key(hash) {
                continue;
            }
            let restriction = match &entry.op {
                AuthorityOp::SlipRevoke { slip_id } => Restriction::SlipRevoke(*slip_id),
                AuthorityOp::SlipGrantRevoke { grant_ref, .. } => {
                    Restriction::SlipGrantRevoke(grant_ref.to_hex())
                }
                AuthorityOp::MembershipExecution(record) if !record.withdrawn_grants.is_empty() => {
                    Restriction::GrantsWithdrawn(
                        record
                            .withdrawn_grants
                            .iter()
                            .map(EntityId::to_hex)
                            .collect(),
                    )
                }
                AuthorityOp::SlipConsume { .. } | AuthorityOp::RemovalArchiveConsume { .. } => {
                    Restriction::SlipBurn(BTreeSet::new())
                }
                _ => continue,
            };
            let Some(state) = verify_signed_branch(*hash, entries, ancestors, context) else {
                continue;
            };
            let kind = match restriction {
                Restriction::SlipBurn(_) => Restriction::SlipBurn(state.slips.consumed),
                other => other,
            };
            self.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind,
                    routed: state.anchor_entries,
                },
            );
        }
    }
}

impl RevokeFacts {
    /// These facts with each actor revocation a whole fold proves in `tail`,
    /// an adopted image's tail that folded past it serially (FIX 11760):
    /// every tail row has its ordinary state in `states`. On a branch whose
    /// every row folds, the whole fold's proof of a `RevokeActor`
    /// ([`verify_signed_branch`]) is its ordinary state, siblings at one
    /// sequence included ([REVOKE-ACTOR-EQUAL-SEQUENCE-SIBLINGS]), so each
    /// takes its fact on its ordinary state's vault and owner-anchor rows. A
    /// slip or Grant withdrawal adds none: the ordinary fold applied it, and
    /// only a dropped one is proved on its own.
    pub(super) fn with_serial_actor_revokes(
        &self,
        tail: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) -> Self {
        let mut facts = self.clone();
        for (hash, entry) in tail {
            let AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } = &entry.op
            else {
                continue;
            };
            let Some(state) = states.get(hash) else {
                continue;
            };
            facts.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind: Restriction::Actor {
                        authority_key: authority_key.clone(),
                        epoch: *epoch,
                    },
                    routed: state.anchor_entries.clone(),
                },
            );
        }
        facts
    }
}

impl RevokeFacts {
    /// Forgets every restriction that stands on a key a handoff retired: the
    /// old root revokes no actor and withdraws no slip the new root bound or
    /// minted, whatever its own old branch says. A row the proof took through
    /// an owner anchor's branch rests on that anchor (Wonder W3-F1).
    pub(super) fn forget_retired(
        &mut self,
        retirements: &super::retired_signers::Retirements,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
    ) {
        self.by_hash
            .retain(|hash, fact| !retirements.excludes(hash, entries, ancestors, &fact.routed));
    }

    /// Forgets every restriction proved through a handoff that did not take
    /// effect. The heir a refused or pruned ReRoot names was never root, so
    /// it restricts nothing, however its own branch folds; a restriction the
    /// fold dropped counts only when every ReRoot in its ancestry `settled`.
    pub(super) fn forget_unsettled(
        &mut self,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
    ) {
        self.by_hash.retain(|hash, _| {
            settled.contains_key(hash)
                || ancestors.get(hash).is_some_and(|line| {
                    line.iter_unordered().all(|ancestor| {
                        settled.contains_key(ancestor)
                            || !entries
                                .get(ancestor)
                                .is_some_and(|row| matches!(row.op, AuthorityOp::ReRoot { .. }))
                    })
                })
        });
    }
}

/// The target's own folded state, proved over its signed ancestry alone. The
/// proof follows the fold: it admits concurrent siblings at one sequence and
/// refuses only a sequence that does not rise along the ancestry. External
/// siblings cannot erase a verified restrictive fact on this branch.
fn verify_signed_branch(
    target: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &AncestorIndex,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut pending = ancestors.get(&target)?.to_set();
    pending.insert(target);
    // Every row of the branch is at hand, and none is its own ancestor.
    for hash in &pending {
        if !entries.contains_key(hash) || ancestors.get(hash)?.contains(hash) {
            return None;
        }
    }
    let branch_context = FoldContext {
        entry_ancestors: Some(ancestors),
        ..context
    };
    let mut states = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    loop {
        let mut progressed = false;
        for hash in pending.clone() {
            match super::ancestry_evaluator::evaluate_entry(
                &entries[&hash],
                hash,
                entries,
                &states,
                branch_context,
                super::ancestry_evaluator::EvaluationPhase::Normal,
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_)
                    if hash != target
                        && super::ancestry_evaluator::skippable_permissive(&entries[&hash].op) =>
                {
                    rejected.insert(hash);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_) => return None,
                EntryFold::Waiting => {}
            }
        }
        if let Some(state) = states.remove(&target) {
            return Some(state);
        }
        if progressed {
            continue;
        }
        // Pending children of a rejected ancestor are not proof that the child
        // was valid. Only their signed links may be traversed, and their ops
        // never apply.
        let skipped: BTreeSet<_> = rejected
            .iter()
            .copied()
            .chain(pending.iter().copied().filter(|hash| {
                *hash != target
                    && super::ancestry_evaluator::skippable_permissive(&entries[hash].op)
                    && ancestors
                        .get(hash)
                        .is_some_and(|past| past.intersects(&rejected))
            }))
            .collect();
        let mut rescued = false;
        for hash in pending.clone() {
            if !restrictive_withdrawal(&entries[&hash].op) {
                continue;
            }
            if let EntryFold::Ready(state) = super::ancestry_evaluator::evaluate_entry(
                &entries[&hash],
                hash,
                entries,
                &states,
                branch_context,
                super::ancestry_evaluator::EvaluationPhase::Stalled(&skipped),
            ) {
                states.insert(hash, state);
                pending.remove(&hash);
                rescued = true;
            }
        }
        if !rescued {
            return None;
        }
    }
}

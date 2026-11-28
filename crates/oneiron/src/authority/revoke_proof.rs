//! Log-derived, typed restrictive facts (actor and device revocations, slip
//! withdrawals, a Grant's slip withdrawals, slip burns and machine removals),
//! independent of roster survivors.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

#[cfg(oneiron_test_support)]
thread_local! {
    /// How many row transitions this thread's restriction proofs tried,
    /// while the work door counts (Some; `signed_branch_door`).
    pub(super) static PROOF_TRIES: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Counts one row transition a restriction proof tries, for the work door.
fn note_proof_try() {
    #[cfg(oneiron_test_support)]
    PROOF_TRIES.with(|tries| tries.set(tries.get().map(|count| count + 1)));
}

/// One fully verified restrictive fact. Scratch ancestry is proof only; it
/// never enters `valid_entries`, the roster, or the permissive merged state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct VerifiedRestriction {
    vault_id: AuthorityVaultId,
    entry_hash: AuthorityEntryHash,
    kind: Restriction,
    /// The rows its proven branch folded through an owner anchor's branch.
    routed: BTreeSet<AuthorityEntryHash>,
    /// The Grants whose line its proven branch's fold ended at this row (pass 28 R1): a
    /// dropped end still ends its Grant's line, as its slip withdrawal still withdraws.
    ended_grants: BTreeSet<EntityId>,
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
    /// A verified grant act that ends a Grant's line and withdraws no slip: the owner's
    /// agent Grant revoke (pass 28 R1). Its end is the fact's `ended_grants`.
    GrantEnd,
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
                Restriction::GrantEnd => {}
            }
            for grant in &fact.ended_grants {
                state.grant_lines.end(*grant, fact.entry_hash);
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
                    routed: state.anchor_entries.to_btree_set(),
                },
            );
        }
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
    let mut proofs = SignedBranches::new(entries, ancestors, context);
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
        // (Astra T1 on #8608; [REVOKE-ACTOR-EQUAL-SEQUENCE-SIBLINGS]). A
        // removal that vouches for its own branch is proved under that vouch
        // alone; every other restriction shares the fold's proofs.
        let proved = if removal_vouch {
            verify_signed_branch(*hash, entries, ancestors, context)
        } else {
            proofs.verify(*hash)
        };
        let Some(state) = proved else {
            continue;
        };
        let (vault_id, routed) = (state.vault_id, state.anchor_entries.to_btree_set());
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
                let Some(removal) = machine_removal(&state, profile.machine, hash) else {
                    continue;
                };
                removal
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
                ended_grants: BTreeSet::new(),
            },
        );
    }
    facts
}

/// The removal `hash` of `machine` as a fact, from a state it folded into:
/// the chain it heads there, carrying only the removal itself.
fn machine_removal(
    state: &FoldState,
    machine: EntityId,
    hash: &AuthorityEntryHash,
) -> Option<Restriction> {
    let (admitter, chain) = state
        .machines
        .get(&machine)
        .into_iter()
        .flatten()
        .find(|(_, chain)| chain.head.entry == *hash)?;
    Some(Restriction::MachineRemoval {
        machine,
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
            // The removal's own revision, past its floor here still: the
            // proof never erases that mark (Astra #1430b).
            revisions: chain
                .revisions
                .iter()
                .filter(|(revision, _)| *revision == hash)
                .map(|(revision, held)| (*revision, std::sync::Arc::clone(held)))
                .collect(),
        }),
    })
}

impl RevokeFacts {
    /// Adds the slip withdrawals and burns the projection dropped. Settling a
    /// handoff removes a fenced row or an unsettled handoff and every entry
    /// after it, a `SlipRevoke`, `SlipConsume` or membership execution
    /// record's Grant withdrawals (FIX 12335) among them, and a revoked or
    /// spent slip would live again. An entry in `survivors` already applied
    /// its restriction through the ordinary fold; each dropped one is proved
    /// on its own signed branch, as an actor revocation is. So is each end of
    /// a Grant's line (pass 28 R1): a dropped `SlipGrantRevoke`, membership
    /// execution record or owner's agent Grant revoke ends each Grant its
    /// proven branch's fold ended at it, or a withdrawn Grant's row put back
    /// would stand again.
    pub(super) fn add_dropped_slip_restrictions(
        &mut self,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
        context: FoldContext<'_>,
        survivors: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        let mut proofs = SignedBranches::new(entries, ancestors, context);
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
                AuthorityOp::AgentGrantAct(record)
                    if matches!(record.change, AgentGrantChange::Revoke { .. }) =>
                {
                    Restriction::GrantEnd
                }
                _ => continue,
            };
            let Some(state) = proofs.verify(*hash) else {
                continue;
            };
            let ended_grants = state.grant_lines.ended_by(hash);
            if matches!(restriction, Restriction::GrantEnd) && ended_grants.is_empty() {
                continue;
            }
            let kind = match restriction {
                Restriction::SlipBurn(_) => {
                    Restriction::SlipBurn(state.slips.consumed.to_btree_set())
                }
                other => other,
            };
            self.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind,
                    routed: state.anchor_entries.to_btree_set(),
                    ended_grants,
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
                    routed: state.anchor_entries.to_btree_set(),
                    ended_grants: BTreeSet::new(),
                },
            );
        }
        facts
    }

    /// Adds each machine removal a whole fold proves in `tail`, an adopted
    /// image's tail that folded past it serially, every row of it with its
    /// ordinary state in `states` (FIX 11760). The whole fold's proof of a
    /// removal ([`verify_signed_branch`]) accepts what the ordinary fold
    /// accepts on its branch, siblings at one sequence included, and no tail
    /// row sits past a floor here: each removal takes its fact on its
    /// ordinary state, as [`derive_revoke_facts`] takes it on the proof's.
    pub(super) fn add_serial_machine_removals(
        &mut self,
        tail: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        for (hash, entry) in tail {
            let AuthorityOp::MachineProfile(profile) = &entry.op else {
                continue;
            };
            if !removes_machine(&entry.op) {
                continue;
            }
            let Some(state) = states.get(hash) else {
                continue;
            };
            let Some(kind) = machine_removal(state, profile.machine, hash) else {
                continue;
            };
            self.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind,
                    routed: state.anchor_entries.to_btree_set(),
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

    /// Forgets the machine removal of every carried answer outside a proving
    /// owner-key enrolment's line that the fold did not count (row
    /// CARRIER-PROOF-OLD-PARENTS): one it held for the owner's proof, or one
    /// that does not stand. Its own branch, which lacks the owner's key,
    /// proves the removal, but the fold judged it where that key reaches, so
    /// the removal would otherwise end the machine on every branch.
    pub(super) fn forget_held_off_the_line(
        &mut self,
        lines: Option<&super::owner_key_line::OwnerKeyLines>,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        let Some(lines) = lines else {
            return;
        };
        self.by_hash.retain(|_, fact| {
            let Restriction::MachineRemoval { machine, .. } = &fact.kind else {
                return true;
            };
            !lines.needs_proof(&fact.entry_hash)
                || settled.get(&fact.entry_hash).is_some_and(|state| {
                    !state
                        .held_machine_answers
                        .get(machine)
                        .is_some_and(|held| held.contains_key(&fact.entry_hash))
                })
        });
    }

    /// Forgets every device revocation whose proven branch holds an
    /// enrolment of the revoked key that a line refuses (row
    /// CARRIER-PROOF-OLD-PARENTS; REVIEW2 #8502, 16 Nov). The custodial
    /// root's agent enrolment of the owner's key on parents before the
    /// owner's enrolment is an invalid entry, and a revoke of that key above
    /// it waits with it. The revoke's own branch, proved with no line, holds
    /// the key as that agent enrolment's, which the root alone may end, so
    /// the fact would end the owner's key on every branch.
    pub(super) fn forget_revokes_above_refused_enrolments(
        &mut self,
        lines: Option<&super::owner_key_line::OwnerKeyLines>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
    ) {
        let Some(lines) = lines else {
            return;
        };
        self.by_hash.retain(|hash, fact| {
            let Restriction::DeviceRevoke(key) = &fact.kind else {
                return true;
            };
            !ancestors
                .get(hash)
                .is_some_and(|branch| lines.refuses_an_enrolment_of(key, branch, entries))
        });
    }

    /// Forgets every restriction proved through a handoff that did not take
    /// effect. The heir a refused or pruned ReRoot names was never root, so
    /// it restricts nothing, however its own branch folds; a restriction the
    /// fold dropped counts only when every ReRoot in its ancestry `settled`.
    /// One marked pass over the index finds the unsettled ReRoots and root
    /// appointments below each restriction (row [ROSTER-KEY-LOG-FLOOD], PR 3).
    pub(super) fn forget_unsettled(
        &mut self,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &AncestorIndex,
    ) {
        let below_unsettled = ancestors.marks(|row| {
            // A root appointment hands the vault over as a handoff does: one
            // this install does not count proves nothing beneath it.
            !settled.contains_key(row)
                && entries.get(row).is_some_and(|entry| {
                    matches!(
                        entry.op,
                        AuthorityOp::ReRoot { .. } | AuthorityOp::RootAppointment(_)
                    )
                })
        });
        self.by_hash.retain(|hash, _| {
            settled.contains_key(hash)
                || (ancestors.get(hash).is_some() && !below_unsettled.in_ancestry(hash))
        });
    }
}

/// The signed-branch proofs of one fold's restrictions under one context
/// (row [REVOKE-PROOF-BRANCH-REFOLD-CUBIC]). A row's normal-round verdict
/// reads only its own row, its parents' states and the context
/// ([`fold_normal_rounds`]), so it is the same in every branch that holds
/// the row. The proofs share those verdicts: each row folds once a fold, not
/// once for each restriction above it. A branch whose normal rounds stall
/// with only rejected permissive rows refused is proved on its own
/// ([`verify_signed_branch`]), since its rescue crosses rows by the
/// branch's own pending set.
struct SignedBranches<'a> {
    entries: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &'a AncestorIndex,
    /// The context [`verify_signed_branch`] would prove each branch under.
    context: FoldContext<'a>,
    /// Every row of the branches proved so far, with its whole ancestry.
    folded: BTreeSet<AuthorityEntryHash>,
    /// The normal-round state of each row of `folded` that folds.
    states: BTreeMap<AuthorityEntryHash, FoldState>,
    /// The rows of `folded` a normal round refuses.
    refused: BTreeSet<AuthorityEntryHash>,
}

impl<'a> SignedBranches<'a> {
    fn new(
        entries: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &'a AncestorIndex,
        context: FoldContext<'a>,
    ) -> Self {
        Self {
            entries,
            ancestors,
            context,
            folded: BTreeSet::new(),
            states: BTreeMap::new(),
            refused: BTreeSet::new(),
        }
    }

    /// `target`'s state as [`verify_signed_branch`] proves it under this
    /// context.
    fn verify(&mut self, target: AuthorityEntryHash) -> Option<FoldState> {
        let branch = signed_branch(target, self.entries, self.ancestors)?;
        // A row folded before came with its whole ancestry, so no row
        // folded now is a parent of it: only the new rows wake each other.
        let unfolded: BTreeSet<_> = branch.difference(&self.folded).copied().collect();
        let children = children_within(&unfolded, self.entries);
        self.folded.extend(unfolded.iter().copied());
        let context = FoldContext {
            entry_ancestors: Some(self.ancestors),
            ..self.context
        };
        fold_normal_rounds(
            unfolded,
            &children,
            self.entries,
            &mut self.states,
            &mut self.refused,
            context,
        );
        if let Some(state) = self.states.get(&target) {
            return Some(state.clone());
        }
        // The branch's own proof ends here too: on a refused row it may not
        // cross, or with no refused row its rescue could cross.
        let mut refused = self
            .refused
            .iter()
            .filter(|hash| branch.contains(*hash))
            .peekable();
        if refused.peek().is_none()
            || refused.any(|hash| {
                *hash == target
                    || !super::ancestry_evaluator::skippable_permissive(&self.entries[hash].op)
            })
        {
            return None;
        }
        verify_signed_branch(target, self.entries, self.ancestors, self.context)
    }
}

/// `target` with its whole ancestry, when every row of it is at hand and
/// none is its own ancestor.
fn signed_branch(
    target: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &AncestorIndex,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    let mut branch = ancestors.get(&target)?.to_set();
    branch.insert(target);
    for hash in &branch {
        if !entries.contains_key(hash) || ancestors.get(hash)?.contains(hash) {
            return None;
        }
    }
    Some(branch)
}

/// Each row of `rows` that is a parent of rows of `rows`, with those rows.
fn children_within(
    rows: &BTreeSet<AuthorityEntryHash>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> {
    let mut children = BTreeMap::<AuthorityEntryHash, Vec<AuthorityEntryHash>>::new();
    for hash in rows {
        for parent in &entries[hash].parent_hashes {
            if rows.contains(parent) {
                children.entry(*parent).or_default().push(*hash);
            }
        }
    }
    children
}

/// Folds in normal rounds each row of `woken` its parents' states let fold,
/// and each row of `children` a landing parent wakes, and records every row
/// a round refuses in `refused`. A transition waits only on a parent with no
/// state, and its verdict reads only its own row, its parents' states and
/// the context (`fold_entry_state`), so a row that waits is tried again only
/// when one of its parents lands. That gives the verdicts of passes over
/// every pending row until none moves, with each row tried about once per
/// parent, not once per pass (row [REVOKE-PROOF-BRANCH-REFOLD-CUBIC]; the
/// ordinary fold's scheduler does the same, H72).
fn fold_normal_rounds(
    mut woken: BTreeSet<AuthorityEntryHash>,
    children: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    refused: &mut BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) {
    while let Some(hash) = woken.pop_first() {
        if states.contains_key(&hash) || refused.contains(&hash) {
            continue;
        }
        note_proof_try();
        match super::ancestry_evaluator::evaluate_entry(
            &entries[&hash],
            hash,
            entries,
            states,
            context,
            super::ancestry_evaluator::EvaluationPhase::Normal,
        ) {
            EntryFold::Ready(state) => {
                states.insert(hash, state);
                woken.extend(children.get(&hash).into_iter().flatten().copied());
            }
            EntryFold::Invalid(_) => {
                refused.insert(hash);
            }
            EntryFold::Waiting => {}
        }
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
    let mut pending = signed_branch(target, entries, ancestors)?;
    let branch_context = FoldContext {
        entry_ancestors: Some(ancestors),
        ..context
    };
    let children = children_within(&pending, entries);
    let mut states = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    let mut woken = pending.clone();
    loop {
        fold_normal_rounds(
            woken,
            &children,
            entries,
            &mut states,
            &mut rejected,
            branch_context,
        );
        if let Some(state) = states.remove(&target) {
            return Some(state);
        }
        // Only a rejected permissive row other than the target may be
        // crossed; any other refused row refuses the proof.
        if rejected.iter().any(|hash| {
            *hash == target || !super::ancestry_evaluator::skippable_permissive(&entries[hash].op)
        }) {
            return None;
        }
        pending.retain(|hash| !states.contains_key(hash) && !rejected.contains(hash));
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
        woken = BTreeSet::new();
        for hash in pending.clone() {
            if !restrictive_withdrawal(&entries[&hash].op) {
                continue;
            }
            note_proof_try();
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
                woken.extend(children.get(&hash).into_iter().flatten().copied());
                rescued = true;
            }
        }
        if !rescued {
            return None;
        }
    }
}

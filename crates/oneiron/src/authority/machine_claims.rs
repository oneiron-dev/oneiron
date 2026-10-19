//! The fold's machine key claims, indexed once per view: P1's poison per
//! admitter (a key two machines claim, a machine that named two keys, a key or
//! row that is authority), judged on the merged history, and the public view
//! of each machine's chains built from them.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::machine_profile::{
    KeyClaim, act_stands, in_host_custody, key_is_authority, machine_is_actor, merge_machine,
};
use super::*;

/// Which claims one chain's poison is judged against.
#[derive(Clone, Copy)]
enum ClaimScope<'a> {
    /// Every roster revision: admission under the roster.
    Roster,
    /// The roster revisions a key P1 accepts signed, and the admitted owner
    /// answers: the trusted roster chain.
    Accepted,
    /// One anchor's revisions.
    Anchor(&'a [u8; 32]),
}

/// The fold's key claims, indexed once for the public view.
pub(super) struct ClaimIndex<'s> {
    state: &'s FoldState,
    by_machine: BTreeMap<EntityId, Vec<(&'s [u8; 32], &'s KeyClaim)>>,
    custodial: std::cell::RefCell<BTreeMap<AuthorityKey, bool>>,
}

impl<'s> ClaimIndex<'s> {
    pub(super) fn new(state: &'s FoldState) -> Self {
        let mut by_machine: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (key, claims) in &state.machine_keys {
            for claim in claims {
                by_machine
                    .entry(claim.machine)
                    .or_default()
                    .push((key, claim));
            }
        }
        Self {
            state,
            by_machine,
            custodial: std::cell::RefCell::default(),
        }
    }

    /// A roster key the owner held as it signed, and that custody on the
    /// merged history has not reached since.
    fn accepted(&self, signer: &AuthorityKey) -> bool {
        let state = self.state;
        !*self
            .custodial
            .borrow_mut()
            .entry(signer.clone())
            .or_insert_with(|| state.hosted && in_host_custody(state, signer))
    }

    /// An approved head that still stands: an owner-held roster signer
    /// custody has not reached, or an admitted owner answer whose carrier
    /// has not lost the removal race since (mesh PR1b). Custody never
    /// reaches an answer, and an answer never makes its key owner-held.
    fn approved_stands(&self, head: &MachineRevision) -> bool {
        match &head.act {
            Some(proof) => act_stands(self.state, proof, &head.entry),
            None => self.accepted(&head.signer),
        }
    }

    fn in_scope(&self, claim: &KeyClaim, scope: ClaimScope<'_>) -> bool {
        match scope {
            ClaimScope::Roster => claim.admitter == MachineAdmitter::Roster,
            ClaimScope::Accepted => {
                claim.admitter == MachineAdmitter::Roster
                    && (claim.act_carrier.is_some()
                        || claim
                            .owner_held
                            .as_ref()
                            .is_some_and(|signer| self.accepted(signer)))
            }
            ClaimScope::Anchor(key) => claim.admitter == MachineAdmitter::Anchor(*key),
        }
    }

    /// The roster revisions a key P1 accepts signed, and the admitted owner
    /// answers, judged on the merged history: the approved head while it
    /// stands ([`Self::approved_stands`]), removed once any accepted signer
    /// or carrier removed the machine. A custodian's removal never counts,
    /// and an accepted one outlives a head whose signer custody reached
    /// since (Sol code-R1 S1-F5). It never falls back to an older owned
    /// revision.
    fn accepted_roster(&self, chain: &MachineChain) -> Option<MachineRevision> {
        let removal = chain
            .owner_held_removals
            .iter()
            .filter(|(signer, _)| self.accepted(signer))
            .map(|(_, removal)| removal.clone())
            .reduce(|left, right| merge_machine(&left, &right));
        match chain
            .owner_held
            .clone()
            .filter(|held| self.approved_stands(held))
        {
            Some(held) => Some(MachineRevision {
                removed: removal.is_some(),
                ..held
            }),
            None => removal,
        }
    }

    /// P1's poison within one scope: the machine named another key there,
    /// another machine claims its key there, or its key or row is authority.
    fn poisoned(&self, id: EntityId, key: &[u8; 32], scope: ClaimScope<'_>) -> bool {
        let rekeyed = self.by_machine.get(&id).is_some_and(|claims| {
            claims
                .iter()
                .any(|(claimed, claim)| *claimed != key && self.in_scope(claim, scope))
        });
        let shared = self.state.machine_keys.get(key).is_some_and(|claims| {
            claims
                .iter()
                .any(|claim| claim.machine != id && self.in_scope(claim, scope))
        });
        rekeyed || shared || key_is_authority(self.state, key) || machine_is_actor(self.state, id)
    }

    /// The trust scopes in which another machine claims `key`.
    fn shared_scopes(&self, id: EntityId, key: &[u8; 32]) -> BTreeSet<MachineAdmitter> {
        self.state
            .machine_keys
            .get(key)
            .into_iter()
            .flatten()
            .filter(|claim| claim.machine != id)
            .filter_map(|claim| match claim.admitter {
                MachineAdmitter::Roster => self
                    .in_scope(claim, ClaimScope::Accepted)
                    .then_some(MachineAdmitter::Roster),
                anchor @ MachineAdmitter::Anchor(_) => Some(anchor),
            })
            .collect()
    }

    /// One machine's public standing, with the derived poison applied per
    /// chain. Custody is judged on the merged history, so a mark signed before
    /// its signer's custody reached that branch counts no more than one
    /// signed after. `hold` says which chain heads this install holds (none
    /// in the roster view). Every reader of a machine's standing goes through
    /// this.
    pub(super) fn folded(
        &self,
        id: EntityId,
        chains: &BTreeMap<MachineAdmitter, MachineChain>,
        roster_unsettled: bool,
        hold: Hold<'_>,
    ) -> FoldedMachine {
        let state = self.state;
        let roster = chains.get(&MachineAdmitter::Roster);
        let roster_head = roster.map(|chain| {
            let mut head = chain.head.clone();
            head.floor_held = hold(MachineAdmitter::Roster, chain, &head.entry);
            if state.hosted && in_host_custody(state, &head.signer) {
                head.signer_class = SignerClass::Custodial;
            }
            // An answer whose carrier lost the removal race since stands on
            // nothing here, and supersedes nothing (FIX 2998, mesh contract
            // §4, FIX 4610).
            if head.act.is_some() && !self.approved_stands(&head) {
                head.act = None;
                head.say_so = None;
            }
            head.conflicted |= self.poisoned(id, &head.profile.machine_key, ClaimScope::Roster);
            head.admitter_unsettled = roster_unsettled;
            head
        });
        let roster_trusted =
            roster
                .and_then(|chain| self.accepted_roster(chain))
                .map(|mut held| {
                    held.conflicted |=
                        self.poisoned(id, &held.profile.machine_key, ClaimScope::Accepted);
                    held.admitter_unsettled = roster_unsettled;
                    held.floor_held = roster
                        .is_some_and(|chain| hold(MachineAdmitter::Roster, chain, &held.entry));
                    held
                });
        let anchored: BTreeMap<_, _> = chains
            .iter()
            .filter_map(|(admitter, chain)| match admitter {
                MachineAdmitter::Anchor(key) => {
                    let mut head = chain.head.clone();
                    head.floor_held = hold(*admitter, chain, &head.entry);
                    head.conflicted |=
                        self.poisoned(id, &head.profile.machine_key, ClaimScope::Anchor(key));
                    Some((*key, head))
                }
                MachineAdmitter::Roster => None,
            })
            .collect();
        let shared = roster_trusted
            .iter()
            .chain(anchored.values())
            .map(|chain| chain.profile.machine_key)
            .map(|key| (key, self.shared_scopes(id, &key)))
            .filter(|(_, scopes)| !scopes.is_empty())
            .collect();
        FoldedMachine {
            roster: roster_head,
            roster_trusted,
            anchored,
            shared,
        }
    }
}

/// Which chain heads this install holds: the chain's admitter, the chain, and
/// the head's entry.
pub(super) type Hold<'a> = &'a dyn Fn(MachineAdmitter, &MachineChain, &AuthorityEntryHash) -> bool;

/// The roster view: no chain held.
pub(super) fn no_hold(_: MachineAdmitter, _: &MachineChain, _: &AuthorityEntryHash) -> bool {
    false
}

/// This install's floors: a head that landed past its signer's sequence
/// floor holds its chain (Astra #1430).
pub(super) fn floor_hold(
    _: MachineAdmitter,
    chain: &MachineChain,
    head: &AuthorityEntryHash,
) -> bool {
    chain
        .revisions
        .get(head)
        .is_some_and(|revision| revision.past_floor)
}

/// The fold's public view: each machine with the derived poison applied per
/// chain, as this install's floors hold it, and no roster standing while the
/// roster has no settled root.
pub(super) fn folded_machines(
    state: &FoldState,
    roster_unsettled: bool,
) -> BTreeMap<EntityId, FoldedMachine> {
    let index = ClaimIndex::new(state);
    state
        .machines
        .iter()
        .map(|(id, chains)| {
            (
                *id,
                index.folded(*id, chains, roster_unsettled, &floor_hold),
            )
        })
        .collect()
}

/// One machine's chains in `state`, with the derived poison applied, in the
/// roster view: what a world-key record's signer and recipients are judged
/// on in the record's parent state.
pub(super) fn folded_machine_in(state: &FoldState, id: EntityId) -> Option<FoldedMachine> {
    let chains = state.machines.get(&id)?;
    Some(ClaimIndex::new(state).folded(id, chains, false, &no_hold))
}

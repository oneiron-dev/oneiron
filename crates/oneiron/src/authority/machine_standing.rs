//! A machine's standing as the owner-act fold reads it: each chain's
//! revisions, the carrier rule and its removal race per chain, and the one
//! seam every world-privacy and grant travel site judges a carrier through
//! (mesh contract §3, FIX 2998).
//!
//! Validity is pin-free: an owner act is judged on the roster view of its
//! carrier's chains, the same on every install, before and after the owner
//! anchor ([`StandingView::Under`]). The settings this install reads are
//! judged with this install's floors, holds and staleness
//! ([`StandingView::Install`]), which only narrow. A chain held here admits
//! nothing and acknowledges nothing, but its restriction still lands (the
//! Engine's held-chain ruling on the P2 port). A chain stale here is not live
//! either, and never vetoes.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_claims::{ClaimIndex, floor_hold, no_hold};
use super::*;

/// One revision of a machine in one admitter's chain, as its entry carried it.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Revision {
    profile: MachineProfile,
    signer: AuthorityKey,
    owner_held: bool,
    /// The "yours" revision this one replaced, if the head it replaced said
    /// "yours".
    replaced_mark: Option<AuthorityEntryHash>,
    /// The chain's revisions in this one's own past.
    past: Arc<BTreeSet<AuthorityEntryHash>>,
    /// It landed past this replica's sequence floor as restriction only: it
    /// acknowledges no edit here, and as the head it holds its chain here
    /// (Astra #1430).
    pub(super) past_floor: bool,
}

impl Revision {
    /// One entry applied over two different pasts (a removal's proof beside
    /// the ordinary fold) keeps what both copies grant: it takes "yours"
    /// away with acknowledgement only when both would, from the same mark,
    /// and exempts only the past both saw. The meet is order-free.
    fn meet(left: &Arc<Self>, right: &Arc<Self>) -> Arc<Self> {
        if Arc::ptr_eq(left, right) || left == right {
            return Arc::clone(left);
        }
        Arc::new(Self {
            profile: left.profile.clone(),
            signer: left.signer.clone(),
            owner_held: left.owner_held
                && right.owner_held
                && left.replaced_mark == right.replaced_mark,
            replaced_mark: left.replaced_mark.min(right.replaced_mark),
            past: Arc::new(left.past.intersection(&right.past).copied().collect()),
            past_floor: left.past_floor || right.past_floor,
        })
    }
}

/// `chain`'s revisions with `head`, the revision it now folds, added.
pub(super) fn with_revision(
    chain: Option<&MachineChain>,
    head: &MachineRevision,
    owner_held: bool,
    restriction_only: bool,
) -> BTreeMap<AuthorityEntryHash, Arc<Revision>> {
    let mut revisions = chain
        .map(|chain| chain.revisions.clone())
        .unwrap_or_default();
    let past = Arc::new(revisions.keys().copied().collect());
    revisions.insert(
        head.entry,
        Arc::new(Revision {
            profile: head.profile.clone(),
            signer: head.signer.clone(),
            owner_held,
            replaced_mark: chain
                .map(|chain| &chain.head)
                .filter(|replaced| replaced.profile.says_mine())
                .map(|replaced| replaced.entry),
            past,
            past_floor: restriction_only,
        }),
    );
    revisions
}

/// Both chains' revisions; two copies of one revision meet.
pub(super) fn merge_revisions(
    left: &BTreeMap<AuthorityEntryHash, Arc<Revision>>,
    right: &BTreeMap<AuthorityEntryHash, Arc<Revision>>,
) -> BTreeMap<AuthorityEntryHash, Arc<Revision>> {
    let mut revisions = left.clone();
    for (hash, revision) in right {
        revisions
            .entry(*hash)
            .and_modify(|held| *held = Revision::meet(held, revision))
            .or_insert_with(|| Arc::clone(revision));
    }
    revisions
}

/// The revisions that landed restriction only on this install, in every chain.
pub(super) fn held_revisions(state: &FoldState, out: &mut BTreeSet<AuthorityEntryHash>) {
    for chain in state.machines.values().flat_map(BTreeMap::values) {
        out.extend(
            chain
                .revisions
                .iter()
                .filter(|(_, revision)| revision.past_floor)
                .map(|(hash, _)| *hash),
        );
    }
}

/// The live head of a chain an owner act was signed under, and that chain's
/// revisions in the head's own past: what the act followed. Not every
/// revision the act's parents carry: an act naming a concurrent removal
/// never exempts it (Wonder P2 round 5, W1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Mark {
    pub(super) entry: AuthorityEntryHash,
    pub(super) prior: Arc<BTreeSet<AuthorityEntryHash>>,
}

/// Whose trust a machine is judged under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum StandingView {
    /// `T(X)`, pin-free and install-free: validity, and `read_X`, which is
    /// diagnostics and holder execution, never who may edit.
    Under(MachineAdmitter),
    /// `T(pin)` with this install's floors and counting: the settings this
    /// install reads, and the machines it counts.
    Install,
}

/// Why this install does not count one admitter's chains of a machine, if
/// it does not: its own projections, which the structural fold never sees.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct InstallHold {
    /// The fold with no vouch does not count it: held, as a head past its
    /// floor is. It admits and acknowledges nothing, and its keys still
    /// count against the other chains'.
    pub(super) held: bool,
    /// Stale here, or its roster has no settled root: not live, and never a
    /// veto (Sol code-R3 S3-F3).
    pub(super) stale: bool,
}

/// How this install counts one machine's chains under one admitter. P2's
/// `MachineStanding` hook, per chain: an owner act carried while its machine
/// was not counted here only narrows.
pub(super) type InstallCounted<'a> = &'a dyn Fn(EntityId, MachineAdmitter) -> InstallHold;

/// Every chain counts.
pub(super) fn every_chain(_: EntityId, _: MachineAdmitter) -> InstallHold {
    InstallHold::default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Roster,
    Install,
}

/// Each machine's view, built on first use.
type Views = BTreeMap<(EntityId, Kind), Option<Rc<FoldedMachine>>>;

/// One state's machines, as the owner-act fold judges them. Built once per
/// entry applied and per world meet; each machine's view is built on first use.
pub(super) struct Standing<'s> {
    state: &'s FoldState,
    claims: ClaimIndex<'s>,
    local: MachineAdmitter,
    counted: InstallCounted<'s>,
    views: RefCell<Views>,
}

impl<'s> Standing<'s> {
    /// `pin` counts only while `state` holds its root: the pinned anchor
    /// signed that id there.
    pub(super) fn new(
        state: &'s FoldState,
        pin: Option<&PinnedRoot>,
        counted: InstallCounted<'s>,
    ) -> Self {
        let local = pin
            .filter(|pin| {
                state
                    .root_anchors
                    .get(&pin.anchor_key)
                    .is_some_and(|ids| ids.contains(&pin.id))
            })
            .map_or(MachineAdmitter::Roster, |pin| {
                MachineAdmitter::Anchor(pin.anchor_key)
            });
        Self {
            state,
            claims: ClaimIndex::new(state),
            local,
            counted,
            views: RefCell::default(),
        }
    }

    pub(super) fn state(&self) -> &'s FoldState {
        self.state
    }

    fn view(&self, id: EntityId, kind: Kind) -> Option<Rc<FoldedMachine>> {
        if let Some(view) = self.views.borrow().get(&(id, kind)) {
            return view.clone();
        }
        let view = self.state.machines.get(&id).map(|chains| {
            Rc::new(match kind {
                Kind::Roster => self.claims.folded(id, chains, false, &no_hold),
                Kind::Install => {
                    let mut folded =
                        self.claims
                            .folded(id, chains, false, &|admitter, chain, head| {
                                floor_hold(admitter, chain, head)
                                    || (self.counted)(id, admitter).held
                            });
                    for admitter in chains.keys() {
                        if (self.counted)(id, *admitter).stale {
                            folded.go_stale(admitter);
                        }
                    }
                    folded
                }
            })
        });
        self.views.borrow_mut().insert((id, kind), view.clone());
        view
    }

    fn admitter_kind(&self, view: StandingView) -> (MachineAdmitter, Kind) {
        match view {
            StandingView::Under(admitter) => (admitter, Kind::Roster),
            StandingView::Install => (self.local, Kind::Install),
        }
    }

    /// The machine key of `id`'s trusted identity under `view`.
    pub(super) fn trusted_key(&self, id: EntityId, view: StandingView) -> Option<[u8; 32]> {
        let (admitter, kind) = self.admitter_kind(view);
        self.view(id, kind)?
            .trusted_under(&admitter)
            .map(|trusted| trusted.profile.machine_key)
    }

    /// The machine key `id` is counted under here as a recipient: mine under
    /// `T(pin)` with this install's floors and counting (a world key
    /// record's signer and readers).
    pub(super) fn counted_key(&self, id: EntityId) -> Option<[u8; 32]> {
        self.trusted_key(id, StandingView::Install)
    }

    /// Some chain admits `id`. Pin-free: it authorizes nothing.
    pub(super) fn is_admitted(&self, id: EntityId) -> bool {
        self.view(id, Kind::Roster)
            .is_some_and(|folded| folded.is_admitted())
    }

    /// The chains whose live head names `id` under `signer`, in any role,
    /// each with its mark: an owner act's signing chains (a world edit, a
    /// grant travel choice; FIX 2998, mesh contract §3).
    pub(super) fn live_signing_chains(
        &self,
        id: EntityId,
        signer: &AuthorityKey,
    ) -> BTreeMap<MachineAdmitter, Mark> {
        let Some(folded) = self.view(id, Kind::Roster) else {
            return BTreeMap::new();
        };
        folded
            .chains()
            .filter(|(_, chain)| {
                chain.is_live() && *signer == AuthorityKey::Ed25519(chain.profile.machine_key)
            })
            .map(|(admitter, chain)| {
                let prior = self
                    .state
                    .machines
                    .get(&id)
                    .and_then(|chains| chains.get(&admitter))
                    .and_then(|state| state.revisions.get(&chain.entry))
                    .map(|revision| Arc::clone(&revision.past))
                    .unwrap_or_default();
                (
                    admitter,
                    Mark {
                        entry: chain.entry,
                        prior,
                    },
                )
            })
            .collect()
    }

    /// The admitter this install trusts here: its pinned anchor while the
    /// state holds the pinned root, else the roster.
    pub(super) fn local(&self) -> MachineAdmitter {
        self.local
    }

    /// Some chain of `id` names `key`, live or not: an owner act's carrier
    /// signed with that machine's install key at all (FIX 2998).
    pub(super) fn names_key(&self, id: EntityId, key: &[u8; 32]) -> bool {
        self.view(id, Kind::Roster)
            .is_some_and(|folded| folded.names_key(key))
    }

    /// [`super::owner_act_signer_admits`] for `id` and `key` under `view`:
    /// pin-free in the roster view, with this install's holds and staleness
    /// in the install view.
    pub(super) fn admits_owner_act_signer(
        &self,
        id: EntityId,
        key: &[u8; 32],
        view: StandingView,
    ) -> bool {
        let (_, kind) = self.admitter_kind(view);
        super::owner_act_signer_admits(self.view(id, kind).as_deref(), &self.state.roster, key)
    }

    /// The removal race for an owner act under `view` (FIX 2998, mesh
    /// contract §4), a world edit and a grant travel choice alike. It passes
    /// while the act's carrier is still admitted there under the key that
    /// signed it. Otherwise each chain that admitted it at the act's parents
    /// (`marks`) and no longer does is a reason, and there must be one: its
    /// head must be neither conflicted, held, stale nor unsettled, and every
    /// revision of the chain outside its mark's past that no longer names
    /// the key live (a removal, a new key) must have seen the act and,
    /// judged as this install reads it, landed in full. A chain that
    /// admitted the machine and is gone now never lifts. So a removal the
    /// owner signed after the act keeps it; an act a machine carried after
    /// it was removed, which no removal saw, only narrows. A role change
    /// between linked roles takes nothing away, and the remover's custody
    /// does not matter: a custodial install may carry an act itself.
    pub(super) fn owner_act_race(
        &self,
        id: EntityId,
        choice: &AuthorityEntryHash,
        key: &[u8; 32],
        marks: &BTreeMap<MachineAdmitter, Mark>,
        view: StandingView,
    ) -> bool {
        if self.admits_owner_act_signer(id, key, view) {
            return true;
        }
        let (_, kind) = self.admitter_kind(view);
        let Some(folded) = self.view(id, kind) else {
            return false;
        };
        let mut reasons = false;
        for (admitter, mark) in marks {
            let Some(head) = folded.chain(admitter) else {
                return false;
            };
            if head.is_live() && head.profile.machine_key == *key {
                continue;
            }
            reasons = true;
            let saw = self
                .state
                .machines
                .get(&id)
                .and_then(|chains| chains.get(admitter))
                .is_some_and(|chain| {
                    let mut takers = chain
                        .revisions
                        .iter()
                        .filter(|(hash, revision)| {
                            !mark.prior.contains(*hash)
                                && (revision.profile.role == MachineRole::Removed
                                    || revision.profile.machine_key != *key)
                        })
                        .peekable();
                    takers.peek().is_some()
                        && takers.all(|(_, revision)| {
                            (kind == Kind::Roster || !revision.past_floor)
                                && revision.profile.seen_world_edits.contains(choice)
                        })
                });
            let lifts = !head.conflicted
                && !head.floor_held
                && !head.stale
                && !head.admitter_unsettled
                && saw;
            if !lifts {
                return false;
            }
        }
        reasons
    }
}

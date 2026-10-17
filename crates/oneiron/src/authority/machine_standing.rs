//! A machine's standing as the world-privacy fold reads it: each chain's
//! revisions, P2's race rule per chain, and the one seam every world-privacy
//! site judges a machine through (world privacy P6b, contract §4).
//!
//! Validity is pin-free: a world edit is judged under `T(X)` for the admitter
//! X of each chain that signed it ([`StandingView::Under`]). The settings this
//! install reads are judged under `T(pin)` with this install's floors, holds
//! and staleness ([`StandingView::Install`]). A chain held here admits nothing
//! and acknowledges nothing, but its restriction still lands, and its keys
//! count against the other chains' (the Engine's held-chain ruling on the P2
//! port). A chain stale here is not live either, and never vetoes.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_claims::{ClaimIndex, floor_hold, no_hold};
use super::machine_profile::in_host_custody;
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

/// The "yours" head of a chain an edit was signed under, and that chain's
/// revisions in the head's own past: what the edit followed. Not every
/// revision the edit's parents carry: an edit naming a concurrent demotion
/// never exempts it (Wonder P2 round 5, W1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Mark {
    pub(super) entry: AuthorityEntryHash,
    pub(super) prior: Arc<BTreeSet<AuthorityEntryHash>>,
}

/// Whether `edit`, by a machine that `chain` no longer admits, keeps its
/// effect through that chain. The mark it was signed under in this chain, if
/// any, must still stand in this history: its signer in no host's custody,
/// and no divergent revision of its number. Every revision of the chain
/// outside the mark's own past that leaves the machine not the owner's must
/// have been signed by a key the owner holds, have landed in full rather than
/// as restriction only past a sequence floor, have seen the edit, and, when it
/// took a "yours" revision away, have taken one that still stands; and there
/// must be one. Judged `floor_free` (the roster view), a revision that landed
/// restriction only counts as the replica with no floor reads it. A revision
/// that saw nothing, a host's removal, or a mark found later not to stand
/// narrows the edit; a "yours" text or the order in which branches meet
/// changes nothing (Sol P2 rounds 7-8, Engine ruling E8).
fn acknowledged(
    state: &FoldState,
    chain: &MachineChain,
    edit: &AuthorityEntryHash,
    mark: Option<&Mark>,
    floor_free: bool,
) -> bool {
    let custodial = |key: &AuthorityKey| state.hosted && in_host_custody(state, key);
    let stands = |mark: &AuthorityEntryHash| {
        chain.revisions.get(mark).is_some_and(|marked| {
            !custodial(&marked.signer)
                && !chain.revisions.values().any(|other| {
                    other.profile.revision == marked.profile.revision
                        && other.profile != marked.profile
                })
        })
    };
    let empty = BTreeSet::new();
    let prior = mark.map_or(&empty, |mark| &*mark.prior);
    let mut takers = chain
        .revisions
        .iter()
        .filter(|(hash, revision)| !prior.contains(*hash) && !revision.profile.says_mine())
        .peekable();
    mark.is_none_or(|mark| stands(&mark.entry))
        && takers.peek().is_some()
        && takers.all(|(_, revision)| {
            (floor_free || !revision.past_floor)
                && revision.owner_held
                && !custodial(&revision.signer)
                && revision.profile.seen_world_edits.contains(edit)
                && revision.replaced_mark.as_ref().is_none_or(&stands)
        })
}

/// Whose trust a machine is judged under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum StandingView {
    /// `T(X)`, pin-free and install-free: validity, `read_X`, who may edit.
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
/// `MachineStanding` hook, per chain: a world edit signed while its machine
/// was not counted here only narrows.
pub(super) type InstallCounted<'a> = &'a dyn Fn(EntityId, MachineAdmitter) -> InstallHold;

/// Every chain counts.
pub(super) fn every_chain(_: EntityId, _: MachineAdmitter) -> InstallHold {
    InstallHold::default()
}

/// Whether an edit's machine was mine under `T(X)`, with the edit's key, at
/// its parents: strength's condition (a) for every admitter at once.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct TrustedAt {
    roster: bool,
    /// The anchors whose trust set judged the machine otherwise than the
    /// roster's; every other anchor judged it as the roster did.
    anchors: BTreeMap<[u8; 32], bool>,
}

impl TrustedAt {
    pub(super) fn under(&self, admitter: &MachineAdmitter) -> bool {
        match admitter {
            MachineAdmitter::Roster => self.roster,
            MachineAdmitter::Anchor(key) => self.anchors.get(key).copied().unwrap_or(self.roster),
        }
    }

    /// What both copies of one edit grant.
    pub(super) fn meet(&self, other: &Self) -> Self {
        let anchors = self
            .anchors
            .keys()
            .chain(other.anchors.keys())
            .map(|key| {
                let admitter = MachineAdmitter::Anchor(*key);
                (*key, self.under(&admitter) && other.under(&admitter))
            })
            .collect();
        Self {
            roster: self.roster && other.roster,
            anchors,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Roster,
    Install,
}

/// Each machine's view, built on first use.
type Views = BTreeMap<(EntityId, Kind), Option<Rc<FoldedMachine>>>;

/// One state's machines, as the world-privacy fold judges them. Built once per
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

    pub(super) fn is_mine(&self, id: EntityId, view: StandingView) -> bool {
        self.trusted_key(id, view).is_some()
    }

    /// The machine key `id` is counted under here: mine under `T(pin)` with
    /// this install's floors and counting. An edit it signs with another key,
    /// or none, only narrows here.
    pub(super) fn counted_key(&self, id: EntityId) -> Option<[u8; 32]> {
        self.trusted_key(id, StandingView::Install)
    }

    /// Some chain admits `id`. Pin-free: it authorizes nothing.
    pub(super) fn is_admitted(&self, id: EntityId) -> bool {
        self.view(id, Kind::Roster)
            .is_some_and(|folded| folded.is_admitted())
    }

    /// The chains whose live "yours" head admits `id` under `signer`, each
    /// with its mark: an edit's signing chains.
    pub(super) fn signing_chains(
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
                chain.says_yours() && *signer == AuthorityKey::Ed25519(chain.profile.machine_key)
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

    /// Whether `id` is mine with `key` under each admitter's trust set here.
    pub(super) fn trusted_at(&self, id: EntityId, key: &[u8; 32]) -> TrustedAt {
        let Some(folded) = self.view(id, Kind::Roster) else {
            return TrustedAt {
                roster: false,
                anchors: BTreeMap::new(),
            };
        };
        let mine = |admitter: &MachineAdmitter| {
            folded
                .trusted_under(admitter)
                .is_some_and(|trusted| &trusted.profile.machine_key == key)
        };
        TrustedAt {
            roster: mine(&MachineAdmitter::Roster),
            anchors: folded
                .judged_anchors()
                .into_iter()
                .map(|anchor| (anchor, mine(&MachineAdmitter::Anchor(anchor))))
                .collect(),
        }
    }

    /// The admitter this install trusts here: its pinned anchor while the
    /// state holds the pinned root, else the roster.
    pub(super) fn local(&self) -> MachineAdmitter {
        self.local
    }

    /// P2's race rule under `view`, per chain of its trust set. The edit passes
    /// while its machine is mine there now. Otherwise every chain of the trust
    /// set that no longer admits it, having admitted it at the edit's parents
    /// (`marks`) or blocking it now, is a reason, and there must be one. Each
    /// reason must be a removal or a demotion at its head, signed for the
    /// edit's key, not conflicted, held or stale, that acknowledged the edit.
    /// In the install view a chain this install holds, past a floor or for
    /// the fold with no vouch, is held (the Engine's held-chain ruling), and
    /// one stale here is stale: neither is live, so neither lifts.
    /// Poison and keys that disagree across the set never acknowledge, nor
    /// does a chain that admitted the machine and is gone now. A chain outside
    /// the set never lifts an edit.
    pub(super) fn race(
        &self,
        id: EntityId,
        edit: &AuthorityEntryHash,
        key: &[u8; 32],
        marks: &BTreeMap<MachineAdmitter, Mark>,
        view: StandingView,
    ) -> bool {
        let (admitter, kind) = self.admitter_kind(view);
        let Some(folded) = self.view(id, kind) else {
            return false;
        };
        if folded.trusted_under(&admitter).is_some() {
            return true;
        }
        let chains = folded.trust_chains(&admitter);
        let in_set = |of: &MachineAdmitter| *of == MachineAdmitter::Roster || *of == admitter;
        if folded.keys_unsettled(&admitter, &chains)
            || marks
                .keys()
                .filter(|of| in_set(of))
                .any(|of| chains.iter().all(|(chain, _)| chain != of))
        {
            return false;
        }
        let mut reasons = false;
        for (chain_admitter, head) in chains {
            // A chain that still admits the machine is no reason it is not
            // mine, and lifts nothing on its own.
            if head.says_yours() {
                continue;
            }
            let mark = marks.get(&chain_admitter);
            reasons = true;
            let lifts = &head.profile.machine_key == key
                && !head.conflicted
                && !head.floor_held
                && !head.stale
                && !head.admitter_unsettled
                && !head.profile.says_mine()
                && (!head.removed || head.profile.role == MachineRole::Removed)
                && self
                    .state
                    .machines
                    .get(&id)
                    .and_then(|chains| chains.get(&chain_admitter))
                    .is_some_and(|chain| {
                        acknowledged(self.state, chain, edit, mark, kind == Kind::Roster)
                    });
            if !lifts {
                return false;
            }
        }
        reasons
    }
}

//! Whether one held revision is valid on its own lineage, and the board's
//! resolutions at one node (decisions 5, 6); `branch.rs` folds a fork.
use super::branch::{Exclusion, Fork};
use super::fold::{ProjectEffective, ProjectRank, authority_fits, rank_at, reason};
use super::read::{Holder, ProjectReader, ProjectVerdict};
use super::resolution::{ProjectResolution, ProjectSeal};
use super::revision::{
    HeldRevisions, ProjectRevision, ProjectRevisionHash, ProjectRevisionProof, RevisionOrigin,
    anchor_of, authenticate, signed_depth,
};
use super::*;
use crate::federation::ScopeId;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

/// Deepest nesting of envelopes (a resolution's `prior`, a seal's
/// `supersedes`) and revisions the fold follows from one entry.
const MAX_FOLD_DEPTH: usize = 4 * MAX_PROJECT_ANCHORS;

#[cfg(test)]
thread_local! {
    /// How many resolution envelopes this thread verified, once per reader:
    /// a frozen re-check verifies only the ones its saved view rests on.
    pub(super) static ENVELOPES_VERIFIED: Cell<u64> = const { Cell::new(0) };
    /// How many verdicts this thread's folds asked for, memoized or not: the
    /// visit count of the parent-cycle linear-cost check.
    pub(super) static FOLD_VISITS: Cell<u64> = const { Cell::new(0) };
}

/// The settlement one resolution gives at its node.
#[derive(Clone, Default)]
pub(super) struct Settlement {
    /// The resolution; `None` when nothing settles the node.
    pub(super) tip: Option<ProjectRevisionHash>,
    /// The resolution and its prior closure.
    pub(super) closure: BTreeSet<ProjectRevisionHash>,
    pub(super) superseded: BTreeSet<ProjectRevisionHash>,
}

/// How a fold reads the parent projects a signed state must fit under.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Parents {
    /// Each parent project's frontier, through the reader.
    Read,
    /// None: a state is judged on its own lineage, and a frontier's parent
    /// bounds are its caller's (`joint.rs` judges them for a component).
    Skip,
}

/// One project's fold over one held set, memoizing each revision's verdict.
pub(super) struct FoldCx<'r, 'a, 't> {
    pub(super) reader: &'r ProjectReader<'a, 't>,
    pub(super) id: EntityId,
    pub(super) held: &'r HeldRevisions,
    pub(super) parents: Parents,
    /// A component's served views of its members, which a parent read takes
    /// before the reader's (a frozen member's re-check in `joint/serve.rs`).
    served: Option<Rc<BTreeMap<EntityId, Option<ProjectEffective>>>>,
    /// Conduit successors hung under their nearest standing ancestor, by
    /// that ancestor: a world of `joint.rs`.
    rehomed: BTreeMap<ProjectRevisionHash, Vec<ProjectRevisionHash>>,
    verdicts: RefCell<BTreeMap<ProjectRevisionHash, ProjectVerdict>>,
    signers: RefCell<BTreeMap<ProjectRevisionHash, String>>,
    /// Per tree root: its exclusions, and each node's fork.
    pub(super) exclusions: RefCell<BTreeMap<ProjectRevisionHash, Rc<Exclusion>>>,
    pub(super) forks: RefCell<BTreeMap<(ProjectRevisionHash, ProjectRevisionHash), Rc<Fork>>>,
    depth: Cell<usize>,
    /// Calls of `verdict`: a component charges them to its work budget.
    visits: Cell<u64>,
    /// How often the depth guard refused. A verdict that consumed a refusal
    /// depends on where the walk entered the chain, so it is not memoized.
    refusals: Cell<u64>,
}

impl<'r, 'a, 't> FoldCx<'r, 'a, 't> {
    pub(super) fn new(
        reader: &'r ProjectReader<'a, 't>,
        id: EntityId,
        held: &'r HeldRevisions,
    ) -> Self {
        Self {
            reader,
            id,
            held,
            parents: Parents::Read,
            served: None,
            rehomed: BTreeMap::new(),
            verdicts: RefCell::new(BTreeMap::new()),
            signers: RefCell::new(BTreeMap::new()),
            exclusions: RefCell::new(BTreeMap::new()),
            forks: RefCell::new(BTreeMap::new()),
            depth: Cell::new(0),
            visits: Cell::new(0),
            refusals: Cell::new(0),
        }
    }

    /// A fold that reads a component member's view as `served` gives it.
    pub(super) fn under(
        reader: &'r ProjectReader<'a, 't>,
        id: EntityId,
        held: &'r HeldRevisions,
        served: Rc<BTreeMap<EntityId, Option<ProjectEffective>>>,
    ) -> Self {
        Self {
            served: Some(served),
            ..Self::new(reader, id, held)
        }
    }

    /// A fold that judges each state on its own lineage only.
    pub(super) fn intrinsic(
        reader: &'r ProjectReader<'a, 't>,
        id: EntityId,
        held: &'r HeldRevisions,
    ) -> Self {
        Self {
            parents: Parents::Skip,
            ..Self::new(reader, id, held)
        }
    }

    /// A fold whose signed states already carry their verdicts and signers
    /// (a component's decision, or one world of it); envelopes are judged
    /// from them.
    pub(super) fn seeded(
        reader: &'r ProjectReader<'a, 't>,
        id: EntityId,
        held: &'r HeldRevisions,
        verdicts: BTreeMap<ProjectRevisionHash, ProjectVerdict>,
        signers: BTreeMap<ProjectRevisionHash, String>,
        rehomed: BTreeMap<ProjectRevisionHash, Vec<ProjectRevisionHash>>,
    ) -> Self {
        Self {
            parents: Parents::Skip,
            rehomed,
            verdicts: RefCell::new(verdicts),
            signers: RefCell::new(signers),
            ..Self::new(reader, id, held)
        }
    }

    /// The verdicts and signers judged so far.
    pub(super) fn judged(
        &self,
    ) -> (
        BTreeMap<ProjectRevisionHash, ProjectVerdict>,
        BTreeMap<ProjectRevisionHash, String>,
    ) {
        (
            self.verdicts.borrow().clone(),
            self.signers.borrow().clone(),
        )
    }

    pub(super) fn row(&self, hash: &ProjectRevisionHash) -> Option<&'r ProjectRevision> {
        self.held.get(hash).map(|row| &row.revision)
    }

    /// The origin a held row has now: its indexed one once authenticated,
    /// else checked here against this snapshot's mints.
    pub(super) fn origin(&self, hash: ProjectRevisionHash) -> Result<RevisionOrigin> {
        match self.held.get(&hash) {
            Some(row) if row.origin == RevisionOrigin::Authenticated => {
                Ok(RevisionOrigin::Authenticated)
            }
            Some(_) => Ok(authenticate(self.held, &*self.reader.authority()?, hash)),
            None => Ok(RevisionOrigin::AwaitingParent),
        }
    }

    /// Whether `hash` is valid on its own lineage at this snapshot.
    pub(super) fn verdict(&self, hash: ProjectRevisionHash) -> Result<ProjectVerdict> {
        #[cfg(test)]
        FOLD_VISITS.with(|count| count.set(count.get() + 1));
        self.visits.set(self.visits.get() + 1);
        if let Some(known) = self.verdicts.borrow().get(&hash) {
            return Ok(*known);
        }
        if self.depth.get() > MAX_FOLD_DEPTH {
            self.refusals.set(self.refusals.get() + 1);
            return Ok(ProjectVerdict::Quarantined(reason::TOO_DEEP));
        }
        let refusals = self.refusals.get();
        self.depth.set(self.depth.get() + 1);
        let verdict = self.judge(hash);
        self.depth.set(self.depth.get() - 1);
        let verdict = verdict?;
        if self.refusals.get() == refusals {
            self.verdicts.borrow_mut().insert(hash, verdict);
        }
        Ok(verdict)
    }

    /// The verified signer of a valid signed revision or resolution.
    pub(super) fn visits(&self) -> u64 {
        self.visits.get()
    }

    pub(super) fn signer(&self, hash: &ProjectRevisionHash) -> Option<String> {
        self.signers.borrow().get(hash).cloned()
    }

    fn judge(&self, hash: ProjectRevisionHash) -> Result<ProjectVerdict> {
        let Some(row) = self.row(&hash) else {
            return Ok(ProjectVerdict::Pending(reason::NOT_HELD));
        };
        match self.origin(hash)? {
            RevisionOrigin::Authenticated => {}
            RevisionOrigin::AwaitingParent => {
                return Ok(ProjectVerdict::Pending(reason::AWAITING_PARENT));
            }
            RevisionOrigin::AwaitingMint => {
                return Ok(ProjectVerdict::Pending(reason::AWAITING_MINT));
            }
            RevisionOrigin::Forged => return Ok(ProjectVerdict::Quarantined(reason::FORGED)),
        }
        match row {
            ProjectRevision::Boundary { authority, .. } => Ok(self.boundary(authority)),
            ProjectRevision::Signed {
                authority,
                proof,
                parent,
                ..
            } => self.signed(hash, authority, proof, *parent),
            ProjectRevision::Resolution { resolution, .. } => self.resolution(hash, resolution),
            ProjectRevision::Seal { seal, .. } => self.seal(hash, seal),
        }
    }

    /// Main's unsigned rule, without the stripped-proof marker: that marker
    /// concerns the stored row, which no longer overrides signed history.
    fn boundary(&self, authority: &ProjectAuthority) -> ProjectVerdict {
        if !well_formed(self.id, authority) {
            ProjectVerdict::Quarantined(reason::MALFORMED)
        } else if authority.roster.is_some() {
            ProjectVerdict::Quarantined(reason::BOUNDARY_ROSTER)
        } else if Some(self.id) == self.reader.root() || !authority.parents.is_empty() {
            ProjectVerdict::Visible
        } else {
            ProjectVerdict::Quarantined(reason::PARENTLESS)
        }
    }

    fn signed(
        &self,
        hash: ProjectRevisionHash,
        authority: &ProjectAuthority,
        proof: &ProjectRevisionProof,
        parent: Option<ProjectRevisionHash>,
    ) -> Result<ProjectVerdict> {
        if !well_formed(self.id, authority) {
            return Ok(ProjectVerdict::Quarantined(reason::MALFORMED));
        }
        if authority.parents.is_empty() && Some(self.id) != self.reader.root() {
            return Ok(ProjectVerdict::Quarantined(reason::PARENTLESS));
        }
        let anchor = match parent {
            None => None,
            Some(parent) => {
                let prior = self.verdict(parent)?;
                if prior != ProjectVerdict::Visible {
                    return Ok(prior);
                }
                // A valid parent's lineage is held, so only length fails
                // here: no row could carry this revision's witness.
                if signed_depth(self.held, hash).is_none() {
                    return Ok(ProjectVerdict::Quarantined(reason::TOO_DEEP));
                }
                match anchor_of(self.held, parent) {
                    Some(anchor) => Some(anchor),
                    None => return Ok(ProjectVerdict::Pending(reason::AWAITING_PARENT)),
                }
            }
        };
        let write_proof = ProjectWriteProof {
            slip_wire: proof.slip_wire.clone(),
            holder_signature: proof.holder_signature.clone(),
            signed_at: proof.signed_at,
            anchor: anchor.map(Box::new),
            version: proof.version,
        };
        let holder = match self
            .reader
            .verify_revision(self.id, hash, authority, &write_proof)?
        {
            Ok(holder) => holder,
            Err(verdict) => return Ok(verdict),
        };
        self.signers.borrow_mut().insert(hash, holder.actor.clone());
        let host = holder.actor == "host";
        let verdict = match parent {
            None => self.birth(authority, &holder, host)?,
            Some(parent) => {
                let Some(prior_row) = self.row(&parent) else {
                    return Ok(ProjectVerdict::Pending(reason::AWAITING_PARENT));
                };
                let Some(prior) = prior_row.authority() else {
                    return Ok(ProjectVerdict::Quarantined(reason::NOT_A_STATE));
                };
                let unsigned = matches!(prior_row, ProjectRevision::Boundary { .. });
                if unsigned && Some(self.id) != self.reader.root() && !host {
                    ProjectVerdict::Quarantined(reason::OVER_UNSIGNED)
                } else if !holder.audience.contains(&ScopeId(self.id)) {
                    ProjectVerdict::Quarantined(reason::AUDIENCE)
                } else if prior.board_action(authority) {
                    if prior.board.contains(&holder.actor) || host {
                        ProjectVerdict::Visible
                    } else {
                        ProjectVerdict::Quarantined(reason::WIDENING)
                    }
                } else if prior.leader == holder.actor
                    || prior.board.contains(&holder.actor)
                    || host
                {
                    ProjectVerdict::Visible
                } else {
                    ProjectVerdict::Quarantined(reason::NOT_LEADER)
                }
            }
        };
        if verdict != ProjectVerdict::Visible || self.parents == Parents::Skip {
            return Ok(verdict);
        }
        for (parent, spawned_under) in read_parents(authority, parent.is_none(), host)? {
            let served = (self.served.as_ref()).and_then(|served| served.get(&parent));
            let view = match served {
                Some(view) => view
                    .clone()
                    .ok_or(ProjectVerdict::Quarantined(reason::PARENT_HIDDEN)),
                None => parent_view(self.reader, parent)?,
            };
            let effective = match view {
                Ok(effective) => effective,
                Err(verdict) => return Ok(verdict),
            };
            if let Some(why) = refusal(&effective, authority, &holder.actor, spawned_under, host) {
                return Ok(ProjectVerdict::Quarantined(why));
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// A spawn's own part of main's rule: an attenuated slip whose audience
    /// holds the parent. Its parent's leader is the parent's to judge.
    fn birth(
        &self,
        authority: &ProjectAuthority,
        holder: &Holder,
        host: bool,
    ) -> Result<ProjectVerdict> {
        let Some(parent) = authority.parents.first() else {
            return Ok(if host && Some(self.id) == self.reader.root() {
                ProjectVerdict::Visible
            } else {
                ProjectVerdict::Quarantined(reason::PARENTLESS)
            });
        };
        let parent_id = EntityId::from_hex(parent)
            .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
        Ok(
            if holder.attenuated && holder.audience.contains(&ScopeId(parent_id)) {
                ProjectVerdict::Visible
            } else {
                ProjectVerdict::Quarantined(reason::SPAWN)
            },
        )
    }

    fn resolution(
        &self,
        hash: ProjectRevisionHash,
        resolution: &ProjectResolution,
    ) -> Result<ProjectVerdict> {
        let anchor = self.verdict(resolution.anchor)?;
        if anchor != ProjectVerdict::Visible {
            return Ok(anchor);
        }
        let Some(anchor_authority) = self
            .row(&resolution.anchor)
            .and_then(ProjectRevision::authority)
        else {
            return Ok(ProjectVerdict::Quarantined(reason::NOT_A_STATE));
        };
        for named in resolution.contenders.iter().chain([&resolution.next]) {
            match self.row(named) {
                None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
                Some(row) if row.parent() != Some(resolution.anchor) => {
                    return Ok(ProjectVerdict::Quarantined(reason::RESOLUTION_STRANGER));
                }
                Some(_) => {}
            }
        }
        let Some(next_authority) = self
            .row(&resolution.next)
            .and_then(ProjectRevision::authority)
        else {
            return Ok(ProjectVerdict::Quarantined(reason::NOT_A_STATE));
        };
        let holder = match self.reader.verify_held_envelope(self.id, hash, || {
            #[cfg(test)]
            ENVELOPES_VERIFIED.with(|count| count.set(count.get() + 1));
            self.reader.verify_envelope(
                self.id,
                &resolution.slip_wire,
                &resolution.challenge(self.id)?,
                &resolution.holder_signature,
                resolution.signed_at,
                &next_authority.slice,
            )
        })? {
            Ok(holder) => holder,
            Err(verdict) => return Ok(verdict),
        };
        self.signers.borrow_mut().insert(hash, holder.actor.clone());
        if !(holder.actor == "host" || anchor_authority.board.contains(&holder.actor)) {
            return Ok(ProjectVerdict::Quarantined(reason::RESOLUTION_SIGNER));
        }
        if !holder.audience.contains(&ScopeId(self.id)) {
            return Ok(ProjectVerdict::Quarantined(reason::AUDIENCE));
        }
        match self.verdict(resolution.next)? {
            ProjectVerdict::Visible => {}
            pending @ ProjectVerdict::Pending(_) => return Ok(pending),
            ProjectVerdict::Quarantined(_) => {
                return Ok(ProjectVerdict::Quarantined(reason::RESOLUTION_SUCCESSOR));
            }
        }
        let next_rank = self
            .signer(&resolution.next)
            .and_then(|signer| rank_at(anchor_authority, &signer));
        if next_rank != Some(ProjectRank::Board) {
            return Ok(ProjectVerdict::Quarantined(reason::RESOLUTION_SUCCESSOR));
        }
        self.judge_priors_first(resolution)?;
        for prior in &resolution.prior {
            match self.row(prior) {
                None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
                Some(ProjectRevision::Resolution {
                    resolution: earlier,
                    ..
                }) if earlier.anchor == resolution.anchor => {}
                Some(_) => return Ok(ProjectVerdict::Quarantined(reason::PRIOR_INVALID)),
            }
            match self.verdict(*prior)? {
                ProjectVerdict::Visible => {}
                pending @ ProjectVerdict::Pending(_) => return Ok(pending),
                ProjectVerdict::Quarantined(_) => {
                    return Ok(ProjectVerdict::Quarantined(reason::PRIOR_INVALID));
                }
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    fn seal(&self, hash: ProjectRevisionHash, seal: &ProjectSeal) -> Result<ProjectVerdict> {
        let Some(next) = self.row(&seal.next) else {
            return Ok(ProjectVerdict::Pending(reason::NOT_HELD));
        };
        let ProjectRevision::Signed {
            authority, proof, ..
        } = next
        else {
            return Ok(ProjectVerdict::Quarantined(reason::SEAL_NEXT));
        };
        if proof.slip_wire != seal.slip_wire {
            return Ok(ProjectVerdict::Quarantined(reason::SEAL_SLIP));
        }
        let holder = match self.reader.verify_held_envelope(self.id, hash, || {
            self.reader.verify_envelope(
                self.id,
                &seal.slip_wire,
                &seal.challenge(self.id)?,
                &seal.holder_signature,
                seal.signed_at,
                &authority.slice,
            )
        })? {
            Ok(holder) => holder,
            Err(verdict) => return Ok(verdict),
        };
        if holder.actor != "host" {
            return Ok(ProjectVerdict::Quarantined(reason::SEAL_SIGNER));
        }
        match self.verdict(seal.next)? {
            ProjectVerdict::Visible => {}
            pending @ ProjectVerdict::Pending(_) => return Ok(pending),
            ProjectVerdict::Quarantined(_) => {
                return Ok(ProjectVerdict::Quarantined(reason::SEAL_NEXT));
            }
        }
        for earlier in &seal.supersedes {
            let earlier_at = match self.row(earlier) {
                None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
                Some(ProjectRevision::Seal { seal: earlier, .. }) => earlier.signed_at,
                Some(_) => return Ok(ProjectVerdict::Quarantined(reason::SEAL_SUPERSEDES)),
            };
            if seal.signed_at <= earlier_at {
                return Ok(ProjectVerdict::Quarantined(reason::SEAL_ORDER));
            }
            match self.verdict(*earlier)? {
                ProjectVerdict::Visible => {}
                pending @ ProjectVerdict::Pending(_) => return Ok(pending),
                ProjectVerdict::Quarantined(_) => {
                    return Ok(ProjectVerdict::Quarantined(reason::SEAL_SUPERSEDES));
                }
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// The valid signed children of `node`.
    pub(super) fn valid_children(
        &self,
        node: ProjectRevisionHash,
    ) -> Result<BTreeSet<ProjectRevisionHash>> {
        let mut valid = BTreeSet::new();
        let rehomed = self.rehomed.get(&node).into_iter().flatten();
        for child in self.held.children_of(&node).chain(rehomed) {
            if self.verdict(*child)? == ProjectVerdict::Visible {
                valid.insert(*child);
            }
        }
        Ok(valid)
    }

    /// Each valid resolution at `node`, as the settlement it gives if it
    /// stands: its prior closure, and every child that closure names but its
    /// own successor. `branch.rs` judges which one stands.
    pub(super) fn settlements(&self, node: ProjectRevisionHash) -> Result<Vec<Settlement>> {
        let valid = self.valid_resolutions_at(node)?;
        let settlement = |tip: ProjectRevisionHash, keep: ProjectRevisionHash| {
            let mut closure = BTreeSet::new();
            let mut todo = vec![tip];
            while let Some(at) = todo.pop() {
                if let Some(resolution) = valid.get(&at)
                    && closure.insert(at)
                {
                    todo.extend(resolution.prior.iter().copied());
                }
            }
            let superseded = closure
                .iter()
                .flat_map(|at| {
                    let resolution = valid[at];
                    resolution
                        .contenders
                        .iter()
                        .copied()
                        .chain([resolution.next])
                })
                .filter(|hash| *hash != keep)
                .collect();
            Settlement {
                tip: Some(tip),
                closure,
                superseded,
            }
        };
        Ok(valid
            .iter()
            .map(|(tip, resolution)| settlement(*tip, resolution.next))
            .collect())
    }

    /// The valid resolutions at `anchor` that no valid resolution there
    /// builds on, sorted: what a new resolution names as its `prior`.
    pub(super) fn resolution_tips(
        &self,
        anchor: ProjectRevisionHash,
    ) -> Result<Vec<ProjectRevisionHash>> {
        let valid = self.valid_resolutions_at(anchor)?;
        let named: BTreeSet<ProjectRevisionHash> = (valid.values())
            .flat_map(|resolution| resolution.prior.iter().copied())
            .collect();
        Ok(valid
            .keys()
            .filter(|hash| !named.contains(hash))
            .copied()
            .collect())
    }

    /// The valid resolutions at `node`.
    pub(super) fn valid_resolutions_at(
        &self,
        node: ProjectRevisionHash,
    ) -> Result<BTreeMap<ProjectRevisionHash, &'r ProjectResolution>> {
        let mut valid = BTreeMap::new();
        for hash in self.held.resolutions_at(&node) {
            if let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(hash)
                && self.verdict(*hash)? == ProjectVerdict::Visible
            {
                valid.insert(*hash, resolution);
            }
        }
        Ok(valid)
    }

    /// Judges the held prior closure of `resolution` at its anchor, each
    /// envelope after its own priors, so its judgement finds every prior
    /// memoized. A chain of any length never meets the depth guard, every
    /// door judges it alike, and only that closure is judged: a frozen
    /// re-check never judges envelopes held after the freeze (Sol #1434 r11
    /// F2, Astra r12 F1, Sol r12 F1).
    fn judge_priors_first(&self, resolution: &ProjectResolution) -> Result<()> {
        let mut entered = BTreeSet::new();
        let mut todo: Vec<(ProjectRevisionHash, bool)> = resolution
            .prior
            .iter()
            .map(|prior| (*prior, false))
            .collect();
        while let Some((hash, priors_judged)) = todo.pop() {
            if priors_judged {
                self.verdict(hash)?;
                continue;
            }
            if self.verdicts.borrow().contains_key(&hash) || !entered.insert(hash) {
                continue;
            }
            if let Some(ProjectRevision::Resolution {
                resolution: earlier,
                ..
            }) = self.row(&hash)
                && earlier.anchor == resolution.anchor
            {
                todo.push((hash, true));
                todo.extend(earlier.prior.iter().map(|prior| (*prior, false)));
            }
        }
        Ok(())
    }

    /// The valid seals no valid seal supersedes.
    pub(super) fn seal_tips(&self) -> Result<BTreeSet<ProjectRevisionHash>> {
        super::fold::seal_tips(self)
    }

    pub(super) fn authority_of(&self, hash: &ProjectRevisionHash) -> Option<&'r ProjectAuthority> {
        self.row(hash).and_then(ProjectRevision::authority)
    }
}

/// The parent projects a signed state's admission reads, each with whether
/// it is the one a birth was spawned under: none for an owner state but a
/// birth's first; every parent otherwise.
pub(super) fn read_parents(
    authority: &ProjectAuthority,
    birth: bool,
    host: bool,
) -> Result<Vec<(EntityId, bool)>> {
    let mut read = Vec::new();
    for (index, parent) in authority.parents.iter().enumerate() {
        let spawned_under = birth && index == 0;
        if host && !spawned_under {
            continue;
        }
        let parent = EntityId::from_hex(parent)
            .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
        read.push((parent, spawned_under));
    }
    Ok(read)
}

/// Why one parent's view refuses a state `signer` signed: a birth's parent
/// must be led by its spawner, and a non-host state never sees more than
/// any parent project does.
pub(super) fn refusal(
    view: &ProjectEffective,
    authority: &ProjectAuthority,
    signer: &str,
    spawned_under: bool,
    host: bool,
) -> Option<&'static str> {
    if spawned_under && view.leader != signer {
        Some(reason::SPAWN)
    } else if !host && !authority_fits(authority, view) {
        Some(reason::EXCEEDS_PARENT)
    } else {
        None
    }
}

/// A parent project's effective view, or the verdict its absence gives a child.
pub(super) fn parent_view(
    reader: &ProjectReader<'_, '_>,
    parent: EntityId,
) -> Result<std::result::Result<ProjectEffective, ProjectVerdict>> {
    Ok(match reader.frontier(parent)? {
        None => Err(ProjectVerdict::Pending(reason::PARENT_MISSING)),
        Some(frontier) => match frontier.effective {
            Some(effective) => Ok(effective),
            None => Err(match frontier.disposition.verdict() {
                ProjectVerdict::Pending(_) => ProjectVerdict::Pending(reason::PARENT_PENDING),
                _ => ProjectVerdict::Quarantined(reason::PARENT_HIDDEN),
            }),
        },
    })
}

/// The structural gates a stored PROJECT row passes at its door, for an
/// authority a companion carries, which no body validation saw (Wonder r6
/// F3): canonical references, no self or repeated parent, no repeated board
/// holder, depth within its limit, and a v3 roster that seats someone.
fn well_formed(id: EntityId, authority: &ProjectAuthority) -> bool {
    let canonical =
        |value: &String| EntityId::from_hex(value).is_ok_and(|parsed| parsed.to_hex() == *value);
    let unique = |list: &[String]| list.iter().collect::<BTreeSet<_>>().len() == list.len();
    authority.depth_remaining <= authority.depth_limit
        && authority.parents.len() <= 256
        && !authority.parents.contains(&id.to_hex())
        && unique(&authority.parents)
        && unique(&authority.board)
        && authority
            .roster
            .as_ref()
            .is_none_or(|roster| !roster.is_empty())
        && authority
            .parents
            .iter()
            .chain(&authority.board)
            .chain(authority.roster.iter().flatten())
            .chain([&authority.leader, &authority.claims_scope_ref])
            .all(canonical)
}

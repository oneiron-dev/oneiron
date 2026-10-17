//! Whether one held revision is valid on its own lineage, and the board's
//! resolutions at one node (decisions 5, 6); `branch.rs` folds a fork.
use super::branch::{Exclusion, Fork};
use super::fold::{ProjectEffective, ProjectRank, authority_fits, rank_at, reason};
use super::read::{Holder, ProjectReader, ProjectVerdict};
use super::resolution::{ProjectResolution, ProjectSeal};
use super::revision::{
    HeldRevisions, ProjectRevision, ProjectRevisionHash, ProjectRevisionProof, REVISIONS,
    RevisionOrigin, anchor_of, authenticate, signed_depth,
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

/// The owner's seals over one held set (ruling (c)). Retiring a seal is
/// apart from rooting at one: neither set asks whether a seal's target stands.
#[derive(Default)]
pub(super) struct SealStatus {
    /// Each held seal's envelope: signed by the owner, waiting, or of no effect.
    envelopes: BTreeMap<ProjectRevisionHash, ProjectVerdict>,
    /// The seals an authorized seal supersedes: never a root candidate.
    pub(super) retired: BTreeSet<ProjectRevisionHash>,
    /// The authorized seals none retires: one roots only where its target
    /// stands, and two or more conflict.
    pub(super) tips: BTreeSet<ProjectRevisionHash>,
}

impl SealStatus {
    /// One held seal's envelope verdict.
    pub(super) fn envelope(&self, hash: &ProjectRevisionHash) -> Option<ProjectVerdict> {
        self.envelopes.get(hash).copied()
    }
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
    /// Each resolution envelope's authorization at its anchor, apart from
    /// whether its successor stands in this fold (ruling (b)).
    envelopes: RefCell<BTreeMap<ProjectRevisionHash, ProjectVerdict>>,
    signers: RefCell<BTreeMap<ProjectRevisionHash, String>>,
    /// The owner's seals, judged once per fold.
    seals: RefCell<Option<Rc<SealStatus>>>,
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
            envelopes: RefCell::new(BTreeMap::new()),
            signers: RefCell::new(BTreeMap::new()),
            seals: RefCell::new(None),
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
        if self.sealed_off(hash, row)? {
            return Ok(ProjectVerdict::Quarantined(reason::SEALED_OFF));
        }
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

    /// Whether a fold reading parents finds `hash` outside the one owner
    /// seal's tree: no state there, as for the solver, so no parent of it is
    /// read and component discovery names none (Astra #1434c F2).
    fn sealed_off(&self, hash: ProjectRevisionHash, row: &ProjectRevision) -> Result<bool> {
        if self.parents != Parents::Read || row.authority().is_none() {
            return Ok(false);
        }
        let facts = self.reader.facts(self.id)?;
        let tree = facts.as_ref().and_then(|facts| facts.sealed.as_ref());
        Ok(tree.is_some_and(|tree| !tree.contains(&hash)))
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
        if verdict != ProjectVerdict::Visible {
            return Ok(verdict);
        }
        if let Some(verdict) = self.witnessed(authority)? {
            return Ok(verdict);
        }
        if self.parents == Parents::Skip {
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

    /// A re-parent's witnesses (ARCH-0079 stacking): every parent head a
    /// state witnesses must be authenticated history held here, led by the
    /// leader its witness seats on the board. A head not yet held, or held
    /// before its lineage or mint, waits, so the same signed re-parent
    /// resumes when it lands (ruling (d)). A witness is a fact of the
    /// parent's history, not its view: the parent's current view still
    /// bounds the state.
    fn witnessed(&self, authority: &ProjectAuthority) -> Result<Option<ProjectVerdict>> {
        for witness in &authority.parent_heads {
            match witnessed_leader(self.reader, witness.project, witness.head)? {
                Err(verdict) => return Ok(Some(verdict)),
                Ok(leader) if leader != witness.leader.to_hex() => {
                    return Ok(Some(ProjectVerdict::Quarantined(
                        reason::PARENT_HEAD_LEADER,
                    )));
                }
                Ok(_) => {}
            }
        }
        Ok(None)
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

    /// A resolution stands in this fold when its envelope is authorized at
    /// its anchor and its successor is a valid board child here.
    fn resolution(
        &self,
        hash: ProjectRevisionHash,
        resolution: &ProjectResolution,
    ) -> Result<ProjectVerdict> {
        let envelope = self.envelope(hash)?;
        if envelope != ProjectVerdict::Visible {
            return Ok(envelope);
        }
        let Some(anchor_authority) = self.authority_of(&resolution.anchor) else {
            return Ok(ProjectVerdict::Quarantined(reason::NOT_A_STATE));
        };
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
        Ok(ProjectVerdict::Visible)
    }

    /// Whether the resolution `hash` is an authorized envelope at its anchor
    /// (ruling (b)), judged with its held prior closure, each envelope after
    /// its own priors: a chain of any length never meets the depth guard,
    /// every door judges it alike, and only that closure is judged, so a
    /// frozen re-check never judges envelopes held after the freeze (Sol
    /// #1434 r11 F2, Astra r12 F1, Sol r12 F1).
    fn envelope(&self, hash: ProjectRevisionHash) -> Result<ProjectVerdict> {
        if let Some(known) = self.envelopes.borrow().get(&hash) {
            return Ok(*known);
        }
        let refusals = self.refusals.get();
        let mut judged: BTreeMap<ProjectRevisionHash, ProjectVerdict> = BTreeMap::new();
        let mut entered = BTreeSet::new();
        let mut todo = vec![(hash, false)];
        while let Some((at, priors_judged)) = todo.pop() {
            if priors_judged {
                let verdict = self.authorized(at, &judged)?;
                judged.insert(at, verdict);
                continue;
            }
            if self.envelopes.borrow().contains_key(&at) || !entered.insert(at) {
                continue;
            }
            todo.push((at, true));
            if let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(&at) {
                for prior in &resolution.prior {
                    if let Some(ProjectRevision::Resolution {
                        resolution: earlier,
                        ..
                    }) = self.row(prior)
                        && earlier.anchor == resolution.anchor
                    {
                        todo.push((*prior, false));
                    }
                }
            }
        }
        let verdict =
            (judged.get(&hash).copied()).unwrap_or(ProjectVerdict::Pending(reason::NOT_HELD));
        // One that met the depth guard depends on where the walk entered.
        if self.refusals.get() == refusals {
            self.envelopes.borrow_mut().extend(judged);
        }
        Ok(verdict)
    }

    /// One envelope's own authorization, its priors already judged: held and
    /// authenticated, naming children of a valid anchor, signed by a board
    /// holder of that anchor (or the host) within audience, over priors each
    /// so authorized at the same anchor. Whether its successor stands is the
    /// fold's question (`resolution`), not the envelope's.
    fn authorized(
        &self,
        hash: ProjectRevisionHash,
        judged: &BTreeMap<ProjectRevisionHash, ProjectVerdict>,
    ) -> Result<ProjectVerdict> {
        let resolution = match self.row(&hash) {
            None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
            Some(ProjectRevision::Resolution { resolution, .. }) => resolution,
            Some(_) => return Ok(ProjectVerdict::Quarantined(reason::PRIOR_INVALID)),
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
        let anchor = self.verdict(resolution.anchor)?;
        if anchor != ProjectVerdict::Visible {
            return Ok(anchor);
        }
        let Some(anchor_authority) = self.authority_of(&resolution.anchor) else {
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
        for prior in &resolution.prior {
            match self.row(prior) {
                None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
                Some(ProjectRevision::Resolution {
                    resolution: earlier,
                    ..
                }) if earlier.anchor == resolution.anchor => {}
                Some(_) => return Ok(ProjectVerdict::Quarantined(reason::PRIOR_INVALID)),
            }
            let known = (judged.get(prior).copied())
                .or_else(|| self.envelopes.borrow().get(prior).copied());
            match known {
                Some(ProjectVerdict::Visible) => {}
                Some(pending @ ProjectVerdict::Pending(_)) => return Ok(pending),
                Some(ProjectVerdict::Quarantined(_)) | None => {
                    return Ok(ProjectVerdict::Quarantined(reason::PRIOR_INVALID));
                }
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// A seal roots a fold when the owner signed it and its target is a
    /// valid owner state here; whether a later seal retires it is the seal
    /// status's question (ruling (c)).
    fn seal(&self, hash: ProjectRevisionHash, seal: &ProjectSeal) -> Result<ProjectVerdict> {
        match self.seal_status()?.envelope(&hash) {
            Some(ProjectVerdict::Visible) => {}
            Some(verdict) => return Ok(verdict),
            None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
        }
        Ok(match self.verdict(seal.next)? {
            ProjectVerdict::Visible => ProjectVerdict::Visible,
            pending @ ProjectVerdict::Pending(_) => pending,
            ProjectVerdict::Quarantined(_) => ProjectVerdict::Quarantined(reason::SEAL_NEXT),
        })
    }

    /// Whether the owner signed the seal `hash` (ruling (c)): held and
    /// authenticated, the host's slip signing it in scope with its target's
    /// slip, over held earlier seals strictly before it. No target's verdict
    /// is asked, its own or an earlier seal's: a forward supersession retires
    /// the seals it names whether or not their targets stand, and a missing
    /// one waits.
    fn seal_envelope(
        &self,
        hash: ProjectRevisionHash,
        seal: &ProjectSeal,
    ) -> Result<ProjectVerdict> {
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
        for earlier in &seal.supersedes {
            let earlier_at = match self.row(earlier) {
                None => return Ok(ProjectVerdict::Pending(reason::NOT_HELD)),
                Some(ProjectRevision::Seal { seal: earlier, .. }) => earlier.signed_at,
                Some(_) => return Ok(ProjectVerdict::Quarantined(reason::SEAL_SUPERSEDES)),
            };
            if seal.signed_at <= earlier_at {
                return Ok(ProjectVerdict::Quarantined(reason::SEAL_ORDER));
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// The owner's seals over this held set: the same in every world of a
    /// component, since no target's verdict enters it (ruling (c)).
    pub(super) fn seal_status(&self) -> Result<Rc<SealStatus>> {
        if let Some(known) = self.seals.borrow().as_ref() {
            return Ok(Rc::clone(known));
        }
        let mut status = SealStatus::default();
        for hash in &self.held.seals {
            let Some(ProjectRevision::Seal { seal, .. }) = self.row(hash) else {
                continue;
            };
            let verdict = self.seal_envelope(*hash, seal)?;
            if verdict == ProjectVerdict::Visible {
                status.retired.extend(seal.supersedes.iter().copied());
            }
            status.envelopes.insert(*hash, verdict);
        }
        status.tips = (status.envelopes.iter())
            .filter(|(hash, verdict)| {
                **verdict == ProjectVerdict::Visible && !status.retired.contains(*hash)
            })
            .map(|(hash, _)| *hash)
            .collect();
        let status = Rc::new(status);
        *self.seals.borrow_mut() = Some(Rc::clone(&status));
        Ok(status)
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

    /// The causal tips at `anchor` (ruling (b)), sorted: the authorized
    /// envelopes there that no authorized envelope there names as a prior,
    /// read before any cycle or deposition removes a competitor. Two or more
    /// are a race, which settles nothing; a new resolution names them all as
    /// its `prior`.
    pub(super) fn resolution_tips(
        &self,
        anchor: ProjectRevisionHash,
    ) -> Result<Vec<ProjectRevisionHash>> {
        let envelopes = self.resolution_envelopes_at(anchor)?;
        let named: BTreeSet<ProjectRevisionHash> = (envelopes.values())
            .flat_map(|resolution| resolution.prior.iter().copied())
            .collect();
        Ok(envelopes
            .keys()
            .filter(|hash| !named.contains(hash))
            .copied()
            .collect())
    }

    /// The authorized resolution envelopes at `anchor`, whatever their
    /// successors do in this fold: the causal graph a race is read from.
    pub(super) fn resolution_envelopes_at(
        &self,
        anchor: ProjectRevisionHash,
    ) -> Result<BTreeMap<ProjectRevisionHash, &'r ProjectResolution>> {
        let mut envelopes = BTreeMap::new();
        for hash in self.held.resolutions_at(&anchor) {
            if let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(hash)
                && self.envelope(*hash)? == ProjectVerdict::Visible
            {
                envelopes.insert(*hash, resolution);
            }
        }
        Ok(envelopes)
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

/// The leader of `parent`'s state `head` as authenticated history gives it
/// (ruling (d)): a held revision whose origin authenticates, or the boundary
/// of an unsigned parent's stored row, which no companion holds. Bytes that
/// merely arrived wait for their lineage and mint; a forged head never
/// witnesses. `Err` is the verdict the witnessing state takes meanwhile.
fn witnessed_leader(
    reader: &ProjectReader<'_, '_>,
    parent: EntityId,
    head: ProjectRevisionHash,
) -> Result<std::result::Result<String, ProjectVerdict>> {
    let waits = ProjectVerdict::Pending(reason::PARENT_HEAD_PENDING);
    let held = reader.held_of(parent)?;
    if let Some(row) = held.get(&head) {
        let origin = match row.origin {
            RevisionOrigin::Authenticated => RevisionOrigin::Authenticated,
            _ => authenticate(&held, &*reader.authority()?, head),
        };
        return Ok(match (origin, row.revision.authority()) {
            (RevisionOrigin::Authenticated, Some(authority)) => Ok(authority.leader.clone()),
            (RevisionOrigin::Authenticated, None) => {
                Err(ProjectVerdict::Quarantined(reason::NOT_A_STATE))
            }
            (RevisionOrigin::Forged, _) => Err(ProjectVerdict::Quarantined(reason::FORGED)),
            (RevisionOrigin::AwaitingParent | RevisionOrigin::AwaitingMint, _) => Err(waits),
        });
    }
    // A held set leaves out a row already found forged.
    let indexed = REVISIONS.get(reader.store(), reader.txn(), &(parent, head))?;
    if indexed.is_some_and(|(_, origin)| origin == RevisionOrigin::Forged) {
        return Ok(Err(ProjectVerdict::Quarantined(reason::FORGED)));
    }
    let Some(stored) = reader.stored_row(parent)? else {
        return Ok(Err(waits));
    };
    if stored.write_proof.is_some() {
        return Ok(Err(waits));
    }
    let boundary = revision::revisions_of(parent, &stored.anchor())?;
    Ok(boundary
        .last()
        .filter(|(hash, _)| *hash == head)
        .map(|_| stored.leader.clone())
        .ok_or(waits))
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
/// holder, depth within its limit, a v3 roster that seats someone, and parent
/// witnesses that each name one of its parents once and seat that parent's
/// leader on its board.
fn well_formed(id: EntityId, authority: &ProjectAuthority) -> bool {
    let canonical =
        |value: &String| EntityId::from_hex(value).is_ok_and(|parsed| parsed.to_hex() == *value);
    let unique = |list: &[String]| list.iter().collect::<BTreeSet<_>>().len() == list.len();
    witnesses_fit(authority)
        && authority.depth_remaining <= authority.depth_limit
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

/// Each parent witness names one of the state's parents, no parent twice,
/// and a leader the state seats on its board.
pub(super) fn witnesses_fit(authority: &ProjectAuthority) -> bool {
    let named: BTreeSet<EntityId> = (authority.parent_heads.iter())
        .map(|witness| witness.project)
        .collect();
    named.len() == authority.parent_heads.len()
        && authority.parent_heads.iter().all(|witness| {
            authority.parents.contains(&witness.project.to_hex())
                && authority.board.contains(&witness.leader.to_hex())
        })
}

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

/// The settlement one resolution gives at its node.
#[derive(Clone, Default)]
pub(super) struct Settlement {
    /// The resolution; `None` when nothing settles the node.
    pub(super) tip: Option<ProjectRevisionHash>,
    /// The resolution and its prior closure.
    pub(super) closure: BTreeSet<ProjectRevisionHash>,
    pub(super) superseded: BTreeSet<ProjectRevisionHash>,
}

/// One project's fold over one held set, memoizing each revision's verdict.
pub(super) struct FoldCx<'r, 'a, 't> {
    pub(super) reader: &'r ProjectReader<'a, 't>,
    pub(super) id: EntityId,
    pub(super) held: &'r HeldRevisions,
    verdicts: RefCell<BTreeMap<ProjectRevisionHash, ProjectVerdict>>,
    signers: RefCell<BTreeMap<ProjectRevisionHash, String>>,
    /// Per tree root: its exclusions, and each node's fork.
    pub(super) exclusions: RefCell<BTreeMap<ProjectRevisionHash, Rc<Exclusion>>>,
    pub(super) forks: RefCell<BTreeMap<(ProjectRevisionHash, ProjectRevisionHash), Rc<Fork>>>,
    depth: Cell<usize>,
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
            verdicts: RefCell::new(BTreeMap::new()),
            signers: RefCell::new(BTreeMap::new()),
            exclusions: RefCell::new(BTreeMap::new()),
            forks: RefCell::new(BTreeMap::new()),
            depth: Cell::new(0),
            refusals: Cell::new(0),
        }
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
            ProjectRevision::Seal { seal, .. } => self.seal(seal),
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
        let holder = match self.reader.verify(self.id, authority, &write_proof)? {
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
        if verdict != ProjectVerdict::Visible || host {
            return Ok(verdict);
        }
        // A non-host revision never sees more than any parent project does.
        for parent in &authority.parents {
            match self.parent_effective(parent)? {
                Ok(effective) if !authority_fits(authority, &effective) => {
                    return Ok(ProjectVerdict::Quarantined(reason::EXCEEDS_PARENT));
                }
                Ok(_) => {}
                Err(verdict) => return Ok(verdict),
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// A spawn keeps main's rule against the parent project's effective leader.
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
        Ok(match self.parent_effective(parent)? {
            Err(verdict) => verdict,
            Ok(effective)
                if effective.leader == holder.actor
                    && holder.attenuated
                    && holder.audience.contains(&ScopeId(parent_id)) =>
            {
                ProjectVerdict::Visible
            }
            Ok(_) => ProjectVerdict::Quarantined(reason::SPAWN),
        })
    }

    /// A parent project's effective view, or the verdict its absence gives.
    fn parent_effective(
        &self,
        parent: &str,
    ) -> Result<std::result::Result<ProjectEffective, ProjectVerdict>> {
        let parent = EntityId::from_hex(parent)
            .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
        parent_view(self.reader, parent)
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
        let holder = match self.reader.verify_envelope(
            self.id,
            &resolution.slip_wire,
            &resolution.challenge(self.id)?,
            &resolution.holder_signature,
            resolution.signed_at,
            &next_authority.slice,
        )? {
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

    fn seal(&self, seal: &ProjectSeal) -> Result<ProjectVerdict> {
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
        let holder = match self.reader.verify_envelope(
            self.id,
            &seal.slip_wire,
            &seal.challenge(self.id)?,
            &seal.holder_signature,
            seal.signed_at,
            &authority.slice,
        )? {
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
        for child in self.held.children_of(&node) {
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

    /// The valid resolutions at `node`. Each is judged after every prior it
    /// names there, as seals are, so a chain of any length never meets the
    /// depth guard and every pass over the node judges it alike (Sol #1434
    /// r11 F2).
    pub(super) fn valid_resolutions_at(
        &self,
        node: ProjectRevisionHash,
    ) -> Result<BTreeMap<ProjectRevisionHash, &'r ProjectResolution>> {
        let held: BTreeMap<ProjectRevisionHash, &'r ProjectResolution> = (self.held)
            .resolutions_at(&node)
            .filter_map(|hash| match self.row(hash) {
                Some(ProjectRevision::Resolution { resolution, .. }) => Some((*hash, resolution)),
                _ => None,
            })
            .collect();
        let mut judged = BTreeSet::new();
        let mut valid = BTreeMap::new();
        for start in held.keys() {
            let mut todo = vec![(*start, false)];
            while let Some((hash, priors_judged)) = todo.pop() {
                if judged.contains(&hash) {
                    continue;
                }
                if !priors_judged {
                    todo.push((hash, true));
                    todo.extend(
                        (held[&hash].prior.iter())
                            .filter(|prior| held.contains_key(*prior) && !judged.contains(*prior))
                            .map(|prior| (*prior, false)),
                    );
                    continue;
                }
                judged.insert(hash);
                if self.verdict(hash)? == ProjectVerdict::Visible {
                    valid.insert(hash, held[&hash]);
                }
            }
        }
        Ok(valid)
    }

    /// The valid seals no valid seal supersedes.
    pub(super) fn seal_tips(&self) -> Result<BTreeSet<ProjectRevisionHash>> {
        super::fold::seal_tips(self)
    }

    pub(super) fn authority_of(&self, hash: &ProjectRevisionHash) -> Option<&'r ProjectAuthority> {
        self.row(hash).and_then(ProjectRevision::authority)
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

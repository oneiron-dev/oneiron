//! Whether one held revision is valid on its own lineage, and how the walk
//! leaves one node: rank, the board's resolutions and ties (decisions 5, 6).
use super::fold::{ProjectEffective, ProjectRank, authority_fits, rank_at, reason};
use super::read::{Holder, ProjectReader, ProjectVerdict};
use super::resolution::{ProjectResolution, ProjectSeal};
use super::revision::{
    HeldRevisions, ProjectRevision, ProjectRevisionHash, ProjectRevisionProof, RevisionOrigin,
    anchor_of, authenticate,
};
use super::*;
use crate::federation::ScopeId;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

/// Deepest nesting of envelopes (a resolution's `prior`, a seal's
/// `supersedes`) and revisions the fold follows from one entry.
const MAX_FOLD_DEPTH: usize = 4 * MAX_PROJECT_ANCHORS;

/// How the walk leaves one node.
pub(super) enum Step {
    /// No valid child: the node is the head.
    Head,
    Advance {
        winner: ProjectRevisionHash,
        resolution: Option<ProjectRevisionHash>,
    },
    Tie {
        rank: ProjectRank,
        contenders: BTreeSet<ProjectRevisionHash>,
    },
}

/// The settlement of the valid resolutions at one node.
pub(super) struct Settlement {
    /// The single tip, when there is exactly one.
    pub(super) tip: Option<ProjectRevisionHash>,
    /// The tip and its prior closure.
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
    depth: Cell<usize>,
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
            depth: Cell::new(0),
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
            return Ok(ProjectVerdict::Quarantined(reason::TOO_DEEP));
        }
        self.depth.set(self.depth.get() + 1);
        let verdict = self.judge(hash);
        self.depth.set(self.depth.get() - 1);
        let verdict = verdict?;
        self.verdicts.borrow_mut().insert(hash, verdict);
        Ok(verdict)
    }

    /// The verified signer of a valid signed revision.
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
            ProjectRevision::Resolution { resolution, .. } => self.resolution(resolution),
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
        Ok(parent_view(self.reader, parent)?)
    }

    fn resolution(&self, resolution: &ProjectResolution) -> Result<ProjectVerdict> {
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

    /// The single resolution tip at `node` and what its prior closure settles.
    pub(super) fn settlement(&self, node: ProjectRevisionHash) -> Result<Settlement> {
        let mut valid = BTreeMap::new();
        for hash in self.held.resolutions_at(&node) {
            if let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(hash)
                && self.verdict(*hash)? == ProjectVerdict::Visible
            {
                valid.insert(*hash, resolution);
            }
        }
        let named: BTreeSet<ProjectRevisionHash> = valid
            .values()
            .flat_map(|resolution| resolution.prior.iter().copied())
            .collect();
        let tips: Vec<ProjectRevisionHash> = valid
            .keys()
            .filter(|hash| !named.contains(hash))
            .copied()
            .collect();
        let [tip] = tips[..] else {
            return Ok(Settlement {
                tip: None,
                closure: BTreeSet::new(),
                superseded: BTreeSet::new(),
            });
        };
        let mut closure = BTreeSet::new();
        let mut todo = vec![tip];
        while let Some(at) = todo.pop() {
            if let Some(resolution) = valid.get(&at)
                && closure.insert(at)
            {
                todo.extend(resolution.prior.iter().copied());
            }
        }
        let keep = valid[&tip].next;
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
        Ok(Settlement {
            tip: Some(tip),
            closure,
            superseded,
        })
    }

    /// How the walk leaves `node`, with its valid children and settlement.
    pub(super) fn step(
        &self,
        node: ProjectRevisionHash,
    ) -> Result<(Step, BTreeSet<ProjectRevisionHash>, Settlement)> {
        let valid = self.valid_children(node)?;
        let settlement = self.settlement(node)?;
        if valid.is_empty() {
            return Ok((Step::Head, valid, settlement));
        }
        let Some(node_authority) = self.row(&node).and_then(ProjectRevision::authority) else {
            return Ok((Step::Head, valid, settlement));
        };
        let candidates: BTreeSet<ProjectRevisionHash> =
            valid.difference(&settlement.superseded).copied().collect();
        let ranked: Vec<(ProjectRank, ProjectRevisionHash)> = candidates
            .iter()
            .filter_map(|child| {
                let signer = self.signer(child)?;
                Some((rank_at(node_authority, &signer)?, *child))
            })
            .collect();
        let Some(top) = ranked.iter().map(|(rank, _)| *rank).max() else {
            return Ok((Step::Head, valid, settlement));
        };
        let at_top: Vec<ProjectRevisionHash> = ranked
            .iter()
            .filter(|(rank, _)| *rank == top)
            .map(|(_, child)| *child)
            .collect();
        let step = if let [winner] = at_top[..] {
            Step::Advance {
                winner,
                resolution: settlement.tip.filter(|_| {
                    settlement
                        .superseded
                        .iter()
                        .any(|lost| valid.contains(lost))
                }),
            }
        } else {
            Step::Tie {
                rank: top,
                contenders: candidates,
            }
        };
        Ok((step, valid, settlement))
    }

    /// The valid resolutions at `anchor` that no valid resolution there
    /// builds on, sorted: what a new resolution names as its `prior`.
    pub(super) fn resolution_tips(
        &self,
        anchor: ProjectRevisionHash,
    ) -> Result<Vec<ProjectRevisionHash>> {
        let mut valid = BTreeSet::new();
        let mut named = BTreeSet::new();
        for hash in self.held.resolutions_at(&anchor) {
            if let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(hash)
                && self.verdict(*hash)? == ProjectVerdict::Visible
            {
                valid.insert(*hash);
                named.extend(resolution.prior.iter().copied());
            }
        }
        Ok(valid.difference(&named).copied().collect())
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

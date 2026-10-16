//! The fold over a project's held revisions (decisions 5-7). It is a set
//! fold: every replica that holds the same revisions and the same folded
//! authority view reaches the same frontier, whatever order they arrived in.
//! Rank decides between sibling branches (`branch.rs`), the board settles its
//! own ties with a signed resolution, the owner's seal re-roots the history,
//! and a tie that stays open seats only the members every frontier keeps.
use super::branch::{Fork, Step};
use super::fork_evidence::{ProjectForkEvidence, ProjectForkOutcome};
use super::history_policy::{
    ProjectDependencies, ProjectEvidenceSet, ProjectHistoryOverBudget, counted_set,
};
use super::read::{ProjectReader, ProjectVerdict};
use super::revision::{ProjectRevision, ProjectRevisionHash, RevisionOrigin, anchor_of};
use super::validity::{FoldCx, Parents, parent_view};
use super::*;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Why a revision or a project carries no authority. Kept as one list so a
/// persisted reason maps back to the same static text.
pub(super) mod reason {
    pub(crate) const NOT_HELD: &str = "project revision not yet received";
    pub(crate) const AWAITING_PARENT: &str = "earlier project revision not yet received";
    pub(crate) const AWAITING_MINT: &str = "authorizing slip not yet received";
    pub(crate) const FORGED: &str = "project revision signature does not verify";
    pub(crate) const BOUNDARY_ROSTER: &str = "an unsigned project state carries a roster";
    pub(crate) const MALFORMED: &str = "project revision authority is malformed";
    pub(crate) const PARENTLESS: &str = "a parentless project is not this vault's root";
    pub(crate) const OVER_UNSIGNED: &str = "only the owner may sign over an unsigned project";
    pub(crate) const AUDIENCE: &str = "project write outside slip audience";
    pub(crate) const WIDENING: &str = "project widening needs board holder proof";
    pub(crate) const NOT_LEADER: &str = "only the leader or board may change project authority";
    pub(crate) const SPAWN: &str = "project spawn needs parent leader slip";
    pub(crate) const PARENT_MISSING: &str = "parent project not yet received";
    pub(crate) const PARENT_PENDING: &str = "parent project pending";
    pub(crate) const PARENT_HIDDEN: &str = "parent project is quarantined";
    pub(crate) const EXCEEDS_PARENT: &str = "project slice exceeds parent";
    pub(crate) const CYCLE: &str = "project ancestry cycle";
    pub(crate) const TOO_DEEP: &str = "project history chain too deep";
    pub(crate) const NOT_A_STATE: &str = "project envelope names an envelope as a state";
    pub(crate) const RESOLUTION_SIGNER: &str = "a resolution needs a board holder of its anchor";
    pub(crate) const RESOLUTION_STRANGER: &str = "a resolution names a revision of another anchor";
    pub(crate) const RESOLUTION_SUCCESSOR: &str =
        "a resolution's successor is not a valid board child";
    pub(crate) const PRIOR_INVALID: &str = "a resolution builds on an invalid resolution";
    pub(crate) const SEAL_SIGNER: &str = "a seal needs the owner's host slip";
    pub(crate) const SEAL_SLIP: &str = "a seal and its revision differ in slip";
    pub(crate) const SEAL_ORDER: &str = "a seal must move forward in time";
    pub(crate) const SEAL_SUPERSEDES: &str = "a seal supersedes something that is not a seal";
    pub(crate) const SEAL_NEXT: &str = "a sealed revision is not a valid owner state";
    pub(crate) const NO_ROOT: &str = "no valid project birth";
    pub(crate) const NO_RECORD: &str = "project history over budget with no verified frontier";
    pub(crate) const STALE_RECORD: &str =
        "project history over budget and its frozen frontier no longer verifies";
    pub(crate) const UNRESOLVED: &str = "project authority unresolved";
    pub(crate) const CYCLE_BOUND: &str = "project parent cycle past its world bound";
    pub(crate) const SEALED_OFF: &str = "project revision lies outside the owner's seal";
    pub(crate) const PARENT_HEAD_PENDING: &str = "witnessed parent revision not yet received";
    pub(crate) const PARENT_HEAD_LEADER: &str = "a parent witness names another leader";

    const ALL: &[&str] = &[
        NOT_HELD,
        AWAITING_PARENT,
        AWAITING_MINT,
        FORGED,
        BOUNDARY_ROSTER,
        MALFORMED,
        PARENTLESS,
        OVER_UNSIGNED,
        AUDIENCE,
        WIDENING,
        NOT_LEADER,
        SPAWN,
        PARENT_MISSING,
        PARENT_PENDING,
        PARENT_HIDDEN,
        EXCEEDS_PARENT,
        CYCLE,
        TOO_DEEP,
        NOT_A_STATE,
        RESOLUTION_SIGNER,
        RESOLUTION_STRANGER,
        RESOLUTION_SUCCESSOR,
        PRIOR_INVALID,
        SEAL_SIGNER,
        SEAL_SLIP,
        SEAL_ORDER,
        SEAL_SUPERSEDES,
        SEAL_NEXT,
        NO_ROOT,
        NO_RECORD,
        STALE_RECORD,
        UNRESOLVED,
        CYCLE_BOUND,
        SEALED_OFF,
        PARENT_HEAD_PENDING,
        PARENT_HEAD_LEADER,
    ];

    /// The static text of a persisted reason; a reason this build does not
    /// know reads as unresolved.
    pub(crate) fn of(text: &str) -> &'static str {
        ALL.iter()
            .find(|known| **known == text)
            .copied()
            .unwrap_or(UNRESOLVED)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRank {
    /// The parent's leader, not on the parent's board.
    Leader,
    /// A board holder at the parent, or the host acting for the owner.
    Board,
}

/// The signer's highest role at `parent`, after the signature, slip, scope
/// and authorization checks; never a role the revision grants itself.
pub(crate) fn rank_at(parent: &ProjectAuthority, signer: &str) -> Option<ProjectRank> {
    if signer == "host" || parent.board.iter().any(|holder| holder == signer) {
        Some(ProjectRank::Board)
    } else if parent.leader == signer {
        Some(ProjectRank::Leader)
    } else {
        None
    }
}

/// What every permission consumer reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectEffective {
    pub leader: String,
    pub board: Vec<String>,
    pub parents: Vec<String>,
    pub claims_scope_ref: String,
    pub seats: BTreeSet<String>,
    /// `None`: the meet of contradicting slices; nothing fits under it.
    pub slice: Option<Scope>,
    pub depth_limit: u8,
    pub depth_remaining: u8,
    /// Main's `bound_by_parents` of the witness head: false for an owner
    /// state (unsigned, or host-signed), which the vault alone caps.
    pub bound_by_parents: bool,
}

impl ProjectEffective {
    pub(super) fn of(
        authority: &ProjectAuthority,
        seats: BTreeSet<String>,
        bound_by_parents: bool,
    ) -> Self {
        Self {
            leader: authority.leader.clone(),
            board: authority.board.clone(),
            parents: authority.parents.clone(),
            claims_scope_ref: authority.claims_scope_ref.clone(),
            seats,
            slice: Some(authority.slice.clone()),
            depth_limit: authority.depth_limit,
            depth_remaining: authority.depth_remaining,
            bound_by_parents,
        }
    }
    /// Main's `fits_under` over effective views; a `None` parent slice admits nothing.
    pub(crate) fn fits_under(&self, parent: &ProjectEffective) -> bool {
        let Some(parent_slice) = &parent.slice else {
            return false;
        };
        self.depth_limit <= parent.depth_limit
            && self.depth_remaining < parent.depth_remaining
            && self
                .slice
                .as_ref()
                .is_none_or(|slice| parent_slice.attenuate(slice.clone()).is_ok())
    }
    /// A state's own bounds: its members seated, its slice and depth.
    pub(super) fn bounds(authority: &ProjectAuthority) -> Self {
        let seats = members_of(authority)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Self::of(authority, seats, true)
    }
    /// Narrows this view by another state: seats it does not keep leave,
    /// the slices meet, and the depths take the minimum.
    pub(super) fn meet(&mut self, other: &ProjectAuthority) {
        self.meet_view(&Self::bounds(other));
    }
    /// Narrows this view by another view's seats, slice and depth.
    pub(super) fn meet_view(&mut self, other: &ProjectEffective) {
        self.seats.retain(|seat| other.seats.contains(seat));
        self.slice = match (&self.slice, &other.slice) {
            (Some(slice), Some(other)) => slice_meet(slice, other),
            _ => None,
        };
        self.depth_limit = self.depth_limit.min(other.depth_limit);
        self.depth_remaining = self.depth_remaining.min(other.depth_remaining);
    }
    /// Whether a member sits in the project's home room.
    pub fn seats(&self, actor: &str) -> bool {
        self.seats.contains(actor)
    }
    /// The seats as a list: in the stored row's order where it agrees, then
    /// the rest in id order.
    pub(crate) fn seat_list(&self, stored_order: Vec<String>) -> Vec<String> {
        let mut seats: Vec<String> = stored_order
            .into_iter()
            .filter(|seat| self.seats.contains(seat))
            .collect();
        for seat in &self.seats {
            if !seats.contains(seat) {
                seats.push(seat.clone());
            }
        }
        seats
    }
}

/// The members a state vouches for: its signed roster, else its leader and board.
pub(super) fn members_of(authority: &ProjectAuthority) -> BTreeSet<&str> {
    match &authority.roster {
        Some(roster) => roster.iter().map(String::as_str).collect(),
        None => std::iter::once(&authority.leader)
            .chain(&authority.board)
            .map(String::as_str)
            .collect(),
    }
}

/// Per axis: unconstrained meets constrained, equal values stay, two
/// different values meet to nothing; resource sets intersect.
fn slice_meet(a: &Scope, b: &Scope) -> Option<Scope> {
    fn axis(a: Option<EntityId>, b: Option<EntityId>) -> Option<Option<EntityId>> {
        match (a, b) {
            (Some(a), Some(b)) if a != b => None,
            (a, b) => Some(a.or(b)),
        }
    }
    Some(Scope {
        world: axis(a.world, b.world)?,
        facet: axis(a.facet, b.facet)?,
        relationship: axis(a.relationship, b.relationship)?,
        project: axis(a.project, b.project)?,
        readable: a.readable.intersection(&b.readable).cloned().collect(),
        writable: a.writable.intersection(&b.writable).cloned().collect(),
    })
}

/// Whether a signed state fits under a parent project's effective view.
pub(super) fn authority_fits(authority: &ProjectAuthority, parent: &ProjectEffective) -> bool {
    ProjectEffective::of(authority, BTreeSet::new(), true).fits_under(parent)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectWitness {
    pub head: ProjectRevisionHash,
    /// The head's authority and the proof that signed it, nested anchors
    /// included: exactly what a new live revision signs over.
    pub anchor: ProjectAnchor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectFrontier {
    pub id: EntityId,
    pub disposition: ProjectDisposition,
    /// Present for Unsigned, Settled and Fork, and for OverBudget with a re-checked record.
    pub witness: Option<ProjectWitness>,
    pub effective: Option<ProjectEffective>,
}

impl ProjectFrontier {
    /// The verdict main's readers see: visible exactly when authority is served.
    pub(crate) fn verdict(&self) -> ProjectVerdict {
        if self.effective.is_some() {
            return ProjectVerdict::Visible;
        }
        self.disposition.verdict()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum ProjectDisposition {
    /// No signed history with a known mint, and main's stored-row reader accepts the row.
    Unsigned,
    Settled,
    /// Tied top-rank children of `anchor`, or the usable contenders of a
    /// resolution race there: none installed.
    Fork {
        anchor: ProjectRevisionHash,
        rank: ProjectRank,
        contenders: BTreeSet<ProjectRevisionHash>,
        /// The causal resolution tips at `anchor` (ruling (b)): two or more
        /// settle nothing, and a new resolution builds on them all.
        resolution_tips: BTreeSet<ProjectRevisionHash>,
    },
    /// Signed history exists but its root waits on a mint, parent or parent project.
    Pending {
        reason: String,
    },
    /// Signed history exists and no valid root survives.
    Unauthorized {
        reason: String,
    },
    /// Two or more valid births: no leader or board until the owner seals.
    ConflictingBirths {
        births: BTreeSet<ProjectRevisionHash>,
    },
    ConflictingSeals {
        seals: BTreeSet<ProjectRevisionHash>,
    },
    /// A parent cycle leaves revisions undefined (`joint.rs`): the deepest
    /// state every candidate passes serves, with the meet of the candidates.
    /// A fork and the cycle are one decision (ruling (a)): `forks` are the
    /// forks its worlds leave open, which a board resolution may settle.
    ParentCycle {
        anchor: ProjectRevisionHash,
        undefined: BTreeSet<ProjectRevisionHash>,
        forks: Vec<ProjectForkConflict>,
    },
    /// Past the budget: the persisted frozen frontier and the state it froze in.
    OverBudget {
        state: ProjectHistoryOverBudget,
        frozen: Box<ProjectDisposition>,
    },
}

/// One fork a parent cycle leaves open (ruling (a)): its worlds tie there,
/// or install different children there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectForkConflict {
    pub anchor: ProjectRevisionHash,
    pub rank: ProjectRank,
    /// Every child of `anchor` some world keeps in contention or installs.
    pub contenders: BTreeSet<ProjectRevisionHash>,
    /// The causal resolution tips at `anchor` (ruling (b)).
    pub resolution_tips: BTreeSet<ProjectRevisionHash>,
}

impl ProjectDisposition {
    pub(super) fn pending(reason: &'static str) -> Self {
        Self::Pending {
            reason: reason.to_owned(),
        }
    }
    pub(super) fn unauthorized(reason: &'static str) -> Self {
        Self::Unauthorized {
            reason: reason.to_owned(),
        }
    }
    /// The verdict of a disposition that serves no authority.
    pub(crate) fn verdict(&self) -> ProjectVerdict {
        match self {
            Self::Pending { reason } => ProjectVerdict::Pending(reason::of(reason)),
            Self::Unauthorized { reason } => ProjectVerdict::Quarantined(reason::of(reason)),
            Self::ConflictingBirths { .. } | Self::ConflictingSeals { .. } => {
                ProjectVerdict::Quarantined(reason::UNRESOLVED)
            }
            Self::OverBudget { state, .. } if state.frozen_head.is_none() => {
                ProjectVerdict::Quarantined(reason::STALE_RECORD)
            }
            _ => ProjectVerdict::Quarantined(reason::UNRESOLVED),
        }
    }
    pub(super) fn of_verdict(verdict: ProjectVerdict) -> Self {
        match verdict {
            ProjectVerdict::Pending(reason) => Self::pending(reason),
            ProjectVerdict::Quarantined(reason) => Self::unauthorized(reason),
            ProjectVerdict::Visible => Self::unauthorized(reason::UNRESOLVED),
        }
    }
}

pub(crate) struct ProjectFold {
    pub(crate) frontier: ProjectFrontier,
    pub(crate) verdicts: BTreeMap<ProjectRevisionHash, ProjectVerdict>,
    /// Every node the served view relies on.
    pub(crate) dependencies: ProjectDependencies,
    pub(crate) forks: Vec<ProjectForkEvidence>,
    pub(crate) evidence: ProjectEvidenceSet,
}

/// What one fold settles: the root, the path and where the walk stopped.
struct Walk {
    root: ProjectRevisionHash,
    seal: Option<ProjectRevisionHash>,
    path: Vec<ProjectRevisionHash>,
    resolutions: BTreeSet<ProjectRevisionHash>,
    end: Option<(ProjectRank, BTreeSet<ProjectRevisionHash>)>,
    /// The root folded to its frontier: what the walk serves.
    served: Rc<Fork>,
}

/// Folds one project's held revisions within budget. `stored` is the PROJECT
/// row; main's stored-row reader judges it when no signed history exists.
pub(crate) fn fold_project(cx: &FoldCx<'_, '_, '_>, stored: &ProjectRecord) -> Result<ProjectFold> {
    let (reader, id, held) = (cx.reader, cx.id, cx.held);
    let mut fold = ProjectFold {
        frontier: ProjectFrontier {
            id,
            disposition: ProjectDisposition::Settled,
            witness: None,
            effective: None,
        },
        verdicts: BTreeMap::new(),
        dependencies: ProjectDependencies::default(),
        forks: Vec::new(),
        evidence: ProjectEvidenceSet::default(),
    };
    let walk = match root_and_walk(cx, stored)? {
        Ok(walk) => walk,
        Err(frontier) => {
            fold.frontier = frontier;
            finish(cx, &mut fold, None)?;
            return Ok(fold);
        }
    };
    if let Some(why) = walk.served.blocked {
        fold.frontier.disposition = ProjectDisposition::unauthorized(why);
        finish(cx, &mut fold, Some(&walk))?;
        return Ok(fold);
    }
    let witness_head = *walk.path.last().unwrap_or(&walk.root);
    let disposition = match &walk.end {
        None => ProjectDisposition::Settled,
        Some((rank, contenders)) => ProjectDisposition::Fork {
            anchor: witness_head,
            rank: *rank,
            contenders: contenders.clone(),
            resolution_tips: cx.resolution_tips(witness_head)?.into_iter().collect(),
        },
    };
    let (Some(_), Some(view)) = (cx.authority_of(&witness_head), &walk.served.view) else {
        fold.frontier.disposition = ProjectDisposition::unauthorized(reason::NOT_A_STATE);
        finish(cx, &mut fold, Some(&walk))?;
        return Ok(fold);
    };
    let effective = ProjectEffective {
        bound_by_parents: cx
            .signer(&witness_head)
            .is_some_and(|signer| signer != "host"),
        ..view.clone()
    };
    // Beside the path: each tie branch to its frontier, the settlements on
    // the way, and what the tree's exclusions rest on (section 5a).
    let listed: BTreeSet<&ProjectRevisionHash> =
        walk.path.iter().chain(&walk.resolutions).collect();
    let exclusion = cx.exclusion(walk.root)?;
    fold.dependencies = ProjectDependencies {
        path: walk.path.clone(),
        contenders: (walk.served.nodes.iter())
            .chain(&exclusion.relied)
            .filter(|node| !listed.contains(node))
            .copied()
            .collect(),
        resolutions: walk.resolutions.iter().copied().collect(),
        seal: walk.seal,
        undefined: Vec::new(),
    };
    let witness = anchor_of(held, witness_head).map(|anchor| ProjectWitness {
        head: witness_head,
        anchor,
    });
    // A component judges its members' parents together (`joint.rs`).
    let bounds = match cx.parents {
        Parents::Read => parent_bounds(reader, id, &effective)?,
        Parents::Skip => Ok(()),
    };
    match (bounds, witness) {
        (Ok(()), Some(witness)) => {
            fold.frontier.disposition = disposition;
            fold.frontier.witness = Some(witness);
            fold.frontier.effective = Some(effective);
        }
        // Authority is served only with the witness a live write builds on.
        (Ok(()), None) => {
            fold.frontier.disposition = ProjectDisposition::unauthorized(reason::TOO_DEEP);
        }
        (Err(verdict), _) => fold.frontier.disposition = ProjectDisposition::of_verdict(verdict),
    }
    finish(cx, &mut fold, Some(&walk))?;
    Ok(fold)
}

/// Step 4: a view bound by its parents fits under each parent's effective
/// view, and every parent carries authority.
pub(super) fn parent_bounds(
    reader: &ProjectReader<'_, '_>,
    id: EntityId,
    effective: &ProjectEffective,
) -> Result<std::result::Result<(), ProjectVerdict>> {
    if Some(id) == reader.root() {
        return Ok(Ok(()));
    }
    if effective.parents.is_empty() {
        return Ok(Err(ProjectVerdict::Quarantined(reason::PARENTLESS)));
    }
    for parent in &effective.parents {
        let parent = EntityId::from_hex(parent)
            .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
        match parent_view(reader, parent)? {
            Err(verdict) => return Ok(Err(verdict)),
            Ok(view) if effective.bound_by_parents && !effective.fits_under(&view) => {
                return Ok(Err(ProjectVerdict::Quarantined(reason::EXCEEDS_PARENT)));
            }
            Ok(_) => {}
        }
    }
    Ok(Ok(()))
}

/// Picks the root (the one seal no seal retires, else the one birth) and
/// walks to the head. `Err` carries a frontier with no signed root.
fn root_and_walk(
    cx: &FoldCx<'_, '_, '_>,
    stored: &ProjectRecord,
) -> Result<std::result::Result<Walk, ProjectFrontier>> {
    let held = cx.held;
    let seals = cx.seal_status()?;
    let mut births = BTreeSet::new();
    // Without a root, the first reason in hash order a root candidate waits
    // or fails for: the same set gives the same reason.
    let mut pending: Option<&'static str> = None;
    let mut refused: Option<&'static str> = None;
    let mut signed_history = false;
    for (hash, row) in &held.rows {
        match &row.revision {
            ProjectRevision::Seal { .. } => {
                if let Some(ProjectVerdict::Pending(why)) = seals.envelope(hash) {
                    pending.get_or_insert(why);
                }
            }
            ProjectRevision::Signed { parent, .. } => {
                if cx.origin(*hash)? == RevisionOrigin::Authenticated {
                    signed_history = true;
                }
                if parent.is_none() {
                    match cx.verdict(*hash)? {
                        ProjectVerdict::Visible => {
                            births.insert(*hash);
                        }
                        ProjectVerdict::Pending(why) => {
                            pending.get_or_insert(why);
                        }
                        ProjectVerdict::Quarantined(why) => {
                            refused.get_or_insert(why);
                        }
                    }
                }
            }
            ProjectRevision::Boundary { .. } => {
                if cx.verdict(*hash)? == ProjectVerdict::Visible {
                    let mut built_on = false;
                    for child in held.children_of(hash) {
                        match cx.verdict(*child)? {
                            ProjectVerdict::Visible => built_on = true,
                            ProjectVerdict::Pending(why) => {
                                pending.get_or_insert(why);
                            }
                            ProjectVerdict::Quarantined(why) => {
                                refused.get_or_insert(why);
                            }
                        }
                    }
                    if built_on {
                        births.insert(*hash);
                    }
                }
            }
            ProjectRevision::Resolution { .. } => {}
        }
    }
    let (root, seal) = if !seals.tips.is_empty() {
        let mut only = seals.tips.iter();
        match (only.next(), only.next()) {
            // The one seal no seal retires roots the fold only where its
            // target stands. Otherwise the project holds: it never falls back
            // to a seal it retired, nor to the births it re-rooted (ruling (c)).
            (Some(tip), None) => match (cx.verdict(*tip)?, cx.row(tip)) {
                (ProjectVerdict::Visible, Some(ProjectRevision::Seal { seal, .. })) => {
                    (seal.next, Some(*tip))
                }
                (ProjectVerdict::Pending(why), _) => {
                    return Ok(Err(ProjectFrontier {
                        id: cx.id,
                        disposition: ProjectDisposition::pending(why),
                        witness: None,
                        effective: None,
                    }));
                }
                (ProjectVerdict::Quarantined(why), _) => return Ok(Err(no_root(cx.id, why))),
                (ProjectVerdict::Visible, _) => return Ok(Err(no_root(cx.id, reason::SEAL_NEXT))),
            },
            _ => {
                return Ok(Err(ProjectFrontier {
                    id: cx.id,
                    disposition: ProjectDisposition::ConflictingSeals {
                        seals: seals.tips.clone(),
                    },
                    witness: None,
                    effective: None,
                }));
            }
        }
    } else {
        let mut only = births.iter();
        match (only.next(), only.next()) {
            (Some(birth), None) => (*birth, None),
            (Some(_), Some(_)) => {
                return Ok(Err(ProjectFrontier {
                    id: cx.id,
                    disposition: ProjectDisposition::ConflictingBirths { births },
                    witness: None,
                    effective: None,
                }));
            }
            (None, _) if !signed_history => return Ok(Err(unsigned(cx, stored)?)),
            (None, _) => {
                return Ok(Err(match pending {
                    Some(why) => ProjectFrontier {
                        id: cx.id,
                        disposition: ProjectDisposition::pending(why),
                        witness: None,
                        effective: None,
                    },
                    None => no_root(cx.id, refused.unwrap_or(reason::NO_ROOT)),
                }));
            }
        }
    };
    let mut walk = Walk {
        root,
        seal,
        path: vec![root],
        resolutions: BTreeSet::new(),
        end: None,
        served: cx.fork(root, root)?,
    };
    let mut node = root;
    loop {
        let fork = cx.fork(root, node)?;
        // A settlement that excluded a valid child shapes what is served,
        // whether one winner or a tie's meet follows: the frozen reader
        // re-verifies it with the path.
        if (fork.settlement.superseded.iter()).any(|lost| fork.valid.contains(lost)) {
            walk.resolutions
                .extend(fork.settlement.closure.iter().copied());
        }
        match &fork.step {
            Step::Head => break,
            Step::Advance { winner, .. } => {
                walk.path.push(*winner);
                node = *winner;
            }
            Step::Tie { rank, contenders } => {
                walk.end = Some((*rank, contenders.clone()));
                break;
            }
        }
    }
    Ok(Ok(walk))
}

fn no_root(id: EntityId, why: &'static str) -> ProjectFrontier {
    ProjectFrontier {
        id,
        disposition: ProjectDisposition::unauthorized(why),
        witness: None,
        effective: None,
    }
}

/// Main's stored-row verdict, translated: Visible serves the row as main
/// reads it; Pending and Quarantined serve no authority.
fn unsigned(cx: &FoldCx<'_, '_, '_>, stored: &ProjectRecord) -> Result<ProjectFrontier> {
    unsigned_frontier(cx.id, stored, cx.reader.judge_stored(cx.id, stored)?)
}

/// The frontier an unsigned stored row serves under `verdict`.
pub(super) fn unsigned_frontier(
    id: EntityId,
    stored: &ProjectRecord,
    verdict: ProjectVerdict,
) -> Result<ProjectFrontier> {
    Ok(match verdict {
        ProjectVerdict::Visible => {
            let authority = stored.authority();
            let head = revision::revisions_of(id, &stored.anchor())?
                .last()
                .map(|(hash, _)| *hash);
            let seats = stored.members().into_iter().collect();
            ProjectFrontier {
                id,
                disposition: ProjectDisposition::Unsigned,
                witness: head.map(|head| ProjectWitness {
                    head,
                    anchor: stored.anchor(),
                }),
                effective: Some(ProjectEffective::of(
                    &authority,
                    seats,
                    read::bound_by_parents(stored),
                )),
            }
        }
        verdict => ProjectFrontier {
            id,
            disposition: ProjectDisposition::of_verdict(verdict),
            witness: None,
            effective: None,
        },
    })
}

/// Fills the verdicts, the fork evidence over the whole authenticated held
/// DAG and the evidence set the record keeps.
fn finish(cx: &FoldCx<'_, '_, '_>, fold: &mut ProjectFold, walk: Option<&Walk>) -> Result<()> {
    for hash in cx.held.rows.keys() {
        fold.verdicts.insert(*hash, cx.verdict(*hash)?);
    }
    let on_path: BTreeSet<ProjectRevisionHash> = walk
        .map(|walk| walk.path.iter().copied().collect())
        .unwrap_or_default();
    let roots: Vec<ProjectRevisionHash> = match walk {
        Some(walk) => vec![walk.root],
        None => cx
            .held
            .rows
            .iter()
            .filter(|(hash, row)| {
                matches!(row.revision, ProjectRevision::Boundary { .. })
                    || matches!(row.revision, ProjectRevision::Signed { parent: None, .. })
                        && fold.verdicts.get(hash) == Some(&ProjectVerdict::Visible)
            })
            .map(|(hash, _)| *hash)
            .collect(),
    };
    let mut seen = BTreeSet::new();
    // Each node folds within the tree of its root, as the walk saw it.
    let mut todo: Vec<(ProjectRevisionHash, ProjectRevisionHash)> =
        roots.into_iter().map(|root| (root, root)).collect();
    while let Some((root, node)) = todo.pop() {
        if !seen.insert(node) {
            continue;
        }
        let fork = cx.fork(root, node)?;
        todo.extend(fork.valid.iter().map(|child| (root, *child)));
        if fork.valid.len() < 2 {
            continue;
        }
        let outcome = match fork.step {
            Step::Head => ProjectForkOutcome::Excluded,
            Step::Advance {
                winner,
                resolution: Some(resolution),
            } if fork.settlement.tip == Some(resolution) => {
                ProjectForkOutcome::Resolved { resolution, winner }
            }
            Step::Advance { winner, .. } => ProjectForkOutcome::Ranked { winner },
            Step::Tie { rank, .. } => ProjectForkOutcome::Tied { rank },
        };
        fold.forks.push(ProjectForkEvidence {
            project: cx.id,
            anchor: node,
            children: fork.valid.clone(),
            outcome,
            on_path: on_path.contains(&node),
        });
    }
    let counted = counted_set(cx)?;
    fold.evidence = ProjectEvidenceSet::of(walk.map(|walk| walk.root), &counted);
    Ok(())
}

//! The per-project history budget (decision 9, ruling F2 (a)). Within budget
//! every read folds fresh. Past it the project serves the frontier its last
//! within-budget fold persisted, re-checked at every read, narrowed by the
//! valid descendants of its frozen head, and takes no new authority until the
//! owner seals or raises the policy. A live write past it is held, never
//! refused, and the crossing opens one owner question per project (OF-520).
//! The over-budget view is local and exempt from order-freedom; a huge
//! threshold raises a typed state, never a quiet limit.
use super::fold::{
    ProjectDisposition, ProjectEffective, ProjectFrontier, ProjectWitness, parent_bounds, reason,
};
use super::read::{ProjectReader, ProjectVerdict};
use super::revision::{ProjectRevision, ProjectRevisionHash, RevisionOrigin};
use super::validity::FoldCx;
use super::*;
use crate::consent::AuthenticatedOwner;

pub const DEFAULT_PROJECT_HISTORY_MAX_REVISIONS: u64 = 10_000;
/// How many worlds one member of a parent cycle may have (`joint.rs`).
pub const DEFAULT_PROJECT_CYCLE_WORLDS_MAX: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectHistoryPolicy {
    pub max_revisions: u64,
    /// Past this many distinct views of one cycle member (or this many per
    /// undecided revision of assignments), the cycle serves no authority
    /// until the owner seals.
    #[serde(default = "default_cycle_worlds_max")]
    pub cycle_worlds_max: u64,
}

fn default_cycle_worlds_max() -> u64 {
    DEFAULT_PROJECT_CYCLE_WORLDS_MAX
}

impl Default for ProjectHistoryPolicy {
    fn default() -> Self {
        Self {
            max_revisions: DEFAULT_PROJECT_HISTORY_MAX_REVISIONS,
            cycle_worlds_max: DEFAULT_PROJECT_CYCLE_WORLDS_MAX,
        }
    }
}

/// The owner's question about a parent cycle past its world bound (OF-520):
/// node-local, raised by the batch-end refresh and cleared when the cycle
/// serves again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCycleQuestion {
    /// The cycle's projects, in id order; each keys a copy of the row.
    pub members: Vec<EntityId>,
    pub raised_at: u64,
}

/// The owner's question about a project past its history budget (OF-520):
/// raised once, when a batch end first freezes the project, while every
/// authenticated revision past it is held; a seal or a raised policy that
/// brings the project back within budget clears it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectHistoryQuestion {
    pub project: EntityId,
    /// The revisions counted when the project crossed its budget.
    pub counted_at_crossing: u64,
    pub raised_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectHistoryOverBudget {
    pub project: EntityId,
    pub held: u64,
    pub max_revisions: u64,
    /// `None` when no record exists or it no longer re-checks.
    pub frozen_head: Option<ProjectRevisionHash>,
    /// Whether descendants of the frozen head narrowed it since the freeze.
    pub narrowed: bool,
}

/// Every node the served view relies on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectDependencies {
    /// Root to head, the seal's `next` or the birth first.
    pub(crate) path: Vec<ProjectRevisionHash>,
    /// The fork contenders whose meet the view holds; in a combined record,
    /// also every other node a world rests on that the component holds valid.
    pub(crate) contenders: Vec<ProjectRevisionHash>,
    /// The effective resolution tips on the path and their prior closures.
    pub(crate) resolutions: Vec<ProjectRevisionHash>,
    pub(crate) seal: Option<ProjectRevisionHash>,
    /// A combined record's nodes that rest on a state its cycle left
    /// undefined: each still verifies on its own lineage, whatever its
    /// parents serve (Astra #1434c F1).
    pub(crate) undefined: Vec<ProjectRevisionHash>,
}

impl ProjectDependencies {
    /// The nodes checked exactly as the fold verifies them.
    pub(super) fn checked(&self) -> impl Iterator<Item = &ProjectRevisionHash> {
        self.path
            .iter()
            .chain(&self.contenders)
            .chain(&self.resolutions)
            .chain(&self.seal)
    }
}

/// Which revisions a fold counted, by identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectEvidenceSet {
    pub(crate) root: Option<ProjectRevisionHash>,
    pub(crate) counted: u64,
    /// blake3 of the sorted counted hashes.
    pub(crate) digest: [u8; 32],
}

impl ProjectEvidenceSet {
    pub(super) fn of(
        root: Option<ProjectRevisionHash>,
        counted: &BTreeSet<ProjectRevisionHash>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        for hash in counted {
            hasher.update(&hash.0);
        }
        Self {
            root,
            counted: counted.len() as u64,
            digest: *hasher.finalize().as_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectFreeze {
    pub(crate) at_counted: u64,
    pub(crate) narrowed: bool,
    /// When the crossing raised the owner's question.
    pub(crate) raised_at: u64,
}

/// LIVE authority: kept across delete, never rolled back by restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectFrontierRecord {
    pub(crate) witness: Option<ProjectWitness>,
    pub(crate) disposition: ProjectDisposition,
    pub(crate) effective: Option<ProjectEffective>,
    pub(crate) dependencies: ProjectDependencies,
    pub(crate) evidence: ProjectEvidenceSet,
    pub(crate) verified_at: u64,
    pub(crate) frozen: Option<ProjectFreeze>,
}

impl ProjectFrontierRecord {
    /// The same served view, whenever it was verified.
    pub(super) fn same_view(&self, other: &Self) -> bool {
        self.witness == other.witness
            && self.disposition == other.disposition
            && self.effective == other.effective
            && self.frozen == other.frozen
    }
}

/// The last verified frontier of each project. LIVE.
pub(super) const PROJECT_FRONTIER: SideTable<EntityId, ProjectFrontierRecord, Named> =
    SideTable::new(&side_table::PROJECT_FRONTIER);
/// LIVE: while frozen, the descendants of the frozen head applied as meets.
pub(super) const PROJECT_FROZEN_APPLIED: SideTable<(EntityId, ProjectRevisionHash), (), Raw> =
    SideTable::new(&side_table::PROJECT_FROZEN_APPLIED);
/// LIVE: frozen descendants whose verdict depends on a parent project:
/// (parent project, (project, hash)). A refresh of the parent that changes
/// its view takes these rows and retries their projects.
pub(super) const PROJECT_FROZEN_WAIT_PROJECT: SideTable<
    (EntityId, (EntityId, ProjectRevisionHash)),
    (),
    Raw,
> = SideTable::new(&side_table::PROJECT_FROZEN_WAIT_PROJECT);
/// LOCAL: the open OF-520 question of a parent cycle past its bound, under
/// each of its members (the owner door lists it once).
pub(super) const PROJECT_CYCLE_QUESTION: SideTable<EntityId, ProjectCycleQuestion, Named> =
    SideTable::new(&side_table::PROJECT_CYCLE_QUESTION);
/// The vault's history policy, set only through the owner door.
const PROJECT_HISTORY_POLICY: SideTable<(), ProjectHistoryPolicy, Named> =
    SideTable::new(&side_table::PROJECT_HISTORY_POLICY);

pub(super) fn policy_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<ProjectHistoryPolicy> {
    Ok(PROJECT_HISTORY_POLICY
        .get(store, txn, &())?
        .unwrap_or_default())
}

/// The frontier of a project past its budget: the persisted record when every
/// node it relies on still verifies exactly as the fold verifies it, and no
/// authority otherwise. Nothing ever folds "the first N".
/// `parents`: whether the saved view is also checked under its parents
/// here (a component checks it with its other members' views instead).
pub(super) fn frozen_frontier(
    reader: &ProjectReader<'_, '_>,
    cx: &FoldCx<'_, '_, '_>,
    held: u64,
    max_revisions: u64,
    parents: bool,
) -> Result<ProjectFrontier> {
    let id = cx.id;
    let state = |frozen_head, narrowed| ProjectHistoryOverBudget {
        project: id,
        held,
        max_revisions,
        frozen_head,
        narrowed,
    };
    let Some(record) = PROJECT_FRONTIER.get(reader.store(), reader.txn(), &id)? else {
        return Ok(ProjectFrontier {
            id,
            disposition: ProjectDisposition::OverBudget {
                state: state(None, false),
                frozen: Box::new(ProjectDisposition::unauthorized(reason::NO_RECORD)),
            },
            witness: None,
            effective: None,
        });
    };
    let narrowed = record.frozen.is_some_and(|freeze| freeze.narrowed);
    let mut verified = record.witness.is_some() && record.effective.is_some();
    for hash in record.dependencies.checked() {
        if !verified {
            break;
        }
        verified = cx.verdict(*hash)? == ProjectVerdict::Visible;
    }
    let alone = FoldCx::intrinsic(reader, id, cx.held);
    for hash in &record.dependencies.undefined {
        if !verified {
            break;
        }
        verified = alone.verdict(*hash)? == ProjectVerdict::Visible;
    }
    // A seal a later owner seal retired roots nothing, so a record frozen
    // under it no longer verifies; its evidence stays held (ruling (c)).
    if let (true, Some(seal)) = (verified, &record.dependencies.seal) {
        verified = !cx.seal_status()?.retired.contains(seal);
    }
    if let (true, true, Some(effective)) = (verified, parents, &record.effective) {
        verified = parent_bounds(reader, id, effective)?.is_ok();
    }
    Ok(if verified {
        ProjectFrontier {
            id,
            disposition: ProjectDisposition::OverBudget {
                state: state(
                    record.witness.as_ref().map(|witness| witness.head),
                    narrowed,
                ),
                frozen: Box::new(record.disposition),
            },
            witness: record.witness,
            effective: record.effective,
        }
    } else {
        ProjectFrontier {
            id,
            disposition: ProjectDisposition::OverBudget {
                state: state(None, narrowed),
                frozen: Box::new(record.disposition),
            },
            witness: None,
            effective: None,
        }
    })
}

impl Vault {
    /// The open questions about parent cycles past their world bound.
    pub fn project_cycle_questions(&self) -> Result<Vec<ProjectCycleQuestion>> {
        let txn = self.store.env.read_txn()?;
        let mut questions: std::collections::BTreeMap<Vec<EntityId>, ProjectCycleQuestion> =
            std::collections::BTreeMap::new();
        for (_, question) in PROJECT_CYCLE_QUESTION.scan_from(&self.store, &txn, &[])? {
            let raised = questions
                .entry(question.members.clone())
                .or_insert_with(|| question.clone());
            raised.raised_at = raised.raised_at.min(question.raised_at);
        }
        Ok(questions.into_values().collect())
    }

    pub fn project_history_policy(&self) -> Result<ProjectHistoryPolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in(&self.store, &txn)
    }

    /// The owner raises (or lowers) the per-project fold budget. The next read
    /// folds against it, and the next write to a project clears its freeze.
    pub fn set_project_history_policy(
        &self,
        owner: &AuthenticatedOwner,
        policy: ProjectHistoryPolicy,
    ) -> Result<()> {
        if policy.max_revisions == 0 || policy.cycle_worlds_max == 0 {
            return Err(Error::InvalidConfig(
                "project history budgets must admit at least one revision and one world".into(),
            ));
        }
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            PROJECT_HISTORY_POLICY.put(&self.store, txn, &(), &policy)
        })
    }

    /// The open questions about projects past their history budget: one per
    /// frozen project that a fresh read still finds over it, so a raised
    /// policy clears its question at once and a seal at its batch end.
    pub fn project_history_questions(&self) -> Result<Vec<ProjectHistoryQuestion>> {
        let txn = self.store.env.read_txn()?;
        let Some(reader) = ProjectReader::new(&self.store, &txn, self.privacy_posture())? else {
            return Ok(Vec::new());
        };
        let reader = reader.committed();
        let mut questions = Vec::new();
        for (project, record) in PROJECT_FRONTIER.scan_from(&self.store, &txn, &[])? {
            let Some(freeze) = record.frozen else {
                continue;
            };
            if let Some(ProjectFrontier {
                disposition: ProjectDisposition::OverBudget { .. },
                ..
            }) = reader.frontier(project)?
            {
                questions.push(ProjectHistoryQuestion {
                    project,
                    counted_at_crossing: freeze.at_counted,
                    raised_at: freeze.raised_at,
                });
            }
        }
        Ok(questions)
    }

    /// Every project whose history is past the budget, for the owner.
    pub fn projects_over_history_budget(&self) -> Result<Vec<ProjectHistoryOverBudget>> {
        let txn = self.store.env.read_txn()?;
        let Some(reader) = ProjectReader::new(&self.store, &txn, self.privacy_posture())? else {
            return Ok(Vec::new());
        };
        let reader = reader.committed();
        let mut over = Vec::new();
        for (id, _, _) in reader.all()? {
            if let Some(ProjectFrontier {
                disposition: ProjectDisposition::OverBudget { state, .. },
                ..
            }) = reader.frontier(id)?
            {
                over.push(state);
            }
        }
        Ok(over)
    }
}

/// How many revisions the budget counts (point H).
pub(super) fn budget_count(cx: &FoldCx<'_, '_, '_>) -> Result<u64> {
    Ok(counted_set(cx)?.len() as u64)
}

/// What the budget counts (point H): authenticated signed revisions reachable
/// through the child index from the root, every boundary and every birth,
/// plus the authenticated envelopes at reachable nodes, read from the index.
/// Under the one seal no seal retires the fold restarts at its revision, so
/// only the seal and what descends from it count. A row nothing reachable
/// names, such as an envelope over an anchor this replica lacks, spends
/// nothing.
pub(super) fn counted_set(cx: &FoldCx<'_, '_, '_>) -> Result<BTreeSet<ProjectRevisionHash>> {
    let authenticated = |hash: &ProjectRevisionHash| {
        cx.held
            .get(hash)
            .is_some_and(|row| row.origin == RevisionOrigin::Authenticated)
    };
    let tips = cx.seal_status()?.tips.clone();
    let mut only = tips.iter();
    let mut counted = BTreeSet::new();
    let roots: Vec<ProjectRevisionHash> = match (only.next(), only.next()) {
        (Some(tip), None) => {
            let Some(ProjectRevision::Seal { seal, .. }) = cx.row(tip) else {
                return Ok(counted);
            };
            counted.insert(*tip);
            vec![seal.next]
        }
        _ => cx
            .held
            .rows
            .iter()
            .filter(|(_, row)| {
                matches!(
                    row.revision,
                    ProjectRevision::Boundary { .. } | ProjectRevision::Signed { parent: None, .. }
                )
            })
            .map(|(hash, _)| *hash)
            .collect(),
    };
    let mut seen = BTreeSet::new();
    let mut todo = roots;
    while let Some(node) = todo.pop() {
        if !seen.insert(node) {
            continue;
        }
        if authenticated(&node) && matches!(cx.row(&node), Some(ProjectRevision::Signed { .. })) {
            counted.insert(node);
        }
        counted.extend(
            cx.held
                .resolutions_at(&node)
                .filter(|hash| authenticated(hash)),
        );
        todo.extend(cx.held.children_of(&node).copied());
    }
    if tips.len() != 1 {
        for hash in &cx.held.seals {
            if authenticated(hash)
                && matches!(cx.row(hash), Some(ProjectRevision::Seal { seal, .. }) if seen.contains(&seal.next))
            {
                counted.insert(*hash);
            }
        }
    }
    Ok(counted)
}

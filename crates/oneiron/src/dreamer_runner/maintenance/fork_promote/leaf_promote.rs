//! The promote step of the project tree fork pass (ARCH-0079 #task-type,
//! OF-420): a type a project's own tree learned that holds up on runs
//! outside the project is offered to the vault tree through the existing
//! merge-back, the shared-skill merge's "useful upstream?" question and its
//! held-out replay.
//!
//! A project's leaf is counted afresh each pass, on a copy of the project's
//! tree that is never stored ([`super::PROJECT_LEAF_PROMOTES`] says how). A
//! leaf that holds up is added to a copy of the vault tree in force, keeping
//! its scope, and that tree goes into the project's promote fork of the vault
//! head, an ordinary local fork. Its bytes, renamed to the head at a version
//! past the head's, are submitted as a refinement of the head; the merge door
//! asks the host's ladder the Coach's question for the host's agent, then the
//! judge replays the head's held-out runs with both trees in view. A merge
//! that widens the skill's permissions, or whose scan asks for review, waits
//! on the owner.
use std::collections::{BTreeMap, BTreeSet};

use super::super::type_tree_gate::{TreeReplayScorer, record_team_shape_outcomes};
use super::{
    ForkPromoteReport, PROMOTE_SKILL_PREFIX, Pass, UpstreamSeat, by_path, fork_files, next_version,
    open_forks, refused,
};
use crate::agent_dispatch::{load_team_type_tree, team_shape_skill_in_force};
use crate::error::ArtifactError;
use crate::llm::decision::{AnswerContract, DecisionClass, DecisionQuestion};
use crate::skill::SkillRecord;
use crate::skill_hub::{HubPackage, SharedSkillMergeDisposition, encode_hub_package};
use crate::skill_optimize::{HeldOutReplayNotes, held_out_receipts};
use crate::task_type::{
    DecisionAxis, PromotionOutcome, TaskTypeNode, TaskTypeRef, TaskTypeTree, TreeScope,
};
use crate::team::TeamReceipt;
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault};

/// The version of the Coach's question; a changed wording takes the next.
/// 2: the question names the Coach and the leader it asks on behalf of.
const QUESTION_VERSION: u32 = 2;

/// The vault head a promotion revises, read again once a merge puts a new
/// head in force.
struct Upstream {
    head: EntityId,
    record: SkillRecord,
    package: HubPackage,
    tree: TaskTypeTree,
    /// The head's open local forks, by skill id.
    open: BTreeMap<String, EntityId>,
    /// Whether the head's reserve holds a held-out run, once this pass has
    /// offered the settled teams to it.
    reserve: Option<bool>,
}

impl Upstream {
    /// The head the fork pass read.
    fn of(pass: &Pass) -> Self {
        Self {
            head: pass.head,
            record: pass.head_record.clone(),
            package: pass.head_package.clone(),
            tree: pass.vault_tree.clone(),
            open: pass.open.clone(),
            reserve: None,
        }
    }

    /// The head in force now; `None` when none is, or it carries no package.
    fn read(vault: &Vault) -> Result<Option<Self>> {
        let Some(head) = team_shape_skill_in_force(vault, None)? else {
            return Ok(None);
        };
        let record = vault
            .get_skill_record(&head)?
            .ok_or(Error::EntityNotFound)?;
        let package = {
            let txn = vault.store.env.read_txn()?;
            vault.runtime_skill_package_in_txn(&txn, &head, &record)?
        };
        let Some(package) = package else {
            return Ok(None);
        };
        Ok(Some(Self {
            tree: load_team_type_tree(vault, None)?,
            open: open_forks(vault, &head)?,
            head,
            record,
            package,
            reserve: None,
        }))
    }
}

/// What each offer borrows from the pass and the host.
struct Lent<'a> {
    judge: &'a dyn HeldOutReplayNotes,
    seat: &'a dyn UpstreamSeat,
    settled: &'a [TeamReceipt],
    now: u64,
}

/// A held-up leaf of `project`, as the vault tree with it added holds it.
struct Offer<'a> {
    project: EntityId,
    leaf: &'a TaskTypeNode,
    parent: &'a TaskTypeNode,
    axis: DecisionAxis,
    winner: &'a str,
}

/// What became of one offer.
enum Ruling {
    /// The merge put this revision in force.
    Promoted(EntityId),
    /// The merge waits on the owner's answer.
    PendingConsent,
    /// The merge ruled it out, or a merge already ruled on these bytes.
    Refused,
    /// The head holds no held-out run to replay yet.
    Unscored,
}

/// The promote step over `projects`: for each one on a fork of its own, each
/// live split leaf the vault tree lacks, under a live parent it holds, is
/// counted on runs elsewhere, and one that holds up is offered to the head in
/// force. Without the host's judge and seat in `seat`, a leaf that holds up
/// is counted and nothing is offered.
///
/// # Errors
///
/// Storage errors, and the doors' and the judge's errors other than a
/// refusal of one offer or an abstention on it, which are counted.
pub(super) fn run(
    vault: &Vault,
    pass: &Pass,
    seat: Option<(&dyn HeldOutReplayNotes, &dyn UpstreamSeat)>,
    projects: impl IntoIterator<Item = EntityId>,
    settled: &[TeamReceipt],
    report: &mut ForkPromoteReport,
) -> Result<()> {
    let mut upstream = Upstream::of(pass);
    for project in projects {
        let tree = load_team_type_tree(vault, Some(project))?;
        let own = project.to_hex();
        if !matches!(&tree.scope, TreeScope::Project { project_ref: Some(of), .. } if *of == own) {
            continue;
        }
        // The counts elsewhere live on this copy alone.
        let mut scratch = tree.clone();
        for leaf in tree
            .nodes
            .values()
            .filter(|node| node.is_live() && tree.is_leaf(&node.node_id))
        {
            let (Some(parent_id), Some(axis), Some(winner)) = (
                leaf.parent.as_deref(),
                leaf.split_axis,
                leaf.split_winner.as_deref(),
            ) else {
                continue;
            };
            if upstream.tree.nodes.contains_key(&leaf.node_id)
                || !upstream
                    .tree
                    .node(parent_id)
                    .is_some_and(TaskTypeNode::is_live)
            {
                continue;
            }
            report.leaves += 1;
            if let Some(node) = scratch.nodes.get_mut(&leaf.node_id) {
                node.held_out_runs = 0;
                node.held_out_wins = 0;
            }
            for won in elsewhere(settled, &upstream.tree, project, parent_id, axis, winner) {
                scratch.record_held_out(&leaf.node_id, won)?;
            }
            let mut promoted = upstream.tree.clone();
            if !matches!(
                scratch.promote_leaf_to(&mut promoted, &leaf.node_id)?,
                PromotionOutcome::Promoted(_)
            ) {
                continue;
            }
            report.held_up += 1;
            let (Some((judge, host)), Some(node), Some(parent)) =
                (seat, promoted.node(&leaf.node_id), promoted.node(parent_id))
            else {
                report.promote_unscored += 1;
                continue;
            };
            let lent = Lent {
                judge,
                seat: host,
                settled,
                now: pass.now,
            };
            let offer = Offer {
                project,
                leaf: node,
                parent,
                axis,
                winner,
            };
            match offer_leaf(vault, &lent, &mut upstream, &promoted, &offer) {
                Ok(Ruling::Promoted(revision)) => {
                    report.promoted.push(revision);
                    // The merged revision is the head the next leaf revises.
                    match Upstream::read(vault)? {
                        Some(next) => upstream = next,
                        None => return Ok(()),
                    }
                }
                Ok(Ruling::PendingConsent) => report.pending_consent += 1,
                Ok(Ruling::Unscored) => report.promote_unscored += 1,
                Ok(Ruling::Refused)
                | Err(
                    Error::Artifact(ArtifactError::InvalidSkillBody(_)) | Error::InvalidConfig(_),
                ) => {
                    report.promote_refused += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// One entry per settled team outside `project` (a team in no project is
/// outside every one) placed under `parent` in `vault_tree` whose pick on
/// `axis` is `winner`: whether it succeeded. A team that picked otherwise,
/// or names no pick on that decision, is not a run; a team counts once.
fn elsewhere(
    settled: &[TeamReceipt],
    vault_tree: &TaskTypeTree,
    project: EntityId,
    parent: &str,
    axis: DecisionAxis,
    winner: &str,
) -> Vec<bool> {
    let mut seen = BTreeSet::new();
    let mut runs = Vec::new();
    for team in settled {
        let Some(outcome) = &team.outcome else {
            continue;
        };
        let placed = vault_tree
            .resolve_ref(&TaskTypeRef::from(&team.type_ref))
            .is_some_and(|node| node.node_id == parent);
        if team.project != Some(project)
            && placed
            && pick(team, axis) == Some(winner)
            && seen.insert(team.team_ref.as_str())
        {
            runs.push(outcome.success);
        }
    }
    runs
}

/// What `team` chose on `axis`: its pattern, or its one model (each id's
/// final `@revision` stripped) when it ran on no other. A mix picks no model,
/// and no team receipt names a critic.
fn pick(team: &TeamReceipt, axis: DecisionAxis) -> Option<&str> {
    match axis {
        DecisionAxis::WinningPattern => Some(team.pattern.as_str()),
        DecisionAxis::WinningModel => {
            let models: BTreeSet<&str> = team
                .models
                .iter()
                .map(|id| id.rsplit_once('@').map_or(id.as_str(), |(model, _)| model))
                .collect();
            let mut models = models.into_iter();
            match (models.next(), models.next()) {
                (Some(model), None) => Some(model),
                _ => None,
            }
        }
        DecisionAxis::TrustedCritic => None,
    }
}

/// Offers `offer`'s leaf, which `promoted` adds to the head's tree, to the
/// head. The head's reserve takes the settled teams first, since the replay
/// reads its held-out runs. Bytes no merge has seen go into the project's
/// promote fork and are submitted from it; bytes already submitted are asked
/// again only while no merge has ruled on them.
fn offer_leaf(
    vault: &Vault,
    lent: &Lent<'_>,
    upstream: &mut Upstream,
    promoted: &TaskTypeTree,
    offer: &Offer<'_>,
) -> Result<Ruling> {
    let reserved = match upstream.reserve {
        Some(reserved) => reserved,
        None => {
            record_team_shape_outcomes(vault, &upstream.head, &upstream.record, lent.settled)?;
            let reserved = !held_out_receipts(vault, &upstream.head)?.is_empty();
            upstream.reserve = Some(reserved);
            reserved
        }
    };
    if !reserved {
        return Ok(Ruling::Unscored);
    }
    let occurred = TimeRange {
        start: lent.now,
        end: lent.now,
    };
    let tree = serde_json::to_vec_pretty(promoted)
        .map_err(|_| refused("a promoted type tree does not encode"))?;
    let version = next_version(&upstream.record.version, &upstream.record.version);
    let files = fork_files(
        &upstream.package,
        &upstream.record.skill_id,
        &version,
        &tree,
    )?;
    let mut record = upstream.record.clone();
    record.version = version;
    let mut offered = HubPackage::new(record, files, upstream.package.capabilities.clone());
    let hash = offered.content_hash()?;
    offered.record.content_hash = Some(hash);
    let earlier = {
        let txn = vault.store.env.read_txn()?;
        vault.skill_entity_for_content_hash_in_txn(&txn, hash)?
    };
    let candidate = match earlier {
        // Submitted before: asked again while no merge has ruled on it (the
        // owner has not answered, or the last ask did not settle).
        Some(earlier) => {
            if vault.shared_skill_delta(&earlier)?.is_none()
                || vault.shared_skill_merge_receipt(&earlier)?.is_some()
            {
                return Ok(Ruling::Refused);
            }
            earlier
        }
        None => {
            let fork = promote_fork(vault, upstream, offer.project, &tree, lent.now)?;
            vault.submit_local_skill_refinement(
                &upstream.head,
                &fork,
                &lent.seat.resident(),
                &encode_hub_package(&offered)?,
                occurred,
                lent.now,
            )?
        }
    };
    let question = upstream_question(candidate, offer, lent.seat.resident());
    let ask = vault.prepare_shared_skill_merge(candidate, lent.seat.resident(), question)?;
    let judge = TreeReplayScorer::new(
        vault,
        lent.judge,
        &candidate,
        &upstream.head,
        upstream.tree.clone(),
        lent.settled,
    )?;
    let merged = lent
        .seat
        .ask(&|useful| vault.merge_shared_skill_delta(&ask, useful, &judge, occurred, lent.now))?;
    Ok(match merged {
        SharedSkillMergeDisposition::PendingConsent => Ruling::PendingConsent,
        SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted => {
            Ruling::Promoted(candidate)
        }
        SharedSkillMergeDisposition::Ruled(_) => Ruling::Refused,
    })
}

/// The project's open promote fork of the head, minted when none is open,
/// holding `tree`: the head's package with only the tree and SKILL.md's
/// `name:` and `version:` lines changed. A package that already holds those
/// bytes is not written again; a changed one takes a version past its own and
/// never the head's.
fn promote_fork(
    vault: &Vault,
    upstream: &mut Upstream,
    project: EntityId,
    tree: &[u8],
    now: u64,
) -> Result<EntityId> {
    let skill_id = format!("{PROMOTE_SKILL_PREFIX}{}", project.to_hex());
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let fork = match upstream.open.get(&skill_id).copied() {
        Some(fork) => fork,
        None => {
            let fork = vault.store.clock.entity_id()?;
            vault.with_write_txn_grouped(|txn| {
                vault.fork_skill_record_in_txn(txn, &upstream.head, &fork, &skill_id, occurred, now)
            })?;
            upstream.open.insert(skill_id.clone(), fork);
            fork
        }
    };
    let (record, stored) = {
        let txn = vault.store.env.read_txn()?;
        let record = vault.read_skill_record_in_txn(&txn, &fork)?;
        let stored = vault.runtime_skill_package_in_txn(&txn, &fork, &record)?;
        (record, stored)
    };
    let current = fork_files(&upstream.package, &skill_id, &record.version, tree)?;
    if record.version != upstream.record.version
        && stored.is_some_and(|stored| by_path(&stored.files) == by_path(&current))
    {
        return Ok(fork);
    }
    let version = next_version(&record.version, &upstream.record.version);
    let files = fork_files(&upstream.package, &skill_id, &version, tree)?;
    vault.write_shared_skill_fork_package(
        &fork,
        &HubPackage::new(record, files, upstream.package.capabilities.clone()),
        occurred,
        now,
    )?;
    Ok(fork)
}

/// The Coach's useful-upstream question on `candidate`, the head with
/// `offer`'s leaf added to its tree (CALLS "UsefulUpstream wording"). It
/// names the leaf, the decision it splits its parent on and that decision's
/// winner, the project it comes from and its record on runs elsewhere, so
/// the answer is about that one type. The Coach has no agent definition of
/// its own (its identity is a MACHINE the submission door does not take), so
/// `resident`, the root project's leader, submits and is asked on its
/// behalf, and the question says so: the work is the Coach's.
fn upstream_question(
    candidate: EntityId,
    offer: &Offer<'_>,
    resident: EntityId,
) -> DecisionQuestion {
    let decision = match offer.axis {
        DecisionAxis::WinningPattern => "the winning coordination pattern",
        DecisionAxis::WinningModel => "the winning model",
        DecisionAxis::TrustedCritic => "the critic to trust",
    };
    let (leaf, parent, winner) = (&offer.leaf.name, &offer.parent.name, offer.winner);
    let (runs, wins) = (offer.leaf.held_out_runs, offer.leaf.held_out_wins);
    let text = format!(
        "Useful upstream? Asked by the Coach, on behalf of {resident}, the leader of the \
vault's root project, who submits it. Project {project} keeps a task type of its own, \
\"{leaf}\" ({id}): the tasks of \"{parent}\" where {decision} is {winner}. Of the {runs} runs \
outside that project placed under \"{parent}\" whose team chose {winner}, {wins} succeeded. \
Candidate {candidate} is the vault's team-shape skill with only this type added to its \
task-type tree. Answer yes if every project that shares the vault tree should have this type, \
no if it should stay the project's own.",
        resident = resident.to_hex(),
        project = offer.project.to_hex(),
        id = offer.leaf.node_id,
        candidate = candidate.to_hex(),
    );
    DecisionQuestion {
        id: candidate,
        version: QUESTION_VERSION,
        text,
        class: DecisionClass::UsefulUpstream,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

//! The project tree fork (ARCH-0079 #task-type, OF-420): a project whose
//! receipts disagree with the vault tree forks it. The vault tree is data in
//! the team-shape skill; a project still on it whose own settled teams read
//! a clear winner the vault tree does not gets its own fork of the
//! in-force team-shape head. The fork carries the vault tree's shape counted
//! on the project's own fit runs alone, and its package is the head's with
//! only the tree and SKILL.md's `name:` and `version:` lines changed. The
//! host's judge scores the fork against the head on the project's held-out
//! runs (the project's teams in the head's reserve), outside any vault
//! transaction; a strict win puts the fork in force for the project, with
//! its OF-023 revert row, in one transaction. A tie or a loss leaves the
//! fork open, and a later night reuses it rather than minting another.
//!
//! Then each project on a fork of its own keeps reshaping it from its own fit
//! runs, as the vault tree is reshaped, and a revision that wins on the
//! project's held-out runs goes in force for the project behind the tree it
//! revised ([`project_upkeep`]); this runs whether or not the vault has a
//! head to fork.
//!
//! After that, a project on a fork of its own offers each leaf its tree
//! learned that holds up on runs outside the project to the vault tree,
//! through the shared-skill merge's "useful upstream?" question and held-out
//! replay ([`leaf_promote`]).
//!
//! A project tree's judge and reshape check read a thin leaf with the vault
//! tree's counts on the same path blended in, under one weight that fades
//! with the leaf's own runs (FIX 5176, [`super::type_tree_prior`]). The pass
//! builds that donor once and lends it; the fork trigger, the fit counts,
//! promotion and the revisions' evidence never read it.
//!
//! The owner's revert takes the fork off the project, which goes back to the
//! vault tree; the pass forks that project again only from a newer head.
use std::collections::{BTreeMap, BTreeSet};

use super::applied;
use super::coach::COACH_FORK_PROMOTE_FACET;
use super::type_tree_gate::{TreeReplayScorer, record_team_shape_outcomes, team_leader};
use super::type_tree_prior::DonorTree;
use super::type_tree_upkeep::{recount, type_evidence};
use crate::agent_dispatch::{TASK_TYPE_TREE_FILE, load_team_type_tree, team_shape_skill_in_force};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::ArtifactError;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPackage, SharedSkillMergeDisposition, UsefulUpstreamDecisions};
use crate::skill_optimize::{HeldOutReplayCase, HeldOutReplayNotes, held_out_receipts};
use crate::task_type::{TaskTypeTree, TreeScope};
use crate::team::run_binding::team_run_tasks;
use crate::team::{TeamReceipt, team_receipts};
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault, WriteActor};

mod leaf_promote;
mod project_upkeep;

/// A project tree fork that wins on its project's held-out runs goes in
/// force at once (admission, the project's attachment and its revert row in
/// one transaction), with no owner step. `false` leaves the winning fork
/// open for an owner door.
pub const PROJECT_TREE_FORK_ADMITS: bool = true;
/// After the forks, each project on a fork of its own offers its leaves to
/// the vault tree. A leaf's record elsewhere is counted afresh each pass and
/// never stored: each settled team outside the project (a team in no
/// project is outside every one) placed under the leaf's parent whose pick
/// on the leaf's decision (its pattern, or its one model) is the leaf's
/// winner is one run, won when the team succeeded; a team that picked
/// otherwise, or whose leader the head's reserve holds, is not counted
/// (the reserve is the merge replay's held-out evidence). A leaf with at least
/// [`crate::task_type::PROMOTE_MIN_HELD_OUT_RUNS`] such runs, won by a
/// strict majority, goes to the merge. `false` offers nothing.
pub const PROJECT_LEAF_PROMOTES: bool = true;
/// A project's fork takes this skill id, then the project's 32 hex.
const FORK_SKILL_PREFIX: &str = "team-shape.project.";
/// A project's local fork of the head that carries a promoted leaf takes
/// this skill id, then the project's 32 hex.
const PROMOTE_SKILL_PREFIX: &str = "team-shape.promote.";
/// Skill records read per page while looking for the open forks.
const SKILL_PAGE: usize = 128;

/// What the host lends the promote step: the agent the Coach asks "useful
/// upstream?" for, and the host's useful-upstream ladder, on a fresh clock
/// for each question.
pub trait UpstreamSeat {
    /// The agent definition the question is asked for.
    fn resident(&self) -> EntityId;

    /// `merge` run with the host's useful-upstream decisions.
    ///
    /// # Errors
    ///
    /// Host-defined, and `merge`'s own.
    fn ask(
        &self,
        merge: &dyn Fn(&UsefulUpstreamDecisions<'_>) -> Result<SharedSkillMergeDisposition>,
    ) -> Result<SharedSkillMergeDisposition>;
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForkPromoteReport {
    /// Projects with settled teams of their own.
    pub projects: u32,
    /// Projects on the vault tree whose own receipts read a clear winner it
    /// does not.
    pub diverged: u32,
    /// Of those, the ones with no held-out run on the head yet: nothing to
    /// score, so nothing is forked.
    pub unscored: u32,
    /// Forks born this pass; the rest reused the project's open fork.
    pub minted: u32,
    /// Fork packages written with a changed tree.
    pub stored: u32,
    /// Forks scored against the head on their project's held-out runs.
    pub scored: u32,
    /// Of those, the ones that scored strictly above the head.
    pub won: u32,
    /// Forks put in force for their project.
    pub admitted: Vec<EntityId>,
    /// Forks a door refused (their birth, their package or their admission),
    /// that the judge abstained on, or whose package moved after it was
    /// scored; each waits for a later night.
    pub refused: u32,
    /// Live split leaves of the projects' own trees that the vault tree
    /// lacks, under a live parent it holds.
    pub leaves: u32,
    /// Of those, the ones that held up on runs elsewhere
    /// ([`PROJECT_LEAF_PROMOTES`] says how they are counted).
    pub held_up: u32,
    /// The revisions a merge put in force, each the vault head with one
    /// held-up leaf added to its tree.
    pub promoted: Vec<EntityId>,
    /// Held-up leaves whose merge waits on the owner's answer: it widens the
    /// skill's permissions, or the scan of its bytes asks for review.
    pub pending_consent: u32,
    /// Held-up leaves a door refused, that the judge abstained on, that the
    /// merge ruled out (not useful upstream, or no strict win on the replay),
    /// or whose same bytes a merge already ruled on; and leaves counted while
    /// a door refused the head's reserve, before any run was read.
    pub promote_refused: u32,
    /// Held-up leaves with nothing to rule them: no judge, no seat or agent
    /// to ask for, or no held-out run on the head yet.
    pub promote_unscored: u32,
    /// Revisions of a project's own tree, reshaped on its fit runs, scored
    /// against that tree on the project's held-out runs.
    pub upkeep_scored: u32,
    /// Of those, the ones put in force for their project.
    pub upkeep_admitted: u32,
    /// Revisions with nothing to rule them yet: no judge, no held-out run on
    /// the project's tree in force, or a judge that abstained. Each waits
    /// for a later night.
    pub upkeep_unscored: u32,
    /// Projects on a fork of their own whose tree a reshape on its fit runs
    /// leaves as it is, or reads the held-out decisions worse.
    pub upkeep_unchanged: u32,
    /// Revisions a door refused, or whose scored bindings moved before the
    /// write (each waits for a later night), and revisions retired because
    /// the tree they revise is no longer the project's.
    pub upkeep_refused: u32,
    /// The donor the pass lent its project tree reads (FIX 5176): the vault
    /// team-shape head in force and its tree version. `None` when no head is
    /// in force, and no project read borrowed.
    pub donor: Option<(EntityId, u64)>,
}

/// What one pass reads once.
struct Pass {
    attempt: AttemptId,
    actor: WriteActor,
    head: EntityId,
    head_record: SkillRecord,
    head_package: HubPackage,
    vault_tree: TaskTypeTree,
    /// The TASK each recorded team start ran.
    tasks: BTreeMap<String, String>,
    /// The open forks of the head (the projects' and their promote forks),
    /// by skill id.
    open: BTreeMap<String, EntityId>,
    /// Projects whose fork of the head the owner reverted.
    reverted: BTreeSet<EntityId>,
    now: u64,
}

impl Vault {
    /// The project tree fork pass as the Coach, under a leased
    /// `coach.fork_promote` attempt: group the settled teams by project, and
    /// for each visible project still on the vault tree whose own receipts
    /// read a clear winner the vault tree does not, store the vault tree's
    /// shape, counted on the project's fit runs alone, in the project's open
    /// fork of the team-shape head (minted when none is open), score it
    /// against the head on the project's held-out runs through `scorer`, and
    /// put a strict winner in force for the project when
    /// [`PROJECT_TREE_FORK_ADMITS`]. With no `scorer` nothing is forked.
    ///
    /// Then every project on a fork of its own, each project entity read to
    /// the end, has its tree reshaped on its own fit runs, and a changed
    /// shape is scored against that tree on the project's held-out runs
    /// through `scorer` ([`project_upkeep`]), with or without a vault head.
    ///
    /// Then, when [`PROJECT_LEAF_PROMOTES`] and a head is in force, each
    /// project on a fork of its own offers each leaf that holds up on runs
    /// elsewhere to the vault tree through the shared-skill merge: `upstream`
    /// asks the Coach's useful-upstream question and `scorer` replays the
    /// head's held-out runs. With either missing, a leaf that holds up is
    /// counted and nothing is offered.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's Coach attempt; storage errors; the
    /// scorer's errors and the outcome and merge doors' errors. A refusal of
    /// one project's fork or of one leaf's offer is counted in the report and
    /// the pass moves on.
    pub fn run_coach_fork_promote(
        &self,
        attempt: &DreamerAdmittedAttempt,
        scorer: Option<&dyn HeldOutReplayNotes>,
        upstream: Option<&dyn UpstreamSeat>,
        now: u64,
    ) -> Result<ForkPromoteReport> {
        self.require_coach_attempt(attempt, COACH_FORK_PROMOTE_FACET)?;
        let mut report = ForkPromoteReport::default();
        let pass = self.fork_pass(attempt, now)?;
        let settled: Vec<TeamReceipt> = team_receipts(self, None)?
            .into_iter()
            .filter(|receipt| receipt.outcome.is_some())
            .collect();
        let mut by_project: BTreeMap<EntityId, Vec<TeamReceipt>> = BTreeMap::new();
        for receipt in &settled {
            if let Some(project) = receipt.project {
                by_project.entry(project).or_default().push(receipt.clone());
            }
        }
        report.projects = u32::try_from(by_project.len()).unwrap_or(u32::MAX);
        // One donor for the pass: the vault's current tree on its own fit
        // runs, lent to every project tree read below.
        let donor = DonorTree::of_vault(self, &settled)?;
        report.donor = donor.as_ref().map(|donor| (donor.skill, donor.version));
        if let (Some(pass), Some(scorer)) = (&pass, scorer) {
            for (project, teams) in &by_project {
                let fork = fork_project(
                    self,
                    pass,
                    scorer,
                    *project,
                    teams,
                    donor.as_ref(),
                    &mut report,
                );
                match fork {
                    Ok(()) => {}
                    Err(Error::Artifact(ArtifactError::InvalidSkillBody(_))) => {
                        report.refused += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let projects = project_upkeep::run(
            self,
            attempt,
            scorer,
            &by_project,
            donor.as_ref(),
            now,
            &mut report,
        )?;
        if PROJECT_LEAF_PROMOTES && let Some(pass) = &pass {
            leaf_promote::run(
                self,
                pass,
                scorer.zip(upstream),
                projects,
                &settled,
                &mut report,
            )?;
        }
        Ok(report)
    }

    /// What a pass reads once: the in-force team-shape head with its package
    /// and tree, the TASK each team ran, the head's open forks and the
    /// projects whose fork of it the owner took back. `None` when no head is
    /// in force or it carries no package to fork.
    fn fork_pass(&self, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<Option<Pass>> {
        let Some(head) = team_shape_skill_in_force(self, None)? else {
            return Ok(None);
        };
        let head_record = self.get_skill_record(&head)?.ok_or(Error::EntityNotFound)?;
        let (head_package, reverted) = {
            let txn = self.store.env.read_txn()?;
            let Some(package) = self.runtime_skill_package_in_txn(&txn, &head, &head_record)?
            else {
                return Ok(None);
            };
            let mut reverted = BTreeSet::new();
            for (project, fork) in applied::reverted_project_tree_forks_in_txn(self, &txn)? {
                if self
                    .get_skill_record_in_txn(&txn, &fork)?
                    .is_some_and(|record| record.forked_from == Some(head))
                {
                    reverted.insert(project);
                }
            }
            (package, reverted)
        };
        let id = attempt.status.attempt.id;
        Ok(Some(Pass {
            attempt: id,
            actor: self.dreamer_actor_for_attempt(id)?,
            head,
            head_record,
            head_package,
            vault_tree: load_team_type_tree(self, None)?,
            tasks: team_run_tasks(self)?,
            open: open_forks(self, &head)?,
            reverted,
            now,
        }))
    }
}

/// One project's step of the pass. A project out of view, already on a fork
/// of its own, taken back by the owner from this head, or whose receipts
/// read no clear winner apart from the vault tree's is left as it is.
fn fork_project(
    vault: &Vault,
    pass: &Pass,
    scorer: &dyn HeldOutReplayNotes,
    project: EntityId,
    teams: &[TeamReceipt],
    donor: Option<&DonorTree>,
    report: &mut ForkPromoteReport,
) -> Result<()> {
    if pass.reverted.contains(&project)
        || load_team_type_tree(vault, Some(project))?.scope != TreeScope::Vault
    {
        return Ok(());
    }
    let visible = {
        let txn = vault.store.env.read_txn()?;
        vault.visible_project_in_txn(&txn, project)?.is_some()
    };
    if !visible {
        return Ok(());
    }
    let own = type_evidence(teams.to_vec(), &pass.tasks);
    let (own_tree, _) = recount(&pass.vault_tree, &own.iter().collect::<Vec<_>>());
    if !own_tree.diverges_from(&pass.vault_tree) {
        return Ok(());
    }
    report.diverged += 1;
    let reserve = record_team_shape_outcomes(vault, &pass.head, &pass.head_record, teams)?;
    let mut held_out: Vec<String> = reserve
        .held_out_teams
        .iter()
        .map(String::as_str)
        .filter_map(team_leader)
        .map(|leader| crate::receipt::attempt_pack_receipt_id(&leader))
        .collect();
    held_out.sort();
    held_out.dedup();
    if held_out.is_empty() {
        report.unscored += 1;
        return Ok(());
    }
    // The fork's counts are the project's fit runs alone: every team of a
    // leader whose pack receipt the head's reserve holds leaves before any
    // decision is read, whether or not this pass recorded it, and no
    // held-out count is carried.
    let reserved: BTreeSet<String> = held_out_receipts(vault, &pass.head)?.into_iter().collect();
    let fit: Vec<TeamReceipt> = teams
        .iter()
        .filter(|team| {
            !team_leader(&team.team_ref).is_some_and(|leader| {
                reserved.contains(&crate::receipt::attempt_pack_receipt_id(&leader))
            })
        })
        .cloned()
        .collect();
    let fit = type_evidence(fit, &pass.tasks);
    let mut tree = pass
        .vault_tree
        .fork_for_project(Some(project.to_hex()), false);
    for node in tree.nodes.values_mut() {
        node.held_out_runs = 0;
        node.held_out_wins = 0;
    }
    let (tree, _) = recount(&tree, &fit.iter().collect::<Vec<_>>());
    let fork = stored_fork(vault, pass, project, &tree, report)?;
    let fork_record = vault
        .get_skill_record(&fork)?
        .ok_or(Error::EntityNotFound)?;
    // The fork's thin leaves read with the pass's donor lent; the head's
    // vault tree reads as before.
    let judge = TreeReplayScorer::new(
        vault,
        scorer,
        &fork,
        &pass.head,
        pass.vault_tree.clone(),
        teams,
    )?
    .with_donor(donor);
    let judge: &dyn HeldOutReplayNotes = &judge;
    // A judge that abstains rules nothing: the fork stays open.
    let score = |record: &SkillRecord| -> Result<f32> {
        let score = judge
            .score(&HeldOutReplayCase {
                skill: pass.head,
                skill_id: &pass.head_record.skill_id,
                version: &record.version,
                instructions: &record.desc,
                held_out_receipts: &held_out,
            })
            .map_err(|error| match error {
                Error::InvalidConfig(_) => refused("the judge abstained on a project tree fork"),
                error => error,
            })?;
        if !(0.0..=1.0).contains(&score) {
            return Err(refused("invalid host held-out score"));
        }
        Ok(score)
    };
    let scores = (score(&pass.head_record)?, score(&fork_record)?);
    report.scored += 1;
    if scores.1 <= scores.0 {
        return Ok(());
    }
    report.won += 1;
    if !PROJECT_TREE_FORK_ADMITS {
        return Ok(());
    }
    let occurred = TimeRange {
        start: pass.now,
        end: pass.now,
    };
    let admitted = vault.with_write_txn_grouped(|txn| {
        // The bytes the judge read are the bytes that go in force.
        let current = vault.read_skill_record_in_txn(txn, &fork)?;
        if current.content_hash != fork_record.content_hash
            || current.version != fork_record.version
        {
            return Ok(false);
        }
        vault.admit_project_tree_fork_in_txn(txn, &fork, project, scores, occurred, pass.now)?;
        vault.append_project_skill_fork_in_txn(txn, project, fork, pass.now)?;
        applied::record_project_tree_fork_in_txn(
            vault,
            txn,
            project,
            fork,
            pass.attempt,
            COACH_FORK_PROMOTE_FACET,
            pass.actor,
            pass.now,
        )?;
        Ok(true)
    })?;
    if admitted {
        report.admitted.push(fork);
    } else {
        report.refused += 1;
    }
    Ok(())
}

/// The project's open fork of the head, minted when none is open, holding
/// `tree`: the head's package with only the tree and SKILL.md's `name:` and
/// `version:` lines changed. A package that already holds those bytes is not
/// written again; a changed one takes a version past its own and never the
/// head's, so the judge reads the two apart.
fn stored_fork(
    vault: &Vault,
    pass: &Pass,
    project: EntityId,
    tree: &TaskTypeTree,
    report: &mut ForkPromoteReport,
) -> Result<EntityId> {
    let skill_id = format!("{FORK_SKILL_PREFIX}{}", project.to_hex());
    let occurred = TimeRange {
        start: pass.now,
        end: pass.now,
    };
    let fork = match pass.open.get(&skill_id) {
        Some(fork) => *fork,
        None => {
            let fork = vault.store.clock.entity_id()?;
            vault.with_write_txn_grouped(|txn| {
                vault
                    .fork_skill_record_in_txn(txn, &pass.head, &fork, &skill_id, occurred, pass.now)
            })?;
            report.minted += 1;
            fork
        }
    };
    let (record, stored) = {
        let txn = vault.store.env.read_txn()?;
        let record = vault.read_skill_record_in_txn(&txn, &fork)?;
        let stored = vault.runtime_skill_package_in_txn(&txn, &fork, &record)?;
        (record, stored)
    };
    let tree = serde_json::to_vec_pretty(tree)
        .map_err(|_| refused("a project type tree does not encode"))?;
    let current = fork_files(&pass.head_package, &skill_id, &record.version, &tree)?;
    if record.version != pass.head_record.version
        && stored.is_some_and(|stored| by_path(&stored.files) == by_path(&current))
    {
        return Ok(fork);
    }
    let version = next_version(&record.version, &pass.head_record.version);
    let files = fork_files(&pass.head_package, &skill_id, &version, &tree)?;
    vault.write_shared_skill_fork_package(
        &fork,
        &HubPackage::new(record, files, pass.head_package.capabilities.clone()),
        occurred,
        pass.now,
    )?;
    report.stored += 1;
    Ok(fork)
}

/// Each open fork of `head` a project took, and each project's open promote
/// fork of it, by skill id; the last listed where a project has several.
fn open_forks(vault: &Vault, head: &EntityId) -> Result<BTreeMap<String, EntityId>> {
    let mut open = BTreeMap::new();
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_SKILL,
            after.as_ref(),
            SKILL_PAGE,
        )?;
        for id in &page {
            let Some(record) = vault.get_skill_record(id)? else {
                continue;
            };
            if record.lifecycle_status == SkillLifecycle::Candidate
                && record.forked_from == Some(*head)
                && (record.skill_id.starts_with(FORK_SKILL_PREFIX)
                    || record.skill_id.starts_with(PROMOTE_SKILL_PREFIX))
            {
                open.insert(record.skill_id, *id);
            }
        }
        if page.len() < SKILL_PAGE {
            return Ok(open);
        }
        after = page.last().copied();
    }
}

/// The head's files with the tree replaced by `tree` and SKILL.md's `name:`
/// and `version:` lines set to `name` and `version`.
fn fork_files(head: &HubPackage, name: &str, version: &str, tree: &[u8]) -> Result<Vec<HubFile>> {
    let mut files = Vec::with_capacity(head.files.len() + 1);
    for file in &head.files {
        if file.path == TASK_TYPE_TREE_FILE {
            continue;
        }
        if file.path == "SKILL.md" {
            let instructions = fork_instructions(&file.content, name, version)?;
            files.push(HubFile::new("SKILL.md", instructions));
        } else {
            files.push(file.clone());
        }
    }
    files.push(HubFile::new(TASK_TYPE_TREE_FILE, tree));
    Ok(files)
}

/// `head`, a SKILL.md, with its frontmatter `name:` and `version:` lines set
/// to `name` and `version` (a missing `version:` line is added last) and
/// every other byte kept.
fn fork_instructions(head: &[u8], name: &str, version: &str) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(head).map_err(|_| refused("the team-shape SKILL.md is not UTF-8"))?;
    let (front, body) = text
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .ok_or_else(|| refused("the team-shape SKILL.md has no frontmatter"))?;
    let line = |key: &str, value: &str| -> Result<String> {
        serde_json::to_string(value)
            .map(|value| format!("{key}: {value}\n"))
            .map_err(|_| refused("a fork's name or version does not encode"))
    };
    let mut out = String::from("---\n");
    let mut versioned = false;
    for entry in front.split('\n') {
        if entry.starts_with("name:") {
            out.push_str(&line("name", name)?);
        } else if entry.starts_with("version:") {
            versioned = true;
            out.push_str(&line("version", version)?);
        } else {
            out.push_str(entry);
            out.push('\n');
        }
    }
    if !versioned {
        out.push_str(&line("version", version)?);
    }
    out.push_str("---\n");
    out.push_str(body);
    Ok(out.into_bytes())
}

/// The version a changed fork package takes: past its own, and never the
/// head's.
fn next_version(current: &str, head: &str) -> String {
    let mut next = current
        .parse::<u64>()
        .map_or(1, |version| version.wrapping_add(1));
    loop {
        let version = next.to_string();
        if version != current && version != head {
            return version;
        }
        next = next.wrapping_add(1);
    }
}

/// Files by path, so two packages compare whatever their order.
fn by_path(files: &[HubFile]) -> BTreeMap<&str, &[u8]> {
    files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_slice()))
        .collect()
}

/// A refusal the pass counts and moves past: the project waits for a later
/// night.
fn refused(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

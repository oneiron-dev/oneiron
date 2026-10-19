//! Project tree upkeep (ARCH-0079 #task-type, OF-420): a project on a tree
//! of its own keeps reshaping it from its own receipts, as the vault tree is
//! reshaped, so the leaves its decisions split off reach the promote step.
//!
//! Every project entity is read to the end, with every project an open
//! journal row names. For each whose tree in force is a fork of its own,
//! each settled team is charged to that tree's reserve, and every team of a
//! leader the reserve holds leaves before any decision is read. The tree in
//! force is recounted on the project's fit runs and reshaped; a shape that
//! reads the fit's held-out decisions no worse is a change. A change is
//! minted once per body of evidence (the project's settled teams): a
//! Candidate forked from the tree in force, journaled with it in one write,
//! holding the reshaped tree counted on the fit runs alone, with no held-out
//! count carried. The host's judge scores it against the tree in force on
//! the project's held-out runs; a strict win puts it in force for the
//! project, with its OF-023 revert row and the journal's settlement, in one
//! transaction. The tree it revised stays active and listed behind it, so
//! the revert takes only the new revision off. A loss, a win, or the owner's
//! revert of the win settles that evidence for good; new teams name new
//! evidence. No judge, no held-out run yet, or a judge that abstains leaves
//! the revision open for a later night.
mod state;

use std::collections::{BTreeMap, BTreeSet};

use self::state::{StoredCandidate, UpkeepKey, UpkeepRow, UpkeepState};
use super::super::applied;
use super::super::coach::COACH_FORK_PROMOTE_FACET;
use super::super::type_tree_gate::{TreeReplayScorer, record_team_shape_outcomes, team_leader};
use super::super::type_tree_upkeep::{
    Reshape, TypeEvidence, fit_split, held_out_hits, recount, reshape, type_evidence,
};
use super::{
    FORK_SKILL_PREFIX, ForkPromoteReport, PROJECT_TREE_FORK_ADMITS, SKILL_PAGE, fork_files,
    next_version, refused,
};
use crate::agent_dispatch::{
    load_team_type_tree_in_txn, store_team_type_tree, team_shape_skill_in_force_in_txn,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::ArtifactError;
use crate::limit_ask::EngineLimit;
use crate::skill::SkillRecord;
use crate::skill_hub::HubPackage;
use crate::skill_optimize::{
    HeldOutReplayCase, HeldOutReplayNotes, held_out_receipts, receipt_is_held_out,
};
use crate::task_type::{TaskTypeTree, TreeScope};
use crate::team::TeamReceipt;
use crate::team::run_binding::team_run_tasks;
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// What the upkeep reads once a pass.
struct Upkeep<'a> {
    vault: &'a Vault,
    scorer: Option<&'a dyn HeldOutReplayNotes>,
    attempt: AttemptId,
    actor: WriteActor,
    /// The TASK each recorded team start ran.
    tasks: BTreeMap<String, String>,
    now: u64,
}

/// A project's own tree in force: its team-shape fork, with the record,
/// package and tree it carries, read in one snapshot.
struct Incumbent {
    id: EntityId,
    record: SkillRecord,
    package: HubPackage,
    tree: TaskTypeTree,
}

/// The upkeep over every project: each project entity, read page by page to
/// the end, each project an open journal row names and each project in
/// `by_project` (the settled teams, by project). A refusal of one project's
/// revision is counted and the pass moves on. Returns every project it
/// looked at, for the promote step.
///
/// # Errors
///
/// Storage errors; the scorer's errors other than an abstention; the doors'
/// errors other than a refusal.
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    scorer: Option<&dyn HeldOutReplayNotes>,
    by_project: &BTreeMap<EntityId, Vec<TeamReceipt>>,
    now: u64,
    report: &mut ForkPromoteReport,
) -> Result<BTreeSet<EntityId>> {
    let (mut projects, journal_rows) = state::pending_projects(vault)?;
    projects.extend(by_project.keys().copied());
    let scanned = scan_projects(vault, &mut projects)?;
    let _ = vault.measure_limit(
        EngineLimit::MaintenanceScanRows,
        journal_rows.saturating_add(scanned),
    );
    let id = attempt.status.attempt.id;
    let upkeep = Upkeep {
        vault,
        scorer,
        attempt: id,
        actor: vault.dreamer_actor_for_attempt(id)?,
        tasks: team_run_tasks(vault)?,
        now,
    };
    let mut largest = 0_usize;
    for project in &projects {
        let teams = by_project.get(project).map_or(&[][..], Vec::as_slice);
        largest = largest.max(teams.len());
        match upkeep.project(*project, teams, report) {
            Ok(()) => {}
            Err(Error::Artifact(
                ArtifactError::InvalidSkillBody(_) | ArtifactError::InvalidAgentDispatchInput(_),
            )) => report.upkeep_refused += 1,
            Err(error) => return Err(error),
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, largest as u64);
    Ok(projects)
}

/// Adds every project entity to `projects`, read page by page until a page
/// comes back short (a page, never a cap); returns how many it read. A vault
/// with no project kind holds no project.
fn scan_projects(vault: &Vault, projects: &mut BTreeSet<EntityId>) -> Result<u64> {
    let Ok(kind) = vault.project_type_byte() else {
        return Ok(0);
    };
    let mut read = 0_u64;
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(kind, after.as_ref(), SKILL_PAGE)?;
        read = read.saturating_add(page.len() as u64);
        projects.extend(page.iter().copied());
        if page.len() < SKILL_PAGE {
            return Ok(read);
        }
        after = page.last().copied();
    }
}

/// The project's own tree in force. `None` when the project is out of view
/// or on the vault tree.
fn incumbent(vault: &Vault, project: EntityId) -> Result<Option<Incumbent>> {
    let txn = vault.store.env.read_txn()?;
    let tree = load_team_type_tree_in_txn(vault, &txn, Some(project))?;
    let own = project.to_hex();
    if !matches!(&tree.scope, TreeScope::Project { project_ref: Some(of), .. } if *of == own) {
        return Ok(None);
    }
    let (Some(id), vault_head) = (
        team_shape_skill_in_force_in_txn(vault, &txn, Some(project))?,
        team_shape_skill_in_force_in_txn(vault, &txn, None)?,
    ) else {
        return Ok(None);
    };
    if vault_head == Some(id) {
        return Ok(None);
    }
    let record = vault.read_skill_record_in_txn(&txn, &id)?;
    let package = vault
        .runtime_skill_package_in_txn(&txn, &id, &record)?
        .ok_or_else(|| refused("a project's own tree in force carries no package"))?;
    Ok(Some(Incumbent {
        id,
        record,
        package,
        tree,
    }))
}

/// The skill id a revision takes: the project's fork prefix and 32 hex, then
/// `.upkeep.` and the evidence digest's 64 hex.
fn skill_id((project, digest): &UpkeepKey) -> String {
    format!(
        "{FORK_SKILL_PREFIX}{}.upkeep.{}",
        project.to_hex(),
        crate::entity_id::bytes_to_hex_lower(digest)
    )
}

/// The leader receipts the judge replays: each of the project's teams whose
/// leader receipt `reserve` holds, the reserve the revision was fit beside.
fn judged(held_out_teams: &BTreeSet<String>, reserve: &BTreeSet<String>) -> Vec<String> {
    let mut held_out: Vec<String> = held_out_teams
        .iter()
        .map(String::as_str)
        .filter_map(team_leader)
        .map(|leader| crate::receipt::attempt_pack_receipt_id(&leader))
        .filter(|receipt| reserve.contains(receipt))
        .collect();
    held_out.sort();
    held_out.dedup();
    held_out
}

/// `skill`'s reserve in `txn`, as the gate reads it.
fn reserve_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, skill: &EntityId) -> Result<Vec<String>> {
    Ok(
        crate::skill_reliability::attributed_outcome_receipts(vault, txn, skill)?
            .into_iter()
            .filter(|receipt| receipt_is_held_out(skill, receipt))
            .collect(),
    )
}

impl Upkeep<'_> {
    fn occurred(&self) -> TimeRange {
        TimeRange {
            start: self.now,
            end: self.now,
        }
    }

    /// One project's step. A project out of view or on the vault tree, or
    /// whose evidence a row already settled, is left as it is.
    fn project(
        &self,
        project: EntityId,
        teams: &[TeamReceipt],
        report: &mut ForkPromoteReport,
    ) -> Result<()> {
        let vault = self.vault;
        let Some(incumbent) = incumbent(vault, project)? else {
            return Ok(());
        };
        // Each settled team fills the reserve of the tree in force its leader
        // loaded, whatever this evidence's row says.
        let write = record_team_shape_outcomes(vault, &incumbent.id, &incumbent.record, teams)?;
        let key = (project, state::evidence_digest(teams, &self.tasks));
        let open = match state::row(vault, &key)? {
            // A loss, a win and the owner's revert of a win all stand for
            // this evidence.
            Some(row) if row.state != UpkeepState::Open => return Ok(()),
            Some(row) if row.incumbent != incumbent.id => {
                self.retire(&key, row, report)?;
                return Ok(());
            }
            row => row,
        };
        let reserve: BTreeSet<String> = match &open {
            Some(row) => row.reserve.iter().cloned().collect(),
            None => held_out_receipts(vault, &incumbent.id)?
                .into_iter()
                .collect(),
        };
        let Some(tree) = self.reshaped(&incumbent, teams, &reserve) else {
            match open {
                Some(row) => self.retire(&key, row, report)?,
                None => report.upkeep_unchanged += 1,
            }
            return Ok(());
        };
        let held_out = judged(&write.held_out_teams, &reserve);
        let Some(scorer) = self.scorer.filter(|_| !held_out.is_empty()) else {
            report.upkeep_unscored += 1;
            return Ok(());
        };
        let mut row = match open {
            Some(row) => row,
            None => self.mint(&key, &incumbent, reserve)?,
        };
        let Some(record) = self.stored(&key, &mut row, &incumbent, &tree)? else {
            self.retire(&key, row, report)?;
            return Ok(());
        };
        let judge = TreeReplayScorer::new(
            vault,
            scorer,
            &row.candidate,
            &incumbent.id,
            incumbent.tree.clone(),
            teams,
        )?;
        let judge: &dyn HeldOutReplayNotes = &judge;
        // The reserve as it stood when scored, which the write checks again.
        let scored_reserve = held_out_receipts(vault, &incumbent.id)?;
        let score = |record: &SkillRecord| -> Result<Option<f32>> {
            let case = HeldOutReplayCase {
                skill: incumbent.id,
                skill_id: &incumbent.record.skill_id,
                version: &record.version,
                instructions: &record.desc,
                held_out_receipts: &held_out,
            };
            match judge.score(&case) {
                Ok(score) if (0.0..=1.0).contains(&score) => Ok(Some(score)),
                Ok(_) => Err(refused("invalid host held-out score")),
                // A judge that abstains rules nothing: the revision stays open.
                Err(Error::InvalidConfig(_)) => Ok(None),
                Err(error) => Err(error),
            }
        };
        let Some(before) = score(&incumbent.record)? else {
            report.upkeep_unscored += 1;
            return Ok(());
        };
        let Some(after) = score(&record)? else {
            report.upkeep_unscored += 1;
            return Ok(());
        };
        report.upkeep_scored += 1;
        let scores = (before, after);
        if after <= before {
            let lost = row.settled(UpkeepState::Lost, Some(scores), self.now);
            return state::put(vault, &key, &lost);
        }
        if !PROJECT_TREE_FORK_ADMITS {
            return Ok(());
        }
        let admitted = vault.with_write_txn_grouped(|txn| {
            // What the judge scored is what goes in force: the project's tree
            // in force, the Candidate's stored bytes and the reserve.
            let current = vault.read_skill_record_in_txn(txn, &row.candidate)?;
            if team_shape_skill_in_force_in_txn(vault, txn, Some(project))? != Some(incumbent.id)
                || !row
                    .stored
                    .as_ref()
                    .is_some_and(|stored| stored.holds(&current))
                || reserve_in_txn(vault, txn, &incumbent.id)? != scored_reserve
            {
                return Ok(false);
            }
            vault.admit_project_tree_revision_in_txn(
                txn,
                &row.candidate,
                project,
                &incumbent.id,
                scores,
                self.occurred(),
                self.now,
            )?;
            vault.append_project_skill_fork_in_txn(txn, project, row.candidate, self.now)?;
            applied::record_project_tree_fork_in_txn(
                vault,
                txn,
                project,
                row.candidate,
                self.attempt,
                COACH_FORK_PROMOTE_FACET,
                self.actor,
                self.now,
            )?;
            let won = row
                .clone()
                .settled(UpkeepState::Won, Some(scores), self.now);
            state::put_in_txn(vault, txn, &key, &won)?;
            Ok(true)
        })?;
        if admitted {
            report.upkeep_admitted += 1;
        } else {
            report.upkeep_refused += 1;
        }
        Ok(())
    }

    /// Settles `row` as stale: the tree it revises is no longer the
    /// project's, or its Candidate is no longer what was stored or fit.
    fn retire(
        &self,
        key: &UpkeepKey,
        row: UpkeepRow,
        report: &mut ForkPromoteReport,
    ) -> Result<()> {
        report.upkeep_refused += 1;
        state::put(
            self.vault,
            key,
            &row.settled(UpkeepState::Stale, None, self.now),
        )
    }

    /// The revision `teams` ask of the project's tree in force: its shape
    /// recounted on the fit runs (every team of a leader `reserve` holds left
    /// out first) and reshaped, kept when it reads the fit's held-out
    /// decisions no worse, then counted on every fit run with no held-out
    /// count carried. `None` when the shape does not change.
    fn reshaped(
        &self,
        incumbent: &Incumbent,
        teams: &[TeamReceipt],
        reserve: &BTreeSet<String>,
    ) -> Option<TaskTypeTree> {
        let fit: Vec<TeamReceipt> = teams
            .iter()
            .filter(|team| {
                !team_leader(&team.team_ref).is_some_and(|leader| {
                    reserve.contains(&crate::receipt::attempt_pack_receipt_id(&leader))
                })
            })
            .cloned()
            .collect();
        let pool = type_evidence(fit, &self.tasks);
        let (held_out, fit) = fit_split(&pool, &incumbent.id);
        let (in_force, _) = recount(&incumbent.tree, &fit);
        let mut shaped = in_force.clone();
        if reshape(&mut shaped) == Reshape::default()
            || held_out_hits(&shaped, &held_out) < held_out_hits(&in_force, &held_out)
        {
            return None;
        }
        let all: Vec<&TypeEvidence> = pool.iter().collect();
        let (mut tree, _) = recount(&shaped, &all);
        for node in tree.nodes.values_mut() {
            node.held_out_runs = 0;
            node.held_out_wins = 0;
        }
        Some(tree)
    }

    /// Mints the Candidate for `key`, a fork of the tree in force, and
    /// journals it, in one write. A row a concurrent pass journaled first is
    /// the one returned.
    fn mint(
        &self,
        key: &UpkeepKey,
        incumbent: &Incumbent,
        reserve: BTreeSet<String>,
    ) -> Result<UpkeepRow> {
        let vault = self.vault;
        let candidate = vault.store.clock.entity_id()?;
        let skill_id = skill_id(key);
        let row = UpkeepRow::open(incumbent.id, candidate, reserve, self.now);
        vault.with_write_txn_grouped(|txn| {
            if let Some(row) = state::row_in_txn(vault, txn, key)? {
                return Ok(row);
            }
            vault.fork_skill_record_in_txn(
                txn,
                &incumbent.id,
                &candidate,
                &skill_id,
                self.occurred(),
                self.now,
            )?;
            state::put_in_txn(vault, txn, key, &row)?;
            Ok(row)
        })
    }

    /// The Candidate `row` names, holding `tree`: the tree in force's package
    /// with only the tree and SKILL.md's `name:` and `version:` lines
    /// changed, at a version past its own and never the tree in force's, the
    /// tree then stored through the type-tree door, which keeps a version
    /// another kept structure uses from being reused. What was stored is
    /// journaled, so a later night reads that Candidate rather than writing
    /// it again. `None` when the Candidate is gone or no longer what was
    /// stored.
    fn stored(
        &self,
        key: &UpkeepKey,
        row: &mut UpkeepRow,
        incumbent: &Incumbent,
        tree: &TaskTypeTree,
    ) -> Result<Option<SkillRecord>> {
        let vault = self.vault;
        let Some(record) = vault.get_skill_record(&row.candidate)? else {
            return Ok(None);
        };
        if let Some(stored) = &row.stored {
            return Ok(stored.holds(&record).then_some(record));
        }
        let content = serde_json::to_vec_pretty(tree)
            .map_err(|_| refused("a project type tree does not encode"))?;
        let version = next_version(&record.version, &incumbent.record.version);
        let files = fork_files(&incumbent.package, &skill_id(key), &version, &content)?;
        vault.write_shared_skill_fork_package(
            &row.candidate,
            &HubPackage::new(record, files, incumbent.package.capabilities.clone()),
            self.occurred(),
            self.now,
        )?;
        store_team_type_tree(vault, row.candidate, tree, Some(key.0), self.now)?;
        let record = vault
            .get_skill_record(&row.candidate)?
            .ok_or(Error::EntityNotFound)?;
        row.stored = Some(StoredCandidate::of(&record));
        state::put(vault, key, row)?;
        Ok(Some(record))
    }
}

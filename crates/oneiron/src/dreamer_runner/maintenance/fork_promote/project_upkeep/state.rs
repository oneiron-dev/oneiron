//! The project tree upkeep journal: one row per project and body of its
//! evidence, naming the Candidate revision minted for it, the project's tree
//! in force it revises, the reserve its fit left out, what was stored and
//! scored, what the project's goal said of a scalar win and why (FIX 8706),
//! and how it settled. The tree bytes live in the Candidate's package
//! alone. A settled row keeps its evidence from minting again.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::admission::UpkeepGoal;
use crate::side_table::{self, Named, SideTable};
use crate::skill::SkillRecord;
use crate::team::TeamReceipt;
use crate::{EntityId, Result, Vault};

/// A project and the digest of a body of its evidence.
pub(super) type UpkeepKey = (EntityId, [u8; 32]);

const JOURNAL: SideTable<UpkeepKey, UpkeepRow, Named> =
    SideTable::new(&side_table::DREAMER_PROJECT_TREE_UPKEEP);

/// Domain separator for the evidence digest.
const EVIDENCE_DOMAIN: &[u8] = b"oneiron:project-tree-upkeep:evidence:v1\0";

/// Where one revision stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UpkeepState {
    /// Minted and journaled; its package, its scoring or its admission waits.
    Open,
    /// Scored strictly above the tree it revises and put in force for the
    /// project. The owner's revert of it leaves the row as it is.
    Won,
    /// Scored no better than the tree it revises.
    Lost,
    /// The tree it revises is no longer the project's, or the Candidate is
    /// no longer what was stored: it can never go in force.
    Stale,
}

/// The Candidate's record as its package was stored: what the judge reads
/// and the admission binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredCandidate {
    version: String,
    content_hash: Option<[u8; 32]>,
}

impl StoredCandidate {
    pub(super) fn of(record: &SkillRecord) -> Self {
        Self {
            version: record.version.clone(),
            content_hash: record.content_hash.map(|hash| *hash.as_bytes()),
        }
    }

    /// Whether `record` is still the stored one.
    pub(super) fn holds(&self, record: &SkillRecord) -> bool {
        *self == Self::of(record)
    }
}

/// One revision of a project's own tree, for one body of its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpkeepRow {
    /// The project's tree in force the Candidate was forked from.
    pub(super) incumbent: EntityId,
    pub(super) candidate: EntityId,
    /// The incumbent's reserve when the Candidate was fit: every team of
    /// these leaders was left out of its fit, and only these are judged.
    pub(super) reserve: Vec<String>,
    /// The Candidate as its package was stored, once it was.
    pub(super) stored: Option<StoredCandidate>,
    pub(super) state: UpkeepState,
    /// The incumbent's and the Candidate's held-out scores, once scored.
    pub(super) scores: Option<(f32, f32)>,
    pub(super) opened_at: u64,
    pub(super) settled_at: Option<u64>,
    /// What the project's goal said of the Candidate's scalar win, and why;
    /// `None` until a win was put to it.
    pub(super) goal: Option<UpkeepGoal>,
}

impl UpkeepRow {
    /// An open row for `candidate`, a fork of `incumbent` fit beside
    /// `reserve`.
    pub(super) fn open(
        incumbent: EntityId,
        candidate: EntityId,
        reserve: BTreeSet<String>,
        at: u64,
    ) -> Self {
        Self {
            incumbent,
            candidate,
            reserve: reserve.into_iter().collect(),
            stored: None,
            state: UpkeepState::Open,
            scores: None,
            opened_at: at,
            settled_at: None,
            goal: None,
        }
    }

    /// This row settled as `state` at `at`.
    #[must_use]
    pub(super) fn settled(
        mut self,
        state: UpkeepState,
        scores: Option<(f32, f32)>,
        at: u64,
    ) -> Self {
        self.state = state;
        self.scores = scores.or(self.scores);
        self.settled_at = Some(at);
        self
    }
}

/// The digest naming one body of a project's evidence: each of its settled
/// teams by ref, with all a decision is read from (its type, pattern, models,
/// outcome and time, and the TASK it ran). Neither the pass's time nor the
/// tree in force enters it, so the same teams name the same evidence
/// whatever went in force since.
pub(super) fn evidence_digest(teams: &[TeamReceipt], tasks: &BTreeMap<String, String>) -> [u8; 32] {
    let settled: BTreeMap<&str, &TeamReceipt> = teams
        .iter()
        .filter(|team| team.outcome.is_some())
        .map(|team| (team.team_ref.as_str(), team))
        .collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVIDENCE_DOMAIN);
    for (team_ref, team) in settled {
        field(&mut hasher, team_ref.as_bytes());
        field(&mut hasher, team.type_ref.node_id.as_bytes());
        hasher.update(&team.type_ref.tree_version.to_be_bytes());
        field(&mut hasher, team.pattern.as_str().as_bytes());
        hasher.update(&(team.models.len() as u64).to_be_bytes());
        for model in &team.models {
            field(&mut hasher, model.as_bytes());
        }
        let success = team.outcome.as_ref().is_some_and(|outcome| outcome.success);
        hasher.update(&[u8::from(success)]);
        hasher.update(&team.at.to_be_bytes());
        match tasks.get(team_ref) {
            Some(task) => {
                hasher.update(&[1]);
                field(&mut hasher, task.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// One length-prefixed field of the digest.
fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// The row `key` names.
pub(super) fn row(vault: &Vault, key: &UpkeepKey) -> Result<Option<UpkeepRow>> {
    let txn = vault.store.env.read_txn()?;
    row_in_txn(vault, &txn, key)
}

pub(super) fn row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &UpkeepKey,
) -> Result<Option<UpkeepRow>> {
    JOURNAL.get(&vault.store, txn, key)
}

pub(super) fn put(vault: &Vault, key: &UpkeepKey, row: &UpkeepRow) -> Result<()> {
    vault.with_write_txn_grouped(|txn| put_in_txn(vault, txn, key, row))
}

pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &UpkeepKey,
    row: &UpkeepRow,
) -> Result<()> {
    JOURNAL.put(&vault.store, txn, key, row)
}

/// The projects with an open row, and how many rows the read went through.
pub(super) fn pending_projects(vault: &Vault) -> Result<(BTreeSet<EntityId>, u64)> {
    let txn = vault.store.env.read_txn()?;
    let mut projects = BTreeSet::new();
    let mut read = 0_u64;
    for entry in JOURNAL.iter_from(&vault.store, &txn, &[])? {
        let ((project, _), row) = entry?;
        read = read.saturating_add(1);
        if row.state == UpkeepState::Open {
            projects.insert(project);
        }
    }
    Ok((projects, read))
}

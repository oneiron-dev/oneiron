//! Born-from (ARCH-0078 section 4): every artifact answers "born from what"
//! the same way. An artifact's first version stamps the artifact row's birth
//! (`provenance::birth`, so [`Vault::rows_born_from`] lists the artifacts a
//! task, ask, run or skill produced). This index is the version-level
//! complement over the version ledger: the trigger in every version's
//! made_by, and the agent run in its provenance, read backwards, so a task
//! also lists the versions it made of artifacts it did not create.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::provenance::made_by::MadeByTrigger;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::versions::{BlobArtifactVersion, VERSIONS};

const SOURCE_TASK: u8 = b't';
const SOURCE_ASK: u8 = b'a';
const SOURCE_CODE_RUN: u8 = b'c';
const SOURCE_SKILL: u8 = b's';
const SOURCE_AGENT_RUN: u8 = b'r';

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BornFromRow {
    at: u64,
}

/// Key: source (kind byte + id16 or run-ref hash prefix) + artifact + version.
const BORN_FROM: SideTable<([u8; 17], EntityId, u64), BornFromRow, Named> =
    SideTable::new(&side_table::BLOB_ARTIFACT_BORN_FROM);

/// What a version was born from: the trigger in its made_by, or the agent
/// run its provenance names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BornFromSource {
    /// The task, ask, code-mode run or skill in the version's made_by.
    Trigger(MadeByTrigger),
    /// The agent run named by the version's provenance.
    AgentRun(String),
}

impl BornFromSource {
    fn key(&self) -> [u8; 17] {
        let mut key = [0u8; 17];
        match self {
            Self::Trigger(trigger) => {
                key[0] = match trigger {
                    MadeByTrigger::Task(_) => SOURCE_TASK,
                    MadeByTrigger::Ask(_) => SOURCE_ASK,
                    MadeByTrigger::Run(_) => SOURCE_CODE_RUN,
                    MadeByTrigger::Skill(_) => SOURCE_SKILL,
                };
                key[1..].copy_from_slice(trigger.row().as_bytes());
            }
            Self::AgentRun(run_ref) => {
                key[0] = SOURCE_AGENT_RUN;
                key[1..].copy_from_slice(&blake3::hash(run_ref.as_bytes()).as_bytes()[..16]);
            }
        }
        key
    }

    /// Every source one version names, trigger first.
    #[must_use]
    pub fn of_version(version: &BlobArtifactVersion) -> Vec<Self> {
        let mut sources = Vec::with_capacity(2);
        if let Some(trigger) = &version.made_by.trigger {
            sources.push(Self::Trigger(trigger.clone()));
        }
        if let Some(run_ref) = version.provenance.run_ref() {
            sources.push(Self::AgentRun(run_ref.to_owned()));
        }
        sources
    }
}

/// One artifact version a source produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BornFromArtifact {
    pub artifact_id: EntityId,
    pub version: u64,
    pub at: u64,
}

/// Indexes one freshly appended version under each source it names.
pub(super) fn index_version_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact_id: &EntityId,
    version: &BlobArtifactVersion,
) -> Result<()> {
    for source in BornFromSource::of_version(version) {
        BORN_FROM.put(
            store,
            wtxn,
            &(source.key(), *artifact_id, version.version),
            &BornFromRow {
                at: version.created_at,
            },
        )?;
    }
    Ok(())
}

/// Drops one version's index rows, for the artifact delete path.
pub(super) fn unindex_version_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact_id: &EntityId,
    version: &BlobArtifactVersion,
) -> Result<()> {
    for source in BornFromSource::of_version(version) {
        BORN_FROM.delete(store, wtxn, &(source.key(), *artifact_id, version.version))?;
    }
    Ok(())
}

impl Vault {
    /// The artifact versions a task, ask, run or skill produced, in artifact
    /// then version order. A deleted artifact's rows go with it; a version
    /// that no longer exists is still not listed, and a run-ref hash collision
    /// is filtered by the version's own provenance.
    pub fn artifacts_born_from(&self, source: &BornFromSource) -> Result<Vec<BornFromArtifact>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in BORN_FROM.iter_from(&self.store, &rtxn, &source.key())? {
            let ((_, artifact_id, version), row) = row?;
            if live_version_names(&self.store, &rtxn, &artifact_id, version, source)? {
                out.push(BornFromArtifact {
                    artifact_id,
                    version,
                    at: row.at,
                });
            }
        }
        Ok(out)
    }

    /// The other direction: each version of one artifact with the sources it
    /// was born from, read from the versions' own made_by and provenance.
    pub fn blob_artifact_born_from(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<(u64, Vec<BornFromSource>)>> {
        Ok(self
            .blob_artifact_versions(artifact_id)?
            .iter()
            .map(|version| (version.version, BornFromSource::of_version(version)))
            .collect())
    }
}

fn live_version_names(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
    version: u64,
    source: &BornFromSource,
) -> Result<bool> {
    Ok(VERSIONS
        .get(store, rtxn, &(*artifact_id, version))?
        .is_some_and(|record| BornFromSource::of_version(&record).contains(source)))
}

/// OF-222 (FIX 2768) archive seam: the born-from projection a whole-vault archive carries
/// beside each version it reads back from, lent with its own key type and codec.
pub(crate) fn archive_born_from_table() -> crate::batch::export::LentSideTable {
    &BORN_FROM
}

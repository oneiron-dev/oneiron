//! Who may name and who may read a waiting proposal's sources.
//!
//! Retention (FIX 1229): a made_by envelope a writer names is admitted in the
//! transaction that retains it, through the writing credential's own lane.
//! Its process actor, unless that is the writer itself, every input row and
//! an entity trigger must each resolve for that lane, and any trigger must be
//! live, so a Run trigger is checked against its replay record and is never
//! read as an entity. A ref that does not resolve refuses the retention by
//! name, in the same words whether the row is missing or withheld.
//!
//! Listing (FIX 8063): a narrowed reader sees a waiting proposal only when
//! its lane admits the proposal's sources: the artifact, the version it was
//! made against, and each source its made_by names.

use super::{PENDING, PendingProposalView, PendingRow};
use crate::Vault;
use crate::claim::ScopedRead;
use crate::edit_settle::codec::RECORD;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::{MadeBy, MadeByTrigger};

/// Whose read a retained proposal's named made_by envelope is admitted
/// under, in the transaction that retains it (FIX 1229).
pub enum MadeByReader<'v> {
    /// The writing credential's own lane. A named envelope's process actor,
    /// unless it is the writer itself, every input row and an entity trigger
    /// must each resolve through it. Its records check covers the proposal's
    /// own artifact's version rows alone (FIX 8245); every other check
    /// still judges each of them.
    Lane(ScopedRead<'v>),
    /// No credential reaches this rail: an organ host's landed or redriven
    /// output that no principal submitted, whose envelope the host built
    /// from its own call receipt. It is kept unadmitted, as before; a
    /// submitted call's output is admitted through its submitter's lane
    /// (`Vault::organ_landing_reader`, FIX 9310).
    OrganReceipt,
}

/// The lane a retention admits `made_by` through, its records check covering
/// `artifact_id`'s own version rows; `None` when nothing is admitted. An
/// envelope that names no row but its writer `writer` needs no read. Any
/// other with no reader is refused: no envelope waits unadmitted unless an
/// organ host built it.
pub(super) fn retention_lane<'v>(
    artifact_id: &EntityId,
    made_by: Option<&MadeBy>,
    writer: EntityId,
    reader: Option<MadeByReader<'v>>,
) -> Result<Option<ScopedRead<'v>>> {
    let names_only_writer = |made_by: &MadeBy| {
        made_by.process.actor == writer && made_by.inputs.is_empty() && made_by.trigger.is_none()
    };
    match (made_by, reader) {
        (None, _) | (Some(_), Some(MadeByReader::OrganReceipt)) => Ok(None),
        (Some(made_by), _) if names_only_writer(made_by) => Ok(None),
        (Some(_), Some(MadeByReader::Lane(lane))) => {
            lane.persist_grant_clock()?;
            Ok(Some(lane.with_artifact_records_cover(&[*artifact_id])))
        }
        (Some(_), None) => Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "a named made_by is admitted through the writing credential's read, and none \
             reached this proposal",
        ))),
    }
}

/// Admits a named `made_by` for `lane` in the retaining transaction `rtxn`,
/// under one live policy (FIX 1229). `writer` is the retaining actor, who may
/// always name itself as the process.
pub(super) fn admit_made_by_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    lane: &ScopedRead<'_>,
    made_by: &MadeBy,
    writer: EntityId,
) -> Result<()> {
    let policy = lane.live_policy_manifest_in(rtxn)?;
    let resolves = |id: &EntityId| lane.is_ref_readable_with_policy_in(rtxn, &policy, id);
    let unreadable =
        |field, row| Error::Artifact(ArtifactError::MadeByRefUnreadable { field, row });
    let actor = made_by.process.actor;
    if actor != writer && !resolves(&actor)? {
        return Err(unreadable("process actor", actor));
    }
    for input in &made_by.inputs {
        if !resolves(&input.row)? {
            return Err(unreadable("input", input.row));
        }
    }
    if let Some(trigger) = &made_by.trigger {
        let named = trigger.row();
        let entity = !matches!(trigger, MadeByTrigger::Run(_));
        if (entity && !resolves(&named)?)
            || !crate::provenance::birth::trigger_is_live_in_txn(&vault.store, rtxn, trigger)?
        {
            return Err(unreadable("trigger", named));
        }
    }
    Ok(())
}

impl Vault {
    /// [`Vault::pending_proposals`] for `lane` (FIX 8063). A proposal is
    /// listed only when the lane admits, in one snapshot under one live
    /// policy, the artifact, the version it was made against (that version's
    /// CLAIM and content ASSET; a lane that opted into its artifact's records
    /// cover covers those), and each source its made_by names: every input
    /// row and an entity trigger. A Run trigger is a replay record, no row a
    /// reader reads. A withheld proposal leaves no trace: no ref, count, hash,
    /// actor or time of it. An artifact the lane withholds lists nothing.
    pub fn pending_proposals_scoped(
        &self,
        lane: &ScopedRead<'_>,
        artifact_id: &EntityId,
    ) -> Result<Vec<PendingProposalView>> {
        lane.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = lane.live_policy_manifest_in(&rtxn)?;
        let admits = |id: &EntityId| lane.is_ref_readable_with_policy_in(&rtxn, &policy, id);
        if !admits(artifact_id)? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for row in PENDING.iter_from(&self.store, &rtxn, artifact_id.as_bytes())? {
            let ((artifact, key), row) = row?;
            if RECORD.contains(&self.store, &rtxn, &(artifact, key))? {
                continue;
            }
            let Some(sources) = self.pending_sources_in_txn(&rtxn, &artifact, &row)? else {
                continue;
            };
            let mut admitted = true;
            for source in &sources {
                if !admits(source)? {
                    admitted = false;
                    break;
                }
            }
            if admitted {
                out.push(row.view(artifact));
            }
        }
        Ok(out)
    }

    /// The rows a waiting proposal was made from, read in `rtxn`: its base
    /// version's rows, then its made_by's inputs and entity trigger. `None`
    /// when its base version is gone, so nothing can admit it.
    fn pending_sources_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        row: &PendingRow,
    ) -> Result<Option<Vec<EntityId>>> {
        let mut sources = Vec::new();
        if let Some(version) = row.base_version {
            let Some(rows) = self.blob_artifact_version_rows_in_txn(rtxn, artifact, version)?
            else {
                return Ok(None);
            };
            sources.extend(rows);
        }
        if let Some(made_by) = &row.made_by {
            sources.extend(made_by.inputs.iter().map(|input| input.row));
            if let Some(trigger) = &made_by.trigger
                && !matches!(trigger, MadeByTrigger::Run(_))
            {
                sources.push(trigger.row());
            }
        }
        Ok(Some(sources))
    }
}

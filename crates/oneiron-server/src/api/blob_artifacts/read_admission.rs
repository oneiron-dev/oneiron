//! The lanes the artifact family's raw reads admit rows through (FIX 7645):
//! a credential's record caveats, honoured row by row. A records caveat that
//! names an artifact covers its own version rows for the records check alone
//! (FIX 8245, `ScopedRead::with_artifact_records_cover`); every other check
//! still judges each of them.

use oneiron::EntityId;
use oneiron::blob_artifact::{BornFromArtifact, BornFromSource};
use oneiron::claim::ScopedRead;

use crate::auth::CoreAuth;
use crate::error::ApiError;

/// The lane a credential's record caveats are honoured through on these raw
/// reads (FIX 7645): its own scoped read, which admits only the rows its
/// grant does, a withheld row reading as a missing one. `None` for a
/// credential that carries no record caveat, the owner's own root among
/// them: its reads answer as they always have.
pub(super) fn caveat_lane<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<Option<ScopedRead<'a>>, ApiError> {
    if auth.require_unrestricted_record_scope().is_ok() {
        return Ok(None);
    }
    crate::api::scoped_read_for_core_auth(vault, auth).map(Some)
}

/// What a born-from answer keeps for a credential with record caveats (FIX
/// 7645): nothing when the trigger it names is withheld; else each born row
/// its lane admits, and each version whose artifact, CLAIM and content ASSET
/// it admits, all judged in one snapshot. The lane's records check covers
/// the listed artifacts' own version rows alone (FIX 8245); a version a
/// check withholds is dropped by itself. A withheld row leaves no trace: no
/// count, time or ref of it.
pub(super) fn admitted_born_from(
    vault: &oneiron::Vault,
    lane: ScopedRead<'_>,
    source: &BornFromSource,
    born: Vec<EntityId>,
    versions: Vec<BornFromArtifact>,
) -> oneiron::Result<(Vec<EntityId>, Vec<BornFromArtifact>)> {
    let mut sets = Vec::with_capacity(born.len().saturating_add(versions.len()).saturating_add(1));
    if let BornFromSource::Trigger(trigger) = source {
        sets.push(vec![trigger.row()]);
    }
    sets.extend(born.iter().map(|id| vec![*id]));
    let mut listed = Vec::with_capacity(versions.len());
    for found in versions {
        // A version gone since the index was read is not listed.
        if let Some((_, rows)) =
            vault.blob_artifact_version_rows(&found.artifact_id, Some(found.version))?
        {
            sets.push(std::iter::once(found.artifact_id).chain(rows).collect());
            listed.push(found);
        }
    }
    let artifacts: Vec<EntityId> = listed.iter().map(|found| found.artifact_id).collect();
    let lane = lane.with_artifact_records_cover(&artifacts);
    let mut admitted = lane.refs_readable_each(&sets)?.into_iter();
    if matches!(source, BornFromSource::Trigger(_)) && admitted.next() != Some(true) {
        return Ok((Vec::new(), Vec::new()));
    }
    let born = born
        .into_iter()
        .zip(admitted.by_ref())
        .filter_map(|(id, kept)| kept.then_some(id))
        .collect();
    let versions = listed
        .into_iter()
        .zip(admitted)
        .filter_map(|(found, kept)| kept.then_some(found))
        .collect();
    Ok((born, versions))
}

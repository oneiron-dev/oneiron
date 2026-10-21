//! The lanes the artifact family's raw reads admit rows through (FIX 7645,
//! FIX 8068): a credential's record caveats, honoured row by row.

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

/// Whether the credential's records caveat names `artifact` (FIX 8068,
/// Engine 10-22): such a caveat covers that artifact's own version CLAIM and
/// ASSET rows, so they count as admitted once its lane admits the artifact.
/// Every other row, another artifact's versions and a trigger's born rows
/// among them, is judged by the lane as before.
pub(super) fn records_name(auth: &CoreAuth, artifact: &EntityId) -> bool {
    auth.verified_slip()
        .is_some_and(|proof| proof.claims().records.contains(&artifact.to_hex()))
}

/// The rows a credential's lane judges for one version of `artifact`: the
/// artifact alone where its records caveat names it ([`records_name`]),
/// else the artifact and the version's own `rows`.
pub(super) fn version_sources(
    auth: &CoreAuth,
    artifact: EntityId,
    rows: Vec<EntityId>,
) -> Vec<EntityId> {
    if records_name(auth, &artifact) {
        return vec![artifact];
    }
    std::iter::once(artifact).chain(rows).collect()
}

/// What a born-from answer keeps for a credential with record caveats (FIX
/// 7645): nothing when the trigger it names is withheld; else each born row
/// its lane admits, and each version whose artifact, CLAIM and content ASSET
/// it admits (the artifact alone where its records caveat names it, FIX
/// 8068), all judged in one snapshot. A withheld row leaves no trace: no
/// count, time or ref of it.
pub(super) fn admitted_born_from(
    vault: &oneiron::Vault,
    lane: &ScopedRead<'_>,
    auth: &CoreAuth,
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
            sets.push(version_sources(auth, found.artifact_id, rows));
            listed.push(found);
        }
    }
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

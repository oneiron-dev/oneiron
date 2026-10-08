//! What the publication and build-cache doors admit of a retained output by
//! the secrets that tainted it: a stale taint holds its publication unless
//! the stale-publish dial is open, and any taint holds its cached result.
use super::{Decision, held_by_both};
use crate::blob_artifact::BlobArtifactVersion;
use crate::codebase::{CodebaseForkHash, codebase_artifact_snapshot_matches_in_txn};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CODE_ARTIFACT};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// The version chain of every blob artifact, read for its keys alone.
const VERSIONS: SideTable<(EntityId, u64), BlobArtifactVersion, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_VERSION);

/// Whether a retained output may be published, and whether a cached result
/// naming it may be stored or hit, as its taint decides: the refs its
/// sidecar and its blob body carry (`exhaust_taint_refs_in_txn`), classified
/// against the custody records as they stand (`taint_state_for_refs_in_txn`).
/// Publication admits a clean or live-tainted output, and a stale-tainted one
/// only under the stale-publish dial (`allow_stale_publish_in_txn`); the
/// cache admits a clean blob version only. A taint attached since the backup
/// to an output the backup holds unchanged is one a restore would drop,
/// admitting the output again.
pub(super) struct ArtifactTaints;

/// A retained output a door admits by its taint.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum TaintSubject {
    /// A code artifact, served as its snapshot of one project at one fork.
    Code(EntityId, String, CodebaseForkHash),
    /// One version of a blob artifact, which a cached result names.
    Blob(EntityId, u64),
}

/// What the doors admit of one output.
pub(super) struct TaintAdmission {
    publish: bool,
    cache: bool,
}

impl Decision for ArtifactTaints {
    type Subject = TaintSubject;
    type Answer = TaintAdmission;

    /// Each code snapshot both vaults hold for the same artifact, project and
    /// fork, where either serves it, and each version of a blob artifact both
    /// vaults hold. An output, snapshot or version only one vault holds
    /// returns or leaves with the restore, its taint with it.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<TaintSubject>> {
        let code = held_by_both(vaults, ENTITY_TYPE_CODE_ARTIFACT)?;
        let blobs = held_by_both(vaults, ENTITY_TYPE_BLOB_ARTIFACT)?;
        let [live, restored] = vaults.map(|vault| outputs(vault, &code, &blobs));
        let restored = restored?;
        Ok(live?
            .into_iter()
            .filter_map(|(output, served)| {
                let served_restored = restored.get(&output)?;
                (served || *served_restored).then_some(output)
            })
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<TaintSubject>,
    ) -> Result<Vec<Option<TaintAdmission>>> {
        let txn = vault.store.env.read_txn()?;
        let mut stale_publish = None;
        Ok(subjects
            .iter()
            .map(|subject| {
                admission(vault, &txn, subject, &mut stale_publish)
                    .ok()
                    .flatten()
            })
            .collect())
    }

    fn loosens(live: &TaintAdmission, restored: &TaintAdmission) -> bool {
        (!live.publish && restored.publish) || (!live.cache && restored.cache)
    }

    fn refusal() -> Option<TaintAdmission> {
        Some(TaintAdmission {
            publish: false,
            cache: false,
        })
    }
}

/// The outputs among `code` and `blobs` that `vault` holds, each with whether
/// a door serves it there: a code snapshot whose artifact is hostable, and
/// every blob version, which a cached result can name.
fn outputs(
    vault: &Vault,
    code: &BTreeSet<EntityId>,
    blobs: &BTreeSet<EntityId>,
) -> Result<BTreeMap<TaintSubject, bool>> {
    let txn = vault.store.env.read_txn()?;
    let mut held = BTreeMap::new();
    for id in code {
        if let Some(snapshot) = vault.get_codebase_snapshot_in_txn(&txn, id)? {
            // A hostability check that fails serves the output: its taint is
            // still compared.
            let served = codebase_artifact_snapshot_matches_in_txn(
                &vault.store,
                &txn,
                id,
                &snapshot.project_id,
                &snapshot.fork_hash,
            )
            .unwrap_or(true);
            held.insert(
                TaintSubject::Code(*id, snapshot.project_id, snapshot.fork_hash),
                served,
            );
        }
    }
    for id in blobs {
        for (artifact, version) in VERSIONS.scan_keys(&vault.store, &txn, id.as_bytes())? {
            if artifact == *id && version != 0 {
                held.insert(TaintSubject::Blob(artifact, version), true);
            }
        }
    }
    Ok(held)
}

/// What the doors admit of `subject` in `txn`, the stale-publish dial read
/// once into `stale_publish` and only for a stale taint, as the publication
/// door reads it; `None` where `vault` no longer holds the snapshot or
/// version the subject names.
fn admission(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &TaintSubject,
    stale_publish: &mut Option<bool>,
) -> Result<Option<TaintAdmission>> {
    let (id, cached) = match subject {
        TaintSubject::Code(id, project, fork) => {
            if !vault
                .get_codebase_snapshot_in_txn(txn, id)?
                .is_some_and(|held| held.project_id == *project && held.fork_hash == *fork)
            {
                return Ok(None);
            }
            (id, false)
        }
        TaintSubject::Blob(id, version) => {
            // The exact version and its ledger claim, as a cache hit binds them.
            if vault
                .blob_artifact_version_metadata_in_txn(txn, id, *version)?
                .is_none()
            {
                return Ok(None);
            }
            (id, true)
        }
    };
    let refs = exhaust_taint_refs_in_txn(&vault.store, txn, id)?;
    let state = taint_state_for_refs_in_txn(&vault.store, txn, &refs)?;
    let publish = match state {
        ArtifactTaintState::Clean | ArtifactTaintState::TaintedLive => true,
        ArtifactTaintState::TaintedStale => match *stale_publish {
            Some(open) => open,
            None => *stale_publish.insert(allow_stale_publish_in_txn(&vault.store, txn)?),
        },
    };
    Ok(Some(TaintAdmission {
        publish,
        cache: cached && state == ArtifactTaintState::Clean,
    }))
}

//! HNSW prepare/validate/commit rebuilds plus the SLIM dropped-marker rehydrate.

use crate::Vault;
use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::hnsw::{
    COUNT_KEY, LinkDiscipline, build_hnsw_graph_from_snapshot, hnsw_is_dropped,
    read_link_discipline, read_vector_version, write_rebuilt_hnsw,
};
use crate::le_bytes_to_f32_vec;

pub(super) struct PreparedHnswRebuild {
    old_count: u64,
    pub(super) vector_version: u64,
    pub(super) rebuilt: crate::hnsw::RebuiltHnswGraph,
    pub(super) invalid_vectors_skipped: u64,
    /// Discipline the prepared graph was built under and must be committed
    /// with — resolved inside the SAME read snapshot as the rebuild, so a
    /// concurrent migration cannot make the prepared shape and the committed
    /// marker disagree.
    discipline: LinkDiscipline,
}

/// Which link discipline a maintenance rebuild writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebuildDiscipline {
    /// Manual maintenance: always (re-)assert the symmetric-link invariant.
    /// This is the one-time ONE-325 migration path.
    MigrateSymmetric,
    /// SLIM marker-aware rehydrate (ONE-1933 / OF-447): keep whatever the
    /// vault already persists, so a Legacy vault rehydrates as Legacy and a
    /// shed never silently stamps the migration.
    Persisted,
}

pub(super) fn prepare_rebuild_hnsw(
    vault: &Vault,
    heal_invalid_vectors: bool,
) -> Result<PreparedHnswRebuild> {
    prepare_rebuild_hnsw_with_discipline(
        vault,
        heal_invalid_vectors,
        RebuildDiscipline::MigrateSymmetric,
    )
}

fn prepare_rebuild_hnsw_with_discipline(
    vault: &Vault,
    heal_invalid_vectors: bool,
    mode: RebuildDiscipline,
) -> Result<PreparedHnswRebuild> {
    let rtxn = vault.store.env.read_txn()?;
    let old_count =
        decode_u64_opt(vault.store.hnsw_meta.get(&rtxn, COUNT_KEY)?.as_deref())?.unwrap_or(0);
    let vector_version = read_vector_version(&vault.store, &rtxn)?;
    let mut vector_ids = Vec::<EntityId>::with_capacity(old_count.min(1_000_000) as usize);
    let mut invalid_vectors_skipped = 0_u64;

    for entry in vault.store.vectors.iter(&rtxn)? {
        let (id_bytes, vector_bytes) = entry?;
        let validation = validate_rebuild_vector(vault, &id_bytes, &vector_bytes);
        match validation {
            Ok(id) => vector_ids.push(id),
            Err(error) if heal_invalid_vectors && is_healable_rebuild_error(&error) => {
                invalid_vectors_skipped += 1;
            }
            Err(error) => return Err(error),
        }
    }

    // Manual maintenance rebuilds always produce a symmetric-link graph: this
    // is the one-time ONE-325 migration path for legacy vaults (and a no-op
    // re-assertion for already-migrated ones). Unmigratable vaults fail
    // closed: invalid vectors error out above unless heal mode skips them.
    // The SLIM marker-aware rehydrate instead keeps the persisted discipline,
    // read from THIS snapshot.
    let discipline = match mode {
        RebuildDiscipline::MigrateSymmetric => LinkDiscipline::Symmetric,
        RebuildDiscipline::Persisted => read_link_discipline(&vault.store, &rtxn)?,
    };
    let rebuilt = build_hnsw_graph_from_snapshot(
        &vault.store,
        &vault.config,
        &rtxn,
        &vector_ids,
        discipline,
    )?;
    drop(rtxn);

    Ok(PreparedHnswRebuild {
        old_count,
        vector_version,
        rebuilt,
        invalid_vectors_skipped,
        discipline,
    })
}

pub(crate) fn validate_rebuild_vector(
    vault: &Vault,
    id_bytes: &[u8],
    vector_bytes: &[u8],
) -> Result<EntityId> {
    let id = parse_entity_id(id_bytes, ERR_VECTOR_KEY)?;
    let vector = le_bytes_to_f32_vec(vector_bytes, vault.config.dimensions)?;
    if vector.len() != vault.config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: vault.config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(&vector) {
        return Err(error);
    }
    Ok(id)
}

fn is_healable_rebuild_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidKey
            | Error::InvalidVector { .. }
            | Error::DimensionMismatch { .. }
            | Error::CorruptedIndex(_)
    )
}

pub(super) fn rebuild_hnsw(vault: &Vault, heal_invalid_vectors: bool) -> Result<(u64, u64, u64)> {
    let prepared = prepare_rebuild_hnsw(vault, heal_invalid_vectors)?;

    commit_rebuilt_hnsw(vault, &prepared.rebuilt, prepared.vector_version)?;

    let live_nodes = prepared.rebuilt.count;
    let invalid_vectors_skipped = prepared.invalid_vectors_skipped;
    let dead_nodes_removed = prepared.old_count.saturating_sub(live_nodes);
    Ok((dead_nodes_removed, live_nodes, invalid_vectors_skipped))
}

/// The one vector-version-guarded commit every maintenance rebuild shares.
///
/// `write_rebuilt_hnsw` also clears the SLIM dropped marker in this same
/// transaction, so a committed rebuild is exactly what rehydrates a shed
/// graph — there is no second rebuild algorithm.
pub(super) fn commit_rebuilt_hnsw(
    vault: &Vault,
    rebuilt: &crate::hnsw::RebuiltHnswGraph,
    expected_vector_version: u64,
) -> Result<()> {
    commit_rebuilt_hnsw_with_discipline(
        vault,
        rebuilt,
        expected_vector_version,
        LinkDiscipline::Symmetric,
    )
}

fn commit_rebuilt_hnsw_with_discipline(
    vault: &Vault,
    rebuilt: &crate::hnsw::RebuiltHnswGraph,
    expected_vector_version: u64,
    discipline: LinkDiscipline,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current_vector_version = read_vector_version(&vault.store, &wtxn)?;
    if current_vector_version != expected_vector_version {
        return Err(Error::ConcurrentWrite(
            "vectors changed during hnsw rebuild; retry maintenance",
        ));
    }
    write_rebuilt_hnsw(&vault.store, &mut wtxn, rebuilt, discipline)?;
    wtxn.commit()?;
    Ok(())
}

/// SLIM (ONE-1933 / OF-447) explicit persisted rehydrate of a shed HNSW graph.
///
/// Returns `false` when the dropped marker is absent — the caller then takes
/// its ordinary rebuild. When present, prepares from ONE read snapshot with
/// the existing [`prepare_rebuild_hnsw`] logic, the vault's persisted
/// [`LinkDiscipline`] and the requested `heal_invalid_vectors` mode, and
/// commits through the same vector-version-guarded helper manual maintenance
/// uses.
///
/// A concurrent vector mutation gets exactly ONE re-check and no retry loop:
/// if the lazy write route already rebuilt and cleared the marker the
/// rehydrate is satisfied, otherwise the existing [`Error::ConcurrentWrite`]
/// surfaces to the caller.
pub(super) fn rebuild_hnsw_if_dropped(vault: &Vault, heal_invalid_vectors: bool) -> Result<bool> {
    if !hnsw_marker_is_dropped(vault)? {
        return Ok(false);
    }

    let prepared = prepare_rebuild_hnsw_with_discipline(
        vault,
        heal_invalid_vectors,
        RebuildDiscipline::Persisted,
    )?;
    commit_dropped_hnsw(vault, &prepared)
}

fn commit_dropped_hnsw(vault: &Vault, prepared: &PreparedHnswRebuild) -> Result<bool> {
    match commit_rebuilt_hnsw_with_discipline(
        vault,
        &prepared.rebuilt,
        prepared.vector_version,
        prepared.discipline,
    ) {
        Ok(()) => Ok(true),
        Err(Error::ConcurrentWrite(context)) => {
            if hnsw_marker_is_dropped(vault)? {
                Err(Error::ConcurrentWrite(context))
            } else {
                Ok(true)
            }
        }
        Err(other) => Err(other),
    }
}

fn hnsw_marker_is_dropped(vault: &Vault) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    hnsw_is_dropped(&vault.store, &rtxn)
}

const ERR_VECTOR_KEY: &str = "vector key";

pub(super) fn decode_u64_opt(raw: Option<&[u8]>) -> Result<Option<u64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

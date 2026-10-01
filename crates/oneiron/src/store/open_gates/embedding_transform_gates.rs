//! The embedding-transform pin: how a vault's vectors were made, beside the
//! model that made them.
//!
//! `hnsw_meta["embedding_transform"]` (UTF-8) holds a host-supplied descriptor
//! of every setting that moves stored vectors without changing the model id.
//! The engine compares descriptors and never reads into one. A vault written
//! before the pin existed has none, and adopts the first descriptor it is
//! opened with: until a host declared one, its vectors came from the model's
//! own transform. A host that supplies no descriptor is not checked.

use heed::{Env, RwTxn};

use super::hnsw_model_gates::parse_utf8_bytes;
use crate::error::{Error, Result, StoreError};
use crate::overlay_db::OverlayDb;
use crate::store::{ManifestDbs, Store};

pub(crate) const EMBEDDING_TRANSFORM_KEY: &[u8] = b"embedding_transform";

/// Refuses a requested descriptor that disagrees with the stored one. `true`
/// when none is stored yet and the requested one should be written.
pub(super) fn preflight_embedding_transform(
    env: &Env,
    hnsw_meta: &OverlayDb,
    requested: Option<&str>,
) -> Result<bool> {
    let Some(requested) = requested else {
        return Ok(false);
    };
    let rtxn = env.read_txn()?;
    match hnsw_meta.get(&rtxn, EMBEDDING_TRANSFORM_KEY)? {
        Some(raw) => {
            refuse_unless_equal(parse_utf8_bytes(&raw)?, requested)?;
            Ok(false)
        }
        None => Ok(true),
    }
}

/// Writes the requested descriptor where none is stored, re-checking under
/// its own write transaction.
pub(super) fn persist_embedding_transform_if_missing(
    env: &Env,
    hnsw_meta: &OverlayDb,
    requested: &str,
) -> Result<()> {
    let mut wtxn = env.write_txn()?;
    match hnsw_meta.get(&wtxn, EMBEDDING_TRANSFORM_KEY)? {
        Some(raw) => refuse_unless_equal(parse_utf8_bytes(&raw)?, requested)?,
        None => hnsw_meta.put(&mut wtxn, EMBEDDING_TRANSFORM_KEY, requested.as_bytes())?,
    }
    wtxn.commit()?;
    Ok(())
}

/// The same admission inside a caller's write transaction, for a descriptor
/// that is only known once the vault is already open.
pub(crate) fn admit_embedding_transform_in_txn(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    requested: &str,
) -> Result<()> {
    match store.hnsw_meta().get(&*wtxn, EMBEDDING_TRANSFORM_KEY)? {
        Some(raw) => refuse_unless_equal(parse_utf8_bytes(&raw)?, requested),
        None => store
            .hnsw_meta()
            .put(wtxn, EMBEDDING_TRANSFORM_KEY, requested.as_bytes()),
    }
}

/// The existing-only door repairs nothing: a requested descriptor must
/// already be the stored one.
pub(super) fn verify_existing_embedding_transform(
    store: &Store,
    requested: Option<&str>,
) -> Result<()> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let rtxn = store.env.read_txn()?;
    let stored = match store.hnsw_meta.get(&rtxn, EMBEDDING_TRANSFORM_KEY)? {
        Some(raw) => parse_utf8_bytes(&raw)?,
        None => super::open_version_keys::MODEL_ID_NONE.to_owned(),
    };
    refuse_unless_equal(stored, requested)
}

fn refuse_unless_equal(stored: String, requested: &str) -> Result<()> {
    if stored == requested {
        return Ok(());
    }
    Err(Error::Store(StoreError::EmbeddingTransformChanged {
        stored,
        requested: requested.to_owned(),
    }))
}

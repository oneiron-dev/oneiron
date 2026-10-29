//! Read-only door: rows of an existing vault's `vault_meta`, read without
//! opening it as a vault, beside another process that may hold it (a side
//! restore of the vault a running server serves).

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{EnvFlags, EnvOpenOptions};

use crate::error::{Error, Result, VaultRootProblem};

use super::manifest_storage_gates::{OwnedEnv, RegisteredPath, vault_root_open_guard};
use super::open_version_keys::MODEL_ID_KEY;
use super::vault_root_bind::vault_root_preflight_error;

/// Rows of one existing vault's metadata database (its `vault_meta`, or the
/// `hnsw_meta` that holds its model pin).
pub(in crate::store) struct VaultMetaRows {
    pub(in crate::store) rows: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Reads the `vault_meta` rows under `prefixes` of the vault at `path`
/// through a read-only LMDB environment.
///
/// The root passes the existing-only door's checks before LMDB sees it: a
/// complete pair of regular, non-symlink, single-link, unaliased LMDB files
/// (bound by descriptor on Linux, with their headers validated). The
/// environment is registered under the process root-open guard like any open
/// for as long as it lives, so a vault this process already holds, under any
/// name or through aliased files, refuses instead of gaining a second
/// environment over the same files. That registration comes before any of
/// the root's files is opened, and every check of the pair after the open
/// reads metadata alone, so this door never closes a descriptor of a
/// `lock.mdb` an environment of this process locks. A missing, empty or
/// incomplete root refuses with nothing created.
pub(in crate::store) fn read_existing_vault_meta(
    path: &Path,
    prefixes: &[&[u8]],
) -> Result<VaultMetaRows> {
    read_existing_rows(
        path,
        ("vault_meta", "vault holds no side-table database"),
        prefixes,
    )
}

/// The `entities` rows at exactly `keys` of the vault at `path`, read
/// through the same read-only environment: a side restore's source's live
/// world key pad rows (KS-5).
pub(crate) fn read_existing_entity_rows(
    path: &Path,
    keys: &[&[u8]],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rows = read_existing_rows(path, ("entities", "vault holds no entity database"), keys)?;
    Ok(rows
        .rows
        .into_iter()
        .filter(|(key, _)| keys.contains(&key.as_slice()))
        .collect())
}

/// The `sync_state` rows under `prefixes` of the vault at `path`, read
/// through the same read-only environment: a side restore's source's
/// hard-delete markers (FIX 4753).
pub(crate) fn read_existing_sync_state_rows(
    path: &Path,
    prefixes: &[&[u8]],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(read_existing_rows(
        path,
        ("sync_state", "vault holds no sync state database"),
        prefixes,
    )?
    .rows)
}

/// The embedding model the vault at `path` is pinned to, read through the
/// same read-only environment; `None` when it holds none.
pub(crate) fn read_existing_embedding_model(path: &Path) -> Result<Option<String>> {
    let rows = read_existing_rows(
        path,
        ("hnsw_meta", "vault holds no vector metadata database"),
        &[MODEL_ID_KEY],
    )?
    .rows;
    rows.into_iter()
        .find(|(key, _)| key.as_slice() == MODEL_ID_KEY)
        .map(|(_, value)| {
            String::from_utf8(value).map_err(|_| Error::CorruptedIndex("embedding model id"))
        })
        .transpose()
}

/// The rows under `prefixes` of one named database of the vault at `path`.
/// `database` pairs the name with the refusal for a vault that lacks it.
fn read_existing_rows(
    path: &Path,
    database: (&str, &'static str),
    prefixes: &[&[u8]],
) -> Result<VaultMetaRows> {
    let root = canonical_existing_root(path)?;
    let (env, registered) = open_read_only(&root)?;
    let rows = (|| -> Result<_> {
        let txn = env.read_txn()?;
        let db = env
            .open_database::<Bytes, Bytes>(&txn, Some(database.0))?
            .ok_or(Error::CorruptedIndex(database.1))?;
        let mut rows = Vec::new();
        for prefix in prefixes {
            for row in db.prefix_iter(&txn, prefix)? {
                let (key, value) = row?;
                rows.push((key.to_vec(), value.to_vec()));
            }
        }
        Ok(rows)
    })();
    // The environment closes before its path registration is released.
    drop(env);
    drop(registered);
    Ok(VaultMetaRows { rows: rows? })
}

/// The canonical root at `path`; a missing one refuses with nothing created.
pub(super) fn canonical_existing_root(path: &Path) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(root) => Ok(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(not_an_existing_root(path, false))
        }
        Err(error) => Err(error.into()),
    }
}

pub(in crate::store) fn not_an_existing_root(root: &Path, after_environment_open: bool) -> Error {
    vault_root_preflight_error(
        root,
        VaultRootProblem::NotAnExistingVaultRoot {
            after_environment_open,
        },
    )
}

/// [`open_read_only_with`] for a door that reads one named database.
fn open_read_only(root: &Path) -> Result<(OwnedEnv, RegisteredPath)> {
    open_read_only_with(root, 1)
}

/// Opens the already-canonical `root` read-only through the bound directory
/// descriptor, as the existing-only door opens it read-write, with room for
/// `databases` named databases (the paired custody read opens two).
#[cfg(target_os = "linux")]
pub(super) fn open_read_only_with(
    root: &Path,
    databases: u32,
) -> Result<(OwnedEnv, RegisteredPath)> {
    use super::super::root_directory::open_root_directory;
    use super::vault_root_bind::BoundVaultRoot;

    let _vault_root_open_guard = vault_root_open_guard()?;
    let dir = open_root_directory(root)?;
    // Reserved from the pair's metadata before either file is opened: a
    // vault this process holds refuses here, its environment's `fcntl` locks
    // on `lock.mdb` untouched.
    let Some(identity) = BoundVaultRoot::pair_by_metadata(root, &dir)? else {
        return Err(not_an_existing_root(root, false));
    };
    let registered = RegisteredPath::reserve(root.to_path_buf(), Some(identity.clone()))?;
    let bound = BoundVaultRoot::bind_dir(root, dir)?;
    if bound.identity != identity {
        return Err(not_an_existing_root(root, false));
    }
    let mut options = EnvOpenOptions::new();
    // The full reader table: a door that opens a vault first builds the
    // table a server opened beside it gets.
    options
        .max_dbs(databases)
        .max_readers(crate::config::READER_SLOTS);
    // A sealed vault (maximum tier) opens here only with the page key of a
    // vault this process opened.
    let keyed = crate::world_keys::seal_read_only(&mut options, root)?;
    // SAFETY: as `open_existing_environment`. The open path is the
    // `/proc/self/fd/<dirfd>` view of the root this call bound and validated,
    // and `bound` keeps that descriptor open through the call and then lives
    // in the returned `OwnedEnv`. The cache identity is the canonical root,
    // and `registered`, reserved under the root-open guard by both path and
    // LMDB file identity, makes this the only environment over these files in
    // this process. `READ_ONLY` asks LMDB for a read-only environment: it
    // never writes `data.mdb`, and registers its reader in the already
    // initialized `lock.mdb` beside any writer another process runs.
    let env = unsafe {
        options.flags(EnvFlags::READ_ONLY);
        options.open_with_cache_identity(
            &bound.environment_path(),
            root.to_path_buf(),
            || {},
            || {},
        )
    }
    .map_err(|error| crate::world_keys::page_seal_open_error(error, keyed))?;
    let mut env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    bound.verify_unchanged_by_metadata(root)?;
    env.retain_bound_root(bound.into_dir());
    Ok((env, registered))
}

/// No descriptor-bound open here: the root is checked by path before and
/// after the open, as the create-capable door checks it on this platform.
#[cfg(not(target_os = "linux"))]
pub(super) fn open_read_only_with(
    root: &Path,
    databases: u32,
) -> Result<(OwnedEnv, RegisteredPath)> {
    use super::vault_root_bind::preflight_vault_root;

    let _vault_root_open_guard = vault_root_open_guard()?;
    let Some(identity) = preflight_vault_root(root)?.identity else {
        return Err(not_an_existing_root(root, false));
    };
    let registered = RegisteredPath::reserve(root.to_path_buf(), Some(identity.clone()))?;
    let mut options = EnvOpenOptions::new();
    // The full reader table: a door that opens a vault first builds the
    // table a server opened beside it gets.
    options
        .max_dbs(databases)
        .max_readers(crate::config::READER_SLOTS);
    // A sealed vault (maximum tier) opens here only with the page key of a
    // vault this process opened.
    let keyed = crate::world_keys::seal_read_only(&mut options, root)?;
    // SAFETY: as the create-capable door on this platform: the canonical root
    // passed the preflight above and is checked again below, and
    // `registered`, reserved under the root-open guard by both path and LMDB
    // file identity, makes this the only environment over these files in this
    // process. `READ_ONLY` asks LMDB for a read-only environment that never
    // writes `data.mdb`.
    let env = unsafe {
        options.flags(EnvFlags::READ_ONLY);
        options.open(root)
    }
    .map_err(|error| crate::world_keys::page_seal_open_error(error, keyed))?;
    let env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    if preflight_vault_root(root)?.identity.as_ref() != Some(&identity) {
        return Err(not_an_existing_root(root, true));
    }
    Ok((env, registered))
}

#[cfg(test)]
mod tests;

//! Read-only door: rows of an existing vault's `vault_meta`, read without
//! opening it as a vault, beside another process that may hold it (a side
//! restore of the vault a running server serves).

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{EnvFlags, EnvOpenOptions};

use crate::error::{Error, Result, VaultRootProblem};

use super::manifest_storage_gates::{OwnedEnv, RegisteredPath, vault_root_open_guard};
use super::vault_root_bind::vault_root_preflight_error;

/// Rows of one existing vault's `vault_meta`, and the canonical root they
/// were read from.
pub(in crate::store) struct VaultMetaRows {
    pub(in crate::store) root: PathBuf,
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
/// environment over the same files. A missing, empty or incomplete root
/// refuses with nothing created.
pub(in crate::store) fn read_existing_vault_meta(
    path: &Path,
    prefixes: &[&[u8]],
) -> Result<VaultMetaRows> {
    let root = match path.canonicalize() {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(not_an_existing_root(path, false));
        }
        Err(error) => return Err(error.into()),
    };
    let (env, registered) = open_read_only(&root)?;
    let rows = (|| -> Result<_> {
        let txn = env.read_txn()?;
        let vault_meta = env
            .open_database::<Bytes, Bytes>(&txn, Some("vault_meta"))?
            .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
        let mut rows = Vec::new();
        for prefix in prefixes {
            for row in vault_meta.prefix_iter(&txn, prefix)? {
                let (key, value) = row?;
                rows.push((key.to_vec(), value.to_vec()));
            }
        }
        Ok(rows)
    })();
    // The environment closes before its path registration is released.
    drop(env);
    drop(registered);
    Ok(VaultMetaRows { root, rows: rows? })
}

fn not_an_existing_root(root: &Path, after_environment_open: bool) -> Error {
    vault_root_preflight_error(
        root,
        VaultRootProblem::NotAnExistingVaultRoot {
            after_environment_open,
        },
    )
}

/// Opens the already-canonical `root` read-only through the bound directory
/// descriptor, as the existing-only door opens it read-write.
#[cfg(target_os = "linux")]
fn open_read_only(root: &Path) -> Result<(OwnedEnv, RegisteredPath)> {
    use super::vault_root_bind::BoundVaultRoot;

    let _vault_root_open_guard = vault_root_open_guard()?;
    let bound = BoundVaultRoot::bind(root)?;
    let registered = RegisteredPath::reserve(root.to_path_buf(), Some(bound.identity.clone()))?;
    let mut options = EnvOpenOptions::new();
    options.max_dbs(1);
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
        )?
    };
    let mut env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    bound.verify_unchanged(root)?;
    env.retain_bound_root(bound.into_dir());
    Ok((env, registered))
}

/// No descriptor-bound open here: the root is checked by path before and
/// after the open, as the create-capable door checks it on this platform.
#[cfg(not(target_os = "linux"))]
fn open_read_only(root: &Path) -> Result<(OwnedEnv, RegisteredPath)> {
    use super::vault_root_bind::preflight_vault_root;

    let _vault_root_open_guard = vault_root_open_guard()?;
    let Some(identity) = preflight_vault_root(root)?.identity else {
        return Err(not_an_existing_root(root, false));
    };
    let registered = RegisteredPath::reserve(root.to_path_buf(), Some(identity.clone()))?;
    let mut options = EnvOpenOptions::new();
    options.max_dbs(1);
    // SAFETY: as the create-capable door on this platform: the canonical root
    // passed the preflight above and is checked again below, and
    // `registered`, reserved under the root-open guard by both path and LMDB
    // file identity, makes this the only environment over these files in this
    // process. `READ_ONLY` asks LMDB for a read-only environment that never
    // writes `data.mdb`.
    let env = unsafe {
        options.flags(EnvFlags::READ_ONLY);
        options.open(root)?
    };
    let env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    if preflight_vault_root(root)?.identity.as_ref() != Some(&identity) {
        return Err(not_an_existing_root(root, true));
    }
    Ok((env, registered))
}

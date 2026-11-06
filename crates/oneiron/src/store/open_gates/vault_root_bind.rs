//! Core half of `store::open_gates::vault_root_bind`: its store-layer items live in `oneiron_store::open_gates::vault_root_bind` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::open_gates::vault_root_bind::*;

#[cfg(unix)]
use super::super::root_directory::{FileIdentity, file_identity};
#[cfg(target_os = "linux")]
use super::super::root_directory::{
    adopt_descriptor, named_directory_identity, open_root_directory,
};
#[cfg(target_os = "linux")]
use super::manifest_storage_gates::vault_root_open_guard;
use super::manifest_storage_gates::{OwnedEnv, RegisteredPath};
#[cfg(target_os = "linux")]
use super::open_version_keys::MAX_DBS;
use crate::config::VaultConfig;
use crate::error::StoreError;
use crate::error::{Error, Result, VaultRootEntry, VaultRootProblem};
#[cfg(all(test, target_os = "linux"))]
use crate::store::test_hooks;
#[cfg(target_os = "linux")]
use heed::EnvOpenOptions;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

/// Binds the existing root and opens its LMDB environment through the bound
/// descriptor. Returns with the root-open guard released, having created
/// nothing and written nothing.
///
/// "Written nothing" is structural, not hopeful: the binding refuses any pair
/// that is not already a complete LMDB environment, so the read-write
/// `mdb_env_open` below can only ever attach to an environment that already
/// existed.
///
/// The guard spans the binding, the path reservation, the unsafe environment
/// open, and the post-open identity assertion, so those are indivisible
/// against another opener exactly as they are on the create-capable path.
#[cfg(target_os = "linux")]
pub(super) fn open_existing_environment(
    path: &Path,
    config: &VaultConfig,
) -> Result<(OwnedEnv, RegisteredPath)> {
    let _vault_root_open_guard = vault_root_open_guard()?;

    // Deliberately no `create_dir_all`: an absent root fails here, with zero
    // filesystem effect.
    let canonical_path = path.canonicalize()?;
    let dir = open_root_directory(&canonical_path)?;
    // Reserved from the pair's metadata before either file is opened: a
    // vault this process holds refuses here, its environment's `fcntl` locks
    // on `lock.mdb` untouched (FIX 8027).
    let Some(identity) = BoundVaultRoot::pair_by_metadata(&canonical_path, &dir)? else {
        return Err(existing_root_refusal(&canonical_path, false));
    };
    let registered_path = RegisteredPath::reserve(canonical_path.clone(), Some(identity.clone()))?;
    let root = BoundVaultRoot::bind_dir(&canonical_path, dir)?;
    if root.identity != identity {
        return Err(existing_root_refusal(&canonical_path, false));
    }

    // SAFETY: heed/LMDB require a single Env per environment, the path must not
    // be on NFS or another unsupported network filesystem, and map_size must
    // not be changed concurrently while the environment is open elsewhere.
    //
    // The pinned local heed seam (`crates/heed/PROVENANCE.md`) adds three
    // obligations, each discharged here:
    //
    // * The open path is the `/proc/self/fd/<dirfd>` view of the root THIS call
    //   bound and validated, and the seam hands those exact bytes to
    //   `mdb_env_open` with no canonicalization or re-resolution in between. So
    //   LMDB's own opens of `data.mdb`/`lock.mdb` resolve through the bound
    //   directory inode, and a rename, swap, or ABA of the caller's pathname
    //   cannot redirect them onto a directory this door never bound.
    // * `root` — hence that descriptor — outlives the call and is then moved
    //   into the returned `OwnedEnv`, so the descriptor number cannot be
    //   recycled for as long as the environment lives.
    // * The cache identity is the already-canonical root path, i.e. exactly the
    //   key heed derives for itself on the create-capable door; it is used for
    //   nothing but heed's registry. `RegisteredPath` under the process-local
    //   root-open guard remains this engine's single-environment-per-root
    //   authority, and `verify_unchanged_by_metadata` below is defense in
    //   depth, not the mechanism that makes the open safe.
    //
    // The two hooks are test-only interleave points: they rename or stage
    // directories and never re-enter heed.
    let mut options = EnvOpenOptions::new();
    options
        .map_size(config.map_size)
        .max_readers(config.max_readers)
        .max_dbs(MAX_DBS);
    if let Some(seal) = &config.page_seal {
        options.page_key(seal.page_key());
    }
    let env = unsafe {
        options.open_with_cache_identity(
            &root.environment_path(),
            canonical_path.clone(),
            || {
                #[cfg(test)]
                test_hooks::run_before_lmdb_open(&canonical_path);
            },
            || {
                #[cfg(test)]
                test_hooks::run_after_lmdb_open(&canonical_path);
            },
        )
    }
    .map_err(|error| {
        crate::key_material::page_seal_open_error(error, config.page_seal.is_some())
    })?;
    // Wrap IMMEDIATELY so every `?` below releases the environment instead of
    // leaking it into heed's process-global registry (ONE-1142).
    let mut env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    // From metadata alone: another descriptor of `lock.mdb` closed now would
    // release the locks this environment just took.
    root.verify_unchanged_by_metadata(&canonical_path)?;
    // Only now, with every post-open check passed, does the environment take
    // ownership of the descriptor it was opened through.
    env.retain_bound_root(root.into_dir());
    Ok((env, registered_path))
}

/// No trustworthy descriptor-bound environment path exists here, so the
/// existing-only door fails closed rather than opening through a pathname a
/// rename could redirect. There is deliberately no pathname fallback.
#[cfg(not(target_os = "linux"))]
pub(super) fn open_existing_environment(
    path: &Path,
    _config: &VaultConfig,
) -> Result<(OwnedEnv, RegisteredPath)> {
    Err(vault_root_preflight_error(
        path,
        VaultRootProblem::UnsupportedPlatform {
            entry: VaultRootEntry::Data,
        },
    ))
}

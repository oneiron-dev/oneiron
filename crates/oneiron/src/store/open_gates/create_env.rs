//! Create-door environment phase: bind the vault root and open LMDB.

use std::path::Path;

use heed::EnvOpenOptions;

use crate::config::VaultConfig;
#[cfg(unix)]
use crate::error::Error;
use crate::error::Result;
use crate::store::VaultWriterLease;
#[cfg(test)]
use crate::store::test_hooks;
use crate::world_keys::{admit_new_vault, page_seal_open_error};

#[cfg(unix)]
use super::super::root_directory::{file_identity, named_directory_identity};
use super::manifest_storage_gates::{
    OwnedEnv, RegisteredPath, TornCreationCleanup, vault_root_open_guard,
};
use super::open_create_door::preflight_named_root;
use super::open_version_keys::{MAX_DBS, VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE};
use super::vault_root_bind::preflight_rejected_aliased_root;

pub(super) fn create_env(
    path: impl AsRef<Path>,
    config: &VaultConfig,
    lease: Option<&VaultWriterLease>,
) -> Result<(TornCreationCleanup, OwnedEnv, RegisteredPath, bool)> {
    // Declared before the environment so its Drop runs after the env has
    // closed, releasing LMDB's file handles before removing torn files.
    let mut torn_creation_cleanup = TornCreationCleanup::default();
    let (env, registered_path, is_new_vault) = {
        let _vault_root_open_guard = vault_root_open_guard()?;

        // A leased open binds a directory that already exists: creating
        // by path could only touch a tree renamed in since the lease.
        if lease.is_none() {
            std::fs::create_dir_all(path.as_ref())?;
        }
        let canonical_path = path.as_ref().canonicalize()?;
        if let Some(lease) = lease {
            lease.validate_directory(&canonical_path)?;
        }
        #[cfg(unix)]
        let bound_root_dir = match lease {
            Some(lease) => lease.clone_directory()?,
            None => crate::store::root_directory::open_root_directory(&canonical_path)?,
        };
        #[cfg(all(test, unix))]
        test_hooks::run_after_create_root_bind(&canonical_path);
        #[cfg(target_os = "linux")]
        let storage_path = match lease {
            Some(lease) => lease.environment_path(),
            None => {
                use std::os::fd::AsRawFd;
                std::path::PathBuf::from(format!("/proc/self/fd/{}", bound_root_dir.as_raw_fd()))
            }
        };
        #[cfg(not(target_os = "linux"))]
        let storage_path = canonical_path.clone();
        let root_preflight = preflight_named_root(&storage_path, &canonical_path)?;
        #[cfg(unix)]
        let bound_root_identity = file_identity(&bound_root_dir.metadata()?);
        let is_new_vault = root_preflight.is_new_vault;
        if is_new_vault {
            // A page-seal mirror with no vault is another vault's
            // custody, and only a seal minted for a new vault creates
            // one (OF-570).
            admit_new_vault(&canonical_path, config.page_seal.as_ref())?;
            #[cfg(target_os = "linux")]
            torn_creation_cleanup.arm_bound(&bound_root_dir)?;
            #[cfg(not(target_os = "linux"))]
            torn_creation_cleanup.arm(storage_path.clone());
        }
        let mut registered_path =
            RegisteredPath::reserve(canonical_path.clone(), root_preflight.identity)?;

        // SAFETY: heed/LMDB require a single Env per filesystem path, the
        // path must not be on NFS or another unsupported network
        // filesystem, and map_size must not be changed concurrently while
        // the environment is open elsewhere. The path
        // existence/writability precondition is established by
        // create_dir_all plus the root preflight above. The caller must
        // not retarget the canonicalized filesystem path while it is being
        // opened. The process-local root-open guard keeps the initial
        // preflight, path reservation, unsafe LMDB open, and post-create
        // identity refresh indivisible against other openers; the
        // path/identity registry then rejects later duplicate live Env
        // opens for the same canonical path or known LMDB file identity.
        let env = unsafe {
            let mut options = EnvOpenOptions::new();
            options
                .map_size(config.map_size)
                .max_readers(config.max_readers)
                .max_dbs(MAX_DBS);
            if let Some(seal) = &config.page_seal {
                options.page_key(seal.page_key());
            }
            #[cfg(target_os = "linux")]
            let opened = if let Some(lease) = lease {
                // Keep the directory capability intact, just like the
                // existing-only door; the canonical path is cache identity.
                options.open_with_cache_identity(
                    &lease.environment_path(),
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
            } else {
                options.open_with_cache_identity(
                    &storage_path,
                    canonical_path.clone(),
                    || {},
                    || {},
                )
            };
            #[cfg(not(target_os = "linux"))]
            let opened = options.open(&canonical_path);
            opened.map_err(|error| page_seal_open_error(error, config.page_seal.is_some()))?
        };
        // Wrap IMMEDIATELY so every `?` early-return below (failed open
        // gates) also releases the environment instead of leaking it into
        // heed's process-global registry (ONE-1142).
        let env = OwnedEnv {
            env,
            #[cfg(unix)]
            _bound_root_dir: Some(bound_root_dir),
            #[cfg(not(unix))]
            _bound_root_dir: None,
        };
        #[cfg(test)]
        test_hooks::run_after_lmdb_open(&canonical_path);
        if let Some(lease) = lease {
            lease.validate_directory(&canonical_path)?;
        }
        if VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE {
            // A root whose LMDB files gained a SECOND HARD LINK while this
            // open was creating them is an ALIAS, not a torn creation, and
            // the difference decides whether the next opener of that alias
            // can still see it. Torn-creation cleanup exists to unlink
            // files this open created so a retry starts clean; here the
            // inode is reachable through another name, so unlinking our
            // side cannot restore a clean root (the inode survives) and it
            // destroys the one fact that makes the alias rejectable —
            // `link_count >= 2`. An opener arriving at the alias afterwards
            // would find a single-link root holding an LMDB environment
            // with no committed `vault_meta`, and would report the ABI gate
            // (`StorageAbiVersionChanged { stored: None }`) instead of the
            // alias, admitting a second environment over shared files.
            //
            // So: disarm cleanup for exactly that verdict and let the
            // preflight error stand. Rejection is not weakened anywhere —
            // this open still fails closed with the SAME
            // `VaultRootPreflight(MultipleHardLinks)`, returns no handle,
            // and releases its path reservation; only the destructive
            // unlink is withheld. Every other failure keeps cleanup armed.
            let refreshed = match preflight_named_root(&storage_path, &canonical_path) {
                Ok(refreshed) => refreshed,
                Err(error) => {
                    if preflight_rejected_aliased_root(&error) {
                        torn_creation_cleanup.disarm();
                    }
                    return Err(error);
                }
            };
            registered_path.refresh_identity(refreshed.identity)?;
        }

        #[cfg(unix)]
        if named_directory_identity(&canonical_path)? != Some(bound_root_identity) {
            return Err(Error::InvalidConfig(
                "vault root changed during open".to_owned(),
            ));
        }
        (env, registered_path, is_new_vault)
    };
    Ok((torn_creation_cleanup, env, registered_path, is_new_vault))
}

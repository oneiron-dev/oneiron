//! Core half of `store::archive_scratch`: its store-layer items live in `oneiron_store::archive_scratch` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::archive_scratch::*;

use super::Store;
use crate::{Error, Result};
use heed::{Env, EnvFlags, EnvOpenOptions};

impl Store {
    /// A new scratch environment for one import's row index (FIX 3678),
    /// its pages sealed under the vault's page key when `seal` holds one, as
    /// the vault's own are (FIX 3910); an unsealed vault's stays plain.
    pub(crate) fn archive_scratch_env(
        &self,
        seal: Option<&oneiron_store::vault_page_seal::VaultPageSeal>,
    ) -> Result<ScratchEnv> {
        let map_size = self
            .env
            .info()
            .map_size
            .div_ceil(SCRATCH_MAP_ROUNDING)
            .saturating_mul(SCRATCH_MAP_ROUNDING);
        let mut options = EnvOpenOptions::new();
        options.map_size(map_size);
        if let Some(seal) = seal {
            options.page_key(seal.page_key());
        }
        // SAFETY: the environment's one file is new and private to this
        // process (below), so no lock is needed: one thread, holding the one
        // `ScratchEnv`, is its only user. NO_SYNC and NO_META_SYNC lose
        // nothing a crash needs, since a crash loses the file anyway.
        unsafe {
            options.flags(
                EnvFlags::NO_SUB_DIR
                    | EnvFlags::NO_LOCK
                    | EnvFlags::NO_SYNC
                    | EnvFlags::NO_META_SYNC
                    | EnvFlags::NO_READ_AHEAD,
            );
        }
        #[cfg(unix)]
        {
            let root = match self.owner.env._bound_root_dir.as_ref() {
                Some(root) => root.try_clone()?,
                None => {
                    super::root_directory::open_root_directory(&self.owner._registered_path.path)?
                }
            };
            let staging = super::root_directory::lfs_staging_dir(&root)?;
            let name = format!(".archive-index-{}", uuid::Uuid::now_v7().simple());
            let identity = self
                .owner
                ._registered_path
                .path
                .join("lfs-staging")
                .join(&name);
            #[cfg(target_os = "linux")]
            let open_path = std::path::PathBuf::from(format!(
                "/proc/self/fd/{}/{name}",
                std::os::fd::AsRawFd::as_raw_fd(&staging)
            ));
            #[cfg(not(target_os = "linux"))]
            let open_path = identity.clone();
            // SAFETY: `open_path` names a file no one has made yet (a fresh
            // name in the 0700 staging directory `staging` holds open through
            // this call), so no other environment maps it, and `identity`
            // names it alone. Its name is unlinked below, so nothing else can
            // ever open it.
            let env =
                unsafe { options.open_with_cache_identity(&open_path, identity, || {}, || {}) }?;
            let scratch = ScratchEnv { env: Some(env) };
            rustix::fs::unlinkat(&staging, name.as_str(), rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            Ok(scratch)
        }
        #[cfg(not(unix))]
        {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("archive-index");
            // SAFETY: the file is new in a private temporary directory this
            // handle removes once the environment is closed.
            let env =
                unsafe { options.open_with_cache_identity(&path, path.clone(), || {}, || {}) }?;
            Ok(ScratchEnv {
                env: Some(env),
                _dir: dir,
            })
        }
    }
}

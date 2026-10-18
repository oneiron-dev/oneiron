//! `oneiron_vault_open_with_host_root`: the raw open that profiles this
//! install from the vault's host root secret (FIX 4730), beside the plain
//! `oneiron_vault_open`, which stays as it was.

use std::{path::Path, ptr, sync::Arc};

use oneiron::Vault;

use super::entity::device_open_config;
use super::guard::{ffi_guard, with_optional_slice, write_out};
use super::parse::engine;
use super::types::{OneironByteSlice, OneironStatus, OneironVault};

/// What the engine's log names this open.
const HOST_ROOT_OPEN: &str = "oneiron_vault_open_with_host_root";

/// `oneiron_vault_open`, then this install's own machine profile from the
/// vault's host root secret, so the owner's acts carry from it.
///
/// `host_root_secret_ptr` and `host_root_secret_len` are the exact bytes of
/// the server's configured `auth_secret`: null with length 0 names none, and
/// the open is `oneiron_vault_open`'s; a non-null empty secret is
/// `InvalidArg`. `initialize_root` is 0 or 1, and 1 needs a secret: it roots
/// the vault under the secret when this open creates its store and its
/// authority log is empty, a new local-origin vault. Never pass 1 for a
/// replica awaiting its root. A secret that cannot profile the install is
/// `EngineError` with `out_vault` left null; the engine logs the reason.
///
/// # Safety
///
/// As `oneiron_vault_open`, and a non-null `host_root_secret_ptr` covers
/// `host_root_secret_len` readable bytes, borrowed for this call only.
#[unsafe(no_mangle)]
#[allow(
    clippy::too_many_arguments,
    reason = "oneiron_vault_open's arguments, then the secret and its flag"
)]
pub unsafe extern "C" fn oneiron_vault_open_with_host_root(
    path_ptr: *const u8,
    path_len: usize,
    dimensions: usize,
    dict_search_paths: *const OneironByteSlice,
    dict_search_paths_len: usize,
    host_root_secret_ptr: *const u8,
    host_root_secret_len: usize,
    initialize_root: u8,
    out_vault: *mut *mut OneironVault,
) -> OneironStatus {
    ffi_guard(|| {
        write_out(out_vault, ptr::null_mut()).map_or_else(
            |status| status,
            |()| {
                let result =
                    with_optional_slice(host_root_secret_ptr, host_root_secret_len, |secret| {
                        let initialize_root = match (initialize_root, secret) {
                            (_, Some([])) | (2.., _) | (1, None) => {
                                return Err(OneironStatus::InvalidArg);
                            }
                            (flag, _) => flag == 1,
                        };
                        let (path, config) = device_open_config(
                            path_ptr,
                            path_len,
                            dimensions,
                            dict_search_paths,
                            dict_search_paths_len,
                        )?;
                        let may_root =
                            Vault::host_root_open_may_root(Path::new(&path), initialize_root);
                        let dimensions = config.dimensions;
                        // Crash output never carries world text: the engine's hook goes in
                        // before any vault opens (owner ruling 2026-10-14, fix 6).
                        oneiron::panic_report::install_panic_hook();
                        let vault = engine(Vault::open(&path, config))?;
                        // Signing doors need this install's keys from the keystore.
                        vault.install_default_keystore(Path::new(&path));
                        engine(vault.profile_local_open_logged(secret, may_root, HOST_ROOT_OPEN))?;
                        let handle = Box::into_raw(Box::new(OneironVault::unbound(
                            Arc::new(vault),
                            dimensions,
                        )));
                        write_out(out_vault, handle)
                    });
                result.map_or_else(|status| status, |()| OneironStatus::Ok)
            },
        )
    })
}

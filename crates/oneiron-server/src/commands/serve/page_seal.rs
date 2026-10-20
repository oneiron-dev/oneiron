//! The vault serve opens before it builds its server, plain or sealed (OF-570
//! maximum tier), for plain serve and an app's embedded engine (moved out of
//! `serve` whole).

use std::sync::Arc;

use oneiron::Error;
use oneiron::error::SecretError;

use super::super::{owner, reembed, resolve_dict_search_paths};
use crate::config::ServeConfig;
use crate::managed;
use crate::owner::backup::CustodyAnchorCredentials;

/// The vault serve opens, and the owner host its server takes.
pub struct OpenedServedVault {
    pub vault: Arc<oneiron::Vault>,
    pub(crate) owner_host: crate::owner::schedule::OwnerHost,
}

/// Opens the vault `config` names the way serve does before it builds its
/// server: dictionary paths resolved, the page seal prepared (a sealed vault
/// unlocks with `host`'s `vault_password` when it holds one), this device's
/// keys installed, embedding slots applied and result bodies collected. An
/// app's embedded engine opens its vault here too, handed no custody anchor
/// credential: a door its config names is not called.
pub fn open_served_vault<H: oneiron_vault_contract::host::Host>(
    host: &mut H,
    config: &ServeConfig,
) -> anyhow::Result<OpenedServedVault> {
    open_served_vault_anchored(host, config, None)
}

/// [`open_served_vault`], its custody anchor door called with `anchor`, the
/// owner credential plain serve was handed on its pipe.
pub(super) fn open_served_vault_anchored<H: oneiron_vault_contract::host::Host>(
    host: &mut H,
    config: &ServeConfig,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
) -> anyhow::Result<OpenedServedVault> {
    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    if let Some(warning) = dicts.warning {
        tracing::warn!(dict_paths = ?dicts.paths, "{warning}");
    } else {
        tracing::info!(dict_paths = ?dicts.paths, "using CJK dictionary search paths");
    }

    // A page-seal mirror whose vault's data is missing is refused, never
    // adopted for a new vault (OF-570).
    owner::refuse_orphaned_page_seal(&config.vault_path)?;
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    // A sealed vault (maximum tier) opens with its page seal, and one the
    // config asks for is created sealed where no vault is yet. One this
    // keystore holds no wrap of unlocks with the vault password the service
    // manager's credential store holds, when it holds one; so does one whose
    // device wrap is no longer current, once its open says so.
    let device_seal = vault_config.page_seal.is_some();
    if !device_seal {
        let password = oneiron::world_keys::vault_is_sealed(&config.vault_path)?
            .then(|| host.secret("vault_password").ok())
            .flatten()
            .map(owner::HostUnlock::Password);
        vault_config.page_seal = owner::prepare_page_seal(config, password.as_ref())?;
    }
    if vault_config.page_seal.is_some() {
        tracing::warn!("{}", oneiron::PAGE_SEAL_WARNING);
    }
    // The live seal opens the live vault and creates none: a rehearsal's
    // scratch takes a fresh incarnation of it (`owner::backup`).
    let mut rehearsal_config = vault_config.clone();
    rehearsal_config.page_seal = None;
    let owner_host = crate::owner::schedule::OwnerHost::from_config(config, rehearsal_config)
        .anchored_at(&config.backup, anchor);
    let vault = open_device_first(host, config, vault_config, device_seal)?;
    managed::warn_if_reader_table_short(&vault);
    // A new sealed vault is wrapped to this device, and serve starts only
    // once its mirror opens it.
    config
        .keystore
        .install_on_boot(&vault, &config.vault_path)?;
    owner::ensure_page_seal_wrapped(&vault, &config.vault_path)?;
    if let Some(embedding) = &config.embedding {
        embedding.apply_to(&vault)?;
    }
    #[cfg(unix)]
    if let Err(error) = vault.collect_result_bodies(4096) {
        tracing::warn!(%error, "result body collection at start failed");
    }
    // Rehearsal scratch a stopped serve left goes before any rehearsal starts (FIX 5677).
    owner_host.sweep_rehearsals(&vault);
    Ok(OpenedServedVault {
        vault: Arc::new(vault),
        owner_host,
    })
}

/// [`oneiron::Vault::open_owned`] under `vault_config`, whose page seal this
/// device's keystore unlocked when `device_seal`. A device wrap a change
/// removed or replaced is refused at admission by kind (FIX 2347); then,
/// once, the vault opens with the vault password `host`'s credential store
/// holds, and that open admits the password's wrap only while it is current.
/// Any other failure, or no stored password, is the first open's.
fn open_device_first<H: oneiron_vault_contract::host::Host>(
    host: &mut H,
    config: &ServeConfig,
    mut vault_config: oneiron::VaultConfig,
    device_seal: bool,
) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    // The same open with no seal yet, for the one retry.
    let seal = vault_config.page_seal.take();
    let mut retry = vault_config.clone();
    vault_config.page_seal = seal;
    let error = match oneiron::Vault::open_owned(path, vault_config) {
        Err(error @ Error::Secret(SecretError::StalePageSealCredential)) if device_seal => error,
        opened => return opened.map_err(reembed::with_model_change_remedy),
    };
    // The failed open dropped its handle and its writer lease; the mirror is
    // as it was, and the open below repairs it.
    let Ok(password) = host.secret("vault_password") else {
        return Err(reembed::with_model_change_remedy(error));
    };
    tracing::warn!(
        %error,
        "this device's wrap of the vault is no longer current; opening with the stored vault \
         password"
    );
    let unlock = owner::HostUnlock::Password(password);
    retry.page_seal = owner::prepare_page_seal(config, Some(&unlock))?;
    oneiron::Vault::open_owned(path, retry).map_err(reembed::with_model_change_remedy)
}

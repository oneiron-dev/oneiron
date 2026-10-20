//! The vault serve opens before it builds its server, plain or sealed (OF-570
//! maximum tier), for plain serve and an app's embedded engine (moved out of
//! `serve` whole).

use std::sync::Arc;

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
    // manager's credential store holds, when it holds one.
    if vault_config.page_seal.is_none() {
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
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(reembed::with_model_change_remedy)?;
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

//! Core half of `secret_record::write_records`: its store-layer items live in `oneiron_store::secret_record::write_records` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::secret_record::write_records::*;

use super::{CustodyClass, SecretCustodyRecord};
use crate::entity_id::EntityId;
use crate::git_wire::GitOid;
use crate::store::Store;
use crate::vault::Vault;
use serde::{Deserialize, Serialize};

/// What a custody write applies through: the vault's store, config and
/// analyzer, and whether its text index is trusted. The batch door's mask on
/// write (OF-560) holds these without a [`Vault`].
pub(crate) struct CustodyWrite<'a> {
    pub(crate) store: &'a Store,
    pub(crate) config: &'a crate::config::VaultConfig,
    pub(crate) analyzer: &'a crate::analyzer::MultilingualAnalyzer,
    pub(crate) text_index_trusted: bool,
}

impl<'a> CustodyWrite<'a> {
    pub(crate) fn of(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
            config: &vault.config,
            analyzer: &vault.analyzer,
            text_index_trusted: vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
        }
    }
}

//! VaultBridge root and ActorScopedVault handle plus the facade() accessor.

use napi_derive::napi;
use oneiron::{EntityId, Memory, Vault, VaultConfig, parse_actor_key};
use std::sync::Arc;

use super::boundary::{boundary_error, facade_error};

// ── classes ─────────────────────────────────────────────────────────────

/// The vault bridge root: opens a vault and mints actor-scoped handles.
/// Carries NO write verbs itself (W3: construction is not authority).
#[napi]
pub struct VaultBridge {
    vault: Arc<Vault>,
}

#[napi]
impl VaultBridge {
    /// Opens (or creates) a vault at `path` with the device preset.
    #[napi(factory)]
    pub fn open(path: String, dimensions: Option<u32>) -> napi::Result<Self> {
        let mut config = VaultConfig::device();
        if let Some(dimensions) = dimensions {
            config.dimensions = dimensions as usize;
        }
        let vault = Vault::open(&path, config)
            .map_err(|e| boundary_error(format!("failed to open vault: {e}")))?;
        Ok(Self {
            vault: Arc::new(vault),
        })
    }

    /// Binds an actor scope from the pinned key grammar
    /// `"<actor_class>:<entity_ref>"` (`human|agent|system`). Malformed
    /// keys are typed errors — never a defaulted class.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<ActorScopedVault> {
        let (actor, actor_class) =
            parse_actor_key(&self.vault, &actor_key).map_err(facade_error)?;
        Ok(ActorScopedVault {
            vault: Arc::clone(&self.vault),
            actor_hex: actor.to_hex(),
            actor_class: actor_class as u8,
        })
    }
}

/// Actor-scoped facade handle: every memory verb lives here.
#[napi]
pub struct ActorScopedVault {
    vault: Arc<Vault>,
    actor_hex: String,
    actor_class: u8,
}

impl ActorScopedVault {
    pub(crate) fn facade(&self) -> napi::Result<Memory<'_>> {
        let actor = EntityId::from_hex(&self.actor_hex)
            .map_err(|e| boundary_error(format!("invalid bound actor id: {e}")))?;
        let actor_class = match self.actor_class {
            0 => oneiron::EdgeActorClass::Human,
            1 => oneiron::EdgeActorClass::Agent,
            2 => oneiron::EdgeActorClass::System,
            other => {
                return Err(boundary_error(format!("invalid bound actor class {other}")));
            }
        };
        Ok(self.vault.memory(actor, actor_class))
    }
}

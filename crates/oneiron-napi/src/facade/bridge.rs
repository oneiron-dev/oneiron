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
        crate::facade::before_vault_open();
        let mut config = VaultConfig::device();
        if let Some(dimensions) = dimensions {
            config.dimensions = dimensions as usize;
        }
        let vault = Vault::open(&path, config)
            .map_err(|e| boundary_error(format!("failed to open vault: {e}")))?;
        // Signing doors (delete receipts) need this install's keys from the keystore.
        vault.install_default_keystore(std::path::Path::new(&path));
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
            off_record_session: None,
        })
    }
}

/// Actor-scoped facade handle: every memory verb lives here.
#[napi]
pub struct ActorScopedVault {
    vault: Arc<Vault>,
    actor_hex: String,
    actor_class: u8,
    /// The off-record session every verb runs inside, when the app host
    /// named one, bound to this handle's actor (OF-063, FIX 1668).
    off_record_session: Option<String>,
}

#[napi]
impl ActorScopedVault {
    /// A NEW handle whose every verb runs inside the off-record session
    /// `session_ref` names, for this handle's actor, the app host's
    /// principal (OF-063, FIX 1668). It grants nothing: inside an anonymous
    /// session that actor is verified in, a refusal writes no receipt.
    #[napi]
    pub fn in_off_record_session(&self, session_ref: String) -> napi::Result<ActorScopedVault> {
        let session_ref = session_ref.trim();
        if session_ref.is_empty() {
            return Err(boundary_error(
                "invalid off-record session reference".to_owned(),
            ));
        }
        Ok(ActorScopedVault {
            vault: Arc::clone(&self.vault),
            actor_hex: self.actor_hex.clone(),
            actor_class: self.actor_class,
            off_record_session: Some(session_ref.to_owned()),
        })
    }
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
        let memory = self.vault.memory(actor, actor_class);
        Ok(match self.off_record_session.as_deref() {
            Some(session) => memory.in_off_record_session(session),
            None => memory,
        })
    }
}

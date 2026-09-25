//! Space presentation frozen on the normal outbound gate/ledger/transport path.
use super::space_posting::head_key;
use super::{GroupPostingPreset, SpacePostingMode, invalid_autonomy};
use crate::error::Result;
use crate::gate::ExternalEffectGateInput;
use crate::{EntityId, Vault};

/// Engine-resolved presentation, not a caller's permission or sender override.
/// The configured space is the exact canonical outbound target. No room memory
/// is loaded or widened by this projection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSpacePosting {
    identity_ref: String,
    space_ref: String,
    setting_ref: String,
    actor_ref: String,
    preset: GroupPostingPreset,
}
impl FrozenSpacePosting {
    pub fn identity_ref(&self) -> &str {
        &self.identity_ref
    }
    pub fn space_ref(&self) -> &str {
        &self.space_ref
    }
    pub fn setting_ref(&self) -> &str {
        &self.setting_ref
    }
    pub fn preset_token(&self) -> &'static str {
        self.preset.token()
    }
    pub const fn preset(&self) -> GroupPostingPreset {
        self.preset
    }
    pub const fn policy_risk(&self) -> bool {
        matches!(self.preset.mode(), SpacePostingMode::PostAsOwner)
    }
}

impl Vault {
    pub(crate) fn outbound_space_posting_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        identity: Option<EntityId>,
        target: &str,
    ) -> Result<Option<FrozenSpacePosting>> {
        let Some(identity) = identity else {
            return Ok(None);
        };
        // These targets cannot have a configured dial. Do not impose new target
        // limits on unrelated existing dispatches that carry no setting.
        if target.trim().is_empty() || target.len() > 512 || target.chars().any(char::is_control) {
            return Ok(None);
        }
        if self
            .store
            .vault_meta
            .get(txn, &head_key(identity, target)?)?
            .is_none()
        {
            return Ok(None);
        }
        let state = self.posting_state_in_txn(txn, identity, target)?;
        Ok(Some(FrozenSpacePosting {
            identity_ref: identity.to_hex(),
            space_ref: target.to_owned(),
            setting_ref: state.setting_ref.ok_or_else(invalid_autonomy)?.to_hex(),
            preset: state.preset,
            actor_ref: self.autonomy_identity_actor(txn, identity)?.to_hex(),
        }))
    }

    /// The gate consumes this copy under its existing writer snapshot. A broad
    /// send grant cannot cover the independent owner-presentation requirement.
    pub(crate) fn space_posting_gate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        payload: &[u8],
        effect: &ExternalEffectGateInput,
    ) -> Result<ExternalEffectGateInput> {
        let mut checked = effect.clone();
        let Some(DispatchPosting {
            binding: frozen,
            identity,
            target,
        }) = decode_dispatch_posting(payload)?
        else {
            return Ok(checked);
        };
        if identity != effect.channel_identity_ref {
            return Err(invalid_autonomy());
        }
        let live = self.outbound_space_posting_in_txn(txn, effect.channel_identity_ref, &target)?;
        if live != frozen {
            return Err(invalid_autonomy());
        }
        if let Some(binding) = live {
            let identity = EntityId::from_hex(&binding.identity_ref)?;
            let state = self.posting_state_in_txn(txn, identity, &target)?;
            if binding.policy_risk() {
                let actor = self.autonomy_identity_actor(txn, identity)?;
                if effect.scoped_mcp_call.is_some()
                    || effect.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
                    || effect.provenance.actor_entity_ref != Some(actor)
                {
                    return Err(invalid_autonomy());
                }
            }
            if state.needs_owner_consent.is_some()
                || state.preset == GroupPostingPreset::OwnerDrafts
            {
                checked.has_permission = false;
            }
        }
        Ok(checked)
    }

    /// Recovery has no mutable request to borrow. Recheck the frozen binding
    /// and exact live grant before a Pending record reaches any transport.
    pub(crate) fn frozen_space_posting_ready_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        payload: &[u8],
    ) -> Result<bool> {
        let Some(DispatchPosting {
            binding: frozen,
            identity,
            target,
        }) = decode_dispatch_posting(payload)?
        else {
            return Ok(true);
        };
        if self.outbound_space_posting_in_txn(txn, identity, &target)? != frozen {
            return Err(invalid_autonomy());
        }
        let Some(binding) = frozen else {
            return Ok(true);
        };
        let identity = EntityId::from_hex(&binding.identity_ref)?;
        let state = self.posting_state_in_txn(txn, identity, &target)?;
        Ok(state.needs_owner_consent.is_none() && state.preset != GroupPostingPreset::OwnerDrafts)
    }
}

pub(crate) fn frozen_space_posting(payload: &[u8]) -> Result<Option<FrozenSpacePosting>> {
    Ok(decode_dispatch_posting(payload)?.and_then(|posting| posting.binding))
}

struct DispatchPosting {
    binding: Option<FrozenSpacePosting>,
    identity: Option<EntityId>,
    target: String,
}
fn decode_dispatch_posting(payload: &[u8]) -> Result<Option<DispatchPosting>> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Ok(None);
    };
    // These are the dispatch carrier's authority fields. Other connector JSON
    // is not an outbound dispatch envelope merely because it has a target key.
    if value.get("actor_class").is_none() || value.get("channel_identity_ref").is_none() {
        return Ok(None);
    }
    let Some(target) = value.get("target").and_then(serde_json::Value::as_str) else {
        return Err(invalid_autonomy());
    };
    let binding = value
        .get("space_posting")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<FrozenSpacePosting>(value.clone())
                .map_err(|_| invalid_autonomy())
        })
        .transpose()?;
    if let Some(binding) = &binding
        && (binding.space_ref != target
            || value
                .get("channel_identity_ref")
                .and_then(serde_json::Value::as_str)
                != Some(binding.identity_ref.as_str()))
    {
        return Err(invalid_autonomy());
    }
    let identity = match value.get("channel_identity_ref") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(id)) => Some(EntityId::from_hex(id)?),
        _ => return Err(invalid_autonomy()),
    };
    Ok(Some(DispatchPosting {
        binding,
        identity,
        target: target.to_owned(),
    }))
}

//! The owner's act on a vault setting as a signed op (FIX 4624, FIX 5660),
//! and its wire codec.
//!
//! The owner changes a vault-wide setting (the dreamer's wake policy, the
//! inference defaults), or the owner or an agent within its Grant sets or
//! clears one agent's free-time policy, from any surface where he is
//! authenticated. The install that served the act, a live machine of the
//! vault in any role, signs it with its install key; the record carries the
//! act ([`OwnerAct`], kind `policy_setting` on the setting's reserved target
//! ([`owner_act_target`]), or kind `free_time_policy` on the agent the policy
//! is for). Its `seen` is the target's live acts as the deciding surface
//! showed them, under [`POLICY_SETTING_REVISION_CONTEXT`]; the setting itself
//! stays a local row, so the record keeps only digests of it: the value it
//! replaced (`prior`) and the value it left (`value`, none for a clear). It
//! is a main-log entry, so every machine the owner admits folds it.
//!
//! Only the free-time policy is an agent's to set, within a Grant line that
//! names it; a vault-wide setting is the owner's own.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_POLICY_SETTING: &str = "policy_setting";
const POLICY_SETTING_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "setting",
    "prior",
    "value",
];
/// The domain of a setting act's `seen`, beside the checkpoint policy's
/// ([`CHECKPOINT_POLICY_REVISION_CONTEXT`]): BLAKE3 over it and the target's
/// sorted live act hashes, in the `PolicyRevision` shape.
pub const POLICY_SETTING_REVISION_CONTEXT: &[u8] = b"oneiron/policy-setting-revision/v1";

/// A setting act's `seen` over its target's live acts, zero for a target no
/// act names.
#[must_use]
pub fn policy_setting_revision(live: impl IntoIterator<Item = AuthorityEntryHash>) -> [u8; 32] {
    super::owner_act::act_revision(POLICY_SETTING_REVISION_CONTEXT, live)
}

/// The target an owner act names when it changes no row of its own: a
/// vault-wide setting, by its name, or a whole-vault export
/// (`vault.export`). Reserved and derived from the name (BLAKE3 under a
/// fixed context, first 16 bytes), so every install names the same target.
///
/// # Errors
/// A derived id that lands on a reserved pattern (never in practice).
pub fn owner_act_target(name: &str) -> Result<EntityId> {
    let digest = blake3::derive_key("oneiron owner act target v1", name.as_bytes());
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(id)
}

/// A setting an owner act of kind [`OwnerActKind::PolicySetting`] or
/// [`OwnerActKind::FreeTimePolicy`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySetting {
    /// The dreamer's wake policy (`dreamer.wake_policy.set`).
    DreamerWakePolicy,
    /// The per-purpose inference defaults (`inference.defaults.replace`).
    InferenceDefaults,
    /// One agent's free-time policy (FIX 4453, FIX 5660): the act's target
    /// is that agent.
    FreeTimePolicy,
}

impl PolicySetting {
    /// The setting's name. A vault-wide setting's act target is derived from
    /// it ([`owner_act_target`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DreamerWakePolicy => "settings.dreamer_wake_policy",
            Self::InferenceDefaults => "settings.inference_defaults",
            Self::FreeTimePolicy => "settings.free_time_policy",
        }
    }

    /// The wire tag.
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            Self::DreamerWakePolicy => "dreamer_wake_policy",
            Self::InferenceDefaults => "inference_defaults",
            Self::FreeTimePolicy => "free_time_policy",
        }
    }

    /// The setting a wire tag names; `None` for any other text.
    #[must_use]
    pub fn parse(wire: &str) -> Option<Self> {
        Some(match wire {
            "dreamer_wake_policy" => Self::DreamerWakePolicy,
            "inference_defaults" => Self::InferenceDefaults,
            "free_time_policy" => Self::FreeTimePolicy,
            _ => return None,
        })
    }

    /// The owner act kind that changes this setting.
    #[must_use]
    pub fn act_kind(self) -> OwnerActKind {
        match self {
            Self::DreamerWakePolicy | Self::InferenceDefaults => OwnerActKind::PolicySetting,
            Self::FreeTimePolicy => OwnerActKind::FreeTimePolicy,
        }
    }

    /// The reserved target a vault-wide setting's act names; `None` for the
    /// free-time policy, whose act names its agent.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn reserved_target(self) -> Result<Option<EntityId>> {
        match self.act_kind() {
            OwnerActKind::PolicySetting => owner_act_target(self.as_str()).map(Some),
            _ => Ok(None),
        }
    }
}

/// One act on a setting, signed by the install key of `machine`, a live
/// machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettingSet {
    /// The act: who decided, from which surface, on which of the target's
    /// revisions. Its kind is the setting's ([`PolicySetting::act_kind`]).
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the act.
    pub machine: EntityId,
    pub setting: PolicySetting,
    /// BLAKE3 over the setting's value the act replaced, as JSON.
    pub prior: [u8; 32],
    /// BLAKE3 over the value the act left, as JSON; `None` for a clear.
    pub value: Option<[u8; 32]>,
}

impl PolicySettingSet {
    /// The act names the setting's own kind, and a vault-wide setting's
    /// reserved target; the free-time policy's act names its agent, which
    /// only the writer knows to be one. An agent's act stands only on the
    /// free-time policy, under a Grant line that names it, no ask answers a
    /// setting act, and only the free-time policy is ever cleared.
    pub fn validate(&self) -> Result<()> {
        let free_time = self.setting == PolicySetting::FreeTimePolicy;
        if (matches!(self.act.by, ActBy::Agent { .. }) && !free_time)
            || self.act.answer.is_some()
            || (self.value.is_none() && !free_time)
        {
            return Err(invalid_authority());
        }
        let target = self.setting.reserved_target()?.unwrap_or(self.act.target);
        self.act.validate_carried(self.setting.act_kind(), target)
    }
}

pub(super) fn policy_setting_value(set: &PolicySettingSet) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_POLICY_SETTING),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&set.act),
        ),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("setting"), Value::from(set.setting.wire())),
        (Value::from("prior"), binary_value(set.prior)),
        (
            Value::from("value"),
            set.value.map_or(Value::Nil, binary_value),
        ),
    ])
}

/// A known setting tag, two digests (the second nil for a clear); the op's
/// shape check then pins the act's kind and who may make it.
pub(super) fn decode_policy_setting(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &POLICY_SETTING_KEYS)?;
    let setting = required(entries, "setting")?
        .as_str()
        .and_then(PolicySetting::parse)
        .ok_or_else(invalid_authority)?;
    let value = match required(entries, "value")? {
        Value::Nil => None,
        value => Some(decode_hash(value)?),
    };
    Ok(AuthorityOp::PolicySettingSet(PolicySettingSet {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        setting,
        prior: decode_hash(required(entries, "prior")?)?,
        value,
    }))
}

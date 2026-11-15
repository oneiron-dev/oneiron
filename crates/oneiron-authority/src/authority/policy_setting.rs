//! The owner's act on a vault setting as a signed op (FIX 4624, FIX 5660),
//! and its wire codec.
//!
//! The owner changes a vault-wide setting (the dreamer's wake policy, the
//! inference defaults, the room-thread admin switches), or the owner or an
//! agent within its Grant sets or clears one agent's free-time policy, from
//! any surface where he is authenticated. The install that served the act,
//! a live machine of the vault in any role, signs it with its install key;
//! the record carries the
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
//!
//! One setting is read by the fold itself and has no local row: web sign-in
//! ([`PolicySetting::WebSignIn`], the owner's ruling AUTH-5, 15 Nov). Its
//! value is no digest of a row: the act that switches a hosted vault back to
//! web sign-in carries [`web_sign_in_value`] over the owner keys it speaks
//! for, and any other value asks for an owner key again.
//!
//! A second is read by the fold the same way: the owner's choice "Let my
//! passkey remove devices and keys" ([`PolicySetting::PasskeyFullOwner`],
//! Engine ruling WEBPASSKEY-OPTIN-HOME = A, 16 Nov). Its value is
//! [`passkey_full_owner_value`] of on or off, never a row's digest.

use std::collections::BTreeSet;

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

/// The domain of [`web_sign_in_value`].
pub const WEB_SIGN_IN_VALUE_CONTEXT: &str = "oneiron web sign-in owner keys v1";

/// The value of the act that switches a hosted vault back to web sign-in
/// ([`PolicySetting::WebSignIn`]): BLAKE3 under
/// [`WEB_SIGN_IN_VALUE_CONTEXT`] over every key the vault has ever held as
/// the owner's, in order, each as one suite byte (1 for Ed25519, 2 for
/// P-256) and its canonical public key bytes. The choice speaks for exactly
/// these keys: a key enrolled later is not among them, so the vault asks for
/// an owner key again.
#[must_use]
pub fn web_sign_in_value(owner_keys: &BTreeSet<AuthorityKey>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(WEB_SIGN_IN_VALUE_CONTEXT);
    for key in owner_keys {
        match key {
            AuthorityKey::Ed25519(bytes) => {
                hasher.update(&[1]);
                hasher.update(bytes);
            }
            AuthorityKey::P256(bytes) => {
                hasher.update(&[2]);
                hasher.update(bytes);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// The domain of [`passkey_full_owner_value`].
pub const PASSKEY_FULL_OWNER_VALUE_CONTEXT: &str = "oneiron passkey full owner v1";

/// The value of an act of the owner's choice "Let my passkey remove devices
/// and keys" ([`PolicySetting::PasskeyFullOwner`]): BLAKE3 under
/// [`PASSKEY_FULL_OWNER_VALUE_CONTEXT`] over one byte, 1 for on and 0 for
/// off. Only the value of on turns it on; any other value is off.
#[must_use]
pub fn passkey_full_owner_value(on: bool) -> [u8; 32] {
    blake3::derive_key(PASSKEY_FULL_OWNER_VALUE_CONTEXT, &[u8::from(on)])
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
    /// The owner's two switches over Admins and private room threads
    /// (`rooms.private_threads.admin_walk_in` /
    /// `rooms.private_threads.admin_delete`).
    RoomThreadAdmin,
    /// One agent's free-time policy (FIX 4453, FIX 5660): the act's target
    /// is that agent.
    FreeTimePolicy,
    /// The owner's board cap and board layout layers (BOARD-LAYOUT).
    BoardLayout,
    /// The most of a context pack's claims worlds other than base may hold
    /// (ARCH-0004 #world-scope; WORLD-SHARE-FRACTION-NO-OWNER-DOOR).
    NonBaseWorldClaimFraction,
    /// The FACET a write with no active mask is born under (ARCH-0022
    /// #facets: "Every vault has one default facet ... the owner may set
    /// another").
    DefaultFacet,
    /// The undo-send window every send waits in on each outbound channel
    /// (DEC-0006 #undo-send; REV-8 = B).
    UndoSend,
    /// The worlds the owner grants one agent and its default among them
    /// (ARCH-0067 #tiers; `vault.agents.worlds.set`). The act names the
    /// setting's reserved target; its digests cover the agent with its
    /// tiers, which stay node-local claims (RULING L2-53-CEILING).
    AgentWorldAccess,
    /// Whether a hosted vault that has held an owner key runs on web sign-in
    /// again (the owner's ruling AUTH-5, 15 Nov: "Switch back to web
    /// sign-in"). The fold reads it and no install keeps a row of it: the
    /// value [`web_sign_in_value`] over the owner keys the act speaks for
    /// switches the vault back, and any other value asks for an owner key
    /// again.
    WebSignIn,
    /// The owner's choice "Let my passkey remove devices and keys" (Engine
    /// ruling WEBPASSKEY-OPTIN-HOME = A, 16 Nov; choice id
    /// `passkey.full_owner`), off by default. While it is on, a passkey and
    /// every key only a passkey vouched for act as full owner keys: the
    /// passkey limits (rulings WEBPASSKEY-BLIND-SIGNATURE = B,
    /// WEBPASSKEY-PASSKEY-OWN-REVOKE = B, WEBPASSKEY-MACHINE-ANSWER = A) are
    /// lifted. The fold reads it and no install keeps a row of it: the value
    /// [`passkey_full_owner_value`] of on turns it on, and only with an owner
    /// key's proof by a key the passkey limits do not reach; any other value
    /// turns it off.
    PasskeyFullOwner,
}

impl PolicySetting {
    /// The setting's name. A vault-wide setting's act target is derived from
    /// it ([`owner_act_target`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DreamerWakePolicy => "settings.dreamer_wake_policy",
            Self::InferenceDefaults => "settings.inference_defaults",
            Self::RoomThreadAdmin => "settings.room_thread_admin",
            Self::FreeTimePolicy => "settings.free_time_policy",
            Self::BoardLayout => "settings.board_layout",
            Self::NonBaseWorldClaimFraction => "settings.non_base_world_claim_fraction",
            Self::DefaultFacet => "settings.default_facet",
            Self::UndoSend => "settings.undo_send",
            Self::AgentWorldAccess => "settings.agent_world_access",
            Self::WebSignIn => "settings.web_sign_in",
            Self::PasskeyFullOwner => "passkey.full_owner",
        }
    }

    /// The wire tag.
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            Self::DreamerWakePolicy => "dreamer_wake_policy",
            Self::InferenceDefaults => "inference_defaults",
            Self::RoomThreadAdmin => "room_thread_admin",
            Self::FreeTimePolicy => "free_time_policy",
            Self::BoardLayout => "board_layout",
            Self::NonBaseWorldClaimFraction => "non_base_world_claim_fraction",
            Self::DefaultFacet => "default_facet",
            Self::UndoSend => "undo_send",
            Self::AgentWorldAccess => "agent_world_access",
            Self::WebSignIn => "web_sign_in",
            Self::PasskeyFullOwner => "passkey_full_owner",
        }
    }

    /// The setting a wire tag names; `None` for any other text.
    #[must_use]
    pub fn parse(wire: &str) -> Option<Self> {
        Some(match wire {
            "dreamer_wake_policy" => Self::DreamerWakePolicy,
            "inference_defaults" => Self::InferenceDefaults,
            "room_thread_admin" => Self::RoomThreadAdmin,
            "free_time_policy" => Self::FreeTimePolicy,
            "board_layout" => Self::BoardLayout,
            "non_base_world_claim_fraction" => Self::NonBaseWorldClaimFraction,
            "default_facet" => Self::DefaultFacet,
            "undo_send" => Self::UndoSend,
            "agent_world_access" => Self::AgentWorldAccess,
            "web_sign_in" => Self::WebSignIn,
            "passkey_full_owner" => Self::PasskeyFullOwner,
            _ => return None,
        })
    }

    /// The owner act kind that changes this setting.
    #[must_use]
    pub fn act_kind(self) -> OwnerActKind {
        match self {
            Self::DreamerWakePolicy
            | Self::InferenceDefaults
            | Self::RoomThreadAdmin
            | Self::BoardLayout
            | Self::NonBaseWorldClaimFraction
            | Self::DefaultFacet
            | Self::UndoSend
            | Self::AgentWorldAccess
            | Self::WebSignIn
            | Self::PasskeyFullOwner => OwnerActKind::PolicySetting,
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

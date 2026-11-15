//! The owner's act on a vault setting as a signed op (FIX 4624, FIX 5660),
//! and its wire codec.
//!
//! The owner changes a vault-wide setting (a catalogue key of the setting
//! primitive, or one of the eight settings its own doors still sign: the
//! dreamer's wake policy, the inference defaults, the room-thread admin
//! switches, ...), or the owner or an agent within its Grant sets or clears
//! one agent's free-time policy, from any surface where he is authenticated.
//! The install that served the act, a live machine of the vault in any role,
//! signs it with its install key; the record carries the act ([`OwnerAct`],
//! kind `policy_setting` on the setting's reserved target
//! ([`policy_setting_target`]), or kind `free_time_policy` on the agent the
//! policy is for). Its `seen` is the target's live acts as the deciding
//! surface showed them, under [`POLICY_SETTING_REVISION_CONTEXT`]; the
//! setting itself stays a local row, so the record keeps only digests of it:
//! the value it replaced (`prior`) and the value it left (`value`, none for a
//! clear). It is a main-log entry, so every machine the owner admits folds
//! it.
//!
//! The setting is named by its text on the wire (stage 7a-1, RULING
//! SETTING-7A-SIGNED-ACT-BASE = A): any name of a setting key's shape, known
//! to this build or not. The eight names of [`PolicySetting`] are that text
//! as before, so every stored entry decodes, validates and folds as it did.
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

/// The longest setting name an act carries, in bytes.
pub const POLICY_SETTING_NAME_MAX: usize = 128;

/// The reserved target of an act on the vault-wide setting `setting` (its
/// wire name): [`owner_act_target`] of `settings.<setting>`. For each of the
/// eight [`PolicySetting`] names that is the target its acts always named
/// ([`PolicySetting::reserved_target`]); a catalogue key's acts name the
/// target of its key name the same way, so every install names the same
/// frontier.
///
/// # Errors
/// As [`owner_act_target`].
pub fn policy_setting_target(setting: &str) -> Result<EntityId> {
    owner_act_target(&format!("settings.{setting}"))
}

/// Whether `setting` has a setting name's shape: a setting key's dotted
/// lowercase ASCII ([`oneiron_setting_contract::check_name`]), at most
/// [`POLICY_SETTING_NAME_MAX`] bytes. The op checks the shape, never a
/// catalogue: a name this build does not know is still a well-formed act.
#[must_use]
pub fn is_policy_setting_name(setting: &str) -> bool {
    setting.len() <= POLICY_SETTING_NAME_MAX
        && oneiron_setting_contract::check_name(setting).is_ok()
}

/// One of the eight settings whose own doors sign their acts until stage 2
/// moves them onto the setting primitive (D4 deletes this list). An act names
/// it by its wire text ([`Self::wire`]).
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
        }
    }

    /// The one of the eight a wire name names; `None` for any other text.
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
            | Self::UndoSend => OwnerActKind::PolicySetting,
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
            OwnerActKind::PolicySetting => policy_setting_target(self.wire()).map(Some),
            _ => Ok(None),
        }
    }
}

/// One act on a setting, signed by the install key of `machine`, a live
/// machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettingSet {
    /// The act: who decided, from which surface, on which of the target's
    /// revisions. Its kind is `free_time_policy` for the free-time policy and
    /// `policy_setting` for every other setting.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the act.
    pub machine: EntityId,
    /// The setting's name as the wire carries it: a [`PolicySetting`]'s
    /// [`PolicySetting::wire`] text, or a catalogue key's name.
    pub setting: String,
    /// BLAKE3 over the setting's value the act replaced, as JSON.
    pub prior: [u8; 32],
    /// BLAKE3 over the value the act left, as JSON; `None` for a clear.
    pub value: Option<[u8; 32]>,
}

impl PolicySettingSet {
    /// The setting's name has a setting name's shape
    /// ([`is_policy_setting_name`]). The act names the setting's own kind,
    /// and a vault-wide setting's reserved target
    /// ([`policy_setting_target`]); the free-time policy's act names its
    /// agent, which only the writer knows to be one. An agent's act stands
    /// only on the free-time policy, under a Grant line that names it, and no
    /// ask answers a setting act. Of the eight [`PolicySetting`]s only the
    /// free-time policy is ever cleared; a catalogue key's clear is an act
    /// like its set.
    pub fn validate(&self) -> Result<()> {
        if !is_policy_setting_name(&self.setting) {
            return Err(invalid_authority());
        }
        let known = PolicySetting::parse(&self.setting);
        let free_time = known == Some(PolicySetting::FreeTimePolicy);
        if (matches!(self.act.by, ActBy::Agent { .. }) && !free_time)
            || self.act.answer.is_some()
            || (self.value.is_none() && known.is_some() && !free_time)
        {
            return Err(invalid_authority());
        }
        if free_time {
            return self
                .act
                .validate_carried(OwnerActKind::FreeTimePolicy, self.act.target);
        }
        self.act.validate_carried(
            OwnerActKind::PolicySetting,
            policy_setting_target(&self.setting)?,
        )
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
        (Value::from("setting"), Value::from(set.setting.as_str())),
        (Value::from("prior"), binary_value(set.prior)),
        (
            Value::from("value"),
            set.value.map_or(Value::Nil, binary_value),
        ),
    ])
}

/// A setting's name, two digests (the second nil for a clear); the op's
/// shape check then pins the name's shape, the act's kind and who may make
/// it ([`PolicySettingSet::validate`]).
pub(super) fn decode_policy_setting(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &POLICY_SETTING_KEYS)?;
    let setting = required(entries, "setting")?
        .as_str()
        .map(str::to_owned)
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

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
//!
//! The act is the write (stage 7a-2, DESIGN 1.6 "What travels"). An owner's
//! act on a catalogue key may name its slot (`slot`: the item, mode and scope
//! of one row, absent for the key's vault value row) and carry the value it
//! left (`inline`: the value's JSON bytes, at most
//! [`POLICY_SETTING_INLINE_MAX`], whose BLAKE3 is `value`). Its target is then
//! derived from the slot ([`setting_slot_target`]), so every install names
//! one frontier per row. Both keys are optional on the wire and absent from
//! every older entry, which therefore decodes, validates, targets and folds as
//! it did.
//!
//! A batch is one act (stage 7a-3, DESIGN 1.6 "What travels"): an owner's act
//! on catalogue keys may list more rows (`more`), each a row of its own slot
//! with its own `seen`, `prior` and value, under the one decider the act
//! names. Every row is judged in its own slot, and the act lands in all of
//! them or none. The op's own fields stay its first row, so a one-row act
//! encodes as in stage 7a-2, and `more` is absent from every older entry.

use std::collections::BTreeSet;

use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};
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
/// The keys a setting act carries only when it names them (stage 7a-2; `more`
/// stage 7a-3), in their wire order after [`POLICY_SETTING_KEYS`].
const POLICY_SETTING_OPTIONAL_KEYS: [&str; 3] = ["slot", "inline", "more"];
/// The keys every further row of a batch act carries (stage 7a-3).
const POLICY_SETTING_ROW_KEYS: [&str; 4] = ["setting", "seen", "prior", "value"];
/// The keys a further row carries only when it names them, in their wire
/// order after [`POLICY_SETTING_ROW_KEYS`].
const POLICY_SETTING_ROW_OPTIONAL_KEYS: [&str; 2] = ["slot", "inline"];
/// The longest value an act carries inline, in bytes: the bound the log's
/// other carried payloads keep ([`MAX_PACT_SCOPE_BYTES`]).
pub const POLICY_SETTING_INLINE_MAX: usize = MAX_PACT_SCOPE_BYTES;
/// The domain of a setting act's `seen`, beside the checkpoint policy's
/// ([`CHECKPOINT_POLICY_REVISION_CONTEXT`]): BLAKE3 over it and the target's
/// sorted live act hashes, in the `PolicyRevision` shape.
pub const POLICY_SETTING_REVISION_CONTEXT: &[u8] = b"oneiron/policy-setting-revision/v1";

/// BLAKE3 over a setting value's JSON bytes: an act's `prior` and `value`,
/// and the digest its inline value must have. The one digest of a setting
/// value every writer and check calls.
#[must_use]
pub fn setting_value_digest(json: &[u8]) -> [u8; 32] {
    *blake3::hash(json).as_bytes()
}

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

/// The target of an act on the row `slot` of a catalogue key (stage 7a-2):
/// the key's [`policy_setting_target`] for its vault value row with no item,
/// the target every act on that row has named since stage 7a-1; for any other
/// row, BLAKE3 under a fixed context over the row's stored key
/// ([`RowKey::encode`]), first 16 bytes. Derived from the slot alone, so
/// every install names the same frontier for one row.
///
/// # Errors
/// As [`owner_act_target`].
pub fn setting_slot_target(slot: &RowKey) -> Result<EntityId> {
    if is_vault_value_row(slot) {
        return policy_setting_target(&slot.name);
    }
    let digest = blake3::derive_key("oneiron setting slot target v1", &slot.encode());
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(id)
}

/// Whether `slot` is its key's vault value row with no item: the row an act
/// names by leaving `slot` out.
fn is_vault_value_row(slot: &RowKey) -> bool {
    slot.item.is_none() && slot.mode == SettingMode::Value && slot.scope == SettingScope::Vault
}

/// A catalogue key's row as an act names it (stage 7a-2): a named slot is of
/// the row's own key and never the vault value row with no item, which a row
/// names by leaving `slot` out, so one row has one encoding; an inline value
/// holds at most [`POLICY_SETTING_INLINE_MAX`] bytes and its digest is the
/// row's `value`.
fn check_catalogue_row(
    setting: &str,
    slot: Option<&RowKey>,
    value: Option<[u8; 32]>,
    inline: Option<&[u8]>,
) -> Result<()> {
    if let Some(slot) = slot
        && (slot.name != setting || is_vault_value_row(slot))
    {
        return Err(invalid_authority());
    }
    if let Some(inline) = inline
        && (inline.len() > POLICY_SETTING_INLINE_MAX || value != Some(setting_value_digest(inline)))
    {
        return Err(invalid_authority());
    }
    Ok(())
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
    /// The row the act changes (stage 7a-2), named whole, its name the
    /// act's `setting`; `None` for the key's vault value row with no item,
    /// which every older act names. Only a catalogue key's act names one.
    pub slot: Option<RowKey>,
    /// The value the act left, as its JSON bytes (stage 7a-2): a closed
    /// value of at most [`POLICY_SETTING_INLINE_MAX`] bytes whose BLAKE3 is
    /// `value`, so every machine that folds the act can write the row. `None`
    /// for a clear, and for an act that keeps only the digest.
    pub inline: Option<Vec<u8>>,
    /// The batch's further rows (stage 7a-3), each on its own target; empty
    /// for a one-row act, and then absent from the wire.
    pub more: Vec<PolicySettingRow>,
}

/// One further row of a batch act (stage 7a-3): a row of a catalogue key, as
/// the op's own fields name its first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettingRow {
    /// The catalogue key's name.
    pub setting: String,
    /// The row; `None` for the key's vault value row with no item.
    pub slot: Option<RowKey>,
    /// The row's target revision the deciding surface showed: its `seen`, as
    /// the act's own names the first row's.
    pub seen: [u8; 32],
    /// BLAKE3 over the value the row replaced, as JSON.
    pub prior: [u8; 32],
    /// BLAKE3 over the value the row left, as JSON; `None` for a clear.
    pub value: Option<[u8; 32]>,
    /// The value the row left, as its JSON bytes; `None` for a clear and a
    /// digest-only row.
    pub inline: Option<Vec<u8>>,
}

impl PolicySettingRow {
    /// The row's target: its slot's ([`setting_slot_target`]), else its
    /// key's ([`policy_setting_target`]).
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn target(&self) -> Result<EntityId> {
        match &self.slot {
            Some(slot) => setting_slot_target(slot),
            None => policy_setting_target(&self.setting),
        }
    }

    /// A catalogue key's name, never one of the eight [`PolicySetting`]s, and
    /// a well-named row ([`check_catalogue_row`]).
    fn validate(&self) -> Result<()> {
        if !is_policy_setting_name(&self.setting) || PolicySetting::parse(&self.setting).is_some() {
            return Err(invalid_authority());
        }
        check_catalogue_row(
            &self.setting,
            self.slot.as_ref(),
            self.value,
            self.inline.as_deref(),
        )
    }
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
    ///
    /// A slot and an inline value (stage 7a-2) stand only on a catalogue
    /// key's act. A named slot is of the act's own key, and never the vault
    /// value row with no item, which an act names by leaving `slot` out, so
    /// one row has one encoding; the act's target is then the slot's
    /// ([`setting_slot_target`]). An inline value goes with a set, never a
    /// clear, holds at most [`POLICY_SETTING_INLINE_MAX`] bytes, and its
    /// BLAKE3 is the act's `value`.
    ///
    /// A batch (stage 7a-3) is an act on catalogue keys alone, its first row
    /// included, and no two of its rows name one target.
    pub fn validate(&self) -> Result<()> {
        if !is_policy_setting_name(&self.setting) {
            return Err(invalid_authority());
        }
        let known = PolicySetting::parse(&self.setting);
        let free_time = known == Some(PolicySetting::FreeTimePolicy);
        if (matches!(self.act.by, ActBy::Agent { .. }) && !free_time)
            || self.act.answer.is_some()
            || (self.value.is_none() && known.is_some() && !free_time)
            || (known.is_some() && (self.slot.is_some() || self.inline.is_some()))
        {
            return Err(invalid_authority());
        }
        check_catalogue_row(
            &self.setting,
            self.slot.as_ref(),
            self.value,
            self.inline.as_deref(),
        )?;
        if !self.more.is_empty() {
            if known.is_some() {
                return Err(invalid_authority());
            }
            let mut targets = BTreeSet::from([self.target()?]);
            for row in &self.more {
                row.validate()?;
                if !targets.insert(row.target()?) {
                    return Err(invalid_authority());
                }
            }
        }
        if free_time {
            return self
                .act
                .validate_carried(OwnerActKind::FreeTimePolicy, self.act.target);
        }
        self.act
            .validate_carried(OwnerActKind::PolicySetting, self.target()?)
    }

    /// The target a catalogue key's or a vault-wide setting's act names: its
    /// slot's ([`setting_slot_target`]), else the setting's
    /// ([`policy_setting_target`]). The free-time policy's act names its
    /// agent instead.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn target(&self) -> Result<EntityId> {
        match &self.slot {
            Some(slot) => setting_slot_target(slot),
            None => policy_setting_target(&self.setting),
        }
    }

    /// The act as each of its rows bears on its own target (stage 7a-3), each
    /// with the value it left: the first row is the act itself; each further
    /// row's act names that row's target and `seen`, under the same decider.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn row_acts(&self) -> Result<Vec<(OwnerAct, Option<[u8; 32]>)>> {
        let mut acts = Vec::with_capacity(1 + self.more.len());
        acts.push((self.act, self.value));
        for row in &self.more {
            let act = OwnerAct {
                target: row.target()?,
                seen: row.seen,
                ..self.act
            };
            acts.push((act, row.value));
        }
        Ok(acts)
    }

    /// The act as it bears on `target` alone (stage 7a-3): the row that names
    /// it as a one-row act, its target and `seen` the row's; `None` when no
    /// row names it.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn on_target(&self, target: EntityId) -> Result<Option<Self>> {
        if self.act.target == target {
            return Ok(Some(Self {
                more: Vec::new(),
                ..self.clone()
            }));
        }
        for row in &self.more {
            if row.target()? == target {
                return Ok(Some(Self {
                    act: OwnerAct {
                        target,
                        seen: row.seen,
                        ..self.act
                    },
                    machine: self.machine,
                    setting: row.setting.clone(),
                    prior: row.prior,
                    value: row.value,
                    slot: row.slot.clone(),
                    inline: row.inline.clone(),
                    more: Vec::new(),
                }));
            }
        }
        Ok(None)
    }
}

pub(super) fn policy_setting_value(set: &PolicySettingSet) -> Value {
    let mut entries = vec![
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
    ];
    if let Some(slot) = &set.slot {
        entries.push((Value::from("slot"), Value::Binary(slot.encode())));
    }
    if let Some(inline) = &set.inline {
        entries.push((Value::from("inline"), Value::Binary(inline.clone())));
    }
    if !set.more.is_empty() {
        entries.push((
            Value::from("more"),
            Value::Array(set.more.iter().map(policy_setting_row_value).collect()),
        ));
    }
    Value::Map(entries)
}

/// One further row of a batch act, its keys in their wire order.
fn policy_setting_row_value(row: &PolicySettingRow) -> Value {
    let mut entries = vec![
        (Value::from("setting"), Value::from(row.setting.as_str())),
        (Value::from("seen"), binary_value(row.seen)),
        (Value::from("prior"), binary_value(row.prior)),
        (
            Value::from("value"),
            row.value.map_or(Value::Nil, binary_value),
        ),
    ];
    if let Some(slot) = &row.slot {
        entries.push((Value::from("slot"), Value::Binary(slot.encode())));
    }
    if let Some(inline) = &row.inline {
        entries.push((Value::from("inline"), Value::Binary(inline.clone())));
    }
    Value::Map(entries)
}

/// A setting's name, two digests (the second nil for a clear), and the slot
/// and inline value when the act names them; the op's shape check then pins
/// the name's shape, the act's kind and who may make it
/// ([`PolicySettingSet::validate`]). A slot is a row's stored key that
/// decodes and encodes back to the same bytes, so one row has one encoding.
/// A batch's further rows are a list that is never empty when present.
pub(super) fn decode_policy_setting(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let present = |name: &str| entries.iter().any(|(key, _)| key.as_str() == Some(name));
    let mut keys = POLICY_SETTING_KEYS.to_vec();
    keys.extend(
        POLICY_SETTING_OPTIONAL_KEYS
            .iter()
            .filter(|name| present(**name)),
    );
    validate_keys(entries, &keys)?;
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
        slot: present("slot")
            .then(|| decode_slot(required(entries, "slot")?))
            .transpose()?,
        inline: present("inline")
            .then(|| binary(required(entries, "inline")?))
            .transpose()?,
        more: present("more")
            .then(|| decode_more(required(entries, "more")?))
            .transpose()?
            .unwrap_or_default(),
    }))
}

/// A batch's further rows: a list of at least one row.
fn decode_more(value: &Value) -> Result<Vec<PolicySettingRow>> {
    let Value::Array(rows) = value else {
        return Err(invalid_authority());
    };
    if rows.is_empty() {
        return Err(invalid_authority());
    }
    rows.iter().map(decode_row).collect()
}

/// One further row, its optional keys present only when it names them.
fn decode_row(value: &Value) -> Result<PolicySettingRow> {
    let entries = map_entries(value)?;
    let present = |name: &str| entries.iter().any(|(key, _)| key.as_str() == Some(name));
    let mut keys = POLICY_SETTING_ROW_KEYS.to_vec();
    keys.extend(
        POLICY_SETTING_ROW_OPTIONAL_KEYS
            .iter()
            .filter(|name| present(**name)),
    );
    validate_keys(entries, &keys)?;
    Ok(PolicySettingRow {
        setting: required(entries, "setting")?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)?,
        slot: present("slot")
            .then(|| decode_slot(required(entries, "slot")?))
            .transpose()?,
        seen: decode_hash(required(entries, "seen")?)?,
        prior: decode_hash(required(entries, "prior")?)?,
        value: match required(entries, "value")? {
            Value::Nil => None,
            value => Some(decode_hash(value)?),
        },
        inline: present("inline")
            .then(|| binary(required(entries, "inline")?))
            .transpose()?,
    })
}

/// A slot as the wire carries it: a row's stored key, canonical.
pub(super) fn decode_slot(value: &Value) -> Result<RowKey> {
    let bytes = binary(value)?;
    let slot = RowKey::decode(&bytes).ok_or_else(invalid_authority)?;
    if slot.encode() != bytes {
        return Err(invalid_authority());
    }
    Ok(slot)
}

/// The bytes of a binary value.
fn binary(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Binary(bytes) => Ok(bytes.clone()),
        _ => Err(invalid_authority()),
    }
}

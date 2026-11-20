//! One pack's head as one engine act (stage 7c-3a; DESIGN 1.6 "Packs across machines"), and
//! its wire codec.
//!
//! The pack's version, the digest of its table of defaults, and the keys held at their earlier
//! accepted value, signed by the install key of the machine whose pack door weighed them alone,
//! with no owner act.
//!
//! The record is shape only; whether a reader can prove the table (its own build ships that
//! digest) each machine's projection judges.

use oneiron_contracts::fingerprint::{Fingerprint, purposes};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

/// The wire kind of a pack's head.
pub const OP_KIND_SETTING_PACK_HEAD: &str = "setting_pack_head";
const SETTING_PACK_HEAD_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    "machine",
    "pack",
    "version",
    "digest",
    "held",
    "seen",
];
/// The longest pack name a head carries, in bytes.
pub const SETTING_PACK_NAME_MAX: usize = 128;
/// The longest pack version a head carries, in bytes.
pub const SETTING_PACK_VERSION_MAX: usize = 64;
/// The most held keys a head carries.
pub const SETTING_PACK_HELD_MAX: usize = 1024;

/// One pack's head as one engine act, signed by the install key of `machine`, the carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingPackHead {
    /// The carrier: the machine whose pack door weighed the defaults.
    pub machine: EntityId,
    /// The pack's name.
    pub pack: String,
    /// The version of the pack the door's build ships.
    pub version: String,
    /// The digest of the pack's table of defaults.
    pub digest: [u8; 32],
    /// The keys held at their earlier accepted value, in name order.
    pub held: Vec<String>,
    /// The pack target's revision as the door's write read it.
    pub seen: [u8; 32],
}

/// The target a pack's head acts name (stage 7c-3a): the fingerprint of the pack's name under
/// [`purposes::setting::PACK_TARGET`], first 16 bytes. Derived from the name alone, so every
/// install names one frontier per pack.
///
/// # Errors
/// As [`owner_act_target`].
pub fn setting_pack_target(pack: &str) -> Result<EntityId> {
    let target = Fingerprint::of_parts(purposes::setting::PACK_TARGET, &[pack.as_bytes()]);
    EntityId::from_bytes(target.prefix::<16>())
}

impl SettingPackHead {
    /// The pack's target ([`setting_pack_target`]), the frontier its head acts name.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn target(&self) -> Result<EntityId> {
        setting_pack_target(&self.pack)
    }

    /// A non-empty pack name and version within their bounds and with no control character;
    /// at most [`SETTING_PACK_HELD_MAX`] held names, strictly ascending, each a setting name
    /// ([`is_policy_setting_name`]).
    pub fn validate(&self) -> Result<()> {
        if self.pack.is_empty()
            || self.pack.len() > SETTING_PACK_NAME_MAX
            || self.pack.chars().any(|at| at.is_control())
            || self.version.is_empty()
            || self.version.len() > SETTING_PACK_VERSION_MAX
            || self.version.chars().any(|at| at.is_control())
            || self.held.len() > SETTING_PACK_HELD_MAX
            || !self.held.windows(2).all(|pair| pair[0] < pair[1])
            || !self.held.iter().all(|name| is_policy_setting_name(name))
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// A pack's head as its wire map: kind, machine, pack, version, digest, held and seen.
pub(super) fn setting_pack_head_value(head: &SettingPackHead) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_SETTING_PACK_HEAD),
        ),
        (Value::from("machine"), Value::from(head.machine.to_hex())),
        (Value::from("pack"), Value::from(head.pack.as_str())),
        (Value::from("version"), Value::from(head.version.as_str())),
        (Value::from("digest"), binary_value(head.digest)),
        (
            Value::from("held"),
            Value::Array(
                head.held
                    .iter()
                    .map(|name| Value::from(name.as_str()))
                    .collect(),
            ),
        ),
        (Value::from("seen"), binary_value(head.seen)),
    ])
}

/// A machine, a pack name and version, two digests and a list of held names; the op's shape
/// check then pins the bounds, the order and the names ([`SettingPackHead::validate`]).
pub(super) fn decode_setting_pack_head(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &SETTING_PACK_HEAD_KEYS)?;
    let held = match required(entries, "held")? {
        Value::Array(names) => names
            .iter()
            .map(|name| {
                name.as_str()
                    .map(str::to_owned)
                    .ok_or_else(invalid_authority)
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::SettingPackHead(SettingPackHead {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        pack: required(entries, "pack")?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)?,
        version: required(entries, "version")?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)?,
        digest: decode_hash(required(entries, "digest")?)?,
        held,
        seen: decode_hash(required(entries, "seen")?)?,
    }))
}

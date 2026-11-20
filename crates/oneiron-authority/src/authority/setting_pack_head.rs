//! One pack's head as one engine act (stage 7c-3a; DESIGN 1.6 "Packs across machines"), and
//! its wire codec.
//!
//! The pack's version, the digest of its table of defaults, and the keys held at their earlier
//! accepted value, signed by the install key of the machine whose pack door weighed them alone,
//! with no owner act.
//!
//! The owner's yes to held defaults is the same record with his act and the keys he accepts
//! (stage 7c-3c; DESIGN 1.6, "A holder's yes to a held default names the digest too", and "A yes
//! is an act of its own"; [`SettingPackAccept`]). It names a target of its own, one per pack and
//! table ([`setting_pack_accept_target`]), so a pack door's later head never replaces it. It is
//! proved as any owner act is proved, and a proved yes proves the table its digest names.
//!
//! The record is shape only; whether a reader can prove the table (its own build ships that
//! digest, or a proved yes names it) each machine's projection judges.

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
/// The most held keys a head carries, and the most keys a yes accepts.
pub const SETTING_PACK_HELD_MAX: usize = 1024;
/// The keys only the owner's yes carries (stage 7c-3c): its act and the keys it accepts.
const SETTING_PACK_ACCEPT_KEYS: [&str; 2] = [OP_KEY_ACT, "accepted"];

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
    /// The keys held at their earlier accepted value, in name order; for the owner's yes, the
    /// keys still held on the machine that carried it.
    pub held: Vec<String>,
    /// The revision of the act's target ([`Self::target`]) as its write read it.
    pub seen: [u8; 32],
    /// The owner's yes this record is (stage 7c-3c); `None` for a pack door's head, which no
    /// one decided.
    pub accept: Option<SettingPackAccept>,
}

/// The owner's yes to held defaults of a pack's table (stage 7c-3c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingPackAccept {
    /// The owner's act on the yes's target ([`setting_pack_accept_target`]): kind
    /// `policy_setting`, by the owner, its `seen` the record's own.
    pub act: OwnerAct,
    /// The keys whose default of the head's table the owner accepts, in name order; none of
    /// them is held.
    pub accepted: Vec<String>,
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

/// The target the owner's yes to defaults of `pack`'s table `digest` names (stage 7c-3c): the
/// fingerprint of the pack's name and the digest under
/// [`purposes::setting::PACK_ACCEPT_TARGET`], first 16 bytes. One frontier per pack and table,
/// apart from the pack's heads.
///
/// # Errors
/// As [`owner_act_target`].
pub fn setting_pack_accept_target(pack: &str, digest: &[u8; 32]) -> Result<EntityId> {
    let target = Fingerprint::of_parts(
        purposes::setting::PACK_ACCEPT_TARGET,
        &[pack.as_bytes(), digest.as_slice()],
    );
    EntityId::from_bytes(target.prefix::<16>())
}

impl SettingPackHead {
    /// The frontier the act names: its pack's ([`setting_pack_target`]) for a pack door's head;
    /// for the owner's yes, its pack's and table's ([`setting_pack_accept_target`]).
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn target(&self) -> Result<EntityId> {
        match &self.accept {
            None => setting_pack_target(&self.pack),
            Some(_) => setting_pack_accept_target(&self.pack, &self.digest),
        }
    }

    /// A non-empty pack name and version within their bounds and with no control character;
    /// at most [`SETTING_PACK_HELD_MAX`] held names, strictly ascending, each a setting name
    /// ([`is_policy_setting_name`]). A yes's act is the owner's own `policy_setting` act on its
    /// target ([`Self::target`]) at the record's `seen`, with no answer, and it accepts at least
    /// one and at most [`SETTING_PACK_HELD_MAX`] names of the same shape, none of them held.
    pub fn validate(&self) -> Result<()> {
        if self.pack.is_empty()
            || self.pack.len() > SETTING_PACK_NAME_MAX
            || self.pack.chars().any(|at| at.is_control())
            || self.version.is_empty()
            || self.version.len() > SETTING_PACK_VERSION_MAX
            || self.version.chars().any(|at| at.is_control())
            || !names_in_shape(&self.held)
        {
            return Err(invalid_authority());
        }
        if let Some(accept) = &self.accept
            && (accept.act.by != ActBy::Owner
                || accept.act.act != OwnerActKind::PolicySetting
                || accept.act.target != self.target()?
                || accept.act.seen != self.seen
                || accept.act.answer.is_some()
                || accept.accepted.is_empty()
                || !names_in_shape(&accept.accepted)
                || accept
                    .accepted
                    .iter()
                    .any(|name| self.held.binary_search(name).is_ok()))
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// At most [`SETTING_PACK_HELD_MAX`] names, strictly ascending, each a setting name
/// ([`is_policy_setting_name`]).
fn names_in_shape(names: &[String]) -> bool {
    names.len() <= SETTING_PACK_HELD_MAX
        && names.windows(2).all(|pair| pair[0] < pair[1])
        && names.iter().all(|name| is_policy_setting_name(name))
}

/// A list of names as its wire array.
fn names_value(names: &[String]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|name| Value::from(name.as_str()))
            .collect(),
    )
}

/// A wire array of names; the shape check pins their order and form.
fn decode_names(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::Array(names) => names
            .iter()
            .map(|name| {
                name.as_str()
                    .map(str::to_owned)
                    .ok_or_else(invalid_authority)
            })
            .collect(),
        _ => Err(invalid_authority()),
    }
}

/// A pack's head as its wire map: kind, machine, pack, version, digest, held and seen, then a
/// yes's act and accepted keys.
pub(super) fn setting_pack_head_value(head: &SettingPackHead) -> Value {
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_SETTING_PACK_HEAD),
        ),
        (Value::from("machine"), Value::from(head.machine.to_hex())),
        (Value::from("pack"), Value::from(head.pack.as_str())),
        (Value::from("version"), Value::from(head.version.as_str())),
        (Value::from("digest"), binary_value(head.digest)),
        (Value::from("held"), names_value(&head.held)),
        (Value::from("seen"), binary_value(head.seen)),
    ];
    if let Some(accept) = &head.accept {
        entries.push((
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&accept.act),
        ));
        entries.push((Value::from("accepted"), names_value(&accept.accepted)));
    }
    Value::Map(entries)
}

/// A machine, a pack name and version, two digests and a list of held names, and for a yes both
/// its act and its accepted names, or neither; the op's shape check then pins the bounds, the
/// order, the names and the act ([`SettingPackHead::validate`]).
pub(super) fn decode_setting_pack_head(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let present = |name: &str| entries.iter().any(|(key, _)| key.as_str() == Some(name));
    let accept = present(OP_KEY_ACT) || present("accepted");
    let mut keys = SETTING_PACK_HEAD_KEYS.to_vec();
    if accept {
        keys.extend(SETTING_PACK_ACCEPT_KEYS);
    }
    validate_keys(entries, &keys)?;
    let held = decode_names(required(entries, "held")?)?;
    let accept = accept
        .then(|| -> Result<SettingPackAccept> {
            Ok(SettingPackAccept {
                act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
                accepted: decode_names(required(entries, "accepted")?)?,
            })
        })
        .transpose()?;
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
        accept,
    }))
}

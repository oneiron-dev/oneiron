//! The owner's naming of a device key's successor (FIX 11135, Engine 11-06
//! 06:58 = A), and its wire codec.
//!
//! An install that rejoins the vault as a new machine (a lost keychain, a
//! raw-copied vault) drops its device key, and with it every erase receipt
//! that key attested: "this device attests only receipts it made" (FIX
//! 2596). When the owner names the old key as the predecessor of the
//! install he is on, that install signs one succession: the predecessor's
//! client id and device key, and the successor machine, its own. The act
//! ([`OwnerAct`], kind `device_succession`) targets the id
//! [`device_succession_target`] derives from the predecessor pair, and its
//! `seen` is that pair's live successions, under
//! [`DEVICE_SUCCESSION_REVISION_CONTEXT`]. It is a main-log entry, so every
//! machine the owner admits folds it.
//!
//! The record is shape only: a nonzero client id, the 32-byte key and a
//! successor machine. Only the successor completes the predecessor's
//! receipts, each still verified under the key that signed it. The succession
//! is the owner's: no Grant action names it, so an agent's act never makes it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_DEVICE_SUCCESSION: &str = "device_succession";
const DEVICE_SUCCESSION_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "client",
    "device_key",
    "successor",
];
/// The domain of a device succession's `seen`, beside the origin cut's
/// ([`ORIGIN_CUT_REVISION_CONTEXT`]): BLAKE3 over it and the predecessor
/// pair's sorted live succession hashes, in the `PolicyRevision` shape.
pub const DEVICE_SUCCESSION_REVISION_CONTEXT: &[u8] = b"oneiron/device-succession-revision/v1";

/// The target a device succession act names: an id derived from the
/// predecessor's client id (8 bytes, little endian, as the install stores
/// it) and its 32-byte device key, so every install names the same target
/// and the act binds the one predecessor it carries.
pub fn device_succession_target(client: u64, device_key: &[u8; 32]) -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::DEVICE_SUCCESSION_TARGET,
        &[client.to_le_bytes().as_slice(), device_key.as_slice()],
    )
}

/// One owner succession of a device key, signed by the install key of
/// `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSuccession {
    /// The owner's act: who decided, from which surface, on which of the
    /// predecessor's succession revisions. Its kind is `device_succession`
    /// and its target [`device_succession_target`] of the predecessor pair.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the succession.
    pub machine: EntityId,
    /// The predecessor's client id, never zero.
    pub client: u64,
    /// The predecessor's device verifying key.
    pub device_key: [u8; 32],
    /// The machine that completes the predecessor's receipts.
    pub successor: EntityId,
}

impl DeviceSuccession {
    pub fn validate(&self) -> Result<()> {
        // The succession is the owner's own: no Grant action names it, and
        // no ask answers it, so only his say-so makes it.
        if self.client == 0
            || self.act.act != OwnerActKind::DeviceSuccession
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names the succession's own predecessor.
    pub fn validate_entry(&self, _entry: &AuthorityLogEntry) -> Result<()> {
        self.act.validate_carried(
            OwnerActKind::DeviceSuccession,
            device_succession_target(self.client, &self.device_key)?,
        )
    }
}

pub(super) fn device_succession_value(succession: &DeviceSuccession) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_DEVICE_SUCCESSION),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&succession.act),
        ),
        (
            Value::from("machine"),
            Value::from(succession.machine.to_hex()),
        ),
        (Value::from("client"), Value::from(succession.client)),
        (
            Value::from("device_key"),
            super::wire_encode::binary_value(succession.device_key),
        ),
        (
            Value::from("successor"),
            Value::from(succession.successor.to_hex()),
        ),
    ])
}

/// A u64 client id, a 32-byte key and two canonical machine ids; the op's
/// shape check then refuses a zero client id.
pub(super) fn decode_device_succession(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &DEVICE_SUCCESSION_KEYS)?;
    Ok(AuthorityOp::DeviceSuccession(DeviceSuccession {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        client: required(entries, "client")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        device_key: super::wire_decode::decode_hash(required(entries, "device_key")?)?,
        successor: decode_canonical_id(required(entries, "successor")?)?,
    }))
}

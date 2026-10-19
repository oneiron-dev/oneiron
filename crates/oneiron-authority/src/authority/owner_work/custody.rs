//! A custody work map: one change to one portable secret's custody (WILL L04
//! row 04), asked of the install the request names.
//!
//! The act's target is the secret's custody record id. The map holds the
//! change, the generation it approves, the digest of the encrypted input an
//! active change needs, the holder that does it and the recipients the owner
//! permits to hold its bytes: ids, digests and a generation only. No name,
//! value, manifest or effector text enters the main log. A revoke needs no
//! byte: it names no input, holder or recipient.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

const CUSTODY_WORK_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    "change",
    "generation",
    "input",
    "holder",
    "recipients",
];
const PERMIT_KEYS: [&str; 3] = ["machine", "profile", "encryption_key"];

/// The most recipients one active custody change permits, as one custody
/// transition seals its value to at most this many machines.
pub const CUSTODY_RECIPIENTS_MAX: usize = 64;

/// The context a custody request's `seen` is hashed under: the live custody
/// request heads of its secret ([`act_revision`]).
pub const CUSTODY_WORK_REVISION_CONTEXT: &[u8] = b"oneiron/custody-work-revision/v1";

/// How a custody body carries the recipients it permits (CALLS
/// CUSTODY_SHARED_BODY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyBodyShape {
    /// Inline in the request's own work map, bounded before allocation. The
    /// shared [`OwnerWorkBody`] and [`OwnerWorkRequest`] are `Clone`, no
    /// longer `Copy`; no permit store, digest or second transport exists.
    CloneNotCopy,
}

const CUSTODY_SHARED_BODY: CustodyBodyShape = CustodyBodyShape::CloneNotCopy;

/// The change a custody request asks for: the `change` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CustodyChange {
    /// Register a new portable secret from the encrypted input.
    Register,
    /// Replace the secret's value from the encrypted input, one generation
    /// on.
    Rotate,
    /// Seal the current value again, same generation and status, to the
    /// recipients permitted.
    Rewrap,
    /// End the secret here and on every replica: terminal for its id. No
    /// byte is needed.
    Revoke,
}

impl CustodyChange {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Rotate => "rotate",
            Self::Rewrap => "rewrap",
            Self::Revoke => "revoke",
        }
    }

    /// The change a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "register" => Self::Register,
            "rotate" => Self::Rotate,
            "rewrap" => Self::Rewrap,
            "revoke" => Self::Revoke,
            _ => return None,
        })
    }
}

/// One install the owner permits to hold a custody change's bytes, bound to
/// the exact profile entry and encryption key he saw.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CustodyRecipientPermit {
    pub machine: EntityId,
    /// The entry hash of the machine profile admitted when he permitted it.
    pub profile: [u8; 32],
    /// The digest of the canonical encryption suite and public key.
    pub encryption_key: [u8; 32],
}

/// A custody request's shape. A register or rotate states its input and its
/// holder, a rewrap its holder and no input, each permitting 1 to
/// [`CUSTODY_RECIPIENTS_MAX`] recipients, ascending by machine, one each,
/// and the holder executes it. A revoke states none of them, and its carrier
/// executes it: a revoke needs no byte. No digest is zero.
pub(super) fn validate_custody(
    request: &OwnerWorkRequest,
    change: CustodyChange,
    input: Option<[u8; 32]>,
    holder: Option<EntityId>,
    recipients: &[CustodyRecipientPermit],
) -> Result<()> {
    let shaped = match change {
        CustodyChange::Revoke => {
            input.is_none()
                && holder.is_none()
                && recipients.is_empty()
                && request.executor == request.carrier
        }
        CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap => {
            input.is_some() == (change != CustodyChange::Rewrap)
                && holder == Some(request.executor)
                && (1..=CUSTODY_RECIPIENTS_MAX).contains(&recipients.len())
                && recipients
                    .windows(2)
                    .all(|pair| pair[0].machine < pair[1].machine)
        }
    };
    let zero = input.is_some_and(|input| input == [0; 32])
        || recipients
            .iter()
            .any(|permit| permit.profile == [0; 32] || permit.encryption_key == [0; 32]);
    if !shaped || zero {
        return Err(invalid_authority());
    }
    Ok(())
}

/// Canonical field order: kind, change, generation, input, holder, then
/// recipients, each field the change does not state nil (recipients empty);
/// a permit map is machine, profile, then encryption key.
pub(super) fn custody_work_value(
    change: CustodyChange,
    generation: u32,
    input: Option<[u8; 32]>,
    holder: Option<EntityId>,
    recipients: &[CustodyRecipientPermit],
) -> Value {
    let recipients = match CUSTODY_SHARED_BODY {
        CustodyBodyShape::CloneNotCopy => recipients.iter().map(permit_value).collect(),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OwnerWorkKind::Custody.as_str()),
        ),
        (Value::from("change"), Value::from(change.as_str())),
        (Value::from("generation"), Value::from(generation)),
        (Value::from("input"), input.map_or(Value::Nil, binary_value)),
        (
            Value::from("holder"),
            holder.map_or(Value::Nil, |holder| Value::from(holder.to_hex())),
        ),
        (Value::from("recipients"), Value::Array(recipients)),
    ])
}

fn permit_value(permit: &CustodyRecipientPermit) -> Value {
    Value::Map(vec![
        (Value::from("machine"), Value::from(permit.machine.to_hex())),
        (Value::from("profile"), binary_value(permit.profile)),
        (
            Value::from("encryption_key"),
            binary_value(permit.encryption_key),
        ),
    ])
}

/// Strict keys; the recipient list is bounded before one permit is decoded.
/// The shape is the request's ([`validate_custody`]).
pub(super) fn decode_custody_work(work: &[(Value, Value)]) -> Result<OwnerWorkBody> {
    validate_keys(work, &CUSTODY_WORK_KEYS)?;
    let recipients = match CUSTODY_SHARED_BODY {
        CustodyBodyShape::CloneNotCopy => {
            let Value::Array(permits) = required(work, "recipients")? else {
                return Err(invalid_authority());
            };
            if permits.len() > CUSTODY_RECIPIENTS_MAX {
                return Err(invalid_authority());
            }
            permits
                .iter()
                .map(decode_permit)
                .collect::<Result<Vec<_>>>()?
        }
    };
    Ok(OwnerWorkBody::Custody {
        change: required(work, "change")?
            .as_str()
            .and_then(CustodyChange::from_name)
            .ok_or_else(invalid_authority)?,
        generation: required(work, "generation")?
            .as_u64()
            .and_then(|generation| u32::try_from(generation).ok())
            .ok_or_else(invalid_authority)?,
        input: decode_optional_hash(required(work, "input")?)?,
        holder: match required(work, "holder")? {
            Value::Nil => None,
            value => Some(decode_canonical_id(value)?),
        },
        recipients,
    })
}

fn decode_permit(value: &Value) -> Result<CustodyRecipientPermit> {
    let entries = map_entries(value)?;
    validate_keys(entries, &PERMIT_KEYS)?;
    Ok(CustodyRecipientPermit {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        profile: decode_hash(required(entries, "profile")?)?,
        encryption_key: decode_hash(required(entries, "encryption_key")?)?,
    })
}

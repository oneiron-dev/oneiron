//! The owner's whole-vault export as a signed owner act (FIX 4624), and its
//! wire codec.
//!
//! An export changes nothing: the record is the signed account of the
//! owner's will to copy the vault out, beside the export audit row the
//! exporting install keeps. The install that served him, a live machine of
//! the vault in any role, signs it with its install key after the copy is
//! made; the record carries his act ([`OwnerAct`], kind `export`, on the
//! reserved target [`EXPORT_ACT_TARGET_NAME`], `seen` zero:
//! [`EXPORT_ACT_SEEN`]) and what left: the copy's id, its format, and its
//! length and BLAKE3 where the door read the copy back. Never a byte of the
//! copy. It is a main-log entry, so every machine the owner admits folds it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_EXPORT_ACT: &str = "export_act";
const EXPORT_ACT_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "export",
    "format",
    "bytes",
    "digest",
];
/// The name the reserved target of every export act derives from
/// ([`owner_act_target`]).
pub const EXPORT_ACT_TARGET_NAME: &str = "vault.export";
/// The `seen` of every export act: an export changes nothing, so it names no
/// revision.
pub const EXPORT_ACT_SEEN: [u8; 32] = [0; 32];
/// The longest format name an export act carries.
pub const EXPORT_ACT_FORMAT_MAX: usize = 64;

/// One owner export, signed by the install key of `machine`, a live machine
/// of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportActRecord {
    /// The owner's act: kind `export`, on the reserved export target, `seen`
    /// zero.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the record.
    pub machine: EntityId,
    /// The copy's id, as the export audit row names it.
    pub export: EntityId,
    /// The copy's format (`archive`, `okf`).
    pub format: String,
    /// The copy's length, where its door read the copy back.
    pub bytes: Option<u64>,
    /// BLAKE3 of the copy, where its door read the copy back.
    pub digest: Option<[u8; 32]>,
}

impl ExportActRecord {
    /// The act names the export target with a zero `seen`, and no ask
    /// answers it; the format is a short name.
    pub fn validate(&self) -> Result<()> {
        if self.act.seen != EXPORT_ACT_SEEN
            || self.format.is_empty()
            || self.format.len() > EXPORT_ACT_FORMAT_MAX
        {
            return Err(invalid_authority());
        }
        self.act.validate_carried(
            OwnerActKind::Export,
            owner_act_target(EXPORT_ACT_TARGET_NAME)?,
        )
    }
}

pub(super) fn export_act_value(record: &ExportActRecord) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_EXPORT_ACT)),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&record.act),
        ),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (Value::from("export"), Value::from(record.export.to_hex())),
        (Value::from("format"), Value::from(record.format.as_str())),
        (
            Value::from("bytes"),
            record.bytes.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("digest"),
            record.digest.map_or(Value::Nil, binary_value),
        ),
    ])
}

/// The length and digest each as written or nil; the op's shape check then
/// pins the act and the format's bound.
pub(super) fn decode_export_act(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &EXPORT_ACT_KEYS)?;
    let bytes = match required(entries, "bytes")? {
        Value::Nil => None,
        value => Some(value.as_u64().ok_or_else(invalid_authority)?),
    };
    let digest = match required(entries, "digest")? {
        Value::Nil => None,
        value => Some(decode_hash(value)?),
    };
    Ok(AuthorityOp::ExportAct(ExportActRecord {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        export: decode_canonical_id(required(entries, "export")?)?,
        format: required(entries, "format")?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)?,
        bytes,
        digest,
    }))
}

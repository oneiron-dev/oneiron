//! One machine's own declaration that it holds a full copy (L7-47;
//! ARCH-0023b `#peer-fetch`; CROSS-ARCH-0024 `#my-network` item 04: "A full
//! copy earns roles. It is a live backup and a standby home."), and its wire
//! codec.
//!
//! To hold a full copy is to hold every window the machine may read, synced
//! under sync all. The machine's own install key signs the mark alone, as it
//! signs that machine's home candidacy: it states what the machine is, never
//! what the owner chose. It is a main-log entry, so every machine the owner
//! admits folds it, and each one's peer order reads every machine's newest
//! mark while its home is down.
//!
//! The record is shape only: which machine, and whether it holds the copy.
//! Whether its machine still proves the key that signed it here, each
//! machine's fold judges on the fold it reads.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_FULL_COPY_MARK: &str = "full_copy_mark";
const FULL_COPY_MARK_KEYS: [&str; 3] = [OP_KEY_KIND, "machine", "held"];

/// One machine's declaration that it holds a full copy, signed by that
/// machine's install key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullCopyMark {
    /// The declaring machine, whose install key signs the mark.
    pub machine: EntityId,
    /// The machine holds a full copy now.
    pub held: bool,
}

impl FullCopyMark {
    /// Signed alone by an Ed25519 install key, with no cosigner, as a
    /// residence result is (L7-47).
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn full_copy_mark_value(mark: &FullCopyMark) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_FULL_COPY_MARK),
        ),
        (Value::from("machine"), Value::from(mark.machine.to_hex())),
        (Value::from("held"), Value::from(mark.held)),
    ])
}

/// A boolean; the op's shape check has nothing more to refuse.
pub(super) fn decode_full_copy_mark(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &FULL_COPY_MARK_KEYS)?;
    Ok(AuthorityOp::FullCopyMark(FullCopyMark {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        held: required(entries, "held")?
            .as_bool()
            .ok_or_else(invalid_authority)?,
    }))
}

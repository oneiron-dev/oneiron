//! A machine's own declaration of itself as a MACRO home candidate (FIX
//! 4898; ARCH-0026: "Election order is cloud node when attached, then an
//! always-on local node, then the primary device"), and its wire codec.
//!
//! Each install declares its own machine: the sync node id an election names
//! it by and MACRO admission matches, the facts the default order ranks (a
//! hosted cloud node, an always-on machine, the owner's primary device), and
//! whether it can take MACRO work now. The install key of that machine signs
//! it, as it signs the owner's acts it carries; no owner act rides it, since
//! it states what the machine is, never what the owner chose. It is a
//! main-log entry, so every machine the owner admits folds it, and each one's
//! election reads every machine's newest declaration.
//!
//! The record is shape only: a nonzero node id. Whether its machine stands,
//! in which role and under which key, each machine's election judges on the
//! fold it reads.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_HOME_CANDIDACY: &str = "home_candidacy";
const HOME_CANDIDACY_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    "machine",
    "node_id",
    "always_on",
    "primary",
    "macro_ready",
    "cloud",
];

/// One machine's declaration of itself as a MACRO home candidate, signed by
/// that machine's install key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeCandidacy {
    /// The declaring machine, whose install key signs the declaration.
    pub machine: EntityId,
    /// Its stable sync node id, never zero: the id an election names and
    /// MACRO admission matches.
    pub node_id: u64,
    /// The machine stays on: a served host, or a device its owner marks so.
    pub always_on: bool,
    /// The owner marks it his primary device.
    pub primary: bool,
    /// Its Dreamer runs, so it can take MACRO work now.
    pub macro_ready: bool,
    /// A hosted node: the cloud node the default order ranks first.
    pub cloud: bool,
}

impl HomeCandidacy {
    pub fn validate(&self) -> Result<()> {
        if self.node_id == 0 {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn home_candidacy_value(declaration: &HomeCandidacy) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_HOME_CANDIDACY),
        ),
        (
            Value::from("machine"),
            Value::from(declaration.machine.to_hex()),
        ),
        (Value::from("node_id"), Value::from(declaration.node_id)),
        (Value::from("always_on"), Value::from(declaration.always_on)),
        (Value::from("primary"), Value::from(declaration.primary)),
        (
            Value::from("macro_ready"),
            Value::from(declaration.macro_ready),
        ),
        (Value::from("cloud"), Value::from(declaration.cloud)),
    ])
}

/// A u64 and four booleans; the op's shape check then refuses a zero node.
pub(super) fn decode_home_candidacy(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &HOME_CANDIDACY_KEYS)?;
    let flag = |name: &str| -> Result<bool> {
        required(entries, name)?
            .as_bool()
            .ok_or_else(invalid_authority)
    };
    Ok(AuthorityOp::HomeCandidacy(HomeCandidacy {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        node_id: required(entries, "node_id")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        always_on: flag("always_on")?,
        primary: flag("primary")?,
        macro_ready: flag("macro_ready")?,
        cloud: flag("cloud")?,
    }))
}

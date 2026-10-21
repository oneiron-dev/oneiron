//! A frontier join (FIX 7908, Phase2 B; CALLS "Phase2 frontier join"): one
//! signed main-log row whose parents are a canonical group of a wide causal
//! frontier's heads, so an act whose frontier is wider than one entry names
//! takes the join tips as its parents and keeps every head in its causal
//! past, instead of being refused.
//!
//! A join carries no semantic payload: no grant, role, clearance, consent or
//! revoke, and it never stands for an owner act. It names only the machine
//! whose install key signs it, as that key signs the act it leads to, or no
//! machine when the host's slip issuer signs it for a host-issued op: the
//! signer domain the store doors vouch for it in, never a new constituency.
//! Its parents are representation only: [`AUTHORITY_FRONTIER_JOIN_ARITY`]
//! bounds one join's parents, never how many heads a frontier may hold.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_FRONTIER_JOIN: &str = "frontier_join";
const FRONTIER_JOIN_KEYS: [&str; 2] = [OP_KEY_KIND, "carrier"];

/// The parents one join names (CALLS "Phase2 frontier join arity"): the
/// entry bound, a representation only, never a logical-head limit.
pub const AUTHORITY_FRONTIER_JOIN_ARITY: usize = MAX_PARENTS;

/// One join of a wide frontier, signed by the install key of `carrier`, or
/// by the host's slip issuer when `carrier` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontierJoin {
    /// The machine whose install key signs the join; `None` for a join the
    /// host's slip issuer signs ahead of a host-issued op.
    pub carrier: Option<EntityId>,
}

impl FrontierJoin {
    /// A join has no field to judge alone.
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// A join names at least two parents and is signed by one key alone, an
    /// Ed25519 install key when a machine carries it.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.parent_hashes.len() < 2
            || !entry.cosigns.is_empty()
            || (self.carrier.is_some() && entry.signer.suite != AuthoritySignatureSuite::Ed25519)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, then carrier (nil for the host's issuer).
pub(super) fn frontier_join_value(join: &FrontierJoin) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_FRONTIER_JOIN)),
        (
            Value::from("carrier"),
            join.carrier
                .map_or(Value::Nil, |carrier| Value::from(carrier.to_hex())),
        ),
    ])
}

pub(super) fn decode_frontier_join(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &FRONTIER_JOIN_KEYS)?;
    let carrier = match required(entries, "carrier")? {
        Value::Nil => None,
        value => Some(decode_canonical_id(value)?),
    };
    Ok(AuthorityOp::FrontierJoin(FrontierJoin { carrier }))
}

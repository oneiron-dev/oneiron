//! A frontier join (FIX 7908, Phase2 B; CALLS "Phase2 frontier join"): one
//! signed main-log row whose parents are a canonical group of a wide causal
//! frontier's heads, so an act whose frontier is wider than one entry names
//! takes the join tips as its parents and keeps every head in its causal
//! past, instead of being refused.
//!
//! A join carries no semantic payload: no grant, role, clearance, consent or
//! revoke, and it never stands for an owner act. It names only the signer
//! family of the rows it leads to: the machine whose install key signs it,
//! as that key signs the act; no machine when the host's slip issuer signs
//! it for a host-issued op; or an owner anchor's own rows when a stored
//! root's anchor signs it (FIX 8498): the signer domain the store doors
//! vouch for it in, never a new constituency. Its parents are representation
//! only: [`AUTHORITY_FRONTIER_JOIN_ARITY`] bounds one join's parents, never
//! how many heads a frontier may hold.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_FRONTIER_JOIN: &str = "frontier_join";
const FRONTIER_JOIN_KEYS: [&str; 2] = [OP_KEY_KIND, "carrier"];
/// An owner anchor's join names no carrier and marks its family.
const ANCHOR_JOIN_KEYS: [&str; 3] = [OP_KEY_KIND, "carrier", "anchor"];

/// The parents one join names (CALLS "Phase2 frontier join arity"): the
/// entry bound, a representation only, never a logical-head limit.
pub const AUTHORITY_FRONTIER_JOIN_ARITY: usize = MAX_PARENTS;

/// The signer family one join is signed in: the one of the rows it leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierJoinFamily {
    /// The install key of this machine, the carrier of the act.
    Install(EntityId),
    /// The host's slip issuer, ahead of a host-issued op.
    Host,
    /// A stored owner root's anchor, ahead of that anchor's own rows: its
    /// root record, its marks and the owner's kit push (FIX 8498, Engine
    /// 09:31). The join carries no key; the fold reads the anchor it
    /// recorded for those rows.
    Anchor,
}

/// One join of a wide frontier, signed in `family`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontierJoin {
    pub family: FrontierJoinFamily,
}

impl FrontierJoin {
    /// A join has no field to judge alone; it names at least two parents
    /// and is signed by one Ed25519 key alone: an install key, the host's
    /// slip issuer or an owner anchor, all Ed25519.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.parent_hashes.len() < 2
            || !entry.cosigns.is_empty()
            || entry.signer.suite != AuthoritySignatureSuite::Ed25519
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, then carrier (nil for the host's issuer and
/// an anchor), then, for an anchor's join alone, `anchor` true.
pub(super) fn frontier_join_value(join: &FrontierJoin) -> Value {
    let carrier = match join.family {
        FrontierJoinFamily::Install(carrier) => Value::from(carrier.to_hex()),
        FrontierJoinFamily::Host | FrontierJoinFamily::Anchor => Value::Nil,
    };
    let mut fields = vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_FRONTIER_JOIN)),
        (Value::from("carrier"), carrier),
    ];
    if join.family == FrontierJoinFamily::Anchor {
        fields.push((Value::from("anchor"), Value::Boolean(true)));
    }
    Value::Map(fields)
}

pub(super) fn decode_frontier_join(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let anchor = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some("anchor"));
    if anchor {
        validate_keys(entries, &ANCHOR_JOIN_KEYS)?;
    } else {
        validate_keys(entries, &FRONTIER_JOIN_KEYS)?;
    }
    let family = match required(entries, "carrier")? {
        Value::Nil if !anchor => FrontierJoinFamily::Host,
        Value::Nil if matches!(required(entries, "anchor")?, Value::Boolean(true)) => {
            FrontierJoinFamily::Anchor
        }
        value if !anchor => FrontierJoinFamily::Install(decode_canonical_id(value)?),
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::FrontierJoin(FrontierJoin { family }))
}

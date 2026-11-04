//! A frontier join (FIX 7908, Phase2 B; CALLS "Phase2 frontier join"): one
//! signed main-log row whose parents are a canonical group of a wide causal
//! frontier's heads, so an act whose frontier is wider than one entry names
//! takes the join tips as its parents and keeps every head in its causal
//! past, instead of being refused.
//!
//! A join carries no semantic payload: no grant, role, clearance, consent or
//! revoke, and it never stands for an owner act. It names only the signer
//! family of the rows it leads to: the machine whose install key signs it,
//! as that key signs the act; no machine when a live owner roster key signs
//! it: the host's slip issuer for a host-issued op, or the root a ReRoot
//! retires ahead of that ReRoot (FIX 11867); or an owner anchor's own rows
//! when a stored root's anchor signs it (FIX 8498): the signer domain the
//! store doors vouch for it in, never a new constituency. Its parents are
//! representation only: [`AUTHORITY_FRONTIER_JOIN_ARITY`] bounds one join's
//! parents, never how many heads a frontier may hold.
//!
//! A join covers the main log's heads, or the signer's own side heads where
//! those alone fill one entry (FIX 11868): an owner anchor's own rows that
//! an install not pinning its root keeps beside the main log, or a world's
//! side leaves. Such a join rides the branch it joins ([`FrontierJoinScope`]).

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_FRONTIER_JOIN: &str = "frontier_join";
const FRONTIER_JOIN_KEYS: [&str; 2] = [OP_KEY_KIND, "carrier"];
/// An owner anchor's join names no carrier and marks its family.
const ANCHOR_JOIN_KEYS: [&str; 3] = [OP_KEY_KIND, "carrier", "anchor"];
/// An anchor's join of its own side heads marks that scope too.
const ANCHOR_SIDE_JOIN_KEYS: [&str; 4] = [OP_KEY_KIND, "carrier", "anchor", "side"];
/// A join of a world's side leaves names its carrier and its world.
const WORLD_JOIN_KEYS: [&str; 3] = [OP_KEY_KIND, "carrier", "world"];

/// The parents one join names (CALLS "Phase2 frontier join arity"): the
/// entry bound, a representation only, never a logical-head limit.
pub const AUTHORITY_FRONTIER_JOIN_ARITY: usize = MAX_PARENTS;

/// The signer family one join is signed in: the one of the rows it leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierJoinFamily {
    /// The install key of this machine, the carrier of the act.
    Install(EntityId),
    /// A live owner roster key: the host's slip issuer, ahead of a
    /// host-issued op, or the root a ReRoot retires, ahead of that ReRoot
    /// (FIX 11867).
    Host,
    /// A stored owner root's anchor, ahead of that anchor's own rows: its
    /// root record, its marks and the owner's kit push (FIX 8498, Engine
    /// 09:31). The join carries no key; the fold reads the anchor it
    /// recorded for those rows.
    Anchor,
}

/// The heads one join joins, and so the branch the join rides (FIX 11868).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierJoinScope {
    /// The main log's heads: the join is a main-log row (FIX 7908).
    Main,
    /// Its anchor's own heads that an install not pinning its root keeps
    /// beside the main log: the join is one of that anchor's own rows, so
    /// it retires them there and no main-log door names it. An anchor's
    /// join alone.
    AnchorSide,
    /// This world's side leaves: the join is a side row of the world, which
    /// travels and folds as the world's key records do. A carrier's join
    /// alone, as the carrier's install key signs those records.
    World(EntityId),
}

/// One join of a wide frontier, signed in `family`, over `scope`'s heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontierJoin {
    pub family: FrontierJoinFamily,
    pub scope: FrontierJoinScope,
}

impl FrontierJoin {
    /// A join has no field to judge alone beyond its scope's signer family;
    /// it names at least two parents and is signed by one Ed25519 key
    /// alone: an install key, the host's slip issuer or an owner anchor, all
    /// Ed25519.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if !self.scoped()
            || entry.parent_hashes.len() < 2
            || !entry.cosigns.is_empty()
            || entry.signer.suite != AuthoritySignatureSuite::Ed25519
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Whether `family` may join `scope`'s heads: the main log's in any
    /// family, an anchor's own heads in the anchor family, and a world's
    /// leaves in a carrier's, never base reality's, which has no side branch.
    fn scoped(&self) -> bool {
        match self.scope {
            FrontierJoinScope::Main => true,
            FrontierJoinScope::AnchorSide => self.family == FrontierJoinFamily::Anchor,
            FrontierJoinScope::World(world) => {
                matches!(self.family, FrontierJoinFamily::Install(_))
                    && world != oneiron_contracts::claim::base_world_id()
            }
        }
    }
}

/// Canonical field order: kind, then carrier (nil for the host's issuer and
/// an anchor), then, for an anchor's join alone, `anchor` true, then the
/// scope of a side join: `side` true for an anchor's own heads, or `world`
/// for a world's leaves. A main-log join carries no scope field.
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
    match join.scope {
        FrontierJoinScope::Main => {}
        FrontierJoinScope::AnchorSide => {
            fields.push((Value::from("side"), Value::Boolean(true)));
        }
        FrontierJoinScope::World(world) => {
            fields.push((Value::from("world"), Value::from(world.to_hex())));
        }
    }
    Value::Map(fields)
}

pub(super) fn decode_frontier_join(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let named = |name: &str| entries.iter().any(|(key, _)| key.as_str() == Some(name));
    let (anchor, side, world) = (named("anchor"), named("side"), named("world"));
    let keys: &[&str] = match (anchor, side, world) {
        (false, false, false) => &FRONTIER_JOIN_KEYS,
        (true, false, false) => &ANCHOR_JOIN_KEYS,
        (true, true, false) => &ANCHOR_SIDE_JOIN_KEYS,
        (false, false, true) => &WORLD_JOIN_KEYS,
        _ => return Err(invalid_authority()),
    };
    validate_keys(entries, keys)?;
    let family = match required(entries, "carrier")? {
        Value::Nil if !anchor => FrontierJoinFamily::Host,
        Value::Nil if matches!(required(entries, "anchor")?, Value::Boolean(true)) => {
            FrontierJoinFamily::Anchor
        }
        value if !anchor => FrontierJoinFamily::Install(decode_canonical_id(value)?),
        _ => return Err(invalid_authority()),
    };
    let scope = if side {
        match required(entries, "side")? {
            Value::Boolean(true) => FrontierJoinScope::AnchorSide,
            _ => return Err(invalid_authority()),
        }
    } else if world {
        FrontierJoinScope::World(decode_canonical_id(required(entries, "world")?)?)
    } else {
        FrontierJoinScope::Main
    };
    let join = FrontierJoin { family, scope };
    if !join.scoped() {
        return Err(invalid_authority());
    }
    Ok(AuthorityOp::FrontierJoin(join))
}

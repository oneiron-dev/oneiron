//! World-access authority values and their strict claim-value codecs.

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use oneiron_authority::federation::{ScopeAxis, ScopeId};
use rmpv::Value;
use std::collections::BTreeSet;

pub use crate::write_envelope::world_access_predicates::{
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
};

/// Pinned schema version of both world-access authority claim values
/// (ONE-1420). A stored row carrying any other version fails closed instead of
/// being read under an assumed shape.
pub const WORLD_ACCESS_SCHEMA_VERSION: u64 = 1;

const WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION: &str = "schema_version";
const WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE: &str = "include_base";
const WORLD_ACCESS_VALUE_KEY_WORLDS: &str = "worlds";

/// One world-access authority value: base reality plus a sorted, unique set of
/// world ids.
///
/// The same shape carries all three tiers — the owner's ALLOWED-SET, the
/// stored DEFAULT-SUBSET, and the per-turn ActiveSet — so subset checking is
/// one predicate ([`WorldAuthoritySet::is_subset_of`]) rather than three.
/// [`Default`] is the EMPTY authority (`include_base == false`, no worlds):
/// the fail-closed value an absent grant resolves to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorldAuthoritySet {
    /// Whether base reality — claims with no `world` key, and every non-claim
    /// entity — is readable under this set.
    include_base: bool,
    /// The readable world ids. Sorted and unique by construction.
    worlds: BTreeSet<EntityId>,
}

impl WorldAuthoritySet {
    /// Builds an authority set from any world-id iterator, normalizing it to
    /// sorted-unique order. Every world is kept, however many a scope selects
    /// (FIX 8668).
    ///
    /// # Errors
    ///
    /// None today: a set of any size is valid.
    pub fn new(include_base: bool, worlds: impl IntoIterator<Item = EntityId>) -> Result<Self> {
        Ok(Self {
            include_base,
            worlds: worlds.into_iter().collect(),
        })
    }

    /// Whether base reality is readable under this set.
    #[must_use]
    pub fn include_base(&self) -> bool {
        self.include_base
    }

    /// The readable world ids in sorted, unique order.
    #[must_use]
    pub fn worlds(&self) -> &BTreeSet<EntityId> {
        &self.worlds
    }

    /// This authority as the One Scope worlds axis: base reality is the
    /// ordinary member `base_world_id` (R13), and an empty set is bottom.
    /// Base has its own boolean here: a listed id equal to the reserved base
    /// id cannot stand in for it.
    #[must_use]
    pub fn scope_axis(&self) -> ScopeAxis<ScopeId> {
        let base = crate::claim::base_world_id();
        self.worlds
            .iter()
            .filter(|id| **id != base)
            .copied()
            .chain(self.include_base.then_some(base))
            .map(ScopeId)
            .collect()
    }

    /// A Scope worlds axis as an authority set, or `None` when the axis is
    /// open: an open axis names no worlds to list.
    ///
    /// # Errors
    ///
    /// None today: [`Self::new`] keeps a named set of any size.
    pub fn from_scope_axis(axis: &ScopeAxis<ScopeId>) -> Result<Option<Self>> {
        let base = ScopeId(crate::claim::base_world_id());
        match axis {
            ScopeAxis::All => Ok(None),
            ScopeAxis::Bottom => Ok(Some(Self::default())),
            ScopeAxis::Some(ids) => Self::new(
                ids.contains(&base),
                ids.iter().filter(|id| **id != base).map(|id| id.0),
            )
            .map(Some),
        }
    }

    /// What both sets admit: the meet on the Scope worlds axis. It holds no
    /// more worlds than either.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        // Two named sets meet at a named set or bottom, never the open axis.
        Self::from_scope_axis(&self.scope_axis().meet(&other.scope_axis()))
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Membership of an ordinary claim world, or base reality for non-claims:
    /// the worlds axis's `contains`, without building the axis per row.
    pub(crate) fn admits(&self, world: Option<EntityId>) -> bool {
        match world.filter(|world| *world != crate::claim::base_world_id()) {
            Some(world) => self.worlds.contains(&world),
            None => self.include_base,
        }
    }

    /// Whether every member of `self` is also a member of `allowed`: the
    /// Scope worlds axis's narrowing order.
    ///
    /// Base reality is a MEMBER of this containment, not a side channel:
    /// asking for base without an owner grant for base is a widening and is
    /// refused like any world id would be.
    #[must_use]
    pub fn is_subset_of(&self, allowed: &Self) -> bool {
        self.scope_axis().is_narrowing_of(&allowed.scope_axis())
    }

    /// Whether this authority admits nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scope_axis().is_bottom()
    }
}

/// The per-turn world selection carried on [`crate::pipeline::PipelineBuilder`] — in memory for
/// exactly one query, never written to the vault.
///
/// `agent_ref` names the CLAIM subject whose stored authority rows the
/// resolver reads; it is not itself a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWorldSelection {
    /// The agent entity the ALLOWED-SET / DEFAULT-SUBSET rows are about.
    pub agent_ref: EntityId,
    /// `None` means use the resolved DEFAULT-SUBSET.
    pub selected: Option<WorldAuthoritySet>,
}

/// The outcome of one authority resolution: the three tiers plus the claim
/// provenance each tier came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorldAuthority {
    /// The owner grant: the intersection of every qualifying ALLOWED-SET row.
    pub allowed_set: WorldAuthoritySet,
    /// The stored default, already checked against `allowed_set`.
    pub default_subset: WorldAuthoritySet,
    /// What this turn actually reads: the explicit selection, else the default.
    pub active_set: WorldAuthoritySet,
    /// The ALLOWED-SET claim rows folded into `allowed_set`, in scan order.
    pub allowed_claim_ids: Vec<EntityId>,
    /// The DEFAULT-SUBSET claim row `default_subset` was read from.
    pub default_claim_id: Option<EntityId>,
}

/// Builds the CLAIM body for one world-access authority row.
///
/// The row is an ORDINARY bitemporal claim: subject = the agent entity, value
/// = the pinned strict map, lifecycle = active, and the caller's `source` /
/// `approval` / `valid_from` / `valid_to` verbatim. Writing it goes through the
/// ordinary claim door, so supersession, retraction and the write gate behave
/// exactly as they do for every other claim.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when `predicate` is not one of the two pinned
/// world-access predicates, or when the validity window is empty
/// (`valid_to <= valid_from`), which would mint a row that is never in force.
pub fn world_access_claim_body(
    predicate: &'static str,
    agent_ref: EntityId,
    value: &WorldAuthoritySet,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
) -> Result<ClaimBody> {
    if predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
        && predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
    {
        return Err(Error::InvalidConfig(format!(
            "{predicate} is not a world-access authority predicate"
        )));
    }
    if let (Some(from), Some(to)) = (valid_from, valid_to)
        && to <= from
    {
        return Err(Error::InvalidConfig(format!(
            "world-access validity window is empty: valid_to {to} does not follow valid_from {from}"
        )));
    }

    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(agent_ref),
        encode_world_access_claim_value(value),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.valid_from = valid_from;
    body.valid_to = valid_to;
    Ok(body)
}

/// Encodes an authority set as the pinned strict claim value.
///
/// `worlds` is emitted from the `BTreeSet`, so the array is sorted and unique
/// on the wire by construction — the exact shape
/// [`decode_world_access_claim_value`] admits.
fn encode_world_access_claim_value(value: &WorldAuthoritySet) -> Value {
    Value::Map(vec![
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION),
            Value::from(WORLD_ACCESS_SCHEMA_VERSION),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE),
            Value::Boolean(value.include_base),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_WORLDS),
            Value::Array(
                value
                    .worlds
                    .iter()
                    .map(|world| Value::Binary(world.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
    ])
}

/// Decodes the strict world-access claim value:
///
/// ```text
/// { "schema_version": 1, "include_base": <bool>, "worlds": [<16-byte binary>, ...] }
/// ```
///
/// Every deviation fails CLOSED with [`Error::InvalidConfig`]: a non-map value,
/// a non-string key, an unknown or duplicated key, a missing key, an
/// unsupported `schema_version`, a non-boolean `include_base`, a non-array
/// `worlds`, an element that is not exactly 16 bytes of MessagePack binary, and
/// an out-of-order or duplicated world id. A list of any length is read whole
/// (FIX 8668). A malformed authority row can therefore never
/// be read as a WIDER authority than it encodes — the read that consulted it
/// refuses instead.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for every shape listed above.
pub fn decode_world_access_claim_value(body: &ClaimBody) -> Result<WorldAuthoritySet> {
    let Value::Map(entries) = &body.value else {
        return Err(invalid_world_access_value("must be a MessagePack map"));
    };

    let mut schema_version: Option<u64> = None;
    let mut include_base: Option<bool> = None;
    let mut worlds: Option<BTreeSet<EntityId>> = None;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_world_access_value("keys must be strings"));
        };
        match key {
            WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION => {
                if schema_version.is_some() {
                    return Err(invalid_world_access_value("repeats schema_version"));
                }
                let version = value.as_u64().ok_or_else(|| {
                    invalid_world_access_value("schema_version must be an unsigned integer")
                })?;
                schema_version = Some(version);
            }
            WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE => {
                if include_base.is_some() {
                    return Err(invalid_world_access_value("repeats include_base"));
                }
                let Value::Boolean(flag) = value else {
                    return Err(invalid_world_access_value("include_base must be a boolean"));
                };
                include_base = Some(*flag);
            }
            WORLD_ACCESS_VALUE_KEY_WORLDS => {
                if worlds.is_some() {
                    return Err(invalid_world_access_value("repeats worlds"));
                }
                worlds = Some(decode_world_access_members(value)?);
            }
            _ => {
                return Err(invalid_world_access_value(
                    "carries a key outside schema_version/include_base/worlds",
                ));
            }
        }
    }

    let schema_version =
        schema_version.ok_or_else(|| invalid_world_access_value("is missing schema_version"))?;
    if schema_version != WORLD_ACCESS_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(format!(
            "world-access claim value schema_version {schema_version} is not the supported \
             {WORLD_ACCESS_SCHEMA_VERSION}"
        )));
    }
    let include_base =
        include_base.ok_or_else(|| invalid_world_access_value("is missing include_base"))?;
    let worlds = worlds.ok_or_else(|| invalid_world_access_value("is missing worlds"))?;

    WorldAuthoritySet::new(include_base, worlds)
}

/// Decodes the `worlds` array: strictly ascending 16-byte binary ids, every
/// one of them.
fn decode_world_access_members(value: &Value) -> Result<BTreeSet<EntityId>> {
    let Value::Array(items) = value else {
        return Err(invalid_world_access_value("worlds must be an array"));
    };
    let mut members = BTreeSet::new();
    let mut previous: Option<EntityId> = None;
    for item in items {
        let Value::Binary(bytes) = item else {
            return Err(invalid_world_access_value(
                "world ids must be MessagePack binary",
            ));
        };
        let raw: [u8; ENTITY_ID_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_world_access_value("world ids must be exactly 16 binary bytes"))?;
        let world = EntityId::from_bytes(raw)
            .map_err(|_| invalid_world_access_value("carries a reserved world id"))?;
        if previous.is_some_and(|previous| previous >= world) {
            return Err(invalid_world_access_value(
                "worlds must be sorted ascending and unique",
            ));
        }
        previous = Some(world);
        members.insert(world);
    }
    Ok(members)
}

fn invalid_world_access_value(reason: &str) -> Error {
    Error::InvalidConfig(format!("world-access claim value {reason}"))
}

//! Pact direction scope: the worlds, facets and bands axes as `ScopeAxis`
//! lattices, and their one canonical codec.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value;

use super::codec::{encode_msgpack_value, required_value};
use super::scope::{ScopeAxis, ScopeId};

use crate::entity_id::{EntityId, is_foreign_world_id_range};
use crate::error::{Error, RecordError, Result};

/// Current FederationPactScope canonical encoding schema version.
pub const FEDERATION_PACT_SCOPE_SCHEMA_VERSION: u64 = 2;

const FEDERATION_PACT_SCOPE_KEYS: [&str; 3] = ["schema_version", "lo_to_hi", "hi_to_lo"];

const KEY_PACT_SCOPE_SCHEMA_VERSION: &str = FEDERATION_PACT_SCOPE_KEYS[0];

const KEY_PACT_SCOPE_LO_TO_HI: &str = FEDERATION_PACT_SCOPE_KEYS[1];

const KEY_PACT_SCOPE_HI_TO_LO: &str = FEDERATION_PACT_SCOPE_KEYS[2];

const FEDERATION_DIRECTION_SCOPE_KEYS: [&str; 3] = ["worlds", "facets", "bands"];

const KEY_DIRECTION_WORLDS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[0];

const KEY_DIRECTION_FACETS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[1];

const KEY_DIRECTION_BANDS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[2];

const FEDERATION_SCOPE_AXIS_KEYS: [&str; 2] = ["kind", "ids"];

const KEY_SCOPE_AXIS_KIND: &str = FEDERATION_SCOPE_AXIS_KEYS[0];

const KEY_SCOPE_AXIS_IDS: &str = FEDERATION_SCOPE_AXIS_KEYS[1];

const SCOPE_AXIS_KIND_ALL: &str = "all";

const SCOPE_AXIS_KIND_BOTTOM: &str = "bottom";

pub use super::selector_kind::{SelectorRange, selector_range_of};

/// One direction of a federation pact scope pair.
///
/// Every axis is a [`ScopeAxis`]: ⊤ and ⊥ are distinct wire values and the
/// meet of disjoint sets is ⊥, never an accidental widen (ARCH-0022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationDirectionScope {
    /// World filter for shared claims. Base reality is the base world id and
    /// is never implicit; named worlds are local-range only, so foreign-range
    /// world ids fail closed.
    pub worlds: ScopeAxis<ScopeId>,
    /// Facet filter for shared content. ⊥ confers nothing: a fail-open widen
    /// here would break the type-13 minting invariant (profiles never merge
    /// across masks).
    pub facets: ScopeAxis<ScopeId>,
    /// Type-byte band filter for shared content; no named band is one
    /// another named band already includes.
    pub bands: ScopeAxis<SelectorRange>,
}

/// Dual-signed federation pact scope pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactScope {
    /// Direction: vault_lo shares → vault_hi.
    pub lo_to_hi: FederationDirectionScope,
    /// Direction: vault_hi shares → vault_lo.
    pub hi_to_lo: FederationDirectionScope,
}

/// How one pact axis spells its lattice points on the wire. ⊤ and ⊥ are the
/// shared `all` and `bottom` kinds; everything else is the axis's own.
struct AxisSpelling<T: Ord> {
    /// Kind tag of a named set, written with its members under `ids`.
    set_kind: &'static str,
    /// A lattice point written as a bare kind tag rather than as a set.
    named_point: Option<NamedPoint<T>>,
    /// Whether an empty named set decodes as ⊥ rather than failing closed.
    empty_set_is_bottom: bool,
    encode_member: fn(&T) -> Value,
    decode_member: fn(&Value) -> Option<T>,
    /// The axis's own rule on a non-empty named set.
    admits_set: fn(&BTreeSet<T>) -> bool,
}

/// A lattice point with its own kind tag: the world axis writes base reality
/// alone as `base`.
struct NamedPoint<T: Ord> {
    kind: &'static str,
    point: fn() -> ScopeAxis<T>,
}

/// A set holding the base world alone is base reality, written `base`; the
/// `worlds` spelling of that same point still decodes.
const WORLDS: AxisSpelling<ScopeId> = AxisSpelling {
    set_kind: "worlds",
    named_point: Some(NamedPoint {
        kind: "base",
        point: base_world_axis,
    }),
    empty_set_is_bottom: true,
    encode_member: id_value,
    decode_member: id_from_value,
    admits_set: |ids| !ids.iter().any(|id| is_foreign_world_id_range(id.0)),
};

const FACETS: AxisSpelling<ScopeId> = AxisSpelling {
    set_kind: "some",
    named_point: None,
    empty_set_is_bottom: false,
    encode_member: id_value,
    decode_member: id_from_value,
    admits_set: |_| true,
};

const BANDS: AxisSpelling<SelectorRange> = AxisSpelling {
    set_kind: "some",
    named_point: None,
    empty_set_is_bottom: false,
    encode_member: |band| Value::from(band.wire_name()),
    decode_member: |value| value.as_str().and_then(SelectorRange::from_wire_name),
    admits_set: |bands| {
        SelectorRange::normalize(bands.iter().copied().collect()).len() == bands.len()
    },
};

/// The world axis naming base reality alone, spelled `base` on the wire.
#[must_use]
pub(crate) fn base_world_axis() -> ScopeAxis<ScopeId> {
    ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]))
}

impl FederationDirectionScope {
    /// Validates every axis of this direction scope.
    pub fn validate(&self) -> Result<()> {
        validate_axis(&self.worlds, &WORLDS)?;
        validate_axis(&self.facets, &FACETS)?;
        validate_axis(&self.bands, &BANDS)
    }

    /// Axis-wise partial order: `self ⊑ ceiling`.
    #[must_use]
    pub fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        self.worlds.is_narrowing_of(&ceiling.worlds)
            && self.facets.is_narrowing_of(&ceiling.facets)
            && self.bands.is_narrowing_of(&ceiling.bands)
    }

    /// Axis-wise meet; disjoint sets meet at the axis's ⊥.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            worlds: self.worlds.meet(&other.worlds),
            facets: self.facets.meet(&other.facets),
            bands: self.bands.meet(&other.bands),
        }
    }
}

impl FederationPactScope {
    /// Validates both direction scopes.
    pub fn validate(&self) -> Result<()> {
        self.lo_to_hi.validate()?;
        self.hi_to_lo.validate()
    }
}

/// Encodes a FederationPactScope in canonical MessagePack field order.
pub fn encode_federation_pact_scope(scope: &FederationPactScope) -> Result<Vec<u8>> {
    scope.validate()?;
    encode_msgpack_value(
        &federation_pact_scope_value(scope),
        "federation pact scope MessagePack encode failed",
    )
}

/// Decodes and validates a canonical FederationPactScope.
pub fn decode_federation_pact_scope(bytes: &[u8]) -> Result<FederationPactScope> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_pact_scope())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_pact_scope());
    }
    decode_federation_pact_scope_value(&value)
}

/// Canonical MessagePack value for a pact scope (authority-log op payloads).
pub(crate) fn federation_pact_scope_value(scope: &FederationPactScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_PACT_SCOPE_SCHEMA_VERSION),
            Value::from(FEDERATION_PACT_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PACT_SCOPE_LO_TO_HI),
            federation_direction_scope_value(&scope.lo_to_hi),
        ),
        (
            Value::from(KEY_PACT_SCOPE_HI_TO_LO),
            federation_direction_scope_value(&scope.hi_to_lo),
        ),
    ])
}

/// Fail-closed value-level pact scope decoder (authority-log op payloads).
pub(crate) fn decode_federation_pact_scope_value(value: &Value) -> Result<FederationPactScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    validate_exact_keys(entries, &FEDERATION_PACT_SCOPE_KEYS)?;
    if pact_scope_value(entries, KEY_PACT_SCOPE_SCHEMA_VERSION)?.as_u64()
        != Some(FEDERATION_PACT_SCOPE_SCHEMA_VERSION)
    {
        return Err(invalid_pact_scope());
    }
    let scope = FederationPactScope {
        lo_to_hi: decode_direction_scope_value(pact_scope_value(
            entries,
            KEY_PACT_SCOPE_LO_TO_HI,
        )?)?,
        hi_to_lo: decode_direction_scope_value(pact_scope_value(
            entries,
            KEY_PACT_SCOPE_HI_TO_LO,
        )?)?,
    };
    scope.validate()?;
    Ok(scope)
}

/// Canonical MessagePack value for one direction scope (Rescope-narrow payloads).
pub(crate) fn federation_direction_scope_value(scope: &FederationDirectionScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DIRECTION_WORLDS),
            axis_value(&scope.worlds, &WORLDS),
        ),
        (
            Value::from(KEY_DIRECTION_FACETS),
            axis_value(&scope.facets, &FACETS),
        ),
        (
            Value::from(KEY_DIRECTION_BANDS),
            axis_value(&scope.bands, &BANDS),
        ),
    ])
}

/// Fail-closed value-level direction scope decoder (Rescope-narrow payloads).
pub(crate) fn decode_federation_direction_scope_value(
    value: &Value,
) -> Result<FederationDirectionScope> {
    decode_direction_scope_value(value)
}

fn decode_direction_scope_value(value: &Value) -> Result<FederationDirectionScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    validate_exact_keys(entries, &FEDERATION_DIRECTION_SCOPE_KEYS)?;
    let scope = FederationDirectionScope {
        worlds: decode_axis(pact_scope_value(entries, KEY_DIRECTION_WORLDS)?, &WORLDS)?,
        facets: decode_axis(pact_scope_value(entries, KEY_DIRECTION_FACETS)?, &FACETS)?,
        bands: decode_axis(pact_scope_value(entries, KEY_DIRECTION_BANDS)?, &BANDS)?,
    };
    scope.validate()?;
    Ok(scope)
}

/// One generic axis codec: ⊤ and ⊥ as bare kinds, the axis's named point as
/// its own kind, and any other set under the axis's set kind.
fn axis_value<T: Ord>(axis: &ScopeAxis<T>, spelling: &AxisSpelling<T>) -> Value {
    if let Some(named) = &spelling.named_point
        && *axis == (named.point)()
    {
        return axis_kind_value(named.kind);
    }
    let values = match axis {
        ScopeAxis::All => return axis_kind_value(SCOPE_AXIS_KIND_ALL),
        ScopeAxis::Bottom => return axis_kind_value(SCOPE_AXIS_KIND_BOTTOM),
        ScopeAxis::Some(values) => values,
    };
    Value::Map(vec![
        (
            Value::from(KEY_SCOPE_AXIS_KIND),
            Value::from(spelling.set_kind),
        ),
        (
            Value::from(KEY_SCOPE_AXIS_IDS),
            Value::Array(values.iter().map(spelling.encode_member).collect()),
        ),
    ])
}

fn axis_kind_value(kind: &str) -> Value {
    Value::Map(vec![(Value::from(KEY_SCOPE_AXIS_KIND), Value::from(kind))])
}

/// Fail-closed axis decoder. Member order is checked on the wire array, before
/// any set is built: a set would quietly accept an unsorted or repeated list.
fn decode_axis<T: Ord>(value: &Value, spelling: &AxisSpelling<T>) -> Result<ScopeAxis<T>> {
    let (kind, ids) = decode_axis_map(value)?;
    let Some(ids) = ids else {
        return match (kind, &spelling.named_point) {
            (SCOPE_AXIS_KIND_ALL, _) => Ok(ScopeAxis::All),
            (SCOPE_AXIS_KIND_BOTTOM, _) => Ok(ScopeAxis::Bottom),
            (kind, Some(named)) if kind == named.kind => Ok((named.point)()),
            _ => Err(invalid_pact_scope()),
        };
    };
    if kind != spelling.set_kind {
        return Err(invalid_pact_scope());
    }
    let members = ids
        .iter()
        .map(|id| (spelling.decode_member)(id).ok_or_else(invalid_pact_scope))
        .collect::<Result<Vec<T>>>()?;
    if members.is_empty() && spelling.empty_set_is_bottom {
        return Ok(ScopeAxis::Bottom);
    }
    if members.is_empty() || !members.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid_pact_scope());
    }
    Ok(ScopeAxis::Some(members.into_iter().collect()))
}

fn validate_axis<T: Ord>(axis: &ScopeAxis<T>, spelling: &AxisSpelling<T>) -> Result<()> {
    match axis {
        ScopeAxis::All | ScopeAxis::Bottom => Ok(()),
        ScopeAxis::Some(values) if !values.is_empty() && (spelling.admits_set)(values) => Ok(()),
        ScopeAxis::Some(_) => Err(invalid_pact_scope()),
    }
}

fn decode_axis_map(value: &Value) -> Result<(&str, Option<&[Value]>)> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    let mut seen = [false; FEDERATION_SCOPE_AXIS_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_pact_scope)?;
        let Some(index) = FEDERATION_SCOPE_AXIS_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_pact_scope());
        };
        if seen[index] {
            return Err(invalid_pact_scope());
        }
        seen[index] = true;
    }
    if !seen[0] {
        return Err(invalid_pact_scope());
    }
    let kind = required_value(entries, KEY_SCOPE_AXIS_KIND)
        .map_err(|_| invalid_pact_scope())?
        .as_str()
        .ok_or_else(invalid_pact_scope)?;
    let ids = if seen[1] {
        let Value::Array(values) =
            required_value(entries, KEY_SCOPE_AXIS_IDS).map_err(|_| invalid_pact_scope())?
        else {
            return Err(invalid_pact_scope());
        };
        Some(values.as_slice())
    } else {
        None
    };
    Ok((kind, ids))
}

fn id_value(id: &ScopeId) -> Value {
    Value::from(id.0.to_hex())
}

fn id_from_value(value: &Value) -> Option<ScopeId> {
    let hex = value.as_str()?;
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex).then_some(ScopeId(id))
}

fn validate_exact_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    let mut seen = vec![false; expected.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_pact_scope)?;
        let Some(index) = expected.iter().position(|known| *known == key) else {
            return Err(invalid_pact_scope());
        };
        if seen[index] {
            return Err(invalid_pact_scope());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_pact_scope())
    }
}

fn pact_scope_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    required_value(entries, key).map_err(|_| invalid_pact_scope())
}

fn invalid_pact_scope() -> Error {
    Error::Record(RecordError::InvalidFederationGrantBody(
        "pact scope failed validation",
    ))
}

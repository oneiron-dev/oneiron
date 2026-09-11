//! Pact direction-scope lattice (worlds/facets/bands axes) and canonical codec.

use std::io::Cursor;

use rmpv::Value;

use super::codec::{encode_msgpack_value, required_value};

use crate::entity_id::{EntityId, is_foreign_world_id_range};
use crate::error::{Error, RecordError, Result};

/// Current FederationPactScope canonical encoding schema version.
pub const FEDERATION_PACT_SCOPE_SCHEMA_VERSION: u64 = 1;

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

const SCOPE_WORLDS_KIND_ALL: &str = "all";

const SCOPE_WORLDS_KIND_BASE: &str = "base";

const SCOPE_WORLDS_KIND_WORLDS: &str = "worlds";

const SCOPE_AXIS_KIND_ALL: &str = "all";

const SCOPE_AXIS_KIND_SOME: &str = "some";

const SCOPE_AXIS_KIND_BOTTOM: &str = "bottom";

/// The FROZEN selector-range vocabulary of federation scopes and sync
/// selectors — deliberately NOT the allocation authority.
///
/// This used to be `registry::SelectorRange`, doing two unrelated jobs at once:
/// deciding where new kinds may be allocated, and naming the byte ranges a
/// replication scope selects. Byte-space v3 (ONE-1754) split them.
/// [`crate::registry::TypeByteZone`] took over allocation; this type kept the
/// wire vocabulary — the six names below are what a federation grant body and
/// a persisted sync selector spell on disk.
///
/// Its ranges are frozen at their pre-v3 values ON PURPOSE. Re-deriving
/// replication scope onto the v3 zones changes which entities a given grant
/// replicates, which is a replication-behaviour decision this ticket does not
/// own. The consequence is recorded rather than hidden: after the v3 re-key
/// these names no longer describe what lives at those bytes (`Companion` now
/// spans REDACTION_AUDIT through COMPANION_REGISTER). Nothing derives
/// allocation from this enum, so the staleness is inert until a selector
/// ticket re-derives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectorRange {
    /// Byte `0`.
    Semantic,
    /// Bytes `1–63`.
    Core,
    /// Bytes `64–79`.
    Companion,
    /// Bytes `80–99`.
    Productivity,
    /// Bytes `100–119`.
    Crm,
    /// Bytes `120–255`.
    InducedDynamicMaintenance,
}

/// Maps a type byte to its frozen selector range. Total over all 256 bytes.
///
/// Allocation code must call [`crate::registry::zone_of`] instead.
#[must_use]
pub const fn selector_range_of(type_byte: u8) -> SelectorRange {
    match type_byte {
        0 => SelectorRange::Semantic,
        1..=63 => SelectorRange::Core,
        64..=79 => SelectorRange::Companion,
        80..=99 => SelectorRange::Productivity,
        100..=119 => SelectorRange::Crm,
        120..=u8::MAX => SelectorRange::InducedDynamicMaintenance,
    }
}

/// Normalized band order shared with `SyncSelector::new`.
const FEDERATION_SCOPE_BAND_ORDER: [SelectorRange; 6] = [
    SelectorRange::Semantic,
    SelectorRange::Core,
    SelectorRange::Companion,
    SelectorRange::Productivity,
    SelectorRange::Crm,
    SelectorRange::InducedDynamicMaintenance,
];

/// World axis of a federation pact direction scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeWorlds {
    /// Base reality plus every world.
    All,
    /// Base reality only.
    Base,
    /// Base reality plus the named worlds (sorted, deduplicated, non-empty,
    /// local-range only — foreign-range world ids fail closed).
    Worlds(Vec<EntityId>),
}

/// Facet axis of a federation pact direction scope.
///
/// The bottom is a distinct wire value: an empty id set is NEVER decoded as
/// "all facets". Per ARCH-0022, a fail-open widen here would break the type-13
/// minting invariant (profiles never merge across masks), so the meet of
/// disjoint facet sets confers nothing on this axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeFacets {
    /// Every facet (⊤).
    All,
    /// Exactly the named facets (sorted, deduplicated, non-empty).
    Some(Vec<EntityId>),
    /// No facet-scoped content at all (⊥).
    Bottom,
}

/// Band axis of a federation pact direction scope.
///
/// Kind-tagged like [`FederationScopeFacets`]: ⊤ and ⊥ are distinct wire
/// values and the disjoint meet is ⊥, never an accidental all-bands widen
/// (ARCH-0022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeBands {
    /// Every band (⊤).
    All,
    /// Exactly the named bands (normalized `SyncSelector::new` order,
    /// deduplicated, non-empty).
    Some(Vec<SelectorRange>),
    /// No band passes (⊥).
    Bottom,
}

/// One direction of a federation pact scope pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationDirectionScope {
    /// World filter for shared claims.
    pub worlds: FederationScopeWorlds,
    /// Facet filter for shared content.
    pub facets: FederationScopeFacets,
    /// Type-byte band filter for shared content.
    pub bands: FederationScopeBands,
}

/// Dual-signed federation pact scope pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactScope {
    /// Direction: vault_lo shares → vault_hi.
    pub lo_to_hi: FederationDirectionScope,
    /// Direction: vault_hi shares → vault_lo.
    pub hi_to_lo: FederationDirectionScope,
}

impl FederationScopeWorlds {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Base => Ok(()),
            Self::Worlds(ids) => {
                validate_strictly_ascending_ids(ids)?;
                if ids.iter().any(|id| is_foreign_world_id_range(*id)) {
                    return Err(invalid_pact_scope());
                }
                Ok(())
            }
        }
    }

    pub(super) fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::All, _) => false,
            (Self::Base, _) => true,
            (Self::Worlds(_), Self::Base) => false,
            (Self::Worlds(narrow), Self::Worlds(wide)) => narrow.iter().all(|id| wide.contains(id)),
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Base, _) | (_, Self::Base) => Self::Base,
            (Self::Worlds(left), Self::Worlds(right)) => {
                let both: Vec<EntityId> = left
                    .iter()
                    .filter(|id| right.contains(id))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Base
                } else {
                    Self::Worlds(both)
                }
            }
        }
    }
}

impl FederationScopeFacets {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(ids) => validate_strictly_ascending_ids(ids),
        }
    }

    pub(super) fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|id| wide.contains(id)),
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Some(left), Self::Some(right)) => {
                let both: Vec<EntityId> = left
                    .iter()
                    .filter(|id| right.contains(id))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Bottom
                } else {
                    Self::Some(both)
                }
            }
        }
    }
}

impl FederationScopeBands {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(bands) => {
                if bands.is_empty() {
                    return Err(invalid_pact_scope());
                }
                let ascending = bands
                    .windows(2)
                    .all(|pair| band_order_index(pair[0]) < band_order_index(pair[1]));
                if ascending {
                    Ok(())
                } else {
                    Err(invalid_pact_scope())
                }
            }
        }
    }

    pub(super) fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|band| wide.contains(band)),
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Some(left), Self::Some(right)) => {
                let both: Vec<SelectorRange> = left
                    .iter()
                    .filter(|band| right.contains(band))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Bottom
                } else {
                    Self::Some(both)
                }
            }
        }
    }
}

impl FederationDirectionScope {
    /// Validates every axis of this direction scope.
    pub fn validate(&self) -> Result<()> {
        self.worlds.validate()?;
        self.facets.validate()?;
        self.bands.validate()
    }

    /// Axis-wise partial order: `self ⊑ ceiling`.
    #[must_use]
    pub fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        self.worlds.is_narrowing_of(&ceiling.worlds)
            && self.facets.is_narrowing_of(&ceiling.facets)
            && self.bands.is_narrowing_of(&ceiling.bands)
    }

    /// Axis-wise meet; disjoint facet/band sets meet at their kind-tagged ⊥.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            worlds: self.worlds.intersect(&other.worlds),
            facets: self.facets.intersect(&other.facets),
            bands: self.bands.intersect(&other.bands),
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
            worlds_axis_value(&scope.worlds),
        ),
        (
            Value::from(KEY_DIRECTION_FACETS),
            facets_axis_value(&scope.facets),
        ),
        (
            Value::from(KEY_DIRECTION_BANDS),
            bands_axis_value(&scope.bands),
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
        worlds: decode_worlds_axis(pact_scope_value(entries, KEY_DIRECTION_WORLDS)?)?,
        facets: decode_facets_axis(pact_scope_value(entries, KEY_DIRECTION_FACETS)?)?,
        bands: decode_bands_axis(pact_scope_value(entries, KEY_DIRECTION_BANDS)?)?,
    };
    scope.validate()?;
    Ok(scope)
}

fn worlds_axis_value(worlds: &FederationScopeWorlds) -> Value {
    match worlds {
        FederationScopeWorlds::All => axis_kind_value(SCOPE_WORLDS_KIND_ALL),
        FederationScopeWorlds::Base => axis_kind_value(SCOPE_WORLDS_KIND_BASE),
        FederationScopeWorlds::Worlds(ids) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_WORLDS_KIND_WORLDS),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect()),
            ),
        ]),
    }
}

fn facets_axis_value(facets: &FederationScopeFacets) -> Value {
    match facets {
        FederationScopeFacets::All => axis_kind_value(SCOPE_AXIS_KIND_ALL),
        FederationScopeFacets::Bottom => axis_kind_value(SCOPE_AXIS_KIND_BOTTOM),
        FederationScopeFacets::Some(ids) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_AXIS_KIND_SOME),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect()),
            ),
        ]),
    }
}

fn bands_axis_value(bands: &FederationScopeBands) -> Value {
    match bands {
        FederationScopeBands::All => axis_kind_value(SCOPE_AXIS_KIND_ALL),
        FederationScopeBands::Bottom => axis_kind_value(SCOPE_AXIS_KIND_BOTTOM),
        FederationScopeBands::Some(bands) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_AXIS_KIND_SOME),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(
                    bands
                        .iter()
                        .map(|band| Value::from(federation_band_wire(*band)))
                        .collect(),
                ),
            ),
        ]),
    }
}

fn axis_kind_value(kind: &str) -> Value {
    Value::Map(vec![(Value::from(KEY_SCOPE_AXIS_KIND), Value::from(kind))])
}

fn decode_worlds_axis(value: &Value) -> Result<FederationScopeWorlds> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_WORLDS_KIND_ALL, None) => Ok(FederationScopeWorlds::All),
        (SCOPE_WORLDS_KIND_BASE, None) => Ok(FederationScopeWorlds::Base),
        (SCOPE_WORLDS_KIND_WORLDS, Some(ids)) => {
            Ok(FederationScopeWorlds::Worlds(decode_hex_id_array(ids)?))
        }
        _ => Err(invalid_pact_scope()),
    }
}

fn decode_facets_axis(value: &Value) -> Result<FederationScopeFacets> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_AXIS_KIND_ALL, None) => Ok(FederationScopeFacets::All),
        (SCOPE_AXIS_KIND_BOTTOM, None) => Ok(FederationScopeFacets::Bottom),
        (SCOPE_AXIS_KIND_SOME, Some(ids)) => {
            Ok(FederationScopeFacets::Some(decode_hex_id_array(ids)?))
        }
        _ => Err(invalid_pact_scope()),
    }
}

fn decode_bands_axis(value: &Value) -> Result<FederationScopeBands> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_AXIS_KIND_ALL, None) => Ok(FederationScopeBands::All),
        (SCOPE_AXIS_KIND_BOTTOM, None) => Ok(FederationScopeBands::Bottom),
        (SCOPE_AXIS_KIND_SOME, Some(values)) => {
            let bands = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(parse_federation_band_wire)
                        .ok_or_else(invalid_pact_scope)
                })
                .collect::<Result<Vec<SelectorRange>>>()?;
            Ok(FederationScopeBands::Some(bands))
        }
        _ => Err(invalid_pact_scope()),
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

fn decode_hex_id_array(values: &[Value]) -> Result<Vec<EntityId>> {
    values
        .iter()
        .map(|value| {
            let hex = value.as_str().ok_or_else(invalid_pact_scope)?;
            let id = EntityId::from_hex(hex).map_err(|_| invalid_pact_scope())?;
            if id.to_hex() != hex {
                return Err(invalid_pact_scope());
            }
            Ok(id)
        })
        .collect()
}

fn validate_strictly_ascending_ids(ids: &[EntityId]) -> Result<()> {
    if ids.is_empty() {
        return Err(invalid_pact_scope());
    }
    if ids.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(invalid_pact_scope())
    }
}

fn band_order_index(band: SelectorRange) -> usize {
    FEDERATION_SCOPE_BAND_ORDER
        .iter()
        .position(|known| *known == band)
        .unwrap_or(FEDERATION_SCOPE_BAND_ORDER.len())
}

fn federation_band_wire(band: SelectorRange) -> &'static str {
    match band {
        SelectorRange::Semantic => "semantic",
        SelectorRange::Core => "core",
        SelectorRange::Companion => "companion",
        SelectorRange::Productivity => "productivity",
        SelectorRange::Crm => "crm",
        SelectorRange::InducedDynamicMaintenance => "maintenance",
    }
}

fn parse_federation_band_wire(value: &str) -> Option<SelectorRange> {
    match value {
        "semantic" => Some(SelectorRange::Semantic),
        "core" => Some(SelectorRange::Core),
        "companion" => Some(SelectorRange::Companion),
        "productivity" => Some(SelectorRange::Productivity),
        "crm" => Some(SelectorRange::Crm),
        "maintenance" => Some(SelectorRange::InducedDynamicMaintenance),
        _ => None,
    }
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

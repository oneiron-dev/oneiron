//! One Scope lattice for disclosure (OF-453/OF-365 ILDF2 steps 9-11).
//!
//! A clearance is a [`ScopeCeiling`]; a record's exposure is a
//! [`ScopePosition`]. The two are distinct types so the admission order can
//! never be applied backwards (OF-471): bottom on a position passes every
//! door, bottom on a ceiling passes nothing.
//!
//! Five axes (R3/R7/R11/R13/R16): worlds, facets, kinds, projects,
//! sensitivity. Wire law (L3): empty never decodes as everything — every
//! axis is kind-tagged with wire-distinct top and bottom.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};

/// Current Scope clearance body schema version (v2 replaces the v1 entity
/// allowlist unit; the prefix bump rides with it).
pub const SCOPE_BODY_SCHEMA_VERSION: u64 = 2;

/// Pinned on-disk MessagePack key set for Scope clearance bodies.
pub const SCOPE_BODY_KEYS: [&str; 6] = [
    "schema_version",
    "worlds",
    "facets",
    "kinds",
    "projects",
    "sensitivity",
];

const KEY_SCHEMA_VERSION: &str = SCOPE_BODY_KEYS[0];
const KEY_WORLDS: &str = SCOPE_BODY_KEYS[1];
const KEY_FACETS: &str = SCOPE_BODY_KEYS[2];
const KEY_KINDS: &str = SCOPE_BODY_KEYS[3];
const KEY_PROJECTS: &str = SCOPE_BODY_KEYS[4];
const KEY_SENSITIVITY: &str = SCOPE_BODY_KEYS[5];

const AXIS_KEYS: [&str; 2] = ["kind", "ids"];
const KEY_AXIS_KIND: &str = AXIS_KEYS[0];
const KEY_AXIS_IDS: &str = AXIS_KEYS[1];

const AXIS_KIND_ALL: &str = "all";
const AXIS_KIND_SOME: &str = "some";
const AXIS_KIND_BOTTOM: &str = "bottom";

/// Sensitivity rungs (R7): public 0, private 1, sensitive 2, restricted 3.
/// A record carries its rung; a ceiling carries the maximum rung it admits.
pub const SENSITIVITY_PUBLIC: u8 = 0;
pub const SENSITIVITY_PRIVATE: u8 = 1;
pub const SENSITIVITY_SENSITIVE: u8 = 2;
pub const SENSITIVITY_RESTRICTED: u8 = 3;
pub const SENSITIVITY_MAX_RUNG: u8 = SENSITIVITY_RESTRICTED;

/// Maximum entries on one id-set axis of a stored clearance.
pub const MAX_SCOPE_AXIS_IDS: usize = 256;

/// Maximum kinds on the kinds axis of a stored clearance.
pub const MAX_SCOPE_KINDS: usize = 256;

/// One entity-id-set axis of a Scope: worlds, facets, or projects.
///
/// `All` is the top, `Bottom` the bottom, and `Some` a non-empty sorted set.
/// Base world reality is an ordinary member, never a kind arm (R13): a
/// `Some` naming only base admits base-scoped records and nothing else, and
/// the meet of disjoint sets is [`ScopeIdAxis::Bottom`], never base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeIdAxis {
    All,
    Some(Vec<EntityId>),
    Bottom,
}

/// The kinds axis of a Scope: sets of type-byte kinds (R3), never the frozen
/// federation band vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeKindAxis {
    All,
    Some(Vec<u8>),
    Bottom,
}

/// A record's exposure position: what the record IS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePosition {
    pub worlds: ScopeIdAxis,
    pub facets: ScopeIdAxis,
    pub kinds: ScopeKindAxis,
    pub projects: ScopeIdAxis,
    pub sensitivity: u8,
}

/// A clearance or room ceiling: what may be DISCLOSED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCeiling {
    pub worlds: ScopeIdAxis,
    pub facets: ScopeIdAxis,
    pub kinds: ScopeKindAxis,
    pub projects: ScopeIdAxis,
    pub sensitivity: u8,
}

impl ScopeIdAxis {
    fn validate(&self, base_world_allowed: bool) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(ids) => {
                if ids.is_empty() || ids.len() > MAX_SCOPE_AXIS_IDS {
                    return Err(invalid_scope());
                }
                if ids.iter().any(|id| {
                    EntityId::from_bytes(*id.as_bytes()).is_err()
                        && !(base_world_allowed && *id == EntityId::scope_base_world())
                }) {
                    return Err(invalid_scope());
                }
                if ids.windows(2).all(|pair| pair[0] < pair[1]) {
                    Ok(())
                } else {
                    Err(invalid_scope())
                }
            }
        }
    }

    /// Axis order: `self` at-or-under `ceiling`.
    fn is_at_or_under(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|id| wide.contains(id)),
        }
    }

    /// Axis meet (restrictive-wins): disjoint `Some` sets meet at bottom.
    fn meet(&self, other: &Self) -> Self {
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

impl ScopeKindAxis {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(kinds) => {
                if kinds.is_empty() || kinds.len() > MAX_SCOPE_KINDS {
                    return Err(invalid_scope());
                }
                if kinds.windows(2).all(|pair| pair[0] < pair[1]) {
                    Ok(())
                } else {
                    Err(invalid_scope())
                }
            }
        }
    }

    fn is_at_or_under(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|kind| wide.contains(kind)),
        }
    }

    fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Some(left), Self::Some(right)) => {
                let both: Vec<u8> = left
                    .iter()
                    .filter(|kind| right.contains(kind))
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

impl ScopePosition {
    /// Checks a record stamp. Bottom is an explicit empty axis, never a
    /// substitute for a missing or malformed stamp.
    pub fn validate(&self) -> Result<()> {
        self.as_ceiling().validate()
    }

    fn as_ceiling(&self) -> ScopeCeiling {
        ScopeCeiling {
            worlds: self.worlds.clone(),
            facets: self.facets.clone(),
            kinds: self.kinds.clone(),
            projects: self.projects.clone(),
            sensitivity: self.sensitivity,
        }
    }
}

/// Encodes a record position with all five axes present.
pub fn encode_scope_position_body(position: &ScopePosition) -> Result<Vec<u8>> {
    encode_scope_ceiling_body(&position.as_ceiling())
}

/// Decodes a record position. The returned type cannot be used as a clearance.
pub fn decode_scope_position_body(bytes: &[u8]) -> Result<ScopePosition> {
    decode_scope_ceiling_body(bytes).map(position_from_axes)
}

pub(super) fn decode_scope_position_value(value: &Value) -> Result<ScopePosition> {
    decode_scope_ceiling_value(value).map(position_from_axes)
}

fn position_from_axes(axes: ScopeCeiling) -> ScopePosition {
    ScopePosition {
        worlds: axes.worlds,
        facets: axes.facets,
        kinds: axes.kinds,
        projects: axes.projects,
        sensitivity: axes.sensitivity,
    }
}

impl ScopeCeiling {
    /// The top of the lattice: every axis open, sensitivity rung 3.
    /// The P1 empty-family identity: an empty non-owner roster folds to TOP.
    #[must_use]
    pub fn top() -> Self {
        Self {
            worlds: ScopeIdAxis::All,
            facets: ScopeIdAxis::All,
            kinds: ScopeKindAxis::All,
            projects: ScopeIdAxis::All,
            sensitivity: SENSITIVITY_MAX_RUNG,
        }
    }

    /// The bottom of the lattice: every axis closed, sensitivity rung 0.
    /// The V3 empty clearance: an unknown, revoked, missing, or undecodable
    /// roster member contributes BOTTOM, never roster-absence.
    #[must_use]
    pub fn bottom() -> Self {
        Self {
            worlds: ScopeIdAxis::Bottom,
            facets: ScopeIdAxis::Bottom,
            kinds: ScopeKindAxis::Bottom,
            projects: ScopeIdAxis::Bottom,
            sensitivity: SENSITIVITY_PUBLIC,
        }
    }

    /// The public ceiling: every axis open, sensitivity rung 0. The union
    /// half of the room rule: public records disclose to any roster.
    #[must_use]
    pub fn public() -> Self {
        Self {
            worlds: ScopeIdAxis::All,
            facets: ScopeIdAxis::All,
            kinds: ScopeKindAxis::All,
            projects: ScopeIdAxis::All,
            sensitivity: SENSITIVITY_PUBLIC,
        }
    }

    /// Validates every axis and the sensitivity rung.
    pub fn validate(&self) -> Result<()> {
        self.worlds.validate(true)?;
        self.facets.validate(false)?;
        self.kinds.validate()?;
        self.projects.validate(false)?;
        if self.sensitivity > SENSITIVITY_MAX_RUNG {
            return Err(invalid_scope());
        }
        Ok(())
    }

    /// Axis-wise meet (restrictive-wins); sensitivity takes the minimum.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            worlds: self.worlds.meet(&other.worlds),
            facets: self.facets.meet(&other.facets),
            kinds: self.kinds.meet(&other.kinds),
            projects: self.projects.meet(&other.projects),
            sensitivity: self.sensitivity.min(other.sensitivity),
        }
    }

    /// Admission order: the position sits at or under this ceiling.
    #[must_use]
    pub fn admits(&self, position: &ScopePosition) -> bool {
        is_at_or_under(position, self)
    }
}

/// The Scope admission order: every axis at-or-under, and the record rung
/// at or under the ceiling rung.
#[must_use]
pub fn is_at_or_under(position: &ScopePosition, ceiling: &ScopeCeiling) -> bool {
    position.validate().is_ok()
        && ceiling.validate().is_ok()
        && position.worlds.is_at_or_under(&ceiling.worlds)
        && position.facets.is_at_or_under(&ceiling.facets)
        && position.kinds.is_at_or_under(&ceiling.kinds)
        && position.projects.is_at_or_under(&ceiling.projects)
        && position.sensitivity <= ceiling.sensitivity
}

/// Meets a non-empty family of clearances. The caller MUST branch on the
/// empty family before calling: the P1 identity is [`ScopeCeiling::top`],
/// and this fold never sees the empty case (`debug_assert` + fail-open-proof
/// TOP on an empty slice can never leak — TOP is the widest value, so an
/// empty input returning TOP matches P1 exactly).
#[must_use]
pub fn meet_all(ceilings: &[ScopeCeiling]) -> ScopeCeiling {
    debug_assert!(
        !ceilings.is_empty(),
        "meet_all over an empty family: branch on non_owner.is_empty() first (P1)"
    );
    let mut folded = ScopeCeiling::top();
    for ceiling in ceilings {
        folded = folded.meet(ceiling);
    }
    folded
}

fn invalid_scope() -> Error {
    Error::Gate(GateError::InvalidDisclosureScope(
        "scope clearance failed validation",
    ))
}

pub(super) fn scope_ceiling_body_value(ceiling: &ScopeCeiling) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SCOPE_BODY_SCHEMA_VERSION),
        ),
        (Value::from(KEY_WORLDS), id_axis_value(&ceiling.worlds)),
        (Value::from(KEY_FACETS), id_axis_value(&ceiling.facets)),
        (Value::from(KEY_KINDS), kind_axis_value(&ceiling.kinds)),
        (Value::from(KEY_PROJECTS), id_axis_value(&ceiling.projects)),
        (
            Value::from(KEY_SENSITIVITY),
            Value::from(u64::from(ceiling.sensitivity)),
        ),
    ])
}

/// Encodes a Scope clearance body in canonical MessagePack key order.
pub fn encode_scope_ceiling_body(ceiling: &ScopeCeiling) -> Result<Vec<u8>> {
    ceiling.validate()?;
    let value = scope_ceiling_body_value(ceiling);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("scope body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a Scope clearance body (strict key set, no
/// duplicates, no trailing bytes). Empty never decodes as everything: every
/// axis is kind-tagged, and a `some` with an empty id set is rejected.
pub fn decode_scope_ceiling_body(bytes: &[u8]) -> Result<ScopeCeiling> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_scope())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_scope());
    }
    decode_scope_ceiling_value(&value)
}

pub(super) fn decode_scope_ceiling_value(value: &Value) -> Result<ScopeCeiling> {
    let Value::Map(entries) = value else {
        return Err(invalid_scope());
    };
    validate_scope_keys(entries, &SCOPE_BODY_KEYS)?;

    if required_scope_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(SCOPE_BODY_SCHEMA_VERSION)
    {
        return Err(invalid_scope());
    }
    let ceiling = ScopeCeiling {
        worlds: decode_id_axis(required_scope_value(entries, KEY_WORLDS)?, true)?,
        facets: decode_id_axis(required_scope_value(entries, KEY_FACETS)?, false)?,
        kinds: decode_kind_axis(required_scope_value(entries, KEY_KINDS)?)?,
        projects: decode_id_axis(required_scope_value(entries, KEY_PROJECTS)?, false)?,
        sensitivity: required_scope_value(entries, KEY_SENSITIVITY)?
            .as_u64()
            .and_then(|rung| u8::try_from(rung).ok())
            .ok_or_else(invalid_scope)?,
    };
    ceiling.validate()?;
    Ok(ceiling)
}

fn id_axis_value(axis: &ScopeIdAxis) -> Value {
    match axis {
        ScopeIdAxis::All => axis_kind_value(AXIS_KIND_ALL),
        ScopeIdAxis::Bottom => axis_kind_value(AXIS_KIND_BOTTOM),
        ScopeIdAxis::Some(ids) => Value::Map(vec![
            (Value::from(KEY_AXIS_KIND), Value::from(AXIS_KIND_SOME)),
            (
                Value::from(KEY_AXIS_IDS),
                Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect()),
            ),
        ]),
    }
}

fn kind_axis_value(axis: &ScopeKindAxis) -> Value {
    match axis {
        ScopeKindAxis::All => axis_kind_value(AXIS_KIND_ALL),
        ScopeKindAxis::Bottom => axis_kind_value(AXIS_KIND_BOTTOM),
        ScopeKindAxis::Some(kinds) => Value::Map(vec![
            (Value::from(KEY_AXIS_KIND), Value::from(AXIS_KIND_SOME)),
            (
                Value::from(KEY_AXIS_IDS),
                Value::Array(
                    kinds
                        .iter()
                        .map(|kind| Value::from(u64::from(*kind)))
                        .collect(),
                ),
            ),
        ]),
    }
}

fn axis_kind_value(kind: &str) -> Value {
    Value::Map(vec![(Value::from(KEY_AXIS_KIND), Value::from(kind))])
}

fn decode_axis_map(value: &Value) -> Result<(&str, Option<&[Value]>)> {
    let Value::Map(entries) = value else {
        return Err(invalid_scope());
    };
    let mut seen = [false; AXIS_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_scope)?;
        let Some(index) = AXIS_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_scope());
        };
        if seen[index] {
            return Err(invalid_scope());
        }
        seen[index] = true;
    }
    if !seen[0] {
        return Err(invalid_scope());
    }
    let kind = required_scope_value(entries, KEY_AXIS_KIND)?
        .as_str()
        .ok_or_else(invalid_scope)?;
    let ids = if seen[1] {
        let Value::Array(values) = required_scope_value(entries, KEY_AXIS_IDS)? else {
            return Err(invalid_scope());
        };
        Some(values.as_slice())
    } else {
        None
    };
    Ok((kind, ids))
}

fn decode_id_axis(value: &Value, base_world_allowed: bool) -> Result<ScopeIdAxis> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (AXIS_KIND_ALL, None) => Ok(ScopeIdAxis::All),
        (AXIS_KIND_BOTTOM, None) => Ok(ScopeIdAxis::Bottom),
        (AXIS_KIND_SOME, Some(ids)) => {
            let parsed = ids
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|hex| {
                            if base_world_allowed && hex == "00000000000000000000000000000000" {
                                Some(EntityId::scope_base_world())
                            } else {
                                EntityId::from_hex(hex).ok()
                            }
                        })
                        .ok_or_else(invalid_scope)
                })
                .collect::<Result<Vec<_>>>()?;
            let axis = ScopeIdAxis::Some(parsed);
            axis.validate(base_world_allowed)?;
            Ok(axis)
        }
        _ => Err(invalid_scope()),
    }
}

fn decode_kind_axis(value: &Value) -> Result<ScopeKindAxis> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (AXIS_KIND_ALL, None) => Ok(ScopeKindAxis::All),
        (AXIS_KIND_BOTTOM, None) => Ok(ScopeKindAxis::Bottom),
        (AXIS_KIND_SOME, Some(ids)) => {
            let parsed = ids
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|raw| u8::try_from(raw).ok())
                        .ok_or_else(invalid_scope)
                })
                .collect::<Result<Vec<_>>>()?;
            let axis = ScopeKindAxis::Some(parsed);
            axis.validate()?;
            Ok(axis)
        }
        _ => Err(invalid_scope()),
    }
}

pub(super) fn validate_scope_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_scope)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_scope());
        };
        if seen[index] {
            return Err(invalid_scope());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_scope())
    }
}

pub(super) fn required_scope_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_scope)
}

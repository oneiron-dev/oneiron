//! Retrieval authority projection and narrowing, independent of result filtering.
//!
//! This leaf does not authorize a claim's relationship, world, or facet. The
//! existing scoped-read checks must still pass conjunctively at integration.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::ScopedReadActorKey;
use crate::error::{Error, Result};

use super::grants::{
    PolicyScopedGrant, scoped_read_actor_matches, scoped_read_grant_has_read_effector,
};
use super::resolution::PolicyManifestResolution;

/// Caller-supplied retrieval constraints. Unset fields inherit vault authority;
/// valid over-asks are clamped, not rejected. Numeric minima must be finite in
/// `[0, 1]`, and sensitivity must be in `0..=3`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RetrievalFilter {
    pub entity_types: Option<BTreeSet<u8>>,
    pub max_sensitivity_band: Option<u8>,
    pub include_stale: Option<bool>,
    pub min_confidence: Option<f32>,
    pub min_salience: Option<f32>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetrievalPolicyFloor {
    /// `None` means all registered types, not all possible type bytes.
    pub(crate) allowed_entity_types: Option<BTreeSet<u8>>,
    pub(crate) max_sensitivity_band: u8,
    pub(crate) include_stale: bool,
    pub(crate) min_confidence: f32,
    pub(crate) min_salience: f32,
    pub(crate) deny_all: bool,
}

/// Only the gate's narrowing door should supply this to retrieval execution.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedRetrievalFilter {
    /// `None` retains the floor's all-registered-types meaning.
    pub(crate) entity_types: Option<BTreeSet<u8>>,
    pub(crate) max_sensitivity_band: u8,
    pub(crate) include_stale: bool,
    pub(crate) min_confidence: f32,
    pub(crate) min_salience: f32,
    pub(crate) deny_all: bool,
}

impl PolicyManifestResolution {
    /// Derive authority from the existing fail-closed scoped-grant projection.
    /// `Some` is the actual scoped-read actor context, with its existing exact
    /// matching rules. `None` is ONLY the trusted local owner/unscoped lane;
    /// failed actor conversion must never be mapped to `None`.
    ///
    /// `GateActor` describes writes and has an optional ref. It cannot by
    /// itself distinguish an owner read from an unkeyed scoped read, so this
    /// door uses `ScopedReadActorKey` instead of guessing from actor class.
    pub(crate) fn retrieval_floor_for_actor(
        &self,
        actor: Option<&ScopedReadActorKey>,
    ) -> RetrievalPolicyFloor {
        match actor {
            None => RetrievalPolicyFloor::legacy(),
            Some(_) if self.diagnostics().loaded_manifest_forces_fail_closed() => {
                RetrievalPolicyFloor::deny_all()
            }
            Some(actor) => RetrievalPolicyFloor::from_scoped_grants(self.scoped_grants(), actor),
        }
    }
}

impl RetrievalPolicyFloor {
    fn legacy() -> Self {
        Self {
            allowed_entity_types: None,
            max_sensitivity_band: 3,
            include_stale: false,
            min_confidence: 0.0,
            min_salience: 0.0,
            deny_all: false,
        }
    }

    fn deny_all() -> Self {
        Self {
            allowed_entity_types: Some(BTreeSet::new()),
            max_sensitivity_band: 0,
            include_stale: false,
            min_confidence: 1.0,
            min_salience: 1.0,
            deny_all: true,
        }
    }

    fn from_scoped_grants(grants: &[PolicyScopedGrant], actor: &ScopedReadActorKey) -> Self {
        let mut saw_read_grant = false;
        let mut floor: Option<Self> = None;
        for grant in grants
            .iter()
            .filter(|grant| scoped_read_grant_has_read_effector(grant))
        {
            saw_read_grant = true;
            if grant.receipt_required
                || grant.budget.is_some()
                || !scoped_read_actor_matches(grant, actor)
            {
                continue;
            }
            let Some(row) = Self::from_scope(grant.scope.as_ref()).filter(|row| !row.deny_all)
            else {
                // Invalid or empty alternatives authorize nothing, not a veto
                // of another independently valid complete grant.
                continue;
            };
            floor = Some(match floor {
                None => row,
                Some(existing) => existing.union_envelope(row),
            });
        }
        floor.unwrap_or_else(|| {
            if saw_read_grant {
                Self::deny_all()
            } else {
                Self::legacy()
            }
        })
    }

    /// A safe prefilter for alternative grants, not a complete authorization.
    /// The final matcher must still accept one whole relationship/world/facet
    /// scope together with that same row's retrieval constraints.
    fn union_envelope(self, other: Self) -> Self {
        let allowed_entity_types = match (self.allowed_entity_types, other.allowed_entity_types) {
            (Some(mut left), Some(right)) => {
                left.extend(right);
                Some(left)
            }
            _ => None,
        };
        Self {
            allowed_entity_types,
            max_sensitivity_band: self.max_sensitivity_band.max(other.max_sensitivity_band),
            include_stale: self.include_stale || other.include_stale,
            min_confidence: self.min_confidence.min(other.min_confidence),
            min_salience: self.min_salience.min(other.min_salience),
            deny_all: false,
        }
    }

    pub(super) fn from_scope(scope: Option<&Value>) -> Option<Self> {
        let mut floor = Self::legacy();
        let entries = match scope {
            None | Some(Value::Nil) => return Some(floor),
            Some(Value::Map(entries)) => entries,
            _ => return None,
        };
        let mut seen = BTreeSet::new();
        for (key, value) in entries {
            let key = key.as_str()?;
            if !matches!(
                key,
                "entity_types"
                    | "max_sensitivity_band"
                    | "include_stale"
                    | "min_confidence"
                    | "min_salience"
            ) {
                // Other scope fields belong to the existing matcher. This
                // projection neither interprets them nor authorizes them.
                continue;
            }
            if !seen.insert(key) {
                return None;
            }
            match key {
                "entity_types" => {
                    let Value::Array(values) = value else {
                        return None;
                    };
                    let types = values
                        .iter()
                        .map(|value| u8::try_from(value.as_u64()?).ok())
                        .collect::<Option<BTreeSet<_>>>()?;
                    floor.deny_all = types.is_empty();
                    floor.allowed_entity_types = Some(types);
                }
                "max_sensitivity_band" => {
                    let band = u8::try_from(value.as_u64()?).ok()?;
                    if band > 3 {
                        return None;
                    }
                    floor.max_sensitivity_band = band;
                }
                "include_stale" => floor.include_stale = value.as_bool()?,
                "min_confidence" => floor.min_confidence = parse_minimum(value)?,
                "min_salience" => floor.min_salience = parse_minimum(value)?,
                _ => unreachable!("only retrieval keys reach this match"),
            }
        }
        Some(floor)
    }

    /// Intersect the grant envelope with caller constraints; requests only narrow.
    fn restrict(self, other: Self) -> Self {
        let allowed_entity_types = match (self.allowed_entity_types, other.allowed_entity_types) {
            (Some(mut left), Some(right)) => {
                left.retain(|entity_type| right.contains(entity_type));
                Some(left)
            }
            (left, right) => left.or(right),
        };
        let deny_all = self.deny_all
            || other.deny_all
            || allowed_entity_types
                .as_ref()
                .is_some_and(BTreeSet::is_empty);
        Self {
            allowed_entity_types,
            max_sensitivity_band: self.max_sensitivity_band.min(other.max_sensitivity_band),
            include_stale: self.include_stale && other.include_stale,
            min_confidence: self.min_confidence.max(other.min_confidence),
            min_salience: self.min_salience.max(other.min_salience),
            deny_all,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_sensitivity_band > 3
            || !valid_minimum(self.min_confidence)
            || !valid_minimum(self.min_salience)
        {
            return Err(Error::InvalidConfig(
                "retrieval constraints require sensitivity in 0..=3 and finite minima in [0, 1]"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn valid_minimum(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn parse_minimum(value: &Value) -> Option<f32> {
    let value = match value {
        Value::F32(value) => f64::from(*value),
        Value::F64(value) => *value,
        Value::Integer(value) => value.as_i64()? as f64,
        _ => return None,
    };
    // Validate BEFORE casting: an invalid f64 just beyond a boundary may
    // otherwise round into the valid f32 interval.
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return None;
    }
    let rounded = value as f32;
    // A minimum must not round down and admit a claim below the authored
    // threshold. The resolved representation is deliberately f32.
    Some(if f64::from(rounded) < value {
        rounded.next_up()
    } else {
        rounded
    })
}

/// Resolve once at the authority boundary. An absent request copies the floor
/// exactly. Invalid numbers return no resolved filter, even for a deny floor.
pub(crate) fn narrow_retrieval_filter(
    floor: &RetrievalPolicyFloor,
    requested: Option<&RetrievalFilter>,
) -> Result<ResolvedRetrievalFilter> {
    floor.validate()?;
    let mut narrowed = floor.clone();
    if let Some(requested) = requested {
        // These are meet identities, NOT a substitute authority floor.
        let request = RetrievalPolicyFloor {
            allowed_entity_types: requested.entity_types.clone(),
            max_sensitivity_band: requested.max_sensitivity_band.unwrap_or(3),
            include_stale: requested.include_stale.unwrap_or(true),
            min_confidence: requested.min_confidence.unwrap_or(0.0),
            min_salience: requested.min_salience.unwrap_or(0.0),
            deny_all: false,
        };
        request.validate()?;
        narrowed = narrowed.restrict(request);
    }
    Ok(ResolvedRetrievalFilter {
        entity_types: narrowed.allowed_entity_types,
        max_sensitivity_band: narrowed.max_sensitivity_band,
        include_stale: narrowed.include_stale,
        min_confidence: narrowed.min_confidence,
        min_salience: narrowed.min_salience,
        deny_all: narrowed.deny_all,
    })
}

#[cfg(test)]
mod tests;

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
        let mut floor: Option<Self> = None;
        for grant in grants.iter().filter(|grant| {
            scoped_read_grant_has_read_effector(grant)
                && !grant.receipt_required
                && grant.budget.is_none()
                && scoped_read_actor_matches(grant, actor)
        }) {
            let Some(row) = Self::from_scope(grant.scope.as_ref()) else {
                // A malformed matching row is not an absent constraint, and
                // another matching row must not rescue it.
                return Self::deny_all();
            };
            floor = Some(match floor {
                None => row,
                Some(existing) => existing.restrict(row),
            });
        }
        floor.unwrap_or_else(Self::deny_all)
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

    /// Meet of already-validated constraints; shared by grant folding and
    /// caller narrowing so the two paths use the same field algebra.
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
mod tests {
    use super::*;

    fn actor() -> ScopedReadActorKey {
        ScopedReadActorKey::with_actor_class("agent:reader", "agent").expect("actor key")
    }

    fn scope(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        )
    }

    fn types(values: &[u8]) -> Value {
        Value::Array(values.iter().copied().map(Value::from).collect())
    }

    fn grant(scope: Value) -> PolicyScopedGrant {
        PolicyScopedGrant {
            actor_class: Some("agent".to_owned()),
            actor_ref: Some("agent:reader".to_owned()),
            effector: "core:read".to_owned(),
            scope: Some(scope),
            budget: None,
            receipt_required: false,
        }
    }

    fn floor() -> RetrievalPolicyFloor {
        RetrievalPolicyFloor {
            allowed_entity_types: Some(BTreeSet::from([0, 1, 3])),
            max_sensitivity_band: 2,
            include_stale: true,
            min_confidence: 0.25,
            min_salience: 0.5,
            deny_all: false,
        }
    }

    fn assert_resolves_to_floor(floor: &RetrievalPolicyFloor, request: Option<&RetrievalFilter>) {
        let resolved = narrow_retrieval_filter(floor, request).expect("valid constraints");
        assert_eq!(resolved.entity_types, floor.allowed_entity_types);
        assert_eq!(resolved.max_sensitivity_band, floor.max_sensitivity_band);
        assert_eq!(resolved.include_stale, floor.include_stale);
        assert_eq!(resolved.min_confidence, floor.min_confidence);
        assert_eq!(resolved.min_salience, floor.min_salience);
        assert_eq!(resolved.deny_all, floor.deny_all);
    }

    #[test]
    fn unset_fails_closed_to_floor() {
        for floor in [
            floor(),
            RetrievalPolicyFloor::legacy(),
            RetrievalPolicyFloor::deny_all(),
        ] {
            assert_resolves_to_floor(&floor, None);
            assert_resolves_to_floor(&floor, Some(&RetrievalFilter::default()));
        }
    }

    #[test]
    fn field_narrows_not_widens() {
        let floor = floor();
        let baseline = narrow_retrieval_filter(&floor, None).expect("floor");
        let cases = [
            RetrievalFilter {
                entity_types: Some(BTreeSet::from([0, 4])),
                ..RetrievalFilter::default()
            },
            RetrievalFilter {
                max_sensitivity_band: Some(1),
                ..RetrievalFilter::default()
            },
            RetrievalFilter {
                include_stale: Some(false),
                ..RetrievalFilter::default()
            },
            RetrievalFilter {
                min_confidence: Some(0.75),
                ..RetrievalFilter::default()
            },
            RetrievalFilter {
                min_salience: Some(0.875),
                ..RetrievalFilter::default()
            },
        ];
        for (index, request) in cases.iter().enumerate() {
            let mut expected = baseline.clone();
            match index {
                0 => expected.entity_types = Some(BTreeSet::from([0])),
                1 => expected.max_sensitivity_band = 1,
                2 => expected.include_stale = false,
                3 => expected.min_confidence = 0.75,
                4 => expected.min_salience = 0.875,
                _ => unreachable!(),
            }
            assert_eq!(
                narrow_retrieval_filter(&floor, Some(request)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn over_ask_clamped() {
        let floor = RetrievalPolicyFloor {
            include_stale: false,
            ..floor()
        };
        let request = RetrievalFilter {
            entity_types: Some(BTreeSet::from([0, 1, 3, 4])),
            max_sensitivity_band: Some(3),
            include_stale: Some(true),
            min_confidence: Some(0.0),
            min_salience: Some(0.0),
        };
        assert_resolves_to_floor(&floor, Some(&request));
        assert_resolves_to_floor(&RetrievalPolicyFloor::deny_all(), Some(&request));
    }

    #[test]
    fn empty_and_disjoint_type_requests_deny_all() {
        for requested in [BTreeSet::new(), BTreeSet::from([4])] {
            let request = RetrievalFilter {
                entity_types: Some(requested),
                ..RetrievalFilter::default()
            };
            let resolved = narrow_retrieval_filter(&floor(), Some(&request)).unwrap();
            assert!(resolved.deny_all);
            assert_eq!(resolved.entity_types, Some(BTreeSet::new()));
        }
        let request = RetrievalFilter {
            entity_types: Some(BTreeSet::from([0, 3])),
            ..RetrievalFilter::default()
        };
        let resolved = narrow_retrieval_filter(&RetrievalPolicyFloor::legacy(), Some(&request))
            .expect("narrow all registered types");
        assert_eq!(resolved.entity_types, request.entity_types);
        assert!(!resolved.deny_all);
    }

    #[test]
    fn matching_rows_meet_restrictively_and_order_independently() {
        let first = grant(scope(vec![
            ("entity_types", types(&[0, 1, 3])),
            ("max_sensitivity_band", Value::from(2)),
            ("include_stale", Value::Boolean(true)),
            ("min_confidence", Value::F32(0.75)),
            ("min_salience", Value::F32(0.25)),
        ]));
        let second = grant(scope(vec![
            ("entity_types", types(&[0, 3, 4])),
            ("max_sensitivity_band", Value::from(1)),
            ("include_stale", Value::Boolean(false)),
            ("min_confidence", Value::F32(0.5)),
            ("min_salience", Value::F32(0.875)),
        ]));
        let expected = RetrievalPolicyFloor {
            allowed_entity_types: Some(BTreeSet::from([0, 3])),
            max_sensitivity_band: 1,
            include_stale: false,
            min_confidence: 0.75,
            min_salience: 0.875,
            deny_all: false,
        };
        for rows in [
            vec![first.clone(), second.clone()],
            vec![second.clone(), first.clone()],
            vec![first.clone(), second, first],
        ] {
            assert_eq!(
                RetrievalPolicyFloor::from_scoped_grants(&rows, &actor()),
                expected
            );
        }
    }

    #[test]
    fn disjoint_grants_and_empty_grant_types_deny_all() {
        for rows in [
            vec![grant(scope(vec![("entity_types", types(&[]))]))],
            vec![
                grant(scope(vec![("entity_types", types(&[0]))])),
                grant(scope(vec![("entity_types", types(&[3]))])),
            ],
        ] {
            let floor = RetrievalPolicyFloor::from_scoped_grants(&rows, &actor());
            assert!(floor.deny_all);
            assert_eq!(floor.allowed_entity_types, Some(BTreeSet::new()));
        }
    }

    #[test]
    fn absent_grant_fields_use_legacy_defaults_but_explicit_stale_can_be_authorized() {
        for scope in [None, Some(Value::Nil), Some(Value::Map(Vec::new()))] {
            let row = PolicyScopedGrant {
                scope,
                ..grant(Value::Nil)
            };
            assert_eq!(
                RetrievalPolicyFloor::from_scoped_grants(&[row], &actor()),
                RetrievalPolicyFloor::legacy()
            );
        }
        let row = grant(scope(vec![("include_stale", Value::Boolean(true))]));
        let floor = RetrievalPolicyFloor::from_scoped_grants(std::slice::from_ref(&row), &actor());
        assert!(floor.include_stale);
        assert_resolves_to_floor(&floor, None);
        let floor = RetrievalPolicyFloor::from_scoped_grants(&[row, grant(Value::Nil)], &actor());
        assert!(!floor.include_stale);
    }

    #[test]
    fn actor_and_read_effector_selection_reuses_existing_rules() {
        let valid = grant(Value::Nil);
        for effector in ["core:read", "oneiron.read", " core:read "] {
            let row = PolicyScopedGrant {
                effector: effector.to_owned(),
                ..valid.clone()
            };
            assert!(!RetrievalPolicyFloor::from_scoped_grants(&[row], &actor()).deny_all);
        }
        let excluded = [
            PolicyScopedGrant {
                actor_ref: Some("agent:other".to_owned()),
                ..valid.clone()
            },
            PolicyScopedGrant {
                actor_class: Some("system".to_owned()),
                ..valid.clone()
            },
            PolicyScopedGrant {
                effector: "core:*".to_owned(),
                ..valid.clone()
            },
            PolicyScopedGrant {
                effector: "oneiron:read".to_owned(),
                ..valid.clone()
            },
            PolicyScopedGrant {
                receipt_required: true,
                ..valid.clone()
            },
            PolicyScopedGrant {
                budget: Some(Value::Nil),
                ..valid.clone()
            },
        ];
        for row in excluded {
            assert!(RetrievalPolicyFloor::from_scoped_grants(&[row], &actor()).deny_all);
        }
        let unclassified = ScopedReadActorKey::new("agent:reader").unwrap();
        assert!(
            RetrievalPolicyFloor::from_scoped_grants(std::slice::from_ref(&valid), &unclassified)
                .deny_all
        );
        let wildcard = PolicyScopedGrant {
            actor_class: None,
            actor_ref: None,
            ..valid
        };
        assert!(!RetrievalPolicyFloor::from_scoped_grants(&[wildcard], &unclassified).deny_all);
    }

    #[test]
    fn missing_manifest_denies_scoped_actor_but_owner_has_explicit_legacy_floor() {
        let policy = PolicyManifestResolution::default();
        assert_eq!(
            policy.retrieval_floor_for_actor(Some(&actor())),
            RetrievalPolicyFloor::deny_all()
        );
        assert_eq!(
            policy.retrieval_floor_for_actor(None),
            RetrievalPolicyFloor::legacy()
        );
    }

    #[test]
    fn floor_uses_resolved_manifest_projection_and_its_fail_closed_diagnostics() -> Result<()> {
        let (_tmp, vault) = crate::test_util::open_test_vault_with(Default::default());
        let bytes = crate::gate::default_policy_manifest();
        let Value::Map(mut entries) =
            rmpv::decode::read_value(&mut bytes.as_slice()).expect("decode manifest fixture")
        else {
            panic!("manifest must be a map");
        };
        entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
        entries.push((
            Value::from("scoped_grants"),
            Value::Array(vec![scope(vec![
                ("actor_ref", Value::from("agent:reader")),
                ("effector", Value::from("core:read")),
                ("receipt_required", Value::Boolean(false)),
                (
                    "scope",
                    scope(vec![("include_stale", Value::Boolean(true))]),
                ),
            ])]),
        ));
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode manifest");
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )?;
        let txn = vault.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        assert!(!policy.is_fail_closed());
        assert_eq!(
            policy.retrieval_floor_for_actor(Some(&actor())),
            RetrievalPolicyFloor {
                include_stale: true,
                ..RetrievalPolicyFloor::legacy()
            }
        );
        for diagnostic in 0..4 {
            let mut invalid = policy.clone();
            match diagnostic {
                0 => invalid.diagnostics.malformed_manifest_seen = true,
                1 => invalid.diagnostics.unsupported_schema_seen = true,
                2 => invalid.diagnostics.engine_version_floor_seen = true,
                3 => invalid.diagnostics.unknown_axis_seen = true,
                _ => unreachable!(),
            }
            assert_eq!(
                invalid.retrieval_floor_for_actor(Some(&actor())),
                RetrievalPolicyFloor::deny_all()
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_matching_grant_denies_only_affected_actor() {
        let bad = grant(scope(vec![("min_confidence", Value::F64(f64::NAN))]));
        let other = PolicyScopedGrant {
            actor_ref: Some("agent:other".to_owned()),
            ..grant(Value::Nil)
        };
        for rows in [
            vec![bad.clone(), grant(Value::Nil), other.clone()],
            vec![other, grant(Value::Nil), bad],
        ] {
            assert!(RetrievalPolicyFloor::from_scoped_grants(&rows, &actor()).deny_all);
            let actor = ScopedReadActorKey::with_actor_class("agent:other", "agent").unwrap();
            assert_eq!(
                RetrievalPolicyFloor::from_scoped_grants(&rows, &actor),
                RetrievalPolicyFloor::legacy()
            );
        }
    }

    #[test]
    fn malformed_grant_values_fail_closed() {
        let bad_numbers = [
            Value::F32(f32::NAN),
            Value::F32(f32::INFINITY),
            Value::F32(f32::NEG_INFINITY),
            Value::F64(f64::NAN),
            Value::F64(f64::INFINITY),
            Value::F64(f64::NEG_INFINITY),
            Value::F64(-f64::MIN_POSITIVE),
            Value::F64(1.0 + f64::EPSILON),
            Value::from(-1),
            Value::from(2),
            Value::from("0.5"),
            Value::Boolean(true),
            Value::Nil,
        ];
        let mut malformed = vec![
            Value::from("scope"),
            Value::Array(Vec::new()),
            Value::Map(vec![(Value::from(1), Value::from(1))]),
        ];
        for key in ["min_confidence", "min_salience"] {
            for value in &bad_numbers {
                malformed.push(scope(vec![(key, value.clone())]));
            }
        }
        for value in [
            Value::from(-1),
            Value::from(4),
            Value::from(256_u64),
            Value::F64(1.0),
            Value::Nil,
        ] {
            malformed.push(scope(vec![("max_sensitivity_band", value)]));
        }
        for value in [Value::from(1), Value::from("true"), Value::Nil] {
            malformed.push(scope(vec![("include_stale", value)]));
        }
        for value in [Value::Nil, Value::from(0), Value::from("0")] {
            malformed.push(scope(vec![("entity_types", value)]));
        }
        for value in [
            Value::from(-1),
            Value::from(256_u64),
            Value::F64(0.0),
            Value::from("0"),
            Value::Nil,
        ] {
            malformed.push(scope(vec![(
                "entity_types",
                Value::Array(vec![Value::from(0), value]),
            )]));
        }
        for value in malformed {
            let floor = RetrievalPolicyFloor::from_scoped_grants(&[grant(value)], &actor());
            assert_eq!(floor, RetrievalPolicyFloor::deny_all());
        }
    }

    #[test]
    fn duplicate_filter_keys_fail_closed() {
        for (key, value) in [
            ("entity_types", types(&[0])),
            ("max_sensitivity_band", Value::from(2)),
            ("include_stale", Value::Boolean(false)),
            ("min_confidence", Value::F32(0.5)),
            ("min_salience", Value::F32(0.5)),
        ] {
            let row = grant(scope(vec![(key, value.clone()), (key, value)]));
            assert!(RetrievalPolicyFloor::from_scoped_grants(&[row], &actor()).deny_all);
        }
    }

    #[test]
    fn invalid_request_and_floor_numbers_return_no_resolved_filter() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 1.1] {
            for request in [
                RetrievalFilter {
                    min_confidence: Some(value),
                    ..RetrievalFilter::default()
                },
                RetrievalFilter {
                    min_salience: Some(value),
                    ..RetrievalFilter::default()
                },
            ] {
                assert!(narrow_retrieval_filter(&floor(), Some(&request)).is_err());
                assert!(
                    narrow_retrieval_filter(&RetrievalPolicyFloor::deny_all(), Some(&request))
                        .is_err()
                );
            }
            for floor in [
                RetrievalPolicyFloor {
                    min_confidence: value,
                    ..floor()
                },
                RetrievalPolicyFloor {
                    min_salience: value,
                    ..floor()
                },
            ] {
                assert!(narrow_retrieval_filter(&floor, None).is_err());
            }
        }
        for band in [4, u8::MAX] {
            let request = RetrievalFilter {
                max_sensitivity_band: Some(band),
                ..RetrievalFilter::default()
            };
            assert!(narrow_retrieval_filter(&floor(), Some(&request)).is_err());
            let floor = RetrievalPolicyFloor {
                max_sensitivity_band: band,
                ..floor()
            };
            assert!(narrow_retrieval_filter(&floor, None).is_err());
        }
    }

    #[test]
    fn numeric_boundaries_and_f64_minima_round_restrictively() {
        for value in [Value::from(0), Value::F32(0.0), Value::F64(0.0)] {
            assert_eq!(parse_minimum(&value), Some(0.0));
        }
        for value in [Value::from(1), Value::F32(1.0), Value::F64(1.0)] {
            assert_eq!(parse_minimum(&value), Some(1.0));
        }
        for value in [0.5 + f64::EPSILON, f64::MIN_POSITIVE] {
            let minimum = parse_minimum(&Value::F64(value)).unwrap();
            assert!(f64::from(minimum) >= value);
            assert!(f64::from(minimum.next_down()) < value);
        }
    }

    #[test]
    fn other_scope_fields_are_not_reinterpreted_by_filter_projection() {
        let row = grant(scope(vec![
            ("world_ref", Value::from("base")),
            ("facet", Value::from("opaque-to-filter")),
            (
                "claim_scope",
                scope(vec![("relationship", Value::from("opaque-to-filter"))]),
            ),
            ("min_salience", Value::F32(0.5)),
        ]));
        let expected = RetrievalPolicyFloor {
            min_salience: 0.5,
            ..RetrievalPolicyFloor::legacy()
        };
        assert_eq!(
            RetrievalPolicyFloor::from_scoped_grants(&[row], &actor()),
            expected
        );
    }
}

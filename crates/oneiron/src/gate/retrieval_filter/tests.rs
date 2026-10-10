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

fn grant(scope: Value) -> PolicyScopedGrant {
    PolicyScopedGrant {
        authority_scope: crate::federation::scope_codec::read_preset(),
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
fn actor_and_read_effector_selection_reuses_existing_rules() {
    let valid = grant(scope(vec![("include_stale", Value::Boolean(true))]));
    for effector in ["core:read", "oneiron.read", " core:read "] {
        let row = PolicyScopedGrant {
            effector: effector.to_owned(),
            ..valid.clone()
        };
        assert!(
            RetrievalPolicyFloor::from_scoped_grants(&[row], &actor())
                .unwrap_or_else(RetrievalPolicyFloor::deny_all)
                .include_stale
        );
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
        // Keep the read plane present even when this row is not a read effector.
        let unmatched = PolicyScopedGrant {
            actor_ref: Some("agent:other".to_owned()),
            ..valid.clone()
        };
        assert!(
            RetrievalPolicyFloor::from_scoped_grants(&[row, unmatched], &actor())
                .unwrap_or_else(RetrievalPolicyFloor::deny_all)
                .deny_all
        );
    }
    let unclassified = ScopedReadActorKey::new("agent:reader").unwrap();
    assert!(
        RetrievalPolicyFloor::from_scoped_grants(std::slice::from_ref(&valid), &unclassified)
            .unwrap_or_else(RetrievalPolicyFloor::deny_all)
            .deny_all
    );
    let wildcard = PolicyScopedGrant {
        actor_class: None,
        actor_ref: None,
        ..valid
    };
    assert!(
        RetrievalPolicyFloor::from_scoped_grants(&[wildcard], &unclassified)
            .unwrap_or_else(RetrievalPolicyFloor::deny_all)
            .include_stale
    );
}

#[test]
fn missing_manifest_denies_plain_scoped_actor_but_preserves_trusted_owner_default() {
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

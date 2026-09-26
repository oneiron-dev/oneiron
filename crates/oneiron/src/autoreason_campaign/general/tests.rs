use super::*;

fn dataset(name: &str) -> CampaignDatasetRef {
    CampaignDatasetRef {
        dataset_id: name.into(),
        revision: "r1".into(),
    }
}

fn config() -> CampaignConfig {
    CampaignConfig {
        campaign_id: "generic-loop".into(),
        search_axes: vec![SearchAxis {
            name: "strategy".into(),
            values: vec!["a".into(), "b".into()],
        }],
        metric_set: MetricSet {
            set_id: "my-metrics".into(),
            revision: "r1".into(),
            axes: vec![
                MetricAxis {
                    name: "quality".into(),
                    direction: MetricDirection::Higher,
                    role: MetricRole::Primary,
                },
                MetricAxis {
                    name: "safety".into(),
                    direction: MetricDirection::Higher,
                    role: MetricRole::Floor,
                },
                MetricAxis {
                    name: "latency".into(),
                    direction: MetricDirection::Lower,
                    role: MetricRole::Cost,
                },
            ],
        },
        splits: CampaignSplits {
            search: dataset("search"),
            held_out: dataset("held-out"),
            sealed: dataset("sealed"),
        },
        budget: BudgetLease {
            budget_id: "vault-lease".into(),
            max_units: 100,
            exploration_units: 20,
        },
        decide: DecideRules {
            min_primary_gain: 0.05,
        },
        knobs: CampaignKnobs::default(),
    }
}

fn scores(config: &CampaignConfig, quality: f64, safety: f64, latency: f64) -> Measurement {
    Measurement {
        dataset: config.splits.held_out.clone(),
        metric_set_id: config.metric_set.set_id.clone(),
        metric_set_revision: config.metric_set.revision.clone(),
        scores: BTreeMap::from([
            ("quality".into(), quality),
            ("safety".into(), safety),
            ("latency".into(), latency),
        ]),
    }
}

#[test]
fn generic_config_round_trips_and_crossover_defaults_off() {
    let config = config();
    let json = serde_json::to_value(&config).unwrap();
    let decoded: CampaignConfig = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, config);
    let mut json = serde_json::to_value(config).unwrap();
    json.as_object_mut().unwrap().remove("knobs");
    let decoded: CampaignConfig = serde_json::from_value(json).unwrap();
    decoded.validate().unwrap();
    assert!(!decoded.knobs.merge_crossover.requested);
}

#[test]
fn rejects_bad_axes_metric_sets_splits_leases_and_rules() {
    type Mutation = (&'static str, fn(&mut CampaignConfig));
    let changes: [Mutation; 14] = [
        ("campaign_id", |c| c.campaign_id.clear()),
        ("search_axes", |c| c.search_axes.clear()),
        ("search_axes", |c| c.search_axes[0].values.push("a".into())),
        ("search_axes", |c| {
            c.search_axes.push(c.search_axes[0].clone());
        }),
        ("metric_set.set_id", |c| c.metric_set.set_id.clear()),
        ("metric_set.axes", |c| c.metric_set.axes.clear()),
        ("metric_set.axes", |c| {
            c.metric_set.axes[0].role = MetricRole::Floor;
        }),
        ("splits", |c| c.splits.search = c.splits.held_out.clone()),
        ("splits", |c| c.splits.sealed.revision.clear()),
        ("budget.budget_id", |c| c.budget.budget_id.clear()),
        ("budget", |c| c.budget.max_units = 0),
        ("budget", |c| c.budget.exploration_units = 101),
        ("decide.min_primary_gain", |c| {
            c.decide.min_primary_gain = f64::NAN;
        }),
        ("knobs.merge_crossover", |c| {
            c.knobs.merge_crossover.min_validation_overlap = 0.0;
        }),
    ];
    for (field, change) in changes {
        let mut c = config();
        change(&mut c);
        assert!(
            matches!(c.validate(), Err(CampaignError::InvalidConfig { field: actual, .. }) if actual == field),
            "{field}"
        );
    }
}

#[test]
fn crossover_needs_explicit_request_and_held_out_dominance() {
    let mut c = config();
    let baseline = scores(&c, 0.5, 1.0, 10.0);
    let winner = scores(&c, 0.7, 1.0, 9.0);
    assert_eq!(
        c.decide_held_out(&baseline, &winner).unwrap().verdict(),
        Verdict::Promote
    );
    assert!(
        !c.decide_held_out(&baseline, &winner)
            .unwrap()
            .merge_crossover_enabled()
    );
    c.knobs.merge_crossover.requested = true;
    // A lower cost with unchanged quality also dominates on held-out.
    assert!(
        c.decide_held_out(&baseline, &scores(&c, 0.5, 1.0, 9.0))
            .unwrap()
            .merge_crossover_enabled()
    );
    assert!(
        c.decide_held_out(&baseline, &winner)
            .unwrap()
            .merge_crossover_enabled()
    );
    for contender in [
        scores(&c, 0.5, 1.0, 10.0),
        scores(&c, 0.8, 0.9, 8.0),
        scores(&c, 0.8, 1.0, 11.0),
        scores(&c, 0.52, 1.0, 9.0),
    ] {
        assert!(
            !c.decide_held_out(&baseline, &contender)
                .unwrap()
                .merge_crossover_enabled()
        );
    }
    assert_eq!(
        c.decide_held_out(&baseline, &scores(&c, 0.8, 1.0, 11.0))
            .unwrap()
            .verdict(),
        Verdict::EscalateTradeoff
    );
}

#[test]
fn search_or_unpinned_measurements_cannot_enable_crossover() {
    let mut c = config();
    c.knobs.merge_crossover.requested = true;
    let before = scores(&c, 0.5, 1.0, 10.0);
    let mut after = scores(&c, 0.8, 1.0, 9.0);
    for change in [
        |m: &mut Measurement| m.dataset = dataset("search"),
        |m: &mut Measurement| m.dataset = dataset("sealed"),
        |m: &mut Measurement| m.metric_set_revision = "other".into(),
        |m: &mut Measurement| {
            m.scores.insert("extra".into(), 1.0);
        },
        |m: &mut Measurement| {
            m.scores.insert("quality".into(), f64::NAN);
        },
    ] {
        change(&mut after);
        assert!(matches!(
            c.decide_held_out(&before, &after),
            Err(CampaignError::InvalidConfig {
                field: "measurement",
                ..
            })
        ));
        after = scores(&c, 0.8, 1.0, 9.0);
    }
}

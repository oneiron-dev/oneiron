//! K-proof (oracle) for PLAN-UC-04 stage 3.2: the agent-health trend replay hash keeps
//! its bytes.
//!
//! The trend pass's replay hash now starts its BLAKE3 through the fingerprint crate's K
//! door (`purposes::dreamer::AGENT_HEALTH_TREND`). A trend DIAGNOSTIC's body stores it as
//! `replay.content_hash`, the row id binds that body, and diagnostic reads return it. So
//! it must give main's bytes for every comparison. `base` below holds main's lines at
//! 9f9cd3693163, copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them
//! only in indentation. The copy reads a view of the comparison whose metric is main's
//! own enum, so the metric token is main's body too; the head is reached through the
//! test door `fingerprint_keep_dreamer`.

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::dreamer_runner::maintenance::agent_health::{
    HealthTrendComparison, TrendDirection, TrendMargin, TrendMetric, TrendRatio, TrendSide,
    TrendStratum,
};
use oneiron::run_budget::LeaseUnit;
use oneiron::store::diagnostic_record::AgentHealthSignal;
use oneiron::test_doors::fingerprint_keep_dreamer as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base {
    use oneiron::dreamer_runner::maintenance::agent_health::{TrendMargin, TrendSide, TrendStratum};
    use oneiron::run_budget::LeaseUnit;
    use oneiron::store::diagnostic_record::AgentHealthSignal;

    /// The fields of a comparison the replay hash reads; the metric is main's enum.
    pub(crate) struct HealthTrendComparison {
        pub(crate) margin: TrendMargin,
        pub(crate) stratum: TrendStratum,
        pub(crate) metric: TrendMetric,
        pub(crate) prior: TrendSide,
        pub(crate) latest: TrendSide,
    }

    /// What a comparison measures, with main's variants.
    pub(crate) enum TrendMetric {
        Signal(AgentHealthSignal),
        Attempts,
        Calls,
        Retries,
        Spend(LeaseUnit),
        Wait,
    }

    impl TrendMetric {
    // main 9f9cd3693163: crates/oneiron/src/dreamer_runner/maintenance/agent_health/trend.rs:81-91
        /// The metric's stable token, as the replay hash binds it.
        pub(super) fn token(&self) -> String {
            match self {
                Self::Signal(signal) => format!("signal.{}", signal.as_str()),
                Self::Attempts => "attempts".to_owned(),
                Self::Calls => "calls".to_owned(),
                Self::Retries => "retries".to_owned(),
                Self::Spend(unit) => format!("spend.{}", unit.as_str()),
                Self::Wait => "wait".to_owned(),
            }
        }
    }

    /// The tag main wrote first.
    pub(crate) const TAG: &[u8] = TREND_DIGEST_DOMAIN;

    // main 9f9cd3693163: crates/oneiron/src/dreamer_runner/maintenance/agent_health/trend_output.rs:37-37
    const TREND_DIGEST_DOMAIN: &[u8] = b"oneiron.coach.agent_health.trend.v1";

    // main 9f9cd3693163: crates/oneiron/src/dreamer_runner/maintenance/agent_health/trend_output.rs:199-253
    /// The replay hash: the margin, the stratum, the metric, and each side's
    /// days (the policy's period), counts and every typed ref, spend scopes
    /// included. The same evidence under the same policy is the same hash.
    fn content_hash(comparison: &HealthTrendComparison) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(TREND_DIGEST_DOMAIN);
        match &comparison.margin {
            TrendMargin::Actor(actor) => {
                digest.update(b"actor");
                digest.update(actor.as_bytes());
            }
            TrendMargin::Project(project) => {
                digest.update(b"project");
                let bytes: [u8; 16] = project.as_ref().map_or([0_u8; 16], |id| *id.as_bytes());
                digest.update(&bytes);
            }
        }
        field(&mut digest, comparison.stratum.type_node.as_bytes());
        match &comparison.stratum.model {
            Some(model) => field(&mut digest, model.as_bytes()),
            None => {
                digest.update(&[0xff]);
            }
        }
        field(&mut digest, comparison.metric.token().as_bytes());
        for side in [&comparison.prior, &comparison.latest] {
            for number in [
                side.days.0,
                side.days.1,
                side.ratio.numerator,
                side.ratio.denominator,
                side.ratio.known,
                side.ratio.eligible,
            ] {
                digest.update(&number.to_le_bytes());
            }
            for ids in [&side.attempts, &side.refs] {
                digest.update(&(ids.len() as u64).to_le_bytes());
                for id in ids {
                    digest.update(id.as_bytes());
                }
            }
            digest.update(&(side.scopes.len() as u64).to_le_bytes());
            for scope in &side.scopes {
                field(&mut digest, scope.as_bytes());
            }
        }
        *digest.finalize().as_bytes()
    }

    /// One length-prefixed field, so no two field lists hash alike.
    fn field(digest: &mut blake3::Hasher, bytes: &[u8]) {
        digest.update(&(bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }

    pub(crate) fn trend_content_hash(comparison: &HealthTrendComparison) -> [u8; 32] {
        content_hash(comparison)
    }
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes(std::array::from_fn(|at| seed ^ (at as u8).wrapping_mul(17)))
        .expect("an id with no reserved bytes")
}

/// Each metric as the engine names it and as main's copy names it: every T1 signal,
/// the volume metrics, spend in two units, and wait.
fn metrics() -> Vec<(TrendMetric, base::TrendMetric)> {
    let mut metrics: Vec<_> = AgentHealthSignal::all()
        .into_iter()
        .map(|signal| {
            (
                TrendMetric::Signal(signal),
                base::TrendMetric::Signal(signal),
            )
        })
        .collect();
    let usd = LeaseUnit::new("usd").expect("a lease unit name");
    metrics.extend([
        (TrendMetric::Attempts, base::TrendMetric::Attempts),
        (TrendMetric::Calls, base::TrendMetric::Calls),
        (TrendMetric::Retries, base::TrendMetric::Retries),
        (
            TrendMetric::Spend(LeaseUnit::tokens()),
            base::TrendMetric::Spend(LeaseUnit::tokens()),
        ),
        (
            TrendMetric::Spend(usd.clone()),
            base::TrendMetric::Spend(usd),
        ),
        (TrendMetric::Wait, base::TrendMetric::Wait),
    ]);
    metrics
}

/// Sides: an empty one; one with refs, attempts and a scope; and one at every maximum,
/// with refs and no attempts, and an empty scope beside two splits of one string.
fn sides() -> [TrendSide; 3] {
    [
        TrendSide {
            days: (0, 0),
            ratio: TrendRatio::default(),
            refs: BTreeSet::new(),
            attempts: BTreeSet::new(),
            scopes: BTreeSet::new(),
        },
        TrendSide {
            days: (10, 17),
            ratio: TrendRatio {
                numerator: 3,
                denominator: 7,
                known: 6,
                eligible: 7,
            },
            refs: BTreeSet::from([id(3)]),
            attempts: BTreeSet::from([id(3), id(4)]),
            scopes: BTreeSet::from(["lease/a".to_owned()]),
        },
        TrendSide {
            days: (u64::MAX, u64::MAX),
            ratio: TrendRatio {
                numerator: u64::MAX,
                denominator: u64::MAX,
                known: u64::MAX,
                eligible: u64::MAX,
            },
            refs: BTreeSet::from([id(5), id(6)]),
            attempts: BTreeSet::new(),
            scopes: BTreeSet::from([String::new(), "ab".to_owned(), "c".to_owned()]),
        },
    ]
}

#[test]
fn the_trend_purpose_keeps_main_s_tag() {
    let purpose = purposes::dreamer::AGENT_HEALTH_TREND;
    assert_eq!(purpose.tag().as_bytes(), base::TAG);
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
}

#[test]
fn the_trend_replay_hash_keeps_its_bytes() {
    let margins = [
        TrendMargin::Actor(id(1)),
        TrendMargin::Project(None),
        TrendMargin::Project(Some(id(2))),
    ];
    let strata = [
        TrendStratum {
            type_node: String::new(),
            model: None,
        },
        TrendStratum {
            type_node: "code.review".to_owned(),
            model: Some(String::new()),
        },
        TrendStratum {
            type_node: "code.review".to_owned(),
            model: Some("model-a".to_owned()),
        },
    ];
    let [empty, some, full] = sides();
    let side_pairs = [
        (empty.clone(), empty.clone()),
        (empty, some.clone()),
        (some.clone(), full.clone()),
        (full, some),
    ];
    let mut checked = 0;
    for margin in &margins {
        for stratum in &strata {
            for (prior, latest) in &side_pairs {
                for (metric, base_metric) in metrics() {
                    let comparison = HealthTrendComparison {
                        margin: margin.clone(),
                        stratum: stratum.clone(),
                        metric,
                        prior: prior.clone(),
                        latest: latest.clone(),
                        delta: None,
                        direction: TrendDirection::Flat,
                    };
                    let view = base::HealthTrendComparison {
                        margin: margin.clone(),
                        stratum: stratum.clone(),
                        metric: base_metric,
                        prior: prior.clone(),
                        latest: latest.clone(),
                    };
                    assert_eq!(
                        door::trend_content_hash(&comparison),
                        base::trend_content_hash(&view),
                        "{comparison:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    // 3 margins x 3 strata x 4 side pairs x 14 metrics.
    assert_eq!(checked, 504);
}

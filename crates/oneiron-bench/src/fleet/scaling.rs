//! Isolated persisted-residual miss cost as graph cardinality grows.
use super::{
    Result,
    configuration::Plan,
    optimization,
    report::{Host, Metric, Optimization},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub(super) struct Sample {
    nodes: usize,
    metrics: BTreeMap<String, Metric>,
    optimization: Optimization,
}
#[derive(Serialize)]
pub(super) struct Scaling {
    schema: &'static str,
    host: Host,
    binary_blake3: String,
    plan: Plan,
    samples: Vec<Sample>,
    node_growth: f64,
    residual_miss_cost_growth: f64,
    observed_sublinear: bool,
}

pub(super) fn measure(plan: &Plan) -> Result<Scaling> {
    let mut samples = Vec::new();
    for multiplier in [1, 4, 16] {
        let mut arm = plan.clone();
        arm.ppr_nodes = plan
            .ppr_nodes
            .checked_mul(multiplier)
            .filter(|n| *n <= 100_000)
            .ok_or("scaling exceeds the profile node bound")?;
        let mut metrics = BTreeMap::new();
        let optimization = optimization::measure(&arm, &mut metrics)?;
        samples.push(Sample {
            nodes: arm.ppr_nodes,
            metrics,
            optimization,
        });
    }
    let node_growth = samples[2].nodes as f64 / samples[0].nodes as f64;
    let residual_miss_cost_growth = samples[2].metrics["ppr_resume"].elapsed_seconds
        / samples[0].metrics["ppr_resume"].elapsed_seconds;
    let observed_sublinear = observed_sublinear(&samples);
    Ok(Scaling {
        schema: "oneiron-ppr-scaling-v1",
        host: Host::capture()?,
        binary_blake3: super::file_hash(&std::env::current_exe()?)?,
        plan: plan.clone(),
        samples,
        node_growth,
        residual_miss_cost_growth,
        observed_sublinear,
    })
}

fn observed_sublinear(samples: &[Sample]) -> bool {
    samples.len() >= 3
        && samples.windows(2).all(|pair| {
            let before = pair[0].metrics["ppr_resume"].elapsed_seconds;
            let after = pair[1].metrics["ppr_resume"].elapsed_seconds;
            sublinear_interval(pair[0].nodes, pair[1].nodes, before, after)
        })
}

fn sublinear_interval(before_nodes: usize, after_nodes: usize, before: f64, after: f64) -> bool {
    before_nodes > 0
        && after_nodes > before_nodes
        && before.is_finite()
        && after.is_finite()
        && before > 0.0
        && after >= before
        && after / before < after_nodes as f64 / before_nodes as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decreasing_or_linear_samples_do_not_prove_sublinear_scaling() {
        assert!(!sublinear_interval(4096, 16384, 112.07, 7.28));
        assert!(!sublinear_interval(1024, 4096, 1.0, 4.0));
        assert!(!sublinear_interval(1024, 4096, 0.0, 1.0));
        assert!(!sublinear_interval(1024, 4096, 1.0, f64::NAN));
        assert!(sublinear_interval(1024, 4096, 1.0, 2.0));
    }
    #[test]
    fn scaling_keeps_real_pairs_separate_from_fleet_receipts() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let plan = Plan::fixture(scratch.path().to_path_buf());
        let measured = measure(&plan)?;
        assert_eq!(measured.schema, "oneiron-ppr-scaling-v1");
        assert_eq!(
            measured.samples.iter().map(|s| s.nodes).collect::<Vec<_>>(),
            vec![32, 128, 512]
        );
        for sample in measured.samples {
            assert_eq!(sample.optimization.equivalent_pairs, plan.ppr_samples);
            assert_eq!(sample.metrics["ppr_resume"].completed, plan.ppr_samples);
        }
        assert!(measured.residual_miss_cost_growth.is_finite());
        // Performance is observed on the assigned host, never asserted by a
        // noisy unit fixture or promoted to a fleet CI floor from this schema.
        Ok(())
    }
}

//! Small falsification fixtures; smoke is never accepted as a fleet baseline.
use super::*;

#[test]
fn fleet_plan_refuses_undersized_fleet_and_unknown_fields() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut plan = Plan::fixture(directory.path().to_path_buf());
    plan.validate()?;
    plan.profile = "fleet20k-v1".into();
    assert!(plan.validate().is_err());
    plan.agents = 20_000;
    plan.hold_ms = 1000;
    plan.ppr_nodes = 128;
    plan.ppr_samples = 100;
    plan.validate()?;
    let mut value = serde_json::to_value(&plan)?;
    value["throughput_target"] = 0.into();
    assert!(serde_json::from_value::<Plan>(value).is_err());
    Ok(())
}

#[test]
fn fleet_metric_nearest_rank_p99_and_empty_samples() -> Result<()> {
    let metric = report::Metric::new((1..=100).map(f64::from).collect(), 2.0)?;
    assert_eq!(metric.p99_ms, 99.0);
    assert_eq!(metric.throughput_per_second, 50.0);
    assert!(report::Metric::new(vec![], 2.0).is_err());
    assert!(report::Metric::new(vec![1.0], 0.0).is_err());
    Ok(())
}

#[test]
fn fleet_small_profile_uses_real_writes_recalls_and_held_sockets() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let plan = Plan::fixture(directory.path().to_path_buf());
    plan.validate()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let observed = runtime.block_on(workload::measure(&plan))?;
    assert_eq!(observed.held_sockets, 4);
    assert_eq!(observed.verified_writes, 4);
    assert_eq!(observed.verified_recalls, 4);
    assert!(observed.hold_observed_ms >= 10.0);
    for metric in observed.metrics.values() {
        assert_eq!(metric.completed, 4);
    }
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    Ok(())
}

#[test]
fn fleet_ppr_pair_checks_real_cold_and_resume_outputs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let plan = Plan::fixture(directory.path().to_path_buf());
    let mut metrics = std::collections::BTreeMap::new();
    let result = optimization::measure(&plan, &mut metrics)?;
    assert_eq!(result.equivalent_pairs, 4);
    assert_eq!(metrics.len(), 3);
    assert!(result.incremental_speedup > 0.0);
    // No speedup claim or performance threshold is made by this correctness fixture.
    Ok(())
}

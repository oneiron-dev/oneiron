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

#[tokio::test]
async fn fleet_clients_reuse_only_owned_ports_across_distinct_listeners() {
    let sockets = super::wire::client_sockets(4, 2).unwrap();
    let ports = sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    assert_eq!(ports[0], ports[1]);
    assert_eq!(ports[2], ports[3]);
    assert_ne!(ports[0], ports[2]);
    let one = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let two = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut clients = Vec::new();
    let mut peers = Vec::new();
    for (index, socket) in sockets.into_iter().enumerate() {
        let listener = if index % 2 == 0 { &one } else { &two };
        clients.push(
            socket
                .connect(listener.local_addr().unwrap())
                .await
                .unwrap(),
        );
        peers.push(listener.accept().await.unwrap());
    }
    assert_eq!(clients.len(), 4);
    assert_eq!(peers.len(), 4);
}

#[test]
fn fleet_digest_prints_the_blake3_of_a_file() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipt.json");
    // Longer than one 64 KiB read, so the digest spans several buffer fills.
    let bytes = (0..=u8::MAX).cycle().take(200_000).collect::<Vec<_>>();
    std::fs::write(&path, &bytes)?;
    let args = [
        "digest",
        "--file",
        path.to_str().ok_or("temp path is not UTF-8")?,
    ]
    .map(String::from);
    let mut stdout = Vec::new();
    dispatch(&args, &mut stdout)?;
    assert_eq!(
        String::from_utf8(stdout)?,
        format!("{}\n", blake3::hash(&bytes).to_hex())
    );
    Ok(())
}

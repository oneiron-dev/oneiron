//! Small falsification fixtures; smoke is never accepted as a fleet baseline.
use super::*;

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

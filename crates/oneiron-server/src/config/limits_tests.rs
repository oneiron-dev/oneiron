//! Resolution rows for the `[limits]` section.

use super::*;
use oneiron::origin::smart_http::ScanBounds;

fn resolve(body: &str) -> anyhow::Result<ServeConfig> {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, body).expect("write config");
    let args = ServeArgs {
        config: Some(path),
        ..Default::default()
    };
    resolve_serve_config_with_sources(
        &args,
        EnvConfig::from_pairs(std::iter::empty::<(&str, &str)>())?,
        None,
    )
}

/// The push door's two scan floors default to the engine's own (the blob
/// bound sized from the machine's memory), reach the server as set, and are
/// refused at startup at zero or past what the hook compares exactly.
#[test]
fn the_push_scan_floors_resolve_into_the_server_and_are_bounded() {
    let limits = |config: &ServeConfig| config.sync_server_config().limits;
    let defaults = limits(&resolve("").unwrap());
    assert_eq!(
        defaults.git_scan_blob_bytes,
        ScanBounds::machine_blob_bytes()
    );
    assert_eq!(
        defaults.git_scan_disk_floor_bytes,
        ScanBounds::default_disk_floor_bytes()
    );
    let filed = limits(
        &resolve("[limits]\ngit_scan_blob_bytes = 4096\ngit_scan_disk_floor_bytes = 8192\n")
            .unwrap(),
    );
    assert_eq!(
        filed.scan_bounds().unwrap(),
        ScanBounds::new(4096, 8192).unwrap()
    );
    let past = ScanBounds::MAX_BYTES + 1;
    for body in [
        "[limits]\ngit_scan_blob_bytes = 0\n".to_owned(),
        "[limits]\ngit_scan_disk_floor_bytes = 0\n".to_owned(),
        format!("[limits]\ngit_scan_blob_bytes = {past}\n"),
        format!("[limits]\ngit_scan_disk_floor_bytes = {past}\n"),
    ] {
        let refused = resolve(&body).expect_err(&body).to_string();
        assert!(refused.contains("limits.git_scan_"), "{refused}");
    }
}

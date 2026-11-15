//! [WIRE-TELEMETRY-SET-THRESHOLDS-PUB]: the thresholds manifest has no
//! public owner-less writer. `WireTelemetry::set_thresholds` writes the
//! manifest with no owner proof, so it stays below `pub`: only the tests
//! reach it (the unit tests directly, the integration tests through
//! `oneiron_server::test_doors::wire_thresholds`). Production writes through
//! the owner's `vault.wire_health.thresholds.set` verb
//! (`set_thresholds_as_owner`). A `pub` owner-less thresholds writer fails
//! the pin below, in the style of the OF-060 fitness pins: a visibility
//! defect shows only at the source surface, never at runtime.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test wire_telemetry_set_thresholds_pub`.

use std::path::{Path, PathBuf};

/// The repository root above this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The owner-less thresholds writer's declaration lines in
/// `crates/oneiron-server/src/wire_telemetry.rs`: `(line number, line)`.
fn owner_less_writer_decls(source: &str) -> Vec<(usize, String)> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            line.contains("fn set_thresholds(") && !line.contains("set_thresholds_as_owner")
        })
        .map(|(idx, line)| (idx + 1, line.trim().to_owned()))
        .collect()
}

#[test]
fn set_thresholds_is_not_public() {
    let path = repo_root().join("crates/oneiron-server/src/wire_telemetry.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let writers = owner_less_writer_decls(&source);
    assert!(
        !writers.is_empty(),
        "the owner-less thresholds writer is gone from {}: move this pin to what replaced it",
        path.display()
    );
    for (line_no, line) in &writers {
        assert!(
            line.starts_with("pub(crate)"),
            "wire_telemetry.rs:{line_no}: keep the owner-less writer below `pub`: {line}"
        );
    }
}

#[test]
fn owner_thresholds_write_stays() {
    let path = repo_root().join("crates/oneiron-server/src/wire_telemetry.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        source
            .lines()
            .any(|line| line.trim().starts_with("pub(crate) fn set_thresholds_as_owner(")),
        "the owner's thresholds write ({}) is gone: production keeps its owner-proofed writer",
        path.display()
    );
}

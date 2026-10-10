//! Resolution rows for the `[recall]` section.

use super::*;
use std::time::Duration;

fn resolve(body: &str, env: &[(&str, &str)]) -> anyhow::Result<ServeConfig> {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, body).expect("write config");
    let args = ServeArgs {
        config: Some(path),
        ..Default::default()
    };
    resolve_serve_config_with_sources(&args, EnvConfig::from_pairs(env.iter().copied())?, None)
}

/// Call mode's deadline defaults to the ARCH-0042 #call-mode-budget bar, is
/// set by the file and then the environment, reaches the vault, and is
/// refused outside 1..=60000 at startup.
#[test]
fn the_call_mode_deadline_resolves_into_the_vault_and_is_bounded() {
    let deadline = |config: &ServeConfig| config.vault_config().call_mode_deadline;
    assert_eq!(
        deadline(&resolve("", &[]).unwrap()),
        oneiron::memory::DEFAULT_CALL_MODE_DEADLINE
    );
    let filed = resolve("[recall]\ncall_deadline_ms = 250\n", &[]).unwrap();
    assert_eq!(deadline(&filed), Duration::from_millis(250));
    let overridden = resolve(
        "[recall]\ncall_deadline_ms = 250\n",
        &[("ONEIRON_RECALL_CALL_DEADLINE_MS", "80")],
    )
    .unwrap();
    assert_eq!(deadline(&overridden), Duration::from_millis(80));
    for body in [
        "[recall]\ncall_deadline_ms = 0\n",
        "[recall]\ncall_deadline_ms = 60001\n",
        "[recall]\ncall_deadline = 100\n",
    ] {
        assert!(resolve(body, &[]).is_err(), "{body}");
    }
    assert!(resolve("", &[("ONEIRON_RECALL_CALL_DEADLINE_MS", "soon")]).is_err());
}

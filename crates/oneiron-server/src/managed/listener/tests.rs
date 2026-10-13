use std::sync::Arc;

use oneiron_vault_contract::Credentials;

use super::*;
use crate::logging::tests::CapturedSink;
use crate::managed::WakeLedger;

const SENTINEL: &str = "sentinel-row-text-ab17";

#[tokio::test]
async fn managed_sink_logs_no_ctl_line_text() -> anyhow::Result<()> {
    // Owner ruling 2026-10-14 (fix 6): logs never carry world text. A ctl line
    // that does not parse used to reach the managed log as serde's message,
    // which quotes the offending value.
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(oneiron::Vault::open(
        dir.path(),
        oneiron::VaultConfig::default(),
    )?);
    let server = Arc::new(crate::SyncServer::new(
        vault.clone(),
        crate::config::SyncServerConfig::default(),
    )?);
    let credentials = Credentials {
        dek: [1; 32],
        token: [2; 32],
    };
    let ledger = WakeLedger::load(
        vault,
        "ctl-test".into(),
        dir.path().join("supervisor.sock"),
        &credentials,
    )?;
    let state = ManagedState::new("ctl-test".into(), server, ledger);

    let sink = CapturedSink::default();
    let _default = tracing::dispatcher::set_default(&sink.production_dispatch());
    for line in [
        format!(r#"{{"verb":"{SENTINEL}"}}"#),
        format!(r#"{{"{SENTINEL}":1}}"#),
        format!("{SENTINEL} is not json\n"),
    ] {
        assert!(matches!(
            dispatch_ctl_line(&line, &state).await,
            CtlResponse::Ok { ok: false }
        ));
    }
    let written = sink.text();
    assert!(
        !written.contains(SENTINEL),
        "ctl line text reached the log: {written}"
    );
    assert!(written.contains("ctl_json_invalid"), "{written}");
    Ok(())
}

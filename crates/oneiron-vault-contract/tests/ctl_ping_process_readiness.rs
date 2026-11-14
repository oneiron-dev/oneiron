//! L8-11: every `Ping` carries the vault process's live readiness as an
//! optional `process` block, `{"state":"draining","lag_ms":1600}`, beside the
//! boot snapshot `readiness`. An engine built before the floor sends none, and
//! its `Ping` is still a `Ping`; a block that does not read is unknown, never
//! a failed `Ping`; and a `Ping` that carries `process` is still never taken
//! for `Ok { ok }` (the untagged declaration-order invariant).
//!
//! Run with: `cargo test --locked -p oneiron-vault-contract --test
//! ctl_ping_process_readiness`.

use oneiron_vault_contract::{
    CONTRACT_VERSION, CtlResponse, ManagedReadiness, ProcessReadinessReport, ProcessState,
};

/// A v3 vault's `Ping` with every build-floor field absent but `process`.
fn ping(process: Option<ProcessReadinessReport>) -> CtlResponse {
    CtlResponse::Ping {
        ok: true,
        vault: "v".into(),
        pid: 42,
        contract_version: CONTRACT_VERSION,
        readiness: ManagedReadiness::Ready,
        browser: None,
        managed_backup: None,
        settings_paths_revision: None,
        artifact_internal_host_revision: None,
        preview_origin_revision: None,
        slim_recovery_revision: None,
        vm_outbox_revision: None,
        vm_outbox_companion: None,
        relay_delete_revision: None,
        engine_instance: None,
        deletion: None,
        process,
    }
}

/// The `process` a `Ping` line decodes to; panics when the line is no `Ping`.
fn process_of(line: &str) -> Option<ProcessReadinessReport> {
    match serde_json::from_str::<CtlResponse>(line) {
        Ok(CtlResponse::Ping { process, .. }) => process,
        other => panic!("expected a Ping from {line}, got {other:?}"),
    }
}

#[test]
fn ping_carries_process_readiness_and_reads_an_older_ping_without_it() {
    let draining = ProcessReadinessReport {
        state: ProcessState::Draining,
        lag_ms: 1_600,
    };

    // The engine's Ping names the state and the last lag.
    let line = serde_json::to_string(&ping(Some(draining))).unwrap();
    assert!(
        line.contains(r#""process":{"state":"draining","lag_ms":1600}"#),
        "{line}"
    );
    assert_eq!(process_of(&line), Some(draining), "{line}");

    // Each state's wire spelling round-trips.
    for state in [
        ProcessState::Ready,
        ProcessState::Degraded,
        ProcessState::Recovering,
        ProcessState::Draining,
    ] {
        let report = ProcessReadinessReport { state, lag_ms: 3 };
        let line = serde_json::to_string(&ping(Some(report))).unwrap();
        assert!(
            line.contains(&format!(r#""state":"{}""#, state.as_str())),
            "{line}"
        );
        assert_eq!(process_of(&line), Some(report), "{line}");
    }

    // An engine built before the floor sends no `process`: still a Ping.
    let older = format!(
        r#"{{"ok":true,"vault":"v","pid":42,"contract_version":{CONTRACT_VERSION},"readiness":{{"state":"ready"}},"vm_outbox_companion":null}}"#
    );
    assert_eq!(process_of(&older), None, "{older}");
    let absent = serde_json::to_string(&ping(None)).unwrap();
    assert!(
        !absent.contains("process"),
        "an absent block is not sent: {absent}"
    );

    // A block that does not read is unknown, never a failed Ping.
    for block in [
        "null",
        r#"{"state":"stalled","lag_ms":1}"#,
        r#"{"state":"ready","lag_ms":-1}"#,
        r#"{"state":"ready"}"#,
        r#""draining""#,
    ] {
        let line = format!(
            r#"{{"ok":true,"vault":"v","pid":42,"contract_version":{CONTRACT_VERSION},"readiness":{{"state":"ready"}},"vm_outbox_companion":null,"process":{block}}}"#
        );
        assert_eq!(process_of(&line), None, "{line}");
    }
}

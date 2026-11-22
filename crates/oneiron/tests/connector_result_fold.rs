//! FIX 14541 (ARCH-0067 #fold-by-kind; owner 2026-11-03 20:33, "kinds may also cover old programs
//! and connector results"): `self.fold({kind: "connector_result"})` folds the console of each step
//! in its span that took a connector's reply, and a step that took none keeps its console. The
//! stub keeps the console's read handle and names each connector call that replied, read from the
//! run's record. A `repl_output` fold over the same step keeps the stub that landed first.
//!
//! The run's steps, their `connector.call`s, its kind marks, the idle pass's seal and the
//! rendered console stub go through `oneiron::test_doors::connector_result_fold`, built only
//! under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::connector_result_fold::{
    self as doors, SealedFoldView, SealedStepView, SeededConnectorCall, SeededStep,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A temporary device vault with a process-memory device keystore and its embedded owner, whose
/// id the seals take as their byline.
fn open_vault() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((dir, vault, owner))
}

/// A run of three steps: t0 calls no connector, t1's `github.search_issues` call is delivered
/// with the tool's reply, and t2's call is refused, so no connector's words reach t2.
fn seed_run(vault: &Vault) -> TestResult<EntityId> {
    let run = EntityId::from_bytes([0x93; 16])?;
    let delivered = SeededConnectorCall {
        name: "github",
        tool: "search_issues",
        reply: json!({
            "outcome": "delivered",
            "result": {
                "source": "connector:github.search_issues",
                "foreign": true,
                "content": [{"type": "text", "text": "issue 42: the build is red"}],
                "is_error": false,
            },
        }),
    };
    let refused = SeededConnectorCall {
        name: "github",
        tool: "close_issue",
        reply: json!({"outcome": "refused", "reasons": ["no_grant"]}),
    };
    doors::seed_steps(
        vault,
        run,
        &[
            SeededStep {
                console: b"plain arithmetic: 4",
                calls: Vec::new(),
            },
            SeededStep {
                console: b"issue 42: the build is red",
                calls: vec![delivered],
            },
            SeededStep {
                console: b"close refused",
                calls: vec![refused],
            },
        ],
    )?;
    Ok(run)
}

#[test]
fn connector_result_folds_only_the_step_a_connector_replied_in() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let run = seed_run(&vault)?;
    let fold = doors::mark_kind_fold(&vault, run, "connector_result", (0, 2))?;

    let sealed = doors::seal_kind_folds(&vault, run, owner)?;
    // Only t1 took a connector's reply: its one call, bridge call 0, is named. The refused call
    // of t2 returned no connector words, so t2 keeps its console, as t0 does.
    assert_eq!(
        sealed,
        vec![SealedFoldView {
            fold,
            kind: "connector_result",
            steps: vec![SealedStepView {
                step: 1,
                handles: 1,
                connector_calls: vec![("connector.call".to_owned(), 0)],
            }],
        }]
    );

    let stub = doors::console_stub(&vault, run, 1)?.ok_or("t1 shows no console stub")?;
    assert!(
        stub.starts_with(&format!("⟨f{fold} · connector_result folded⟩")),
        "{stub}"
    );
    assert!(
        stub.contains("\nconnector.call github/search_issues (call 0)"),
        "{stub}"
    );
    assert!(stub.contains("\"sandbox.fs.read_file\""), "{stub}");
    // The folded console's words are not in its stub.
    assert!(!stub.contains("the build is red"), "{stub}");
    assert_eq!(doors::console_stub(&vault, run, 0)?, None);
    assert_eq!(doors::console_stub(&vault, run, 2)?, None);
    Ok(())
}

#[test]
fn a_step_both_console_kinds_fold_keeps_the_first_landed_stub() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let run = seed_run(&vault)?;
    let connector = doors::mark_kind_fold(&vault, run, "connector_result", (0, 2))?;
    doors::seal_kind_folds(&vault, run, owner)?;
    let first = doors::console_stub(&vault, run, 1)?.ok_or("t1 shows no console stub")?;

    // A later repl_output fold over t0–t1 folds t0's console, and t1 keeps the connector_result
    // stub it showed, byte for byte, so the cached log holds.
    let output = doors::mark_kind_fold(&vault, run, "repl_output", (0, 1))?;
    let sealed = doors::seal_kind_folds(&vault, run, owner)?;
    let steps: Vec<u64> = sealed
        .iter()
        .flat_map(|fold| fold.steps.iter().map(|step| step.step))
        .collect();
    assert_eq!(steps, vec![0, 1]);
    assert_eq!(doors::console_stub(&vault, run, 1)?, Some(first.clone()));
    assert!(
        first.starts_with(&format!("⟨f{connector} · connector_result folded⟩")),
        "{first}"
    );
    let plain = doors::console_stub(&vault, run, 0)?.ok_or("t0 shows no console stub")?;
    assert!(
        plain.starts_with(&format!("⟨f{output} · repl_output folded⟩")),
        "{plain}"
    );
    Ok(())
}

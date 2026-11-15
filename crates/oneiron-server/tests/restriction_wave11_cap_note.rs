//! Restriction wave 11, PR 1: the confirm sheet's line for letting an agent
//! pay (RESTRICTION-WAVE-11-CAP-NOTE). Turning on `top_up` or
//! `pay_as_you_go` of `models.quota.agent_may_answer` states the spend cap of
//! the open roots the owner opened, or "no cap" and the provider's account
//! when none is open; the answers that spend nothing state no line.
//!
//! Read through the engine's pub `Vault::setting_loosening_note`, the line the
//! sheet shows. Deterministic: one in-process vault per case.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test restriction_wave11_cap_note`.

use oneiron::agent_dispatch::budget_doors::OpenSpendLeaseRequest;
use oneiron::{EdgeActorClass, Vault, VaultConfig};

/// The quota key under test.
const QUOTA_KEY: &str = "models.quota.agent_may_answer";

/// The line with no open root (RESTRICTION-WAVE-11-CAP-NOTE Q2).
const NO_CAP_LINE: &str = "no cap; the engine does not meter this provider's calls; the payment goes through the provider's account";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config).expect("open vault");
    (dir, vault)
}

/// The owner opens one root spend scope with a hard cap in tokens.
fn open_root(vault: &Vault, launch: &str, cap_units: u64) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    oneiron::verbs::vault_budgets_lease_open(
        &vault.memory(owner, EdgeActorClass::Human),
        OpenSpendLeaseRequest {
            launch: launch.to_owned(),
            cap_units,
            unit: "tokens".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )
    .expect("the owner opens a root");
}

/// The confirm sheet's line for turning on one quota answer.
fn quota_note(vault: &Vault, item: &str) -> Option<String> {
    vault
        .setting_loosening_note(QUOTA_KEY, Some(item))
        .expect("read the confirm sheet's line")
}

/// With no open root: "no cap" and the provider's account, for `top_up` and
/// `pay_as_you_go`; no line for the answers that spend nothing.
#[test]
fn a_payment_answer_states_no_cap_without_an_open_root() {
    let (_dir, vault) = open_vault();
    for item in ["top_up", "pay_as_you_go"] {
        assert_eq!(
            quota_note(&vault, item).as_deref(),
            Some(NO_CAP_LINE),
            "{item}"
        );
    }
    for item in ["wait", "add_account", "use_fallback"] {
        assert_eq!(quota_note(&vault, item), None, "{item}");
    }
}

/// With open roots, the line names the hard cap: one root's amount and unit,
/// then the largest of two and how many are open.
#[test]
fn a_payment_answer_states_the_open_root_cap() {
    let (_dir, vault) = open_vault();
    open_root(&vault, "launch-wave11-a", 5_000);
    for item in ["top_up", "pay_as_you_go"] {
        assert_eq!(
            quota_note(&vault, item).as_deref(),
            Some("spend cap in force: 5000 tokens"),
            "{item}"
        );
    }
    open_root(&vault, "launch-wave11-b", 9_000);
    assert_eq!(
        quota_note(&vault, "top_up").as_deref(),
        Some("spend cap in force: up to 9000 tokens per run, across 2 open runs")
    );
    assert_eq!(quota_note(&vault, "wait"), None);
}

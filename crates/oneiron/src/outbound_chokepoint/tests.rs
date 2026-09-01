//! Recovery-side governance tests (ONE-1885).
//!
//! These drive production [`recovery_governance`] directly: recovery is the
//! second, later reader of the same stamped charter, and a per-grant deny that
//! binds at the gate but not here would simply replay onto the wire.

use super::*;

use crate::config::VaultConfig;
use crate::outbound_intent_ledger::IntentLedgerRecord;
use crate::test_util::entity;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::device()).expect("open vault");
    (tmp, vault)
}

/// Registers an ACTIVE key on the engine-produced per-grant capability
/// connector, exactly as the scoped-MCP fixtures mint it, and returns the
/// stored connector string.
fn register_scoped_key(
    vault: &Vault,
    key_id: &EntityId,
    grant_id: &EntityId,
    server: &str,
) -> String {
    let connector = gate::scoped_mcp_credential_connector_key(server, grant_id);
    register_key(vault, key_id, &connector);
    connector
}

fn register_key(vault: &Vault, key_id: &EntityId, connector: &str) {
    vault
        .register_connector_key(
            key_id,
            crate::connector_key::ConnectorKeyRecord::active(connector, None, Vec::new(), 10),
        )
        .expect("register active connector key");
}

fn stamp_charter(vault: &Vault, key_id: &EntityId, text: &str) {
    let pending = vault
        .propose_connector_charter(key_id, text, 1_001)
        .expect("propose charter");
    vault
        .approve_connector_charter(key_id, pending.compiled_hash, "owner", 1_002)
        .expect("approve charter");
}

/// A durable Pending row whose budget marker names the key this intent was
/// charged against — the only connector identity recovery ever holds.
fn charged_record(key_id: EntityId, tool: &str) -> IntentLedgerRecord {
    IntentLedgerRecord::pending(
        OutboundCallRequest::new(
            AttemptId::from_bytes(&[0x5A; 16]).expect("attempt id"),
            1,
            "files",
            tool,
            b"recovery payload".to_vec(),
            10,
        ),
        true,
        BudgetChargeMarker {
            key_ref: Some(key_id),
            budget_class: BudgetClass::Operation,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 10,
        },
    )
    .expect("pending ledger record")
}

#[test]
fn recovery_blocks_the_exact_per_grant_capability_key() {
    let (_tmp, vault) = temp_vault();
    let denied_key = entity(0xD1);
    let neighbour_key = entity(0xD2);
    let denied_connector = register_scoped_key(&vault, &denied_key, &entity(0x8A), "files");
    register_scoped_key(&vault, &neighbour_key, &entity(0x8B), "files");
    let text = format!("never key {denied_connector}");
    stamp_charter(&vault, &denied_key, &text);
    // The neighbour grant carries the SAME stamped prohibition text, naming the
    // other grant's key.
    stamp_charter(&vault, &neighbour_key, &text);

    assert!(matches!(
        recovery_governance(&vault, &charged_record(denied_key, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    // Discriminating: a prefix or per-segment reading of the opaque remainder,
    // or dropping the capability identity, would block this neighbour grant too.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(neighbour_key, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));
}

#[test]
fn recovery_re_scopes_tool_entries_only_for_capability_keys() {
    let (_tmp, vault) = temp_vault();
    let capability_key = entity(0xD3);
    let capability_connector = register_scoped_key(&vault, &capability_key, &entity(0x8C), "files");
    assert!(gate::is_scoped_capability_connector_key(&capability_connector));
    stamp_charter(&vault, &capability_key, "never key mcp:read_file");
    // Effective-channel re-scoping: the key's first segment is `mcp`, so a
    // two-part `mcp:{tool}` entry denies that tool on this grant.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(capability_key, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    assert!(matches!(
        recovery_governance(&vault, &charged_record(capability_key, "write_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));

    // An ordinary colon-bearing channel key is NOT a capability key: it keeps
    // full-channel matching, where `mcp:read_file`'s channel is `mcp` and never
    // equals `mcp:calendar:grant:foo`.
    let channel_key = entity(0xD4);
    let ordinary_connector = "mcp:calendar:grant:foo";
    assert!(!gate::is_scoped_capability_connector_key(ordinary_connector));
    register_key(&vault, &channel_key, ordinary_connector);
    stamp_charter(&vault, &channel_key, "never key mcp:read_file");
    assert!(matches!(
        recovery_governance(&vault, &charged_record(channel_key, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));

    // The landed wildcard form still binds every channel, capability or not.
    let wildcard_key = entity(0xD5);
    register_key(&vault, &wildcard_key, "mcp:agenda");
    stamp_charter(&vault, &wildcard_key, "never read_file");
    assert!(matches!(
        recovery_governance(&vault, &charged_record(wildcard_key, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
}

#[test]
fn recovery_leaves_uncharted_and_unregistered_keys_unchanged() {
    let (_tmp, vault) = temp_vault();
    let key_id = entity(0xD6);
    register_scoped_key(&vault, &key_id, &entity(0x8D), "files");
    // A key with no stamped charter is an empty floor: recovery allows.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(key_id, "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));
    // An unregistered charged key still fails closed, and a row that was never
    // charged against a key is out of the connector-key stage entirely.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(entity(0xD8), "read_file"))
            .expect("recovery governance"),
        RecoveryGovernance::Block("connector_key_unregistered")
    ));
    let mut uncharged = charged_record(key_id, "read_file");
    uncharged.budget_accounting.key_ref = None;
    assert!(matches!(
        recovery_governance(&vault, &uncharged).expect("recovery governance"),
        RecoveryGovernance::Allow
    ));
}

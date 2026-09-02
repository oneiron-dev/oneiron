//! Recovery-side governance tests (ONE-1885).
//!
//! These drive production [`recovery_governance`] directly: recovery is the
//! second, later reader of the same stamped charter, and a per-grant deny that
//! binds at the gate but not here would simply replay onto the wire. Recovery
//! reads the row's DURABLE TYPED provenance, never its connector text, so an
//! ordinary connector that spells a capability key keeps its own outcome.

use super::*;

use crate::config::VaultConfig;
use crate::connector_key::ScopedCapabilityProvenance;
use crate::outbound_intent_ledger::{IntentLedgerRecord, OutboundAuthorizationBinding};
use crate::test_util::entity;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::device()).expect("open vault");
    (tmp, vault)
}

/// The ONE way a test may obtain a capability identity: the engine producer.
fn capability(server: &str, grant_id: &EntityId) -> ScopedCapabilityProvenance {
    ScopedCapabilityProvenance::mint(server, grant_id).expect("safe canonical scoped server")
}

/// Registers an ACTIVE key on the engine-produced per-grant capability
/// connector, exactly as the scoped-MCP fixtures mint it.
fn register_scoped_key(
    vault: &Vault,
    key_id: &EntityId,
    grant_id: &EntityId,
    server: &str,
) -> ScopedCapabilityProvenance {
    let capability = capability(server, grant_id);
    register_key(vault, key_id, capability.connector());
    capability
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
/// charged against. `capability` is the typed provenance the scoped admission
/// path minted; an ordinary connector row carries `None` and can never acquire
/// one from its text.
fn charged_record(
    key_id: EntityId,
    tool: &str,
    capability: Option<ScopedCapabilityProvenance>,
) -> IntentLedgerRecord {
    // A capability row's typed provenance must name the row's OWN call server,
    // exactly as durable validation requires, so these fixtures stay rows this
    // engine could actually have written (ONE-1885).
    let server = capability
        .as_ref()
        .map_or_else(|| "files".to_owned(), |value| value.server().to_owned());
    let mut request = recovery_request(&server, tool);
    if let Some(capability) = capability {
        // Capability rows are minted only on the scoped path, which always
        // binds the authorization in the same admission step.
        request = request
            .with_authorization_binding(OutboundAuthorizationBinding::new([0xB1; 32]))
            .with_resolved_endpoint("https://files.example.test/mcp")
            .with_capability_provenance(capability);
    }
    IntentLedgerRecord::pending(request, true, charged_marker(key_id))
        .expect("pending ledger record")
}

/// The reconstructed v3 shape a recovery seam must never downgrade: endpoint-
/// and binding-bound — so only scoped authorization could have written it —
/// while the typed discriminator is absent.
fn endpoint_bound_record_without_provenance(key_id: EntityId, tool: &str) -> IntentLedgerRecord {
    IntentLedgerRecord::pending(
        recovery_request("files", tool)
            .with_authorization_binding(OutboundAuthorizationBinding::new([0xB1; 32]))
            .with_resolved_endpoint("https://files.example.test/mcp"),
        true,
        charged_marker(key_id),
    )
    .expect("pending ledger record")
}

/// The frozen call identity every recovery fixture shares.
fn recovery_request(server: &str, tool: &str) -> OutboundCallRequest {
    OutboundCallRequest::new(
        AttemptId::from_bytes(&[0x5A; 16]).expect("attempt id"),
        1,
        server,
        tool,
        b"recovery payload".to_vec(),
        10,
    )
}

fn charged_marker(key_id: EntityId) -> BudgetChargeMarker {
    BudgetChargeMarker {
        key_ref: Some(key_id),
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: 10,
    }
}

#[derive(Default)]
struct CountingTransport {
    sends: usize,
}

impl OutboundTransport for CountingTransport {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        OutboundSendOutcome::Acked
    }
}

#[test]
fn recovery_rejects_reconstructed_capability_without_endpoint_before_transport() {
    let (_tmp, vault) = temp_vault();
    let key_id = entity(0xDB);
    let capability = register_scoped_key(&vault, &key_id, &entity(0x90), "files");
    let persisted = charged_record(key_id, "read_file", Some(capability));

    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    insert_pending_in_txn(&vault, &mut wtxn, &persisted).expect("persist valid capability row");
    wtxn.commit().expect("commit valid capability row");
    force_sync(&vault).expect("sync valid capability row");

    // Simulate a reconstructed in-memory v3 row whose capability provenance
    // and binding look valid but whose endpoint is absent. The persisted copy
    // remains valid so the recovery seam can abandon it durably on rejection.
    let mut reconstructed = persisted;
    reconstructed.resolved_endpoint = None;
    let authority = OutboundBindingAuthority::from_secret([0xAC; 32]);
    let mut transport = CountingTransport::default();
    let result = send_pending(
        &vault,
        &authority,
        reconstructed,
        11,
        true,
        &mut transport,
    )
    .expect("recovery must fail closed");

    assert_eq!(transport.sends, 0, "missing endpoint must not reach transport");
    assert_eq!(result.dispatch.send_outcome, None);
    assert_eq!(result.dispatch.state, Some(IntentState::Abandoned));
    assert!(matches!(
        result.dispatch.escalation,
        Some(IntentEscalation {
            reason: IntentEscalationReason::BindingInvalid,
            ..
        })
    ));
}

#[test]
fn recovery_rejects_reconstructed_endpoint_row_without_provenance_before_transport() {
    let (_tmp, vault) = temp_vault();
    let key_id = entity(0xDC);
    let capability = register_scoped_key(&vault, &key_id, &entity(0x94), "files");
    let persisted = charged_record(key_id, "read_file", Some(capability));

    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    insert_pending_in_txn(&vault, &mut wtxn, &persisted).expect("persist valid capability row");
    wtxn.commit().expect("commit valid capability row");
    force_sync(&vault).expect("sync valid capability row");

    // The SAME durable identity, reconstructed without its typed discriminator.
    // The endpoint and binding survive, so an ordinary reading of this row would
    // send it; an endpoint-bound row is a scoped row and must fail closed.
    let reconstructed = endpoint_bound_record_without_provenance(key_id, "read_file");
    assert_eq!(
        reconstructed.id, persisted.id,
        "the reconstructed row must keep the persisted identity"
    );
    let authority = OutboundBindingAuthority::from_secret([0xAC; 32]);
    let mut transport = CountingTransport::default();
    let result = send_pending(&vault, &authority, reconstructed, 11, true, &mut transport)
        .expect("recovery must fail closed");

    assert_eq!(
        transport.sends, 0,
        "an untyped endpoint-bound row must not reach transport"
    );
    assert_eq!(result.dispatch.send_outcome, None);
    assert_eq!(result.dispatch.state, Some(IntentState::Abandoned));
    assert!(matches!(
        result.dispatch.escalation,
        Some(IntentEscalation {
            reason: IntentEscalationReason::BindingInvalid,
            ..
        })
    ));
}

#[test]
fn recovery_keeps_typed_scoped_channel_spellings_distinct() {
    let (_tmp, vault) = temp_vault();
    let hyphen_key = entity(0xC5);
    let hyphen = register_scoped_key(&vault, &hyphen_key, &entity(0x91), "foo-bar");
    let underscore_key = entity(0xC6);
    let underscore = register_scoped_key(&vault, &underscore_key, &entity(0x92), "foo_bar");
    // ONE stamped text on BOTH keys, naming the hyphenated server with the
    // wildcard ordinary verb.
    for key_id in [hyphen_key, underscore_key] {
        stamp_charter(&vault, &key_id, "never * on mcp:foo-bar");
    }
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(hyphen_key, "read_file", Some(hyphen)),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    // Discriminating: `_` is a DIFFERENT server identity. Ordinary connector
    // normalization would alias the two spellings, so recovery must read the
    // exact scoped channel — the same rule the gate applied at admission.
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(underscore_key, "read_file", Some(underscore)),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));

    // The whole-fleet wildcard channel names no spelling at all, so it cannot
    // alias anything and keeps reaching a typed capability dispatch here too.
    let fleet_key = entity(0xC7);
    let fleet = register_scoped_key(&vault, &fleet_key, &entity(0x93), "foo-bar");
    stamp_charter(&vault, &fleet_key, "never read_file");
    assert!(matches!(
        recovery_governance(&vault, &charged_record(fleet_key, "read_file", Some(fleet)))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
}

#[test]
fn recovery_blocks_the_exact_per_grant_capability_key() {
    let (_tmp, vault) = temp_vault();
    let denied_key = entity(0xD1);
    let neighbour_key = entity(0xD2);
    let denied = register_scoped_key(&vault, &denied_key, &entity(0x8A), "files");
    let neighbour = register_scoped_key(&vault, &neighbour_key, &entity(0x8B), "files");
    let text = format!("never key {}", denied.connector());
    stamp_charter(&vault, &denied_key, &text);
    // The neighbour grant carries the SAME stamped prohibition text, naming the
    // other grant's key.
    stamp_charter(&vault, &neighbour_key, &text);

    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(denied_key, "read_file", Some(denied)),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    // Discriminating: a prefix, per-segment, or server-wide reading of the
    // capability key would block this neighbour grant too.
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(neighbour_key, "read_file", Some(neighbour)),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));
}

#[test]
fn recovery_reads_typed_provenance_never_connector_text() {
    let (_tmp, vault) = temp_vault();
    let real_grant = entity(0x8C);
    let real_key = entity(0xD3);
    let real = register_scoped_key(&vault, &real_key, &real_grant, "files");

    // An ORDINARY connector key registered under the EXACT spelling the engine
    // producer mints for a real grant. Only its typed construction — none at
    // all — distinguishes it; no heuristic examines its text.
    let lookalike_key = entity(0xD4);
    let lookalike_connector = capability("files", &entity(0x8D)).connector().to_owned();
    register_key(&vault, &lookalike_key, &lookalike_connector);
    // Two more ordinary colon-bearing connectors, including the grant-shaped one.
    let calendar_key = entity(0xD5);
    register_key(&vault, &calendar_key, "mcp:calendar");
    let calendar_grant_key = entity(0xD6);
    register_key(&vault, &calendar_grant_key, "mcp:calendar:grant:foo");

    // One charter text naming BOTH capability identities, stamped on every key.
    let text = format!(
        "never key {}\nnever key {lookalike_connector}",
        real.connector()
    );
    for key_id in [real_key, lookalike_key, calendar_key, calendar_grant_key] {
        stamp_charter(&vault, &key_id, &text);
    }

    // The real typed capability is denied by its exact `never key`.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(real_key, "read_file", Some(real)))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    // Every ordinary row stays ordinary: no capability provenance, so the
    // capability-only rules cannot reach it and there is no replay divergence.
    for key_id in [lookalike_key, calendar_key, calendar_grant_key] {
        assert!(
            matches!(
                recovery_governance(&vault, &charged_record(key_id, "read_file", None))
                    .expect("recovery governance"),
                RecoveryGovernance::Allow
            ),
            "ordinary connector {key_id:?} must not be denied by a capability rule"
        );
    }
}

#[test]
fn recovery_matches_ordinary_never_channel_rules_whole() {
    let (_tmp, vault) = temp_vault();
    // `never <verb> on <channel>` names the COMPLETE ordinary connector string,
    // colons included.
    let exact_key = entity(0xC1);
    register_key(&vault, &exact_key, "mcp:calendar:grant:foo");
    stamp_charter(
        &vault,
        &exact_key,
        "never read_file on mcp:calendar:grant:foo",
    );
    assert!(matches!(
        recovery_governance(&vault, &charged_record(exact_key, "read_file", None))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));

    // A DIFFERENT whole connector does not match — a first-colon or prefix
    // reading of the same rule would block this one.
    let other_key = entity(0xC2);
    register_key(&vault, &other_key, "mcp:calendar");
    stamp_charter(
        &vault,
        &other_key,
        "never read_file on mcp:calendar:grant:foo",
    );
    assert!(matches!(
        recovery_governance(&vault, &charged_record(other_key, "read_file", None))
            .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));

    // The landed wildcard form still binds every ordinary channel. (That it
    // also still reaches a typed capability dispatch is proven in
    // `recovery_keeps_typed_scoped_channel_spellings_distinct`.)
    let wildcard_key = entity(0xC3);
    register_key(&vault, &wildcard_key, "mcp:agenda");
    stamp_charter(&vault, &wildcard_key, "never read_file");
    assert!(matches!(
        recovery_governance(&vault, &charged_record(wildcard_key, "read_file", None))
            .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
    let scoped_key = entity(0xC4);
    let scoped = register_scoped_key(&vault, &scoped_key, &entity(0x8E), "files");
    stamp_charter(&vault, &scoped_key, "never read_file on mcp:files");
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(scoped_key, "read_file", Some(scoped))
        )
        .expect("recovery governance"),
        RecoveryGovernance::Block("charter_never_list")
    ));
}

#[test]
fn recovery_leaves_uncharted_and_unregistered_keys_unchanged() {
    let (_tmp, vault) = temp_vault();
    let key_id = entity(0xDA);
    let scoped = register_scoped_key(&vault, &key_id, &entity(0x8F), "files");
    // A key with no stamped charter is an empty floor: recovery allows.
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(key_id, "read_file", Some(scoped.clone())),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Allow
    ));
    // An unregistered charged key still fails closed, and a row that was never
    // charged against a key is out of the connector-key stage entirely.
    assert!(matches!(
        recovery_governance(&vault, &charged_record(entity(0xD8), "read_file", None))
            .expect("recovery governance"),
        RecoveryGovernance::Block("connector_key_unregistered")
    ));
    let mut uncharged = charged_record(key_id, "read_file", None);
    uncharged.budget_accounting.key_ref = None;
    assert!(matches!(
        recovery_governance(&vault, &uncharged).expect("recovery governance"),
        RecoveryGovernance::Allow
    ));

    // A typed provenance that does NOT describe the charged key fails closed
    // rather than continuing as an ordinary connector.
    let ordinary_key = entity(0xD9);
    register_key(&vault, &ordinary_key, "mcp:calendar");
    stamp_charter(&vault, &ordinary_key, "never read_file on mcp:calendar");
    assert!(matches!(
        recovery_governance(
            &vault,
            &charged_record(ordinary_key, "read_file", Some(scoped)),
        )
        .expect("recovery governance"),
        RecoveryGovernance::Block("connector_key_unregistered")
    ));
}

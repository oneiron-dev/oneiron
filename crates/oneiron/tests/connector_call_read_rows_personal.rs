//! A connector call from a code run that was served vault rows freezes at least Personal
//! (FIX CONNECTOR-CALL-VAULT-TEXT-UNCLASSED, the Personal half of FIX 8807).
//!
//! Ledger: `run_was_served_person_rows` is true for a run whose ledger notes a served TURN,
//! false for a run whose ledger notes only an access grant row, false for a run with no
//! ledger, true for a run whose header carries an unknown cause.
//!
//! Class: under a standing grant with `data_class_ceiling` Public on a tool whose slate
//! class is Public, a code-run call from a run served person rows holds (no send) while
//! the same call from a run served nothing delivers (one send).
//!
//! Fixture: `restored_unjoined_code_consent_waits.rs` for code-site `Memory`
//! (`test_doors::restored_code_consent_waits::code_consent_memory`) plus the
//! register/stamp/attest/consent shape of `connector_protocol_narrow_keeps_stamp.rs`,
//! with a Public slate and a Public ceiling so the clean call auto-fires.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test connector_call_read_rows_personal`
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::AccessGrant;
use oneiron::booking::DisclosureRung;
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCallRoute, ConnectorCatalogEntry, ConnectorConsentTarget,
    ConnectorKeySpec, ConnectorKeyStatus, ConnectorToolConsent, ConnectorToolConsentRow,
    SlateDataClass, SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::tool_scope::DataClass;
use oneiron::outbound_consent::tool_call::MutationIntent;
use oneiron::outbound_consent::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
    OutboundResultSender, OutboundTransportResult, RawOutboundResult, UntrustedToolResult,
};
use oneiron::outbound_intent_ledger::{FrozenOutboundCall, OutboundSendOutcome};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::connector_call_read_rows::{
    mark_read_world_unknown_for_test, note_read_rows_for_test, run_was_served_person_rows,
};
use oneiron::test_doors::restored_code_consent_waits::code_consent_memory;
use oneiron::{AttemptId, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 1_700_000_000;
const SERVER: &str = "read_rows_personal";
const TOOL: &str = "read";
const REVISION: &str = "2026-09-01";
const ENDPOINT: &str = "https://connector.invalid/mcp";

/// The scripted connector host: it installs one endpoint, counts sends, acks
/// at once and keeps no reply.
struct PersonalHost {
    calls: usize,
}

impl OutboundResultSender for PersonalHost {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.calls += 1;
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

impl ConnectorCallHost for PersonalHost {
    fn tool_endpoint(&self, _route: &ConnectorCallRoute) -> Option<String> {
        Some(ENDPOINT.to_owned())
    }

    fn take_result(&mut self) -> Option<UntrustedToolResult> {
        None
    }
}

/// A vault with its owner, one catalog connector whose tool is Public, and
/// one standing grant for the owner with a Public ceiling.
struct PersonalFixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn personal_fixture() -> PersonalFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory holds");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault opens");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("install signing prepares");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner exists");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof authenticates");
    let manifest = [SlateToolManifest {
        name: TOOL.to_owned(),
        data_class: SlateDataClass::Public,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(json!({"type": "object"})),
        resolved_output_schema: None,
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: true,
        idempotent: true,
        price: None,
        http: None,
    }];
    let draft =
        serde_json::to_string(&draft_connector_slate(&manifest)).expect("slate draft encodes");
    let slate = vault
        .store_connector_slate(&manifest, &draft)
        .expect("connector slate stores");
    let mut spec = ConnectorKeySpec::new(SERVER);
    spec.slate_ref = Some(slate);
    spec.protocol_revision = Some(REVISION.to_owned());
    let (catalog, pending) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: SERVER.to_owned(),
                connector: SERVER.to_owned(),
                summary: "read-rows personal fixture".to_owned(),
                verbs: vec![TOOL.to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: NOW,
            },
            spec,
            NOW,
        )
        .expect("catalog connector registers");
    assert_eq!(
        pending.status,
        ConnectorKeyStatus::Pending,
        "a catalog registration starts pending"
    );
    let stored = vault
        .connector_slate(slate)
        .expect("slate reads")
        .expect("stored slate exists");
    vault
        .stamp_connector_slate(&proof, slate, stored.revision(), &BTreeMap::new(), None)
        .expect("owner stamps the slate");
    let active = vault
        .attest_connector_key(&proof, &catalog, REVISION, NOW + 1)
        .expect("owner attests the key");
    assert_eq!(
        active.status,
        ConnectorKeyStatus::Active,
        "attested key is active"
    );
    let granted = vault
        .consent_connector_tools(
            &proof,
            &ConnectorToolConsent {
                connector: SERVER.to_owned(),
                target: ConnectorConsentTarget::Owner,
                endpoint: ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: TOOL.to_owned(),
                    data_class_ceiling: DataClass::Public,
                    headers: false,
                }],
            },
        )
        .expect("owner consents the tool");
    assert_eq!(granted.len(), 1, "one grant for one tool");
    PersonalFixture {
        vault,
        owner,
        _dir: dir,
    }
}

/// A minimal vault for ledger-only cases: no connector, just rows and a ledger.
fn ledger_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory holds");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault opens");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    (dir, vault)
}

/// One TURN row, the person-words probe the ledger test seeds.
fn put_turn(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"what was said",
        )
        .expect("turn row stores");
    id
}

/// One access-grant row, the non-person probe the ledger test seeds.
fn put_grant(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .create_access_grant(
            &id,
            &AccessGrant::calendar_disclosure(
                EntityId::now(),
                EntityId::now(),
                DisclosureRung::Busy,
                1,
            ),
        )
        .expect("access grant stores");
    id
}

#[test]
fn ledger_notes_person_turn_true() {
    let (_dir, vault) = ledger_vault();
    let turn = put_turn(&vault);
    let run = EntityId::now();
    note_read_rows_for_test(&vault, run, &[turn]).expect("ledger notes the turn");
    assert!(
        run_was_served_person_rows(&vault, run).expect("ledger reads"),
        "a run whose ledger notes a served TURN was served person rows"
    );
}

#[test]
fn ledger_notes_grant_only_false() {
    let (_dir, vault) = ledger_vault();
    let grant = put_grant(&vault);
    let run = EntityId::now();
    note_read_rows_for_test(&vault, run, &[grant]).expect("ledger notes the grant");
    assert!(
        !run_was_served_person_rows(&vault, run).expect("ledger reads"),
        "a run whose ledger notes only a grant row was served no person rows"
    );
}

#[test]
fn ledger_missing_is_false() {
    let (_dir, vault) = ledger_vault();
    let run = EntityId::now();
    assert!(
        !run_was_served_person_rows(&vault, run).expect("ledger reads"),
        "a run with no ledger was served no person rows"
    );
}

#[test]
fn ledger_unknown_is_true() {
    let (_dir, vault) = ledger_vault();
    let run = EntityId::now();
    mark_read_world_unknown_for_test(&vault, run).expect("ledger marks unknown");
    assert!(
        run_was_served_person_rows(&vault, run).expect("ledger reads"),
        "a run whose header carries an unknown cause was served person rows"
    );
}

/// One code-run call through the public door on a code-site `Memory`.
fn code_call(
    vault: &Vault,
    actor: EntityId,
    run: EntityId,
    host: &mut PersonalHost,
) -> ConnectorCallOutcome {
    let memory = code_consent_memory(vault, actor, run, EntityId::now(), None)
        .expect("code consent site binds");
    // The actor the door names is the owner the fixture consented for.
    assert_eq!(
        memory.actor(),
        actor,
        "the code-site memory is bound to the consented actor"
    );
    vault
        .call_connector(
            &memory,
            ConnectorCallRequest {
                name: SERVER.to_owned(),
                source: None,
                tool: TOOL.to_owned(),
                arguments: json!({}),
                mutation: MutationIntent::default(),
            },
            Some(ConnectorCallInvocation {
                attempt_id: AttemptId::now(),
                call_seq: 0,
            }),
            host,
        )
        .expect("connector call drives")
}

#[test]
fn code_run_without_person_rows_auto_fires() {
    let fixture = personal_fixture();
    let run = EntityId::now();
    let mut host = PersonalHost { calls: 0 };
    let outcome = code_call(&fixture.vault, fixture.owner, run, &mut host);
    assert!(
        matches!(outcome, ConnectorCallOutcome::Delivered { .. }),
        "a code run served no counted row auto-fires under a Public ceiling, got {outcome:?}"
    );
    assert_eq!(host.calls, 1, "the auto-fired call sends once");
}

#[test]
fn code_run_with_person_rows_holds() {
    let fixture = personal_fixture();
    let turn = put_turn(&fixture.vault);
    let run = EntityId::now();
    note_read_rows_for_test(&fixture.vault, run, &[turn]).expect("ledger notes the turn");
    assert!(
        run_was_served_person_rows(&fixture.vault, run).expect("ledger reads"),
        "the seeded run was served person rows before the call"
    );
    let mut host = PersonalHost { calls: 0 };
    let outcome = code_call(&fixture.vault, fixture.owner, run, &mut host);
    match outcome {
        ConnectorCallOutcome::Held { reasons, .. } => {
            assert!(
                reasons.iter().any(|reason| {
                    reason == "data_class_ceiling_exceeded"
                        || reason == "gate.pending.consent.bound_exceeded"
                }),
                "a code run served person rows holds for its ceiling under a Public grant, got {reasons:?}"
            );
        }
        other => {
            panic!("a code run served person rows holds instead of auto-firing, got {other:?}")
        }
    }
    assert_eq!(host.calls, 0, "the held call sends nothing");
}

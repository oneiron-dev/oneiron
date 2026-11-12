//! Named-server grants are part of a generic AGENT_DEF writer's usable slice.
//!
//! Each author is a PERSON with no AGENT_DEF, holding only Base authority
//! and, in the positive cases, an owner-consented ScopedMcp grant. The same
//! admitted catalog without tool consent is the control for both reference
//! forms. Registration, owner attestation and dispatch admission stay local;
//! no connector tool or outbound network request is executed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, McpRef, encode_agent_definition,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::authority::{ActSurface, AgentTier};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, base_world_id};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget, ConnectorKeySpec,
    ConnectorKeyStatus, ConnectorToolConsent, ConnectorToolConsentRow, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::tool_scope::DataClass;
use oneiron::federation::{Scope, ScopeId};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::AgentGrantMintRequest;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;
const SERVER: &str = "conformance_allowed";
const PROTOCOL_REVISION: &str = "2026-09-01";
const ENDPOINT: &str = "https://connector.invalid/mcp";

fn definition(
    name: &str,
    scope: AgentScope,
    ceiling: AgentCeiling,
    source: ClaimSource,
    generated: bool,
    human_authored: bool,
) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "generic writer conformance fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        source,
        1.0,
        generated,
        human_authored,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => Value::Bool(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("an integer fits i64 or u64"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => Value::String(text.as_str().expect("UTF-8").to_owned()),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum Slice {
    Within,
}

fn candidate(slice: Slice) -> AgentDefinition {
    let (scope, ceiling) = match slice {
        Slice::Within => (AgentScope::Base, AgentCeiling::Proposed),
    };
    definition(
        "conformance.candidate",
        scope,
        ceiling,
        ClaimSource::Generated,
        true,
        false,
    )
}

struct Fixture {
    vault: Vault,
    owner_person: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        vault,
        owner_person,
        _dir: dir,
    }
}

fn named_agent(fixture: &Fixture, name: &str) -> EntityId {
    let writer = fixture
        .vault
        .ensure_agent_principal(name)
        .expect("named agent principal");
    // A PERSON row is no AGENT_DEF: `get_agent_definition` refuses a
    // non-AGENT_DEF row rather than answering `None`, so the type is the check.
    assert_eq!(
        fixture.vault.get_entity_type(&writer).expect("entity type"),
        Some(ENTITY_TYPE_PERSON),
        "a named agent's principal holds no definition"
    );
    writer
}

fn grant_base_reach(fixture: &Fixture, writer: EntityId) {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = oneiron::verbs::mint_agent_grant_as(
        &fixture.vault,
        &owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: writer,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reality");
    assert!(minted.grant.confers, "the grant confers");
}

/// The public admission chain, without granting the author any tool yet.
fn register_server(fixture: &Fixture) {
    let vault = &fixture.vault;
    let manifest = vec![SlateToolManifest {
        name: "read".to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(json!({"type": "object"})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: true,
        idempotent: true,
        price: None,
    }];
    let draft = draft_connector_slate(&manifest);
    let slate_id = vault
        .store_connector_slate(
            &manifest,
            &serde_json::to_string(&draft).expect("typed slate draft"),
        )
        .expect("store the connector slate");
    let mut spec = ConnectorKeySpec::new(SERVER);
    spec.slate_ref = Some(slate_id);
    spec.protocol_revision = Some(PROTOCOL_REVISION.to_owned());
    let (catalog_id, pending) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: SERVER.to_owned(),
                connector: SERVER.to_owned(),
                summary: "named-server grant conformance fixture".to_owned(),
                verbs: vec!["read".to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: NOW,
            },
            spec,
            NOW,
        )
        .expect("register the pending catalog connector");
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    let owner = vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let slate = vault
        .connector_slate(slate_id)
        .expect("read the slate")
        .expect("stored slate");
    vault
        .stamp_connector_slate(&owner, slate_id, slate.revision(), &BTreeMap::new(), None)
        .expect("owner stamps the real slate revision");
    let active = vault
        .attest_connector_key(&owner, &catalog_id, PROTOCOL_REVISION, NOW + 1)
        .expect("owner attests without network probes");
    assert_eq!(active.status, ConnectorKeyStatus::Active);
}

/// Mint and read back the exact server grant the definition writer checks.
fn consent_server(fixture: &Fixture, writer: EntityId) {
    let vault = &fixture.vault;
    let owner = vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let granted = vault
        .consent_connector_tools(
            &owner,
            &ConnectorToolConsent {
                connector: SERVER.to_owned(),
                target: ConnectorConsentTarget::Actor(writer),
                endpoint: ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: "read".to_owned(),
                    data_class_ceiling: DataClass::Personal,
                    headers: false,
                }],
            },
        )
        .expect("owner consents the read tool for the author PERSON");
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].tool, "read");
    let grant_id = EntityId::from_hex(&granted[0].grant_id).expect("returned grant id");
    let grant = vault
        .get_standing_outbound_grant(&grant_id)
        .expect("read the outbound grant")
        .expect("the minted grant exists");
    assert_eq!(grant.principal_ref, writer.to_hex());
    assert!(grant.is_active(), "the author's grant is active");
    let scope = grant.scope.scoped_mcp_grant().expect("a ScopedMcp grant");
    assert_eq!(scope.server, SERVER);
    assert_eq!(scope.tool, "read");
    assert_eq!(scope.data_class_ceiling, DataClass::Personal);
    let view = vault
        .connector_consent_view(&owner, SERVER, Some(writer))
        .expect("read the author's live consent")
        .expect("the catalog exists");
    assert!(view.ready);
    assert_eq!(view.actor, writer.to_hex());
    assert_eq!(view.rows.len(), 1);
    assert_eq!(view.rows[0].tool, "read");
    // This public view includes a grant only while active under current policy.
    assert_eq!(
        view.rows[0].grant_id.as_deref(),
        Some(granted[0].grant_id.as_str())
    );
    println!(
        "CONFORMANCE case=named-server-consent writer={} server={SERVER} grant={} live=true",
        writer.to_hex(),
        granted[0].grant_id
    );
}

/// The Batch arm of the generic-writer fixture, on the author's Agent Memory.
fn put(
    vault: &Vault,
    writer: EntityId,
    id: EntityId,
    def: &AgentDefinition,
    at: u64,
) -> Result<(), String> {
    let memory = vault.memory(writer, EdgeActorClass::Agent);
    let bytes = encode_agent_definition(def).expect("valid definition");
    let input = json!({"entities": [{
        "id": id.to_hex(),
        "entity_type": ENTITY_TYPE_AGENT_DEF,
        "occurred_start": at,
        "occurred_end": at,
        "learned_at": at,
        "body": json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack")),
    }]});
    let verb = "vault.batch";
    assert!(
        oneiron::task_verb::sdk::code_mode_verb_names().any(|name| name == verb),
        "{verb} is a code-mode row"
    );
    oneiron::task_verb::sdk::invoke(&memory, verb, input)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lands {
    Proposal,
    Active,
}

fn dispatch_of(vault: &Vault, id: EntityId) -> String {
    match AgentDispatcher::new(vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: NOW + 9,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

fn write_label_of(write: &Result<(), String>) -> String {
    match write {
        Ok(()) => "landed".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

fn standing_of(def: Option<&AgentDefinition>) -> String {
    def.map_or_else(
        || "absent".to_owned(),
        |def| {
            format!(
                "version={} approval={:?} lifecycle={:?} enabled={} scope={:?} ceiling={:?} source={:?}",
                def.version,
                def.approval_status,
                def.lifecycle_status,
                def.enabled,
                def.scope,
                def.ceiling,
                def.source
            )
        },
    )
}

fn assert_lands(case: &str, write: &Result<(), String>, vault: &Vault, id: EntityId, lands: Lands) {
    let stored = vault.get_agent_definition(&id).expect("read the row");
    let dispatch = dispatch_of(vault, id);
    let write_label = write_label_of(write);
    let standing = standing_of(stored.as_ref());
    println!("CONFORMANCE case={case} write={write_label} stored=[{standing}] dispatch={dispatch}");
    assert!(
        write.is_ok(),
        "ARCH-0053:20: {case}: the put was refused: {write_label}"
    );
    let def = stored.expect("the put left a definition");
    assert_eq!(
        def.lifecycle_status,
        ClaimLifecycleStatus::Active,
        "{case}: a saved definition is live at rest"
    );
    match lands {
        Lands::Proposal => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Proposed,
                "ARCH-0053:20: {case}: a definition wider than its author's slice is stored as other than a proposal"
            );
            assert_ne!(
                dispatch, "dispatched",
                "ARCH-0053:20: {case}: a definition wider than its author's slice is dispatchable"
            );
        }
        Lands::Active => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Approved,
                "ARCH-0053:20: {case}: a definition inside its author's slice is not at the author's approval"
            );
            assert!(def.enabled, "{case}: the definition stays enabled");
            assert_eq!(
                dispatch, "dispatched",
                "ARCH-0053:20: {case}: a definition inside its author's slice is undispatchable"
            );
        }
    }
}

fn assert_candidate_lands(
    fixture: &Fixture,
    writer: EntityId,
    seed: u8,
    requested: &AgentDefinition,
    case: &str,
    lands: Lands,
) {
    let id = EntityId::from_bytes([seed; 16]).expect("candidate id");
    assert!(
        fixture
            .vault
            .get_agent_definition(&id)
            .expect("fresh candidate id")
            .is_none()
    );
    let write = put(&fixture.vault, writer, id, requested, NOW + 2);
    assert_lands(case, &write, &fixture.vault, id, lands);
    let stored = fixture
        .vault
        .get_agent_definition(&id)
        .expect("read the candidate")
        .expect("stored candidate");
    assert_eq!(
        stored.connectors, requested.connectors,
        "the connector reference survives the put"
    );
    assert_eq!(
        stored.code_mode_mcps, requested.code_mode_mcps,
        "the code-mode MCP reference survives the put"
    );
    assert_eq!(stored.scope, requested.scope);
    assert_eq!(stored.ceiling, requested.ceiling);
}

#[test]
fn agent_batch_stores_a_definition_naming_a_connector_its_author_can_use_active() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.server-author");
    grant_base_reach(&fixture, writer);
    register_server(&fixture);
    consent_server(&fixture, writer);
    let mut requested = candidate(Slice::Within);
    requested.connectors = vec![SERVER.to_owned()];
    assert_candidate_lands(
        &fixture,
        writer,
        0x82,
        &requested,
        "granted-agent-memory/vault.batch/new/connector-with-server-grant",
        Lands::Active,
    );
}

#[test]
fn agent_batch_stores_a_definition_naming_a_code_mode_mcp_its_author_can_use_active() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.server-author");
    grant_base_reach(&fixture, writer);
    register_server(&fixture);
    consent_server(&fixture, writer);
    let mut requested = candidate(Slice::Within);
    requested.code_mode_mcps = vec![McpRef::new(SERVER)];
    assert_candidate_lands(
        &fixture,
        writer,
        0x83,
        &requested,
        "granted-agent-memory/vault.batch/new/code-mode-mcp-with-server-grant",
        Lands::Active,
    );
}

#[test]
fn agent_batch_stores_a_definition_naming_a_server_its_author_holds_no_grant_on_as_a_proposal() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.server-author");
    grant_base_reach(&fixture, writer);
    register_server(&fixture);
    // Only tool consent is omitted; the catalog and Base grant are identical.
    let owner = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let view = fixture
        .vault
        .connector_consent_view(&owner, SERVER, Some(writer))
        .expect("read the author's consent")
        .expect("the catalog exists");
    assert!(view.ready);
    assert_eq!(view.actor, writer.to_hex());
    assert_eq!(view.rows.len(), 1);
    assert_eq!(view.rows[0].tool, "read");
    assert!(
        view.rows[0].grant_id.is_none(),
        "the author has no live server grant"
    );
    let mut connector = candidate(Slice::Within);
    connector.connectors = vec![SERVER.to_owned()];
    let mut code_mode_mcp = candidate(Slice::Within);
    code_mode_mcp.code_mode_mcps = vec![McpRef::new(SERVER)];
    for (seed, requested, case) in [
        (
            0x84,
            connector,
            "granted-agent-memory/vault.batch/new/connector-without-server-grant",
        ),
        (
            0x85,
            code_mode_mcp,
            "granted-agent-memory/vault.batch/new/code-mode-mcp-without-server-grant",
        ),
    ] {
        assert_candidate_lands(&fixture, writer, seed, &requested, case, Lands::Proposal);
    }
}

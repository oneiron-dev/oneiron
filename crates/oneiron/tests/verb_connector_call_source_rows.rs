//! `connector.call_source_rows` through the generated verb dispatch (`oneiron::task_verb::sdk::invoke`),
//! as a client calls it: JSON in, JSON out, on the caller's own `Memory`. An agent with no
//! Grant listing the verb is refused FORBIDDEN; the holder reads its own held call's source
//! rows its lane admits with an in-lane row kept and an existing outside row dropped; a call
//! another agent owns reads the exact `connector.call_status` not-found; and a revoked Grant
//! is refused again live. The held calls come from the public `Vault::call_connector` door
//! with a scripted host, held for a missing standing grant, listing fixed in/out claims.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_connector_call_source_rows`
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, SlateDataClass, SlateToolManifest,
    draft_connector_slate,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND,
    Memory, ScopedClaimInput,
};
use oneiron::outbound_consent::tool_call::MutationIntent;
use oneiron::outbound_consent::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
    OutboundResultSender, OutboundTransportResult,
};
use oneiron::outbound_intent_ledger::FrozenOutboundCall;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use serde_json::{Value, json};

const CONNECTOR_SOURCE_ROWS_TEST_NOW: u64 = 1_700_000_000;
const CONNECTOR_SOURCE_ROWS_TEST_VERB: &str = "connector.call_source_rows";

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const CONNECTOR_SOURCE_ROWS_TEST_HOLDER_SEED: u8 = 0x70;
const CONNECTOR_SOURCE_ROWS_TEST_OTHER_SEED: u8 = 0x71;
const CONNECTOR_SOURCE_ROWS_TEST_GRANTLESS_SEED: u8 = 0x72;
const CONNECTOR_SOURCE_ROWS_TEST_BASE_CLAIM_SEED: u8 = 0x73;
const CONNECTOR_SOURCE_ROWS_TEST_OTHER_CLAIM_SEED: u8 = 0x74;
const CONNECTOR_SOURCE_ROWS_TEST_HOLDER_ATTEMPT_SEED: u8 = 0x75;
const CONNECTOR_SOURCE_ROWS_TEST_OTHER_ATTEMPT_SEED: u8 = 0x76;

const CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME: &str = "memory";
const CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_TOOL: &str = "memory";
const CONNECTOR_SOURCE_ROWS_TEST_PROTOCOL_REVISION: &str = "2026-09-01";

/// An enabled, active agent definition the owner creates as `name`.
fn connector_source_rows_test_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "connector source rows fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// The scripted connector host: it installs one endpoint, never sends (a held fixture stops
/// before transport), and reports `custody` as the rows its passes picked, so the held row
/// lists fixed in/out claims beside its catalog route key.
struct ConnectorSourceRowsTestHost {
    custody: Vec<EntityId>,
}

impl OutboundResultSender for ConnectorSourceRowsTestHost {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        panic!("connector source rows fixture must hold before transport")
    }
}

impl ConnectorCallHost for ConnectorSourceRowsTestHost {
    fn tool_endpoint(&self, _route: &oneiron::connector_key::ConnectorCallRoute) -> Option<String> {
        Some("https://example.invalid".to_owned())
    }

    fn take_result(&mut self) -> Option<oneiron::outbound_consent::UntrustedToolResult> {
        None
    }

    fn take_sent_custody(&mut self) -> Option<Vec<EntityId>> {
        Some(self.custody.clone())
    }
}

/// A personal vault whose owner created three agents, granted the holder its base lane and
/// the verb, wrote one claim in base reality and one in an excluded world, admitted one
/// catalog connector, and held one call per owning agent listing fixed source rows.
struct ConnectorSourceRowsTestFixture {
    vault: Vault,
    owner_proof: AuthenticatedOwner,
    holder: EntityId,
    grantless: EntityId,
    base_claim: EntityId,
    other_claim: EntityId,
    holder_call: EntityId,
    other_call: EntityId,
    holder_grant: EntityId,
    _dir: tempfile::TempDir,
}

fn connector_source_rows_test_write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    claim: EntityId,
    world: EntityId,
    value: &str,
) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(CONNECTOR_SOURCE_ROWS_TEST_NOW),
            learned_at: Some(CONNECTOR_SOURCE_ROWS_TEST_NOW),
            salience: None,
        })
        .expect("owner writes a claim in the requested world");
}

/// The catalog connector `memory` admitted Active by owner attestation, so a call routes.
fn connector_source_rows_test_admit_connector(vault: &Vault, owner_proof: &AuthenticatedOwner) {
    let manifest = vec![SlateToolManifest {
        resolved_output_schema: None,
        name: CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_TOOL.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(
            json!({"type": "object", "properties": {"idempotency_key": {"type": "string"}}}),
        ),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: false,
        price: None,
    }];
    let slate = vault
        .store_connector_slate(
            &manifest,
            &serde_json::to_string(&draft_connector_slate(&manifest)).expect("draft slate"),
        )
        .expect("owner stores the connector slate");
    let (key, pending) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME.to_owned(),
                connector: CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME.to_owned(),
                summary: "Memory connector".to_owned(),
                verbs: vec!["read".to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: 0,
            },
            ConnectorKeySpec {
                slate_ref: Some(slate),
                protocol_revision: Some(CONNECTOR_SOURCE_ROWS_TEST_PROTOCOL_REVISION.to_owned()),
                ..ConnectorKeySpec::new(CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME)
            },
            CONNECTOR_SOURCE_ROWS_TEST_NOW,
        )
        .expect("owner registers the catalog connector");
    assert!(
        matches!(
            pending.status,
            oneiron::connector_key::ConnectorKeyStatus::Pending
        ),
        "a catalog registration starts pending"
    );
    vault
        .override_connector_slate(owner_proof, slate, 0, &BTreeMap::new())
        .expect("owner stamps the slate");
    vault
        .attest_connector_key(
            owner_proof,
            &key,
            CONNECTOR_SOURCE_ROWS_TEST_PROTOCOL_REVISION,
            CONNECTOR_SOURCE_ROWS_TEST_NOW + 1,
        )
        .expect("owner attests the connector active");
    assert!(
        vault
            .route_connector_call(CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME)
            .expect("route reads")
            .is_some(),
        "the attested connector routes"
    );
}

/// One held call owned by `caller`, listing `custody` beside its route key: with no standing
/// outbound grant the public door holds for `standing_grant_required` instead of sending.
fn connector_source_rows_test_held_call(
    vault: &Vault,
    caller: EntityId,
    attempt_seed: u8,
    custody: Vec<EntityId>,
) -> EntityId {
    let memory = vault.memory(caller, EdgeActorClass::Agent);
    let mut host = ConnectorSourceRowsTestHost { custody };
    let outcome = vault
        .call_connector(
            &memory,
            ConnectorCallRequest {
                name: CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_NAME.to_owned(),
                source: None,
                tool: CONNECTOR_SOURCE_ROWS_TEST_CONNECTOR_TOOL.to_owned(),
                arguments: json!({}),
                mutation: MutationIntent::Preview,
            },
            Some(ConnectorCallInvocation {
                attempt_id: AttemptId::from_bytes(&[attempt_seed; 16]).expect("attempt id"),
                call_seq: 0,
            }),
            &mut host,
        )
        .expect("the fixture call holds");
    match outcome {
        ConnectorCallOutcome::Held {
            call_ref, reasons, ..
        } => {
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason == "standing_grant_required"),
                "the fixture holds for its missing grant: {reasons:?}"
            );
            call_ref
        }
        other => panic!("the fixture call must hold, got {other:?}"),
    }
}

fn connector_source_rows_test_fixture() -> ConnectorSourceRowsTestFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let staging_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder =
        EntityId::from_bytes([CONNECTOR_SOURCE_ROWS_TEST_HOLDER_SEED; 16]).expect("holder id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &holder,
            &connector_source_rows_test_definition("owen"),
            TimeRange {
                start: CONNECTOR_SOURCE_ROWS_TEST_NOW,
                end: CONNECTOR_SOURCE_ROWS_TEST_NOW,
            },
            CONNECTOR_SOURCE_ROWS_TEST_NOW,
        )
        .expect("owner creates the holder");
    let other =
        EntityId::from_bytes([CONNECTOR_SOURCE_ROWS_TEST_OTHER_SEED; 16]).expect("other id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &other,
            &connector_source_rows_test_definition("yuki"),
            TimeRange {
                start: CONNECTOR_SOURCE_ROWS_TEST_NOW,
                end: CONNECTOR_SOURCE_ROWS_TEST_NOW,
            },
            CONNECTOR_SOURCE_ROWS_TEST_NOW,
        )
        .expect("owner creates the other caller");
    let grantless = EntityId::from_bytes([CONNECTOR_SOURCE_ROWS_TEST_GRANTLESS_SEED; 16])
        .expect("grantless id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &grantless,
            &connector_source_rows_test_definition("sora"),
            TimeRange {
                start: CONNECTOR_SOURCE_ROWS_TEST_NOW,
                end: CONNECTOR_SOURCE_ROWS_TEST_NOW,
            },
            CONNECTOR_SOURCE_ROWS_TEST_NOW,
        )
        .expect("owner creates the grantless agent");
    vault
        .install_read_permit_for_test(oneiron::WriteActor::new(grantless, EdgeActorClass::Agent))
        .expect("grantless read permit");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let other_world = vault
        .create_world(
            &owner_proof,
            "Grant-excluded world",
            CONNECTOR_SOURCE_ROWS_TEST_NOW,
        )
        .expect("owner creates the second world");
    let base_claim = EntityId::from_bytes([CONNECTOR_SOURCE_ROWS_TEST_BASE_CLAIM_SEED; 16])
        .expect("base claim id");
    connector_source_rows_test_write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        base_claim,
        base_world_id(),
        "base-world claim",
    );
    let other_claim = EntityId::from_bytes([CONNECTOR_SOURCE_ROWS_TEST_OTHER_CLAIM_SEED; 16])
        .expect("other claim id");
    connector_source_rows_test_write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        other_claim,
        other_world,
        "other-world claim",
    );
    connector_source_rows_test_admit_connector(&vault, &owner_proof);
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        CONNECTOR_SOURCE_ROWS_TEST_VERB.to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: holder,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner grants the holder its base lane and the verb");
    assert!(minted.grant.confers, "the grant confers");
    let holder_call = connector_source_rows_test_held_call(
        &vault,
        holder,
        CONNECTOR_SOURCE_ROWS_TEST_HOLDER_ATTEMPT_SEED,
        vec![base_claim, other_claim],
    );
    let other_call = connector_source_rows_test_held_call(
        &vault,
        other,
        CONNECTOR_SOURCE_ROWS_TEST_OTHER_ATTEMPT_SEED,
        vec![base_claim],
    );
    ConnectorSourceRowsTestFixture {
        vault,
        owner_proof,
        holder,
        grantless,
        base_claim,
        other_claim,
        holder_call,
        other_call,
        holder_grant: minted.grant.grant_ref,
        _dir: dir,
    }
}

/// The verb by name, as a client calls it: JSON in, JSON out.
fn connector_source_rows_test_invoke(
    memory: &Memory<'_>,
    call_ref: &EntityId,
) -> Result<Value, oneiron::memory::MemoryError> {
    invoke(
        memory,
        CONNECTOR_SOURCE_ROWS_TEST_VERB,
        json!({ "call_ref": call_ref.to_hex() }),
    )
}

#[test]
fn connector_source_rows_test_grantless_is_forbidden() {
    let fixture = connector_source_rows_test_fixture();
    let memory = fixture
        .vault
        .memory(fixture.grantless, EdgeActorClass::Agent);
    let error = connector_source_rows_test_invoke(&memory, &fixture.holder_call)
        .expect_err("an agent with no grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a no-grant refusal names FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(CONNECTOR_SOURCE_ROWS_TEST_VERB),
        "the refusal names the verb; got {}",
        error.message,
    );
}

#[test]
fn connector_source_rows_test_holder_reads_lane_and_filters_outside() {
    let fixture = connector_source_rows_test_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let out = connector_source_rows_test_invoke(&memory, &fixture.holder_call)
        .expect("the holder reads its own call");
    assert_eq!(
        out.get("call_ref").and_then(Value::as_str),
        Some(fixture.holder_call.to_hex()).as_deref(),
        "the answer names the call read; got {out}",
    );
    let rows = out
        .get("source_rows")
        .expect("the answer carries source_rows");
    let rows = rows.as_array().expect("pending rows stay Some, never null");
    let seen: Vec<String> = rows
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    assert!(
        seen.contains(&fixture.base_claim.to_hex()),
        "the in-lane row reads; got {out}",
    );
    assert!(
        !seen.contains(&fixture.other_claim.to_hex()),
        "the row outside the lane is dropped silently; got {out}",
    );
    assert!(
        out.get("withheld").is_none(),
        "no withheld count rides the DTO; got {out}",
    );
}

#[test]
fn connector_source_rows_test_foreign_is_not_found() {
    let fixture = connector_source_rows_test_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let error = connector_source_rows_test_invoke(&memory, &fixture.other_call)
        .expect_err("another caller's call reads not-found");
    assert_eq!(
        error.code, MEMORY_CODE_NOT_FOUND,
        "a foreign call names NOT_FOUND; got {}: {}",
        error.code, error.message,
    );
    assert_eq!(
        error.message, "no connector call with this ref is yours to read",
        "the foreign refusal copies connector.call_status exactly; got {}",
        error.message,
    );
}

#[test]
fn connector_source_rows_test_revoked_grant_is_forbidden_live() {
    let fixture = connector_source_rows_test_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let before = connector_source_rows_test_invoke(&memory, &fixture.holder_call)
        .expect("the holder reads before the revoke");
    assert!(
        before
            .get("source_rows")
            .and_then(Value::as_array)
            .is_some(),
        "the pre-revoke read holds Some rows; got {before}",
    );
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: fixture.holder_grant,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
    let error = connector_source_rows_test_invoke(&memory, &fixture.holder_call)
        .expect_err("the revoked grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a revoked-grant refusal names FORBIDDEN; got {}: {}",
        error.code, error.message,
    );
}

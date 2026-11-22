//! Success paths of the connector scope revision doors (FIX
//! [CONNECTORS-SCOPE-SIGNAL-NO-PUBLIC-GETTER]): `vault.connectors.slates.
//! scope_outcome`, `revision_offers` (a non-empty scope page),
//! `defer_revision` and `accept_revision` on a scope-exceed cause.
//! `vault_connectors_doors.rs` proves only their 403 / 404 / 400 rows: a
//! scope signal is kept by the call driver under a crate-private table, and
//! no public read names one (the owner's ask names the held call).
//!
//! The fixture admits one catalog connector through the public engine chain
//! (rule-drafted slate, register, owner stamp, owner attest, owner consent of
//! the `read` tool to the embedded owner at endpoint A), the recipe of
//! `crates/oneiron/tests/agent_definition_named_server_grant.rs`. The host
//! installs the connector at endpoint B, so each `connector.call` the owner
//! makes through the facade holds on a typed endpoint exceed before anything
//! is sent, and keeps one scope signal. The cfg door
//! `oneiron::test_doors::slate_scope_signals` lists the signal refs (it
//! reads only); every ruling, offer, deferral and acceptance goes through the
//! facade doors as the owner's root.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test connector_scope_signal_doors`.
//! Without the cfg this file holds no test (as `model_binding_proposer_grant`).
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget, ConnectorKeySpec,
    ConnectorToolConsent, ConnectorToolConsentRow, SlateDataClass, SlateToolManifest,
    draft_connector_slate,
};
use oneiron::consent::tool_scope::DataClass;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::slate_scope_signals::signal_refs;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    build_app,
    config::{ConnectorHostConfig, ConnectorTransport, SyncServerConfig},
    server::SyncServer,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

const CONNECTOR: &str = "scope_signal_door";
const PROTOCOL_REVISION: &str = "2026-09-01";
/// The endpoint the owner's consent names.
const GRANTED_ENDPOINT: &str = "https://scope-accepted.invalid/mcp";
/// The endpoint the host installs: every call names it and exceeds the grant.
const REQUESTED_ENDPOINT: &str = "https://scope-target.invalid/mcp";
const SLATES: &str = "/v1/core/facade/vault.connectors.slates.";
/// The clean rulings an offer needs under the default threshold row.
const EARNING_RULINGS: u32 = 12;

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    prior: EntityId,
    original_grant: EntityId,
    _dir: tempfile::TempDir,
}

fn owner_proof(vault: &Vault, owner: EntityId) -> oneiron::consent::AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the fixture holds the vault owner's live proof")
}

/// The public admission chain, then the owner's consent of `read` to
/// `actor` at the granted endpoint only. Returns the accepted slate and the
/// grant.
fn admit_connector(vault: &Vault, actor: EntityId) -> (EntityId, EntityId) {
    let owner = owner_proof(vault, actor);
    let manifest = vec![SlateToolManifest {
        name: "read".to_owned(),
        data_class: SlateDataClass::Public,
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
    let prior = vault
        .store_connector_slate(
            &manifest,
            &serde_json::to_string(&draft_connector_slate(&manifest)).expect("typed slate draft"),
        )
        .expect("store the rule-drafted slate");
    let mut spec = ConnectorKeySpec::new(CONNECTOR);
    spec.slate_ref = Some(prior);
    spec.protocol_revision = Some(PROTOCOL_REVISION.to_owned());
    let at = vault.now_recorded_at();
    let (catalog_id, _) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: CONNECTOR.to_owned(),
                connector: CONNECTOR.to_owned(),
                summary: "scope signal door fixture".to_owned(),
                verbs: vec!["read".to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: at,
            },
            spec,
            at,
        )
        .expect("register the pending catalog connector");
    let slate = vault
        .connector_slate(prior)
        .expect("read the slate")
        .expect("stored slate");
    vault
        .stamp_connector_slate(&owner, prior, slate.revision(), &BTreeMap::new(), None)
        .expect("the owner stamps the slate");
    vault
        .attest_connector_key(&owner, &catalog_id, PROTOCOL_REVISION, at)
        .expect("the owner attests the key without network probes");
    let granted = vault
        .consent_connector_tools(
            &owner,
            &ConnectorToolConsent {
                connector: CONNECTOR.to_owned(),
                target: ConnectorConsentTarget::Actor(actor),
                endpoint: GRANTED_ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: "read".to_owned(),
                    data_class_ceiling: DataClass::Public,
                    headers: false,
                }],
            },
        )
        .expect("the owner consents read at the granted endpoint");
    assert_eq!(granted.len(), 1, "the fixture mints one read grant");
    let grant = EntityId::from_hex(&granted[0].grant_id).expect("returned grant id");
    (prior, grant)
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("connector-scope-signal-doors".into()),
                connectors: BTreeMap::from([(
                    CONNECTOR.to_owned(),
                    ConnectorHostConfig {
                        transport: ConnectorTransport::McpHttp,
                        endpoint: Some(REQUESTED_ENDPOINT.to_owned()),
                        command: Vec::new(),
                        env: BTreeMap::new(),
                        cwd: None,
                        upstream: None,
                    },
                )]),
                ..Default::default()
            },
        )
        .expect("create the server with the connector installed at the requested endpoint"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let (prior, original_grant) = admit_connector(&vault, owner);
    Fixture {
        app: build_app(server),
        vault,
        issuer,
        owner_slip,
        owner_token,
        owner,
        prior,
        original_grant,
        _dir: dir,
    }
}

/// One facade POST as the owner's root, with a fresh binding and a fresh
/// `x-oneiron-invocation` (a repeated one replays the first reply).
async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
    let request = Request::post(path)
        .header("authorization", format!("Bearer {}", fixture.owner_token))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-invocation", EntityId::now().to_hex())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn slate_post(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    post_as_owner(fixture, &format!("{SLATES}{verb}"), body).await
}

/// A held scope exceed: the call's kept signal ref, the held ask's
/// approve-once digest and the held call's ref.
struct HeldScope {
    signal_ref: String,
    approval_digest: String,
    call_ref: String,
}

/// One `connector.call` that holds on the endpoint exceed. The door reads
/// the signal refs before and after: exactly one new ref is this call's.
async fn held_scope(fixture: &Fixture) -> HeldScope {
    let before = signal_refs(&fixture.vault).expect("scan the signals before the call");
    let (status, held) = post_as_owner(
        fixture,
        "/v1/core/facade/connector.call",
        json!({"source": "catalog", "name": CONNECTOR, "tool": "read", "arguments": {}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the call answers its typed outcome: {held}"
    );
    assert_eq!(
        held["outcome"], "held",
        "an endpoint outside the grant holds the call: {held}"
    );
    assert!(
        held["reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.contains(&json!("endpoint_not_allowed"))),
        "the hold is the typed endpoint exceed, not a missing admission: {held}"
    );
    let after = signal_refs(&fixture.vault).expect("scan the signals after the call");
    let added: Vec<String> = after
        .into_iter()
        .filter(|signal| !before.contains(signal))
        .collect();
    assert_eq!(
        added.len(),
        1,
        "one held endpoint exceed keeps exactly one scope signal: {added:?}"
    );
    HeldScope {
        signal_ref: added[0].clone(),
        approval_digest: held["approval_digest"]
            .as_str()
            .expect("the held call names its approve-once digest")
            .to_owned(),
        call_ref: held["call_ref"]
            .as_str()
            .expect("the held call names its ref")
            .to_owned(),
    }
}

/// Twelve held calls, each ruled `approved_untouched` by the owner; the
/// twelfth ruling's reply names the proposal the earned offer drafted.
async fn earn_offer(fixture: &Fixture) -> Value {
    let mut last = Value::Null;
    for ruling in 1..=EARNING_RULINGS {
        let held = held_scope(fixture).await;
        let (status, reply) = slate_post(
            fixture,
            "scope_outcome",
            json!({
                "signal_ref": held.signal_ref,
                "linked_ruling": held.approval_digest,
                "outcome": "approved_untouched",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "ruling {ruling} is recorded through the owner's door: {reply}"
        );
        assert_eq!(
            reply["untouched_streak"], ruling,
            "signals of one live scope fold into one streak: {reply}"
        );
        if ruling < EARNING_RULINGS {
            assert!(
                reply["proposal_ref"].is_null(),
                "fewer than {EARNING_RULINGS} clean rulings earn no proposal: {reply}"
            );
        }
        last = reply;
    }
    assert!(
        last["proposal_ref"].is_string(),
        "{EARNING_RULINGS} clean rulings earn an unstamped proposal: {last}"
    );
    last
}

fn proposal_of(earned: &Value) -> EntityId {
    EntityId::from_hex(earned["proposal_ref"].as_str().expect("proposal ref"))
        .expect("32-hex proposal ref")
}

/// The live authority is still the original consent: its grant live, at
/// the granted endpoint only.
fn assert_original_authority(fixture: &Fixture) {
    let owner = owner_proof(&fixture.vault, fixture.owner);
    let view = fixture
        .vault
        .connector_consent_view(&owner, CONNECTOR, Some(fixture.owner))
        .expect("read the owner's consent")
        .expect("the catalog connector exists");
    assert_eq!(
        view.rows[0].grant_id.as_deref(),
        Some(fixture.original_grant.to_hex().as_str()),
        "the live grant for read is still the original one"
    );
    let grant = fixture
        .vault
        .get_standing_outbound_grant(&fixture.original_grant)
        .expect("read the original grant")
        .expect("the original grant exists");
    assert!(grant.is_active(), "the original grant stays live");
    assert_eq!(
        grant
            .scope
            .scoped_mcp_grant()
            .expect("a scoped MCP grant")
            .endpoint_allowlist,
        &[GRANTED_ENDPOINT.to_owned()],
        "no signal, ruling, offer or deferral widens the endpoint allowlist"
    );
}

/// ARCH-0072 (llms-full.txt:367508): "repeated scope-exceed escalations on
/// one row is the canonical signal"; (:367423) "Only the accepted slate
/// grants authority; a memory of past consent never widens it by itself."
#[test]
fn scope_outcome_records_one_rejection_of_a_held_scope_signal_without_widening() {
    run_on_engine_stack("scope-outcome-rejected", || async {
        let fixture = setup().await;
        let held = held_scope(&fixture).await;
        let request = json!({
            "signal_ref": held.signal_ref,
            "linked_ruling": held.approval_digest,
            "outcome": "rejected",
        });
        let (status, reply) = slate_post(&fixture, "scope_outcome", request.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner records a rejection of a held scope signal: {reply}"
        );
        assert_eq!(
            reply["signal"]["signal_ref"], held.signal_ref,
            "the ruling answers the signal the call kept: {reply}"
        );
        assert_eq!(
            reply["signal"]["call_ref"], held.call_ref,
            "the signal names the held call: {reply}"
        );
        assert_eq!(
            reply["signal"]["ruling"], "rejected",
            "the signal keeps the owner's rejection: {reply}"
        );
        assert_eq!(
            reply["rejected"], 1,
            "a scope rejection counts as one rejection, not an amendment: {reply}"
        );
        assert_eq!(
            reply["amended"], 0,
            "a rejection counts no amendment: {reply}"
        );
        assert_eq!(
            reply["untouched_streak"], 0,
            "a rejection adds nothing to the untouched streak: {reply}"
        );
        assert!(
            reply["proposal_ref"].is_null(),
            "a rejection earns no widening proposal: {reply}"
        );
        let (status, repeated) = slate_post(&fixture, "scope_outcome", request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a signal is ruled on once: {repeated}"
        );
        assert_eq!(
            repeated["error"]["message"].as_str(),
            Some("invalid connector key body: the scope signal's ruling is already recorded"),
            "the second ruling is refused by the once-only guard: {repeated}"
        );
        assert_original_authority(&fixture);
    });
}

/// ARCH-0072 (llms-full.txt:367508): "A proposed delta slate that lands only
/// on a person's stamp under DEC-0006's settlement row, like any authority
/// op: initiate freely, land on consent."
#[test]
fn revision_offers_lists_the_earned_scope_delta_without_granting() {
    run_on_engine_stack("scope-offer-list", || async {
        let fixture = setup().await;
        let earned = earn_offer(&fixture).await;
        let (status, page) =
            slate_post(&fixture, "revision_offers", json!({"connector": CONNECTOR})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the revision offers: {page}"
        );
        let offers = page["offers"].as_array().expect("the offers array");
        assert_eq!(
            offers.len(),
            1,
            "revision_offers surfaces the one earned scope delta: {page}"
        );
        let offer = &offers[0];
        assert_eq!(
            offer["proposal_ref"], earned["proposal_ref"],
            "the page names the earned proposal: {page}"
        );
        assert_eq!(
            offer["prior_ref"],
            fixture.prior.to_hex(),
            "the delta revises the accepted slate: {page}"
        );
        assert_eq!(
            offer["reask"],
            json!(["read"]),
            "only the exceeded tool asks again: {page}"
        );
        assert_eq!(
            offer["cause"]["kind"], "scope_exceed",
            "the offer's cause is the scope exceed: {page}"
        );
        assert_eq!(
            offer["cause"]["signal_ref"], earned["signal"]["signal_ref"],
            "the cause names the signal whose ruling earned it: {page}"
        );
        let proposal = fixture
            .vault
            .connector_slate(proposal_of(&earned))
            .expect("read the proposal")
            .expect("the proposal is stored");
        assert!(
            proposal.owner_actor().is_none(),
            "earning and listing leave the proposal unstamped"
        );
        assert_original_authority(&fixture);
    });
}

/// ARCH-0072 (llms-full.txt:367510): "Widening is never free. An agent
/// proposes, and only a stamp under DEC-0006's settlement row mints the
/// wider Grant." A deferral is not that stamp.
#[test]
fn defer_revision_pins_and_unpins_the_scope_offer_without_accepting_it() {
    run_on_engine_stack("scope-offer-defer", || async {
        let fixture = setup().await;
        let earned = earn_offer(&fixture).await;
        let signal_ref = earned["signal"]["signal_ref"].clone();
        let (status, pinned) = slate_post(
            &fixture,
            "defer_revision",
            json!({"signal_ref": signal_ref, "deferral": "manual_pinned"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner pins the earned offer: {pinned}"
        );
        assert_eq!(
            pinned["state"], "manual_pinned",
            "manual deferral keeps a manual pin, not a timed snooze: {pinned}"
        );
        let proposal = proposal_of(&earned);
        let stored = fixture
            .vault
            .connector_slate(proposal)
            .expect("read the proposal")
            .expect("the proposal is stored");
        assert!(
            stored.owner_actor().is_none(),
            "a deferral does not stamp the proposal"
        );
        let (status, refused) = slate_post(
            &fixture,
            "accept_revision",
            json!({"slate_ref": proposal.to_hex(), "expected_revision": stored.revision()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a pinned offer is not accepted: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid connector key body: the scope revision's offer no longer stands"),
            "the accept recheck refuses the pinned offer: {refused}"
        );
        let (status, unpinned) = slate_post(
            &fixture,
            "defer_revision",
            json!({"signal_ref": signal_ref, "deferral": "unpin"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner unpins the offer: {unpinned}"
        );
        assert_eq!(
            unpinned["state"], "surfacing",
            "an unpin clears the hold: {unpinned}"
        );
        assert_original_authority(&fixture);
    });
}

/// ARCH-0072 (llms-full.txt:367496): "The stamp mints a wider Grant covering
/// that one row. The wider Grant replaces the one before it."
#[test]
fn accept_revision_stamps_the_scope_delta_and_remints_a_wider_endpoint_grant() {
    run_on_engine_stack("scope-offer-accept", || async {
        let fixture = setup().await;
        let earned = earn_offer(&fixture).await;
        let proposal = proposal_of(&earned);
        let before = fixture
            .vault
            .connector_slate(proposal)
            .expect("read the proposal")
            .expect("the proposal is stored");
        let (status, accepted) = slate_post(
            &fixture,
            "accept_revision",
            json!({"slate_ref": proposal.to_hex(), "expected_revision": before.revision()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's stamp accepts the standing scope delta: {accepted}"
        );
        assert_eq!(
            accepted["cause"]["kind"], "scope_exceed",
            "the accept takes the scope branch: {accepted}"
        );
        let grants = accepted["grants"].as_array().expect("the minted grants");
        assert_eq!(
            grants.len(),
            1,
            "one exceeded row re-mints one grant: {accepted}"
        );
        assert_eq!(
            grants[0]["tool"], "read",
            "the new grant covers the exceeded tool: {accepted}"
        );
        let wider_id = EntityId::from_hex(grants[0]["grant_id"].as_str().expect("grant id"))
            .expect("32-hex grant id");
        let wider = fixture
            .vault
            .get_standing_outbound_grant(&wider_id)
            .expect("read the new grant")
            .expect("the new grant is stored");
        let scope = wider.scope.scoped_mcp_grant().expect("a scoped MCP grant");
        assert!(
            scope
                .endpoint_allowlist
                .contains(&REQUESTED_ENDPOINT.to_owned()),
            "acceptance adds the requested endpoint to the re-minted grant: {:?}",
            scope.endpoint_allowlist
        );
        assert!(
            scope
                .endpoint_allowlist
                .contains(&GRANTED_ENDPOINT.to_owned()),
            "acceptance keeps the granted endpoint: {:?}",
            scope.endpoint_allowlist
        );
        assert_eq!(
            wider.principal_ref,
            fixture.owner.to_hex(),
            "the new grant is the caller's whose calls earned it"
        );
        assert!(wider.is_active(), "the new grant is live");
        let old = fixture
            .vault
            .get_standing_outbound_grant(&fixture.original_grant)
            .expect("read the original grant")
            .expect("the original grant is kept");
        assert!(
            !old.is_active(),
            "the wider grant replaces the original one"
        );
        let stamped = fixture
            .vault
            .connector_slate(proposal)
            .expect("read the stamped proposal")
            .expect("the proposal is kept");
        assert_eq!(
            stamped.owner_actor(),
            Some(fixture.owner.to_hex().as_str()),
            "the acceptance stamps the scope delta"
        );
        assert_eq!(
            accepted["slate_ref"],
            proposal.to_hex(),
            "the reply names the stamped proposal: {accepted}"
        );
        assert_eq!(
            accepted["revision"],
            stamped.revision(),
            "the reply names the stamped revision: {accepted}"
        );
    });
}

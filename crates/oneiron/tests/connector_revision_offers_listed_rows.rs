//! FIX [MCP-READ-REVISION-OFFERS-UNLISTED-ROWS]: `connector_slate_revision_offers_listed`
//! names the rows each listed offer was read from, each an entity row a
//! release can judge again. A standing scope offer lists the connector key
//! its standing check read, and not its side-table consent grant or any
//! slate (REVIEW-10630: a replay judges each listed id as an entity, and a
//! grant id stands as none); an open issuer revision lists the catalog key
//! and each dependent key, and not its side-table binding or its tool-name
//! dependent rows; no waiting revision lists no row.
//!
//! The scope fixture earns its offer as
//! `crates/oneiron-server/tests/connector_scope_signal_doors.rs` does (one
//! held endpoint exceed per streak step, each ruled clean), with the
//! crate-private keep behind `test_doors::revision_offers_listed_rows`.
//! The issuer fixture is the baseline-plus-detection of
//! `crates/oneiron/tests/connector_issuer_detection.rs`.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test connector_revision_offers_listed_rows`
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::connector_key::{
    ConnectorBindingDependent, ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget,
    ConnectorCredentialBinding, ConnectorIssuerDetection, ConnectorIssuerObservation,
    ConnectorKeySpec, ConnectorScopeOutcome, ConnectorToolConsent, ConnectorToolConsentRow,
    SlateDataClass, SlateRevisionCause, SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::tool_scope::DataClass;
use oneiron::consent_graduation::DEFAULT_GRADUATION_STREAK_FLOOR;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    ConnectorSlateRevisionOffersRequest, connector_slate_revision_offers_listed,
};
use oneiron::test_doors::revision_offers_listed_rows::keep_scope_signal;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 1_700_000_000;
const CONNECTOR: &str = "memory";
const PROTOCOL_REVISION: &str = "2026-09-01";
const READ_ROW: &str = "read";
const WRITE_ROW: &str = "write";
const GRANTED_ENDPOINT: &str = "https://granted.invalid/mcp";
const REQUESTED_ENDPOINT: &str = "https://requested.invalid/mcp";
const SLOT: &str = "route";
const OLD_ISSUER: &str = "https://as-old.test";
const NEW_ISSUER: &str = "https://as-new.test";

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    owner_actor: EntityId,
    /// The attested catalog key of `CONNECTOR`.
    key: EntityId,
    _dir: tempfile::TempDir,
}

fn tool(name: &str) -> SlateToolManifest {
    SlateToolManifest {
        name: name.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(json!({"type": "object", "properties": {}})),
        resolved_output_schema: None,
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: false,
        price: None,
        http: None,
    }
}

/// A rooted vault whose owner registered, stamped and attested `CONNECTOR`
/// with two slate rows, `read` and `write`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner = vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let manifest = vec![tool(READ_ROW), tool(WRITE_ROW)];
    let slate = vault
        .store_connector_slate(
            &manifest,
            &serde_json::to_string(&draft_connector_slate(&manifest)).expect("draft slate"),
        )
        .expect("owner stores the connector slate");
    let (key, _) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: CONNECTOR.to_owned(),
                connector: CONNECTOR.to_owned(),
                summary: "Memory connector".to_owned(),
                verbs: vec![READ_ROW.to_owned(), WRITE_ROW.to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: 0,
            },
            ConnectorKeySpec {
                slate_ref: Some(slate),
                protocol_revision: Some(PROTOCOL_REVISION.to_owned()),
                ..ConnectorKeySpec::new(CONNECTOR)
            },
            NOW,
        )
        .expect("owner registers the catalog connector");
    vault
        .override_connector_slate(&owner, slate, 0, &BTreeMap::new())
        .expect("owner stamps the slate");
    vault
        .attest_connector_key(&owner, &key, PROTOCOL_REVISION, NOW + 1)
        .expect("owner attests the connector active");
    Fixture {
        vault,
        owner,
        owner_actor,
        key,
        _dir: dir,
    }
}

/// The owner's consent of the `write` row at the granted endpoint only;
/// the standing grant it mints.
fn consent_write(fixture: &Fixture) -> EntityId {
    let granted = fixture
        .vault
        .consent_connector_tools(
            &fixture.owner,
            &ConnectorToolConsent {
                connector: CONNECTOR.to_owned(),
                target: ConnectorConsentTarget::Actor(fixture.owner_actor),
                endpoint: GRANTED_ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: WRITE_ROW.to_owned(),
                    data_class_ceiling: DataClass::Personal,
                    headers: false,
                }],
            },
        )
        .expect("the owner consents the write row at the granted endpoint");
    assert_eq!(granted.len(), 1, "the fixture mints one write grant");
    EntityId::from_hex(&granted[0].grant_id).expect("the grant id is 32 hex")
}

/// One held endpoint exceed per streak step, each ruled clean, until the
/// earned offer drafts its proposal.
fn earn_scope_offer(fixture: &Fixture, grant: &EntityId) {
    for seq in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        let (signal_ref, ask) = keep_scope_signal(
            &fixture.vault,
            &fixture.key,
            grant,
            CONNECTOR,
            REQUESTED_ENDPOINT,
            u64::from(seq),
        )
        .expect("the held call keeps its scope signal");
        let signal_id = EntityId::from_hex(&signal_ref).expect("the signal ref is 32 hex");
        let recorded = fixture
            .vault
            .record_connector_scope_outcome(
                &fixture.owner,
                signal_id,
                &ask,
                ConnectorScopeOutcome::ApprovedUntouched,
            )
            .expect("the owner rules on the held scope signal");
        if seq + 1 == DEFAULT_GRADUATION_STREAK_FLOOR {
            assert!(
                recorded.proposed_slate_ref.is_some(),
                "the twelfth clean ruling drafts the earned proposal"
            );
        }
    }
}

/// The owner's baseline: the route's slot answers for `OLD_ISSUER`, and only
/// the `write` row depends on it.
fn baseline(fixture: &Fixture) -> ConnectorCredentialBinding {
    let binding = fixture
        .vault
        .observe_connector_credential_issuer(
            &fixture.owner,
            &ConnectorIssuerObservation {
                connector: CONNECTOR.to_owned(),
                slot: SLOT.to_owned(),
                issuer: OLD_ISSUER.to_owned(),
                credential_ref: "custody:route-token".to_owned(),
                expected_generation: 0,
                dependents: vec![ConnectorBindingDependent {
                    key_ref: fixture.key,
                    tool: Some(WRITE_ROW.to_owned()),
                }],
                witness: "owner read the route's issuer".to_owned(),
            },
        )
        .expect("owner baselines the route's issuer");
    assert_eq!(binding.generation, 1, "the baseline is generation 1");
    assert!(binding.transition.is_none(), "a baseline is no change");
    binding
}

#[test]
fn standing_scope_offer_lists_its_key_and_no_grant() {
    let fixture = fixture();
    let grant = consent_write(&fixture);
    earn_scope_offer(&fixture, &grant);

    let (offers, rows) = fixture
        .vault
        .connector_slate_revision_offers_listed(None)
        .expect("the offers list with their rows");

    assert_eq!(
        offers.len(),
        1,
        "the earned scope delta is the one waiting revision"
    );
    let offer = &offers[0];
    let SlateRevisionCause::ScopeExceed { key_ref, .. } = &offer.cause else {
        panic!(
            "the waiting revision is the earned scope exceed, not {:?}",
            offer.cause
        );
    };
    assert_eq!(
        *key_ref, fixture.key,
        "the scope cause carries the catalog key"
    );
    for row in &rows {
        assert!(
            fixture
                .vault
                .get_entity_type(row)
                .expect("the listed row's type reads")
                .is_some(),
            "each listed row is an entity row a release judges again: {row:?}"
        );
    }
    assert!(
        !rows.contains(&grant),
        "the consent grant is a side-table record and lists no row: {rows:?}"
    );
    assert_eq!(
        rows,
        vec![fixture.key],
        "a scope offer lists its key, nothing else"
    );
    assert!(
        rows.windows(2).all(|pair| pair[0] <= pair[1]),
        "the listed rows are sorted and deduped: {rows:?}"
    );
    let proposal = offer
        .proposal_ref
        .expect("the earned offer names its proposal");
    assert!(
        !rows.contains(&proposal),
        "the proposal slate is a side table and lists no row: {rows:?}"
    );
    let prior = offer
        .prior_ref
        .expect("the delta names the slate it revises");
    assert!(
        !rows.contains(&prior),
        "the prior slate is a side table and lists no row: {rows:?}"
    );

    let (view, sdk_rows) = connector_slate_revision_offers_listed(
        &fixture.vault,
        &fixture.owner,
        ConnectorSlateRevisionOffersRequest { connector: None },
    )
    .expect("the SDK lists the same offers with their rows");
    assert_eq!(
        view.offers.len(),
        1,
        "the SDK surfaces the one earned scope delta"
    );
    assert_eq!(sdk_rows, rows, "the SDK lists the rows the engine read");
}

#[test]
fn open_issuer_revision_lists_its_keys_and_no_side_table_row() {
    let fixture = fixture();
    let binding = baseline(&fixture);
    let drifted = fixture
        .vault
        .detect_connector_credential_issuer(&ConnectorIssuerDetection {
            key_ref: fixture.key,
            authorization_servers: vec![NEW_ISSUER.to_owned()],
            witness: "protected-resource metadata lists the new issuer".to_owned(),
        })
        .expect("detection reads the bindings");
    assert_eq!(drifted.len(), 1, "the one binding drifted: {drifted:?}");

    let (offers, rows) = fixture
        .vault
        .connector_slate_revision_offers_listed(None)
        .expect("the offers list with their rows");

    assert_eq!(
        offers.len(),
        1,
        "the detected issuer change is the one waiting revision"
    );
    let offer = &offers[0];
    let SlateRevisionCause::CredentialIssuerChanged {
        binding_ref,
        dependent_rows,
        ..
    } = &offer.cause
    else {
        panic!(
            "the waiting revision is the issuer change, not {:?}",
            offer.cause
        );
    };
    assert_eq!(
        *binding_ref, binding.binding_ref,
        "the cause names the drifted binding"
    );
    assert_eq!(
        dependent_rows,
        &BTreeSet::from([WRITE_ROW.to_owned()]),
        "the cause's dependent rows are tool names"
    );
    assert!(
        EntityId::from_hex(WRITE_ROW).is_err(),
        "a tool name is not an entity id"
    );
    assert_eq!(
        rows,
        vec![fixture.key],
        "an issuer revision lists its catalog key, here also its one dependent key, and nothing else"
    );
    assert!(
        !rows.contains(binding_ref),
        "the credential binding is a side-table row, not an entity: {rows:?}"
    );
    if let Some(proposal) = offer.proposal_ref {
        assert!(
            !rows.contains(&proposal),
            "the drafted slate is a side table and lists no row: {rows:?}"
        );
    }
    if let Some(prior) = offer.prior_ref {
        assert!(
            !rows.contains(&prior),
            "the prior slate is a side table and lists no row: {rows:?}"
        );
    }
}

#[test]
fn no_waiting_revisions_list_no_rows() {
    let fixture = fixture();

    let (offers, rows) = fixture
        .vault
        .connector_slate_revision_offers_listed(None)
        .expect("the offers list with their rows");

    assert!(offers.is_empty(), "a fresh vault holds no waiting revision");
    assert!(rows.is_empty(), "no listed offer means no listed row");
}

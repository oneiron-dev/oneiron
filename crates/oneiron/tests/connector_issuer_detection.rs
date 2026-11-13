//! L5-11 (ARCH-0072 #drift, #living; ARCH-0054 #auth): the engine's own
//! detection of a credential issuer change. A catalog connector's binding
//! answers for one issuer, baselined by the owner's observation. When the
//! connector's protected-resource metadata no longer lists that issuer,
//! `Vault::detect_connector_credential_issuer` records the change with no
//! owner act and no second re-ask: every dependent row holds, and an
//! unrelated row keeps running. A listed issuer is not drift, a connector
//! with no binding records nothing, and the owner's accept of the drafted
//! revision lifts the hold at the next generation.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test connector_issuer_detection`
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::connector_key::{
    CONNECTOR_ISSUER_HOLD_REASON, ConnectorBindingDependent, ConnectorCallClass,
    ConnectorCatalogEntry, ConnectorCredentialBinding, ConnectorIssuerDetection,
    ConnectorIssuerObservation, ConnectorIssuerTransitionState, ConnectorKeySpec, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 1_700_000_000;
const CONNECTOR: &str = "memory";
const PROTOCOL_REVISION: &str = "2026-09-01";
const READ_ROW: &str = "read";
const WRITE_ROW: &str = "write";
const SLOT: &str = "route";
const OLD_ISSUER: &str = "https://as-old.test";
const NEW_ISSUER: &str = "https://as-new.test";

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
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
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: false,
        price: None,
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
        key,
        _dir: dir,
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

fn detect(fixture: &Fixture, listed: &[&str]) -> Vec<ConnectorCredentialBinding> {
    fixture
        .vault
        .detect_connector_credential_issuer(&ConnectorIssuerDetection {
            key_ref: fixture.key,
            authorization_servers: listed.iter().map(|issuer| (*issuer).to_owned()).collect(),
            witness: format!("protected-resource metadata lists {listed:?}"),
        })
        .expect("detection reads the bindings")
}

fn hold(fixture: &Fixture, row: &str) -> Option<&'static str> {
    fixture
        .vault
        .connector_issuer_hold(&fixture.key, row)
        .expect("the hold reads")
}

#[test]
fn detected_issuer_holds_dependent_rows_without_reask() {
    let fixture = fixture();
    let binding = baseline(&fixture);
    assert_eq!(hold(&fixture, WRITE_ROW), None, "a baseline holds nothing");

    let drifted = detect(&fixture, &[NEW_ISSUER]);

    assert_eq!(drifted.len(), 1, "the one binding drifted: {drifted:?}");
    let detected = &drifted[0];
    assert_eq!(detected.binding_ref, binding.binding_ref);
    assert_eq!(
        detected.issuer, OLD_ISSUER,
        "the binding keeps its issuer until accepted"
    );
    assert_eq!(detected.generation, 1, "detection moves no generation");
    let transition = detected
        .transition
        .as_ref()
        .expect("detection records the change");
    assert_eq!(transition.old_issuer, OLD_ISSUER);
    assert_eq!(transition.new_issuer, NEW_ISSUER);
    assert_eq!(
        transition.proposed_credential_ref, binding.credential_ref,
        "the engine saw no new credential"
    );
    let ConnectorIssuerTransitionState::Drafted { slate_ref } = transition.state else {
        panic!("detection drafts the forced re-ask: {:?}", transition.state);
    };

    let halt = fixture
        .vault
        .open_issuer_halt_for_connector(CONNECTOR)
        .expect("the halt reads")
        .expect("the connector shows the open change");
    assert_eq!(halt.old_issuer, OLD_ISSUER);
    assert_eq!(halt.new_issuer, NEW_ISSUER);
    assert_eq!(halt.dependent_rows, vec![WRITE_ROW.to_owned()]);
    assert_eq!(
        hold(&fixture, WRITE_ROW),
        Some(CONNECTOR_ISSUER_HOLD_REASON),
        "the dependent row holds"
    );
    assert_eq!(
        hold(&fixture, READ_ROW),
        None,
        "an unrelated row keeps running"
    );
    assert_eq!(
        fixture
            .vault
            .connector_credential_binding(&binding.binding_ref)
            .expect("the binding reads")
            .as_ref(),
        Some(detected),
        "the change is durable as answered"
    );

    let again = detect(&fixture, &[NEW_ISSUER]);
    assert_eq!(again.len(), 1);
    assert_eq!(
        again[0].transition, detected.transition,
        "a repeat detection keeps the one open change and its draft"
    );
    assert!(
        matches!(
            again[0].transition.as_ref().map(|open| &open.state),
            Some(ConnectorIssuerTransitionState::Drafted { slate_ref: same }) if *same == slate_ref
        ),
        "no second re-ask is drafted"
    );
}

#[test]
fn listed_issuer_is_not_drift() {
    let fixture = fixture();
    let binding = baseline(&fixture);

    let drifted = detect(&fixture, &["https://as-other.test", OLD_ISSUER]);

    assert!(
        drifted.is_empty(),
        "a listed issuer is not drift: {drifted:?}"
    );
    assert_eq!(
        fixture
            .vault
            .connector_credential_binding(&binding.binding_ref)
            .expect("the binding reads"),
        Some(binding),
        "the binding is unchanged"
    );
    assert_eq!(
        fixture
            .vault
            .open_issuer_halt_for_connector(CONNECTOR)
            .expect("the halt reads"),
        None
    );
    assert_eq!(hold(&fixture, WRITE_ROW), None);
}

#[test]
fn no_baseline_records_nothing() {
    let fixture = fixture();

    let drifted = detect(&fixture, &[NEW_ISSUER]);

    assert!(drifted.is_empty(), "no binding, no change: {drifted:?}");
    assert_eq!(
        fixture
            .vault
            .open_issuer_halt_for_connector(CONNECTOR)
            .expect("the halt reads"),
        None,
        "the engine never chooses a connector's first issuer"
    );
    assert_eq!(hold(&fixture, WRITE_ROW), None);
    assert_eq!(hold(&fixture, READ_ROW), None);
}

#[test]
fn owner_accept_lifts_detected_hold() {
    let fixture = fixture();
    let binding = baseline(&fixture);
    let drifted = detect(&fixture, &[NEW_ISSUER]);
    let Some(ConnectorIssuerTransitionState::Drafted { slate_ref }) = drifted
        .first()
        .and_then(|detected| detected.transition.as_ref())
        .map(|open| open.state.clone())
    else {
        panic!("detection drafts the forced re-ask: {drifted:?}");
    };
    assert_eq!(
        hold(&fixture, WRITE_ROW),
        Some(CONNECTOR_ISSUER_HOLD_REASON)
    );
    let revision = fixture
        .vault
        .connector_slate(slate_ref)
        .expect("the drafted revision reads")
        .expect("the drafted revision exists")
        .revision();

    fixture
        .vault
        .accept_connector_slate_revision(&fixture.owner, slate_ref, revision)
        .expect("the owner accepts the issuer revision");

    let accepted = fixture
        .vault
        .connector_credential_binding(&binding.binding_ref)
        .expect("the binding reads")
        .expect("the binding stays");
    assert_eq!(
        accepted.issuer, NEW_ISSUER,
        "the binding answers for the new issuer"
    );
    assert_eq!(accepted.generation, 2, "acceptance moves the generation");
    assert!(
        matches!(
            accepted.transition.as_ref().map(|change| &change.state),
            Some(ConnectorIssuerTransitionState::Accepted { slate_ref: same }) if *same == slate_ref
        ),
        "the change stays as accepted evidence"
    );
    assert_eq!(
        hold(&fixture, WRITE_ROW),
        None,
        "the accepted row runs again"
    );
    assert_eq!(
        fixture
            .vault
            .open_issuer_halt_for_connector(CONNECTOR)
            .expect("the halt reads"),
        None
    );
}

//! Census row L5-15 (Engine ruling L5-15-PROTOCOL-NARROW = A): a catalog
//! connector whose protocol revision changes, and whose next slate only
//! narrows, keeps the owner's stamp. ARCH-0072 #drift: "A revision that only
//! narrows carries forward." The key still halts to Pending and re-qualifies
//! (ARCH-0054 #drift), and the owner is asked once, never left with a silent
//! state. A widened row still needs the owner's tap.
//!
//! On unmodified main the narrow slate starts unstamped. The owner's
//! attestation is then refused, and a probe re-qualification retires every
//! per-grant key the owner gave an agent. So the first case fails at the
//! carried stamp. The second case is the widening guard and holds on main
//! too.
//!
//! Public crate surface only: register, stamp, attest, consent, revise, and
//! read back each slate, key, grant, consent view and decision ask. No
//! connector tool or network request runs. The question's queue name is
//! spelled out here, not imported.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! connector_protocol_narrow_keeps_stamp`.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget, ConnectorKeySpec,
    ConnectorKeyStatus, ConnectorToolConsent, ConnectorToolConsentRow, ConnectorToolGrant,
    SlateDataClass, SlateDisposition, SlateDraftRow, SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::tool_scope::DataClass;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 1_700_000_000;
const SERVER: &str = "harbor_ledger";
const ENDPOINT: &str = "https://connector.invalid/mcp";
/// The decision-ask queue a narrowing protocol revision's question rides.
const NARROW_ASK_QUEUE: &str = "connector_key.protocol_revision.narrow";
/// The owner door the question names as the one act that switches it off.
const SWITCH_OFF_DOOR: &str = "POST /v1/owner/connectors/enabled";

struct Fixture {
    vault: Vault,
    owner_person: EntityId,
    catalog: EntityId,
    first_slate: EntityId,
    _dir: tempfile::TempDir,
}

fn tool(name: &str) -> SlateToolManifest {
    SlateToolManifest {
        name: name.to_owned(),
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
    }
}

/// Stores a slate of `manifest` whose drafted rows `tighten` may change.
fn store_slate(
    vault: &Vault,
    manifest: &[SlateToolManifest],
    tighten: impl FnOnce(&mut [SlateDraftRow]),
) -> EntityId {
    let mut rows = draft_connector_slate(manifest);
    tighten(&mut rows);
    vault
        .store_connector_slate(
            manifest,
            &serde_json::to_string(&rows).expect("typed slate draft"),
        )
        .expect("store the connector slate")
}

fn owner(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// A vault whose catalog connector serves `read` and `write` at protocol
/// revision "A", its slate stamped by the owner and attested Active.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let first_slate = store_slate(&vault, &[tool("read"), tool("write")], |_| {});
    let mut spec = ConnectorKeySpec::new(SERVER);
    spec.slate_ref = Some(first_slate);
    spec.protocol_revision = Some("A".to_owned());
    let (catalog, pending) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: SERVER.to_owned(),
                connector: SERVER.to_owned(),
                summary: "protocol narrow fixture".to_owned(),
                verbs: vec!["read".to_owned(), "write".to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: NOW,
            },
            spec,
            NOW,
        )
        .expect("register the pending catalog connector");
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    let fixture = Fixture {
        vault,
        owner_person,
        catalog,
        first_slate,
        _dir: dir,
    };
    let owner = owner(&fixture);
    let slate = fixture
        .vault
        .connector_slate(first_slate)
        .expect("read the slate")
        .expect("stored slate");
    fixture
        .vault
        .stamp_connector_slate(
            &owner,
            first_slate,
            slate.revision(),
            &BTreeMap::new(),
            None,
        )
        .expect("owner stamps the first slate");
    let active = fixture
        .vault
        .attest_connector_key(&owner, &catalog, "A", NOW + 1)
        .expect("owner attests revision A");
    assert_eq!(active.status, ConnectorKeyStatus::Active);
    fixture
}

/// The owner consents both tools for `agent`: one grant and one per-grant
/// key each.
fn consent_both(fixture: &Fixture, agent: EntityId) -> Vec<ConnectorToolGrant> {
    let rows = ["read", "write"]
        .into_iter()
        .map(|tool| ConnectorToolConsentRow {
            tool: tool.to_owned(),
            data_class_ceiling: DataClass::Personal,
            headers: false,
        })
        .collect();
    let granted = fixture
        .vault
        .consent_connector_tools(
            &owner(fixture),
            &ConnectorToolConsent {
                connector: SERVER.to_owned(),
                target: ConnectorConsentTarget::Actor(agent),
                endpoint: ENDPOINT.to_owned(),
                rows,
            },
        )
        .expect("owner consents read and write for the agent");
    assert_eq!(granted.len(), 2, "{granted:?}");
    granted
}

fn granted<'a>(grants: &'a [ConnectorToolGrant], tool: &str) -> &'a ConnectorToolGrant {
    grants
        .iter()
        .find(|grant| grant.tool == tool)
        .expect("the tool's grant")
}

fn key_status(vault: &Vault, grant: &ConnectorToolGrant) -> ConnectorKeyStatus {
    let key = EntityId::from_hex(&grant.key_id).expect("per-grant key id");
    vault
        .get_connector_key(&key)
        .expect("read the per-grant key")
        .expect("the per-grant key exists")
        .status
}

fn grant_active(vault: &Vault, grant: &ConnectorToolGrant) -> bool {
    let id = EntityId::from_hex(&grant.grant_id).expect("grant id");
    vault
        .get_standing_outbound_grant(&id)
        .expect("read the grant")
        .is_some_and(|grant| grant.is_active())
}

/// The wall clock in Unix seconds. The consent door stamps its per-grant
/// keys with it, so a later status change must not be dated before it.
fn wall_clock_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads after 1970")
        .as_secs()
}

/// The open asks on the narrowing protocol revision's queue.
fn narrow_asks(vault: &Vault) -> Vec<oneiron::llm::decision::DecisionAsk> {
    vault
        .decision_asks(None, 100, true)
        .expect("read the open decision asks")
        .into_iter()
        .filter(|ask| ask.queue_pin.model == NARROW_ASK_QUEUE)
        .collect()
}

#[test]
fn a_narrowing_protocol_revision_keeps_the_stamp_and_the_agents_tools() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let agent = vault
        .ensure_agent_principal("harbor.ledger.agent")
        .expect("named agent principal");
    let grants = consent_both(&fixture, agent);
    let consented_at = wall_clock_seconds();

    // Revision B drops `write` and tightens `read` to always ask.
    let narrow = store_slate(vault, &[tool("read")], |rows| {
        rows[0].disposition = SlateDisposition::AlwaysAsk;
    });
    let pending = vault
        .revise_connector_protocol(&fixture.catalog, "B", narrow, consented_at + 2)
        .expect("revise to protocol revision B");
    assert_eq!(pending.status, ConnectorKeyStatus::Pending, "the key halts");
    assert!(!pending.consent_required, "a pure narrow re-asks no row");

    let prior = vault
        .connector_slate(fixture.first_slate)
        .expect("read the first slate")
        .expect("first slate");
    let next = vault
        .connector_slate(narrow)
        .expect("read the narrow slate")
        .expect("narrow slate");
    assert_eq!(
        next.owner_actor(),
        prior.owner_actor(),
        "the owner's stamp carries to the narrow slate",
    );
    assert!(next.stamp_holds(), "the carried stamp holds");
    assert_eq!(next.revision(), prior.revision());

    let asks = narrow_asks(vault);
    assert_eq!(asks.len(), 1, "one owner question: {asks:?}");
    let ask = &asks[0];
    assert!(ask.is_open());
    assert!(
        ask.evidence.contains(&fixture.catalog),
        "{:?}",
        ask.evidence
    );
    let text = &ask.question.text;
    for named in [
        SERVER,
        "from A to B",
        "Narrowed: read.",
        "Dropped: write.",
        SWITCH_OFF_DOOR,
    ] {
        assert!(text.contains(named), "the question names {named:?}: {text}");
    }

    let active = vault
        .attest_connector_key(&owner(&fixture), &fixture.catalog, "B", consented_at + 3)
        .expect("the owner attests revision B without a new tap");
    assert_eq!(active.status, ConnectorKeyStatus::Active);

    let read = granted(&grants, "read");
    let write = granted(&grants, "write");
    assert_eq!(key_status(vault, read), ConnectorKeyStatus::Active);
    assert!(grant_active(vault, read), "the agent keeps its read grant");
    assert_eq!(key_status(vault, write), ConnectorKeyStatus::Revoked);
    assert!(
        !grant_active(vault, write),
        "a dropped tool's grant retires"
    );
    let view = vault
        .connector_consent_view(&owner(&fixture), SERVER, Some(agent))
        .expect("read the agent's consent")
        .expect("the catalog exists");
    assert!(view.ready, "a consent can be written again at once");
    let rows: Vec<(&str, Option<&str>)> = view
        .rows
        .iter()
        .map(|row| (row.tool.as_str(), row.grant_id.as_deref()))
        .collect();
    assert_eq!(rows, vec![("read", Some(read.grant_id.as_str()))]);
}

#[test]
fn a_widening_protocol_revision_still_needs_the_owners_tap() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let mut widened = tool("read");
    widened.sends_outward = true;
    let next_slate = store_slate(vault, &[widened, tool("write")], |_| {});
    let pending = vault
        .revise_connector_protocol(&fixture.catalog, "C", next_slate, NOW + 2)
        .expect("revise to protocol revision C");
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    assert!(pending.consent_required, "a widened row re-asks");
    let next = vault
        .connector_slate(next_slate)
        .expect("read the widened slate")
        .expect("widened slate");
    assert!(
        next.owner_actor().is_none(),
        "no stamp carries to a widening"
    );
    assert!(
        vault
            .attest_connector_key(&owner(&fixture), &fixture.catalog, "C", NOW + 3)
            .is_err(),
        "the owner must stamp the widened slate first",
    );
    assert!(
        narrow_asks(vault).is_empty(),
        "a widening asks on its own path"
    );
}

//! L5-11 (ARCH-0054 #auth "PRM 401 bootstrap"; ARCH-0072 #drift): the
//! issuer watch a connector send runs at a refusal. A 401 with a `Bearer`
//! challenge reads the connector's own protected-resource metadata (RFC
//! 9728) at the URL derived from the installed endpoint, once and with no
//! credential. When it names the endpoint and no longer lists the bound
//! issuer, the dependent row holds and an unrelated row keeps running. A
//! metadata reply for another resource, or one that still lists the bound
//! issuer (an expired token), records nothing; any other refusal reads no
//! metadata at all.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test connector_issuer_prm_refusal`
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use oneiron::authority::MachineRole;
use oneiron::connector_key::{
    CONNECTOR_ISSUER_HOLD_REASON, ConnectorBindingDependent, ConnectorCallClass,
    ConnectorCatalogEntry, ConnectorIssuerObservation, ConnectorKeySpec, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::connector_issuer_watch::{resource_metadata_url, watch_refusal};
use serde_json::json;

const NOW: u64 = 1_700_000_000;
const CONNECTOR: &str = "memory";
const PROTOCOL_REVISION: &str = "2026-09-01";
const READ_ROW: &str = "read";
const WRITE_ROW: &str = "write";
const OLD_ISSUER: &str = "https://as-old.test";
const NEW_ISSUER: &str = "https://as-new.test";
const BEARER_CHALLENGE: &str = "Bearer error=\"invalid_token\"";
const METADATA_REQUEST_LINE: &str = "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1";

struct Fixture {
    vault: Vault,
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

/// A rooted vault whose owner attested `CONNECTOR` (rows `read` and
/// `write`) and baselined its route's issuer as `OLD_ISSUER`, with only the
/// `write` row depending on it.
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
    vault
        .observe_connector_credential_issuer(
            &owner,
            &ConnectorIssuerObservation {
                connector: CONNECTOR.to_owned(),
                slot: "route".to_owned(),
                issuer: OLD_ISSUER.to_owned(),
                credential_ref: "custody:route-token".to_owned(),
                expected_generation: 0,
                dependents: vec![ConnectorBindingDependent {
                    key_ref: key,
                    tool: Some(WRITE_ROW.to_owned()),
                }],
                witness: "owner read the route's issuer".to_owned(),
            },
        )
        .expect("owner baselines the route's issuer");
    Fixture {
        vault,
        key,
        _dir: dir,
    }
}

/// A connector origin on loopback that answers its metadata path with one
/// JSON body and any other path with 404, keeping each request's head.
struct ConnectorOrigin {
    /// The installed MCP endpoint, `http://127.0.0.1:<port>/mcp`.
    endpoint: String,
    heads: Arc<Mutex<Vec<String>>>,
}

impl ConnectorOrigin {
    /// Serves the metadata `body(endpoint)` on a free loopback port.
    fn serve(body: impl Fn(&str) -> serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let endpoint = format!("http://127.0.0.1:{port}/mcp");
        let metadata = body(&endpoint).to_string();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let found = head.starts_with(METADATA_REQUEST_LINE);
                kept.lock().expect("heads lock").push(head);
                let reply = if found {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{metadata}",
                        metadata.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                };
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self { endpoint, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads lock").clone()
    }
}

fn hold(fixture: &Fixture, row: &str) -> Option<&'static str> {
    fixture
        .vault
        .connector_issuer_hold(&fixture.key, row)
        .expect("the hold reads")
}

fn open_halt(fixture: &Fixture) -> Option<oneiron::connector_key::ConnectorIssuerHaltView> {
    fixture
        .vault
        .open_issuer_halt_for_connector(CONNECTOR)
        .expect("the halt reads")
}

#[test]
fn metadata_url_goes_between_host_and_path() {
    assert_eq!(
        resource_metadata_url("https://mcp.example.com/mcp").as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    );
    assert_eq!(
        resource_metadata_url("https://mcp.example.com/").as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource")
    );
    assert_eq!(
        resource_metadata_url("http://127.0.0.1:8080/a/b?tenant=1").as_deref(),
        Some("http://127.0.0.1:8080/.well-known/oauth-protected-resource/a/b?tenant=1")
    );
    assert_eq!(
        resource_metadata_url("https://mcp.example.com/mcp#part"),
        None
    );
    assert_eq!(resource_metadata_url("file:///etc/hosts"), None);
}

#[test]
fn prm_naming_another_issuer_holds_dependent_row() {
    let fixture = fixture();
    let origin = ConnectorOrigin::serve(
        |endpoint| json!({ "resource": endpoint, "authorization_servers": [NEW_ISSUER] }),
    );

    let drifted = watch_refusal(
        &fixture.vault,
        &origin.endpoint,
        &fixture.key,
        401,
        Some(BEARER_CHALLENGE),
    )
    .expect("the watch reads the refusal");

    assert_eq!(drifted.len(), 1, "the route's binding drifted: {drifted:?}");
    let heads = origin.heads();
    assert_eq!(heads.len(), 1, "one metadata read: {heads:?}");
    assert!(
        heads[0].starts_with(METADATA_REQUEST_LINE),
        "the read goes to the derived well-known path: {}",
        heads[0]
    );
    assert!(
        !heads[0].to_ascii_lowercase().contains("\r\nauthorization:"),
        "the metadata read presents no credential: {}",
        heads[0]
    );
    let halt = open_halt(&fixture).expect("the connector shows the open change");
    assert_eq!(halt.old_issuer, OLD_ISSUER);
    assert_eq!(halt.new_issuer, NEW_ISSUER);
    assert_eq!(halt.dependent_rows, vec![WRITE_ROW.to_owned()]);
    assert_eq!(
        hold(&fixture, WRITE_ROW),
        Some(CONNECTOR_ISSUER_HOLD_REASON),
        "the next send on the dependent row holds"
    );
    assert_eq!(
        hold(&fixture, READ_ROW),
        None,
        "an unrelated row keeps running"
    );
}

#[test]
fn prm_resource_mismatch_records_nothing() {
    let fixture = fixture();
    let origin = ConnectorOrigin::serve(|endpoint| {
        json!({
            "resource": endpoint.replace("/mcp", "/other"),
            "authorization_servers": [NEW_ISSUER],
        })
    });

    let drifted = watch_refusal(
        &fixture.vault,
        &origin.endpoint,
        &fixture.key,
        401,
        Some(BEARER_CHALLENGE),
    )
    .expect("the watch reads the refusal");

    assert!(
        drifted.is_empty(),
        "another resource's metadata: {drifted:?}"
    );
    assert_eq!(origin.heads().len(), 1, "the metadata was read once");
    assert_eq!(open_halt(&fixture), None);
    assert_eq!(hold(&fixture, WRITE_ROW), None);
}

#[test]
fn prm_listing_the_bound_issuer_records_nothing() {
    let fixture = fixture();
    let origin = ConnectorOrigin::serve(
        |endpoint| json!({ "resource": endpoint, "authorization_servers": [NEW_ISSUER, OLD_ISSUER] }),
    );

    let drifted = watch_refusal(
        &fixture.vault,
        &origin.endpoint,
        &fixture.key,
        401,
        Some(BEARER_CHALLENGE),
    )
    .expect("the watch reads the refusal");

    assert!(
        drifted.is_empty(),
        "a 401 under a listed issuer is an expired token, not drift: {drifted:?}"
    );
    assert_eq!(origin.heads().len(), 1, "the metadata was read once");
    assert_eq!(open_halt(&fixture), None);
    assert_eq!(hold(&fixture, WRITE_ROW), None);
}

#[test]
fn non_401_or_no_bearer_challenge_fetches_nothing() {
    let fixture = fixture();
    let origin = ConnectorOrigin::serve(
        |endpoint| json!({ "resource": endpoint, "authorization_servers": [NEW_ISSUER] }),
    );

    for (status, challenge) in [
        (403, Some(BEARER_CHALLENGE)),
        (401, None),
        (401, Some("Basic realm=\"connector\"")),
    ] {
        let drifted = watch_refusal(
            &fixture.vault,
            &origin.endpoint,
            &fixture.key,
            status,
            challenge,
        )
        .expect("the watch reads the refusal");
        assert!(
            drifted.is_empty(),
            "{status} {challenge:?} records nothing: {drifted:?}"
        );
    }

    assert_eq!(origin.heads(), Vec::<String>::new(), "no metadata read");
    assert_eq!(open_halt(&fixture), None);
    assert_eq!(hold(&fixture, WRITE_ROW), None);
}

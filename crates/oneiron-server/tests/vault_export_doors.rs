//! Public-door promise tests for the scoped and kept `vault.export` family
//! (ruling L4-23 = A: each test proves a promise at the door; DOOR-FAMILIES
//! Part 2, row 3).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>`, `GET`/`DELETE
//! /v1/core/export-transfers/{transfer_ref}` and `GET
//! /v1/core/export-secret-supplements/{request}`. Callers: the owner on the
//! host root credential; slips the host mints for the owner's own PERSON
//! (a full one, and readers narrowed to `read` + `export` with a sensitivity
//! ceiling); and an agent on its own paired credential, enrolled through a
//! real pairing redemption. Each proves its holder key on every request.
//! Each case owns its vault. No sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`):
//! - a scoped credential exports only what it may read
//!   (`cross/api/cross-arch-0002c-api-contract-appendices.md:259`), and a
//!   wide channel never widens it;
//! - a scoped export still skips custody rows
//!   (`oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:323`, "A scoped
//!   or contact export still skips them");
//! - a scoped export nulls credential fields at serialization
//!   (`oneiron/core/oneiron-arch-0038-deletion-redaction-canonical-snapshot-v1.md:164`);
//! - a kept whole-vault export (`vault.export` with `delivery: "transfer"`)
//!   is read and released by its exporter alone, admitted again at each read
//!   (`crates/oneiron-server/src/api/facade/export_transfer.rs:10-17`), and
//!   the exporter always gets his data out
//!   (`oneiron/agents/oneiron-arch-0027-import-pipeline-v1.md:337`);
//! - an export secret supplement answers only its owner
//!   (`export_transfer.rs:19-23`).
//!
//! The owner's own whole-vault `vault.export` is exercised only on its
//! positive path here; no case gates or changes it.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_export_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis, Sensitivity, SensitivityCeiling};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The length of a stored record's metadata header: a scoped export record's
/// body starts here (`ENTITY_METADATA_HEADER_LEN`,
/// `crates/oneiron-contracts/src/record_layout.rs:21`).
const RECORD_HEADER_LEN: usize = 33;

/// The channel every scoped export in this file names.
const CHANNEL: &str = "doors-custody-export";

/// The custody record a case registers.
const SECRET_NAME: &str = "doors-custody-export-secret";

/// The credential-named field a claim value carries, and its value: a
/// whole-value template, which the write door reads as a placeholder
/// (`batch/secret_scan/shapes.rs` `write_placeholder` / `template`) and the
/// release door does not (`RELEASE_PLACEHOLDERS`), so the claim lands and
/// its field is a credential at export.
const CREDENTIAL_FIELD: &str = "doors_custody_api_key";
const CREDENTIAL_VALUE: &str = "${DOORS_CUSTODY_EXPORT_KEY}";

/// The plain field beside it, which a field-level nulling keeps.
const PLAIN_FIELD: &str = "doors_custody_note";
const PLAIN_VALUE: &str = "kept beside the nulled field";

/// One credential a test holds: its slip, its holder key and its token.
struct Holder {
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential, the owner's own
/// PERSON, and one paired agent.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
    agent: Holder,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The owner on the host root credential.
    Owner,
    /// The paired agent.
    Agent,
    /// A slip the host minted.
    Minted(&'a Holder),
}

/// One answered request: its status, its headers and its body bytes.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }

    fn header(&self, name: header::HeaderName) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-export-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let owner_person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "export-doors-agent", [0x42; 32]).await;
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
        agent,
    }
}

/// Pairs one agent the way `token agent` does: a registered PERSON
/// principal, a principal-bound link narrowed to `core:read` and
/// `core:write`, redeemed over the real pairing route with the
/// holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Holder {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let key = SigningKey::from_bytes(&seed);
    let binding_key = key.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature = hex(&key.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    assert_eq!(
        slip.claims.actor_class.as_deref(),
        Some("agent"),
        "the redeemed slip binds an agent"
    );
    Holder { key, slip, token }
}

/// A scope at the root's own except for its verbs, `read` and `export`, and
/// its sensitivity ceiling.
fn reader_scope(sensitivity: SensitivityCeiling) -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "export".to_owned()]));
    scope.sensitivity = sensitivity;
    scope
}

/// A channel open on every axis: it narrows nothing, so what a scoped export
/// carries is the credential's own ceiling.
fn open_channel() -> Value {
    let all = json!({"kind": "all"});
    json!({
        "channel_ref": CHANNEL,
        "scope": {
            "worlds": all, "facets": all, "bands": all,
            "audience": all, "verbs": all, "sensitivity": all,
        },
    })
}

/// The ids of the records a scoped export reply carries.
fn record_ids(export: &Value) -> BTreeSet<String> {
    export["records"]
        .as_array()
        .expect("a scoped export lists its records")
        .iter()
        .map(|record| {
            record["record"]["id"]
                .as_str()
                .expect("a record names its id")
                .to_owned()
        })
        .collect()
}

/// One exported record's bytes: its metadata header and body.
fn record_bytes(record: &Value) -> Vec<u8> {
    record["bytes"]
        .as_array()
        .expect("a record carries its bytes")
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("a byte")).expect("a byte value"))
        .collect()
}

/// The value under the map key `key` anywhere in `value`, reading a binary
/// leaf as the MessagePack it may hold.
fn find_entry(value: &rmpv::Value, key: &str) -> Option<rmpv::Value> {
    match value {
        rmpv::Value::Map(entries) => entries.iter().find_map(|(name, inner)| {
            if name.as_str() == Some(key) {
                Some(inner.clone())
            } else {
                find_entry(inner, key)
            }
        }),
        rmpv::Value::Array(items) => items.iter().find_map(|item| find_entry(item, key)),
        rmpv::Value::Binary(bytes) => rmpv::decode::read_value(&mut bytes.as_slice())
            .ok()
            .and_then(|inner| find_entry(&inner, key)),
        _ => None,
    }
}

impl Served {
    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller<'_>) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let held = |holder: &Holder| {
            let transcript = holder
                .slip
                .binding_transcript(challenge.as_bytes())
                .expect("holder binding transcript");
            hex(&holder.key.sign(&transcript).to_bytes())
        };
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Agent => held(&self.agent),
            Caller::Minted(holder) => held(holder),
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token<'a>(&'a self, caller: Caller<'a>) -> &'a str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
            Caller::Minted(holder) => holder.token.as_str(),
        }
    }

    /// `caller` sends `method` to `path`, with `headers` and a JSON `body`
    /// when one is given.
    async fn send(
        &self,
        caller: Caller<'_>,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("route request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("route response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 256 * 1024 * 1024)
            .await
            .expect("route response body")
            .to_vec();
        Reply {
            status,
            headers,
            bytes,
        }
    }

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller<'_>, verb: &str, input: Value) -> (StatusCode, Value) {
        let reply = self
            .send(
                caller,
                Method::POST,
                &format!("/v1/core/facade/{verb}"),
                &[],
                Some(input),
            )
            .await;
        (reply.status, reply.json())
    }

    /// A slip the host mints for the owner's own PERSON, as a human, at
    /// `scope`: uncaveated, holder key from `seed`.
    fn mint_owner_slip(&self, seed: u8, scope: Scope) -> Holder {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [seed; 32];
        claims.holder_ref = self.owner_person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = scope;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("an owner slip");
        assert!(slip.caveats.is_empty(), "a mint carries no caveat");
        let token = slip.to_token().expect("owner slip token");
        Holder { key, slip, token }
    }

    /// The owner remembers one claim about himself with `value` at
    /// `sensitivity`: asserts the 200 and answers the claim's id.
    async fn remember(&self, predicate: &str, value: Value, sensitivity: &str) -> String {
        let (status, receipt) = self
            .post(
                Caller::Owner,
                "vault.remember",
                json!({
                    "predicate": predicate,
                    "subject_ref": self.owner_person.to_hex(),
                    "value": value,
                    "confidence": 0.9,
                    "source": "user_stated",
                    "scope": {"sensitivity": sensitivity},
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner remembers {predicate}: {receipt}"
        );
        receipt["claim"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("the receipt names the claim: {receipt}"))
            .to_owned()
    }

    /// `holder` exports, through an open channel, the rows of `kinds` (every
    /// kind when empty).
    async fn export_scoped(&self, caller: Caller<'_>, kinds: &[&str]) -> (StatusCode, Value) {
        self.post(
            caller,
            "vault.export.scoped",
            json!({"selector": {"kinds": kinds}, "channel": open_channel()}),
        )
        .await
    }

    /// `caller` exports the whole vault with `delivery: "transfer"`: asserts
    /// the 200 and answers the transfer reply.
    async fn keep_export(&self, caller: Caller<'_>) -> Value {
        let (status, kept) = self
            .post(caller, "vault.export", json!({"delivery": "transfer"}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner keeps an export: {kept}");
        let transfer_ref = kept["transfer_ref"].as_str().unwrap_or_default();
        assert!(
            transfer_ref.starts_with("export_transfer:"),
            "a kept export answers its transfer_ref: {kept}"
        );
        assert!(
            kept["bytes"].as_u64().is_some_and(|bytes| bytes > 0),
            "a kept export names its length: {kept}"
        );
        kept
    }
}

fn transfer_path(kept: &Value) -> String {
    format!(
        "/v1/core/export-transfers/{}",
        kept["transfer_ref"].as_str().expect("transfer_ref")
    )
}

/// A credential narrowed to the public band exports the public claim and
/// not the private one, though its channel is open on every axis; a reader
/// whose ceiling admits both exports both. The reply names the credential's
/// own ceiling. "a scoped credential exports only what it may read"
/// (cross-arch-0002c:259).
#[test]
fn scoped_export_carries_only_what_the_credential_reads() {
    run_on_engine_stack("export-doors-scoped-narrows", || async {
        let served = served().await;
        let public = served
            .remember(
                "doors.export.public_fact",
                json!({"text": "exported to every reader"}),
                "public",
            )
            .await;
        let private = served
            .remember(
                "doors.export.private_fact",
                json!({"text": "kept from the public reader"}),
                "private",
            )
            .await;
        let wide = served.mint_owner_slip(0x51, reader_scope(SensitivityCeiling::TOP));
        let narrow = served.mint_owner_slip(
            0x52,
            reader_scope(SensitivityCeiling::AtMost(Sensitivity::Public)),
        );

        let (status, export) = served
            .export_scoped(Caller::Minted(&wide), &["CLAIM"])
            .await;
        assert_eq!(status, StatusCode::OK, "the wide reader exports: {export}");
        let ids = record_ids(&export);
        assert!(
            ids.contains(&public) && ids.contains(&private),
            "a reader whose ceiling admits both claims exports both: {ids:?}"
        );

        let (status, export) = served
            .export_scoped(Caller::Minted(&narrow), &["CLAIM"])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the narrow reader exports: {export}"
        );
        let ids = record_ids(&export);
        assert!(
            ids.contains(&public),
            "the public claim is the narrow reader's: {ids:?}"
        );
        assert!(
            !ids.contains(&private),
            "an open channel never widens the credential: the private claim stays: {ids:?}"
        );
        assert_eq!(
            export["credential"],
            json!({
                "kind": "ceiling",
                "scope": serde_json::to_value(&narrow.slip.claims.scope).expect("scope JSON"),
            }),
            "the reply names the credential's own ceiling, not the channel's"
        );
    });
}

/// A credential that does not grant `export` is refused the scoped export
/// 403 and carries out no row: the paired agent (`core:read`, `core:write`)
/// and the owner's own read-only slip alike. The door admits by the export
/// verb, not by who holds the credential.
#[test]
fn scoped_export_refuses_a_credential_without_export() {
    run_on_engine_stack("export-doors-scoped-verb", || async {
        let served = served().await;
        served
            .remember(
                "doors.export.public_fact",
                json!({"text": "no reader without export reads this"}),
                "public",
            )
            .await;
        let mut read_only = Scope::top();
        read_only.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let reader = served.mint_owner_slip(0x53, read_only);
        for (who, caller) in [
            ("the paired agent", Caller::Agent),
            ("the owner's read-only slip", Caller::Minted(&reader)),
        ] {
            let (status, body) = served.export_scoped(caller, &[]).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{who}: {body}");
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{who}: {body}");
            assert!(
                body.get("records").is_none(),
                "{who} exports no row: {body}"
            );
        }
    });
}

/// After the owner registers a secret, a reader whose ceiling admits every
/// kind exports the vault's claims and no custody row: no record of the
/// custody kind, none that names the secret, none that carries its value.
/// "A scoped or contact export still skips them" (arch-0069:323).
#[test]
fn scoped_export_skips_custody_rows() {
    run_on_engine_stack("export-doors-scoped-custody", || async {
        let served = served().await;
        let raw = format!("doors_custody_export_{}", EntityId::now().to_hex());
        let base64 = STANDARD.encode(raw.as_bytes());
        let (status, registered) = served
            .post(
                Caller::Owner,
                "vault.secrets.register",
                json!({
                    "name": SECRET_NAME,
                    "class": "custody-portable",
                    "device_only": false,
                    "rung": 0,
                    "value_base64": base64,
                    "bindings": [],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner registers: {registered}");
        let control = served
            .remember(
                "doors.export.public_fact",
                json!({"text": "the export is not empty"}),
                "public",
            )
            .await;
        let wide = served.mint_owner_slip(0x54, reader_scope(SensitivityCeiling::TOP));

        let (status, export) = served.export_scoped(Caller::Minted(&wide), &[]).await;
        assert_eq!(status, StatusCode::OK, "the wide reader exports: {export}");
        assert!(
            record_ids(&export).contains(&control),
            "the export carries the reader's claim"
        );
        for record in export["records"].as_array().expect("records") {
            let kind = record["record"]["kind"].as_str().unwrap_or_default();
            assert_ne!(kind, "SECRET_CUSTODY", "a custody row left: {record}");
            let bytes = record_bytes(record);
            for (what, needle) in [
                ("the secret's name", SECRET_NAME.as_bytes()),
                ("the secret's value", raw.as_bytes()),
                ("the secret's base64", base64.as_bytes()),
            ] {
                assert!(
                    !contains(&bytes, needle),
                    "a {kind} record carries {what}: {}",
                    record["record"]
                );
            }
        }
    });
}

/// A claim whose value holds a credential-named field exports with that
/// field's value null and the plain field beside it kept, and the credential
/// leaves in no byte. "A scoped export or an export to a contact nulls
/// credential fields at serialization time" (arch-0038:164).
#[test]
fn scoped_export_nulls_credential_fields() {
    run_on_engine_stack("export-doors-scoped-nulls", || async {
        let served = served().await;
        let mut value = serde_json::Map::new();
        value.insert(CREDENTIAL_FIELD.to_owned(), json!(CREDENTIAL_VALUE));
        value.insert(PLAIN_FIELD.to_owned(), json!(PLAIN_VALUE));
        let claim = served
            .remember(
                "doors.export.service_settings",
                Value::Object(value),
                "public",
            )
            .await;
        let wide = served.mint_owner_slip(0x55, reader_scope(SensitivityCeiling::TOP));

        let (status, export) = served
            .export_scoped(Caller::Minted(&wide), &["CLAIM"])
            .await;
        assert_eq!(status, StatusCode::OK, "the wide reader exports: {export}");
        let records = export["records"].as_array().expect("records");
        for record in records {
            assert!(
                !contains(&record_bytes(record), CREDENTIAL_VALUE.as_bytes()),
                "an exported record carries the credential: {}",
                record["record"]
            );
        }
        let record = records
            .iter()
            .find(|record| record["record"]["id"].as_str() == Some(claim.as_str()))
            .unwrap_or_else(|| panic!("the claim is exported, its field nulled: {export}"));
        let bytes = record_bytes(record);
        let body = rmpv::decode::read_value(&mut &bytes[RECORD_HEADER_LEN..])
            .expect("the exported claim body is MessagePack");
        assert_eq!(
            find_entry(&body, CREDENTIAL_FIELD),
            Some(rmpv::Value::Nil),
            "the credential field is kept, its value null: {body}"
        );
        assert_eq!(
            find_entry(&body, PLAIN_FIELD),
            Some(rmpv::Value::from(PLAIN_VALUE)),
            "the plain field beside it is kept: {body}"
        );
    });
}

/// The owner keeps a whole-vault export and reads it back: whole (200, the
/// archive's length and digest as its ETag, a zip), one range (206, the
/// first ten bytes, its Content-Range); a DELETE lets it go (204) and a read
/// after answers 404. "if the data is yours, you can always take it out"
/// (arch-0027:337).
#[test]
fn kept_export_reads_whole_and_by_range_then_releases() {
    run_on_engine_stack("export-doors-kept-bytes", || async {
        let served = served().await;
        let kept = served.keep_export(Caller::Owner).await;
        let path = transfer_path(&kept);
        let len = kept["bytes"].as_u64().expect("length");
        let digest = kept["digest"].as_str().expect("digest").to_owned();

        let whole = served
            .send(Caller::Owner, Method::GET, &path, &[], None)
            .await;
        assert_eq!(whole.status, StatusCode::OK, "{}", whole.json());
        assert_eq!(whole.bytes.len() as u64, len, "the whole archive");
        assert!(whole.bytes.starts_with(b"PK"), "the archive is a zip");
        assert_eq!(
            whole.header(header::ETAG),
            Some(format!("\"{digest}\"")),
            "the ETag is the archive's digest"
        );
        assert_eq!(
            whole.header(header::ACCEPT_RANGES).as_deref(),
            Some("bytes")
        );

        let range = served
            .send(
                Caller::Owner,
                Method::GET,
                &path,
                &[("range", "bytes=0-9")],
                None,
            )
            .await;
        assert_eq!(range.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(range.bytes, whole.bytes[..10], "the first ten bytes");
        assert_eq!(
            range.header(header::CONTENT_RANGE),
            Some(format!("bytes 0-9/{len}"))
        );

        let released = served
            .send(Caller::Owner, Method::DELETE, &path, &[], None)
            .await;
        assert_eq!(
            released.status,
            StatusCode::NO_CONTENT,
            "{}",
            released.json()
        );
        let after = served
            .send(Caller::Owner, Method::GET, &path, &[], None)
            .await;
        assert_eq!(
            after.status,
            StatusCode::NOT_FOUND,
            "a released export is gone"
        );
        assert_eq!(error_code(&after.json()), Some("NOT_FOUND"));
    });
}

/// A kept export answers no one but its exporter, and a refusal lets
/// nothing go. The paired agent is refused 403 at the byte route, at its
/// DELETE and at the transfer verbs. The owner's own full slip, another
/// principal than the host root that exported, reads 404 (the exporter
/// check answers as for an unknown ref); the export it keeps itself is in
/// turn 404 to the host root. Each exporter still reads its own.
#[test]
fn kept_export_answers_only_its_exporter() {
    run_on_engine_stack("export-doors-kept-exporter", || async {
        let served = served().await;
        let kept = served.keep_export(Caller::Owner).await;
        let path = transfer_path(&kept);
        let transfer_ref = kept["transfer_ref"].as_str().expect("transfer_ref");

        for method in [Method::GET, Method::DELETE] {
            let refused = served
                .send(Caller::Agent, method.clone(), &path, &[], None)
                .await;
            assert_eq!(
                refused.status,
                StatusCode::FORBIDDEN,
                "the agent's {method}: {}",
                refused.json()
            );
            assert_eq!(error_code(&refused.json()), Some("FORBIDDEN"));
        }
        for (verb, input) in [
            (
                "vault.export.transfer.read",
                json!({"transfer_ref": transfer_ref, "length": 10}),
            ),
            (
                "vault.export.transfer.release",
                json!({"transfer_ref": transfer_ref}),
            ),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "the agent's {verb}: {body}");
            assert!(body.get("bytes_base64").is_none(), "{verb}: {body}");
        }

        let own = served.mint_owner_slip(0x56, Scope::top());
        let stranger = served
            .send(Caller::Minted(&own), Method::GET, &path, &[], None)
            .await;
        assert_eq!(
            stranger.status,
            StatusCode::NOT_FOUND,
            "another principal reads no export it did not keep: {}",
            stranger.json()
        );
        assert_eq!(error_code(&stranger.json()), Some("NOT_FOUND"));

        let its_own = served.keep_export(Caller::Minted(&own)).await;
        let its_path = transfer_path(&its_own);
        let crossed = served
            .send(Caller::Owner, Method::GET, &its_path, &[], None)
            .await;
        assert_eq!(
            crossed.status,
            StatusCode::NOT_FOUND,
            "the host root reads no export the owner's slip kept: {}",
            crossed.json()
        );
        let mine = served
            .send(Caller::Minted(&own), Method::GET, &its_path, &[], None)
            .await;
        assert_eq!(mine.status, StatusCode::OK, "{}", mine.json());

        let whole = served
            .send(Caller::Owner, Method::GET, &path, &[], None)
            .await;
        assert_eq!(
            whole.status,
            StatusCode::OK,
            "no refusal let the exporter's export go: {}",
            whole.json()
        );
        assert_eq!(
            whole.bytes.len() as u64,
            kept["bytes"].as_u64().expect("length")
        );
    });
}

/// The transfer verbs read the same kept export the byte route does: two
/// pieces (ten bytes, then the rest) join to the archive the route serves,
/// each naming its total and digest, the last its end; the release verb
/// lets it go, after which the route and the verb answer 404.
#[test]
fn kept_export_transfer_verbs_match_the_byte_route() {
    run_on_engine_stack("export-doors-kept-verbs", || async {
        let served = served().await;
        let kept = served.keep_export(Caller::Owner).await;
        let path = transfer_path(&kept);
        let transfer_ref = kept["transfer_ref"].as_str().expect("transfer_ref");
        let len = kept["bytes"].as_u64().expect("length");
        let digest = kept["digest"].as_str().expect("digest");
        let whole = served
            .send(Caller::Owner, Method::GET, &path, &[], None)
            .await;
        assert_eq!(whole.status, StatusCode::OK, "{}", whole.json());

        let mut joined = Vec::new();
        for (input, ends) in [
            (
                json!({"transfer_ref": transfer_ref, "offset": 0, "length": 10}),
                false,
            ),
            (json!({"transfer_ref": transfer_ref, "offset": 10}), true),
        ] {
            let (status, piece) = served
                .post(Caller::Owner, "vault.export.transfer.read", input)
                .await;
            assert_eq!(status, StatusCode::OK, "{piece}");
            assert_eq!(piece["total_bytes"].as_u64(), Some(len), "{piece}");
            assert_eq!(piece["digest"].as_str(), Some(digest), "{piece}");
            assert_eq!(piece["end"].as_bool(), Some(ends), "{piece}");
            joined.extend(
                STANDARD
                    .decode(piece["bytes_base64"].as_str().expect("piece bytes"))
                    .expect("piece base64"),
            );
        }
        assert_eq!(joined, whole.bytes, "the pieces join to the archive");

        let (status, released) = served
            .post(
                Caller::Owner,
                "vault.export.transfer.release",
                json!({"transfer_ref": transfer_ref}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{released}");
        assert_eq!(released["released"].as_bool(), Some(true), "{released}");
        let after = served
            .send(Caller::Owner, Method::GET, &path, &[], None)
            .await;
        assert_eq!(
            after.status,
            StatusCode::NOT_FOUND,
            "a released export is gone"
        );
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.export.transfer.read",
                json!({"transfer_ref": transfer_ref}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

/// An export secret supplement answers only its owner: the agent is refused
/// 403 at the owner check; the owner reads 404 for an entry no export of his
/// recorded and for a malformed one, the same answer, so a read learns
/// nothing of what exists. No export in a one-install vault records a
/// request (no value is left unopened), so no case reads one.
#[test]
fn secret_supplement_answers_only_its_owner() {
    run_on_engine_stack("export-doors-supplement", || async {
        let served = served().await;
        let unknown = format!("/v1/core/export-secret-supplements/{}", "0".repeat(64));
        let refused = served
            .send(Caller::Agent, Method::GET, &unknown, &[], None)
            .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "the agent: {}",
            refused.json()
        );
        assert_eq!(error_code(&refused.json()), Some("FORBIDDEN"));

        for path in [
            unknown.clone(),
            "/v1/core/export-secret-supplements/not-an-entry".to_owned(),
        ] {
            let reply = served
                .send(Caller::Owner, Method::GET, &path, &[], None)
                .await;
            assert_eq!(
                reply.status,
                StatusCode::NOT_FOUND,
                "{path}: {}",
                reply.json()
            );
            assert_eq!(error_code(&reply.json()), Some("NOT_FOUND"), "{path}");
        }
    });
}

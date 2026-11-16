//! FIX SCREENING-PER-TOOL-SKIP (FIX-LIST 26659), PR C2: the secret lift
//! census reads a connector key record without the tool strings the owner
//! accepted as public at install (RULING SCREENING-SECRET-OVERRIDE = B;
//! ANSWERS SCREENING-SECRET-READERS = A and SCREENING-C2-EXPORT-SCOPE = B,
//! 16 Nov).
//!
//! A key's retained manifest holds the tool `docs_token`, whose `limit`
//! parameter description holds a secret-shaped string. Marked public (the
//! owner's "install it anyway" lifted the secret-shaped string), the census
//! leaves the record. Unmarked, or once the row changed since it was marked,
//! the census lifts it, and another secret in the same record is still
//! lifted. A public tool's name leaves only the fields that name tools: a
//! tool named `token` does not hide another tool's `"token":"..."` (review-c2
//! F1; at 5b76aba1c318 the census read that key clean), and a tool whose name
//! is the secret leaves the catalog's verbs too. A marked candidate meets
//! the probe listing as its unmarked twin does (review-c2 F2; at
//! 5b76aba1c318 it was refused as "connector declarations differ from
//! candidate").
//!
//! At PR C (2e746276611a) this file does not compile:
//! `with_public_secret_shape`, `public_secret_shape_tools` and the door
//! `test_doors::secret_lift_census` are new (E0599 / E0432).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test connector_key_public_secret_shape`.

#![cfg(oneiron_test_support)]

use oneiron::connector_key::qualification::{
    GroundingOracle, ProbeReply, ProbeRequest, ProbeTool, ProbeToolsList, QualificationCase,
    QualificationConnection, QualificationConnector, QualificationFailure, QualificationLimits,
    QualificationPlan,
};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeyStatus,
    ConnectorManifestQualifier, ConnectorToolSchema, ProbeManifestQualifier,
    ResolvedConnectorManifest, encode_connector_key_body,
};
use oneiron::registry::ENTITY_TYPE_CONNECTOR_KEY;
use oneiron::test_doors::secret_lift_census::census_hit;
use oneiron::{Vault, VaultConfig};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// The secret-shaped string the owner accepted in `docs_token`'s schema.
const ACCEPTED: &str = "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
/// Another secret-shaped string, in a tool the owner did not accept.
const OTHER: &str = "token=ghp_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210";
/// A tool name that is itself a secret-shaped string.
const SECRET_NAME: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const REVISION: &str = "2025-06-18";
const AT: u64 = 1_700_000_000;

fn fixture() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

/// One tool row whose `limit` parameter is described by `param`.
fn row(name: &str, param: &str) -> ConnectorToolSchema {
    tool_row(
        name,
        json!({
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": param}
            }
        }),
    )
}

/// One `read` tool row with `input_schema`, read from JSON as a stored row
/// is: a field the row type gains later reads as absent here.
fn tool_row(name: &str, input_schema: Value) -> ConnectorToolSchema {
    serde_json::from_value(json!({
        "name": name,
        "permissions": ["read"],
        "triggers": [],
        "input_schema": input_schema,
    }))
    .expect("tool row")
}

fn manifest(rows: Vec<ConnectorToolSchema>) -> ResolvedConnectorManifest {
    ResolvedConnectorManifest::resolve(rows).expect("resolved manifest")
}

/// A Pending key holding `retained` as its approved manifest at
/// [`REVISION`]: an Active key with a manifest also needs a qualification
/// receipt, which the census does not read (review-c2 F5).
fn pending_key(retained: ResolvedConnectorManifest) -> ConnectorKeyRecord {
    let mut record = ConnectorKeyRecord::active("docs", None, Vec::new(), AT);
    record.status = ConnectorKeyStatus::Pending;
    record.protocol_revision = Some(REVISION.to_owned());
    record.retained_manifest = Some(retained);
    record
}

/// A catalog-free scoped key's body holding `retained`.
fn key_body(retained: ResolvedConnectorManifest) -> Vec<u8> {
    encode_connector_key_body(&pending_key(retained)).expect("key body")
}

/// A catalog key's body holding `retained`, its catalog listing `verbs`.
fn catalog_key_body(retained: ResolvedConnectorManifest, verbs: &[&str]) -> Vec<u8> {
    let mut record = pending_key(retained);
    record.catalog = Some(ConnectorCatalogEntry {
        name: "docs".to_owned(),
        connector: "docs".to_owned(),
        summary: "Documents".to_owned(),
        verbs: verbs.iter().copied().map(str::to_owned).collect(),
        call_class: ConnectorCallClass::ScopedMcp,
        registered_at: AT,
    });
    encode_connector_key_body(&record).expect("catalog key body")
}

fn census_of(vault: &Vault, body: &[u8]) -> Option<&'static str> {
    census_hit(vault, ENTITY_TYPE_CONNECTOR_KEY, body).expect("census read")
}

fn census(vault: &Vault, retained: ResolvedConnectorManifest) -> Option<&'static str> {
    census_of(vault, &key_body(retained))
}

#[test]
fn an_unmarked_key_with_a_secret_shaped_schema_string_is_lifted() {
    let (_dir, vault) = fixture();
    let unmarked = manifest(vec![row("docs_token", ACCEPTED)]);
    assert_eq!(unmarked.public_secret_shape_tools().count(), 0);
    assert!(census(&vault, unmarked).is_some());
}

#[test]
fn a_key_whose_tool_the_owner_accepted_is_not_lifted() {
    let (_dir, vault) = fixture();
    let marked = manifest(vec![
        row("docs_read", "Maximum rows"),
        row("docs_token", ACCEPTED),
    ])
    .with_public_secret_shape(["docs_token", "docs_absent"]);
    let public: Vec<&str> = marked
        .public_secret_shape_tools()
        .map(|tool| tool.name.as_str())
        .collect();
    assert_eq!(public, ["docs_token"]);
    assert_eq!(census(&vault, marked), None);
}

#[test]
fn a_changed_row_drops_the_mark_and_the_census_lifts_it_again() {
    let (_dir, vault) = fixture();
    let marked =
        manifest(vec![row("docs_token", ACCEPTED)]).with_public_secret_shape(["docs_token"]);
    // The stored manifest keeps its mark while the tool's schema changes
    // under it: a new parameter.
    let mut stored: Value = serde_json::to_value(&marked).expect("manifest json");
    stored["tools"][0]["input_schema"]["properties"]["cursor"] = json!({"type": "string"});
    let changed: ResolvedConnectorManifest =
        serde_json::from_value(stored).expect("changed manifest");
    assert_eq!(changed.public_secret_shape_tools().count(), 0);
    assert!(census(&vault, changed).is_some());
}

#[test]
fn another_secret_in_the_same_key_is_still_lifted() {
    let (_dir, vault) = fixture();
    let marked = manifest(vec![row("docs_token", ACCEPTED), row("docs_other", OTHER)])
        .with_public_secret_shape(["docs_token"]);
    assert!(census(&vault, marked).is_some());
}

#[test]
fn a_manifest_without_a_mark_keeps_its_bytes() {
    let unmarked = manifest(vec![row("docs_token", ACCEPTED)]);
    let json = serde_json::to_value(&unmarked).expect("manifest json");
    assert!(json.get("public_secret_shape").is_none(), "{json}");
    let marked = unmarked.clone().with_public_secret_shape(["docs_token"]);
    assert_ne!(
        marked.hash().expect("marked hash"),
        unmarked.hash().expect("unmarked hash")
    );
}

/// `docs_other`, whose `auth` parameter defaults to `default`.
fn defaulted(default: Value) -> ConnectorToolSchema {
    tool_row(
        "docs_other",
        json!({
            "type": "object",
            "properties": {
                "auth": {"type": "object", "default": default}
            }
        }),
    )
}

#[test]
fn a_public_tool_name_leaves_another_tools_assignment_in_place() {
    let (_dir, vault) = fixture();
    let marked = |other: ConnectorToolSchema| {
        manifest(vec![row("token", ACCEPTED), other]).with_public_secret_shape(["token"])
    };
    assert_eq!(
        census(&vault, marked(defaulted(json!({"scope": "read"})))),
        None
    );
    // `docs_other` was not accepted: its own credential assignment, keyed
    // by the public tool's name, is still lifted.
    assert!(census(&vault, marked(defaulted(json!({"token": "Abc12345678"})))).is_some());
}

#[test]
fn a_public_tool_name_leaves_the_catalog_verbs() {
    let (_dir, vault) = fixture();
    let unmarked = manifest(vec![
        row("docs_read", "Maximum rows"),
        row(SECRET_NAME, "Maximum rows"),
    ]);
    let verbs = ["docs_read", SECRET_NAME];
    assert!(census_of(&vault, &catalog_key_body(unmarked.clone(), &verbs)).is_some());
    let marked = unmarked.with_public_secret_shape([SECRET_NAME]);
    assert_eq!(census_of(&vault, &catalog_key_body(marked, &verbs)), None);
}

/// A connector that lists the same tools on every connection and answers no
/// call.
struct Listing(Vec<ProbeTool>);
struct ListingConnection<'a>(&'a [ProbeTool]);

impl QualificationConnection for ListingConnection<'_> {
    fn tools_list(&mut self) -> Result<ProbeToolsList, QualificationFailure> {
        Ok(ProbeToolsList {
            tools: self.0.to_vec(),
            requests: Vec::new(),
        })
    }
    fn call(&mut self, _request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
        Err(QualificationFailure::Transport)
    }
}

impl QualificationConnector for Listing {
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
        Ok(Box::new(ListingConnection(&self.0)))
    }
    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
        Ok(Vec::new())
    }
}

struct NoSources;

impl GroundingOracle for NoSources {
    fn source_bytes(&self, _reference: &str) -> Option<Vec<u8>> {
        None
    }
    fn claim_sources(&self, _reference: &str) -> Option<Vec<String>> {
        None
    }
}

fn probe_case(tool: &str) -> QualificationCase {
    QualificationCase {
        call: ProbeRequest {
            id: "probe-1".to_owned(),
            name: tool.to_owned(),
            arguments: json!({}),
        },
        in_scope: true,
        allowed_predicates: BTreeSet::new(),
    }
}

/// Why the probe suite refuses `candidate` when the connector lists its
/// rows as they are and answers no call.
fn probe_refusal(candidate: &ResolvedConnectorManifest) -> String {
    let listing = Listing(
        candidate
            .tools()
            .iter()
            .map(|row| ProbeTool {
                name: row.name.clone(),
                input_schema: row.input_schema.clone(),
                trigger: None,
                result_types: BTreeSet::new(),
                writes: false,
            })
            .collect(),
    );
    let plan = QualificationPlan {
        reads: vec![probe_case("docs_token")],
        unanswerable: probe_case("docs_token"),
        injections: Vec::new(),
        scope_escape: Vec::new(),
        write: None,
        timeout_retry: None,
        handled_result_types: BTreeSet::new(),
        limits: QualificationLimits {
            tokens: 1_000,
            latency_ms: 1_000,
            budget_units: 1,
        },
    };
    let qualifier = ProbeManifestQualifier {
        connector: &listing,
        plan: &plan,
        oracle: &NoSources,
    };
    qualifier
        .qualify(candidate, REVISION)
        .expect_err("no probe call is answered")
        .to_string()
}

#[test]
fn a_marked_candidate_meets_the_probe_listing_as_its_unmarked_twin() {
    let unmarked = manifest(vec![row("docs_token", ACCEPTED)]);
    let marked = unmarked.clone().with_public_secret_shape(["docs_token"]);
    let refusal = probe_refusal(&unmarked);
    assert!(!refusal.contains("differ from candidate"), "{refusal}");
    assert_eq!(probe_refusal(&marked), refusal);
}

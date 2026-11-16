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
//! lifted.
//!
//! At PR C (2e746276611a) this file does not compile:
//! `with_public_secret_shape`, `public_secret_shape_tools` and the door
//! `test_doors::secret_lift_census` are new (E0599 / E0432).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test connector_key_public_secret_shape`.

#![cfg(oneiron_test_support)]

use oneiron::connector_key::{
    ConnectorKeyRecord, ConnectorToolSchema, ResolvedConnectorManifest, encode_connector_key_body,
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

fn fixture() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

/// One tool row whose `limit` parameter is described by `param`.
fn row(name: &str, param: &str) -> ConnectorToolSchema {
    ConnectorToolSchema {
        name: name.into(),
        permissions: BTreeSet::from(["read".to_owned()]),
        triggers: BTreeSet::new(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": param}
            }
        }),
    }
}

fn manifest(rows: Vec<ConnectorToolSchema>) -> ResolvedConnectorManifest {
    ResolvedConnectorManifest::resolve(rows).expect("resolved manifest")
}

/// A catalog-free scoped key holding `retained` as its approved manifest.
fn key_body(retained: ResolvedConnectorManifest) -> Vec<u8> {
    let mut record = ConnectorKeyRecord::active("docs", None, Vec::new(), 1_700_000_000);
    record.protocol_revision = Some("2025-06-18".to_owned());
    record.retained_manifest = Some(retained);
    encode_connector_key_body(&record).expect("key body")
}

fn census(vault: &Vault, retained: ResolvedConnectorManifest) -> Option<&'static str> {
    census_hit(vault, ENTITY_TYPE_CONNECTOR_KEY, &key_body(retained)).expect("census read")
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

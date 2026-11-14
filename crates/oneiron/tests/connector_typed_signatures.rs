//! Typed code-mode signatures for admitted connectors (L8-31, PR 1; agent
//! runtime `#code-mode-translation`, `#d10-built-state`: "schema-to-TypeScript
//! generation, output schemas included").
//!
//! - The renderer turns a resolved schema into the exact TypeScript the
//!   caller reads, bounded so one huge schema cannot flood a context.
//! - A tool's output schema rides the resolved manifest and the owner's
//!   slate: resolved as the input is, dropped (never a refusal) when it does
//!   not resolve, absent from the serialized row when there is none, and a
//!   changed one re-asks the owner.
//! - `connector.schema` on a registered, stamped, attested and consented
//!   connector serves the stamped output schema and both types.
//!
//! On main every test fails to build: no `connector_key::typescript`, no
//! `output_schema` row field and no typed reply fields exist there.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test connector_typed_signatures`

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::connector_key::typescript::{
    MAX_TYPESCRIPT_BYTES, input_typescript, output_typescript,
};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget, ConnectorDriftKind,
    ConnectorKeySpec, ConnectorKeyStatus, ConnectorManifestDrift, ConnectorToolConsent,
    ConnectorToolConsentRow, ConnectorToolSchema, ResolvedConnectorManifest, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::tool_scope::DataClass;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{ConnectorSchemaRequest, connector_schema_read};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TYPED_SIGNATURES_NOW: u64 = 1_700_000_000;
const TYPED_SIGNATURES_SERVER: &str = "typed_signatures";
const TYPED_SIGNATURES_REVISION: &str = "2026-09-01";
const TYPED_SIGNATURES_ENDPOINT: &str = "https://connector.invalid/mcp";

/// `search`'s input: a required described string and an optional integer.
fn search_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Words to find."},
            "limit": {"type": "integer", "minimum": 1}
        },
        "required": ["query"]
    })
}

/// `search`'s output: a list of hits, each an id and a score.
fn search_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "hits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}, "score": {"type": "number"}},
                    "required": ["id", "score"]
                }
            }
        },
        "required": ["hits"]
    })
}

const SEARCH_INPUT_TYPESCRIPT: &str =
    "{\n  /** Words to find. */\n  query: string;\n  limit?: number;\n}";
const SEARCH_OUTPUT_TYPESCRIPT: &str =
    "{\n  hits: {\n    id: string;\n    score: number;\n  }[];\n}";

fn tool_row(name: &str, input: Value, output: Option<Value>) -> ConnectorToolSchema {
    ConnectorToolSchema {
        name: name.to_owned(),
        permissions: BTreeSet::from(["read".to_owned()]),
        triggers: BTreeSet::new(),
        input_schema: input,
        output_schema: output,
    }
}

#[test]
fn typed_signatures_render_args_and_structured_content() {
    assert_eq!(input_typescript(&search_input()), SEARCH_INPUT_TYPESCRIPT);
    assert_eq!(
        output_typescript(&search_output()),
        SEARCH_OUTPUT_TYPESCRIPT
    );
    // Literal unions, nullable types, quoted keys, intersections and an
    // escaped doc comment.
    let mixed = json!({
        "type": "object",
        "properties": {
            "mode": {"enum": ["fast", "exact"]},
            "cursor": {"type": ["string", "null"], "format": "byte"},
            "x-trace": {"const": 7, "description": "Ends a comment */ early."},
            "pair": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "boolean"}], "items": false},
            "either": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "number"}}]},
            "free": {"type": "object", "additionalProperties": {"type": "integer"}}
        },
        "required": ["mode"],
        "additionalProperties": false
    });
    assert_eq!(
        input_typescript(&mixed),
        "{\n  mode: \"fast\" | \"exact\";\n  /** format: byte */\n  cursor?: string | null;\n  \
         /** Ends a comment *\\/ early. */\n  \"x-trace\"?: 7;\n  pair?: [string, boolean];\n  \
         either?: string | number[];\n  free?: {\n    [key: string]: number;\n  };\n}"
    );
    // An object with no declared keys admits any; `true` reads `unknown`.
    assert_eq!(
        input_typescript(&json!({"type": "object"})),
        "{\n  [key: string]: unknown;\n}"
    );
    assert_eq!(output_typescript(&json!(true)), "unknown");
    // One huge schema renders its fallback, never a flood.
    let properties: serde_json::Map<String, Value> = (0..600)
        .map(|n| {
            (
                format!("field_{n}"),
                json!({"type": "string", "description": "A long, repeated description of this field."}),
            )
        })
        .collect();
    let huge = json!({"type": "object", "properties": properties});
    assert!(serde_json::to_vec(&huge).map(|v| v.len()).unwrap_or(0) < 65_536);
    assert_eq!(input_typescript(&huge), "object");
    assert_eq!(output_typescript(&huge), "unknown");
    assert!(input_typescript(&search_input()).len() <= MAX_TYPESCRIPT_BYTES);
}

#[test]
fn an_output_schema_rides_the_resolved_manifest_and_a_change_reasks() -> TestResult {
    // A local ref in the output resolves as the input's would.
    let referenced = json!({
        "type": "object",
        "properties": {"hits": {"type": "array", "items": {"$ref": "#/$defs/hit"}}},
        "required": ["hits"],
        "$defs": {"hit": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "score": {"type": "number"}},
            "required": ["id", "score"]
        }}
    });
    let manifest = ResolvedConnectorManifest::resolve(vec![tool_row(
        "search",
        search_input(),
        Some(referenced),
    )])?;
    assert_eq!(manifest.tools()[0].output_schema, Some(search_output()));

    // An output that does not resolve (a cyclic ref), or that the owner's
    // slate cannot hold (a boolean property schema), is dropped; the
    // connector still resolves.
    for unusable in [
        json!({"$ref": "#/$defs/loop", "$defs": {"loop": {"$ref": "#/$defs/loop"}}}),
        json!({"type": "object", "properties": {"x": true}}),
    ] {
        let manifest = ResolvedConnectorManifest::resolve(vec![tool_row(
            "search",
            search_input(),
            Some(unusable),
        )])?;
        assert_eq!(manifest.tools()[0].output_schema, None);
    }

    // No output schema: the serialized rows are the pre-L8-31 ones, so the
    // stored manifests and stamped slates hash as before.
    let plain = ResolvedConnectorManifest::resolve(vec![tool_row("search", search_input(), None)])?;
    assert_eq!(
        serde_json::to_value(&plain.tools()[0])?.get("output_schema"),
        None
    );
    let slate_row = SlateToolManifest {
        name: "search".to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(search_input()),
        resolved_output_schema: None,
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: true,
        idempotent: true,
        price: None,
        http: None,
    };
    assert_eq!(
        serde_json::to_value(&slate_row)?.get("resolved_output_schema"),
        None
    );

    // A changed output schema drifts and re-asks the tool; the same one does not.
    let typed = ResolvedConnectorManifest::resolve(vec![tool_row(
        "search",
        search_input(),
        Some(search_output()),
    )])?;
    let retyped = ResolvedConnectorManifest::resolve(vec![tool_row(
        "search",
        search_input(),
        Some(json!({"type": "object", "properties": {"total": {"type": "integer"}}})),
    )])?;
    for (old, new) in [(&plain, &typed), (&typed, &retyped), (&typed, &plain)] {
        let drift = ConnectorManifestDrift::between(
            old,
            new,
            TYPED_SIGNATURES_REVISION,
            TYPED_SIGNATURES_REVISION,
        );
        assert_eq!(drift.kinds, BTreeSet::from([ConnectorDriftKind::Schema]));
        assert_eq!(drift.reconsent_tools, BTreeSet::from(["search".to_owned()]));
        assert!(drift.needs_reconsent());
    }
    let same = ConnectorManifestDrift::between(
        &typed,
        &typed.clone(),
        TYPED_SIGNATURES_REVISION,
        TYPED_SIGNATURES_REVISION,
    );
    assert!(!same.has_change());
    assert_ne!(plain.hash()?, typed.hash()?);
    Ok(())
}

/// One slate row: `search` reads and declares an output schema;
/// `delete_item` destroys and declares none.
fn typed_signatures_slate_row(name: &str) -> SlateToolManifest {
    let search = name == "search";
    SlateToolManifest {
        name: name.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(if search {
            search_input()
        } else {
            json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]})
        }),
        resolved_output_schema: search.then(search_output),
        trigger: None,
        destroys: !search,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: search,
        idempotent: search,
        price: None,
        http: None,
    }
}

#[test]
fn schema_read_serves_the_stamped_output_type() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_person = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner_person,
        &owner_person.to_hex(),
        true,
        GateDecisionId::now(),
    )?;

    // Register, stamp and attest the connector with its two tools.
    let manifest = vec![
        typed_signatures_slate_row("search"),
        typed_signatures_slate_row("delete_item"),
    ];
    let slate_id = vault.store_connector_slate(
        &manifest,
        &serde_json::to_string(&draft_connector_slate(&manifest))?,
    )?;
    let mut spec = ConnectorKeySpec::new(TYPED_SIGNATURES_SERVER);
    spec.slate_ref = Some(slate_id);
    spec.protocol_revision = Some(TYPED_SIGNATURES_REVISION.to_owned());
    let (catalog_id, pending) = vault.register_connector(
        ConnectorCatalogEntry {
            name: TYPED_SIGNATURES_SERVER.to_owned(),
            connector: TYPED_SIGNATURES_SERVER.to_owned(),
            summary: "typed signatures fixture".to_owned(),
            verbs: vec!["read".to_owned()],
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: TYPED_SIGNATURES_NOW,
        },
        spec,
        TYPED_SIGNATURES_NOW,
    )?;
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    let slate = vault.connector_slate(slate_id)?.ok_or("the stored slate")?;
    vault.stamp_connector_slate(&owner, slate_id, slate.revision(), &BTreeMap::new(), None)?;
    let active = vault.attest_connector_key(
        &owner,
        &catalog_id,
        TYPED_SIGNATURES_REVISION,
        TYPED_SIGNATURES_NOW + 1,
    )?;
    assert_eq!(active.status, ConnectorKeyStatus::Active);

    // The owner consents both tools for the caller, a named agent principal.
    let caller = vault.ensure_agent_principal("typed-signatures-caller")?;
    let granted = vault.consent_connector_tools(
        &owner,
        &ConnectorToolConsent {
            connector: TYPED_SIGNATURES_SERVER.to_owned(),
            target: ConnectorConsentTarget::Actor(caller),
            endpoint: TYPED_SIGNATURES_ENDPOINT.to_owned(),
            rows: ["search", "delete_item"]
                .into_iter()
                .map(|tool| ConnectorToolConsentRow {
                    tool: tool.to_owned(),
                    data_class_ceiling: DataClass::Personal,
                    headers: false,
                })
                .collect(),
        },
    )?;
    assert_eq!(granted.len(), 2);

    let memory = vault.memory(caller, EdgeActorClass::Agent);
    let read = |tool: &str| {
        connector_schema_read(
            &memory,
            ConnectorSchemaRequest {
                name: TYPED_SIGNATURES_SERVER.to_owned(),
                source: None,
                tool: tool.to_owned(),
            },
        )
    };
    let search = read("search")?;
    assert_eq!(search.reasons, Vec::<String>::new(), "search is callable");
    assert_eq!(search.input_schema, Some(search_input()));
    assert_eq!(search.output_schema, Some(search_output()));
    assert_eq!(
        search.input_typescript.as_deref(),
        Some(SEARCH_INPUT_TYPESCRIPT)
    );
    assert_eq!(
        search.output_typescript.as_deref(),
        Some(SEARCH_OUTPUT_TYPESCRIPT)
    );
    assert!(search.foreign);

    let delete = read("delete_item")?;
    assert_eq!(
        delete.reasons,
        Vec::<String>::new(),
        "delete_item is callable"
    );
    assert_eq!(delete.output_schema, None);
    assert_eq!(delete.output_typescript, None);
    assert_eq!(
        delete.input_typescript.as_deref(),
        Some("{\n  id: string;\n}")
    );
    assert_eq!(delete.destructive, Some(true));
    Ok(())
}

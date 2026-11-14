//! `google.docs` and `google.slides` on the workspace connector core (L3-17,
//! PR 2): each routes to the built-in through the one Google connection,
//! declares a read and a batch write with their grants, and plans a write
//! as one `POST …:batchUpdate` of the requests as written, then a `GET`
//! readback of the file. Uses only doors PR 1 has, so its red there is a
//! wrong value, not a missing door.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test google_docs_slides_connector`

use oneiron::channel_identity_provider::workspace_connector::{
    WorkspacePlan, module, workspace_manifest,
};
use oneiron::verbs::{ConnectorSchemaRequest, connector_schema_read};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DOCS_SLIDES_TEST_FILE: &str = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";

/// The plan `catalog`'s tool `name` makes of `arguments`, or its refusal.
fn docs_slides_test_plan(
    catalog: &str,
    name: &str,
    arguments: &Value,
) -> TestResult<Result<WorkspacePlan, &'static str>> {
    let api = module(catalog).ok_or_else(|| format!("{catalog} routes to no module"))?;
    let tool = api
        .tools()
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| format!("{catalog} has no tool {name}"))?;
    Ok(api.plan(tool, arguments))
}

#[test]
fn docs_and_slides_schemas_route_to_the_google_connection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for (name, tool) in [
        ("google.docs", "documents.get"),
        ("google.docs", "documents.batchUpdate"),
        ("google.slides", "presentations.get"),
        ("google.slides", "presentations.batchUpdate"),
    ] {
        let reply = connector_schema_read(
            &memory,
            ConnectorSchemaRequest {
                name: name.to_owned(),
                source: None,
                tool: tool.to_owned(),
            },
        )?;
        assert_eq!(reply.input_schema, None, "{name} {tool}");
        assert_eq!(
            reply.reasons,
            vec!["google_connection_not_checked".to_owned()],
            "{name} {tool} answers as the built-in, through the one Google connection"
        );
    }
    Ok(())
}

#[test]
fn docs_and_slides_declare_a_read_and_a_batch_write() -> TestResult {
    for (catalog, id_field, read, write, read_grant, write_grant) in [
        (
            "google.docs",
            "documentId",
            "documents.get",
            "documents.batchUpdate",
            "docs.read",
            "docs.write",
        ),
        (
            "google.slides",
            "presentationId",
            "presentations.get",
            "presentations.batchUpdate",
            "slides.read",
            "slides.write",
        ),
    ] {
        let api = module(catalog).ok_or_else(|| format!("{catalog} routes to no module"))?;
        let tools: Vec<(&str, &str, bool)> = api
            .tools()
            .iter()
            .map(|tool| (tool.name, tool.grant, tool.writes))
            .collect();
        assert_eq!(
            tools,
            vec![(read, read_grant, false), (write, write_grant, true)],
            "{catalog}"
        );
        assert_eq!(api.connection().pack, "oneiron.google", "{catalog}");
        let manifest = workspace_manifest(api)?;
        let schema = |name: &str| {
            manifest
                .tools()
                .iter()
                .find(|tool| tool.name == name)
                .map(|tool| tool.input_schema.clone())
                .ok_or_else(|| format!("{catalog} declares no {name}"))
        };
        assert_eq!(schema(read)?["required"], json!([id_field]), "{catalog}");
        assert_eq!(
            schema(write)?["required"],
            json!([id_field, "requests"]),
            "{catalog}"
        );
    }
    Ok(())
}

#[test]
fn docs_batch_update_plans_one_post_then_a_read_back() -> TestResult {
    let requests = json!([
        { "insertText": { "location": { "index": 1 }, "text": "owen" } },
        { "updateTextStyle": { "range": { "startIndex": 1, "endIndex": 5 }, "textStyle": { "bold": true }, "fields": "bold" } }
    ]);
    let write = docs_slides_test_plan(
        "google.docs",
        "documents.batchUpdate",
        &json!({
            "documentId": DOCS_SLIDES_TEST_FILE,
            "requests": requests,
            "writeControl": { "requiredRevisionId": "rev-owen-1" }
        }),
    )?
    .map_err(|reason| format!("the write's plan was refused: {reason}"))?;
    assert_eq!(write.target(), DOCS_SLIDES_TEST_FILE);
    assert_eq!(write.effect().endpoint().method(), "POST");
    assert_eq!(
        write.effect().url(),
        format!("https://docs.googleapis.com/v1/documents/{DOCS_SLIDES_TEST_FILE}:batchUpdate")
    );
    let body: Value = serde_json::from_slice(write.effect().body())?;
    assert_eq!(
        body,
        json!({ "requests": requests, "writeControl": { "requiredRevisionId": "rev-owen-1" } }),
        "the requests pass through as written, in one batch"
    );
    let readback = write.readback().ok_or("a write reads the document back")?;
    assert_eq!(readback.endpoint().method(), "GET");
    assert_eq!(
        readback.url(),
        format!("https://docs.googleapis.com/v1/documents/{DOCS_SLIDES_TEST_FILE}")
    );
    assert!(readback.body().is_empty());

    let read = docs_slides_test_plan(
        "google.docs",
        "documents.get",
        &json!({
            "documentId": DOCS_SLIDES_TEST_FILE,
            "suggestionsViewMode": "PREVIEW_WITHOUT_SUGGESTIONS",
            "includeTabsContent": true
        }),
    )?
    .map_err(|reason| format!("the read's plan was refused: {reason}"))?;
    assert_eq!(
        read.effect().url(),
        format!(
            "https://docs.googleapis.com/v1/documents/{DOCS_SLIDES_TEST_FILE}?suggestionsViewMode=PREVIEW_WITHOUT_SUGGESTIONS&includeTabsContent=true"
        )
    );
    assert!(read.readback().is_none(), "a read sends one request");

    for refused in [
        // A request that names two kinds.
        json!({ "documentId": DOCS_SLIDES_TEST_FILE, "requests": [{ "insertText": {}, "deleteContentRange": {} }] }),
        // Both revision controls at once.
        json!({ "documentId": DOCS_SLIDES_TEST_FILE, "requests": [{ "insertText": {} }],
                "writeControl": { "requiredRevisionId": "a", "targetRevisionId": "b" } }),
        // No request at all.
        json!({ "documentId": DOCS_SLIDES_TEST_FILE, "requests": [] }),
        // An id outside Google's alphabet.
        json!({ "documentId": "../files", "requests": [{ "insertText": {} }] }),
    ] {
        assert_eq!(
            docs_slides_test_plan("google.docs", "documents.batchUpdate", &refused)?.err(),
            Some("connector_arguments_invalid"),
            "{refused}"
        );
    }
    assert_eq!(
        docs_slides_test_plan(
            "google.docs",
            "documents.get",
            &json!({ "documentId": DOCS_SLIDES_TEST_FILE, "suggestionsViewMode": "EVERYTHING" })
        )?
        .err(),
        Some("connector_arguments_invalid")
    );
    Ok(())
}

#[test]
fn slides_batch_update_plans_one_post_then_a_read_back() -> TestResult {
    let requests = json!([
        { "createSlide": { "objectId": "owen_slide_1" } },
        { "insertText": { "objectId": "owen_title", "text": "yuki" } }
    ]);
    let write = docs_slides_test_plan(
        "google.slides",
        "presentations.batchUpdate",
        &json!({
            "presentationId": DOCS_SLIDES_TEST_FILE,
            "requests": requests,
            "writeControl": { "requiredRevisionId": "rev-yuki-2" }
        }),
    )?
    .map_err(|reason| format!("the write's plan was refused: {reason}"))?;
    assert_eq!(write.effect().endpoint().method(), "POST");
    assert_eq!(
        write.effect().url(),
        format!(
            "https://slides.googleapis.com/v1/presentations/{DOCS_SLIDES_TEST_FILE}:batchUpdate"
        )
    );
    let body: Value = serde_json::from_slice(write.effect().body())?;
    assert_eq!(
        body,
        json!({ "requests": requests, "writeControl": { "requiredRevisionId": "rev-yuki-2" } })
    );
    let readback = write
        .readback()
        .ok_or("a write reads the presentation back")?;
    assert_eq!(readback.endpoint().method(), "GET");
    assert_eq!(
        readback.url(),
        format!("https://slides.googleapis.com/v1/presentations/{DOCS_SLIDES_TEST_FILE}")
    );

    let read = docs_slides_test_plan(
        "google.slides",
        "presentations.get",
        &json!({ "presentationId": DOCS_SLIDES_TEST_FILE }),
    )?
    .map_err(|reason| format!("the read's plan was refused: {reason}"))?;
    assert!(read.readback().is_none(), "a read sends one request");
    assert_eq!(
        docs_slides_test_plan(
            "google.slides",
            "presentations.batchUpdate",
            &json!({ "presentationId": DOCS_SLIDES_TEST_FILE, "requests": [{ "createSlide": {} }],
                     "writeControl": { "targetRevisionId": "b" } })
        )?
        .err(),
        Some("connector_arguments_invalid"),
        "Slides pins a batch to a required revision only"
    );
    Ok(())
}

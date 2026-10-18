//! The public signing ceremony routes (`/sign/*`, DOOR-117): their
//! request and answer schemas are the verb table's `vault.esign.signing.*`
//! types, the same bodies the typed facade rows take, so the page, the
//! SDK and this document describe one ceremony. The capability in the
//! request body is the authority on these routes, never a path token or
//! a core credential; a credential a call also presents only classes
//! the caller, and an agent's Complete is an automated sign act. The
//! typed facade twins answer the same acts as base64 JSON views; these
//! public routes serve the PDF and the signature image as bytes.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{input_schema, output_schema};

pub(super) fn merge_signing_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    paths.insert(
        "/sign".to_owned(),
        json!({"get": {
            "tags": ["signing"],
            "operationId": "signing_page",
            "summary": "The signing page shell. The recipient link is /sign#<capability>; the page scrubs the fragment and sends the capability only in POST bodies.",
            "security": [],
            "responses": {
                "200": {
                    "description": "The signing page, served no-store with a hash-pinned script.",
                    "content": {"text/html": {"schema": {"type": "string"}}}
                }
            }
        }}),
    );
    if let (Some(request), Some(answer)) = (
        input_schema("vault.esign.signing.act"),
        output_schema("vault.esign.signing.act"),
    ) {
        paths.insert(
            "/sign/action".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_action",
                "summary": "One recipient ceremony act: load, save a field, complete with consent, or reject.",
                "description": "The capability in the body is the authority. A call that also presents a vault credential is classed by it: an agent Complete is an automated sign act, held or refused where the signing dial or a natural-person recipient requires a person. Complete answers awaiting_seal; sealing runs as its own task and is observed through vault.esign.seal.get and vault.esign.get.",
                "security": [],
                "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
                "responses": ceremony_responses(json!({
                    "description": "The ceremony outcome: the page, not_your_turn, terminal, awaiting_seal, held_for_owner, or consent_required.",
                    "content": {"application/json": {"schema": answer}}
                }))
            }}),
        );
    }
    if let Some(request) = input_schema("vault.esign.signing.pdf") {
        paths.insert(
            "/sign/pdf".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_pdf",
                "summary": "One ceremony item as a PDF attachment: the pinned original while signing, the hash-checked sealed output after sealing.",
                "security": [],
                "requestBody": {"required": true, "content": {"application/json": {"schema": request.clone()}}},
                "responses": ceremony_responses(json!({
                    "description": "The item bytes, as an attachment.",
                    "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}
                }))
            }}),
        );
        paths.insert(
            "/sign/preview".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_preview",
                "summary": "The page geometry and field layout of one ceremony item, for the signing page to draw its fields.",
                "security": [],
                "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
                "responses": ceremony_responses(json!({
                    "description": "The item pages and its fields laid out on them.",
                    "content": {"application/json": {"schema": {"type": "object"}}}
                }))
            }}),
        );
    }
    if let (Some(request), Some(answer)) = (
        input_schema("vault.esign.signing.image"),
        output_schema("vault.esign.signing.image"),
    ) {
        paths.insert(
            "/sign/image".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_image",
                "summary": "Stores one signature image bound to the capability recipient and answers its ref.",
                "security": [],
                "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
                "responses": ceremony_responses(json!({
                    "description": "The stored signature image ref a signature field value names.",
                    "content": {"application/json": {"schema": answer}}
                }))
            }}),
        );
    }
    if let Some(request) = input_schema("vault.esign.signing.signature") {
        paths.insert(
            "/sign/signature".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_signature",
                "summary": "One stored signature image under the capability that uploaded it, as image bytes.",
                "security": [],
                "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
                "responses": ceremony_responses(json!({
                    "description": "The signature image bytes.",
                    "content": {"image/png": {"schema": {"type": "string", "format": "binary"}}}
                }))
            }}),
        );
    }
}

/// A ceremony route's answer beside the refusals every such route
/// shares: no refusal echoes the capability.
fn ceremony_responses(ok: Value) -> Value {
    let refusal = json!({
        "type": "object",
        "required": ["error"],
        "properties": {"error": {
            "type": "object",
            "required": ["code"],
            "properties": {"code": {"type": "string"}}
        }}
    });
    let mut responses = Map::new();
    responses.insert("200".to_owned(), ok);
    for (status, description) in [
        ("400", "The request body is malformed."),
        (
            "403",
            "The capability does not admit this act (signing_unavailable).",
        ),
        (
            "503",
            "The signing transport peer is unavailable (signing_transport_unavailable).",
        ),
    ] {
        responses.insert(
            status.to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": refusal}}
            }),
        );
    }
    Value::Object(responses)
}

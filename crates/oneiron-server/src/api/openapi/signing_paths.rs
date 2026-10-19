//! The public signing ceremony routes (`/sign/*`, DOOR-117): their
//! payload and answer schemas are the verb table's `vault.esign.signing.*`
//! types, the bodies the typed facade rows take less their `token`, so the
//! page, the SDK and this document describe one ceremony. On these routes
//! the capability rides in the `x-oneiron-esign-capability` header, which
//! the vault admits before the body is read (FIX 3808); it is never a path
//! token, a body field or a core credential. A credential a call also
//! presents only classes the caller, and an agent's Complete is an
//! automated sign act. The typed facade twins carry the capability in
//! their input and answer the same acts as base64 JSON views; these public
//! routes take the signature image and serve the PDF and the image as
//! bytes.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{input_schema, output_schema};

/// The security scheme the ceremony POSTs name.
const CAPABILITY_SCHEME: &str = "EsignCapability";

pub(super) fn merge_signing_paths(spec: &mut Value) {
    add_capability_scheme(spec);
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    paths.insert(
        "/sign".to_owned(),
        json!({"get": {
            "tags": ["signing"],
            "operationId": "signing_page",
            "summary": "The signing page shell. The recipient link is /sign#<capability>; the page scrubs the fragment and sends the capability only in the x-oneiron-esign-capability header of each ceremony POST.",
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
                "description": "The capability in the x-oneiron-esign-capability header is the authority. A call that also presents a vault credential is classed by it: an agent Complete is an automated sign act, held or refused where the signing dial or a natural-person recipient requires a person. Complete answers awaiting_seal; sealing runs as its own task and is observed through vault.esign.seal.get and vault.esign.get.",
                "security": capability_security(),
                "requestBody": {"required": true, "content": {"application/json": {"schema": headerless(request)}}},
                "responses": ceremony_responses(json!({
                    "description": "The ceremony outcome: the page, not_your_turn, terminal, awaiting_seal, held_for_owner, or consent_required.",
                    "content": {"application/json": {"schema": answer}}
                }))
            }}),
        );
    }
    if let Some(request) = input_schema("vault.esign.signing.pdf") {
        let request = headerless(request);
        paths.insert(
            "/sign/pdf".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_pdf",
                "summary": "One ceremony item as a PDF attachment: the pinned original while signing, the hash-checked sealed output after sealing.",
                "security": capability_security(),
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
                "security": capability_security(),
                "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
                "responses": ceremony_responses(json!({
                    "description": "The item pages and its fields laid out on them.",
                    "content": {"application/json": {"schema": {"type": "object"}}}
                }))
            }}),
        );
    }
    if let Some(answer) = output_schema("vault.esign.signing.image") {
        let image = json!({"schema": {"type": "string", "format": "binary"}});
        paths.insert(
            "/sign/image".to_owned(),
            json!({"post": {
                "tags": ["signing"],
                "operationId": "signing_image",
                "summary": "Stores one signature image bound to the capability recipient and answers its ref.",
                "description": "The body is the raw PNG or JPEG image, of any size: past the [limits] esign_body_bytes and esign_signature_* rows the envelope's sender is asked whether everything is okay, and the image is still stored and bound.",
                "security": capability_security(),
                "requestBody": {"required": true, "content": {"image/png": image.clone(), "image/jpeg": image}},
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
                "security": capability_security(),
                "requestBody": {"required": true, "content": {"application/json": {"schema": headerless(request)}}},
                "responses": ceremony_responses(json!({
                    "description": "The signature image bytes.",
                    "content": {"image/png": {"schema": {"type": "string", "format": "binary"}}}
                }))
            }}),
        );
    }
}

/// Adds the header scheme a ceremony POST names: the recipient link's
/// capability, the 64 lowercase hex characters after `/sign#`.
fn add_capability_scheme(spec: &mut Value) {
    let Some(schemes) = spec
        .get_mut("components")
        .and_then(Value::as_object_mut)
        .map(|components| {
            components
                .entry("securitySchemes")
                .or_insert_with(|| json!({}))
        })
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    schemes.insert(
        CAPABILITY_SCHEME.to_owned(),
        json!({
            "type": "apiKey",
            "in": "header",
            "name": "x-oneiron-esign-capability",
            "description": "The recipient's signing capability from their link (/sign#<capability>). The vault admits it against its envelope before the request body is read; a request without an admitted one is refused with its body unread. It is never a path segment or a body field on these routes."
        }),
    );
}

/// The `security` a ceremony POST names: the capability header alone.
fn capability_security() -> Value {
    json!([{ CAPABILITY_SCHEME: [] }])
}

/// A facade row's input as its public door takes it: the `token` field
/// dropped, since the door reads the capability from its header.
fn headerless(schema: &Value) -> Value {
    let mut schema = schema.clone();
    if let Some(schema) = schema.as_object_mut() {
        if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            properties.remove("token");
        }
        if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|name| name.as_str() != Some("token"));
        }
    }
    schema
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
        (
            "400",
            "The admitted body is not the route's payload (signing_body_malformed) or did not arrive whole (signing_body_unread).",
        ),
        (
            "403",
            "No x-oneiron-esign-capability header, or one the vault does not admit, refused with the body unread; or the capability does not admit this act (signing_unavailable).",
        ),
        (
            "503",
            "The signing transport peer is unavailable (signing_transport_unavailable).",
        ),
        (
            "507",
            "The vault's disk is at its free-space reserve, limits.disk_reserve_bytes (signing_disk_floor). A body's size alone is never refused.",
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

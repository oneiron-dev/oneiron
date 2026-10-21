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
            "The signing transport peer is unavailable (signing_transport_unavailable); or, at POST /sign/image, the wait for the machine memory reading and decoding the image takes passed its deadline (signing_memory_waited_out).",
        ),
        (
            "507",
            "The vault's disk is at its free-space reserve, limits.disk_reserve_bytes (signing_disk_floor); or, at POST /sign/image, the machine memory reading and decoding the image takes does not fit past the server's free-memory reserve (signing_memory_floor). A body's size alone is never refused.",
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

/// The security scheme the owner's editor computation POSTs name (FIX 5618).
const EDITOR_SCHEME: &str = "EsignEditorCapability";

/// The owner's field editor (FIX 5618): its shell, `GET /sign/editor`,
/// behind an owner-grade caller, and its two computation POSTs, which take
/// the editor token the shell minted, or no credential at all.
pub(super) fn merge_editor_paths(spec: &mut Value) {
    add_editor_scheme(spec);
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    paths.insert(
        "/sign/editor".to_owned(),
        json!({"get": {
            "tags": ["signing"],
            "operationId": "signing_editor",
            "summary": "The owner's field geography editor page, which mints its editor token.",
            "description": "Owner-grade callers only: a top-scope logged slip presented as CoreBearer with its holder proof in x-oneiron-binding, or a managed vault's attested owner. Owner grade is the authorization; the bearer scheme alone is not. The page is served no-store and carries a fresh random editor token; its script reads the token, removes it from the document, keeps it in memory and sends it only in the x-oneiron-esign-editor header of POST /sign/layout and POST /sign/geometry. The server keeps only the token's digest, purpose, caller and expiry. A token admits new requests for 3,600 seconds and is forgotten when the server restarts; the owner then reloads this page for a new one.",
            "security": [{"CoreBearer": []}],
            "responses": {
                "200": {
                    "description": "The editor page, served no-store.",
                    "content": {"text/html": {"schema": {"type": "string"}}}
                },
                "401": {"description": "The caller is not owner-grade."}
            }
        }}),
    );
    paths.insert(
        "/sign/layout".to_owned(),
        json!({"post": {
            "tags": ["signing"],
            "operationId": "signing_editor_layout",
            "summary": "Lays the editor's fields out on the PDF's pages, from caller data alone: no vault row is read or written.",
            "description": editor_description("esign_body_bytes", "3 MiB"),
            "security": editor_security(),
            "requestBody": {"required": true, "content": {"application/json": {"schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["fields", "values", "pages"],
                "properties": {
                    "fields": {"type": "array", "items": {"type": "object"}, "description": "Field geography pack fields; every one is laid out against its page."},
                    "values": {"type": "object", "description": "Field values by field id."},
                    "pages": {"type": "array", "items": {"type": "object"}, "description": "Page geometry as POST /sign/geometry answers it."}
                }
            }}}},
            "responses": editor_responses(json!({
                "description": "The pages and the fields laid out on them.",
                "content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["pages", "fields"],
                    "properties": {
                        "pages": {"type": "array", "items": {"type": "object"}},
                        "fields": {"type": "array", "items": {"type": "object"}}
                    }
                }}}
            }))
        }}),
    );
    paths.insert(
        "/sign/geometry".to_owned(),
        json!({"post": {
            "tags": ["signing"],
            "operationId": "signing_editor_geometry",
            "summary": "Inspects a PDF's pages for the editor: boxes and rotation, from the caller's bytes alone. No template is parsed, no blob is written and no effect is sent.",
            "description": editor_description("esign_geometry_body_bytes", "16 MiB"),
            "security": editor_security(),
            "requestBody": {"required": true, "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}},
            "responses": editor_responses(json!({
                "description": "The PDF's page geometry.",
                "content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["pages"],
                    "properties": {"pages": {"type": "array", "items": {"type": "object"}}}
                }}}
            }))
        }}),
    );
}

/// Adds the header scheme the editor's computation POSTs name: the token
/// the editor page was minted, never a recipient capability or a core
/// credential.
fn add_editor_scheme(spec: &mut Value) {
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
        EDITOR_SCHEME.to_owned(),
        json!({
            "type": "apiKey",
            "in": "header",
            "name": "x-oneiron-esign-editor",
            "description": "The editor token GET /sign/editor minted for its owner-grade caller. It is checked before the request body is read: its digest, its editor-computation purpose and its expiry, and its caller's credential is re-consulted. It buys computation over the caller's own bytes only: no document read, recipient act or other door. It is never a URL, cookie or browser-storage carrier."
        }),
    );
}

/// The `security` an editor computation POST names: the editor token, or
/// none (the capability-free door).
fn editor_security() -> Value {
    json!([{ EDITOR_SCHEME: [] }, {}])
}

/// How an editor computation POST is admitted and bounded, for its `row`
/// and its capability-free door's `anonymous_limit`.
fn editor_description(row: &str, anonymous_limit: &str) -> String {
    format!(
        "With an x-oneiron-esign-editor token, the request is admitted from its head before the body is read, then waits its turn for one of the editor's two computation slots, at most [limits] queue_wait_timeout_ms (then 503 editor_waited_out); no queue length refuses it. After the wait its token and caller are checked again. Its body spools whole under the vault's disk floor: past the [limits] {row} row the vault owner is asked whether everything is okay (GET /v1/owner/decisions/asks), and the work still runs. A token that is unknown or expired, or whose caller's credential no longer stands, is refused with 401 and the body unread; it is never served as an anonymous request. With no editor header the route is the public, capability-free door it was: a {anonymous_limit} body limit, and two slots taken only when free with 60 requests a minute, else 429 with Retry-After: 60."
    )
}

/// An editor computation POST's answer beside its refusals.
fn editor_responses(ok: Value) -> Value {
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
    for (status, description, coded) in [
        (
            "400",
            "An admitted body that is not the route's payload (signing_body_malformed) or did not arrive whole (signing_body_unread); without a token, a body the JSON extractor refuses.",
            true,
        ),
        (
            "401",
            "The x-oneiron-esign-editor token is unknown or expired (editor_token_unadmitted), or its caller's credential no longer stands (editor_caller_not_live), at the head or after the slot wait; the body is unread. Reload GET /sign/editor for a new token.",
            true,
        ),
        (
            "403",
            "The fields do not lay out on the pages given, or the PDF cannot be inspected safely (signing_unavailable).",
            true,
        ),
        (
            "413",
            "Without a token only: the body is past the route's body limit.",
            false,
        ),
        (
            "429",
            "Without a token only: no free slot, or the minute's 60 requests are used. Retry-After: 60.",
            false,
        ),
        (
            "503",
            "The editor's state is unavailable (signing_transport_unavailable), or an admitted request waited [limits] queue_wait_timeout_ms for a slot (editor_waited_out, Retry-After: 1); or, at POST /sign/geometry with a token, the wait for the machine memory reading the PDF takes passed its deadline (signing_memory_waited_out).",
            true,
        ),
        (
            "507",
            "With a token: the vault's disk is at its free-space reserve, limits.disk_reserve_bytes (signing_disk_floor); or, at POST /sign/geometry, the machine memory reading the PDF takes does not fit past the server's free-memory reserve (signing_memory_floor). An admitted body's size alone is never refused.",
            true,
        ),
    ] {
        let mut response = json!({"description": description});
        if coded {
            response["content"] = json!({"application/json": {"schema": refusal}});
        }
        responses.insert(status.to_owned(), response);
    }
    Value::Object(responses)
}

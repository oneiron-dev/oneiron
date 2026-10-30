//! The voice bank's `/v1/ai/voices` routes in the OpenAPI document
//! (DOOR-143). Each body's and answer's schema is read from the type the
//! route reads or writes (api/ai/voices.rs and the SDK receipts it answers
//! with), so no second list of shapes is kept. The owner's typed
//! `vault.voices.*` rows publish beside them at `/v1/core/facade/<verb>`.
//! A route refuses in the `{error: {code, message}}` envelope `/v1/ai`
//! answers with.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{
    VoiceBankPackReceipt, VoiceRenderConsentReceipt, VoiceTargetEvictReceipt, VoiceTargetReceipt,
};
use oneiron::voice_identity::ref_bank::VoiceBankView;
use oneiron_contracts::code_run::vault_read::request_schema;

use crate::api::ai::{ConsentBody, PackBody, ProvisionBody};

/// One `/v1/ai/voices` route: its method, path, what it does, its body's
/// schema (none for a delete), its answer's, and each refusal it answers.
struct VoiceRoute {
    method: &'static str,
    path: &'static str,
    summary: &'static str,
    body: Option<fn() -> Value>,
    answer: fn() -> Value,
    refusals: &'static [(&'static str, &'static str)],
}

/// What every route refuses: a credential that is not owner-grade, a bank
/// refusal, and a bank that could not be read or written.
const OWNER_REQUIRED: (&str, &str) = (
    "403",
    "The credential is not owner-grade (`owner_required`).",
);
const BANK_REFUSED: (&str, &str) = (
    "409",
    "The bank refused: an unknown voice, a ref the render consent does not reach, another subject, or a changed decision (`voice_refused`).",
);
const BANK_FAILED: (&str, &str) = (
    "500",
    "The voice bank could not be read or written (`voice_bank_failed`).",
);

const VOICE_ROUTES: &[VoiceRoute] = &[
    VoiceRoute {
        method: "get",
        path: "/v1/ai/voices/{voice_id}",
        summary: "The voice as the bank holds it: its identity, each pack's metadata, its current render decision, and each configured clone target's current clone, read from one snapshot with no provider call.",
        body: None,
        answer: request_schema::<VoiceBankView>,
        refusals: &[
            (
                "404",
                "The bank holds nothing of that voice (`unknown_voice`).",
            ),
            OWNER_REQUIRED,
            BANK_REFUSED,
            BANK_FAILED,
        ],
    },
    VoiceRoute {
        method: "post",
        path: "/v1/ai/voices/{voice_id}/packs",
        summary: "Banks one immutable reference pack under the voice. A captured pack cites the subject's current render grant; a retry of the same pack is a no-op. Audio is base64.",
        body: Some(request_schema::<PackBody>),
        answer: request_schema::<VoiceBankPackReceipt>,
        refusals: &[
            (
                "400",
                "The owner is not an entity id (`invalid_entity`), or a clip's audio is not base64 (`invalid_audio`).",
            ),
            OWNER_REQUIRED,
            BANK_REFUSED,
            BANK_FAILED,
        ],
    },
    VoiceRoute {
        method: "post",
        path: "/v1/ai/voices/{voice_id}/render_consent",
        summary: "Records the subject's render decision. A withdrawal drops the voice's target pointers and deletes their clones at the vendors, best effort; the packs stay.",
        body: Some(request_schema::<ConsentBody>),
        answer: request_schema::<VoiceRenderConsentReceipt>,
        refusals: &[
            (
                "400",
                "The subject or the recorder is not an entity id (`invalid_entity`).",
            ),
            OWNER_REQUIRED,
            BANK_REFUSED,
            BANK_FAILED,
        ],
    },
    VoiceRoute {
        method: "post",
        path: "/v1/ai/voices/{voice_id}/targets/{target}",
        summary: "Provisions the hosted target's clone of the voice: its current clone, else a new vendor voice from the selected refs, made only while the render consent reaches the target's locality.",
        body: Some(request_schema::<ProvisionBody>),
        answer: request_schema::<VoiceTargetReceipt>,
        refusals: &[
            (
                "400",
                "The target clones only with the clips' language, and none was named (`language_required`).",
            ),
            OWNER_REQUIRED,
            (
                "404",
                "No configured hosted speech provider by that name clones voices (`no_clone_target`).",
            ),
            BANK_REFUSED,
            BANK_FAILED,
            (
                "502",
                "The provider did not make the clone (`vendor_clone_failed`).",
            ),
        ],
    },
    VoiceRoute {
        method: "delete",
        path: "/v1/ai/voices/{voice_id}/targets/{target}",
        summary: "Drops the target's clone pointer and deletes the clone at its vendor, best effort. The identity and its packs stay.",
        body: None,
        answer: request_schema::<VoiceTargetEvictReceipt>,
        refusals: &[OWNER_REQUIRED, BANK_REFUSED, BANK_FAILED],
    },
];

/// The `/v1/ai` refusal envelope.
fn refusal_schema() -> Value {
    json!({
        "type": "object",
        "required": ["error"],
        "properties": {"error": {
            "type": "object",
            "required": ["code", "message"],
            "properties": {"code": {"type": "string"}, "message": {"type": "string"}}
        }}
    })
}

/// Adds each `/v1/ai/voices` route's operation to `spec`'s paths.
pub(super) fn merge_voice_bank_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for route in VOICE_ROUTES {
        let Some(item) = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
        else {
            continue;
        };
        item.insert(route.method.to_owned(), operation(route));
    }
}

fn operation(route: &VoiceRoute) -> Value {
    let mut operation = Map::new();
    operation.insert("tags".to_owned(), json!(["ai"]));
    operation.insert("summary".to_owned(), json!(route.summary));
    operation.insert(
        "operationId".to_owned(),
        json!(format!(
            "ai_{}_{}",
            route.method,
            route
                .path
                .trim_start_matches("/v1/ai/")
                .replace(['/', '{', '}'], "_")
        )),
    );
    operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
    let parameters: Vec<Value> = route
        .path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}))
        .collect();
    operation.insert("parameters".to_owned(), Value::Array(parameters));
    if let Some(body) = route.body {
        operation.insert(
            "requestBody".to_owned(),
            json!({"required": true, "content": {"application/json": {"schema": body()}}}),
        );
    }
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "The route's typed answer.",
            "content": {"application/json": {"schema": (route.answer)()}}
        }),
    );
    for (status, description) in route.refusals {
        responses.insert(
            (*status).to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": refusal_schema()}}
            }),
        );
    }
    operation.insert("responses".to_owned(), Value::Object(responses));
    Value::Object(operation)
}

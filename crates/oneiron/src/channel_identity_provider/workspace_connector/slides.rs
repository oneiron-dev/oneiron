//! `google.slides` (MAIL-GOOGLE = A, row 3; L3-17): a presentation read and
//! one batch of edits with a readback, over the Slides v1 REST API, on the
//! workspace connector core. The deck stays in Google, and the agent edits
//! it in place (ARCH-0075 `#edit-in-place`).
//!
//! * **Read.** `presentations.get` reads one presentation whole: its slides,
//!   layouts, masters and revision id.
//! * **Write.** `presentations.batchUpdate` passes the edit requests through
//!   as written, in one batch Google applies whole or not at all, then reads
//!   the presentation back. `writeControl` pins the batch to the revision the
//!   agent read (`requiredRevisionId`).

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::requests::{
    decode, file_id_schema, plain_file_id, plain_revision_id, request_kinds, requests_fit,
    requests_schema, revision_id_schema,
};
use super::{
    ARGUMENTS_INVALID, GOOGLE_CONNECTION, WorkspaceApi, WorkspaceConnection, WorkspaceEndpoint,
    WorkspacePlan, WorkspaceTarget, WorkspaceTool, WorkspaceWireRequest,
};

/// The connector's catalog name, as `connector.call` names it.
pub const SLIDES_CATALOG_NAME: &str = "google.slides";

/// The pack grant a read needs the owner to have allowed.
pub const SLIDES_READ_GRANT: &str = "slides.read";

/// The pack grant a write needs the owner to have allowed.
pub const SLIDES_WRITE_GRANT: &str = "slides.write";

/// The connector's one-line catalog summary.
const SLIDES_SUMMARY: &str = "Google Slides: read a presentation, and edit it in place with one batch of requests and a readback, through the credential broker.";

/// `presentations.get`.
const PRESENTATION_GET: &str = "presentations.get";
/// `presentations.batchUpdate`.
const PRESENTATION_BATCH_UPDATE: &str = "presentations.batchUpdate";

/// The two tools, in catalog order.
static SLIDES_TOOLS: [WorkspaceTool; 2] = [
    WorkspaceTool {
        name: PRESENTATION_GET,
        grant: SLIDES_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: PRESENTATION_BATCH_UPDATE,
        grant: SLIDES_WRITE_GRANT,
        writes: true,
    },
];

/// `presentations.get`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PresentationGetInput {
    presentation_id: String,
}

/// `presentations.batchUpdate`'s input: each request one object naming one
/// request kind, passed through as written.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PresentationBatchUpdateInput {
    presentation_id: String,
    requests: Vec<Map<String, Value>>,
    #[serde(default)]
    write_control: Option<SlidesWriteControl>,
}

/// The revision a batch applies to.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SlidesWriteControl {
    required_revision_id: String,
}

/// The `google.slides` descriptor.
pub(super) struct SlidesApi;

impl WorkspaceApi for SlidesApi {
    fn catalog_name(&self) -> &'static str {
        SLIDES_CATALOG_NAME
    }

    fn summary(&self) -> &'static str {
        SLIDES_SUMMARY
    }

    fn connection(&self) -> &'static WorkspaceConnection {
        &GOOGLE_CONNECTION
    }

    fn target(&self) -> WorkspaceTarget {
        WorkspaceTarget {
            field: "presentationId",
            kind: "presentation",
        }
    }

    fn tools(&self) -> &'static [WorkspaceTool] {
        &SLIDES_TOOLS
    }

    fn input_schema(&self, tool: &WorkspaceTool) -> Value {
        let presentation_id =
            file_id_schema("The presentation's id, as its URL shows it after /d/.");
        if tool.writes {
            json!({
                "type": "object",
                "properties": {
                    "presentationId": presentation_id,
                    "requests": requests_schema("Slides v1", "createSlide"),
                    "writeControl": {
                        "type": "object",
                        "properties": {
                            "requiredRevisionId": revision_id_schema(
                                "Apply the batch only to this revision, the one a read returned; Google refuses it once the presentation changed."
                            )
                        },
                        "required": ["requiredRevisionId"],
                        "additionalProperties": false
                    }
                },
                "required": ["presentationId", "requests"],
                "additionalProperties": false
            })
        } else {
            json!({
                "type": "object",
                "properties": { "presentationId": presentation_id },
                "required": ["presentationId"],
                "additionalProperties": false
            })
        }
    }

    fn plan(&self, tool: &WorkspaceTool, arguments: &Value) -> Result<WorkspacePlan, &'static str> {
        match tool.name {
            PRESENTATION_GET => {
                let input: PresentationGetInput = decode(arguments)?;
                let effect = presentation_get(&input.presentation_id)?;
                Ok(WorkspacePlan::new(
                    input.presentation_id,
                    effect,
                    None,
                    Map::new(),
                ))
            }
            PRESENTATION_BATCH_UPDATE => {
                let input: PresentationBatchUpdateInput = decode(arguments)?;
                if !requests_fit(&input.requests) || !plain_file_id(&input.presentation_id) {
                    return Err(ARGUMENTS_INVALID);
                }
                let mut body = json!({ "requests": input.requests });
                if let Some(control) = &input.write_control {
                    if !plain_revision_id(&control.required_revision_id) {
                        return Err(ARGUMENTS_INVALID);
                    }
                    body["writeControl"] =
                        json!({ "requiredRevisionId": control.required_revision_id });
                }
                let effect = WorkspaceWireRequest::new(
                    WorkspaceEndpoint::SlidesBatchUpdate,
                    format!("/v1/presentations/{}:batchUpdate", input.presentation_id),
                    serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
                )?;
                let readback = presentation_get(&input.presentation_id)?;
                let mut preview = Map::new();
                preview.insert("requests".to_owned(), request_kinds(&input.requests));
                Ok(WorkspacePlan::new(
                    input.presentation_id,
                    effect,
                    Some(readback),
                    preview,
                ))
            }
            _ => Err(ARGUMENTS_INVALID),
        }
    }
}

/// One presentation.
fn presentation_get(presentation_id: &str) -> Result<WorkspaceWireRequest, &'static str> {
    if !plain_file_id(presentation_id) {
        return Err(ARGUMENTS_INVALID);
    }
    WorkspaceWireRequest::new(
        WorkspaceEndpoint::SlidesPresentationGet,
        format!("/v1/presentations/{presentation_id}"),
        Vec::new(),
    )
}

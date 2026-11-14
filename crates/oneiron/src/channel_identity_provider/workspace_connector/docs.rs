//! `google.docs` (MAIL-GOOGLE = A, row 3; L3-17): a document read and one
//! batch of edits with a readback, over the Docs v1 REST API, on the
//! workspace connector core. The document stays in Google, and the agent
//! edits it in place (ARCH-0075 `#edit-in-place`).
//!
//! * **Read.** `documents.get` reads one document whole: its body, its
//!   revision id, and its tabs when `includeTabsContent` asks for them.
//! * **Write.** `documents.batchUpdate` passes the edit requests through as
//!   written, in one batch Google applies whole or not at all, then reads the
//!   document back. `writeControl` pins the batch to the revision the agent
//!   read (`requiredRevisionId`) or merges it into the latest one
//!   (`targetRevisionId`).

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
pub const DOCS_CATALOG_NAME: &str = "google.docs";

/// The pack grant a read needs the owner to have allowed.
pub const DOCS_READ_GRANT: &str = "docs.read";

/// The pack grant a write needs the owner to have allowed.
pub const DOCS_WRITE_GRANT: &str = "docs.write";

/// The connector's one-line catalog summary.
const DOCS_SUMMARY: &str = "Google Docs: read a document, and edit it in place with one batch of requests and a readback, through the credential broker.";

/// `documents.get`.
const DOCUMENT_GET: &str = "documents.get";
/// `documents.batchUpdate`.
const DOCUMENT_BATCH_UPDATE: &str = "documents.batchUpdate";

/// The two tools, in catalog order.
static DOCS_TOOLS: [WorkspaceTool; 2] = [
    WorkspaceTool {
        name: DOCUMENT_GET,
        grant: DOCS_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: DOCUMENT_BATCH_UPDATE,
        grant: DOCS_WRITE_GRANT,
        writes: true,
    },
];

/// The suggestion views a read may ask for.
const SUGGESTIONS_VIEW_MODES: [&str; 4] = [
    "DEFAULT_FOR_CURRENT_ACCESS",
    "SUGGESTIONS_INLINE",
    "PREVIEW_SUGGESTIONS_ACCEPTED",
    "PREVIEW_WITHOUT_SUGGESTIONS",
];

/// `documents.get`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DocumentGetInput {
    document_id: String,
    #[serde(default)]
    suggestions_view_mode: Option<String>,
    #[serde(default)]
    include_tabs_content: Option<bool>,
}

/// `documents.batchUpdate`'s input: each request one object naming one
/// request kind, passed through as written.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DocumentBatchUpdateInput {
    document_id: String,
    requests: Vec<Map<String, Value>>,
    #[serde(default)]
    write_control: Option<DocsWriteControl>,
}

/// The revision a batch applies to: exactly one of the two.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DocsWriteControl {
    #[serde(default)]
    required_revision_id: Option<String>,
    #[serde(default)]
    target_revision_id: Option<String>,
}

impl DocsWriteControl {
    /// The control as the request body carries it, or `None` when it does
    /// not name exactly one plain revision.
    fn body(&self) -> Option<Value> {
        match (&self.required_revision_id, &self.target_revision_id) {
            (Some(required), None) if plain_revision_id(required) => {
                Some(json!({ "requiredRevisionId": required }))
            }
            (None, Some(target)) if plain_revision_id(target) => {
                Some(json!({ "targetRevisionId": target }))
            }
            _ => None,
        }
    }
}

/// The `google.docs` descriptor.
pub(super) struct DocsApi;

impl WorkspaceApi for DocsApi {
    fn catalog_name(&self) -> &'static str {
        DOCS_CATALOG_NAME
    }

    fn summary(&self) -> &'static str {
        DOCS_SUMMARY
    }

    fn connection(&self) -> &'static WorkspaceConnection {
        &GOOGLE_CONNECTION
    }

    fn target(&self) -> WorkspaceTarget {
        WorkspaceTarget {
            field: "documentId",
            kind: "document",
        }
    }

    fn tools(&self) -> &'static [WorkspaceTool] {
        &DOCS_TOOLS
    }

    fn input_schema(&self, tool: &WorkspaceTool) -> Value {
        let document_id = file_id_schema("The document's id, as its URL shows it after /d/.");
        if tool.writes {
            json!({
                "type": "object",
                "properties": {
                    "documentId": document_id,
                    "requests": requests_schema("Docs v1", "insertText"),
                    "writeControl": {
                        "type": "object",
                        "properties": {
                            "requiredRevisionId": revision_id_schema(
                                "Apply the batch only to this revision, the one a read returned; Google refuses it once the document changed."
                            ),
                            "targetRevisionId": revision_id_schema(
                                "Apply the batch to the latest revision, merging it with changes made since this one."
                            )
                        },
                        "minProperties": 1,
                        "maxProperties": 1,
                        "additionalProperties": false
                    }
                },
                "required": ["documentId", "requests"],
                "additionalProperties": false
            })
        } else {
            json!({
                "type": "object",
                "properties": {
                    "documentId": document_id,
                    "suggestionsViewMode": { "type": "string", "enum": SUGGESTIONS_VIEW_MODES },
                    "includeTabsContent": { "type": "boolean" }
                },
                "required": ["documentId"],
                "additionalProperties": false
            })
        }
    }

    fn plan(&self, tool: &WorkspaceTool, arguments: &Value) -> Result<WorkspacePlan, &'static str> {
        match tool.name {
            DOCUMENT_GET => {
                let input: DocumentGetInput = decode(arguments)?;
                let mode = input.suggestions_view_mode.as_deref();
                if mode.is_some_and(|mode| !SUGGESTIONS_VIEW_MODES.contains(&mode)) {
                    return Err(ARGUMENTS_INVALID);
                }
                let effect = document_get(&input.document_id, mode, input.include_tabs_content)?;
                Ok(WorkspacePlan::new(
                    input.document_id,
                    effect,
                    None,
                    Map::new(),
                ))
            }
            DOCUMENT_BATCH_UPDATE => {
                let input: DocumentBatchUpdateInput = decode(arguments)?;
                if !requests_fit(&input.requests) {
                    return Err(ARGUMENTS_INVALID);
                }
                let mut body = json!({ "requests": input.requests });
                if let Some(control) = &input.write_control {
                    body["writeControl"] = control.body().ok_or(ARGUMENTS_INVALID)?;
                }
                let effect = WorkspaceWireRequest::new(
                    WorkspaceEndpoint::DocsBatchUpdate,
                    format!("/v1/documents/{}:batchUpdate", plain(&input.document_id)?),
                    serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
                )?;
                let readback = document_get(&input.document_id, None, None)?;
                let mut preview = Map::new();
                preview.insert("requests".to_owned(), request_kinds(&input.requests));
                Ok(WorkspacePlan::new(
                    input.document_id,
                    effect,
                    Some(readback),
                    preview,
                ))
            }
            _ => Err(ARGUMENTS_INVALID),
        }
    }
}

/// `id` when it is a plain file id, else [`ARGUMENTS_INVALID`].
fn plain(id: &str) -> Result<&str, &'static str> {
    if plain_file_id(id) {
        Ok(id)
    } else {
        Err(ARGUMENTS_INVALID)
    }
}

/// One document, with the suggestion view and tabs a read asked for.
fn document_get(
    document_id: &str,
    suggestions_view_mode: Option<&str>,
    include_tabs_content: Option<bool>,
) -> Result<WorkspaceWireRequest, &'static str> {
    let mut query = Vec::new();
    if let Some(mode) = suggestions_view_mode {
        query.push(format!("suggestionsViewMode={mode}"));
    }
    if let Some(tabs) = include_tabs_content {
        query.push(format!("includeTabsContent={tabs}"));
    }
    let mut path = format!("/v1/documents/{}", plain(document_id)?);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    WorkspaceWireRequest::new(WorkspaceEndpoint::DocsDocumentGet, path, Vec::new())
}

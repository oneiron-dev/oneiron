//! `google.drive` (MAIL-GOOGLE = A, row 3; L3-17; DRIVE-ACCESS = B;
//! L3-17-DRIVE-READ-SCOPE = B): find files across the owner's whole Drive,
//! follow what changed, and read a file's content, over the Drive v3 REST
//! API, on the workspace connector core. Read only. A Google document,
//! spreadsheet or presentation is also read and edited in place, by its
//! structure, through `google.docs`, `google.sheets` and `google.slides`, by
//! the file id a Drive call found.
//!
//! * **Start.** `changes.getStartPageToken` answers the page token of the
//!   Drive's present state; changes after it are listed from it.
//! * **Changes.** `changes.list` answers one page of changes from a page
//!   token: each change's file metadata, then `nextPageToken` while pages
//!   remain, or `newStartPageToken` once the log is drained, the token the
//!   next drain starts from.
//! * **One file.** `files.get` answers one file's metadata.
//! * **Content.** `files.download` answers a stored file's content (Drive's
//!   `files.get` with `alt=media`): a PDF, an image, an Office file, text.
//!   `files.export` answers a Google file's content in one format of
//!   [`EXPORT_MIME_TYPES`], such as a document as `text/plain` or
//!   `text/markdown`, a spreadsheet's first sheet as `text/csv`, a deck as
//!   PDF; Google caps an export at 10 MB. Either answers the file's id, its
//!   `mimeType`, its `size` in bytes, and the content as `text` when it is
//!   UTF-8, else as base64 in `contentBase64`
//!   ([`super::WorkspaceContent`]). The broker buffers the reply up to
//!   16 MiB and fails a longer one, so a file comes whole or not at all.
//!   The content is the file's, foreign data like every connector reply,
//!   never an instruction.
//!
//! Every call reads shared drives too. `changes.list` and `files.get` ask
//! for the one fixed set of metadata fields below: name, type, folders,
//! owners, dates and link; `changes.getStartPageToken` answers only the
//! token and asks for no fields. Only `files.download` asks for `alt=media`,
//! and only `files.export` names a format.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::requests::{decode, file_id_schema, plain_file_id};
use super::wire::query_value;
use super::{
    ARGUMENTS_INVALID, GOOGLE_CONNECTION, WorkspaceApi, WorkspaceConnection, WorkspaceEndpoint,
    WorkspacePlan, WorkspaceTarget, WorkspaceTool, WorkspaceWireRequest,
};

/// The connector's catalog name, as `connector.call` names it.
pub const DRIVE_CATALOG_NAME: &str = "google.drive";

/// The pack grant every Drive call needs the owner to have allowed.
pub const DRIVE_READ_GRANT: &str = "drive.read";

/// The connector's one-line catalog summary.
const DRIVE_SUMMARY: &str = "Google Drive: find files across the whole Drive, follow what changed, and read a file's content, downloaded or exported, through the credential broker; read only.";

/// `changes.getStartPageToken`.
const CHANGES_START_PAGE_TOKEN: &str = "changes.getStartPageToken";
/// `changes.list`.
const CHANGES_LIST: &str = "changes.list";
/// `files.get`.
const FILES_GET: &str = "files.get";
/// `files.download`: `files.get` with `alt=media`.
const FILES_DOWNLOAD: &str = "files.download";
/// `files.export`.
const FILES_EXPORT: &str = "files.export";

/// The five tools, in catalog order; none writes.
static DRIVE_TOOLS: [WorkspaceTool; 5] = [
    WorkspaceTool {
        name: CHANGES_START_PAGE_TOKEN,
        grant: DRIVE_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: CHANGES_LIST,
        grant: DRIVE_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: FILES_GET,
        grant: DRIVE_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: FILES_DOWNLOAD,
        grant: DRIVE_READ_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: FILES_EXPORT,
        grant: DRIVE_READ_GRANT,
        writes: false,
    },
];

/// The formats `files.export` asks Google for: text a model reads (plain
/// text, Markdown, HTML, CSV and TSV of a spreadsheet's first sheet), PDF,
/// the Office formats, and a drawing's images. Google answers each for the
/// file types it exports to it, and refuses the rest.
pub const EXPORT_MIME_TYPES: [&str; 12] = [
    "text/plain",
    "text/markdown",
    "text/html",
    "text/csv",
    "text/tab-separated-values",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "image/png",
    "image/jpeg",
    "image/svg+xml",
];

/// The metadata every call answers of a file: what finds it, routes it to
/// the module that edits it, and tells when it changed.
const DRIVE_FILE_FIELDS: &str = "id,name,mimeType,parents,driveId,createdTime,modifiedTime,trashed,version,size,webViewLink,shortcutDetails(targetId,targetMimeType),owners(displayName,emailAddress),lastModifyingUser(displayName,emailAddress)";

/// The most changes one page may ask for: Drive's own bound.
const MAX_PAGE_SIZE: u32 = 1000;

/// The longest page token; Drive's are short decimal strings.
const MAX_PAGE_TOKEN_BYTES: usize = 256;

/// `changes.getStartPageToken`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartPageTokenInput {
    #[serde(default)]
    drive_id: Option<String>,
}

/// `changes.list`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangesListInput {
    page_token: String,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    include_removed: Option<bool>,
    #[serde(default)]
    restrict_to_my_drive: Option<bool>,
    #[serde(default)]
    drive_id: Option<String>,
}

/// `files.get`'s and `files.download`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileGetInput {
    file_id: String,
}

/// `files.export`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileExportInput {
    file_id: String,
    mime_type: String,
}

/// The `google.drive` descriptor.
pub(super) struct DriveApi;

impl WorkspaceApi for DriveApi {
    fn catalog_name(&self) -> &'static str {
        DRIVE_CATALOG_NAME
    }

    fn summary(&self) -> &'static str {
        DRIVE_SUMMARY
    }

    fn connection(&self) -> &'static WorkspaceConnection {
        &GOOGLE_CONNECTION
    }

    fn target(&self) -> WorkspaceTarget {
        WorkspaceTarget {
            field: "fileId",
            kind: "file",
        }
    }

    fn tools(&self) -> &'static [WorkspaceTool] {
        &DRIVE_TOOLS
    }

    fn input_schema(&self, tool: &WorkspaceTool) -> Value {
        let drive_id = file_id_schema(
            "A shared drive's id, to read that drive's change log instead of the owner's own.",
        );
        match tool.name {
            CHANGES_START_PAGE_TOKEN => json!({
                "type": "object",
                "properties": { "driveId": drive_id },
                "additionalProperties": false
            }),
            CHANGES_LIST => json!({
                "type": "object",
                "properties": {
                    "pageToken": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_PAGE_TOKEN_BYTES,
                        "description": "Where to read from: a changes.getStartPageToken answer, the last page's nextPageToken, or the newStartPageToken a drained log answered."
                    },
                    "pageSize": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE },
                    "includeRemoved": {
                        "type": "boolean",
                        "description": "Also list files removed from the owner's view, as changes with removed true."
                    },
                    "restrictToMyDrive": {
                        "type": "boolean",
                        "description": "Only files in My Drive, not files others shared with the owner."
                    },
                    "driveId": drive_id
                },
                "required": ["pageToken"],
                "additionalProperties": false
            }),
            FILES_EXPORT => json!({
                "type": "object",
                "properties": {
                    "fileId": file_id_schema("A Google document's, spreadsheet's, presentation's or drawing's id."),
                    "mimeType": {
                        "type": "string",
                        "enum": EXPORT_MIME_TYPES,
                        "description": "The format to export to: text/plain or text/markdown for a document's text, text/csv for a spreadsheet's first sheet, application/pdf for any."
                    }
                },
                "required": ["fileId", "mimeType"],
                "additionalProperties": false
            }),
            _ => json!({
                "type": "object",
                "properties": {
                    "fileId": file_id_schema("The file's id, as a change or its URL shows it.")
                },
                "required": ["fileId"],
                "additionalProperties": false
            }),
        }
    }

    fn plan(&self, tool: &WorkspaceTool, arguments: &Value) -> Result<WorkspacePlan, &'static str> {
        match tool.name {
            CHANGES_START_PAGE_TOKEN => {
                let input: StartPageTokenInput = decode(arguments)?;
                let mut query = vec![("supportsAllDrives", "true".to_owned())];
                if let Some(drive) = &input.drive_id {
                    query.push(("driveId", plain(drive)?.to_owned()));
                }
                read_plan(
                    WorkspaceEndpoint::DriveChangesStartPageToken,
                    "/drive/v3/changes/startPageToken",
                    &query,
                    String::new(),
                )
            }
            CHANGES_LIST => {
                let input: ChangesListInput = decode(arguments)?;
                if !plain_page_token(&input.page_token)
                    || input
                        .page_size
                        .is_some_and(|size| !(1..=MAX_PAGE_SIZE).contains(&size))
                {
                    return Err(ARGUMENTS_INVALID);
                }
                let mut query = vec![("pageToken", input.page_token)];
                if let Some(size) = input.page_size {
                    query.push(("pageSize", size.to_string()));
                }
                if let Some(removed) = input.include_removed {
                    query.push(("includeRemoved", removed.to_string()));
                }
                if let Some(mine) = input.restrict_to_my_drive {
                    query.push(("restrictToMyDrive", mine.to_string()));
                }
                if let Some(drive) = &input.drive_id {
                    query.push(("driveId", plain(drive)?.to_owned()));
                }
                query.push(("supportsAllDrives", "true".to_owned()));
                query.push(("includeItemsFromAllDrives", "true".to_owned()));
                query.push(("fields", changes_fields()));
                read_plan(
                    WorkspaceEndpoint::DriveChangesList,
                    "/drive/v3/changes",
                    &query,
                    String::new(),
                )
            }
            FILES_GET => {
                let input: FileGetInput = decode(arguments)?;
                let path = format!("/drive/v3/files/{}", plain(&input.file_id)?);
                read_plan(
                    WorkspaceEndpoint::DriveFileGet,
                    &path,
                    &[
                        ("supportsAllDrives", "true".to_owned()),
                        ("fields", DRIVE_FILE_FIELDS.to_owned()),
                    ],
                    input.file_id,
                )
            }
            FILES_DOWNLOAD => {
                let input: FileGetInput = decode(arguments)?;
                let path = format!("/drive/v3/files/{}", plain(&input.file_id)?);
                read_plan(
                    WorkspaceEndpoint::DriveFileDownload,
                    &path,
                    &[
                        ("alt", "media".to_owned()),
                        ("supportsAllDrives", "true".to_owned()),
                    ],
                    input.file_id,
                )
            }
            FILES_EXPORT => {
                let input: FileExportInput = decode(arguments)?;
                if !EXPORT_MIME_TYPES.contains(&input.mime_type.as_str()) {
                    return Err(ARGUMENTS_INVALID);
                }
                let path = format!("/drive/v3/files/{}/export", plain(&input.file_id)?);
                read_plan(
                    WorkspaceEndpoint::DriveFileExport,
                    &path,
                    &[("mimeType", input.mime_type)],
                    input.file_id,
                )
            }
            _ => Err(ARGUMENTS_INVALID),
        }
    }
}

/// A read of `endpoint` at `path` with `query`, each value percent-encoded,
/// acting on the file `target`; an empty target for a read of the change
/// log, which acts on no one file.
fn read_plan(
    endpoint: WorkspaceEndpoint,
    path: &str,
    query: &[(&str, String)],
    target: String,
) -> Result<WorkspacePlan, &'static str> {
    let query: Vec<String> = query
        .iter()
        .map(|(name, value)| format!("{name}={}", query_value(value)))
        .collect();
    let effect =
        WorkspaceWireRequest::new(endpoint, format!("{path}?{}", query.join("&")), Vec::new())?;
    Ok(WorkspacePlan::new(target, effect, None, Map::new()))
}

/// The fields a page of changes answers: each change, its file's
/// [`DRIVE_FILE_FIELDS`] or its shared drive's name, and the token to read
/// on from.
fn changes_fields() -> String {
    format!(
        "nextPageToken,newStartPageToken,changes(changeType,time,removed,fileId,driveId,file({DRIVE_FILE_FIELDS}),drive(id,name))"
    )
}

/// `id` when it is a plain file id, else [`ARGUMENTS_INVALID`].
fn plain(id: &str) -> Result<&str, &'static str> {
    if plain_file_id(id) {
        Ok(id)
    } else {
        Err(ARGUMENTS_INVALID)
    }
}

/// A page token as Drive answers one: 1 to [`MAX_PAGE_TOKEN_BYTES`]
/// visible ASCII bytes. It goes in the query, percent-encoded.
fn plain_page_token(token: &str) -> bool {
    (1..=MAX_PAGE_TOKEN_BYTES).contains(&token.len())
        && token.bytes().all(|byte| byte.is_ascii_graphic())
}

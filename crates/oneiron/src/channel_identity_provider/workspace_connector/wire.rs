//! The workspace wire (FIX 4862; L3-17): each call's exact REST request, and
//! the host seam that sends it through the credential broker.
//!
//! The engine builds every request whole: the endpoint, the path with its
//! query, the JSON body, and any header the API names a call's context by
//! (Graph's `workbook-session-id`). The host checks it as the broker will and
//! reaches the broker before the engine reads the grant at the custody door;
//! the broker adds the access token as `Authorization: Bearer`, sends once
//! over verified TLS, and strips the token from the reply. The token goes to
//! the broker with that one request and to nothing else. The host hands the
//! reply back as it came; the engine reads it ([`WorkspaceWireOutcome::answered`]).

use std::fmt::Debug;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::ARGUMENTS_INVALID;

/// The Sheets v4 origin.
const SHEETS_ORIGIN: &str = "https://sheets.googleapis.com";

/// The Docs v1 origin.
const DOCS_ORIGIN: &str = "https://docs.googleapis.com";

/// The Slides v1 origin.
const SLIDES_ORIGIN: &str = "https://slides.googleapis.com";

/// The Drive v3 origin, under Google's shared API host.
const DRIVE_ORIGIN: &str = "https://www.googleapis.com";

/// The Microsoft Graph origin.
const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";

/// The longest path with its query: well inside the broker's frame header.
const MAX_PATH_BYTES: usize = 16 << 10;

/// The largest request body.
const MAX_BODY_BYTES: usize = 8 << 20;

/// The longest header value: the broker's own bound.
const MAX_HEADER_VALUE_BYTES: usize = 1024;

/// The REST endpoint one request calls: one broker shape row each, of the
/// same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceEndpoint {
    /// Sheets v4: `GET /v4/spreadsheets/{id}` with the one field mask.
    SheetsSpreadsheetGet,
    /// Sheets v4: `GET /v4/spreadsheets/{id}/values:batchGet`.
    SheetsValuesBatchGet,
    /// Sheets v4: `POST /v4/spreadsheets/{id}/values:batchUpdate`.
    SheetsValuesBatchUpdate,
    /// Sheets v4: `POST /v4/spreadsheets/{id}:batchUpdate`.
    SheetsBatchUpdate,
    /// Docs v1: `GET /v1/documents/{id}`, its query only
    /// `suggestionsViewMode` and `includeTabsContent`.
    DocsDocumentGet,
    /// Docs v1: `POST /v1/documents/{id}:batchUpdate`.
    DocsBatchUpdate,
    /// Slides v1: `GET /v1/presentations/{id}`.
    SlidesPresentationGet,
    /// Slides v1: `POST /v1/presentations/{id}:batchUpdate`.
    SlidesBatchUpdate,
    /// Drive v3: `GET /drive/v3/changes/startPageToken`.
    DriveChangesStartPageToken,
    /// Drive v3: `GET /drive/v3/changes`, one page of the change log.
    DriveChangesList,
    /// Drive v3: `GET /drive/v3/files/{id}`, one file's metadata.
    DriveFileGet,
    /// Drive v3: `GET /drive/v3/files/{id}?alt=media&supportsAllDrives=true`,
    /// one stored file's content.
    DriveFileDownload,
    /// Drive v3: `GET /drive/v3/files/{id}/export?mimeType=…`, one Google
    /// file's content in one format.
    DriveFileExport,
    /// Graph v1.0: `POST /v1.0/me/drive/items/{id}/workbook/createSession`.
    ExcelCreateSession,
    /// Graph v1.0: `GET /v1.0/me/drive/items/{id}/workbook/worksheets/{name}/range(address='{a1}')`.
    ExcelRangeGet,
    /// Graph v1.0: `PATCH` the same range.
    ExcelRangeUpdate,
    /// Graph v1.0: `POST /v1.0/me/drive/items/{id}/workbook/closeSession`.
    ExcelCloseSession,
}

impl WorkspaceEndpoint {
    /// The origin the endpoint's requests go to.
    #[must_use]
    pub const fn origin(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet
            | Self::SheetsValuesBatchGet
            | Self::SheetsValuesBatchUpdate
            | Self::SheetsBatchUpdate => SHEETS_ORIGIN,
            Self::DocsDocumentGet | Self::DocsBatchUpdate => DOCS_ORIGIN,
            Self::SlidesPresentationGet | Self::SlidesBatchUpdate => SLIDES_ORIGIN,
            Self::DriveChangesStartPageToken
            | Self::DriveChangesList
            | Self::DriveFileGet
            | Self::DriveFileDownload
            | Self::DriveFileExport => DRIVE_ORIGIN,
            Self::ExcelCreateSession
            | Self::ExcelRangeGet
            | Self::ExcelRangeUpdate
            | Self::ExcelCloseSession => GRAPH_ORIGIN,
        }
    }

    /// The wire model a call binds. A workspace API names no model on the
    /// wire, so the broker's binding stands for one: the API and its version.
    #[must_use]
    pub const fn wire_model(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet
            | Self::SheetsValuesBatchGet
            | Self::SheetsValuesBatchUpdate
            | Self::SheetsBatchUpdate => "sheets.v4",
            Self::DocsDocumentGet | Self::DocsBatchUpdate => "docs.v1",
            Self::SlidesPresentationGet | Self::SlidesBatchUpdate => "slides.v1",
            Self::DriveChangesStartPageToken
            | Self::DriveChangesList
            | Self::DriveFileGet
            | Self::DriveFileDownload
            | Self::DriveFileExport => "drive.v3",
            Self::ExcelCreateSession
            | Self::ExcelRangeGet
            | Self::ExcelRangeUpdate
            | Self::ExcelCloseSession => "graph.v1.0",
        }
    }

    /// The HTTP method: `GET` for a read, else `POST`, or `PATCH` for a
    /// Graph range write.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet
            | Self::SheetsValuesBatchGet
            | Self::DocsDocumentGet
            | Self::SlidesPresentationGet
            | Self::DriveChangesStartPageToken
            | Self::DriveChangesList
            | Self::DriveFileGet
            | Self::DriveFileDownload
            | Self::DriveFileExport
            | Self::ExcelRangeGet => "GET",
            Self::SheetsValuesBatchUpdate
            | Self::SheetsBatchUpdate
            | Self::DocsBatchUpdate
            | Self::SlidesBatchUpdate
            | Self::ExcelCreateSession
            | Self::ExcelCloseSession => "POST",
            Self::ExcelRangeUpdate => "PATCH",
        }
    }

    /// Whether a success answers a file's content, its bytes as sent, rather
    /// than one JSON body: Drive's download and export.
    #[must_use]
    pub const fn answers_content(self) -> bool {
        matches!(self, Self::DriveFileDownload | Self::DriveFileExport)
    }

    /// The endpoint's name in a request digest.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet => "sheets.spreadsheets.get",
            Self::SheetsValuesBatchGet => "sheets.values.batchGet",
            Self::SheetsValuesBatchUpdate => "sheets.values.batchUpdate",
            Self::SheetsBatchUpdate => "sheets.spreadsheets.batchUpdate",
            Self::DocsDocumentGet => "docs.documents.get",
            Self::DocsBatchUpdate => "docs.documents.batchUpdate",
            Self::SlidesPresentationGet => "slides.presentations.get",
            Self::SlidesBatchUpdate => "slides.presentations.batchUpdate",
            Self::DriveChangesStartPageToken => "drive.changes.getStartPageToken",
            Self::DriveChangesList => "drive.changes.list",
            Self::DriveFileGet => "drive.files.get",
            Self::DriveFileDownload => "drive.files.download",
            Self::DriveFileExport => "drive.files.export",
            Self::ExcelCreateSession => "excel.workbook.createSession",
            Self::ExcelRangeGet => "excel.range.get",
            Self::ExcelRangeUpdate => "excel.range.update",
            Self::ExcelCloseSession => "excel.workbook.closeSession",
        }
    }
}

/// One exact request under its endpoint's origin: the endpoint, the path
/// with its query, the JSON body, empty for a read, and the headers that
/// name the call's context, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceWireRequest {
    endpoint: WorkspaceEndpoint,
    path: String,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
}

impl WorkspaceWireRequest {
    /// A request within [`MAX_PATH_BYTES`] and [`MAX_BODY_BYTES`], or
    /// [`ARGUMENTS_INVALID`].
    pub(crate) fn new(
        endpoint: WorkspaceEndpoint,
        path: String,
        body: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if path.len() > MAX_PATH_BYTES || body.len() > MAX_BODY_BYTES {
            return Err(ARGUMENTS_INVALID);
        }
        Ok(Self {
            endpoint,
            path,
            body,
            headers: Vec::new(),
        })
    }

    /// The request with the header `name` (lowercase) set to `value`: 1 to
    /// [`MAX_HEADER_VALUE_BYTES`] visible ASCII bytes and no space, or
    /// [`ARGUMENTS_INVALID`].
    pub(crate) fn with_header(
        mut self,
        name: &'static str,
        value: &str,
    ) -> Result<Self, &'static str> {
        let visible = (1..=MAX_HEADER_VALUE_BYTES).contains(&value.len())
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        if !visible || self.headers.iter().any(|(set, _)| *set == name) {
            return Err(ARGUMENTS_INVALID);
        }
        self.headers.push((name, value.to_owned()));
        Ok(self)
    }

    /// The endpoint, which names the broker shape row.
    #[must_use]
    pub const fn endpoint(&self) -> WorkspaceEndpoint {
        self.endpoint
    }

    /// The path under the endpoint's origin, with its query.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The whole URL: the endpoint's origin and the path.
    #[must_use]
    pub fn url(&self) -> String {
        format!("{}{}", self.endpoint.origin(), self.path)
    }

    /// The exact body bytes: one JSON object for a write, none for a read.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The headers that name the call's context, in the order set; the
    /// broker adds the credential's own.
    #[must_use]
    pub fn headers(&self) -> &[(&'static str, String)] {
        &self.headers
    }

    /// The request's digest, lower hex: its endpoint, path and body, then
    /// each header's name and value, each framed by its length. A receipt
    /// names the request by it.
    pub(crate) fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.workspace.wire-request.v1");
        let parts: [&[u8]; 3] = [
            self.endpoint.as_str().as_bytes(),
            self.path.as_bytes(),
            &self.body,
        ];
        let headers = self
            .headers
            .iter()
            .flat_map(|(name, value)| [name.as_bytes(), value.as_bytes()]);
        for part in parts.into_iter().chain(headers) {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// `value` percent-encoded but for letters, digits and `-._~`, in uppercase
/// hex: the one spelling the broker's data-query check takes.
pub(crate) fn query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The host's credential-broker leg for the workspace modules. It holds no
/// custody and no actor authority; the engine calls it on the call's own
/// blocking thread.
pub trait WorkspaceBrokerHost: Debug + Send + Sync {
    /// Checks `request` as the broker will and connects to the broker,
    /// before the engine reads any credential. `call` is the call's id, which
    /// the broker echoes.
    ///
    /// # Errors
    ///
    /// Why the request cannot go, in plain words: a shape the broker refuses,
    /// or no broker to reach. Nothing was sent.
    fn prepare(
        &self,
        request: &WorkspaceWireRequest,
        call: &str,
    ) -> Result<Box<dyn WorkspaceBrokerCall>, String>;
}

/// One checked request on a connected broker, never another.
pub trait WorkspaceBrokerCall: Send {
    /// Sends once, the broker adding `access_token` as the Bearer credential.
    fn present(self: Box<Self>, access_token: &[u8]) -> WorkspaceWireOutcome;
}

/// What one brokered request came to.
#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceWireOutcome {
    /// The provider answered: its status, and its body read as JSON with the
    /// credential stripped; a body that is not JSON reads as `null`.
    Answered { status: u16, body: Value },
    /// The provider answered a content read
    /// ([`WorkspaceEndpoint::answers_content`]) with a success: the file's
    /// content, the credential stripped.
    Content(WorkspaceContent),
    /// Nothing reached the provider: why, as a code.
    NotSent(String),
    /// The request may have reached the provider, and no answer came back:
    /// why, as a code.
    Uncertain(String),
}

impl WorkspaceWireOutcome {
    /// What the provider's reply to a request of `endpoint` came to: its
    /// `status`, the media type its `content-type` header named, if any, and
    /// its `body` with the credential stripped. A content read's success
    /// answers the body as [`Self::Content`]; every other reply answers as
    /// [`Self::Answered`], an error from a content read included.
    #[must_use]
    pub fn answered(
        endpoint: WorkspaceEndpoint,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Self {
        if endpoint.answers_content() && (200..300).contains(&status) {
            return Self::Content(WorkspaceContent::new(content_type, body.to_vec()));
        }
        Self::Answered {
            status,
            body: serde_json::from_slice(body).unwrap_or(Value::Null),
        }
    }

    /// The provider's JSON body, when it answered with a success status.
    pub(super) fn success(&self) -> Option<&Value> {
        match self {
            Self::Answered { status, body } if (200..300).contains(status) => Some(body),
            _ => None,
        }
    }
}

/// One file's content as a content read answered it: the bytes as the
/// provider sent them, and their media type. The broker buffers the reply
/// up to its frame bound (16 MiB) and fails a longer one, so a file is
/// answered whole or not at all, never cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceContent {
    media_type: String,
    bytes: Vec<u8>,
}

impl WorkspaceContent {
    /// `bytes` under the media type of `content_type`, the header's value
    /// without its parameters, in lowercase: `application/octet-stream` when
    /// the reply named none.
    #[must_use]
    pub fn new(content_type: Option<&str>, bytes: Vec<u8>) -> Self {
        let media_type = content_type
            .and_then(|value| value.split(';').next())
            .map(|essence| essence.trim().to_ascii_lowercase())
            .filter(|essence| !essence.is_empty())
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        Self { media_type, bytes }
    }

    /// The media type, such as `text/plain`.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// The bytes as the provider sent them.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The tool's output: `mimeType`, `size` in bytes, and the content as
    /// `text` when it is UTF-8, without a leading byte-order mark, else as
    /// standard base64 in `contentBase64`.
    #[must_use]
    pub fn output(&self) -> Value {
        let mut output = json!({ "mimeType": self.media_type, "size": self.bytes.len() });
        match std::str::from_utf8(&self.bytes) {
            Ok(text) => output["text"] = Value::from(text.strip_prefix('\u{feff}').unwrap_or(text)),
            Err(_) => output["contentBase64"] = Value::from(STANDARD.encode(&self.bytes)),
        }
        output
    }
}

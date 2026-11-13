//! The workspace wire (FIX 4862; L3-17): each call's exact REST request, and
//! the host seam that sends it through the credential broker.
//!
//! The engine builds every request whole: the endpoint, the path with its
//! query, and the JSON body. The host checks it as the broker will and
//! reaches the broker before the engine reads the grant at the custody door;
//! the broker adds the access token as `Authorization: Bearer`, sends once
//! over verified TLS, and strips the token from the reply. The token goes to
//! the broker with that one request and to nothing else.

use std::fmt::Debug;

use serde_json::Value;

use super::ARGUMENTS_INVALID;

/// The Sheets v4 origin.
const SHEETS_ORIGIN: &str = "https://sheets.googleapis.com";

/// The longest path with its query: well inside the broker's frame header.
const MAX_PATH_BYTES: usize = 16 << 10;

/// The largest request body.
const MAX_BODY_BYTES: usize = 8 << 20;

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
        }
    }

    /// The HTTP method: `GET` for a read, else the write's method, which
    /// carries a JSON body.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet | Self::SheetsValuesBatchGet => "GET",
            Self::SheetsValuesBatchUpdate | Self::SheetsBatchUpdate => "POST",
        }
    }

    /// The endpoint's name in a request digest.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SheetsSpreadsheetGet => "sheets.spreadsheets.get",
            Self::SheetsValuesBatchGet => "sheets.values.batchGet",
            Self::SheetsValuesBatchUpdate => "sheets.values.batchUpdate",
            Self::SheetsBatchUpdate => "sheets.spreadsheets.batchUpdate",
        }
    }
}

/// One exact request under its endpoint's origin: the endpoint, the path
/// with its query, and the JSON body, empty for a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceWireRequest {
    endpoint: WorkspaceEndpoint,
    path: String,
    body: Vec<u8>,
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
        })
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

    /// The request's digest, lower hex: its endpoint, path and body, each
    /// framed by its length. A receipt names the request by it.
    pub(crate) fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.workspace.wire-request.v1");
        let parts: [&[u8]; 3] = [
            self.endpoint.as_str().as_bytes(),
            self.path.as_bytes(),
            &self.body,
        ];
        for part in parts {
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
    /// Nothing reached the provider: why, as a code.
    NotSent(String),
    /// The request may have reached the provider, and no answer came back:
    /// why, as a code.
    Uncertain(String),
}

impl WorkspaceWireOutcome {
    /// The provider's body, when it answered with a success status.
    pub(super) fn success(&self) -> Option<&Value> {
        match self {
            Self::Answered { status, body } if (200..300).contains(status) => Some(body),
            _ => None,
        }
    }
}

//! The Sheets wire (FIX 4862): each call's exact Sheets v4 request, and the
//! host seam that sends it through the credential broker.
//!
//! The engine builds every request whole: the endpoint, the path with its
//! query, and the JSON body. The host checks it as the broker will and
//! reaches the broker before the engine reads the grant at the custody door;
//! the broker adds the access token as `Authorization: Bearer`, sends once
//! over verified TLS, and strips the token from the reply. The token goes to
//! the broker with that one request and to nothing else.

use std::fmt::Debug;

use serde_json::{Value, json};

use super::tools::{
    ARGUMENTS_INVALID, MajorDimension, StructuralBatchUpdateInput, ValueRenderOption,
    ValuesBatchUpdateInput,
};

/// The Sheets v4 origin every request goes to.
pub const SHEETS_API_ORIGIN: &str = "https://sheets.googleapis.com";

/// The wire model a Sheets call binds. Sheets names no model on the wire, so
/// the broker's binding stands for one.
pub const SHEETS_WIRE_MODEL: &str = "sheets.v4";

/// The one field mask a metadata read asks for; the broker's
/// `SheetsSpreadsheetGet` row takes this query and no other.
const SPREADSHEET_FIELDS: &str = "fields=spreadsheetId,spreadsheetUrl,properties(title,locale,timeZone),sheets(properties(sheetId,title,index,sheetType,gridProperties))";

/// The longest path with its query: well inside the broker's frame header.
const MAX_PATH_BYTES: usize = 16 << 10;

/// The largest request body.
const MAX_BODY_BYTES: usize = 8 << 20;

/// The Sheets v4 endpoint one request calls: one broker shape row each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheetsEndpoint {
    /// `GET /v4/spreadsheets/{id}` with the one field mask.
    SpreadsheetGet,
    /// `GET /v4/spreadsheets/{id}/values:batchGet`.
    ValuesBatchGet,
    /// `POST /v4/spreadsheets/{id}/values:batchUpdate`.
    ValuesBatchUpdate,
    /// `POST /v4/spreadsheets/{id}:batchUpdate`.
    BatchUpdate,
}

impl SheetsEndpoint {
    /// The endpoint's name in a request digest.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SpreadsheetGet => "spreadsheets.get",
            Self::ValuesBatchGet => "values.batchGet",
            Self::ValuesBatchUpdate => "values.batchUpdate",
            Self::BatchUpdate => "spreadsheets.batchUpdate",
        }
    }
}

/// One exact Sheets v4 request under [`SHEETS_API_ORIGIN`]: its endpoint,
/// its path with its query, and its JSON body, empty for a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheetsWireRequest {
    endpoint: SheetsEndpoint,
    path: String,
    body: Vec<u8>,
}

impl SheetsWireRequest {
    /// The endpoint, which names the broker shape row.
    #[must_use]
    pub const fn endpoint(&self) -> SheetsEndpoint {
        self.endpoint
    }

    /// The path under [`SHEETS_API_ORIGIN`], with its query.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The exact body bytes: one JSON object for a write, none for a read.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// One spreadsheet's metadata.
    pub(super) fn spreadsheet_get(spreadsheet_id: &str) -> Result<Self, &'static str> {
        Self::sized(
            SheetsEndpoint::SpreadsheetGet,
            format!("/v4/spreadsheets/{spreadsheet_id}?{SPREADSHEET_FIELDS}"),
            Vec::new(),
        )
    }

    /// The values of `ranges`, each range percent-encoded in the query.
    pub(super) fn values_batch_get(
        spreadsheet_id: &str,
        ranges: &[&str],
        render: Option<ValueRenderOption>,
        dimension: Option<MajorDimension>,
    ) -> Result<Self, &'static str> {
        let mut query: Vec<String> = ranges
            .iter()
            .map(|range| format!("ranges={}", query_value(range)))
            .collect();
        if let Some(render) = render {
            query.push(format!("valueRenderOption={}", render.as_str()));
        }
        if let Some(dimension) = dimension {
            query.push(format!("majorDimension={}", dimension.as_str()));
        }
        Self::sized(
            SheetsEndpoint::ValuesBatchGet,
            format!(
                "/v4/spreadsheets/{spreadsheet_id}/values:batchGet?{}",
                query.join("&")
            ),
            Vec::new(),
        )
    }

    /// The value write `input` asks for. Google's own echo of the written
    /// values stays off: the readback reads them again.
    pub(super) fn values_batch_update(
        input: &ValuesBatchUpdateInput,
    ) -> Result<Self, &'static str> {
        let data: Vec<Value> = input
            .data
            .iter()
            .map(|range| {
                let mut entry = json!({ "range": range.range, "values": range.values });
                if let Some(dimension) = range.major_dimension {
                    entry["majorDimension"] = Value::from(dimension.as_str());
                }
                entry
            })
            .collect();
        let body = json!({
            "valueInputOption": input.value_input_option.as_str(),
            "data": data,
            "includeValuesInResponse": false
        });
        Self::sized(
            SheetsEndpoint::ValuesBatchUpdate,
            format!(
                "/v4/spreadsheets/{}/values:batchUpdate",
                input.spreadsheet_id
            ),
            serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
        )
    }

    /// The structural requests `input` carries, passed through as written.
    pub(super) fn batch_update(input: &StructuralBatchUpdateInput) -> Result<Self, &'static str> {
        let body = json!({
            "requests": input.requests,
            "includeSpreadsheetInResponse": false
        });
        Self::sized(
            SheetsEndpoint::BatchUpdate,
            format!("/v4/spreadsheets/{}:batchUpdate", input.spreadsheet_id),
            serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
        )
    }

    /// The request's digest, lower hex: its endpoint, path and body, each
    /// framed by its length. A receipt names the request by it.
    pub(super) fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.sheets.wire-request.v1");
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

    /// A request within [`MAX_PATH_BYTES`] and [`MAX_BODY_BYTES`], or
    /// [`ARGUMENTS_INVALID`].
    fn sized(endpoint: SheetsEndpoint, path: String, body: Vec<u8>) -> Result<Self, &'static str> {
        if path.len() > MAX_PATH_BYTES || body.len() > MAX_BODY_BYTES {
            return Err(ARGUMENTS_INVALID);
        }
        Ok(Self {
            endpoint,
            path,
            body,
        })
    }
}

/// `value` percent-encoded but for letters, digits and `-._~`, in uppercase
/// hex: the one spelling the broker's data-query check takes.
fn query_value(value: &str) -> String {
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

/// The host's credential-broker leg for Sheets. It holds no custody and no
/// actor authority; the engine calls it on the call's own blocking thread.
pub trait SheetsBrokerHost: Debug + Send + Sync {
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
        request: &SheetsWireRequest,
        call: &str,
    ) -> Result<Box<dyn SheetsBrokerCall>, String>;
}

/// One checked request on a connected broker, never another.
pub trait SheetsBrokerCall: Send {
    /// Sends once, the broker adding `access_token` as the Bearer credential.
    fn present(self: Box<Self>, access_token: &[u8]) -> SheetsWireOutcome;
}

/// What one brokered Sheets request came to.
#[derive(Debug, Clone, PartialEq)]
pub enum SheetsWireOutcome {
    /// Google answered: its status, and its body read as JSON with the
    /// credential stripped; a body that is not JSON reads as `null`.
    Answered { status: u16, body: Value },
    /// Nothing reached Google: why, as a code.
    NotSent(String),
    /// The request may have reached Google, and no answer came back: why, as
    /// a code.
    Uncertain(String),
}

impl SheetsWireOutcome {
    /// Google's body, when it answered with a success status.
    pub(super) fn success(&self) -> Option<&Value> {
        match self {
            Self::Answered { status, body } if (200..300).contains(status) => Some(body),
            _ => None,
        }
    }
}

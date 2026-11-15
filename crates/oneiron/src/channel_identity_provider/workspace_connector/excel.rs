//! `microsoft.excel` (L3-17; L3-17-EXCEL = A): the ranges of an Excel
//! workbook in the user's OneDrive or SharePoint, read and written in place
//! over the Microsoft Graph workbook API, on the workspace connector core.
//! The workbook stays in Microsoft 365, and the agent edits it there
//! (ARCH-0075 `#edit-in-place`).
//!
//! A workbook session keeps several calls on one copy of the workbook in
//! Excel's calculation service (research-1393): `workbook.createSession`
//! opens one and answers its id, each later call names it as `sessionId`,
//! which goes out as the `workbook-session-id` header, and
//! `workbook.closeSession` ends it. A call that names no session runs on its
//! own.
//!
//! * **Sessions.** `workbook.createSession` (`persistChanges`, true by
//!   default: each write is saved to the file; false: writes last only as
//!   long as the session) and `workbook.closeSession` change no cell.
//! * **Read.** `workbook.range.get` reads one range of one worksheet: its
//!   address, values, formulas, number formats and text.
//! * **Write.** `workbook.range.update` writes values, formulas or number
//!   formats to one range, one array of cells per row, then reads the range
//!   back in the same session.
//!
//! A workbook is named by its drive item id. A worksheet's name goes into
//! the path, so it is held to letters, digits, spaces, `-` and `_`, up to
//! Excel's 31 characters; a range is an A1 address of letters, digits, `$`
//! and `:`.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::requests::{decode, file_id_schema, plain_file_id};
use super::{
    ARGUMENTS_INVALID, MICROSOFT365_CONNECTION, WorkspaceApi, WorkspaceConnection,
    WorkspaceEndpoint, WorkspacePlan, WorkspaceTarget, WorkspaceTool, WorkspaceWireRequest,
};

/// The connector's catalog name, as `connector.call` names it.
pub const EXCEL_CATALOG_NAME: &str = "microsoft.excel";

/// The pack grant every call needs the owner to have allowed: the
/// connection's one Excel permission (`Files.ReadWrite`).
pub const EXCEL_WRITE_GRANT: &str = "excel.write";

/// The header a call names its workbook session by.
pub const WORKBOOK_SESSION_HEADER: &str = "workbook-session-id";

/// The connector's one-line catalog summary.
const EXCEL_SUMMARY: &str = "Microsoft Excel: read and write a workbook's ranges in place, in one workbook session, with a readback after each write, through the credential broker.";

/// `workbook.createSession`.
const CREATE_SESSION: &str = "workbook.createSession";
/// `workbook.range.get`.
const RANGE_GET: &str = "workbook.range.get";
/// `workbook.range.update`.
const RANGE_UPDATE: &str = "workbook.range.update";
/// `workbook.closeSession`.
const CLOSE_SESSION: &str = "workbook.closeSession";

/// Excel's longest worksheet name, in characters.
const MAX_WORKSHEET_CHARS: usize = 31;
/// The longest A1 address.
const MAX_ADDRESS_BYTES: usize = 64;
/// The longest session id: the broker's header bound.
const MAX_SESSION_ID_BYTES: usize = 1024;

/// The four tools, in catalog order.
static EXCEL_TOOLS: [WorkspaceTool; 4] = [
    WorkspaceTool {
        name: CREATE_SESSION,
        grant: EXCEL_WRITE_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: RANGE_GET,
        grant: EXCEL_WRITE_GRANT,
        writes: false,
    },
    WorkspaceTool {
        name: RANGE_UPDATE,
        grant: EXCEL_WRITE_GRANT,
        writes: true,
    },
    WorkspaceTool {
        name: CLOSE_SESSION,
        grant: EXCEL_WRITE_GRANT,
        writes: false,
    },
];

/// `workbook.createSession`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateSessionInput {
    item_id: String,
    #[serde(default = "persist_by_default")]
    persist_changes: bool,
}

/// A session saves its writes to the file unless the call says otherwise.
const fn persist_by_default() -> bool {
    true
}

/// One range of one worksheet, in a session or on its own.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RangeGetInput {
    item_id: String,
    worksheet: String,
    address: String,
    #[serde(default)]
    session_id: Option<String>,
}

/// `workbook.range.update`'s input: the range, and at least one grid to
/// write to it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RangeUpdateInput {
    item_id: String,
    worksheet: String,
    address: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    values: Option<Vec<Vec<Value>>>,
    #[serde(default)]
    formulas: Option<Vec<Vec<Value>>>,
    #[serde(default)]
    number_format: Option<Vec<Vec<Value>>>,
}

/// `workbook.closeSession`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloseSessionInput {
    item_id: String,
    session_id: String,
}

/// The `microsoft.excel` descriptor.
pub(super) struct ExcelApi;

impl WorkspaceApi for ExcelApi {
    fn catalog_name(&self) -> &'static str {
        EXCEL_CATALOG_NAME
    }

    fn summary(&self) -> &'static str {
        EXCEL_SUMMARY
    }

    fn connection(&self) -> &'static WorkspaceConnection {
        &MICROSOFT365_CONNECTION
    }

    fn target(&self) -> WorkspaceTarget {
        WorkspaceTarget {
            field: "itemId",
            kind: "workbook",
        }
    }

    fn tools(&self) -> &'static [WorkspaceTool] {
        &EXCEL_TOOLS
    }

    fn input_schema(&self, tool: &WorkspaceTool) -> Value {
        let item_id = file_id_schema("The workbook's drive item id, as Graph names the file.");
        let session_id = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_SESSION_ID_BYTES,
            "description": "The id workbook.createSession answered; the call runs in that session."
        });
        let worksheet = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_WORKSHEET_CHARS,
            "pattern": "^[A-Za-z0-9_-]+( [A-Za-z0-9_-]+)*$",
            "description": "The worksheet's name: letters, digits, single spaces, - and _."
        });
        let address = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_ADDRESS_BYTES,
            "pattern": "^[A-Za-z0-9$:]+$",
            "description": "The range as an A1 address within the worksheet, such as A1:C3."
        });
        let grid = |what: &str| {
            json!({
                "type": "array",
                "minItems": 1,
                "items": { "type": "array", "minItems": 1 },
                "description": format!("{what}, one array of cells per row of the range; a null cell is left as it is.")
            })
        };
        match tool.name {
            CREATE_SESSION => json!({
                "type": "object",
                "properties": {
                    "itemId": item_id,
                    "persistChanges": {
                        "type": "boolean",
                        "description": "Save each write to the file (the default), or keep writes only for the session's life."
                    }
                },
                "required": ["itemId"],
                "additionalProperties": false
            }),
            RANGE_UPDATE => json!({
                "type": "object",
                "properties": {
                    "itemId": item_id,
                    "worksheet": worksheet,
                    "address": address,
                    "sessionId": session_id,
                    "values": grid("The values to write"),
                    "formulas": grid("The formulas to write, each starting with ="),
                    "numberFormat": grid("The number formats to set, such as 0.00")
                },
                "required": ["itemId", "worksheet", "address"],
                "anyOf": [
                    { "required": ["values"] },
                    { "required": ["formulas"] },
                    { "required": ["numberFormat"] }
                ],
                "additionalProperties": false
            }),
            CLOSE_SESSION => json!({
                "type": "object",
                "properties": { "itemId": item_id, "sessionId": session_id },
                "required": ["itemId", "sessionId"],
                "additionalProperties": false
            }),
            _ => json!({
                "type": "object",
                "properties": {
                    "itemId": item_id,
                    "worksheet": worksheet,
                    "address": address,
                    "sessionId": session_id
                },
                "required": ["itemId", "worksheet", "address"],
                "additionalProperties": false
            }),
        }
    }

    fn plan(&self, tool: &WorkspaceTool, arguments: &Value) -> Result<WorkspacePlan, &'static str> {
        match tool.name {
            CREATE_SESSION => create_session(decode(arguments)?),
            RANGE_GET => {
                let input: RangeGetInput = decode(arguments)?;
                let effect = range_request(WorkspaceEndpoint::ExcelRangeGet, &input, Vec::new())?;
                Ok(WorkspacePlan::new(input.item_id, effect, None, Map::new()))
            }
            RANGE_UPDATE => range_update(decode(arguments)?),
            CLOSE_SESSION => close_session(decode(arguments)?),
            _ => Err(ARGUMENTS_INVALID),
        }
    }
}

/// A session on the workbook: one `POST`, its reply the session's id.
fn create_session(input: CreateSessionInput) -> Result<WorkspacePlan, &'static str> {
    let effect = WorkspaceWireRequest::new(
        WorkspaceEndpoint::ExcelCreateSession,
        format!("{}/createSession", workbook_path(&input.item_id)?),
        body_of(&json!({ "persistChanges": input.persist_changes }))?,
    )?;
    Ok(WorkspacePlan::new(input.item_id, effect, None, Map::new()))
}

/// A range write: one `PATCH` of the grids given, then a read of the range
/// in the same session. The preview names the worksheet, the address and
/// which grids it writes.
fn range_update(input: RangeUpdateInput) -> Result<WorkspacePlan, &'static str> {
    let RangeUpdateInput {
        item_id,
        worksheet,
        address,
        session_id,
        values,
        formulas,
        number_format,
    } = input;
    let range = RangeGetInput {
        item_id,
        worksheet,
        address,
        session_id,
    };
    let mut body = Map::new();
    for (field, grid) in [
        ("values", values),
        ("formulas", formulas),
        ("numberFormat", number_format),
    ] {
        match grid {
            Some(grid) if grid_fits(&grid) => {
                body.insert(field.to_owned(), json!(grid));
            }
            Some(_) => return Err(ARGUMENTS_INVALID),
            None => {}
        }
    }
    if body.is_empty() {
        return Err(ARGUMENTS_INVALID);
    }
    let mut preview = Map::new();
    preview.insert(
        "worksheet".to_owned(),
        Value::from(range.worksheet.as_str()),
    );
    preview.insert("address".to_owned(), Value::from(range.address.as_str()));
    preview.insert("writes".to_owned(), json!(body.keys().collect::<Vec<_>>()));
    let effect = range_request(
        WorkspaceEndpoint::ExcelRangeUpdate,
        &range,
        body_of(&Value::Object(body))?,
    )?;
    let readback = range_request(WorkspaceEndpoint::ExcelRangeGet, &range, Vec::new())?;
    Ok(WorkspacePlan::new(
        range.item_id,
        effect,
        Some(readback),
        preview,
    ))
}

/// A session's end: one `POST` carrying the session's id.
fn close_session(input: CloseSessionInput) -> Result<WorkspacePlan, &'static str> {
    // An action with no parameters takes an empty JSON object.
    let effect = WorkspaceWireRequest::new(
        WorkspaceEndpoint::ExcelCloseSession,
        format!("{}/closeSession", workbook_path(&input.item_id)?),
        body_of(&json!({}))?,
    )?
    .with_header(WORKBOOK_SESSION_HEADER, &input.session_id)?;
    Ok(WorkspacePlan::new(input.item_id, effect, None, Map::new()))
}

/// The workbook of the drive item `item_id`, under the signed-in user's
/// drive.
fn workbook_path(item_id: &str) -> Result<String, &'static str> {
    if !plain_file_id(item_id) {
        return Err(ARGUMENTS_INVALID);
    }
    Ok(format!("/v1.0/me/drive/items/{item_id}/workbook"))
}

/// `range`'s request at `endpoint`, in the session it names when it names
/// one.
fn range_request(
    endpoint: WorkspaceEndpoint,
    range: &RangeGetInput,
    body: Vec<u8>,
) -> Result<WorkspaceWireRequest, &'static str> {
    let (Some(worksheet), true) = (
        worksheet_segment(&range.worksheet),
        plain_address(&range.address),
    ) else {
        return Err(ARGUMENTS_INVALID);
    };
    let request = WorkspaceWireRequest::new(
        endpoint,
        format!(
            "{}/worksheets/{worksheet}/range(address='{}')",
            workbook_path(&range.item_id)?,
            range.address
        ),
        body,
    )?;
    match &range.session_id {
        Some(session_id) => request.with_header(WORKBOOK_SESSION_HEADER, session_id),
        None => Ok(request),
    }
}

/// A worksheet name as its path segment: 1 to [`MAX_WORKSHEET_CHARS`]
/// words of letters, digits, `-` and `_`, joined by single spaces, each
/// space written `%20`. `None` for any other name.
fn worksheet_segment(name: &str) -> Option<String> {
    let plain = (1..=MAX_WORKSHEET_CHARS).contains(&name.len())
        && name.split(' ').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    plain.then(|| name.replace(' ', "%20"))
}

/// An A1 address: 1 to [`MAX_ADDRESS_BYTES`] letters, digits, `$` and `:`.
fn plain_address(address: &str) -> bool {
    (1..=MAX_ADDRESS_BYTES).contains(&address.len())
        && address
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'$' || byte == b':')
}

/// A grid Graph takes: at least one row, each at least one cell, and each
/// cell a string, a number, a boolean, or null to leave the cell as it is.
fn grid_fits(grid: &[Vec<Value>]) -> bool {
    !grid.is_empty()
        && grid.iter().all(|row| {
            !row.is_empty()
                && row
                    .iter()
                    .all(|cell| !matches!(cell, Value::Array(_) | Value::Object(_)))
        })
}

/// `value`'s exact JSON bytes.
fn body_of(value: &Value) -> Result<Vec<u8>, &'static str> {
    serde_json::to_vec(value).map_err(|_| ARGUMENTS_INVALID)
}

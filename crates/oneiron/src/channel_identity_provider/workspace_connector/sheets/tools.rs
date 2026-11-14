//! The four `google.sheets` tools (FIX 4862): their names, typed inputs and input
//! schemas. Arguments are spelled as the Sheets v4 REST fields are, so an
//! agent that knows the API writes them as it knows them. Each input is typed
//! at its top level; a structural request passes through as JSON, checked
//! only to name one request kind.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::super::requests::{
    decode, file_id_schema, plain_file_id, requests_fit, requests_schema,
};
use super::super::{ARGUMENTS_INVALID, WorkspaceTool};
use super::{SHEETS_READ_GRANT, SHEETS_WRITE_GRANT};

/// The most ranges one read or write names.
const MAX_RANGES: usize = 100;
/// The longest A1 range, a quoted sheet name included.
const MAX_RANGE_BYTES: usize = 512;

/// One `google.sheets` tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SheetsTool {
    /// `spreadsheets.get`: the spreadsheet's title, and each sheet's id,
    /// title, index and grid size.
    SpreadsheetGet,
    /// `values.batchGet`: the values of one or more A1 ranges.
    ValuesBatchGet,
    /// `values.batchUpdate`: values written into one or more A1 ranges, and
    /// those ranges read back.
    ValuesBatchUpdate,
    /// `spreadsheets.batchUpdate`: structural requests passed through, and
    /// the spreadsheet's sheets read back.
    StructuralBatchUpdate,
}

impl SheetsTool {
    /// Every tool, in catalog order.
    pub(super) const ALL: [Self; 4] = [
        Self::SpreadsheetGet,
        Self::ValuesBatchGet,
        Self::ValuesBatchUpdate,
        Self::StructuralBatchUpdate,
    ];

    /// The tool's name, as `connector.call` names it.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::SpreadsheetGet => "spreadsheets.get",
            Self::ValuesBatchGet => "values.batchGet",
            Self::ValuesBatchUpdate => "values.batchUpdate",
            Self::StructuralBatchUpdate => "spreadsheets.batchUpdate",
        }
    }

    /// The tool `name` names.
    pub(super) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.as_str() == name)
    }

    /// Whether the tool changes the spreadsheet.
    pub(super) const fn writes(self) -> bool {
        matches!(self, Self::ValuesBatchUpdate | Self::StructuralBatchUpdate)
    }

    /// The pack grant the owner must have allowed for a call of the tool.
    pub(super) const fn grant(self) -> &'static str {
        if self.writes() {
            SHEETS_WRITE_GRANT
        } else {
            SHEETS_READ_GRANT
        }
    }

    /// The tool as the workspace core lists it.
    pub(super) const fn descriptor(self) -> WorkspaceTool {
        WorkspaceTool {
            name: self.as_str(),
            grant: self.grant(),
            writes: self.writes(),
        }
    }

    /// The tool's input schema, typed at its top level.
    pub(super) fn input_schema(self) -> Value {
        let spreadsheet_id = file_id_schema("The spreadsheet's id, as its URL shows it after /d/.");
        let range = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_RANGE_BYTES,
            "description": "An A1 range, such as Sheet1!A1:C10."
        });
        let render = json!({
            "type": "string",
            "enum": ["FORMATTED_VALUE", "UNFORMATTED_VALUE", "FORMULA"]
        });
        let dimension = json!({ "type": "string", "enum": ["ROWS", "COLUMNS"] });
        match self {
            Self::SpreadsheetGet => json!({
                "type": "object",
                "properties": { "spreadsheetId": spreadsheet_id },
                "required": ["spreadsheetId"],
                "additionalProperties": false
            }),
            Self::ValuesBatchGet => json!({
                "type": "object",
                "properties": {
                    "spreadsheetId": spreadsheet_id,
                    "ranges": {
                        "type": "array",
                        "items": range,
                        "minItems": 1,
                        "maxItems": MAX_RANGES
                    },
                    "valueRenderOption": render,
                    "majorDimension": dimension
                },
                "required": ["spreadsheetId", "ranges"],
                "additionalProperties": false
            }),
            Self::ValuesBatchUpdate => json!({
                "type": "object",
                "properties": {
                    "spreadsheetId": spreadsheet_id,
                    "valueInputOption": { "type": "string", "enum": ["RAW", "USER_ENTERED"] },
                    "data": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_RANGES,
                        "items": {
                            "type": "object",
                            "properties": {
                                "range": range,
                                "majorDimension": dimension,
                                "values": {
                                    "type": "array",
                                    "items": {
                                        "type": "array",
                                        "items": { "type": ["string", "number", "boolean", "null"] }
                                    }
                                }
                            },
                            "required": ["range", "values"],
                            "additionalProperties": false
                        }
                    },
                    "responseValueRenderOption": render
                },
                "required": ["spreadsheetId", "valueInputOption", "data"],
                "additionalProperties": false
            }),
            Self::StructuralBatchUpdate => json!({
                "type": "object",
                "properties": {
                    "spreadsheetId": spreadsheet_id,
                    "requests": requests_schema("Sheets v4", "addSheet")
                },
                "required": ["spreadsheetId", "requests"],
                "additionalProperties": false
            }),
        }
    }
}

/// How a read renders cell values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum ValueRenderOption {
    FormattedValue,
    UnformattedValue,
    Formula,
}

impl ValueRenderOption {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::FormattedValue => "FORMATTED_VALUE",
            Self::UnformattedValue => "UNFORMATTED_VALUE",
            Self::Formula => "FORMULA",
        }
    }
}

/// How a write reads the values it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum ValueInputOption {
    Raw,
    UserEntered,
}

impl ValueInputOption {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UserEntered => "USER_ENTERED",
        }
    }
}

/// Whether the outer value lists are rows or columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum MajorDimension {
    Rows,
    Columns,
}

impl MajorDimension {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Rows => "ROWS",
            Self::Columns => "COLUMNS",
        }
    }
}

/// `spreadsheets.get`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpreadsheetGetInput {
    spreadsheet_id: String,
}

/// `values.batchGet`'s input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ValuesBatchGetInput {
    pub(super) spreadsheet_id: String,
    pub(super) ranges: Vec<String>,
    #[serde(default)]
    pub(super) value_render_option: Option<ValueRenderOption>,
    #[serde(default)]
    pub(super) major_dimension: Option<MajorDimension>,
}

/// One range a write fills: its A1 range and its values, row by row unless
/// `majorDimension` says columns.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ValueRangeInput {
    pub(super) range: String,
    #[serde(default)]
    pub(super) major_dimension: Option<MajorDimension>,
    pub(super) values: Vec<Vec<Value>>,
}

/// `values.batchUpdate`'s input. `responseValueRenderOption` renders the
/// readback.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ValuesBatchUpdateInput {
    pub(super) spreadsheet_id: String,
    pub(super) value_input_option: ValueInputOption,
    pub(super) data: Vec<ValueRangeInput>,
    #[serde(default)]
    pub(super) response_value_render_option: Option<ValueRenderOption>,
}

/// `spreadsheets.batchUpdate`'s input: each request one object naming one
/// request kind, passed through as written.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StructuralBatchUpdateInput {
    pub(super) spreadsheet_id: String,
    pub(super) requests: Vec<Map<String, Value>>,
}

/// One call's checked input.
#[derive(Debug)]
pub(super) enum SheetsCall {
    SpreadsheetGet { spreadsheet_id: String },
    ValuesBatchGet(ValuesBatchGetInput),
    ValuesBatchUpdate(ValuesBatchUpdateInput),
    StructuralBatchUpdate(StructuralBatchUpdateInput),
}

impl SheetsCall {
    /// `arguments` read as `tool`'s input and checked, or
    /// [`ARGUMENTS_INVALID`].
    pub(super) fn parse(tool: SheetsTool, arguments: &Value) -> Result<Self, &'static str> {
        let call = match tool {
            SheetsTool::SpreadsheetGet => {
                let input: SpreadsheetGetInput = decode(arguments)?;
                Self::SpreadsheetGet {
                    spreadsheet_id: input.spreadsheet_id,
                }
            }
            SheetsTool::ValuesBatchGet => Self::ValuesBatchGet(decode(arguments)?),
            SheetsTool::ValuesBatchUpdate => Self::ValuesBatchUpdate(decode(arguments)?),
            SheetsTool::StructuralBatchUpdate => Self::StructuralBatchUpdate(decode(arguments)?),
        };
        if call.fits() {
            Ok(call)
        } else {
            Err(ARGUMENTS_INVALID)
        }
    }

    pub(super) fn spreadsheet_id(&self) -> &str {
        match self {
            Self::SpreadsheetGet { spreadsheet_id } => spreadsheet_id,
            Self::ValuesBatchGet(input) => &input.spreadsheet_id,
            Self::ValuesBatchUpdate(input) => &input.spreadsheet_id,
            Self::StructuralBatchUpdate(input) => &input.spreadsheet_id,
        }
    }

    /// Whether the input is within the tool's bounds: a plain spreadsheet
    /// id, 1 to [`MAX_RANGES`] plain ranges, cells that are JSON scalars,
    /// and a batch of requests that each name one request kind.
    fn fits(&self) -> bool {
        plain_file_id(self.spreadsheet_id())
            && match self {
                Self::SpreadsheetGet { .. } => true,
                Self::ValuesBatchGet(input) => ranges_fit(input.ranges.iter()),
                Self::ValuesBatchUpdate(input) => {
                    ranges_fit(input.data.iter().map(|range| &range.range))
                        && input
                            .data
                            .iter()
                            .flat_map(|range| range.values.iter().flatten())
                            .all(scalar)
                }
                Self::StructuralBatchUpdate(input) => requests_fit(&input.requests),
            }
    }
}

/// 1 to [`MAX_RANGES`] ranges, each [`plain_range`].
fn ranges_fit<R: AsRef<str>>(mut ranges: impl ExactSizeIterator<Item = R>) -> bool {
    (1..=MAX_RANGES).contains(&ranges.len()) && ranges.all(|range| plain_range(range.as_ref()))
}

/// A range that is not blank, within [`MAX_RANGE_BYTES`], and free of
/// control characters.
fn plain_range(range: &str) -> bool {
    !range.trim().is_empty()
        && range.len() <= MAX_RANGE_BYTES
        && !range.chars().any(char::is_control)
}

/// A cell Google takes: a string, a number, a boolean, or null to leave the
/// cell as it is.
fn scalar(cell: &Value) -> bool {
    !matches!(cell, Value::Array(_) | Value::Object(_))
}

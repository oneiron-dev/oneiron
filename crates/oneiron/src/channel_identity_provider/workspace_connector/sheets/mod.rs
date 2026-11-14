//! `google.sheets` (FIX 4862; MAIL-GOOGLE = A, row 1): four tools over the
//! Sheets v4 REST API, on the workspace connector core.
//!
//! * **Reads.** `spreadsheets.get` reads a spreadsheet's title and each
//!   sheet's id, title, index and grid size; `values.batchGet` reads the
//!   values of one or more A1 ranges.
//! * **Writes.** `values.batchUpdate` writes values into A1 ranges and reads
//!   them back; `spreadsheets.batchUpdate` passes structural requests through
//!   and reads the sheets back.

mod tools;
mod wire;

use serde_json::Value;

use self::tools::{SheetsCall, SheetsTool};
use super::{
    ARGUMENTS_INVALID, GOOGLE_CONNECTION, WorkspaceApi, WorkspaceConnection, WorkspacePlan,
    WorkspaceTarget, WorkspaceTool,
};

/// The connector's catalog name, as `connector.call` names it.
pub const SHEETS_CATALOG_NAME: &str = "google.sheets";

/// The pack grant each read needs the owner to have allowed.
pub const SHEETS_READ_GRANT: &str = "sheets.read";

/// The pack grant each write needs the owner to have allowed.
pub const SHEETS_WRITE_GRANT: &str = "sheets.write";

/// The connector's one-line catalog summary.
const SHEETS_SUMMARY: &str = "Google Sheets: read sheets and cell values, and write values and sheet structure with a readback, through the credential broker.";

/// The four tools, in catalog order.
static SHEETS_TOOLS: [WorkspaceTool; 4] = [
    SheetsTool::SpreadsheetGet.descriptor(),
    SheetsTool::ValuesBatchGet.descriptor(),
    SheetsTool::ValuesBatchUpdate.descriptor(),
    SheetsTool::StructuralBatchUpdate.descriptor(),
];

/// The `google.sheets` descriptor.
pub(super) struct SheetsApi;

impl WorkspaceApi for SheetsApi {
    fn catalog_name(&self) -> &'static str {
        SHEETS_CATALOG_NAME
    }

    fn summary(&self) -> &'static str {
        SHEETS_SUMMARY
    }

    fn connection(&self) -> &'static WorkspaceConnection {
        &GOOGLE_CONNECTION
    }

    fn target(&self) -> WorkspaceTarget {
        WorkspaceTarget {
            field: "spreadsheetId",
            kind: "spreadsheet",
        }
    }

    fn tools(&self) -> &'static [WorkspaceTool] {
        &SHEETS_TOOLS
    }

    fn input_schema(&self, tool: &WorkspaceTool) -> Value {
        SheetsTool::parse(tool.name).map_or(Value::Null, SheetsTool::input_schema)
    }

    fn plan(&self, tool: &WorkspaceTool, arguments: &Value) -> Result<WorkspacePlan, &'static str> {
        let tool = SheetsTool::parse(tool.name).ok_or(ARGUMENTS_INVALID)?;
        wire::plan(&SheetsCall::parse(tool, arguments)?)
    }
}

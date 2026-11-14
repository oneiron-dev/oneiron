//! Each `google.sheets` call's exact Sheets v4 requests (FIX 4862): its
//! effect, and after a write the read that reads it back.

use serde_json::{Map, Value, json};

use super::super::wire::query_value;
use super::super::{ARGUMENTS_INVALID, WorkspaceEndpoint, WorkspacePlan, WorkspaceWireRequest};
use super::tools::{
    MajorDimension, SheetsCall, StructuralBatchUpdateInput, ValueRenderOption,
    ValuesBatchUpdateInput,
};

/// The one field mask a metadata read asks for; the broker's
/// `SheetsSpreadsheetGet` row takes this query and no other.
const SPREADSHEET_FIELDS: &str = "fields=spreadsheetId,spreadsheetUrl,properties(title,locale,timeZone),sheets(properties(sheetId,title,index,sheetType,gridProperties))";

/// The exact requests `call` sends, and what a write's preview shows of it:
/// the ranges it writes or the request kinds it carries. Or the reason code
/// its input does not fit a request.
pub(super) fn plan(call: &SheetsCall) -> Result<WorkspacePlan, &'static str> {
    let target = call.spreadsheet_id().to_owned();
    let mut preview = Map::new();
    let (effect, readback) = match call {
        SheetsCall::SpreadsheetGet { spreadsheet_id } => (spreadsheet_get(spreadsheet_id)?, None),
        SheetsCall::ValuesBatchGet(input) => {
            let ranges: Vec<&str> = input.ranges.iter().map(String::as_str).collect();
            let effect = values_batch_get(
                &input.spreadsheet_id,
                &ranges,
                input.value_render_option,
                input.major_dimension,
            )?;
            (effect, None)
        }
        SheetsCall::ValuesBatchUpdate(input) => {
            let ranges: Vec<&str> = input
                .data
                .iter()
                .map(|range| range.range.as_str())
                .collect();
            preview.insert("ranges".to_owned(), json!(ranges));
            let readback = values_batch_get(
                &input.spreadsheet_id,
                &ranges,
                input.response_value_render_option,
                None,
            )?;
            (values_batch_update(input)?, Some(readback))
        }
        SheetsCall::StructuralBatchUpdate(input) => {
            let kinds: Vec<&str> = input
                .requests
                .iter()
                .filter_map(|request| request.keys().next().map(String::as_str))
                .collect();
            preview.insert("requests".to_owned(), json!(kinds));
            (
                batch_update(input)?,
                Some(spreadsheet_get(&input.spreadsheet_id)?),
            )
        }
    };
    Ok(WorkspacePlan::new(target, effect, readback, preview))
}

/// One spreadsheet's metadata.
fn spreadsheet_get(spreadsheet_id: &str) -> Result<WorkspaceWireRequest, &'static str> {
    WorkspaceWireRequest::new(
        WorkspaceEndpoint::SheetsSpreadsheetGet,
        format!("/v4/spreadsheets/{spreadsheet_id}?{SPREADSHEET_FIELDS}"),
        Vec::new(),
    )
}

/// The values of `ranges`, each range percent-encoded in the query.
fn values_batch_get(
    spreadsheet_id: &str,
    ranges: &[&str],
    render: Option<ValueRenderOption>,
    dimension: Option<MajorDimension>,
) -> Result<WorkspaceWireRequest, &'static str> {
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
    WorkspaceWireRequest::new(
        WorkspaceEndpoint::SheetsValuesBatchGet,
        format!(
            "/v4/spreadsheets/{spreadsheet_id}/values:batchGet?{}",
            query.join("&")
        ),
        Vec::new(),
    )
}

/// The value write `input` asks for. Google's own echo of the written values
/// stays off: the readback reads them again.
fn values_batch_update(
    input: &ValuesBatchUpdateInput,
) -> Result<WorkspaceWireRequest, &'static str> {
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
    WorkspaceWireRequest::new(
        WorkspaceEndpoint::SheetsValuesBatchUpdate,
        format!(
            "/v4/spreadsheets/{}/values:batchUpdate",
            input.spreadsheet_id
        ),
        serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
    )
}

/// The structural requests `input` carries, passed through as written.
fn batch_update(input: &StructuralBatchUpdateInput) -> Result<WorkspaceWireRequest, &'static str> {
    let body = json!({
        "requests": input.requests,
        "includeSpreadsheetInResponse": false
    });
    WorkspaceWireRequest::new(
        WorkspaceEndpoint::SheetsBatchUpdate,
        format!("/v4/spreadsheets/{}:batchUpdate", input.spreadsheet_id),
        serde_json::to_vec(&body).map_err(|_| ARGUMENTS_INVALID)?,
    )
}

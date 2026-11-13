//! The workspace connector core (L3-17, PR 1): `google.sheets` is one module
//! on it, and keeps its four tools with their grants and its exact Sheets v4
//! requests. Its refusals: tests/google_connection_routes.rs.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test workspace_connector_routes`

use oneiron::channel_identity_provider::workspace_connector::{
    GOOGLE_CONNECTION, WorkspaceEndpoint, module, workspace_manifest,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKSPACE_ROUTES_TEST_SPREADSHEET: &str = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";

#[test]
fn sheets_keeps_its_four_tools_on_the_core() -> TestResult {
    let sheets = module("google.sheets").ok_or("google.sheets routes to no module")?;
    assert_eq!(sheets.catalog_name(), "google.sheets");
    let tools: Vec<(&str, &str, bool)> = sheets
        .tools()
        .iter()
        .map(|tool| (tool.name, tool.grant, tool.writes))
        .collect();
    assert_eq!(
        tools,
        vec![
            ("spreadsheets.get", "sheets.read", false),
            ("values.batchGet", "sheets.read", false),
            ("values.batchUpdate", "sheets.write", true),
            ("spreadsheets.batchUpdate", "sheets.write", true),
        ],
        "the four tools, in catalog order, with their grants"
    );
    let connection = sheets.connection();
    assert_eq!(connection.pack, "oneiron.google");
    assert_eq!(connection.connection, "google");
    assert_eq!(connection.effector, "connector:google");
    assert!(
        std::ptr::eq(connection, &GOOGLE_CONNECTION),
        "Sheets presents the one Google connection"
    );
    let manifest = workspace_manifest(sheets)?;
    let declared: Vec<&str> = manifest
        .tools()
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    assert_eq!(
        declared,
        vec![
            "spreadsheets.get",
            "values.batchGet",
            "values.batchUpdate",
            "spreadsheets.batchUpdate"
        ]
    );
    assert!(
        module("google.sheetz").is_none() && module("Google.Sheets").is_none(),
        "only the exact catalog name routes"
    );
    Ok(())
}

#[test]
fn sheets_write_plan_is_one_post_then_a_read_back() -> TestResult {
    let sheets = module("google.sheets").ok_or("google.sheets routes to no module")?;
    let tool = |name: &str| {
        sheets
            .tools()
            .iter()
            .find(|tool| tool.name == name)
            .ok_or("no such Sheets tool")
    };
    let write = sheets
        .plan(
            tool("values.batchUpdate")?,
            &json!({
                "spreadsheetId": WORKSPACE_ROUTES_TEST_SPREADSHEET,
                "valueInputOption": "RAW",
                "data": [{ "range": "Sheet1!A1:B1", "values": [["owen", 2]] }]
            }),
        )
        .map_err(|reason| format!("the write's plan was refused: {reason}"))?;
    assert_eq!(write.target(), WORKSPACE_ROUTES_TEST_SPREADSHEET);
    assert_eq!(
        write.effect().endpoint(),
        WorkspaceEndpoint::SheetsValuesBatchUpdate
    );
    assert_eq!(write.effect().endpoint().method(), "POST");
    assert_eq!(
        write.effect().url(),
        format!(
            "https://sheets.googleapis.com/v4/spreadsheets/{WORKSPACE_ROUTES_TEST_SPREADSHEET}/values:batchUpdate"
        )
    );
    let body: serde_json::Value = serde_json::from_slice(write.effect().body())?;
    assert_eq!(
        body,
        json!({
            "valueInputOption": "RAW",
            "data": [{ "range": "Sheet1!A1:B1", "values": [["owen", 2]] }],
            "includeValuesInResponse": false
        })
    );
    let readback = write.readback().ok_or("a write reads its ranges back")?;
    assert_eq!(readback.endpoint().method(), "GET");
    assert_eq!(
        readback.url(),
        format!(
            "https://sheets.googleapis.com/v4/spreadsheets/{WORKSPACE_ROUTES_TEST_SPREADSHEET}/values:batchGet?ranges=Sheet1%21A1%3AB1"
        )
    );
    assert!(readback.body().is_empty());

    let read = sheets
        .plan(
            tool("values.batchGet")?,
            &json!({ "spreadsheetId": WORKSPACE_ROUTES_TEST_SPREADSHEET, "ranges": ["A1"] }),
        )
        .map_err(|reason| format!("the read's plan was refused: {reason}"))?;
    assert!(read.readback().is_none(), "a read sends one request");
    assert_eq!(
        sheets
            .plan(
                tool("values.batchGet")?,
                &json!({ "spreadsheetId": "not/an/id", "ranges": ["A1"] })
            )
            .err(),
        Some("connector_arguments_invalid"),
        "a spreadsheet id outside Google's alphabet is refused before anything is sent"
    );
    Ok(())
}

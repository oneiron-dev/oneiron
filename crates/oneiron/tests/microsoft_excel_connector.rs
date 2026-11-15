//! `microsoft.excel` on the workspace connector core (L3-17 PR 4;
//! L3-17-EXCEL-CONNECTION = B): it routes to the built-in through the
//! Microsoft 365 connection of the `oneiron.microsoft365` pack, and declares
//! its four workbook tools under the one Excel permission. Uses only doors
//! PR 2 has, so its red there is a wrong value, not a missing door.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test microsoft_excel_connector`

use oneiron::channel_identity_provider::workspace_connector::{module, workspace_manifest};
use oneiron::verbs::{ConnectorSchemaRequest, connector_schema_read};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXCEL_TOOLS: [&str; 4] = [
    "workbook.createSession",
    "workbook.range.get",
    "workbook.range.update",
    "workbook.closeSession",
];

#[test]
fn excel_schema_routes_to_the_microsoft365_connection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for tool in EXCEL_TOOLS {
        let reply = connector_schema_read(
            &memory,
            ConnectorSchemaRequest {
                name: "microsoft.excel".to_owned(),
                source: None,
                tool: tool.to_owned(),
            },
        )?;
        assert_eq!(reply.input_schema, None, "{tool}");
        assert_eq!(
            reply.reasons,
            vec!["microsoft365_connection_not_checked".to_owned()],
            "{tool} answers as the built-in, through the Microsoft 365 connection"
        );
    }
    Ok(())
}

#[test]
fn excel_declares_four_workbook_tools_under_one_permission() -> TestResult {
    let api = module("microsoft.excel").ok_or("microsoft.excel routes to no module")?;
    let tools: Vec<(&str, &str, bool)> = api
        .tools()
        .iter()
        .map(|tool| (tool.name, tool.grant, tool.writes))
        .collect();
    assert_eq!(
        tools,
        vec![
            (EXCEL_TOOLS[0], "excel.write", false),
            (EXCEL_TOOLS[1], "excel.write", false),
            (EXCEL_TOOLS[2], "excel.write", true),
            (EXCEL_TOOLS[3], "excel.write", false),
        ]
    );
    let connection = api.connection();
    assert_eq!(
        (connection.pack, connection.connection, connection.effector),
        (
            "oneiron.microsoft365",
            "microsoft365",
            "connector:microsoft365"
        ),
        "the effector the Microsoft 365 mail wire reads, so one grant serves both"
    );
    let manifest = workspace_manifest(api)?;
    let schema = |name: &str| {
        manifest
            .tools()
            .iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.input_schema.clone())
            .ok_or_else(|| format!("microsoft.excel declares no {name}"))
    };
    assert_eq!(schema(EXCEL_TOOLS[0])?["required"], json!(["itemId"]));
    for tool in [EXCEL_TOOLS[1], EXCEL_TOOLS[2]] {
        assert_eq!(
            schema(tool)?["required"],
            json!(["itemId", "worksheet", "address"]),
            "{tool}"
        );
    }
    assert_eq!(
        schema(EXCEL_TOOLS[3])?["required"],
        json!(["itemId", "sessionId"])
    );
    Ok(())
}

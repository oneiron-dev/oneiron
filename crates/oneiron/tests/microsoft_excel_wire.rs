//! The `microsoft.excel` wire (L3-17 PR 4): calls in one workbook session
//! carry its id as the `workbook-session-id` header on Graph's workbook
//! paths; a worksheet name, an address, an item id or a session id outside
//! the path and header alphabets is refused before anything is sent; and the
//! Microsoft 365 connection presents a grant that names no Microsoft tenant
//! as it is, so a Microsoft refresh token never reaches Google's token
//! endpoint (RULING L3-17-EXCEL-CONNECTION, 14 Nov 06:23). A grant the
//! Microsoft code exchange stored refreshes at Microsoft:
//! tests/microsoft365_connection_refresh.rs.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test microsoft_excel_wire`

use oneiron::channel_identity_provider::workspace_connector::{
    WorkspaceEndpoint, WorkspacePlan, WorkspaceWireRequest, module,
};
use oneiron::test_doors::workspace_token::access_token_offline;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One request as a test compares it: its endpoint, method, URL, headers,
/// and body as JSON (null when empty).
type ExcelTestRequest = (
    WorkspaceEndpoint,
    &'static str,
    String,
    Vec<(String, String)>,
    Value,
);

const EXCEL_TEST_ITEM: &str = "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K";
/// A session id as Graph spells one: `=`, `&`, `%` and `.` in it.
const EXCEL_TEST_SESSION: &str = "cluster=PSG1&session=15.SG2PEPF00004F38.A82.1.V24.7737Nwad4oPuVafaO%2fTt8V9mv11.5.en-US5.en-US26";

/// The plan `microsoft.excel`'s tool `name` makes of `arguments`, or its
/// refusal.
fn excel_test_plan(
    name: &str,
    arguments: &Value,
) -> TestResult<Result<WorkspacePlan, &'static str>> {
    let api = module("microsoft.excel").ok_or("microsoft.excel routes to no module")?;
    let tool = api
        .tools()
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| format!("microsoft.excel has no tool {name}"))?;
    Ok(api.plan(tool, arguments))
}

/// `request` as (endpoint, method, URL, headers, body as JSON or null).
fn excel_test_request(request: &WorkspaceWireRequest) -> ExcelTestRequest {
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect();
    let body = if request.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(request.body()).unwrap_or(Value::Null)
    };
    (
        request.endpoint(),
        request.endpoint().method(),
        request.url(),
        headers,
        body,
    )
}

#[test]
fn excel_calls_in_one_session_carry_its_id() -> TestResult {
    let workbook =
        format!("https://graph.microsoft.com/v1.0/me/drive/items/{EXCEL_TEST_ITEM}/workbook");
    let session = vec![(
        "workbook-session-id".to_owned(),
        EXCEL_TEST_SESSION.to_owned(),
    )];

    let create = excel_test_plan(
        "workbook.createSession",
        &json!({ "itemId": EXCEL_TEST_ITEM }),
    )??;
    assert_eq!(create.target(), EXCEL_TEST_ITEM);
    assert_eq!(
        excel_test_request(create.effect()),
        (
            WorkspaceEndpoint::ExcelCreateSession,
            "POST",
            format!("{workbook}/createSession"),
            Vec::new(),
            json!({ "persistChanges": true }),
        )
    );
    assert!(create.readback().is_none(), "a session changes no cell");
    let scratch = excel_test_plan(
        "workbook.createSession",
        &json!({ "itemId": EXCEL_TEST_ITEM, "persistChanges": false }),
    )??;
    assert_eq!(
        excel_test_request(scratch.effect()).4,
        json!({ "persistChanges": false })
    );

    let range = format!("{workbook}/worksheets/Q1%20Plan/range(address='A1:B2')");
    let update = excel_test_plan(
        "workbook.range.update",
        &json!({
            "itemId": EXCEL_TEST_ITEM,
            "worksheet": "Q1 Plan",
            "address": "A1:B2",
            "sessionId": EXCEL_TEST_SESSION,
            "values": [[1, "owen"], [null, true]],
            "formulas": [["=SUM(C1:C9)", null], [null, null]]
        }),
    )??;
    assert_eq!(
        excel_test_request(update.effect()),
        (
            WorkspaceEndpoint::ExcelRangeUpdate,
            "PATCH",
            range.clone(),
            session.clone(),
            json!({
                "values": [[1, "owen"], [null, true]],
                "formulas": [["=SUM(C1:C9)", null], [null, null]]
            }),
        )
    );
    let readback = update
        .readback()
        .ok_or("a range write reads the range back")?;
    assert_eq!(
        excel_test_request(readback),
        (
            WorkspaceEndpoint::ExcelRangeGet,
            "GET",
            range,
            session.clone(),
            Value::Null,
        ),
        "the readback runs in the write's session"
    );

    let read = excel_test_plan(
        "workbook.range.get",
        &json!({
            "itemId": EXCEL_TEST_ITEM,
            "worksheet": "Q1 Plan",
            "address": "A1:B2",
            "sessionId": EXCEL_TEST_SESSION
        }),
    )??;
    assert_eq!(excel_test_request(read.effect()).3, session);
    assert!(read.readback().is_none());
    let alone = excel_test_plan(
        "workbook.range.get",
        &json!({ "itemId": EXCEL_TEST_ITEM, "worksheet": "Sheet1", "address": "$A$1" }),
    )??;
    assert_eq!(
        excel_test_request(alone.effect()),
        (
            WorkspaceEndpoint::ExcelRangeGet,
            "GET",
            format!("{workbook}/worksheets/Sheet1/range(address='$A$1')"),
            Vec::new(),
            Value::Null,
        ),
        "a call that names no session runs on its own"
    );

    let close = excel_test_plan(
        "workbook.closeSession",
        &json!({ "itemId": EXCEL_TEST_ITEM, "sessionId": EXCEL_TEST_SESSION }),
    )??;
    assert_eq!(
        excel_test_request(close.effect()),
        (
            WorkspaceEndpoint::ExcelCloseSession,
            "POST",
            format!("{workbook}/closeSession"),
            session,
            json!({}),
        )
    );
    Ok(())
}

#[test]
fn excel_inputs_outside_the_path_alphabet_are_refused() -> TestResult {
    let range = |worksheet: &str, address: &str| json!({ "itemId": EXCEL_TEST_ITEM, "worksheet": worksheet, "address": address });
    let long_session = "s".repeat(1025);
    let refused = [
        ("workbook.range.get", range("a/b", "A1")),
        ("workbook.range.get", range("..", "A1")),
        ("workbook.range.get", range("Sheet'1", "A1")),
        ("workbook.range.get", range(" Sheet1", "A1")),
        ("workbook.range.get", range("Sheet  1", "A1")),
        ("workbook.range.get", range("Sheet%2F1", "A1")),
        ("workbook.range.get", range("x".repeat(32).as_str(), "A1")),
        ("workbook.range.get", range("Sheet1", "A1')/x")),
        ("workbook.range.get", range("Sheet1", "Sheet2!A1")),
        ("workbook.range.get", range("Sheet1", "")),
        (
            "workbook.range.get",
            json!({ "itemId": "a.b", "worksheet": "Sheet1", "address": "A1" }),
        ),
        (
            "workbook.range.get",
            json!({ "itemId": EXCEL_TEST_ITEM, "worksheet": "Sheet1", "address": "A1", "sessionId": "two words" }),
        ),
        (
            "workbook.closeSession",
            json!({ "itemId": EXCEL_TEST_ITEM, "sessionId": "" }),
        ),
        (
            "workbook.closeSession",
            json!({ "itemId": EXCEL_TEST_ITEM, "sessionId": long_session }),
        ),
        ("workbook.range.update", range("Sheet1", "A1")),
        (
            "workbook.range.update",
            json!({ "itemId": EXCEL_TEST_ITEM, "worksheet": "Sheet1", "address": "A1", "values": [[[1]]] }),
        ),
        (
            "workbook.range.update",
            json!({ "itemId": EXCEL_TEST_ITEM, "worksheet": "Sheet1", "address": "A1", "values": [[]] }),
        ),
        (
            "workbook.createSession",
            json!({ "itemId": EXCEL_TEST_ITEM, "mode": "scratch" }),
        ),
    ];
    for (tool, arguments) in &refused {
        assert_eq!(
            excel_test_plan(tool, arguments)?.err(),
            Some("connector_arguments_invalid"),
            "{tool} {arguments}"
        );
    }
    Ok(())
}

#[test]
fn a_microsoft_grant_never_reaches_googles_token_endpoint() -> TestResult {
    // A refresh token and a client id: what a Google grant carries, and
    // what a Microsoft sign-in returns too.
    let grant =
        br#"{"access_token":"ms-access","refresh_token":"ms-refresh","client_id":"ms-client"}"#;
    assert_eq!(
        access_token_offline("microsoft.excel", grant)?,
        "ms-access",
        "a grant naming no tenant: the Microsoft 365 connection presents its stored access token and exchanges nothing"
    );
    assert_eq!(
        access_token_offline("microsoft.excel", b"ms-bare")?,
        "ms-bare"
    );
    assert!(
        access_token_offline("google.sheets", grant).is_err(),
        "the Google connection tries the exchange with the same grant, and the door's client reaches nothing"
    );
    Ok(())
}

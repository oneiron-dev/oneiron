//! `google.drive` on the workspace connector core (L3-17, PR 3;
//! DRIVE-ACCESS = B): it routes to the built-in through the one Google
//! connection, declares three reads under the one `drive.read` grant, and
//! plans each as one `GET` under Drive v3 with the one fixed field mask and
//! no content download. Uses only doors main has, so its red there is a
//! wrong value, not a missing door.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test google_drive_connector`

use oneiron::channel_identity_provider::workspace_connector::{
    WorkspacePlan, module, workspace_manifest,
};
use oneiron::verbs::{ConnectorSchemaRequest, connector_schema_read};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DRIVE_TEST_FILE: &str = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";
const DRIVE_TEST_SHARED_DRIVE: &str = "0AOwenSharedDrive_yuki";

/// The metadata each Drive read asks for of a file.
const DRIVE_TEST_FILE_FIELDS: &str = "id,name,mimeType,parents,driveId,createdTime,modifiedTime,trashed,version,size,webViewLink,shortcutDetails(targetId,targetMimeType),owners(displayName,emailAddress),lastModifyingUser(displayName,emailAddress)";

/// The plan `google.drive`'s tool `name` makes of `arguments`, or its
/// refusal.
fn drive_test_plan(
    name: &str,
    arguments: &Value,
) -> TestResult<Result<WorkspacePlan, &'static str>> {
    let api = module("google.drive").ok_or("google.drive routes to no module")?;
    let tool = api
        .tools()
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| format!("google.drive has no tool {name}"))?;
    Ok(api.plan(tool, arguments))
}

/// A URL's path and its query as `(name, value)` pairs in order, each value
/// percent-decoded.
fn drive_test_query(url: &str) -> TestResult<(String, Vec<(String, String)>)> {
    let (path, query) = url.split_once('?').ok_or("the read carries a query")?;
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or("a query pair has a value")?;
        let bytes = value.as_bytes();
        let mut decoded = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = value.get(index + 1..index + 3).ok_or("a whole escape")?;
                decoded.push(u8::from_str_radix(hex, 16)?);
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        pairs.push((name.to_owned(), String::from_utf8(decoded)?));
    }
    Ok((path.to_owned(), pairs))
}

#[test]
fn drive_schema_routes_to_the_google_connection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for tool in ["changes.getStartPageToken", "changes.list", "files.get"] {
        let reply = connector_schema_read(
            &memory,
            ConnectorSchemaRequest {
                name: "google.drive".to_owned(),
                source: None,
                tool: tool.to_owned(),
            },
        )?;
        assert_eq!(reply.input_schema, None, "{tool}");
        assert_eq!(
            reply.reasons,
            vec!["google_connection_not_checked".to_owned()],
            "google.drive {tool} answers as the built-in, through the one Google connection"
        );
    }
    Ok(())
}

#[test]
fn drive_declares_three_reads_under_one_grant() -> TestResult {
    let api = module("google.drive").ok_or("google.drive routes to no module")?;
    let tools: Vec<(&str, &str, bool)> = api
        .tools()
        .iter()
        .map(|tool| (tool.name, tool.grant, tool.writes))
        .collect();
    assert_eq!(
        tools,
        vec![
            ("changes.getStartPageToken", "drive.read", false),
            ("changes.list", "drive.read", false),
            ("files.get", "drive.read", false),
        ],
        "every Drive tool reads, under the one drive.read grant"
    );
    assert_eq!(api.connection().pack, "oneiron.google");
    let manifest = workspace_manifest(api)?;
    let schema = |name: &str| {
        manifest
            .tools()
            .iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.input_schema.clone())
            .ok_or_else(|| format!("google.drive declares no {name}"))
    };
    assert_eq!(schema("changes.getStartPageToken")?.get("required"), None);
    assert_eq!(schema("changes.list")?["required"], json!(["pageToken"]));
    assert_eq!(schema("files.get")?["required"], json!(["fileId"]));
    for name in ["changes.getStartPageToken", "changes.list", "files.get"] {
        assert_eq!(
            schema(name)?["additionalProperties"],
            json!(false),
            "{name} takes no field the module does not name, so no caller picks the mask"
        );
    }
    Ok(())
}

#[test]
fn drive_changes_list_carries_the_page_token_and_never_downloads() -> TestResult {
    let start = drive_test_plan("changes.getStartPageToken", &json!({}))?
        .map_err(|reason| format!("the start token read was refused: {reason}"))?;
    assert_eq!(start.effect().endpoint().method(), "GET");
    assert_eq!(
        start.effect().url(),
        "https://www.googleapis.com/drive/v3/changes/startPageToken?supportsAllDrives=true"
    );
    assert!(start.readback().is_none(), "a read sends one request");

    let page = drive_test_plan(
        "changes.list",
        &json!({
            "pageToken": "4182",
            "pageSize": 100,
            "includeRemoved": true,
            "driveId": DRIVE_TEST_SHARED_DRIVE
        }),
    )?
    .map_err(|reason| format!("the change page read was refused: {reason}"))?;
    assert_eq!(page.effect().endpoint().method(), "GET");
    assert!(page.effect().body().is_empty());
    assert!(page.readback().is_none(), "a read sends one request");
    assert_eq!(
        page.target(),
        "",
        "a page of the change log acts on no one file"
    );
    let (path, query) = drive_test_query(&page.effect().url())?;
    assert_eq!(path, "https://www.googleapis.com/drive/v3/changes");
    let expected: Vec<(String, String)> = [
        ("pageToken", "4182".to_owned()),
        ("pageSize", "100".to_owned()),
        ("includeRemoved", "true".to_owned()),
        ("driveId", DRIVE_TEST_SHARED_DRIVE.to_owned()),
        ("supportsAllDrives", "true".to_owned()),
        ("includeItemsFromAllDrives", "true".to_owned()),
        (
            "fields",
            format!(
                "nextPageToken,newStartPageToken,changes(changeType,time,removed,fileId,driveId,file({DRIVE_TEST_FILE_FIELDS}),drive(id,name))"
            ),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    assert_eq!(query, expected, "the page token, then the one fixed mask");

    let file = drive_test_plan("files.get", &json!({ "fileId": DRIVE_TEST_FILE }))?
        .map_err(|reason| format!("the file read was refused: {reason}"))?;
    assert_eq!(file.target(), DRIVE_TEST_FILE);
    let (path, query) = drive_test_query(&file.effect().url())?;
    assert_eq!(
        path,
        format!("https://www.googleapis.com/drive/v3/files/{DRIVE_TEST_FILE}")
    );
    assert_eq!(
        query,
        vec![
            ("supportsAllDrives".to_owned(), "true".to_owned()),
            ("fields".to_owned(), DRIVE_TEST_FILE_FIELDS.to_owned()),
        ],
        "metadata only: no alt=media, no export"
    );
    Ok(())
}

#[test]
fn drive_reads_refuse_a_download_a_caller_mask_and_a_bad_token() -> TestResult {
    for (tool, refused) in [
        // A content download or a caller's own mask.
        (
            "files.get",
            json!({ "fileId": DRIVE_TEST_FILE, "alt": "media" }),
        ),
        (
            "files.get",
            json!({ "fileId": DRIVE_TEST_FILE, "fields": "*" }),
        ),
        // An id outside Google's alphabet.
        ("files.get", json!({ "fileId": "../files" })),
        ("changes.getStartPageToken", json!({ "driveId": "a/b" })),
        // A page size outside Drive's bound, and no page token.
        (
            "changes.list",
            json!({ "pageToken": "4182", "pageSize": 0 }),
        ),
        (
            "changes.list",
            json!({ "pageToken": "4182", "pageSize": 1001 }),
        ),
        ("changes.list", json!({ "pageToken": "" })),
        ("changes.list", json!({ "pageToken": "41 82" })),
        ("changes.list", json!({})),
    ] {
        assert_eq!(
            drive_test_plan(tool, &refused)?.err(),
            Some("connector_arguments_invalid"),
            "{tool} {refused}"
        );
    }
    Ok(())
}

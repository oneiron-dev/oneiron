//! `google.drive` on the workspace connector core (L3-17, PR 3;
//! DRIVE-ACCESS = B; GOOGLE-DRIVE-CONTENT-READ): it routes to the built-in
//! through the one Google connection, declares five reads under the one
//! `drive.read` grant, and plans each as one `GET` under Drive v3: the
//! metadata reads with the one fixed field mask and no content download,
//! `files.download` with `alt=media`, `files.export` with one listed format.
//! A content read's success answers the file's bytes, as text when they are
//! UTF-8, else as base64; its error, and every other read, answers JSON.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test google_drive_connector`

use oneiron::channel_identity_provider::workspace_connector::drive::EXPORT_MIME_TYPES;
use oneiron::channel_identity_provider::workspace_connector::{
    WorkspaceContent, WorkspaceEndpoint, WorkspacePlan, WorkspaceWireOutcome, module,
    workspace_manifest,
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
    for tool in [
        "changes.getStartPageToken",
        "changes.list",
        "files.get",
        "files.download",
        "files.export",
    ] {
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
fn drive_declares_five_reads_under_one_grant() -> TestResult {
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
            ("files.download", "drive.read", false),
            ("files.export", "drive.read", false),
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
    assert_eq!(schema("files.download")?["required"], json!(["fileId"]));
    let export = schema("files.export")?;
    assert_eq!(export["required"], json!(["fileId", "mimeType"]));
    assert_eq!(
        export["properties"]["mimeType"]["enum"],
        json!(EXPORT_MIME_TYPES),
        "the caller picks a format from the one list"
    );
    for name in [
        "changes.getStartPageToken",
        "changes.list",
        "files.get",
        "files.download",
        "files.export",
    ] {
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

#[test]
fn drive_content_reads_ask_google_for_the_file_and_nothing_else() -> TestResult {
    let download = drive_test_plan("files.download", &json!({ "fileId": DRIVE_TEST_FILE }))?
        .map_err(|reason| format!("the download was refused: {reason}"))?;
    assert_eq!(
        download.effect().endpoint(),
        WorkspaceEndpoint::DriveFileDownload
    );
    assert_eq!(download.effect().endpoint().method(), "GET");
    assert_eq!(download.effect().endpoint().wire_model(), "drive.v3");
    assert!(download.effect().endpoint().answers_content());
    assert_eq!(
        download.effect().url(),
        format!(
            "https://www.googleapis.com/drive/v3/files/{DRIVE_TEST_FILE}?alt=media&supportsAllDrives=true"
        ),
        "the file's media under Drive's own origin, the one query the broker's row takes"
    );
    assert!(download.effect().body().is_empty());
    assert!(download.effect().headers().is_empty());
    assert!(download.readback().is_none(), "a read sends one request");
    assert_eq!(download.target(), DRIVE_TEST_FILE);

    for format in EXPORT_MIME_TYPES {
        let export = drive_test_plan(
            "files.export",
            &json!({ "fileId": DRIVE_TEST_FILE, "mimeType": format }),
        )?
        .map_err(|reason| format!("the {format} export was refused: {reason}"))?;
        assert_eq!(
            export.effect().endpoint(),
            WorkspaceEndpoint::DriveFileExport
        );
        assert_eq!(export.effect().endpoint().method(), "GET");
        assert!(export.effect().endpoint().answers_content());
        let (path, query) = drive_test_query(&export.effect().url())?;
        assert_eq!(
            path,
            format!("https://www.googleapis.com/drive/v3/files/{DRIVE_TEST_FILE}/export")
        );
        assert_eq!(
            query,
            vec![("mimeType".to_owned(), format.to_owned())],
            "the format, and nothing else"
        );
        assert!(export.readback().is_none(), "a read sends one request");
        assert_eq!(export.target(), DRIVE_TEST_FILE);
    }
    assert_eq!(
        drive_test_plan(
            "files.export",
            &json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "text/plain" }),
        )?
        .map_err(|reason| format!("the text export was refused: {reason}"))?
        .effect()
        .url(),
        format!(
            "https://www.googleapis.com/drive/v3/files/{DRIVE_TEST_FILE}/export?mimeType=text%2Fplain"
        ),
        "the format percent-encoded, as the broker's data-query check takes it"
    );
    for endpoint in [
        WorkspaceEndpoint::DriveChangesStartPageToken,
        WorkspaceEndpoint::DriveChangesList,
        WorkspaceEndpoint::DriveFileGet,
    ] {
        assert!(!endpoint.answers_content(), "{endpoint:?} answers JSON");
    }
    Ok(())
}

#[test]
fn drive_content_reads_refuse_another_format_or_field() -> TestResult {
    for (tool, refused) in [
        // A format outside the list: Google's own type, a parameter, none.
        (
            "files.export",
            json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "application/vnd.google-apps.document" }),
        ),
        (
            "files.export",
            json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "text/plain; charset=utf-8" }),
        ),
        (
            "files.export",
            json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "" }),
        ),
        ("files.export", json!({ "fileId": DRIVE_TEST_FILE })),
        // A field the tools do not name: a flagged file's override, a mask.
        (
            "files.download",
            json!({ "fileId": DRIVE_TEST_FILE, "acknowledgeAbuse": true }),
        ),
        (
            "files.download",
            json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "text/plain" }),
        ),
        (
            "files.export",
            json!({ "fileId": DRIVE_TEST_FILE, "mimeType": "text/plain", "alt": "media" }),
        ),
        // An id outside Google's alphabet.
        ("files.download", json!({ "fileId": "../files" })),
        (
            "files.export",
            json!({ "fileId": "a?alt=media", "mimeType": "text/plain" }),
        ),
        ("files.download", json!({})),
    ] {
        assert_eq!(
            drive_test_plan(tool, &refused)?.err(),
            Some("connector_arguments_invalid"),
            "{tool} {refused}"
        );
    }
    Ok(())
}

#[test]
fn drive_content_answers_text_as_text_and_other_bytes_as_base64() -> TestResult {
    // A document exported as text: UTF-8 behind Google's byte-order mark.
    let text = "\u{feff}Quarterly plan\nOwen: ship the draft.\n";
    let exported = WorkspaceWireOutcome::answered(
        WorkspaceEndpoint::DriveFileExport,
        200,
        Some("text/plain; charset=utf-8"),
        text.as_bytes(),
    );
    let WorkspaceWireOutcome::Content(content) = &exported else {
        return Err(format!("a text export answered {exported:?}").into());
    };
    assert_eq!(content.media_type(), "text/plain");
    assert_eq!(
        content.bytes(),
        text.as_bytes(),
        "the bytes as Google sent them"
    );
    assert_eq!(
        content.output(),
        json!({
            "mimeType": "text/plain",
            "size": 40,
            "text": "Quarterly plan\nOwen: ship the draft.\n"
        })
    );

    // A stored PDF: bytes that are not UTF-8 answer as standard base64.
    let pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
    assert_eq!(
        WorkspaceWireOutcome::answered(
            WorkspaceEndpoint::DriveFileDownload,
            200,
            Some("Application/PDF"),
            pdf,
        ),
        WorkspaceWireOutcome::Content(WorkspaceContent::new(Some("application/pdf"), pdf.to_vec()))
    );
    assert_eq!(
        WorkspaceContent::new(Some("application/pdf"), pdf.to_vec()).output(),
        json!({
            "mimeType": "application/pdf",
            "size": 15,
            "contentBase64": "JVBERi0xLjcKJeLjz9MK"
        })
    );
    assert_eq!(
        WorkspaceContent::new(None, Vec::new()).output(),
        json!({ "mimeType": "application/octet-stream", "size": 0, "text": "" }),
        "no content type names the bytes as octets"
    );

    // A content read's error is Google's JSON, as every other read's reply.
    let refused = json!({ "error": { "code": 403, "reason": "fileNotDownloadable" } });
    assert_eq!(
        WorkspaceWireOutcome::answered(
            WorkspaceEndpoint::DriveFileDownload,
            403,
            Some("application/json; charset=UTF-8"),
            refused.to_string().as_bytes(),
        ),
        WorkspaceWireOutcome::Answered {
            status: 403,
            body: refused
        }
    );
    let metadata = json!({ "id": DRIVE_TEST_FILE, "name": "Quarterly plan" });
    assert_eq!(
        WorkspaceWireOutcome::answered(
            WorkspaceEndpoint::DriveFileGet,
            200,
            Some("application/json; charset=UTF-8"),
            metadata.to_string().as_bytes(),
        ),
        WorkspaceWireOutcome::Answered {
            status: 200,
            body: metadata
        }
    );
    assert_eq!(
        WorkspaceWireOutcome::answered(
            WorkspaceEndpoint::DriveFileGet,
            200,
            Some("text/plain"),
            b"not json",
        ),
        WorkspaceWireOutcome::Answered {
            status: 200,
            body: Value::Null
        },
        "a metadata read's body that is not JSON reads as null"
    );
    Ok(())
}

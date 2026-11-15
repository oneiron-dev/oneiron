//! The Google Workspace REST rows for Docs, Slides and Drive (L3-17;
//! GOOGLE-DRIVE-CONTENT-READ): each accepts only its own endpoint and query,
//! never another API's path; only Drive's download row takes `alt=media`, and
//! only its export row a format.
//!
//! Fleet: `cargo test --locked -p oneiron-broker --test workspace_shapes`

use oneiron_broker::{Refusal, Shape};

#[test]
fn docs_and_slides_rows_accept_only_their_paths() {
    let id = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";
    let accepted = [
        (Shape::DocsDocumentGet, format!("/v1/documents/{id}")),
        (
            Shape::DocsDocumentGet,
            format!(
                "/v1/documents/{id}?suggestionsViewMode=PREVIEW_WITHOUT_SUGGESTIONS&includeTabsContent=true"
            ),
        ),
        (
            Shape::DocsBatchUpdate,
            format!("/v1/documents/{id}:batchUpdate"),
        ),
        (
            Shape::SlidesPresentationGet,
            format!("/v1/presentations/{id}"),
        ),
        (
            Shape::SlidesBatchUpdate,
            format!("/v1/presentations/{id}:batchUpdate"),
        ),
    ];
    for (shape, path) in &accepted {
        assert_eq!(shape.check_path(path), Ok(()), "{shape:?} {path}");
    }
    let refused = [
        // A query the row does not name, or one on a row that takes none.
        (
            Shape::DocsDocumentGet,
            format!("/v1/documents/{id}?fields=body"),
        ),
        (
            Shape::SlidesPresentationGet,
            format!("/v1/presentations/{id}?fields=slides"),
        ),
        // One API's path on another's row.
        (
            Shape::DocsBatchUpdate,
            format!("/v4/spreadsheets/{id}:batchUpdate"),
        ),
        (
            Shape::SlidesBatchUpdate,
            format!("/v1/documents/{id}:batchUpdate"),
        ),
        (
            Shape::SheetsBatchUpdate,
            format!("/v1/presentations/{id}:batchUpdate"),
        ),
        (Shape::DocsDocumentGet, format!("/v1/presentations/{id}")),
        // An id outside the file id alphabet.
        (
            Shape::DocsBatchUpdate,
            "/v1/documents/a.b:batchUpdate".to_owned(),
        ),
    ];
    for (shape, path) in &refused {
        assert_eq!(
            shape.check_path(path),
            Err(Refusal::Path),
            "{shape:?} {path}"
        );
    }
    assert_eq!(Shape::DocsDocumentGet.method(), "GET");
    assert_eq!(Shape::DocsBatchUpdate.method(), "POST");
    assert_eq!(Shape::SlidesPresentationGet.method(), "GET");
    assert_eq!(Shape::SlidesBatchUpdate.method(), "POST");
    assert_eq!(Shape::DocsBatchUpdate.auth_prefix(), "Bearer ");
}

#[test]
fn drive_rows_read_metadata_only() {
    let id = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";
    let accepted = [
        (
            Shape::DriveChangesStartPageToken,
            "/drive/v3/changes/startPageToken?supportsAllDrives=true".to_owned(),
        ),
        (
            Shape::DriveChangesStartPageToken,
            format!("/drive/v3/changes/startPageToken?supportsAllDrives=true&driveId={id}"),
        ),
        (
            Shape::DriveChangesList,
            "/drive/v3/changes?pageToken=4182&pageSize=100&includeRemoved=true&supportsAllDrives=true&includeItemsFromAllDrives=true&fields=nextPageToken%2CnewStartPageToken%2Cchanges%28fileId%29".to_owned(),
        ),
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}?supportsAllDrives=true&fields=id%2Cname%2CmimeType"),
        ),
    ];
    for (shape, path) in &accepted {
        assert_eq!(shape.check_path(path), Ok(()), "{shape:?} {path}");
    }
    let refused = [
        // A content download or export on the metadata row: only the
        // download row takes `alt`, and only the export row its path.
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}?alt=media"),
        ),
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}/export?mimeType=text%2Fplain"),
        ),
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}?supportsAllDrives=true&acknowledgeAbuse=true"),
        ),
        // A parameter of another Drive row.
        (
            Shape::DriveChangesStartPageToken,
            "/drive/v3/changes/startPageToken?pageToken=1".to_owned(),
        ),
        // The change log on the start token's row, and the reverse.
        (
            Shape::DriveChangesStartPageToken,
            "/drive/v3/changes?supportsAllDrives=true".to_owned(),
        ),
        (
            Shape::DriveChangesList,
            "/drive/v3/changes/startPageToken".to_owned(),
        ),
        // A file listing or another API's path.
        (Shape::DriveFileGet, "/drive/v3/files?fields=id".to_owned()),
        (Shape::DriveFileGet, format!("/v1/documents/{id}")),
        // A value that is not percent-encoded.
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}?fields=id,name"),
        ),
    ];
    for (shape, path) in &refused {
        assert_eq!(
            shape.check_path(path),
            Err(Refusal::Path),
            "{shape:?} {path}"
        );
    }
    for shape in [
        Shape::DriveChangesStartPageToken,
        Shape::DriveChangesList,
        Shape::DriveFileGet,
    ] {
        assert_eq!(shape.method(), "GET", "{shape:?} only reads");
        assert_eq!(shape.auth_prefix(), "Bearer ", "{shape:?}");
    }
}

#[test]
fn drive_content_rows_take_only_their_own_query() {
    let id = "1AbC-dEf_2gHiJkLmNoPqRsTuVwXyZ0123456789ab";
    let accepted = [
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?alt=media&supportsAllDrives=true"),
        ),
        (
            Shape::DriveFileExport,
            format!("/drive/v3/files/{id}/export?mimeType=text%2Fplain"),
        ),
        (
            Shape::DriveFileExport,
            format!(
                "/drive/v3/files/{id}/export?mimeType=application%2Fvnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
        ),
    ];
    for (shape, path) in &accepted {
        assert_eq!(shape.check_path(path), Ok(()), "{shape:?} {path}");
    }
    let refused = [
        // The download's one query, and no other: none, part of it, another
        // order, a flagged file's override, a field mask.
        (Shape::DriveFileDownload, format!("/drive/v3/files/{id}")),
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?alt=media"),
        ),
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?supportsAllDrives=true&alt=media"),
        ),
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?alt=media&supportsAllDrives=true&acknowledgeAbuse=true"),
        ),
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?acknowledgeAbuse=true&alt=media&supportsAllDrives=true"),
        ),
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}?fields=id&alt=media&supportsAllDrives=true"),
        ),
        // Another Drive path on the download row: the export, a listing.
        (
            Shape::DriveFileDownload,
            format!("/drive/v3/files/{id}/export?alt=media&supportsAllDrives=true"),
        ),
        (
            Shape::DriveFileDownload,
            "/drive/v3/files?alt=media&supportsAllDrives=true".to_owned(),
        ),
        // The export takes only its format, percent-encoded in uppercase.
        (
            Shape::DriveFileExport,
            format!("/drive/v3/files/{id}/export?mimeType=text%2Fplain&alt=media"),
        ),
        (
            Shape::DriveFileExport,
            format!("/drive/v3/files/{id}/export?mimeType=text%2fplain"),
        ),
        (
            Shape::DriveFileExport,
            format!("/drive/v3/files/{id}/export?mimeType=text/plain"),
        ),
        // The metadata path on the export row, and the reverse.
        (
            Shape::DriveFileExport,
            format!("/drive/v3/files/{id}?mimeType=text%2Fplain"),
        ),
        (
            Shape::DriveFileGet,
            format!("/drive/v3/files/{id}?alt=media&supportsAllDrives=true"),
        ),
        // Another API's path.
        (
            Shape::DriveFileDownload,
            format!("/v1/documents/{id}?alt=media&supportsAllDrives=true"),
        ),
    ];
    for (shape, path) in &refused {
        assert_eq!(
            shape.check_path(path),
            Err(Refusal::Path),
            "{shape:?} {path}"
        );
    }
    for shape in [Shape::DriveFileDownload, Shape::DriveFileExport] {
        assert_eq!(shape.method(), "GET", "{shape:?} only reads");
        assert_eq!(shape.auth_header(), "authorization", "{shape:?}");
        assert_eq!(shape.auth_prefix(), "Bearer ", "{shape:?}");
        assert!(
            !shape.streams(),
            "{shape:?} buffers its reply up to the frame bound and fails a longer one"
        );
    }
}

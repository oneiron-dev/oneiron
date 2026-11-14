//! The Google Workspace REST rows for Docs and Slides (L3-17): each accepts
//! only its own endpoint and query, never another API's path.
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

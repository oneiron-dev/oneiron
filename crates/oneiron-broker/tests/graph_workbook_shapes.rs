//! The Microsoft Graph workbook rows (L3-17 PR 4): each accepts only its own
//! workbook path, a worksheet name only in letters, digits, `-`, `_` and
//! `%20`, and a range only as an A1 address, so no escape or quote reaches
//! Graph's path parser.
//!
//! Fleet: `cargo test --locked -p oneiron-broker --test graph_workbook_shapes`

use oneiron_broker::{Refusal, Shape};

#[test]
fn graph_workbook_rows_accept_only_their_paths() {
    let workbook = "/v1.0/me/drive/items/01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K/workbook";
    let accepted = [
        (
            Shape::ExcelCreateSession,
            format!("{workbook}/createSession"),
        ),
        (Shape::ExcelCloseSession, format!("{workbook}/closeSession")),
        (
            Shape::ExcelRangeGet,
            format!("{workbook}/worksheets/Sheet1/range(address='A1:B2')"),
        ),
        (
            Shape::ExcelRangeGet,
            format!("{workbook}/worksheets/Q1%20Plan/range(address='$A$1')"),
        ),
        (
            Shape::ExcelRangeUpdate,
            format!("{workbook}/worksheets/Q1%20Plan/range(address='A:A')"),
        ),
    ];
    for (shape, path) in &accepted {
        assert_eq!(shape.check_path(path), Ok(()), "{shape:?} {path}");
    }
    let range = |worksheet: &str, address: &str| {
        format!("{workbook}/worksheets/{worksheet}/range(address='{address}')")
    };
    let refused = [
        // An escape other than a single space, a quote, a dot segment.
        (Shape::ExcelRangeGet, range("a%2Fb", "A1")),
        (Shape::ExcelRangeGet, range("Sheet%201%20", "A1")),
        (Shape::ExcelRangeGet, range("%20Sheet1", "A1")),
        (Shape::ExcelRangeGet, range("Sheet%20%201", "A1")),
        (Shape::ExcelRangeGet, range("Sheet'1", "A1")),
        (Shape::ExcelRangeGet, range("..", "A1")),
        (Shape::ExcelRangeGet, range("x".repeat(32).as_str(), "A1")),
        // An address outside the A1 alphabet, or no range call at all.
        (Shape::ExcelRangeGet, range("Sheet1", "A1')/x('")),
        (Shape::ExcelRangeGet, range("Sheet1", "Sheet2!A1")),
        (Shape::ExcelRangeGet, range("Sheet1", "")),
        (
            Shape::ExcelRangeGet,
            format!("{workbook}/worksheets/Sheet1/usedRange"),
        ),
        // One row's path on another's, and another Graph resource.
        (
            Shape::ExcelCreateSession,
            format!("{workbook}/closeSession"),
        ),
        (Shape::ExcelRangeUpdate, "/v1.0/me/messages/AAMk".to_owned()),
        (
            Shape::ExcelCreateSession,
            "/v1.0/me/drive/items/a.b/workbook/createSession".to_owned(),
        ),
    ];
    for (shape, path) in &refused {
        assert_eq!(
            shape.check_path(path),
            Err(Refusal::Path),
            "{shape:?} {path}"
        );
    }
    assert_eq!(Shape::ExcelCreateSession.method(), "POST");
    assert_eq!(Shape::ExcelRangeGet.method(), "GET");
    assert_eq!(Shape::ExcelRangeUpdate.method(), "PATCH");
    assert_eq!(Shape::ExcelCloseSession.method(), "POST");
    assert_eq!(Shape::ExcelRangeUpdate.auth_prefix(), "Bearer ");
}

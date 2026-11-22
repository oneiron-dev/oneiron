//! A caller in another crate writes a cell format's alignment and protection
//! by name.
//!
//! `XlsxFormat` has two public fields, `alignment` and `protection`, whose
//! types `xlsx_body` did not export. A caller could read both fields and fill
//! them through serde, and could not write `XlsxAlignment { .. }` or
//! `XlsxProtection { .. }`. This file is such a caller.

use oneiron_docedit::xlsx_body::{
    XlsxAlignment, XlsxBodyError, XlsxFormat, XlsxProtection, check_format,
};
use serde_json::json;

/// A format over the workbook's first cell format with these two parts changed.
fn format(alignment: XlsxAlignment, protection: XlsxProtection) -> XlsxFormat {
    XlsxFormat {
        base: 0,
        cell_style: None,
        font: None,
        fill: None,
        border: None,
        number_format: None,
        alignment: Some(alignment),
        protection: Some(protection),
    }
}

fn centred() -> XlsxAlignment {
    XlsxAlignment {
        horizontal: Some("center".into()),
        vertical: None,
        wrap_text: Some(true),
        shrink_to_fit: None,
        indent: None,
        rotation: None,
        reading_order: None,
    }
}

fn unlocked() -> XlsxProtection {
    XlsxProtection {
        locked: Some(false),
        hidden: None,
    }
}

#[test]
fn a_format_written_by_name_is_the_format_its_json_reads_as() {
    let written = format(centred(), unlocked());
    let read: XlsxFormat = serde_json::from_value(json!({
        "base": 0,
        "alignment": {"horizontal": "center", "wrap_text": true},
        "protection": {"locked": false},
    }))
    .expect("the JSON form of the same format");
    assert_eq!(written, read);
    check_format(&written, 1).expect("a workbook with one cell format holds this format");
}

#[test]
fn an_alignment_written_by_name_is_checked_as_any_other() {
    let alignment = XlsxAlignment {
        horizontal: Some("diagonal".into()),
        ..centred()
    };
    let refusal = check_format(&format(alignment, unlocked()), 1)
        .expect_err("diagonal is no horizontal alignment");
    assert!(
        matches!(
            refusal,
            XlsxBodyError::Refused("not a horizontal alignment")
        ),
        "{refusal:?}"
    );
}

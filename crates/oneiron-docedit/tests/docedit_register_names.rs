//! The names of 2 name lists in `oneiron-docedit`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-docedit/src/docx_body.rs`
//! - `crates/oneiron-docedit/src/resource.rs`

use oneiron_docedit::docx_body::DocxMark;
use oneiron_docedit::resource::Dimension;
use serde_json::Value;

/// Every row of `DocxMark`, as its hand table spelled it.
const DOCX_MARK_ROWS: [(DocxMark, &str); 6] = [
    (DocxMark::Bold, "bold"),
    (DocxMark::Italic, "italic"),
    (DocxMark::Underline, "underline"),
    (DocxMark::Strike, "strike"),
    (DocxMark::Subscript, "subscript"),
    (DocxMark::Superscript, "superscript"),
];

#[test]
fn every_docx_mark_keeps_its_name() {
    assert_eq!(DocxMark::Bold.key(), "bold");
    assert_eq!(DocxMark::Italic.key(), "italic");
    assert_eq!(DocxMark::Underline.key(), "underline");
    assert_eq!(DocxMark::Strike.key(), "strike");
    assert_eq!(DocxMark::Subscript.key(), "subscript");
    assert_eq!(DocxMark::Superscript.key(), "superscript");
}

#[test]
fn every_docx_mark_name_is_its_serde_name() {
    for (row, name) in DOCX_MARK_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: DocxMark =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn docx_mark_from_key_reads_each_name_back() {
    for (row, name) in DOCX_MARK_ROWS {
        assert_eq!(DocxMark::from_key(name), Some(row), "{name}");
    }
    assert_eq!(DocxMark::from_key("not.a.row"), None);
}

/// Every row of `Dimension`, as its hand table spelled it.
const DIMENSION_ROWS: [(Dimension, &str); 9] = [
    (Dimension::ArchiveBytes, "archive_bytes"),
    (Dimension::PartBytes, "part_bytes"),
    (Dimension::ExpandedBytes, "expanded_bytes"),
    (Dimension::XmlBytes, "xml_bytes"),
    (Dimension::SvgBytes, "svg_bytes"),
    (Dimension::RasterBytes, "raster_bytes"),
    (Dimension::RasterPixels, "raster_pixels"),
    (Dimension::ZipEntries, "zip_entries"),
    (Dimension::ZipBytes, "zip_bytes"),
];

#[test]
fn every_dimension_keeps_its_name() {
    assert_eq!(Dimension::ArchiveBytes.as_str(), "archive_bytes");
    assert_eq!(Dimension::PartBytes.as_str(), "part_bytes");
    assert_eq!(Dimension::ExpandedBytes.as_str(), "expanded_bytes");
    assert_eq!(Dimension::XmlBytes.as_str(), "xml_bytes");
    assert_eq!(Dimension::SvgBytes.as_str(), "svg_bytes");
    assert_eq!(Dimension::RasterBytes.as_str(), "raster_bytes");
    assert_eq!(Dimension::RasterPixels.as_str(), "raster_pixels");
    assert_eq!(Dimension::ZipEntries.as_str(), "zip_entries");
    assert_eq!(Dimension::ZipBytes.as_str(), "zip_bytes");
}

#[test]
fn every_dimension_name_is_its_serde_name() {
    for (row, name) in DIMENSION_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: Dimension =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

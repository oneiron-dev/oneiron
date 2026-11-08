//! The place a comment stands on in a version, as the artifact routes read
//! and write it: one JSON object keyed by its locator's format (FIX 22108).
//! Every format a locator has crosses: Excel ranges, Word, HTML and plain
//! text character spans, PowerPoint shapes, and character spans in one code
//! file at a commit (FIX 7905).

use oneiron::anchored_annotation::Locator;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::ApiError;

/// A format-typed place in a version, as the offers name it.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PlaceInput {
    Xlsx {
        sheet: String,
        range: String,
    },
    Docx {
        para_path: String,
        char_start: u64,
        char_end: u64,
    },
    DocxStory {
        scope: oneiron_docedit::docx_body::DocxStoryScope,
        para_path: String,
        char_start: u64,
        char_end: u64,
    },
    Pptx {
        slide: u64,
        shape_id: String,
    },
    Html {
        part_id: String,
        char_start: u64,
        char_end: u64,
    },
    Text {
        char_start: u64,
        char_end: u64,
    },
    /// A span in one file of a code artifact's tree: the commit, the file's
    /// path and its content hash (64 lowercase hex), as an offer names them.
    Code {
        commit: String,
        path: String,
        file_hash: String,
        char_start: u64,
        char_end: u64,
    },
}

/// `locator` as the routes write a place; `null` for a format these routes
/// do not name.
pub(super) fn place_json(locator: &Locator) -> Value {
    match locator {
        Locator::Xlsx { sheet, range } => {
            json!({ "xlsx": { "sheet": sheet, "range": range.to_a1() } })
        }
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => json!({ "docx": {
            "para_path": para_path,
            "char_start": char_start,
            "char_end": char_end,
        } }),
        Locator::DocxStory {
            scope,
            para_path,
            char_start,
            char_end,
        } => json!({ "docx_story": {
            "scope": scope, "para_path": para_path, "char_start": char_start, "char_end": char_end,
        } }),
        Locator::Pptx { slide, shape_id } => {
            json!({ "pptx": { "slide": slide, "shape_id": shape_id } })
        }
        Locator::Html {
            part_id,
            char_start,
            char_end,
        } => json!({ "html": {
            "part_id": part_id,
            "char_start": char_start,
            "char_end": char_end,
        } }),
        Locator::Text {
            char_start,
            char_end,
        } => json!({ "text": { "char_start": char_start, "char_end": char_end } }),
        Locator::Code {
            commit,
            path,
            file_hash,
            char_start,
            char_end,
        } => json!({ "code": {
            "commit": commit,
            "path": path,
            "file_hash": file_hash,
            "char_start": char_start,
            "char_end": char_end,
        } }),
        _ => Value::Null,
    }
}

/// The locator `place` names, validated as the engine builds each format's.
pub(super) fn place_locator(place: PlaceInput) -> Result<Locator, ApiError> {
    match place {
        PlaceInput::Xlsx { sheet, range } => Locator::xlsx(sheet, &range),
        PlaceInput::Docx {
            para_path,
            char_start,
            char_end,
        } => Locator::docx(para_path, char_start, char_end),
        PlaceInput::DocxStory {
            scope,
            para_path,
            char_start,
            char_end,
        } => Locator::docx_story(scope, para_path, char_start, char_end),
        PlaceInput::Pptx { slide, shape_id } => Locator::pptx(slide, shape_id),
        PlaceInput::Html {
            part_id,
            char_start,
            char_end,
        } => Locator::html(part_id, char_start, char_end),
        PlaceInput::Text {
            char_start,
            char_end,
        } => Locator::text(char_start, char_end),
        PlaceInput::Code {
            commit,
            path,
            file_hash,
            char_start,
            char_end,
        } => Locator::code(commit, path, file_hash, char_start, char_end),
    }
    .map_err(|_| ApiError::bad_request("place is not a valid locator", Some("place")))
}

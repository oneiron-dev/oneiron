// Copyright (c) 2026 Stemma. Licensed under Apache-2.0.
// Oneiron fork: selected stateless engine components; see ../PROVENANCE.md.
//! Stateless Stemma source fork. No runtime, MCP server, filesystem, or storage.
pub mod domain;
pub mod docx_validate;
pub mod docx_validate_annotations;
mod xml_attrs;
mod parse;
pub use parse::{body_paragraph_ranges, has_paragraph_mark_revision, plain_paragraph_shape};

/// Parse and run upstream tracked-change content-model and annotation checks.
/// Only error-severity findings block the retained writer.
pub fn validate_document(bytes: &[u8]) -> Result<Vec<docx_validate::ValidationFinding>, String> {
    use docx_validate_annotations::*;
    let root = parse::parse(bytes)?;
    let stories = [("word/document.xml".to_owned(), &root)];
    let mut findings = check_document_root(&root);
    for check in [
        check_required_tracked_change_ids,
        check_tracked_change_content_model,
        check_no_nested_tracked_changes,
        check_bookmark_pairing,
        check_comment_marker_pairing,
        check_comment_range_count,
        check_para_id_range,
        check_custom_xml_range_pairing,
        check_footnote_endnote_id_range,
        check_bookmark_name_length,
        check_omath_placement,
        check_perm_id_validity,
        check_colfirst_collast_pairing,
    ] {
        findings.extend(check(&stories));
    }
    // Word reuses numeric IDs across unrelated annotation classes; upstream's
    // document-wide uniqueness heuristic is advisory, not a corruption gate.
    Ok(findings)
}

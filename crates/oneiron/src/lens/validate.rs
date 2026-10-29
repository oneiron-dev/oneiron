//! Cross-cutting lens validators and the capability-degradation compiler used
//! by [`super::atom`], [`super::self_ui`] and [`super::generated_ui`] at
//! construction and deserialize time.

use std::collections::HashSet;

use crate::{Error, Result};

use super::atom::{
    GeneratedUiResultSetSelectAll, LensAtom, LensNode, LensText, LensTextSpan, TextBlockAtom,
};
use super::generated_ui::GENERATED_UI_WIRE_VERSION;
use super::self_ui::SelfUiOption;
use super::wire_ids::SelfUiOptionValue;

pub(super) const MAX_LENS_TOKEN_BYTES: usize = 128;

/// Validates the whole tree, at any width or depth (FIX 9900): every node id
/// is unique, every node's text and atom are valid, and every result set's
/// handles and action ids hold. The walk keeps its own stack, so depth costs
/// no call stack.
pub(super) fn validate_lens_tree(root: &LensNode) -> Result<()> {
    let mut stack = vec![root];
    let mut seen_node_ids = HashSet::new();
    let mut seen_result_set_action_ids = HashSet::new();

    while let Some(node) = stack.pop() {
        if !seen_node_ids.insert(node.id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated lens nodes must not contain duplicate ids".to_string(),
            ));
        }
        validate_required_lens_text("lens node fallbackText", &node.fallback_text)?;
        node.atom.validate()?;
        validate_result_set_node(node, &mut seen_result_set_action_ids)?;

        for child in node.children.iter().rev() {
            stack.push(child);
        }
    }

    Ok(())
}

/// Node-level result-set rules: row ids are unique, every handle a row or a select-all
/// predicate names is one *this node* declared exactly once, and an action id is
/// allowlisted by at most one atom anywhere in the tree. Handles come from the node's
/// own bindings, so a row can never point at reach a different node advertised.
fn validate_result_set_node<'a>(
    node: &'a LensNode,
    seen_action_ids: &mut HashSet<&'a str>,
) -> Result<()> {
    let Some(result_set) = node.atom.result_set_payload() else {
        return Ok(());
    };

    let mut row_ids = HashSet::with_capacity(result_set.rows.len());
    for row in &result_set.rows {
        if !row_ids.insert(row.id.as_str()) {
            return Err(Error::InvalidConfig(
                "result set rows must not contain duplicate ids".to_string(),
            ));
        }
        validate_declared_backing_handle(node, row.target_handle.as_str())?;
    }

    if let GeneratedUiResultSetSelectAll::WithinFilter { predicate_handle } = &result_set.select_all
    {
        validate_declared_backing_handle(node, predicate_handle.as_str())?;
    }

    for action_id in &result_set.action_bar {
        if !seen_action_ids.insert(action_id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui result set action ids must be allowlisted by at most one atom"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_declared_backing_handle(node: &LensNode, handle: &str) -> Result<()> {
    let declared = node
        .bindings
        .iter()
        .filter(|binding| binding.name.as_str() == handle)
        .count();
    if declared != 1 {
        return Err(Error::InvalidConfig(
            "result set handles must be declared exactly once by their own node".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_generated_ui_node_count(context: &str, len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidConfig(format!("{context} must be non-zero")));
    }
    Ok(())
}

pub(super) fn validate_required_lens_text(context: &str, value: &LensText) -> Result<()> {
    if value.as_str().trim().is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    Ok(())
}

pub(super) fn validate_generated_ui_protocol_version(protocol_version: u16) -> Result<()> {
    if protocol_version != GENERATED_UI_WIRE_VERSION {
        return Err(Error::InvalidConfig(format!(
            "unsupported generated-ui wire version {protocol_version}"
        )));
    }
    Ok(())
}

pub(super) fn fallback_lens_text(kind: &'static str, value: String) -> LensText {
    LensText::new(value).unwrap_or_else(|_| LensText::new(kind).expect("static fallback is valid"))
}

/// The text block an atom lowers to on a surface that does not draw it: its
/// node's `fallbackText` (ARCH-0048 G3 compile-to-lowest). A result set
/// lowers like any other atom (FIX 9892).
pub(super) fn fallback_text_atom(fallback_text: &LensText) -> LensAtom {
    LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(fallback_text.clone())],
    })
}

pub(super) fn validate_self_ui_options(context: &str, options: &[SelfUiOption]) -> Result<()> {
    let mut seen = HashSet::with_capacity(options.len());
    for option in options {
        if !seen.insert(option.value.as_str()) {
            return Err(Error::InvalidConfig(format!(
                "{context} must not contain duplicate values"
            )));
        }
    }

    Ok(())
}

pub(super) fn validate_selected_option(
    context: &str,
    options: &[SelfUiOption],
    selected: Option<&SelfUiOptionValue>,
) -> Result<()> {
    let Some(selected) = selected else {
        return Ok(());
    };

    if options
        .iter()
        .any(|option| option.value.as_str() == selected.as_str())
    {
        return Ok(());
    }

    Err(Error::InvalidConfig(format!(
        "{context} must be present in options"
    )))
}

pub(super) fn validate_lens_token(context: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    if value.len() > MAX_LENS_TOKEN_BYTES {
        return Err(Error::InvalidConfig(format!(
            "{context} must be at most {MAX_LENS_TOKEN_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(format!(
            "{context} must use only ASCII alnum, '.', '_', or '-'"
        )));
    }

    Ok(())
}

pub(super) fn validate_lens_capability_name(context: &str, value: &str) -> Result<()> {
    if names_forbidden_lens_capability(value) {
        return Err(Error::InvalidConfig(format!(
            "{context} names a forbidden lens capability"
        )));
    }

    Ok(())
}

fn names_forbidden_lens_capability(value: &str) -> bool {
    let normalized = normalize_lens_capability_name(value);
    normalized.split('_').any(|segment| {
        matches!(
            segment,
            "script" | "javascript" | "eval" | "fetch" | "network" | "storage"
        )
    })
}

fn normalize_lens_capability_name(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut normalized = String::with_capacity(value.len());

    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'.' | b'-' | b'_' => {
                if !normalized.ends_with('_') {
                    normalized.push('_');
                }
            }
            b'A'..=b'Z' => {
                let previous_is_lower_or_digit = index > 0
                    && (bytes[index - 1].is_ascii_lowercase() || bytes[index - 1].is_ascii_digit());
                let acronym_boundary = index > 0
                    && index + 1 < bytes.len()
                    && bytes[index - 1].is_ascii_uppercase()
                    && bytes[index + 1].is_ascii_lowercase();
                if (previous_is_lower_or_digit || acronym_boundary) && !normalized.ends_with('_') {
                    normalized.push('_');
                }
                normalized.push(byte.to_ascii_lowercase() as char);
            }
            _ => normalized.push(byte as char),
        }
    }

    normalized
}

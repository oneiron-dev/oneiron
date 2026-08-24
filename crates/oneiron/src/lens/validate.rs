//! Cross-cutting lens validators and the capability-degradation compiler used
//! by [`super::atom`], [`super::self_ui`] and [`super::generated_ui`] at
//! construction and deserialize time.

use std::collections::HashSet;

use crate::{Error, Result};

use super::atom::{LensAtom, LensNode, LensText, LensTextSpan, TextBlockAtom};
use super::generated_ui::{GENERATED_UI_WIRE_VERSION, GeneratedUiSurfaceCapabilities};
use super::self_ui::SelfUiOption;
use super::wire_ids::{MAX_LENS_COLLECTION_ITEMS, MAX_LENS_TREE_DEPTH, SelfUiOptionValue};

const MAX_LENS_TOKEN_BYTES: usize = 128;
pub(super) const MAX_LENS_NODE_COUNT: usize = 4096;

pub(super) fn validate_lens_tree(root: &LensNode) -> Result<()> {
    let mut stack = vec![(root, 1usize)];
    let mut node_count = 0usize;
    let mut budget = LensBudget::default();
    let mut seen_node_ids = HashSet::with_capacity(MAX_LENS_NODE_COUNT);

    while let Some((node, depth)) = stack.pop() {
        node_count += 1;
        if node_count > MAX_LENS_NODE_COUNT {
            return Err(Error::InvalidConfig(format!(
                "generated lens tree must contain at most {MAX_LENS_NODE_COUNT} nodes"
            )));
        }
        if !seen_node_ids.insert(node.id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated lens nodes must not contain duplicate ids".to_string(),
            ));
        }
        if depth > MAX_LENS_TREE_DEPTH {
            return Err(Error::InvalidConfig(format!(
                "generated lens tree depth must be at most {MAX_LENS_TREE_DEPTH}"
            )));
        }

        budget.add_collection("lens node bindings", node.bindings.len())?;
        budget.add_collection("lens node $bind", node.state_bindings.len())?;
        budget.add_collection("lens node children", node.children.len())?;
        validate_required_lens_text("lens node fallbackText", &node.fallback_text)?;
        node.atom.validate()?;
        node.atom.count_collection_items(&mut budget)?;

        for child in node.children.iter().rev() {
            stack.push((child, depth + 1));
        }
    }

    Ok(())
}

#[derive(Default)]
pub(super) struct LensBudget {
    collection_items: usize,
}

impl LensBudget {
    pub(super) fn add_collection(&mut self, context: &str, len: usize) -> Result<()> {
        validate_lens_collection_len(context, len)?;
        self.collection_items = self.collection_items.checked_add(len).ok_or_else(|| {
            Error::InvalidConfig("generated lens collection budget overflowed".to_string())
        })?;
        if self.collection_items > MAX_LENS_COLLECTION_ITEMS {
            return Err(Error::InvalidConfig(format!(
                "generated lens collections must contain at most {MAX_LENS_COLLECTION_ITEMS} total items"
            )));
        }
        Ok(())
    }
}

pub(super) fn validate_lens_collection_len(context: &str, len: usize) -> Result<()> {
    if len > MAX_LENS_COLLECTION_ITEMS {
        return Err(Error::InvalidConfig(format!(
            "{context} must contain at most {MAX_LENS_COLLECTION_ITEMS} items"
        )));
    }
    Ok(())
}

pub(super) fn validate_generated_ui_node_count(context: &str, len: usize) -> Result<()> {
    validate_lens_collection_len(context, len)?;
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

pub(super) fn compile_atom_for_surface(
    atom: &LensAtom,
    fallback_text: &LensText,
    surface: &GeneratedUiSurfaceCapabilities,
) -> LensAtom {
    if surface.supports(atom.primitive()) {
        return atom.clone();
    }

    LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(fallback_text.clone())],
    })
}

pub(super) fn validate_self_ui_options(context: &str, options: &[SelfUiOption]) -> Result<()> {
    validate_lens_collection_len(context, options.len())?;

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

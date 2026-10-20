//! Content-addressed semantic changes. Text output is only a rendering of this list.

use super::codec::sha256_bytes;
use super::validate::validate_manifest_path;
use crate::error::{CodeError, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeContentVersion {
    pub content_hash: [u8; 32],
    pub text: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSemanticChange {
    pub path: String,
    /// Qualified syntax identity; non-Rust sources use the file as the unit.
    pub symbol: String,
    pub before: Option<CodeContentVersion>,
    pub after: Option<CodeContentVersion>,
}

/// Compare definitions by identity and content, not by where their lines moved.
/// A rename is a removal and an addition, never an inferred provenance transfer.
pub fn semantic_code_diff(path: &str, old: &str, new: &str) -> Result<Vec<CodeSemanticChange>> {
    validate_manifest_path(path)?;
    let before = units(path, old)?;
    let after = units(path, new)?;
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    Ok(keys
        .into_iter()
        .filter_map(|key| {
            let left = before.get(key);
            let right = after.get(key);
            if left.map(|v| &v.0) == right.map(|v| &v.0) {
                return None;
            }
            Some(CodeSemanticChange {
                path: path.to_owned(),
                symbol: key.clone(),
                before: left.map(|v| v.1.clone()),
                after: right.map(|v| v.1.clone()),
            })
        })
        .collect())
}

/// Render only the supplied semantic changes. No independent text differ runs.
pub fn render_code_semantic_diff(changes: &[CodeSemanticChange]) -> String {
    let mut out = String::new();
    for change in changes {
        out.push_str(&format!("@@ {}::{} @@\n", change.path, change.symbol));
        for (prefix, version) in [("-", &change.before), ("+", &change.after)] {
            if let Some(version) = version {
                out.push_str(&format!("{prefix} hash:{}\n", hex(&version.content_hash)));
                for line in version.text.split_inclusive('\n') {
                    out.push_str(prefix);
                    out.push_str(line);
                    if !line.ends_with('\n') {
                        out.push_str("\n\\ No newline at end of unit\n");
                    }
                }
            }
        }
    }
    out
}

pub fn code_text_diff(path: &str, old: &str, new: &str) -> Result<String> {
    Ok(render_code_semantic_diff(&semantic_code_diff(
        path, old, new,
    )?))
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

type Units = BTreeMap<String, ([u8; 32], CodeContentVersion)>;

fn units(path: &str, source: &str) -> Result<Units> {
    let mut units = Units::new();
    if !path.ends_with(".rs") {
        if !source.is_empty() {
            insert(
                &mut units,
                "file".into(),
                source,
                source,
                1,
                source.lines().count().max(1) as u32,
            )?;
        }
        return Ok(units);
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| invalid())?;
    let tree = parser.parse(source, None).ok_or_else(invalid)?;
    if tree.root_node().has_error() {
        return Err(invalid());
    }
    let mut implementations = BTreeMap::new();
    collect(
        tree.root_node(),
        source,
        "",
        &mut units,
        &mut implementations,
    )?;
    for (key, mut blocks) in implementations {
        // Block order is not an identity. Keep all headers/attributes, with
        // method bodies removed from comparison and retained in child units.
        blocks.sort_by(|a, b| a.own.cmp(&b.own).then_with(|| a.text.cmp(&b.text)));
        let own = blocks
            .iter()
            .map(|b| b.own.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let text = blocks
            .iter()
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let start = blocks.iter().map(|b| b.start).min().ok_or_else(invalid)?;
        let end = blocks.iter().map(|b| b.end).max().ok_or_else(invalid)?;
        insert(&mut units, key, &text, &own, start, end)?;
    }
    Ok(units)
}

struct ImplBlock {
    own: String,
    text: String,
    start: u32,
    end: u32,
}

fn invalid() -> Error {
    Error::Code(CodeError::InvalidCodeSymbolManifestBody(
        "ambiguous or invalid semantic source",
    ))
}

fn insert(
    units: &mut Units,
    key: String,
    text: &str,
    own: &str,
    start_line: u32,
    end_line: u32,
) -> Result<()> {
    let value = (
        sha256_bytes(own.as_bytes()),
        CodeContentVersion {
            content_hash: sha256_bytes(text.as_bytes()),
            text: text.to_owned(),
            start_line,
            end_line,
        },
    );
    if units.insert(key, value).is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn identity(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if matches!(node.kind(), "attribute_item" | "inner_attribute_item") {
        return None;
    }
    if node.kind().ends_with("_item") || node.kind() == "function_signature_item" {
        let name = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("type"));
        let name = name.map_or(node.kind(), |n| &source[n.byte_range()]);
        let trait_name = node
            .child_by_field_name("trait")
            .map(|n| &source[n.byte_range()]);
        let mut key = match trait_name {
            Some(trait_name) => format!("{}:{} for {}", node.kind(), trait_name, name),
            None => format!("{}:{}", node.kind(), name),
        };
        // Source capture sees every configuration, not just this host's build.
        // Conditional siblings have distinct identities even when they name the
        // same method. Conditions on an impl/module also qualify its children.
        let mut conditions = Vec::new();
        let mut previous = node.prev_named_sibling();
        while let Some(attribute) = previous {
            match attribute.kind() {
                "line_comment" | "block_comment" => {}
                "attribute_item" => {
                    if let Some(name) = attribute.named_child(0).and_then(|n| n.named_child(0))
                        && matches!(&source[name.byte_range()], "cfg" | "cfg_attr")
                    {
                        conditions.push(&source[attribute.byte_range()]);
                    }
                }
                _ => break,
            }
            previous = attribute.prev_named_sibling();
        }
        conditions.sort_unstable();
        for condition in conditions {
            key.push_str(condition);
        }
        return Some(key);
    }
    None
}

// Remove child definitions from the parent's comparison bytes. Changing a
// method does not also report its unchanged impl header as a second change.
//
// The walk is an explicit post-order frame stack, never native recursion:
// how deeply a source nests decides how many frames are held, not how deep
// the caller's thread stack goes. Output and unit order match the
// recursive walk exactly.
fn collect(
    node: tree_sitter::Node<'_>,
    source: &str,
    scope: &str,
    units: &mut Units,
    implementations: &mut BTreeMap<String, Vec<ImplBlock>>,
) -> Result<String> {
    let Some(root) = open_frame(node, source, scope) else {
        return Ok(String::new());
    };
    let mut stack = vec![root];
    loop {
        let Some(frame) = stack.last_mut() else {
            return Err(invalid());
        };
        if let Some(&child) = frame.children.get(frame.next) {
            frame.next += 1;
            let gap = &source[frame.end..child.start_byte()];
            if frame.node.kind() != "source_file" || !gap.trim().is_empty() {
                frame.own.push_str(gap);
            }
            match open_frame(child, source, &frame.child_scope) {
                Some(opened) => stack.push(opened),
                None => frame.end = child.end_byte(),
            }
            continue;
        }
        let Some(done) = stack.pop() else {
            return Err(invalid());
        };
        let done_end = done.node.end_byte();
        let residual = close_frame(done, source, units, implementations)?;
        match stack.last_mut() {
            Some(parent) => {
                parent.own.push_str(&residual);
                parent.end = done_end;
            }
            None => return Ok(residual),
        }
    }
}

/// One node of the `collect` walk whose children are still being folded
/// into its own comparison bytes.
struct CollectFrame<'tree> {
    node: tree_sitter::Node<'tree>,
    name: Option<String>,
    key: Option<String>,
    /// The scope this node's children are qualified by.
    child_scope: String,
    own: String,
    end: usize,
    children: Vec<tree_sitter::Node<'tree>>,
    next: usize,
}

/// `None` is a comment or attribute that belongs to the next definition:
/// it contributes no residual bytes and its children are not walked.
fn open_frame<'tree>(
    node: tree_sitter::Node<'tree>,
    source: &str,
    scope: &str,
) -> Option<CollectFrame<'tree>> {
    if matches!(
        node.kind(),
        "line_comment" | "block_comment" | "attribute_item" | "inner_attribute_item"
    ) {
        let mut next = node.next_named_sibling();
        while let Some(sibling) = next {
            if identity(sibling, source).is_some() {
                return None;
            }
            if !matches!(
                sibling.kind(),
                "line_comment" | "block_comment" | "attribute_item" | "inner_attribute_item"
            ) {
                break;
            }
            next = sibling.next_named_sibling();
        }
    }
    let name = identity(node, source);
    let key = name.as_ref().map(|n| {
        if scope.is_empty() {
            n.clone()
        } else {
            format!("{scope}::{n}")
        }
    });
    let child_scope = key.clone().unwrap_or_else(|| scope.to_owned());
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect();
    Some(CollectFrame {
        node,
        name,
        key,
        child_scope,
        own: String::new(),
        end: node.start_byte(),
        children,
        next: 0,
    })
}

/// Every child is folded in: add the tail, file the unit and hand back the
/// residual the parent keeps in its own bytes.
fn close_frame(
    frame: CollectFrame<'_>,
    source: &str,
    units: &mut Units,
    implementations: &mut BTreeMap<String, Vec<ImplBlock>>,
) -> Result<String> {
    let CollectFrame {
        node,
        name,
        key,
        mut own,
        end,
        ..
    } = frame;
    let tail = &source[end..node.end_byte()];
    if node.kind() != "source_file" || !tail.trim().is_empty() {
        own.push_str(tail);
    }
    if let (Some(key), Some(name)) = (key, name) {
        let start = super::rust_source::rust_doc_context_start_byte(node, source);
        let comparison = format!("{}{}", &source[start..node.start_byte()], own);
        let start_line = source[..start].bytes().filter(|b| *b == b'\n').count() as u32 + 1;
        if node.kind() == "impl_item" {
            implementations.entry(key).or_default().push(ImplBlock {
                own: comparison,
                text: source[start..node.end_byte()].to_owned(),
                start: start_line,
                end: node.end_position().row as u32 + 1,
            });
        } else {
            insert(
                units,
                key,
                &source[start..node.end_byte()],
                &comparison,
                start_line,
                node.end_position().row as u32 + 1,
            )?;
        }
        // Conditional identity is already retained by the definition's unit.
        // Do not make condition ordering change its parent's residual bytes.
        let residual_name = name.split("#[").next().unwrap_or(&name);
        Ok(format!("<{residual_name}>"))
    } else {
        if node.kind() == "source_file" && !own.trim().is_empty() {
            // The root residual contains imports, attributes and other source
            // facts that must not disappear merely because they lack a name.
            let residual = own.trim();
            insert(
                units,
                "file-residual".into(),
                source,
                residual,
                1,
                source.lines().count().max(1) as u32,
            )?;
        }
        Ok(own)
    }
}

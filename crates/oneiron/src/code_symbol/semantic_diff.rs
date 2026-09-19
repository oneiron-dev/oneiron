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
    collect(tree.root_node(), source, "", &mut units)?;
    Ok(units)
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
        return Some(match trait_name {
            Some(trait_name) => format!("{}:{} for {}", node.kind(), trait_name, name),
            None => format!("{}:{}", node.kind(), name),
        });
    }
    None
}

// Remove child definitions from the parent's comparison bytes. Changing a
// method does not also report its unchanged impl header as a second change.
fn collect(
    node: tree_sitter::Node<'_>,
    source: &str,
    scope: &str,
    units: &mut Units,
) -> Result<String> {
    if matches!(
        node.kind(),
        "line_comment" | "block_comment" | "attribute_item" | "inner_attribute_item"
    ) {
        let mut next = node.next_named_sibling();
        while let Some(sibling) = next {
            if identity(sibling, source).is_some() {
                return Ok(String::new());
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
    let child_scope = key.as_deref().unwrap_or(scope);
    let mut own = String::new();
    let mut end = node.start_byte();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        own.push_str(&source[end..child.start_byte()]);
        own.push_str(&collect(child, source, child_scope, units)?);
        end = child.end_byte();
    }
    own.push_str(&source[end..node.end_byte()]);
    if let (Some(key), Some(name)) = (key, name) {
        let start = super::rust_source::rust_doc_context_start_byte(node, source);
        let comparison = format!("{}{}", &source[start..node.start_byte()], own);
        let start_line = source[..start].bytes().filter(|b| *b == b'\n').count() as u32 + 1;
        insert(
            units,
            key,
            &source[start..node.end_byte()],
            &comparison,
            start_line,
            node.end_position().row as u32 + 1,
        )?;
        Ok(format!("<{name}>"))
    } else {
        if node.kind() == "source_file" && !own.trim().is_empty() {
            // The root residual contains imports, attributes and other source
            // facts that must not disappear merely because they lack a name.
            let residual = own.split_whitespace().collect::<Vec<_>>().join(" ");
            insert(
                units,
                "file-residual".into(),
                source,
                &residual,
                1,
                source.lines().count().max(1) as u32,
            )?;
        }
        Ok(own)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_define_changes_and_text_is_derived() {
        let before = "fn a() -> u8 { 1 }\nfn b() {}\n";
        let after = "fn a() -> u8 { 2 }\nfn b() {}\n";
        let diff = semantic_code_diff("src/lib.rs", before, after).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].symbol, "function_item:a");
        assert_eq!(
            diff[0].before.as_ref().unwrap().content_hash,
            sha256_bytes(b"fn a() -> u8 { 1 }")
        );
        assert_eq!(
            diff[0].after.as_ref().unwrap().content_hash,
            sha256_bytes(b"fn a() -> u8 { 2 }")
        );
        assert_eq!(
            code_text_diff("src/lib.rs", before, after).unwrap(),
            render_code_semantic_diff(&diff)
        );
        let moved = "\n\nfn a() -> u8 { 1 }\nfn b() {}\n";
        assert!(
            semantic_code_diff("src/lib.rs", before, moved)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn method_change_is_not_also_an_impl_change() {
        let diff = semantic_code_diff(
            "a.rs",
            "impl A { fn f() { a(); } }",
            "impl A { fn f() { b(); } }",
        )
        .unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].symbol, "impl_item:A::function_item:f");
    }
}

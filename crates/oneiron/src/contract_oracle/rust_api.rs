//! Tree-sitter public-name extraction over a crate's module tree.
use super::{invalid, safe_path};
use crate::error::Result;
use std::collections::BTreeSet;
use std::path::Path;
use tree_sitter::{Node, Parser};

/// Extract syntactically public names, including inline/external modules and aliases.
/// Restricted visibility is private. Glob exports and custom module paths fail closed:
/// their resolved surface needs compiler metadata rather than a guessed name set.
pub fn rust_public_names(
    root: &Path,
    crate_name: &str,
    root_file: &str,
) -> Result<BTreeSet<String>> {
    if crate_name.is_empty() {
        return Err(invalid("crate name is empty"));
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| invalid("Rust language initialization failed"))?;
    let mut names = BTreeSet::new();
    let directory = Path::new(root_file).parent().unwrap_or(Path::new(""));
    let directory = directory.to_string_lossy();
    let mut scan = Scan {
        root,
        crate_name,
        parser,
        names: &mut names,
        files: BTreeSet::new(),
    };
    scan.file(
        root_file,
        &directory,
        crate_name,
        0,
        ModuleScope {
            reachable: true,
            conditional: false,
        },
    )?;
    Ok(names)
}

#[derive(Clone, Copy)]
struct ModuleScope {
    reachable: bool,
    conditional: bool,
}

struct Scan<'a> {
    root: &'a Path,
    crate_name: &'a str,
    parser: Parser,
    names: &'a mut BTreeSet<String>,
    files: BTreeSet<String>,
}

impl Scan<'_> {
    fn file(
        &mut self,
        file: &str,
        directory: &str,
        prefix: &str,
        depth: usize,
        scope: ModuleScope,
    ) -> Result<()> {
        if depth > 64 || self.files.len() >= 4096 || !self.files.insert(file.to_owned()) {
            return Err(invalid("Rust module traversal is recursive or too large"));
        }
        let path = safe_path(self.root, file)?;
        let bytes = std::fs::read(path)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid("Rust source exceeds oracle limit"));
        }
        let source =
            std::str::from_utf8(&bytes).map_err(|_| invalid("Rust source is not UTF-8"))?;
        let tree = self
            .parser
            .parse(source, None)
            .ok_or_else(|| invalid("Rust parse failed"))?;
        if tree.root_node().has_error() {
            return Err(invalid("Rust source contains parse errors"));
        }
        self.items(tree.root_node(), source, directory, prefix, depth, scope)
    }

    fn items(
        &mut self,
        parent: Node<'_>,
        source: &str,
        directory: &str,
        prefix: &str,
        depth: usize,
        scope: ModuleScope,
    ) -> Result<()> {
        let mut cursor = parent.walk();
        let children: Vec<_> = parent.named_children(&mut cursor).collect();
        for node in &children {
            if node.kind() == "impl_item" {
                continue;
            }
            if node.kind() == "attribute_item" && text(*node, source).contains("path") {
                return Err(invalid("custom module paths require compiler API metadata"));
            }
            if node.kind() == "macro_definition" && exported_macro(*node, source)? {
                if scope.conditional || conditional_attributes(*node, source) {
                    return Err(invalid(
                        "conditional macro exports require compiler API metadata",
                    ));
                }
                let name = node
                    .child_by_field_name("name")
                    .ok_or_else(|| invalid("exported macro name missing"))?;
                self.names
                    .insert(format!("{}::{}", self.crate_name, text(name, source)));
                continue;
            }
            let visible = scope.reachable && public(*node, source);
            // A private module may contain a macro_export at the crate root.
            if !visible && node.kind() != "mod_item" {
                continue;
            }
            if node.kind() == "use_declaration" {
                let argument = node
                    .child_by_field_name("argument")
                    .ok_or_else(|| invalid("public use has no argument"))?;
                let mut exports = BTreeSet::new();
                use_names(argument, source, &mut exports)?;
                for name in exports {
                    self.names.insert(format!("{prefix}::{name}"));
                }
                continue;
            }
            let Some(name_node) = node.child_by_field_name("name") else {
                continue;
            };
            let name = text(name_node, source);
            let full = format!("{prefix}::{name}");
            if visible {
                self.names.insert(full.clone());
            }
            match node.kind() {
                "mod_item" => {
                    let child_directory = join(directory, name);
                    let child_scope = ModuleScope {
                        reachable: visible,
                        conditional: scope.conditional || conditional_attributes(*node, source),
                    };
                    if let Some(body) = node.child_by_field_name("body") {
                        self.items(
                            body,
                            source,
                            &child_directory,
                            &full,
                            depth + 1,
                            child_scope,
                        )?;
                    } else {
                        let flat = format!("{child_directory}.rs");
                        let nested = format!("{child_directory}/mod.rs");
                        let has_flat = safe_path(self.root, &flat)?.is_file();
                        let has_nested = safe_path(self.root, &nested)?.is_file();
                        let file = match (has_flat, has_nested) {
                            (true, false) => flat,
                            (false, true) => nested,
                            _ => {
                                return Err(invalid(
                                    "public module source is missing or ambiguous",
                                ));
                            }
                        };
                        self.file(&file, &child_directory, &full, depth + 1, child_scope)?;
                    }
                }
                "struct_item" | "union_item" | "enum_item" | "trait_item" => {
                    if let Some(body) = node.child_by_field_name("body") {
                        let implicit = matches!(node.kind(), "enum_item" | "trait_item");
                        self.members(body, source, &full, implicit);
                    }
                }
                _ => {}
            }
        }
        // Only inherent methods of publicly reachable types are part of this surface.
        for node in children.into_iter().filter(|n| n.kind() == "impl_item") {
            if node.child_by_field_name("trait").is_some() {
                continue;
            }
            let Some(ty) = node.child_by_field_name("type") else {
                continue;
            };
            let type_name = text(ty, source).split('<').next().unwrap_or_default();
            let full = format!("{prefix}::{type_name}");
            if self.names.contains(&full)
                && let Some(body) = node.child_by_field_name("body")
            {
                self.members(body, source, &full, false);
            }
        }
        Ok(())
    }

    fn members(&mut self, body: Node<'_>, source: &str, prefix: &str, implicit: bool) {
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            if (implicit || public(member, source))
                && let Some(name) = member.child_by_field_name("name")
            {
                self.names
                    .insert(format!("{prefix}::{}", text(name, source)));
            }
        }
    }
}

fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}
fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
fn exported_macro(node: Node<'_>, source: &str) -> Result<bool> {
    let mut exported = false;
    let mut previous = node.prev_named_sibling();
    while let Some(attribute) = previous {
        match attribute.kind() {
            "line_comment" | "block_comment" => {}
            "attribute_item" => {
                let attribute = attribute
                    .named_child(0)
                    .ok_or_else(|| invalid("macro attribute missing"))?;
                let name = attribute.named_child(0).map(|n| text(n, source));
                if name == Some("macro_export") {
                    exported = true;
                }
                if name == Some("cfg_attr") && text(attribute, source).contains("macro_export") {
                    return Err(invalid(
                        "conditional macro exports require compiler API metadata",
                    ));
                }
            }
            _ => break,
        }
        previous = attribute.prev_named_sibling();
    }
    Ok(exported)
}
fn conditional_attributes(node: Node<'_>, source: &str) -> bool {
    let mut previous = node.prev_named_sibling();
    while let Some(attribute) = previous {
        match attribute.kind() {
            "line_comment" | "block_comment" => {}
            "attribute_item" => {
                if let Some(name) = attribute.named_child(0).and_then(|n| n.named_child(0))
                    && matches!(text(name, source), "cfg" | "cfg_attr")
                {
                    return true;
                }
            }
            _ => break,
        }
        previous = attribute.prev_named_sibling();
    }
    false
}
fn public(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "visibility_modifier" && text(child, source) == "pub")
}
fn use_names(node: Node<'_>, source: &str, names: &mut BTreeSet<String>) -> Result<()> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            names.insert(text(node, source).to_owned());
        }
        "scoped_identifier" => {
            let name = node
                .child_by_field_name("name")
                .ok_or_else(|| invalid("public use name missing"))?;
            names.insert(text(name, source).to_owned());
        }
        "use_as_clause" => {
            let alias = node
                .child_by_field_name("alias")
                .ok_or_else(|| invalid("public alias missing"))?;
            if text(alias, source) != "_" {
                names.insert(text(alias, source).to_owned());
            }
        }
        "scoped_use_list" => {
            let list = node
                .child_by_field_name("list")
                .ok_or_else(|| invalid("public use list missing"))?;
            use_names(list, source, names)?;
        }
        "use_list" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                use_names(child, source, names)?;
            }
        }
        _ => {
            return Err(invalid(
                "unresolved public use requires compiler API metadata",
            ));
        }
    }
    Ok(())
}

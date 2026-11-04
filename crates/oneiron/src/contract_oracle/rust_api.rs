//! Tree-sitter public-name extraction over a crate's module tree.
use super::{invalid, safe_path};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tree_sitter::{Node, Parser};

/// A crate's public names, and the explicit re-exports whose target the
/// syntactic walk could not reach (FIX 9767).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustPublicNames {
    pub names: BTreeSet<String>,
    /// Exported paths whose target is not one of the crate's own items: an
    /// external crate, a module or an alias the walk does not follow. Their
    /// members are not in `names`; a record of the gap, never a refusal.
    pub unresolved: BTreeSet<String>,
}

/// Extract syntactically public names, including inline/external modules and aliases.
/// Restricted visibility is private. Glob exports and custom module paths fail closed:
/// their resolved surface needs compiler metadata rather than a guessed name set.
/// An explicit re-export carries its defining type's members under the exported path.
pub fn rust_public_names(
    root: &Path,
    crate_name: &str,
    root_file: &str,
) -> Result<RustPublicNames> {
    if crate_name.is_empty() {
        return Err(invalid("crate name is empty"));
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| invalid("Rust language initialization failed"))?;
    let directory = Path::new(root_file).parent().unwrap_or(Path::new(""));
    let mut scan = Scan {
        root,
        crate_name,
        parser,
        names: BTreeSet::new(),
        files: BTreeSet::new(),
        pending: vec![ModuleFile {
            file: root_file.to_owned(),
            directory: directory.to_string_lossy().into_owned(),
            prefix: crate_name.to_owned(),
            scope: ModuleScope {
                reachable: true,
                conditional: false,
            },
        }],
        defined: BTreeMap::new(),
        aliases: BTreeMap::new(),
        exports: Vec::new(),
        impls: Vec::new(),
        unresolved: BTreeSet::new(),
    };
    // An explicit worklist, so a deep or wide module tree completes instead of
    // refusing past a depth or file count (FIX 9768).
    while let Some(module) = scan.pending.pop() {
        scan.file(module)?;
    }
    Ok(scan.finish())
}

#[derive(Clone, Copy)]
struct ModuleScope {
    reachable: bool,
    conditional: bool,
}

/// An out-of-line module the walk has yet to read.
struct ModuleFile {
    file: String,
    directory: String,
    prefix: String,
    scope: ModuleScope,
}

/// An inline module body the walk has yet to read: its node, directory,
/// path and scope.
type ModuleBody<'t> = (Node<'t>, String, String, ModuleScope);

struct Scan<'a> {
    root: &'a Path,
    crate_name: &'a str,
    parser: Parser,
    names: BTreeSet<String>,
    files: BTreeSet<String>,
    pending: Vec<ModuleFile>,
    /// Every `pub` item by its defining path, reachable or not, with the
    /// members a type declares: what a re-export resolves to.
    defined: BTreeMap<String, BTreeSet<String>>,
    /// Every `pub use` name by its path, to the path it names: the hops a
    /// re-export's resolution may take.
    aliases: BTreeMap<String, String>,
    /// Each reachable re-export's path and the path it names.
    exports: Vec<(String, String)>,
    /// Each inherent impl's type path and its `pub` member names, applied
    /// once every module is read.
    impls: Vec<(String, Vec<String>)>,
    unresolved: BTreeSet<String>,
}

impl Scan<'_> {
    fn file(&mut self, module: ModuleFile) -> Result<()> {
        // Without custom paths (refused) every module has a file of its own,
        // so a file reached twice is a module cycle.
        if !self.files.insert(module.file.clone()) {
            return Err(invalid("Rust module traversal is recursive"));
        }
        let path = safe_path(self.root, &module.file)?;
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
        // Inline module bodies wait on a worklist of their own, so nesting
        // never deepens the call stack.
        let mut bodies: Vec<ModuleBody<'_>> = vec![(
            tree.root_node(),
            module.directory,
            module.prefix,
            module.scope,
        )];
        while let Some((body, directory, prefix, scope)) = bodies.pop() {
            self.items(body, source, &directory, &prefix, scope, &mut bodies)?;
        }
        Ok(())
    }

    fn items<'t>(
        &mut self,
        parent: Node<'t>,
        source: &str,
        directory: &str,
        prefix: &str,
        scope: ModuleScope,
        bodies: &mut Vec<ModuleBody<'t>>,
    ) -> Result<()> {
        let mut cursor = parent.walk();
        let children: Vec<_> = parent.named_children(&mut cursor).collect();
        let scope = ModuleScope {
            conditional: scope.conditional
                || children.iter().any(|node| {
                    node.kind() == "inner_attribute_item"
                        && node
                            .named_child(0)
                            .and_then(|n| n.named_child(0))
                            .is_some_and(|name| matches!(text(name, source), "cfg" | "cfg_attr"))
                }),
            ..scope
        };
        for node in &children {
            if node.kind() == "impl_item" {
                self.inherent_impl(*node, source, prefix);
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
            let is_pub = public(*node, source);
            let visible = scope.reachable && is_pub;
            if node.kind() == "use_declaration" {
                if is_pub {
                    self.use_declaration(*node, source, prefix, visible)?;
                }
                continue;
            }
            // A private module may contain a macro_export at the crate root,
            // and an unreachable `pub` item may be re-exported.
            if !is_pub && node.kind() != "mod_item" {
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
                        bodies.push((body, child_directory, full, child_scope));
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
                        self.pending.push(ModuleFile {
                            file,
                            directory: child_directory,
                            prefix: full,
                            scope: child_scope,
                        });
                    }
                }
                "struct_item" | "union_item" | "enum_item" | "trait_item" => {
                    let implicit = matches!(node.kind(), "enum_item" | "trait_item");
                    let members = node
                        .child_by_field_name("body")
                        .map(|body| member_names(body, source, implicit))
                        .unwrap_or_default();
                    if visible {
                        for member in &members {
                            self.names.insert(format!("{full}::{member}"));
                        }
                    }
                    self.defined.entry(full).or_default().extend(members);
                }
                "function_item" | "const_item" | "static_item" => {
                    self.defined.entry(full).or_default();
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Keeps an inherent impl's `pub` members for its type, applied once
    /// every module is read.
    fn inherent_impl(&mut self, node: Node<'_>, source: &str, prefix: &str) {
        if node.child_by_field_name("trait").is_some() {
            return;
        }
        let (Some(ty), Some(body)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("body"),
        ) else {
            return;
        };
        let type_name = text(ty, source).split('<').next().unwrap_or_default();
        self.impls.push((
            format!("{prefix}::{type_name}"),
            member_names(body, source, false),
        ));
    }

    /// Records a `pub use`'s names: exported when `visible`, and each one a
    /// hop a re-export's resolution may take either way (FIX 9767). An
    /// unreachable one that does not parse is skipped, never refused.
    fn use_declaration(
        &mut self,
        node: Node<'_>,
        source: &str,
        prefix: &str,
        visible: bool,
    ) -> Result<()> {
        let mut exports = Vec::new();
        let parsed = node
            .child_by_field_name("argument")
            .ok_or_else(|| invalid("public use has no argument"))
            .and_then(|argument| use_exports(argument, source, &[], &mut exports));
        match parsed {
            Err(error) if visible => return Err(error),
            Err(_) => return Ok(()),
            Ok(()) => {}
        }
        for (name, path) in exports {
            let full = format!("{prefix}::{name}");
            let target = self.module_path(prefix, &path);
            if visible {
                self.names.insert(full.clone());
                match &target {
                    Some(target) => self.exports.push((full.clone(), target.clone())),
                    None => {
                        self.unresolved.insert(full.clone());
                    }
                }
            }
            if let Some(target) = target {
                self.aliases.insert(full, target);
            }
        }
        Ok(())
    }

    /// The crate path `segments` name from the module at `prefix`, or `None`
    /// for one outside the crate.
    fn module_path(&self, prefix: &str, segments: &[String]) -> Option<String> {
        let (mut module, rest): (Vec<&str>, &[String]) = match segments.split_first() {
            Some((first, rest)) if first == "crate" => (vec![self.crate_name], rest),
            _ => (prefix.split("::").collect(), segments),
        };
        for segment in rest {
            match segment.as_str() {
                "::" | "crate" => return None,
                "self" => {}
                "super" => {
                    if module.len() <= 1 {
                        return None;
                    }
                    module.pop();
                }
                name => module.push(name),
            }
        }
        Some(module.join("::"))
    }

    /// Applies the inherent impls, then gives each reachable re-export its
    /// target type's members under the exported path; one that reaches no
    /// item of the crate is unresolved.
    fn finish(mut self) -> RustPublicNames {
        for (full, members) in std::mem::take(&mut self.impls) {
            if self.names.contains(&full) {
                for member in &members {
                    self.names.insert(format!("{full}::{member}"));
                }
            }
            if let Some(defined) = self.defined.get_mut(&full) {
                defined.extend(members);
            }
        }
        for (export, mut target) in std::mem::take(&mut self.exports) {
            let mut hops: BTreeSet<String> = BTreeSet::new();
            loop {
                if let Some(members) = self.defined.get(&target) {
                    for member in members {
                        self.names.insert(format!("{export}::{member}"));
                    }
                    break;
                }
                // A hop already taken is an alias cycle: unresolved too.
                let next = self.aliases.get(&target).cloned();
                let Some(next) = next.filter(|_| !hops.contains(&target)) else {
                    self.unresolved.insert(export);
                    break;
                };
                hops.insert(std::mem::replace(&mut target, next));
            }
        }
        RustPublicNames {
            names: self.names,
            unresolved: self.unresolved,
        }
    }
}

/// The member names a type or impl body declares: every one when
/// `implicit` (enum variants, trait items), else the `pub` ones.
fn member_names(body: Node<'_>, source: &str, implicit: bool) -> Vec<String> {
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|member| implicit || public(*member, source))
        .filter_map(|member| member.child_by_field_name("name"))
        .map(|name| text(name, source).to_owned())
        .collect()
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
/// The segments a use path spells, outermost first; a leading `::` stays a
/// segment of its own, so an external path never resolves in the crate.
fn path_segments(node: Node<'_>, source: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut at = Some(node);
    while let Some(node) = at {
        if node.kind() != "scoped_identifier" {
            segments.push(text(node, source).to_owned());
            break;
        }
        if let Some(name) = node.child_by_field_name("name") {
            segments.push(text(name, source).to_owned());
        }
        at = node.child_by_field_name("path");
        if at.is_none() {
            segments.push("::".to_owned());
        }
    }
    segments.reverse();
    segments
}
fn joined(base: &[String], path: &[String]) -> Vec<String> {
    [base, path].concat()
}
/// Each name a use tree exports, with the path it names; `base` is the path
/// the lists above it spelled.
fn use_exports(
    node: Node<'_>,
    source: &str,
    base: &[String],
    exports: &mut Vec<(String, Vec<String>)>,
) -> Result<()> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let name = text(node, source).to_owned();
            exports.push((name.clone(), joined(base, std::slice::from_ref(&name))));
        }
        "scoped_identifier" => {
            let name = node
                .child_by_field_name("name")
                .ok_or_else(|| invalid("public use name missing"))?;
            exports.push((
                text(name, source).to_owned(),
                joined(base, &path_segments(node, source)),
            ));
        }
        "use_as_clause" => {
            let alias = node
                .child_by_field_name("alias")
                .ok_or_else(|| invalid("public alias missing"))?;
            if text(alias, source) != "_" {
                let path = node
                    .child_by_field_name("path")
                    .map(|path| path_segments(path, source))
                    .unwrap_or_default();
                exports.push((text(alias, source).to_owned(), joined(base, &path)));
            }
        }
        "scoped_use_list" => {
            let list = node
                .child_by_field_name("list")
                .ok_or_else(|| invalid("public use list missing"))?;
            let path = node
                .child_by_field_name("path")
                .map_or_else(|| vec!["::".to_owned()], |path| path_segments(path, source));
            use_exports(list, source, &joined(base, &path), exports)?;
        }
        "use_list" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                use_exports(child, source, base, exports)?;
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

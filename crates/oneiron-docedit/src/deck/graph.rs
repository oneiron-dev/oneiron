//! The deck's part graph: relationship targets resolved to part names, and the
//! presentation, slide, layout, master and theme parts parsed once. Nothing
//! here writes to the package.
use super::DeckError;
use crate::ooxml::{PACKAGE_RELATIONSHIPS, XmlTree};
use crate::retained_opc::{Package, XmlLimits};
use std::collections::BTreeMap;

pub(super) const P: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
pub(super) const A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
pub(super) const P14: &str = "http://schemas.microsoft.com/office/powerpoint/2010/main";
pub(super) const A16: &str = "http://schemas.microsoft.com/office/drawing/2014/main";

/// Relationship kinds the view parses up front; every other part is read as
/// bytes only when a fingerprint needs it.
const FOLLOW: [&str; 4] = ["slide", "slideLayout", "slideMaster", "theme"];

/// One relationship; `kind` is the type URI's last segment (`slideLayout`).
#[derive(Debug, Clone)]
pub(super) struct Relationship {
    pub(super) id: String,
    pub(super) kind: String,
    /// The resolved part name; `None` for an external target.
    pub(super) target: Option<String>,
    /// An external target as written (FIX 8576): never a part, never
    /// fetched, hashed into the render fingerprint as written.
    pub(super) external: Option<String>,
}

/// One parsed XML part and the relationships it owns.
pub(super) struct Part {
    pub(super) tree: XmlTree,
    pub(super) rels: Vec<Relationship>,
}

pub(super) struct Graph {
    pub(super) limits: XmlLimits,
    pub(super) parts: BTreeMap<String, Part>,
    pub(super) presentation: String,
}

impl Graph {
    pub(super) fn load(package: &Package) -> Result<Self, DeckError> {
        let limits = package.limits().xml;
        let presentation = relationships(package, "", limits)?
            .into_iter()
            .find(|rel| rel.kind == "officeDocument")
            .and_then(|rel| rel.target)
            .ok_or(DeckError::Invalid("package has no presentation part"))?;
        let mut graph = Self {
            limits,
            parts: BTreeMap::new(),
            presentation: presentation.clone(),
        };
        let mut queue = vec![presentation];
        while let Some(name) = queue.pop() {
            if graph.parts.contains_key(&name) {
                continue;
            }
            let bytes = package
                .part(&name)?
                .ok_or(DeckError::Invalid("related part is missing"))?;
            let part = Part {
                tree: XmlTree::parse(&bytes, limits)?,
                rels: relationships(package, &name, limits)?,
            };
            queue.extend(
                part.rels
                    .iter()
                    .filter(|rel| FOLLOW.contains(&rel.kind.as_str()))
                    .filter_map(|rel| rel.target.clone()),
            );
            graph.parts.insert(name, part);
        }
        Ok(graph)
    }

    pub(super) fn part(&self, name: &str) -> Result<&Part, DeckError> {
        self.parts
            .get(name)
            .ok_or(DeckError::Invalid("related part is missing"))
    }

    /// The single internal target of `kind` from `part`; two are ambiguous.
    pub(super) fn related(&self, part: &str, kind: &str) -> Result<Option<&str>, DeckError> {
        let mut targets = self
            .part(part)?
            .rels
            .iter()
            .filter(|rel| rel.kind == kind)
            .filter_map(|rel| rel.target.as_deref());
        let first = targets.next();
        if targets.next().is_some() {
            return Err(DeckError::Invalid("ambiguous part relationship"));
        }
        Ok(first)
    }
}

/// Parse the relationships `part` owns; a part without a `.rels` has none.
/// The empty name addresses the package's own relationships.
pub(super) fn relationships(
    package: &Package,
    part: &str,
    limits: XmlLimits,
) -> Result<Vec<Relationship>, DeckError> {
    let Some(bytes) = package.part(&rels_path(part))? else {
        return Ok(Vec::new());
    };
    let tree = XmlTree::parse(&bytes, limits)?;
    tree.root(PACKAGE_RELATIONSHIPS, "Relationships")?;
    let mut rels: Vec<Relationship> = Vec::new();
    for (_, node) in tree.children(0) {
        if !node.is(PACKAGE_RELATIONSHIPS, "Relationship") {
            continue;
        }
        let (Some(id), Some(kind), Some(target)) =
            (node.attr("Id"), node.attr("Type"), node.attr("Target"))
        else {
            return Err(DeckError::Invalid("incomplete relationship"));
        };
        if rels.iter().any(|rel| rel.id == id) {
            return Err(DeckError::Invalid("duplicate relationship id"));
        }
        let (target, external) = match node.attr("TargetMode") {
            Some("External") => (None, Some(target.to_owned())),
            None | Some("Internal") => (Some(resolve_target(part, target)?), None),
            Some(_) => return Err(DeckError::Invalid("unknown relationship target mode")),
        };
        rels.push(Relationship {
            id: id.to_owned(),
            kind: kind.rsplit('/').next().unwrap_or(kind).to_owned(),
            target,
            external,
        });
    }
    Ok(rels)
}

fn rels_path(part: &str) -> String {
    match part.rsplit_once('/') {
        Some((dir, file)) => format!("{dir}/_rels/{file}.rels"),
        None => format!("_rels/{part}.rels"),
    }
}

/// Resolve an internal target against its source part's folder. Escapes,
/// URI syntax and paths above the package root are refused, never repaired.
fn resolve_target(source: &str, target: &str) -> Result<String, DeckError> {
    if target.is_empty() || target.contains(['\\', ':', '%', '?', '#', '\0']) {
        return Err(DeckError::Invalid("unsupported relationship target"));
    }
    let mut segments: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        source.split('/').collect()
    };
    segments.pop();
    for segment in target.trim_start_matches('/').split('/') {
        match segment {
            "" => return Err(DeckError::Invalid("empty relationship target segment")),
            "." => {}
            ".." => {
                segments
                    .pop()
                    .ok_or(DeckError::Invalid("relationship target leaves the package"))?;
            }
            name => segments.push(name),
        }
    }
    Ok(segments.join("/"))
}

/// The first direct child with this expanded name.
pub(super) fn child(tree: &XmlTree, at: usize, ns: &str, name: &str) -> Option<usize> {
    tree.nodes
        .get(at)?
        .children
        .iter()
        .copied()
        .find(|&index| tree.nodes[index].is(ns, name))
}

/// Follow direct children by expanded name.
pub(super) fn path(tree: &XmlTree, at: usize, steps: &[(&str, &str)]) -> Option<usize> {
    steps
        .iter()
        .try_fold(at, |node, &(ns, name)| child(tree, node, ns, name))
}

/// Every element inside `at`, in document order.
pub(super) fn descendants(tree: &XmlTree, at: usize) -> impl Iterator<Item = usize> + '_ {
    let end = tree.nodes.get(at).map_or(0, |node| node.span.end);
    (at + 1..tree.nodes.len()).take_while(move |&index| tree.nodes[index].span.start < end)
}

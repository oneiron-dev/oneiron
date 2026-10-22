//! Content and render fingerprints. A content fingerprint hashes one
//! normalized element; a render fingerprint hashes the slide and every part it
//! renders through (layout, master, theme, media, charts, embedded workbooks),
//! so a theme change is visible even when `p:spTree` is untouched.
use super::graph::{Graph, P, descendants, relationships};
use super::{DeckError, Dependency};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

const XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// Relationship kinds that never change what the slide shows.
const NOT_RENDERED: [&str; 5] = [
    "notesSlide",
    "comments",
    "commentAuthors",
    "authors",
    "slide",
];

/// Hash an element and its subtree by expanded names, sorted attributes and
/// text. Prefixes, namespace declarations and indentation do not count.
pub(super) fn content(tree: &XmlTree, at: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let field = |hasher: &mut blake3::Hasher, bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    for index in std::iter::once(at).chain(descendants(tree, at)) {
        let node = &tree.nodes[index];
        let parent = node
            .parent
            .filter(|_| index != at)
            .map_or(u64::MAX, |parent| (parent - at) as u64);
        hasher.update(&parent.to_le_bytes());
        field(&mut hasher, node.namespace.as_bytes());
        field(&mut hasher, node.name.as_bytes());
        for ((ns, local), value) in &node.attrs_ns {
            if ns == XMLNS || (ns.is_empty() && (local == "xmlns" || local.starts_with("xmlns:"))) {
                continue;
            }
            field(&mut hasher, ns.as_bytes());
            field(&mut hasher, local.as_bytes());
            field(&mut hasher, value.as_bytes());
        }
        let text = if node.children.is_empty() {
            node.text.as_str()
        } else {
            node.text.trim()
        };
        if !text.is_empty() {
            field(&mut hasher, text.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Walk the slide's rendering relationships. Notes, comments, authors and
/// slide-to-slide links are not followed, and a master's layout list is not a
/// dependency of every slide under it.
pub(super) fn render(
    package: &Package,
    graph: &Graph,
    slide: &str,
) -> Result<([u8; 32], Vec<Dependency>), DeckError> {
    let mut parts: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut edges: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut queue = vec![slide.to_owned()];
    while let Some(part) = queue.pop() {
        if parts.contains_key(&part) {
            continue;
        }
        let hash = package
            .part(&part)?
            .map_or([0; 32], |bytes| *blake3::hash(&bytes).as_bytes());
        let rels = match graph.parts.get(&part) {
            Some(parsed) => parsed.rels.clone(),
            None if hash == [0; 32] => Vec::new(),
            None => relationships(package, &part)?,
        };
        parts.insert(part.clone(), hash);
        let master = graph.parts.get(&part).is_some_and(|parsed| {
            parsed
                .tree
                .nodes
                .first()
                .is_some_and(|root| root.is(P, "sldMaster"))
        });
        for rel in rels {
            if NOT_RENDERED.contains(&rel.kind.as_str()) || (master && rel.kind == "slideLayout") {
                continue;
            }
            let Some(target) = rel.target else {
                // An external target the slide renders through (a linked
                // picture or media) is an edge as written, never fetched; a
                // hyperlink shows nothing (FIX 8576). `:` is in no part name.
                if let Some(url) = rel.external
                    && rel.kind != "hyperlink"
                {
                    edges.insert((part.clone(), rel.id, format!("external:{}:{url}", rel.kind)));
                }
                continue;
            };
            edges.insert((part.clone(), rel.id, target.clone()));
            queue.push(target);
        }
    }
    // No slide links to the presentation, yet its slide size and default
    // text style render every slide. Its dependency hash covers only those
    // elements, so a slide-list edit leaves the render untouched.
    if let Some(parsed) = graph.parts.get(&graph.presentation)
        && let Some(bytes) = package.part(&graph.presentation)?
    {
        let mut context = blake3::Hasher::new();
        for (_, node) in parsed.tree.children(0) {
            if node.is(P, "sldSz") || node.is(P, "defaultTextStyle") {
                context.update(bytes.get(node.span.clone()).unwrap_or_default());
            }
        }
        parts.insert(graph.presentation.clone(), *context.finalize().as_bytes());
    }
    let mut hasher = blake3::Hasher::new();
    for (source, id, target) in &edges {
        for field in [source, id, target] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
    }
    let dependencies: Vec<Dependency> = parts
        .into_iter()
        .map(|(part, hash)| Dependency { part, hash })
        .collect();
    for dependency in &dependencies {
        hasher.update(&(dependency.part.len() as u64).to_le_bytes());
        hasher.update(dependency.part.as_bytes());
        hasher.update(&dependency.hash);
    }
    Ok((*hasher.finalize().as_bytes(), dependencies))
}

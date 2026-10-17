//! Slide-level structural edits: `duplicate_slide`, with relationship-aware
//! cloning under a tested policy, and `reorder_slides`.
//!
//! A copy keeps every relationship id of its source. Its relationships are
//! shared (layout, pictures, media, links, other slides), cloned with their
//! own closure (the notes slide, with its backlink repointed at the copy; a
//! chart with its embedded workbook, style, colours and theme override) or
//! left with the source (legacy and modern comments). A link to the source
//! itself points at the copy. Anything else refuses. The copy takes a slide
//! id above the caller's high-water mark and every id in the list, and fresh
//! creation ids drawn from the caller's seed; its shape ids and timing ids
//! are its source's. It goes after its source in the slide list and in its
//! section; custom shows are not given it.
//!
//! A reorder is a permutation of the slide ids. It rewrites the order of
//! `p:sldIdLst` and of each section's list, and refuses an order that splits
//! a section or moves sections past each other.
mod check;
mod lifecycle;
#[cfg(test)]
mod tests;

use super::super::check::declared_type;
use super::super::media::related;
use super::super::xml::{self, P, R};
use super::{Plan, mint_guid};
use crate::deck::{DeckView, guid};
use crate::edit::{EditRefusal, Effect};
use crate::ooxml::{Node, PACKAGE_RELATIONSHIPS, XmlTree};
use crate::retained_opc::{Package, Relationship, rels_name};

pub(super) use check::{duplicated, reordered};
pub(super) use lifecycle::{add_blank, delete};

const P14: &str = "http://schemas.microsoft.com/office/powerpoint/2010/main";
const A16: &str = "http://schemas.microsoft.com/office/drawing/2014/main";
/// The `p:ext` of a slide's `p14:creationId`.
const SLIDE_CREATION_EXT: &str = "{BB962C8B-B14F-4D97-AF65-F5344CB8AC3E}";
/// The `p:ext` of the presentation's `p14:sectionLst`.
const SECTION_EXT: &str = "{521415D9-36F7-43E2-AB2F-B90AF26B5E84}";
/// The `p:ext` of a slide's `p188:commentRel`.
const COMMENT_EXT: &str = "{6950BFC3-D8DA-4A85-94F7-54DA5524770B}";
const MODERN_COMMENTS: &str = "http://schemas.microsoft.com/office/2018/10/relationships/comments";
const MEDIA: &str = "http://schemas.microsoft.com/office/2007/relationships/media";
const CHART_STYLE: &str = "http://schemas.microsoft.com/office/2011/relationships/chartStyle";
const CHART_COLORS: &str = "http://schemas.microsoft.com/office/2011/relationships/chartColorStyle";
/// `ST_SlideId`: 256 to 2^31 - 1.
const SLIDE_IDS: std::ops::Range<u32> = 256..1 << 31;

/// What a copy wrote, for the independent check.
pub(super) struct Duplicate {
    pub(super) clone: String,
    pub(super) sld_id: u32,
    /// Each cloned dependency: `(original, copy)`.
    pub(super) cloned: Vec<(String, String)>,
}

/// The presentation's slide list and sections, as read.
struct Lists {
    part: String,
    bytes: Vec<u8>,
    tree: XmlTree,
    /// `p:sldId` elements in order, with their ids.
    slides: Vec<(usize, u32)>,
    /// Each section's `p14:sldId` elements in order, with their ids.
    sections: Vec<Vec<(usize, u32)>>,
}

impl Lists {
    fn read(package: &Package) -> Result<Self, EditRefusal> {
        let part =
            related(package, "", "officeDocument")?.ok_or(EditRefusal::Missing("presentation"))?;
        let (bytes, tree) = xml::read(package, &part)?;
        let ids = |list: Option<usize>, ns: &str| -> Result<Vec<(usize, u32)>, EditRefusal> {
            let Some(list) = list else {
                return Ok(Vec::new());
            };
            tree.children(list)
                .filter(|(_, node)| node.is(ns, "sldId"))
                .map(|(at, node)| {
                    let id = node.attr("id").and_then(|id| id.parse().ok());
                    Ok((at, id.ok_or(EditRefusal::Invalid("a slide id"))?))
                })
                .collect()
        };
        let slides = ids(xml::child(&tree, 0, P, "sldIdLst"), P)?;
        let lists: Vec<usize> = xml::child(&tree, 0, P, "extLst")
            .map(|list| {
                tree.children(list)
                    .filter(|(_, node)| node.is(P, "ext") && node.attr("uri") == Some(SECTION_EXT))
                    .filter_map(|(at, _)| xml::child(&tree, at, P14, "sectionLst"))
                    .collect()
            })
            .unwrap_or_default();
        let sections: Vec<Vec<(usize, u32)>> = match lists[..] {
            [] => Vec::new(),
            [list] => tree
                .children(list)
                .filter(|(_, node)| node.is(P14, "section"))
                .map(|(at, _)| ids(xml::child(&tree, at, P14, "sldIdLst"), P14))
                .collect::<Result<_, _>>()?,
            _ => return Err(EditRefusal::AmbiguousAnchor("two section lists")),
        };
        Ok(Self {
            part,
            bytes,
            tree,
            slides,
            sections,
        })
    }

    /// The section index of each slide id, when sections exist.
    fn section_of(&self, sld_id: u32) -> Option<usize> {
        self.sections
            .iter()
            .position(|section| section.iter().any(|&(_, id)| id == sld_id))
    }
}

/// `node`'s element bytes with the named attributes' values replaced.
fn copy_with(bytes: &[u8], node: &Node, values: &[(&str, &str)]) -> Result<Vec<u8>, EditRefusal> {
    let start = node.span.start;
    let edits = values
        .iter()
        .map(|(name, value)| {
            let (range, value) = xml::set_attribute(bytes, node, name, value);
            (range.start - start..range.end - start, value)
        })
        .collect();
    xml::splice(&bytes[node.span.clone()], edits)
}

/// The qualified name `r:id` is written with on `node`.
fn relationship_attribute(node: &Node) -> Option<&str> {
    let mut found = node.attr_spans.keys().filter(|name| {
        name.rsplit_once(':')
            .is_some_and(|(_, local)| local == "id")
    });
    let name = found.next()?;
    (found.next().is_none() && node.attr_ns(R, "id").is_some()).then_some(name.as_str())
}

/// A slide `p14:creationId` from BLAKE3 over the seed and a draw counter,
/// drawn again while another slide holds it.
pub(super) fn mint_creation_id(seed: &[u8], taken: &[u32]) -> Result<u32, EditRefusal> {
    (0u32..64)
        .map(|draw| {
            let mut hasher =
                blake3::Hasher::new_derive_key("oneiron-docedit 2026-10-16 slide creationId");
            hasher.update(seed);
            hasher.update(&draw.to_le_bytes());
            let mut b = [0u8; 4];
            b.copy_from_slice(&hasher.finalize().as_bytes()[..4]);
            u32::from_le_bytes(b)
        })
        .find(|id| *id != 0 && !taken.contains(id))
        .ok_or(EditRefusal::IdSpaceExhausted)
}

/// A new name in `original`'s folder, `{stem}{n}{extension}` above every
/// existing one: the stem is the file name less its extension and trailing
/// digits.
fn clone_name(package: &Package, original: &str) -> Result<String, EditRefusal> {
    let file = original.rfind('/').map_or(0, |at| at + 1);
    let (stem, extension) = match original[file..].rfind('.') {
        Some(dot) => original.split_at(file + dot),
        None => (original, ""),
    };
    xml::next_part(
        package,
        stem.trim_end_matches(|c: char| c.is_ascii_digit()),
        extension,
    )
}

/// A relationship target string pointing at `part`, which sits in the same
/// folder as the part `target` resolved to.
fn repointed(target: &str, part: &str) -> String {
    let file = part.rsplit('/').next().unwrap_or(part);
    match target.rsplit_once('/') {
        Some((folder, _)) => format!("{folder}/{file}"),
        None => file.to_owned(),
    }
}

/// The part a cloned relationship's source is: what its relationships may
/// reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Slide,
    Notes,
    Chart,
    /// A cloned part with no relationships of its own.
    Leaf,
}

enum Action {
    Share,
    /// Repoint at the copy: the source slide's link to itself, or its notes
    /// slide's backlink.
    ToCopy,
    Clone(Owner),
    /// Comments stay with the source.
    Omit,
}

/// The tested clone policy.
fn action(owner: Owner, rel: &Relationship, source: &str) -> Result<Action, EditRefusal> {
    if rel.external {
        return Ok(Action::Share);
    }
    let kind = rel.kind.as_str();
    let suffix = kind.strip_prefix(R).and_then(|rest| rest.strip_prefix('/'));
    Ok(match (owner, suffix) {
        (Owner::Slide, Some("slideLayout" | "image" | "hyperlink" | "video" | "audio")) => {
            Action::Share
        }
        (Owner::Slide, _) if kind == MEDIA => Action::Share,
        (Owner::Slide | Owner::Notes, Some("slide")) if rel.target == source => Action::ToCopy,
        (Owner::Slide, Some("slide")) => Action::Share,
        (Owner::Slide, Some("notesSlide")) => Action::Clone(Owner::Notes),
        (Owner::Slide, Some("chart")) => Action::Clone(Owner::Chart),
        (Owner::Slide, Some("comments")) => Action::Omit,
        (Owner::Slide, _) if kind == MODERN_COMMENTS => Action::Omit,
        (Owner::Notes, Some("notesMaster" | "image" | "hyperlink")) => Action::Share,
        (Owner::Chart, Some("package" | "themeOverride")) => Action::Clone(Owner::Leaf),
        (Owner::Chart, _) if kind == CHART_STYLE || kind == CHART_COLORS => {
            Action::Clone(Owner::Leaf)
        }
        (Owner::Chart, Some("image")) => Action::Share,
        _ => return Err(EditRefusal::CloneDependencyUnsupported(kind.to_owned())),
    })
}

/// Clones a slide's dependencies into `next`, reading the originals from
/// `input`.
struct Cloner<'a> {
    input: &'a Package,
    source: &'a str,
    copy: &'a str,
    cloned: Vec<(String, String)>,
    omitted: Vec<String>,
}

impl Cloner<'_> {
    /// Write `to`'s relationship part: `from`'s, with the same ids, each
    /// relationship shared, repointed, cloned or left out by the policy.
    fn relationships(
        &mut self,
        next: &mut Package,
        from: &str,
        to: &str,
        owner: Owner,
    ) -> Result<(), EditRefusal> {
        let Some(bytes) = self.input.part(&rels_name(from))? else {
            return Ok(());
        };
        let tree = XmlTree::parse(&bytes, self.input.limits().xml)?;
        let resolved = self.input.relationships(from)?;
        let mut edits = Vec::new();
        for (_, node) in tree.children(0) {
            if !node.is(PACKAGE_RELATIONSHIPS, "Relationship") {
                continue;
            }
            let id = node.attr("Id").unwrap_or_default();
            let rel = resolved
                .iter()
                .find(|rel| rel.id == id)
                .ok_or(EditRefusal::Invalid("a relationship without an id"))?;
            let target = match action(owner, rel, self.source)? {
                Action::Share => continue,
                Action::Omit => {
                    edits.push((node.span.clone(), Vec::new()));
                    self.omitted.push(rel.id.clone());
                    continue;
                }
                Action::ToCopy => self.copy.to_owned(),
                Action::Clone(inner) => self.clone_part(next, &rel.target, inner)?,
            };
            let written = node.attr("Target").unwrap_or_default();
            edits.push(xml::set_attribute(
                &bytes,
                node,
                "Target",
                &repointed(written, &target),
            ));
        }
        next.add_relationship_part(to, xml::splice(&bytes, edits)?)?;
        Ok(())
    }

    /// Clone `original` (once per operation) with its closure; returns the
    /// copy's name.
    fn clone_part(
        &mut self,
        next: &mut Package,
        original: &str,
        owner: Owner,
    ) -> Result<String, EditRefusal> {
        if let Some((_, copy)) = self.cloned.iter().find(|(from, _)| from == original) {
            return Ok(copy.clone());
        }
        let bytes = self
            .input
            .part(original)?
            .ok_or(EditRefusal::Missing("a dependency to clone"))?;
        let content_type =
            declared_type(self.input, original)?.ok_or(EditRefusal::Missing("content type"))?;
        if owner == Owner::Leaf && !self.input.relationships(original)?.is_empty() {
            return Err(EditRefusal::CloneDependencyUnsupported(format!(
                "relationships of {original}"
            )));
        }
        let name = clone_name(next, original)?;
        next.add_part(&name, &content_type, bytes)?;
        self.cloned.push((original.to_owned(), name.clone()));
        self.relationships(next, original, &name, owner)?;
        Ok(name)
    }
}

/// The copy's bytes: the source's, with fresh creation ids (one new GUID per
/// distinct old one, so repeated references stay paired) and no comment
/// extension.
fn slide_copy(
    bytes: &[u8],
    tree: &XmlTree,
    creation_id: Option<u32>,
    seed: &[u8],
    taken: &mut Vec<String>,
) -> Result<Vec<u8>, EditRefusal> {
    let mut edits = Vec::new();
    let mut fresh: Vec<(String, String)> = Vec::new();
    for node in tree.nodes.iter().filter(|node| node.is(A16, "creationId")) {
        // Keyed as the view reads it: equal GUIDs spelled apart stay paired.
        let old = guid(node.attr("id").unwrap_or_default());
        let new = match fresh.iter().find(|(from, _)| *from == old) {
            Some((_, new)) => new.clone(),
            None => {
                let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
                let new = mint_guid(
                    &[seed, b"/shape/".as_slice(), old.as_bytes()].concat(),
                    &refs,
                )?;
                taken.push(new.clone());
                fresh.push((old, new.clone()));
                new
            }
        };
        edits.push(xml::set_attribute(bytes, node, "id", &new));
    }
    if let Some(value) = creation_id {
        let at = slide_creation(tree).ok_or(EditRefusal::Missing("slide creation id"))?;
        edits.push(xml::set_attribute(
            bytes,
            &tree.nodes[at],
            "val",
            &value.to_string(),
        ));
    }
    if let Some(at) = comment_ext(tree) {
        edits.push((tree.nodes[at].span.clone(), Vec::new()));
    }
    xml::splice(bytes, edits)
}

/// The slide's `p14:creationId` element.
fn slide_creation(tree: &XmlTree) -> Option<usize> {
    let list = xml::path(tree, 0, &[(P, "cSld"), (P, "extLst")])?;
    tree.children(list)
        .find(|(_, node)| node.is(P, "ext") && node.attr("uri") == Some(SLIDE_CREATION_EXT))
        .and_then(|(at, _)| xml::child(tree, at, P14, "creationId"))
}

/// The slide's `p:ext` holding `p188:commentRel`.
fn comment_ext(tree: &XmlTree) -> Option<usize> {
    let list = xml::child(tree, 0, P, "extLst")?;
    tree.children(list)
        .find(|(_, node)| node.is(P, "ext") && node.attr("uri") == Some(COMMENT_EXT))
        .map(|(at, _)| at)
}

pub(super) fn duplicate(
    next: &mut Package,
    before: &DeckView,
    slide: &str,
    expected: [u8; 32],
    high_water: u32,
    seed: &[u8],
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let input = next.clone();
    let view = before
        .slides
        .iter()
        .find(|view| view.part == slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    if view.render_fingerprint != expected {
        return Err(EditRefusal::TargetChanged);
    }
    let lists = Lists::read(&input)?;
    let sld_id = lists
        .slides
        .iter()
        .map(|&(_, id)| id)
        .chain([high_water, SLIDE_IDS.start - 1])
        .max()
        .and_then(|high| high.checked_add(1))
        .filter(|id| SLIDE_IDS.contains(id))
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let creation_id = match view.creation_id {
        None => None,
        Some(_) => {
            let taken: Vec<u32> = before.slides.iter().filter_map(|s| s.creation_id).collect();
            Some(mint_creation_id(seed, &taken)?)
        }
    };
    let mut taken: Vec<String> = before
        .slides
        .iter()
        .flat_map(|s| {
            s.shapes
                .iter()
                .filter_map(|shape| shape.creation_id.clone())
        })
        .collect();
    let (bytes, tree) = xml::read(&input, slide)?;
    let content_type = declared_type(&input, slide)?.ok_or(EditRefusal::Missing("content type"))?;
    let copy = clone_name(&input, slide)?;
    next.add_part(
        &copy,
        &content_type,
        slide_copy(&bytes, &tree, creation_id, seed, &mut taken)?,
    )?;
    let mut cloner = Cloner {
        input: &input,
        source: slide,
        copy: &copy,
        cloned: Vec::new(),
        omitted: Vec::new(),
    };
    cloner.relationships(next, slide, &copy, Owner::Slide)?;
    let link = next.relate(&lists.part, &format!("{R}/slide"), &copy)?;

    // The new list entries go right after the source's.
    let links = input.relationships(&lists.part)?;
    let names_source = |node: &Node| {
        node.attr_ns(R, "id")
            .is_some_and(|id| links.iter().any(|rel| rel.id == id && rel.target == slide))
    };
    let mut entries = lists
        .slides
        .iter()
        .filter(|&&(at, id)| id == view.sld_id && names_source(&lists.tree.nodes[at]));
    let (Some(&(entry, _)), None) = (entries.next(), entries.next()) else {
        return Err(EditRefusal::AmbiguousAnchor(
            "the source's slide list entry",
        ));
    };
    let node = &lists.tree.nodes[entry];
    let attribute = relationship_attribute(node).ok_or(EditRefusal::Invalid("a slide id entry"))?;
    let id = sld_id.to_string();
    let at = node.span.end;
    let mut edits = vec![(
        at..at,
        copy_with(
            &lists.bytes,
            node,
            &[("id", id.as_str()), (attribute, link.as_str())],
        )?,
    )];
    let mut placed = lists
        .sections
        .iter()
        .flatten()
        .filter(|&&(_, id)| id == view.sld_id);
    match (placed.next(), placed.next()) {
        (Some(&(entry, _)), None) => {
            let node = &lists.tree.nodes[entry];
            let at = node.span.end;
            edits.push((
                at..at,
                copy_with(&lists.bytes, node, &[("id", id.as_str())])?,
            ));
        }
        (None, _) => {}
        (Some(_), Some(_)) => {
            return Err(EditRefusal::AmbiguousAnchor("the slide is in two sections"));
        }
    }
    next.replace_xml_part(&lists.part, xml::splice(&lists.bytes, edits)?)?;

    let mut effects = vec![Effect::SlideAdded {
        part: copy.clone(),
        sld_id,
        creation_id,
    }];
    effects.extend(cloner.cloned.iter().map(|(from, to)| Effect::PartCloned {
        from: from.clone(),
        to: to.clone(),
    }));
    effects.extend(cloner.omitted.iter().map(|id| Effect::CommentsOmitted {
        relationship: id.clone(),
    }));
    effects.extend(
        custom_shows(&lists, &names_source)
            .into_iter()
            .map(|show| Effect::NotInCustomShow { show }),
    );
    let cloned = cloner.cloned;
    Ok((
        Plan::Duplicated(Duplicate {
            clone: copy,
            sld_id,
            cloned,
        }),
        effects,
    ))
}

/// The custom shows that list the source slide.
fn custom_shows(lists: &Lists, names_source: &dyn Fn(&Node) -> bool) -> Vec<String> {
    let tree = &lists.tree;
    let Some(shows) = xml::child(tree, 0, P, "custShowLst") else {
        return Vec::new();
    };
    tree.children(shows)
        .filter(|(at, node)| {
            node.is(P, "custShow")
                && xml::child(tree, *at, P, "sldLst").is_some_and(|list| {
                    tree.children(list)
                        .any(|(_, entry)| entry.is(P, "sld") && names_source(entry))
                })
        })
        .map(|(_, node)| node.attr("name").unwrap_or_default().to_owned())
        .collect()
}

pub(super) fn reorder(
    next: &mut Package,
    before: &DeckView,
    order: &[u32],
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let current: Vec<u32> = before.slides.iter().map(|s| s.sld_id).collect();
    let mut sorted = current.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EditRefusal::AmbiguousAnchor("duplicate slide ids"));
    }
    let mut wanted = order.to_vec();
    wanted.sort_unstable();
    if wanted != sorted {
        return Err(EditRefusal::Invalid(
            "the order is not a permutation of the slide ids",
        ));
    }
    if order == current {
        return Err(EditRefusal::Invalid("the order is unchanged"));
    }
    let lists = Lists::read(next)?;
    if lists
        .slides
        .iter()
        .map(|&(_, id)| id)
        .ne(current.iter().copied())
    {
        return Err(EditRefusal::Invalid(
            "the slide list holds entries the view skips",
        ));
    }
    if !lists.sections.is_empty() {
        let mut sections = Vec::with_capacity(order.len());
        for &id in order {
            sections.push(
                lists
                    .section_of(id)
                    .ok_or(EditRefusal::ReorderUnsupported("a slide in no section"))?,
            );
        }
        if sections.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(EditRefusal::ReorderUnsupported(
                "the order splits a section or moves sections past each other",
            ));
        }
    }
    let element = |id: u32| {
        let (at, _) = lists.slides[current.iter().position(|&c| c == id).unwrap_or(0)];
        lists.bytes[lists.tree.nodes[at].span.clone()].to_vec()
    };
    let mut edits: Vec<xml::Splice> = lists
        .slides
        .iter()
        .zip(order)
        .map(|(&(at, _), &id)| (lists.tree.nodes[at].span.clone(), element(id)))
        .collect();
    for section in &lists.sections {
        let entry = |id: u32| {
            section
                .iter()
                .find(|&&(_, member)| member == id)
                .map(|&(at, _)| lists.bytes[lists.tree.nodes[at].span.clone()].to_vec())
                .unwrap_or_default()
        };
        let members = order
            .iter()
            .filter(|&&id| section.iter().any(|&(_, member)| member == id));
        for (&(at, _), &id) in section.iter().zip(members) {
            edits.push((lists.tree.nodes[at].span.clone(), entry(id)));
        }
    }
    next.replace_xml_part(&lists.part, xml::splice(&lists.bytes, edits)?)?;
    Ok((Plan::Reordered, Vec::new()))
}

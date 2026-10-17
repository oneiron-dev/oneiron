//! The PPTX body inside its Loro document, schema 1 (ARCH-0077, "One deck,
//! one document").
//!
//! Root `office` holds the kind and schema. Root `alloc` holds the import's
//! sequential identity floor (`next/<peer>`) and the native-id allocation
//! history (`slide/<peer>`, `shape/<part>/<peer>`) as max registers: each
//! group reads as the largest of its entries, a writer that raises a group
//! adds its own commit peer's entry and deletes the entries it read, so two
//! peers' concurrent raises join as their maximum, part by part.
//! Root `tree`, one LoroTree, holds the slides as its roots and their groups
//! and shapes below them; sibling position is the only order, and the model
//! root is implicit. Each tree node's meta map holds its model identity (`id`,
//! decimal, kept apart from the Loro handle), its kind, name, binding,
//! placeholder, its preset and payload, and one key per
//! geometry field, so concurrent writes of different fields merge. Root `texts` maps a text shape's identity to its
//! body: `order`, a movable list of paragraph identities, and `paras`, each
//! paragraph's level and one rich text whose run formatting rides as marks,
//! one mark key per run property, each written only where it changed.
//! Root `opaque` maps each opaque part to its BLAKE3. Root `log` is the
//! append-only stamped operation log, so concurrent calls' operations both
//! survive, and root `landed` lists every landed export's version and hash,
//! the last binding the deck. The deck's version counts both.
//!
//! [`sync_to`] is the one writer: it makes the document's deck equal a target
//! deck with the fewest container writes, so an edit read against an older
//! frontier merges with the head unit by unit.

use super::{invalid, live};
use crate::error::{Error, Result};
use loro::{
    Container, ExpandType, LoroDoc, LoroList, LoroMap, LoroMovableList, LoroText, LoroTree,
    LoroValue, StyleConfig, StyleConfigMap, TextDelta, TreeParentId, UpdateOptions,
    ValueOrContainer,
};
use oneiron_docedit::edit::transaction::IdMarks;
use oneiron_docedit::live::{
    DeckNode, DeckOp, GeometryProps, LiveDeck, LiveError, NodeId, NodeKind, Paragraph, Run,
    StampedOp, TextBody,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const OFFICE: &str = "office";
const ALLOC: &str = "alloc";
const TREE: &str = "tree";
const TEXTS: &str = "texts";
const OPAQUE: &str = "opaque";
const LOG: &str = "log";
const LANDED: &str = "landed";
const KIND: &str = "kind";
const SCHEMA_KEY: &str = "schema";
const SCHEMA: i64 = 1;
/// The `alloc` groups: the identity floor, the slide-id mark, and each slide
/// part's shape-id mark (`shape/<part>`).
const NEXT_NODE: &str = "next";
const SLIDE_MARK: &str = "slide";
const SHAPE_MARK: &str = "shape/";
const ID: &str = "id";
const NAME: &str = "name";
const BINDING: &str = "binding";
const PLACEHOLDER: &str = "placeholder";
const PRESET: &str = "preset";
const PAYLOAD: &str = "payload";
const OFFSET: &str = "offset";
const EXTENT: &str = "extent";
const ROTATION: &str = "rotation";
const FLIP_H: &str = "flip_h";
const FLIP_V: &str = "flip_v";
const ORDER: &str = "order";
const PARAS: &str = "paras";
const LEVEL: &str = "level";
const TEXT: &str = "text";
/// The run ordinal within its paragraph, which keeps adjacent runs of equal
/// formatting apart.
const RUN: &str = "run";
const BOLD: &str = "bold";
const ITALIC: &str = "italic";
const SIZE: &str = "size";
const LATIN: &str = "latin";
/// How every run mark meets an insertion at its edge: text typed at a run's
/// end joins that run and takes its formatting; text typed before a run's
/// start does not ("Define mark expansion at insertion positions"). Every
/// writer configures the same expansion.
const EXPAND: ExpandType = ExpandType::After;

/// The deck as its document holds it.
pub(super) struct Body {
    pub(super) deck: LiveDeck,
    pub(super) log: Vec<StampedOp>,
    /// The landed export the deck is bound to; `None` while it is bound to
    /// the imported source.
    pub(super) retained: Option<Retained>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) struct Retained {
    pub(super) version: u64,
    pub(super) hash: [u8; 32],
}

/// Write an imported deck as the body's first state.
pub(in crate::office_body) fn birth(doc: &LoroDoc, deck: &LiveDeck) -> Result<()> {
    let office = doc.get_map(OFFICE);
    office.insert(KIND, "pptx").map_err(loro)?;
    office.insert(SCHEMA_KEY, SCHEMA).map_err(loro)?;
    sync_to(doc, deck)
}

/// Fail closed on a document that no longer reads as a deck.
pub(in crate::office_body) fn validate(doc: &LoroDoc) -> Result<()> {
    read(doc).map(drop)
}

/// The deck the document holds. A merged state that breaks the deck's tree
/// rules, or names one node or paragraph twice, refuses: a converged state is
/// not necessarily a valid deck.
pub(super) fn read(doc: &LoroDoc) -> Result<Body> {
    let office = doc.get_map(OFFICE);
    if string(&office, KIND).as_deref() != Some("pptx") || int(&office, SCHEMA_KEY) != Some(SCHEMA)
    {
        return Err(invalid("not a schema-1 PPTX body"));
    }
    let alloc = allocation(&doc.get_map(ALLOC))?;
    let next_node = alloc
        .get(NEXT_NODE)
        .map(|group| group.max)
        .ok_or_else(|| invalid("deck body identity floor"))?;
    let mark = |max: u64| u32::try_from(max).map_err(|_| invalid("deck body id mark"));
    let mut id_marks = IdMarks {
        slide: alloc
            .get(SLIDE_MARK)
            .map_or(Ok(0), |group| mark(group.max))?,
        shapes: BTreeMap::new(),
    };
    for (group, held) in &alloc {
        if let Some(part) = group.strip_prefix(SHAPE_MARK) {
            id_marks.shapes.insert(part.to_owned(), mark(held.max)?);
        }
    }

    let mut nodes = BTreeMap::from([(NodeId(0), root())]);
    let tree = doc.get_tree(TREE);
    let mut stack = vec![(TreeParentId::Root, NodeId(0), NodeKind::Root)];
    while let Some((parent, parent_id, parent_kind)) = stack.pop() {
        for handle in tree.children(parent).unwrap_or_default() {
            let (id, node) = node_of(&tree.get_meta(handle).map_err(loro)?, parent_id)?;
            if !parent_kind.holds(node.kind) {
                return Err(live(LiveError::TreeShape(
                    "the merged deck puts a node under a parent that cannot hold it",
                )));
            }
            let kind = node.kind;
            if nodes.insert(id, node).is_some() {
                return Err(invalid("a deck node appears twice in the body"));
            }
            if let Some(found) = nodes.get_mut(&parent_id) {
                found.children.push(id);
            }
            stack.push((TreeParentId::Node(handle), id, kind));
        }
    }

    let mut texts = BTreeMap::new();
    let map = doc.get_map(TEXTS);
    for key in keys(&map) {
        let id = node_id(&key)?;
        // A body whose shape a concurrent edit removed is not part of the deck.
        if !nodes.contains_key(&id) {
            continue;
        }
        if let Some(entry) = child_map(&map, &key) {
            texts.insert(id, text_body(&entry)?);
        }
    }

    let mut opaque_parts = BTreeMap::new();
    let opaque = doc.get_map(OPAQUE);
    for part in keys(&opaque) {
        let hash = string(&opaque, &part)
            .and_then(|hex| blake3::Hash::from_hex(hex).ok())
            .ok_or_else(|| invalid("deck body opaque part hash"))?;
        opaque_parts.insert(part, *hash.as_bytes());
    }

    let log: Vec<StampedOp> = entries(&doc.get_list(LOG))?;
    let landed: Vec<Retained> = entries(&doc.get_list(LANDED))?;
    let version =
        u64::try_from(log.len() + landed.len()).map_err(|_| invalid("the deck log is too long"))?;
    Ok(Body {
        deck: LiveDeck {
            nodes,
            texts,
            opaque_parts,
            next_node,
            version,
            id_marks,
        },
        log,
        retained: landed.last().copied(),
    })
}

/// Make the document's deck equal `target` with the fewest container writes:
/// tree nodes created, moved or deleted only where they differ, meta keys,
/// paragraph lists and opaque hashes written only where they changed, and
/// paragraph text diffed, so concurrent edits of other units (another node,
/// field or paragraph, other characters of one paragraph) merge. The log and
/// the landed exports are appended apart.
pub(super) fn sync_to(doc: &LoroDoc, target: &LiveDeck) -> Result<()> {
    configure(doc);
    sync_alloc(doc, target)?;
    sync_tree(&doc.get_tree(TREE), target)?;
    sync_texts(&doc.get_map(TEXTS), target)?;
    let opaque = doc.get_map(OPAQUE);
    for part in keys(&opaque) {
        if !target.opaque_parts.contains_key(&part) {
            opaque.delete(&part).map_err(loro)?;
        }
    }
    for (part, hash) in &target.opaque_parts {
        put(
            &opaque,
            part,
            blake3::Hash::from(*hash).to_hex().to_string(),
        )?;
    }
    Ok(())
}

/// Append one call's stamped operations to the log.
pub(super) fn append_log(doc: &LoroDoc, ops: &[StampedOp]) -> Result<()> {
    let log = doc.get_list(LOG);
    for op in ops {
        log.push(encode(op)?).map_err(loro)?;
    }
    Ok(())
}

/// Record a landed export the deck now binds to.
pub(super) fn push_landed(doc: &LoroDoc, retained: &Retained) -> Result<()> {
    doc.get_list(LANDED).push(encode(retained)?).map_err(loro)
}

/// Opaque replacements read against `base`: a part another writer replaced
/// since then refuses, unless it holds the same replacement (equal hashes
/// agree; a winning map value does not resolve the conflict).
pub(super) fn admit(base: &LoroDoc, head: &LoroDoc, ops: &[DeckOp]) -> Result<()> {
    let (base, head) = (base.get_map(OPAQUE), head.get_map(OPAQUE));
    for op in ops {
        if let DeckOp::ReplaceOpaque {
            part, replacement, ..
        } = op
        {
            let held = string(&head, part);
            let wanted = blake3::Hash::from(*replacement).to_hex();
            if string(&base, part) != held && held.as_deref() != Some(wanted.as_str()) {
                return Err(invalid(
                    "the opaque part was replaced since the base; read the deck again",
                ));
            }
        }
    }
    Ok(())
}

/// One `alloc` group as read: its largest entry and every entry's key.
struct Held {
    max: u64,
    keys: Vec<String>,
}

/// Each `alloc` group's maximum, by group (`next`, `slide`, `shape/<part>`).
fn allocation(alloc: &LoroMap) -> Result<BTreeMap<String, Held>> {
    let mut groups: BTreeMap<String, Held> = BTreeMap::new();
    for key in keys(alloc) {
        let value = string(alloc, &key)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| invalid("deck body allocation entry"))?;
        let (group, _peer) = key
            .rsplit_once('/')
            .ok_or_else(|| invalid("deck body allocation entry"))?;
        let held = groups.entry(group.to_owned()).or_insert(Held {
            max: value,
            keys: Vec::new(),
        });
        held.max = held.max.max(value);
        held.keys.push(key);
    }
    Ok(groups)
}

/// Raise each `alloc` group to the target's value where the document holds
/// less: the commit peer's own entry takes the value and the entries read
/// are deleted, so an entry another peer adds concurrently survives and the
/// group still reads as the maximum of both. A group never lowers.
fn sync_alloc(doc: &LoroDoc, target: &LiveDeck) -> Result<()> {
    let alloc = doc.get_map(ALLOC);
    let held = allocation(&alloc)?;
    let peer = doc.peer_id();
    let mut wanted = vec![
        (NEXT_NODE.to_owned(), target.next_node),
        (SLIDE_MARK.to_owned(), u64::from(target.id_marks.slide)),
    ];
    for (part, mark) in &target.id_marks.shapes {
        wanted.push((format!("{SHAPE_MARK}{part}"), u64::from(*mark)));
    }
    for (group, value) in wanted {
        let read = held.get(&group);
        if read.is_some_and(|read| read.max >= value) {
            continue;
        }
        let own = format!("{group}/{peer}");
        for key in read.map(|read| read.keys.as_slice()).unwrap_or_default() {
            if *key != own {
                alloc.delete(key).map_err(loro)?;
            }
        }
        alloc.insert(&own, value.to_string()).map_err(loro)?;
    }
    Ok(())
}

fn sync_tree(tree: &LoroTree, target: &LiveDeck) -> Result<()> {
    tree.enable_fractional_index(0);
    let mut handles = BTreeMap::new();
    let mut stack = vec![TreeParentId::Root];
    while let Some(parent) = stack.pop() {
        for handle in tree.children(parent).unwrap_or_default() {
            handles.insert(identity(&tree.get_meta(handle).map_err(loro)?)?, handle);
            stack.push(TreeParentId::Node(handle));
        }
    }
    // Top down, each parent's children become the prefix of its sibling list
    // in target order: the first at index 0, each next right after the one
    // before. A parent is placed before its children, so no move makes a
    // cycle.
    let mut queue = VecDeque::from([NodeId(0)]);
    while let Some(parent) = queue.pop_front() {
        let place = match parent {
            NodeId(0) => TreeParentId::Root,
            _ => TreeParentId::Node(
                *handles
                    .get(&parent)
                    .ok_or_else(|| live(LiveError::UnknownNode))?,
            ),
        };
        let mut held = tree.children(place).unwrap_or_default();
        let children = &target
            .nodes
            .get(&parent)
            .ok_or_else(|| live(LiveError::UnknownNode))?
            .children;
        for (index, child) in children.iter().enumerate() {
            let handle = match handles.get(child) {
                Some(&handle) if held.get(index) == Some(&handle) => handle,
                Some(&handle) => {
                    match index {
                        0 => tree.mov_to(handle, place, 0),
                        _ => tree.mov_after(handle, held[index - 1]),
                    }
                    .map_err(loro)?;
                    held.retain(|other| *other != handle);
                    held.insert(index, handle);
                    handle
                }
                None => {
                    let handle = tree.create_at(place, index).map_err(loro)?;
                    handles.insert(*child, handle);
                    held.insert(index, handle);
                    handle
                }
            };
            let node = target
                .nodes
                .get(child)
                .ok_or_else(|| live(LiveError::UnknownNode))?;
            sync_meta(&tree.get_meta(handle).map_err(loro)?, *child, node)?;
            queue.push_back(*child);
        }
    }
    // Every node left outside the target heads a subtree of such nodes.
    let mut stack = vec![TreeParentId::Root];
    while let Some(parent) = stack.pop() {
        for handle in tree.children(parent).unwrap_or_default() {
            let id = identity(&tree.get_meta(handle).map_err(loro)?)?;
            if id != NodeId(0) && target.nodes.contains_key(&id) {
                stack.push(TreeParentId::Node(handle));
            } else {
                tree.delete(handle).map_err(loro)?;
            }
        }
    }
    Ok(())
}

fn sync_meta(meta: &LoroMap, id: NodeId, node: &DeckNode) -> Result<()> {
    put(meta, ID, id.0.to_string())?;
    put_json(meta, KIND, &node.kind)?;
    put_json(meta, NAME, &node.name)?;
    put_json(meta, BINDING, &node.binding)?;
    put_json(meta, PLACEHOLDER, &node.placeholder)?;
    put_json(meta, PRESET, &node.preset)?;
    put_json(meta, PAYLOAD, &node.payload)?;
    put_json(meta, OFFSET, &node.geometry.offset)?;
    put_json(meta, EXTENT, &node.geometry.extent)?;
    put_json(meta, ROTATION, &node.geometry.rotation)?;
    put_json(meta, FLIP_H, &node.geometry.flip_h)?;
    put_json(meta, FLIP_V, &node.geometry.flip_v)
}

fn sync_texts(map: &LoroMap, target: &LiveDeck) -> Result<()> {
    for key in keys(map) {
        if node_id(&key).map_or(true, |id| !target.texts.contains_key(&id)) {
            map.delete(&key).map_err(loro)?;
        }
    }
    for (id, body) in &target.texts {
        let entry = map.ensure_mergeable_map(&id.0.to_string()).map_err(loro)?;
        let order = entry.ensure_mergeable_movable_list(ORDER).map_err(loro)?;
        let paras = entry.ensure_mergeable_map(PARAS).map_err(loro)?;
        let wanted: Vec<String> = body
            .paragraphs
            .iter()
            .map(|paragraph| paragraph.id.0.to_string())
            .collect();
        let keep: BTreeSet<&str> = wanted.iter().map(String::as_str).collect();
        // Drop what the body no longer holds and any repeat, keeping the
        // first; what is left is placed in target order.
        let held = paragraph_ids(&order)?;
        for (index, id) in held.iter().enumerate().rev() {
            if !keep.contains(id.as_str()) || held[..index].contains(id) {
                order.delete(index, 1).map_err(loro)?;
            }
        }
        let mut held = paragraph_ids(&order)?;
        for (index, id) in wanted.iter().enumerate() {
            if held.get(index) == Some(id) {
                continue;
            }
            match held.iter().position(|other| other == id) {
                Some(from) => {
                    order.mov(from, index).map_err(loro)?;
                    let moved = held.remove(from);
                    held.insert(index, moved);
                }
                None => {
                    order.insert(index, id.as_str()).map_err(loro)?;
                    held.insert(index, id.clone());
                }
            }
        }
        for key in keys(&paras) {
            if !keep.contains(key.as_str()) {
                paras.delete(&key).map_err(loro)?;
            }
        }
        for (paragraph, key) in body.paragraphs.iter().zip(&wanted) {
            sync_paragraph(&paras.ensure_mergeable_map(key).map_err(loro)?, paragraph)?;
        }
    }
    Ok(())
}

/// One paragraph: its level, its text by diff, then each run property's mark
/// only over the characters whose held value differs from the target's, so
/// two writers' formatting of different properties or characters of one
/// paragraph both survive. A run holds at least one character.
fn sync_paragraph(para: &LoroMap, paragraph: &Paragraph) -> Result<()> {
    let level = i64::from(paragraph.level);
    if int(para, LEVEL) != Some(level) {
        para.insert(LEVEL, level).map_err(loro)?;
    }
    let text = para.ensure_mergeable_text(TEXT).map_err(loro)?;
    let runs: Vec<&Run> = paragraph
        .runs
        .iter()
        .filter(|run| !run.text.is_empty())
        .collect();
    let plain: String = runs.iter().map(|run| run.text.as_str()).collect();
    if text.to_string() != plain {
        text.update(&plain, UpdateOptions::default())
            .map_err(|_| invalid("deck paragraph text update"))?;
    }
    let mut wanted = Vec::new();
    for (ordinal, run) in runs.iter().enumerate() {
        let marks = RunMarks::of(
            Some(i64::try_from(ordinal).map_err(|_| invalid("deck paragraph runs"))?),
            run,
        );
        wanted.extend(std::iter::repeat_n(marks, run.text.chars().count()));
    }
    let mut held = Vec::new();
    for (len, marks) in marked(&text)? {
        held.extend(std::iter::repeat_n(marks, len));
    }
    if held == wanted {
        return Ok(());
    }
    for key in [RUN, BOLD, ITALIC, SIZE, LATIN] {
        let mut at = 0;
        while at < wanted.len() {
            let value = wanted[at].value(key);
            if held.get(at).map(|held| held.value(key)) == Some(value.clone()) {
                at += 1;
                continue;
            }
            let start = at;
            while at < wanted.len()
                && wanted[at].value(key) == value
                && held.get(at).map(|held| held.value(key)) != Some(value.clone())
            {
                at += 1;
            }
            mark(&text, start..at, key, value)?;
        }
    }
    Ok(())
}

/// One character's run marks: its run ordinal and formatting.
#[derive(Clone, PartialEq)]
struct RunMarks {
    ordinal: Option<i64>,
    bold: Option<bool>,
    italic: Option<bool>,
    size: Option<u32>,
    latin: Option<String>,
}

impl RunMarks {
    fn of(ordinal: Option<i64>, run: &Run) -> Self {
        Self {
            ordinal,
            bold: run.bold,
            italic: run.italic,
            size: run.size,
            latin: run.latin.clone(),
        }
    }

    /// The mark value `key` takes; `None` is no mark.
    fn value(&self, key: &str) -> Option<LoroValue> {
        match key {
            RUN => self.ordinal.map(LoroValue::from),
            BOLD => self.bold.map(LoroValue::from),
            ITALIC => self.italic.map(LoroValue::from),
            SIZE => self.size.map(|size| i64::from(size).into()),
            _ => self.latin.as_deref().map(LoroValue::from),
        }
    }
}

fn mark(
    text: &LoroText,
    range: std::ops::Range<usize>,
    key: &str,
    value: Option<LoroValue>,
) -> Result<()> {
    match value {
        Some(value) => text.mark(range, key, value),
        None => text.unmark(range, key),
    }
    .map_err(loro)
}

/// Every run mark expands after an insertion; see [`EXPAND`].
fn configure(doc: &LoroDoc) {
    let mut styles = StyleConfigMap::new();
    for key in [RUN, BOLD, ITALIC, SIZE, LATIN] {
        styles.insert(key.into(), StyleConfig { expand: EXPAND });
    }
    doc.config_text_style(styles);
}

fn root() -> DeckNode {
    DeckNode {
        kind: NodeKind::Root,
        parent: None,
        children: Vec::new(),
        name: None,
        binding: None,
        geometry: GeometryProps::default(),
        placeholder: None,
        preset: None,
        payload: None,
    }
}

fn node_of(meta: &LoroMap, parent: NodeId) -> Result<(NodeId, DeckNode)> {
    Ok((
        identity(meta)?,
        DeckNode {
            kind: json(meta, KIND)?,
            parent: Some(parent),
            children: Vec::new(),
            name: json(meta, NAME)?,
            binding: json(meta, BINDING)?,
            geometry: GeometryProps {
                offset: json(meta, OFFSET)?,
                extent: json(meta, EXTENT)?,
                rotation: json(meta, ROTATION)?,
                flip_h: json(meta, FLIP_H)?,
                flip_v: json(meta, FLIP_V)?,
            },
            placeholder: json(meta, PLACEHOLDER)?,
            preset: json(meta, PRESET)?,
            payload: json(meta, PAYLOAD)?,
        },
    ))
}

/// A tree node's model identity; the implicit root is never a tree node.
fn identity(meta: &LoroMap) -> Result<NodeId> {
    string(meta, ID)
        .ok_or_else(|| invalid("deck node identity"))
        .and_then(|id| node_id(&id))
        .and_then(|id| match id {
            NodeId(0) => Err(invalid("deck node identity")),
            id => Ok(id),
        })
}

fn node_id(key: &str) -> Result<NodeId> {
    key.parse()
        .map(NodeId)
        .map_err(|_| invalid("deck node identity"))
}

fn text_body(entry: &LoroMap) -> Result<TextBody> {
    let (Some(order), Some(paras)) = (child_list(entry, ORDER), child_map(entry, PARAS)) else {
        return Err(invalid("deck text body entry"));
    };
    let mut seen = BTreeSet::new();
    let mut paragraphs = Vec::new();
    for key in paragraph_ids(&order)? {
        if !seen.insert(key.clone()) {
            return Err(invalid("a paragraph appears twice in its body"));
        }
        let para = child_map(&paras, &key).ok_or_else(|| invalid("deck paragraph entry"))?;
        let text = match para.get(TEXT) {
            Some(ValueOrContainer::Container(Container::Text(text))) => text,
            _ => return Err(invalid("deck paragraph text")),
        };
        paragraphs.push(Paragraph {
            id: node_id(&key)?,
            level: int(&para, LEVEL)
                .and_then(|level| u8::try_from(level).ok())
                .ok_or_else(|| invalid("deck paragraph level"))?,
            runs: runs_of(&text)?,
        });
    }
    Ok(TextBody { paragraphs })
}

/// The runs a paragraph's text reads as: one per stretch of one run ordinal
/// and one formatting.
fn runs_of(text: &LoroText) -> Result<Vec<Run>> {
    let mut runs: Vec<(RunMarks, Run)> = Vec::new();
    for (insert, marks) in stretches(text)? {
        match runs.last_mut() {
            Some((last, held)) if *last == marks => held.text.push_str(&insert),
            _ => runs.push((
                marks.clone(),
                Run {
                    text: insert,
                    bold: marks.bold,
                    italic: marks.italic,
                    size: marks.size,
                    latin: marks.latin,
                },
            )),
        }
    }
    Ok(runs.into_iter().map(|(_, run)| run).collect())
}

/// The text's marked stretches, each with its length in characters.
fn marked(text: &LoroText) -> Result<Vec<(usize, RunMarks)>> {
    Ok(stretches(text)?
        .into_iter()
        .map(|(insert, marks)| (insert.chars().count(), marks))
        .collect())
}

/// The text's delta stretches with the run marks each carries.
fn stretches(text: &LoroText) -> Result<Vec<(String, RunMarks)>> {
    let mut out = Vec::new();
    for delta in text.to_delta() {
        let TextDelta::Insert { insert, attributes } = delta else {
            continue;
        };
        let marks = attributes.unwrap_or_default();
        out.push((
            insert,
            RunMarks {
                ordinal: match marks.get(RUN) {
                    Some(LoroValue::I64(ordinal)) => Some(*ordinal),
                    _ => None,
                },
                bold: flag(marks.get(BOLD))?,
                italic: flag(marks.get(ITALIC))?,
                size: match marks.get(SIZE) {
                    None | Some(LoroValue::Null) => None,
                    Some(LoroValue::I64(size)) => {
                        Some(u32::try_from(*size).map_err(|_| invalid("deck run size mark"))?)
                    }
                    Some(_) => return Err(invalid("deck run size mark")),
                },
                latin: match marks.get(LATIN) {
                    None | Some(LoroValue::Null) => None,
                    Some(LoroValue::String(font)) => Some(font.to_string()),
                    Some(_) => return Err(invalid("deck run font mark")),
                },
            },
        ));
    }
    Ok(out)
}

fn flag(value: Option<&LoroValue>) -> Result<Option<bool>> {
    match value {
        None | Some(LoroValue::Null) => Ok(None),
        Some(LoroValue::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid("deck run flag mark")),
    }
}

fn paragraph_ids(order: &LoroMovableList) -> Result<Vec<String>> {
    (0..order.len())
        .map(|index| match order.get(index) {
            Some(ValueOrContainer::Value(LoroValue::String(id))) => Ok(id.to_string()),
            _ => Err(invalid("deck paragraph order entry")),
        })
        .collect()
}

/// A JSON list's entries, in list order.
fn entries<T: DeserializeOwned>(list: &LoroList) -> Result<Vec<T>> {
    (0..list.len())
        .map(|index| match list.get(index) {
            Some(ValueOrContainer::Value(LoroValue::String(entry))) => {
                serde_json::from_str(&entry).map_err(|_| invalid("deck body list entry"))
            }
            _ => Err(invalid("deck body list entry")),
        })
        .collect()
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| invalid("deck body encoding"))
}

fn keys(map: &LoroMap) -> Vec<String> {
    map.keys().map(|key| key.to_string()).collect()
}

fn child_map(map: &LoroMap, key: &str) -> Option<LoroMap> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Map(child)) => Some(child),
        _ => None,
    }
}

fn child_list(map: &LoroMap, key: &str) -> Option<LoroMovableList> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::MovableList(child)) => Some(child),
        _ => None,
    }
}

fn string(map: &LoroMap, key: &str) -> Option<String> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::String(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn int(map: &LoroMap, key: &str) -> Option<i64> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::I64(value)) => Some(value),
        _ => None,
    }
}

/// A JSON-encoded value; every key is written whole, so a missing one is a
/// malformed body.
fn json<T: DeserializeOwned>(map: &LoroMap, key: &str) -> Result<T> {
    string(map, key)
        .and_then(|value| serde_json::from_str(&value).ok())
        .ok_or_else(|| invalid("deck body value"))
}

/// Write `value` under `key` unless it is already there.
fn put(map: &LoroMap, key: &str, value: String) -> Result<()> {
    if string(map, key).as_deref() != Some(value.as_str()) {
        map.insert(key, value).map_err(loro)?;
    }
    Ok(())
}

fn put_json<T: Serialize>(map: &LoroMap, key: &str, value: &T) -> Result<()> {
    put(map, key, encode(value)?)
}

fn loro(_: loro::LoroError) -> Error {
    invalid("deck body document operation")
}

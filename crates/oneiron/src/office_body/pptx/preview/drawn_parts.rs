//! The parts of a deck's retained package a preview's asked slides draw,
//! and the keys their marks name (OF-510, FIX 10453). A key the lift marked
//! in a ZIP entry of the package, or in an opaque part the deck pins, holds
//! the drawing back only when that part is one the asked slides draw: each
//! slide's part, the part of each node on it, each held picture or OLE
//! preview it shows, and every part their relationships reach, each with
//! its relationship part. A marked entry is mapped to its part by its place
//! in the central directory, the place the scan that marked it walked, and
//! a key in the package's own bytes by the entry whose bytes hold it. A key
//! no entry holds, a slide the deck was not imported with, a slide part the
//! package does not hold, or a package or relationship part that does not
//! read counts every part, as a preview did before.
//!
//! The same asked slides map to the nodes they draw for the body's texts
//! and its live-born pictures (FIX 12234): a text or picture no asked slide
//! draws withholds nothing, and where the mapping cannot tell the caller
//! counts every text and picture as before.

use std::collections::BTreeSet;
use std::io::Cursor;

use heed::RoTxn;
use oneiron_docedit::edit::transaction::AssetRef;
use oneiron_docedit::live::{LiveDeck, NodeId, NodePayload};
use oneiron_docedit::retained_opc::{Package, rels_name};
use zip::ZipArchive;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{MaskedFile, MemberStep, masked_file_in_txn};
use crate::store::Store;

/// The marks of the package a preview draws over and of the deck's opaque
/// parts, read in the snapshot the deck is.
pub(super) struct PackageMarks {
    package: Option<MaskedFile>,
    /// Each marked opaque part, by its name.
    parts: Vec<(String, MaskedFile)>,
}

impl PackageMarks {
    /// The marks of the package whose bytes hash to `package` and of each
    /// opaque part `deck` pins, read in `txn`.
    pub(super) fn read_in_txn(
        store: &Store,
        txn: &RoTxn<'_>,
        package: &[u8; 32],
        deck: &LiveDeck,
    ) -> Result<Self> {
        let mut parts = Vec::new();
        for (name, hash) in &deck.opaque_parts {
            if let Some(mark) = masked_file_in_txn(store, txn, hash)? {
                parts.push((name.clone(), mark));
            }
        }
        Ok(Self {
            package: masked_file_in_txn(store, txn, package)?,
            parts,
        })
    }

    /// The custody records these marks name in the parts `slides` of `deck`
    /// draw, `package` read from `bytes`, the bytes the package mark is of.
    pub(super) fn drawn_keys(
        &self,
        deck: &LiveDeck,
        slides: &[u64],
        package: &Package,
        bytes: &[u8],
    ) -> Vec<EntityId> {
        if self.package.is_none() && self.parts.is_empty() {
            return Vec::new();
        }
        let drawn = drawn_parts(deck, slides, package);
        let counts = |part: &str| drawn.as_ref().is_none_or(|drawn| drawn.contains(part));
        let mut keys = Vec::new();
        for (name, mark) in &self.parts {
            if counts(name.as_str()) {
                keys.extend(every_key(mark));
            }
        }
        let Some(mark) = &self.package else {
            return keys;
        };
        let Some(entries) = drawn.is_some().then(|| zip_entries(bytes)).flatten() else {
            keys.extend(every_key(mark));
            return keys;
        };
        let named = |entry: Option<&(String, u64, u64)>| {
            entry.is_none_or(|(name, ..)| counts(name.as_str()))
        };
        for key in &mark.keys {
            let entry = entries
                .iter()
                .find(|(_, start, end)| *start <= key.start && key.end <= *end);
            if named(entry) {
                keys.push(key.custody);
            }
        }
        for member in &mark.members {
            let entry = match member.path.first() {
                Some(MemberStep::Zip { entry }) => {
                    usize::try_from(*entry).ok().and_then(|at| entries.get(at))
                }
                _ => None,
            };
            if named(entry) {
                keys.extend(member.keys.iter().map(|key| key.custody));
            }
        }
        keys
    }
}

/// Every custody record `mark` names, a key in a member included.
fn every_key(mark: &MaskedFile) -> impl Iterator<Item = EntityId> + '_ {
    mark.keys
        .iter()
        .chain(mark.members.iter().flat_map(|member| member.keys.iter()))
        .map(|key| key.custody)
}

/// The asked `slides` of `deck` and every node on them, 1-based in its
/// order; `None` when the mapping cannot tell (an asked slide the deck does
/// not hold, or one born live with no binding to map it by), so the caller
/// counts every text and picture as before (FIX 12234).
pub(super) fn drawn_nodes(deck: &LiveDeck, slides: &[u64]) -> Option<BTreeSet<NodeId>> {
    let order = &deck.nodes.get(&NodeId(0))?.children;
    let mut drawn = BTreeSet::new();
    for &slide in slides {
        let at = usize::try_from(slide.checked_sub(1)?).ok()?;
        let id = *order.get(at)?;
        deck.nodes.get(&id)?.binding.as_ref()?;
        drawn.insert(id);
        drawn.extend(deck.descendants(id));
    }
    Some(drawn)
}

/// Every string the nodes `drawn` of `deck` hold, as their JSON shows them:
/// each node's fields and its text body (FIX 12234).
pub(super) fn drawn_strings(deck: &LiveDeck, drawn: &BTreeSet<NodeId>) -> Vec<String> {
    let mut out = Vec::new();
    for id in drawn {
        if let Some(node) = deck.nodes.get(id)
            && let Ok(value) = serde_json::to_value(node)
        {
            strings_of(&value, &mut out);
        }
        if let Some(body) = deck.texts.get(id)
            && let Ok(value) = serde_json::to_value(body)
        {
            strings_of(&value, &mut out);
        }
    }
    out
}

/// Every live-born picture the nodes `drawn` of `deck` name, each once
/// (FIX 12234).
pub(super) fn drawn_pictures(deck: &LiveDeck, drawn: &BTreeSet<NodeId>) -> Vec<AssetRef> {
    let mut out = Vec::new();
    for id in drawn {
        if let Some(node) = deck.nodes.get(id)
            && let Some(image) = node.payload.as_ref().and_then(NodePayload::picture)
            && !out.contains(image)
        {
            out.push(image.clone());
        }
    }
    out
}

/// Every string `value` holds, in document order.
fn strings_of(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                strings_of(item, out);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                strings_of(item, out);
            }
        }
        _ => {}
    }
}

/// The parts the asked `slides` of `deck` draw, 1-based in its order, as
/// `package` names them; `None` when every part counts.
pub(super) fn drawn_parts(
    deck: &LiveDeck,
    slides: &[u64],
    package: &Package,
) -> Option<BTreeSet<String>> {
    let held: BTreeSet<&str> = package.names().collect();
    let order = &deck.nodes.get(&NodeId(0))?.children;
    let mut queue = Vec::new();
    for &slide in slides {
        let at = usize::try_from(slide.checked_sub(1)?).ok()?;
        let id = *order.get(at)?;
        let part = &deck.nodes.get(&id)?.binding.as_ref()?.slide_part;
        if !held.contains(part.as_str()) {
            return None;
        }
        queue.push(part.clone());
        for node in deck.descendants(id).iter().filter_map(|id| deck.nodes.get(id)) {
            // A node moved here keeps the part it was read from.
            if let Some(binding) = &node.binding {
                queue.push(binding.slide_part.clone());
            }
            if let Some(
                NodePayload::HeldPicture { media }
                | NodePayload::Ole {
                    preview: Some(media),
                    ..
                },
            ) = &node.payload
            {
                queue.push(media.part.clone());
            }
        }
    }
    let mut drawn = BTreeSet::new();
    while let Some(part) = queue.pop() {
        if drawn.contains(&part) || !held.contains(part.as_str()) {
            continue;
        }
        for relationship in package.relationships(&part).ok()? {
            if !relationship.external {
                queue.push(relationship.target);
            }
        }
        drawn.insert(rels_name(&part));
        drawn.insert(part);
    }
    Some(drawn)
}

/// Each entry of the ZIP archive `bytes`, in central-directory order: its
/// name and the bytes its local header and data cover. `None` when the
/// archive does not read.
fn zip_entries(bytes: &[u8]) -> Option<Vec<(String, u64, u64)>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).ok()?;
    (0..archive.len())
        .map(|index| {
            let entry = archive.by_index_raw(index).ok()?;
            let end = entry.data_start().saturating_add(entry.compressed_size());
            Some((entry.name().to_owned(), entry.header_start(), end))
        })
        .collect()
}

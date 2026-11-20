//! Importing a retained package into the live model (`LiveDeck::import`),
//! and a retained shape's own geometry and text body as the live model
//! holds them.

use super::{
    DeckNode, GeometryProps, LiveDeck, NodeBinding, NodeId, NodeKind, NodePayload, Paragraph, Run,
    TextBody,
};
use crate::deck::{DeckView, ShapeKind, ShapeView, TextView};
use crate::edit::{BREAK, IdMarks};
use crate::live::{LiveError, held};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

impl LiveDeck {
    /// Import a retained package into the live model. Authorship of every
    /// imported node is unknown by construction.
    pub fn import(package: &Package) -> Result<Self, LiveError> {
        let view = DeckView::read(package)?;
        let mut deck = Self {
            nodes: BTreeMap::new(),
            texts: BTreeMap::new(),
            opaque_parts: BTreeMap::new(),
            next_node: 1,
            version: 0,
            id_marks: IdMarks::of_deck(&view),
        };
        deck.nodes.insert(
            NodeId(0),
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
            },
        );
        let slide_parts: BTreeSet<&str> = view
            .slides
            .iter()
            .map(|slide| slide.part.as_str())
            .collect();
        for slide in &view.slides {
            let slide_id = deck.mint();
            deck.nodes.insert(
                slide_id,
                DeckNode {
                    kind: NodeKind::Slide,
                    parent: Some(NodeId(0)),
                    children: Vec::new(),
                    name: None,
                    binding: Some(NodeBinding {
                        slide_part: slide.part.clone(),
                        native_id: Some(slide.sld_id),
                        creation_id: slide.creation_id.map(|id| id.to_string()),
                        fingerprint: slide.content_fingerprint,
                        table: None,
                        series: None,
                    }),
                    geometry: GeometryProps::default(),
                    placeholder: None,
                    preset: None,
                    payload: None,
                },
            );
            deck.nodes
                .get_mut(&NodeId(0))
                .expect("root inserted above")
                .children
                .push(slide_id);
            // First pass mints every shape identity in document order; the
            // second wires parents from each shape's group path.
            let mut ids: Vec<NodeId> = Vec::with_capacity(slide.shapes.len());
            let tree = held::slide_tree(package, &slide.part)?;
            for shape in &slide.shapes {
                let id = deck.mint();
                ids.push(id);
                let geometry = geometry_of(shape);
                deck.nodes.insert(
                    id,
                    DeckNode {
                        kind: match shape.kind {
                            ShapeKind::Shape => NodeKind::Shape,
                            ShapeKind::Picture => NodeKind::Picture,
                            ShapeKind::GraphicFrame => NodeKind::GraphicFrame,
                            ShapeKind::Connector => NodeKind::Connector,
                            ShapeKind::Group => NodeKind::Group,
                        },
                        parent: Some(slide_id),
                        children: Vec::new(),
                        name: shape.name.clone(),
                        binding: Some(NodeBinding {
                            slide_part: slide.part.clone(),
                            native_id: shape.id,
                            creation_id: shape.creation_id.clone(),
                            fingerprint: shape.content_fingerprint,
                            table: None,
                            series: None,
                        }),
                        geometry,
                        placeholder: shape
                            .placeholder
                            .as_ref()
                            .map(|ph| (ph.kind.clone(), ph.idx)),
                        preset: None,
                        payload: None,
                    },
                );
                if let Some(text) = &shape.text {
                    let body = text_body(text, &tree, || deck.mint());
                    deck.texts.insert(id, body);
                }
            }
            for (index, shape) in slide.shapes.iter().enumerate() {
                let parent = shape
                    .group_path
                    .last()
                    .map_or(slide_id, |group| ids[*group]);
                let id = ids[index];
                deck.nodes
                    .get_mut(&id)
                    .expect("shape inserted above")
                    .parent = Some(parent);
                deck.nodes
                    .get_mut(&parent)
                    .expect("parent inserted above")
                    .children
                    .push(id);
            }
            // Third, what each element is written as, glue by live node.
            let native: BTreeMap<u32, NodeId> = slide
                .shapes
                .iter()
                .zip(&ids)
                .filter_map(|(shape, id)| Some((shape.id?, *id)))
                .collect();
            // A table's rows and columns, and a chart's series, are minted
            // once, here, in retained order, and bound to the coordinates
            // its XML holds them at.
            for (shape, id) in slide.shapes.iter().zip(&ids) {
                let (mut payload, table) = match held::table::import(&tree, shape, || deck.mint()) {
                    Some((body, binding)) => (Some(NodePayload::Table(body)), Some(binding)),
                    None => (
                        held::payload(package, &slide.part, &tree, shape, |at| {
                            native.get(&at).copied()
                        })?,
                        None,
                    ),
                };
                let special = held::chart_evidence(package, &slide.part, &tree, shape.node.index);
                let series = held::bind(&mut payload, || deck.mint(), &special);
                let node = deck.nodes.get_mut(id).expect("shape inserted above");
                node.preset = held::shape_preset(&tree, shape);
                node.payload = payload;
                if let Some(binding) = &mut node.binding {
                    binding.table = table;
                    binding.series = series;
                }
            }
        }
        for name in package.names() {
            if slide_parts.contains(name) {
                continue;
            }
            if let Some(bytes) = package.part(name)? {
                deck.opaque_parts
                    .insert(name.to_owned(), *blake3::hash(&bytes).as_bytes());
            }
        }
        Ok(deck)
    }
}

/// A retained shape's own geometry, as the live model holds it.
pub(crate) fn geometry_of(shape: &ShapeView) -> GeometryProps {
    GeometryProps {
        offset: own(&shape.geometry.offset),
        extent: own(&shape.geometry.extent),
        rotation: own(&shape.geometry.rotation),
        flip_h: own(&shape.geometry.flip_h),
        flip_v: own(&shape.geometry.flip_v),
    }
}

/// A retained text body as the live model holds it, paragraph identities
/// drawn from `mint`. `tree` is the slide the body is read from: each soft
/// break (`a:br`) in it is a run of its own holding one U+000B, as the text
/// mapping counts it. A break declares no property, so its `a:rPr` stays
/// as written.
pub(crate) fn text_body(
    text: &TextView,
    tree: &XmlTree,
    mut mint: impl FnMut() -> NodeId,
) -> TextBody {
    TextBody {
        paragraphs: text
            .paragraphs
            .iter()
            .map(|paragraph| {
                let id = mint();
                let mut breaks = crate::deck::soft_breaks(tree, paragraph.node.index)
                    .into_iter()
                    .peekable();
                let mut runs = Vec::with_capacity(paragraph.runs.len());
                for (at, run) in paragraph.runs.iter().enumerate() {
                    while breaks.next_if_eq(&at).is_some() {
                        runs.push(soft_break());
                    }
                    runs.push(Run {
                        text: run.text.clone(),
                        bold: run.bold.value,
                        italic: run.italic.value,
                        size: run.size.value,
                        latin: run.latin.value.as_ref().map(|font| font.typeface.clone()),
                    });
                }
                runs.extend(breaks.map(|_| soft_break()));
                Paragraph {
                    id,
                    level: paragraph.level.value.unwrap_or(0),
                    runs,
                }
            })
            .collect(),
    }
}

/// A soft break in live text: one U+000B, declaring no property.
fn soft_break() -> Run {
    Run {
        text: BREAK.to_string(),
        bold: None,
        italic: None,
        size: None,
        latin: None,
    }
}

/// An effective value the target element itself holds; inherited values are
/// never materialised into the live model.
fn own<T: Clone>(value: &crate::deck::Value<T>) -> Option<T> {
    if value.inherited {
        None
    } else {
        value.value.clone()
    }
}

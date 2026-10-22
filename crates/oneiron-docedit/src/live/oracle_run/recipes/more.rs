//! The step 2 mutations FIX 5670 adds, so the Office gate says how
//! PowerPoint opens each: Edit Points, a ragged table padded, a live-born
//! SmartArt and a moved node of a held one (its presentation points and
//! presParOf links stay from its old place until PowerPoint lays it out),
//! a live-born picture of an image the deck holds, and live-born charts over
//! two-level categories and over one series' own (D9a). Each keeps its
//! candidate and evidence like every other mutation.

use super::super::edits::{Ids, Scope, Subject, add, frame};
use super::super::record::{OfficeCheck, Res};
use super::super::spec::Recipe;
use super::{Plan, markup, table_of};
use crate::edit::{Digest, Preset};
use crate::live::{
    ChartCategories, ChartCategory, ChartKind, ChartSeries, ChartSource, Coord, DeckOp, GeomPath,
    HeldMedia, NodeId, NodeKind, NodePayload, PathCommand, PathPoint, SmartArtNode,
};

/// The image extensions a picture shows (the projector's own list).
const IMAGES: &[&str] = &[
    "png", "jpg", "jpeg", "jpe", "jfif", "gif", "bmp", "tif", "tiff", "emf", "wmf", "svg", "webp",
];

/// The live-born SmartArt's outline: two top-level nodes and a child.
const OUTLINE: [(&str, u32); 3] = [("Plan", 0), ("Build", 1), ("Ship", 0)];

/// This module's mutations; `None` for the others.
pub(super) fn plan(recipe: Recipe, subject: &Subject<'_>, ids: &mut Ids) -> Res<Option<Plan>> {
    let (s, t) = (subject.anchor.slide, subject.anchor.shape);
    let deck = &subject.deck.deck;
    let place = |n: NodeId| DeckOp::SetGeometry {
        node: n,
        geometry: frame(914_400, 3_657_600, 3_657_600, 1_097_280),
    };
    Ok(Some(match recipe {
        Recipe::EditPoints => {
            let at = |x: i64, y: i64| PathPoint {
                x: Coord::Value(x),
                y: Coord::Value(y),
            };
            let paths = vec![GeomPath {
                w: Some(100),
                h: Some(100),
                fill: None,
                stroke: None,
                extrusion_ok: None,
                commands: vec![
                    PathCommand::MoveTo { to: at(0, 0) },
                    PathCommand::LineTo { to: at(100, 0) },
                    PathCommand::LineTo { to: at(50, 100) },
                    PathCommand::Close,
                ],
            }];
            Plan::of(
                vec![DeckOp::SetPayload {
                    node: t,
                    payload: NodePayload::CustomGeometry { paths },
                }],
                Scope::SLIDE,
                vec![markup("custGeom>")],
            )
        }
        Recipe::RaggedTable => {
            let n = ids.mint();
            Plan::of(
                vec![
                    add(
                        n,
                        s,
                        NodeKind::GraphicFrame,
                        "Ragged table",
                        None,
                        Some(NodePayload::Table(table_of(&[
                            &["Region", "Units", "Note"],
                            &["North", "12"],
                            &["South"],
                        ]))),
                    ),
                    place(n),
                ],
                Scope::SLIDE,
                vec![
                    OfficeCheck::Text {
                        slide: 1,
                        contains: "Note".to_owned(),
                    },
                    OfficeCheck::Text {
                        slide: 1,
                        contains: "South".to_owned(),
                    },
                    markup("a:tbl>"),
                ],
            )
        }
        Recipe::SmartArtBirth => {
            let n = ids.mint();
            Plan::of(smart_art(n, s), Scope::RELATED, vec![markup("relIds")])
        }
        Recipe::SmartArtRestructure => {
            let (art, nodes) = held_smart_art(subject)?;
            let mut moved = nodes.clone();
            let last = moved.pop().ok_or("the held SmartArt has no node")?;
            moved.insert(0, last);
            Plan::of(
                vec![DeckOp::SetPayload {
                    node: art,
                    payload: NodePayload::SmartArt { nodes: moved },
                }],
                Scope::HELD,
                vec![markup("relIds")],
            )
        }
        Recipe::HeldPictureBirth => {
            let (part, hash) = deck
                .opaque_parts
                .iter()
                .find(|(part, _)| {
                    part.rsplit_once('.').is_some_and(|(_, ext)| {
                        IMAGES.iter().any(|known| ext.eq_ignore_ascii_case(known))
                    })
                })
                .ok_or("the deck holds no image part")?;
            let n = ids.mint();
            Plan::of(
                vec![
                    add(
                        n,
                        s,
                        NodeKind::Picture,
                        "Held picture",
                        None,
                        Some(NodePayload::HeldPicture {
                            media: HeldMedia {
                                part: part.clone(),
                                hash: Digest(*hash),
                            },
                        }),
                    ),
                    place(n),
                ],
                Scope::RELATED,
                vec![markup("p:pic>")],
            )
        }
        Recipe::MultiLevelCategories => {
            let n = ids.mint();
            let point = |leaf: &str, group: &str| ChartCategory {
                id: None,
                levels: vec![Some(leaf.to_owned()), Some(group.to_owned())],
            };
            let categories = ChartCategories {
                level_count: 2,
                points: vec![
                    point("Q1", "H1"),
                    point("Q2", "H1"),
                    point("Q3", "H2"),
                    point("Q4", "H2"),
                ],
            };
            Plan::of(
                vec![
                    add(
                        n,
                        s,
                        NodeKind::GraphicFrame,
                        "Two-level chart",
                        None,
                        Some(chart(categories, None)),
                    ),
                    place(n),
                ],
                Scope::RELATED,
                vec![markup("c:chart ")],
            )
        }
        Recipe::PerSeriesCategories => {
            let n = ids.mint();
            let own = ChartCategories::flat(["North", "South", "East", "West"]);
            Plan::of(
                vec![
                    add(
                        n,
                        s,
                        NodeKind::GraphicFrame,
                        "Own-categories chart",
                        None,
                        Some(chart(
                            ChartCategories::flat(["Q1", "Q2", "Q3", "Q4"]),
                            Some(own),
                        )),
                    ),
                    place(n),
                ],
                Scope::RELATED,
                vec![markup("c:chart ")],
            )
        }
        _ => return Ok(None),
    }))
}

/// The stage a mutation needs the deck to have taken first, exported and
/// imported again so what it adds is held: `None` for most.
pub(in crate::live::oracle_run) fn stage(
    recipe: Recipe,
    subject: &Subject<'_>,
    ids: &mut Ids,
) -> Option<Vec<DeckOp>> {
    match recipe {
        Recipe::SmartArtRestructure => Some(smart_art(ids.mint(), subject.anchor.slide)),
        _ => None,
    }
}

/// A live-born SmartArt of [`OUTLINE`] on slide `s`.
fn smart_art(n: NodeId, s: NodeId) -> Vec<DeckOp> {
    let nodes = OUTLINE
        .iter()
        .map(|(text, level)| SmartArtNode {
            text: (*text).to_owned(),
            level: *level,
            id: None,
        })
        .collect();
    vec![
        add(
            n,
            s,
            NodeKind::GraphicFrame,
            "Oracle SmartArt",
            None,
            Some(NodePayload::SmartArt { nodes }),
        ),
        DeckOp::SetGeometry {
            node: n,
            geometry: frame(914_400, 3_657_600, 5_486_400, 2_286_000),
        },
    ]
}

/// The SmartArt the deck holds and its nodes, as its import read them.
fn held_smart_art(subject: &Subject<'_>) -> Res<(NodeId, Vec<SmartArtNode>)> {
    subject
        .deck
        .deck
        .nodes
        .iter()
        .find_map(|(id, node)| match &node.payload {
            Some(NodePayload::SmartArt { nodes }) if node.binding.is_some() => {
                Some((*id, nodes.clone()))
            }
            _ => None,
        })
        .ok_or_else(|| "the deck holds no SmartArt".to_owned())
}

/// A live-born bar chart of one series over `categories`, the series
/// drawing `own` categories when given.
fn chart(categories: ChartCategories, own: Option<ChartCategories>) -> NodePayload {
    let values = (1..=4_u32)
        .map(|v| Some(serde_json::Number::from(v * 3)))
        .collect();
    NodePayload::Chart {
        family: ChartKind::Bar,
        categories,
        series: vec![ChartSeries {
            id: None,
            name: "Units".to_owned(),
            values,
            family: None,
            x: None,
            x_labels: None,
            plot: None,
            categories: own,
            bubble_size: None,
            bubble_3d: None,
        }],
        source: ChartSource::Workbook,
        plots: Vec::new(),
        view: None,
    }
}

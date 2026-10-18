//! The live mutations step 2 exercises, each over the first slide and its
//! first text shape: the operations, the parts their kind may add, and the
//! checks PowerPoint owes the export.

use super::assets::OracleAssets;
use super::edits::{EDIT_MARK, Ids, Scope, Subject, add, appended, body, frame, shifted};
use super::record::{OfficeCheck, Res};
use super::spec::Recipe;
use crate::edit::Preset;
use crate::live::{
    ChartKind, ChartSeries, ChartSource, ConnectorEnd, DeckOp, NodeId, NodeKind, NodePayload,
    Paragraph,
};

/// One mutation over the probed baseline.
pub(super) struct Plan {
    pub(super) ops: Vec<DeckOp>,
    pub(super) scope: Scope,
    pub(super) checks: Vec<OfficeCheck>,
    /// The text shape (and its probe) leaves the deck.
    pub(super) removes_shape: bool,
}

impl Plan {
    fn of(ops: Vec<DeckOp>, scope: Scope, checks: Vec<OfficeCheck>) -> Self {
        Self {
            ops,
            scope,
            checks,
            removes_shape: false,
        }
    }
}

pub(super) fn plan(
    recipe: Recipe,
    subject: &Subject<'_>,
    ids: &mut Ids,
    assets: &OracleAssets,
) -> Res<Plan> {
    let t = subject.anchor.shape;
    let deck = &subject.deck.deck;
    let body = deck.texts.get(&t).ok_or("the text shape has no body")?;
    let first = body
        .paragraphs
        .first()
        .ok_or("the text body has no paragraph")?;
    Ok(match recipe {
        Recipe::SetText => {
            let (next, edited) = appended(body, EDIT_MARK)?;
            Plan::of(
                vec![DeckOp::SetText {
                    node: t,
                    body: next,
                }],
                Scope::SLIDE,
                vec![OfficeCheck::Text {
                    slide: 1,
                    contains: edited,
                }],
            )
        }
        Recipe::SetRunMarks => {
            let mut runs = first.runs.clone();
            for run in &mut runs {
                run.bold = Some(true);
            }
            Plan::of(
                vec![DeckOp::SetRunMarks {
                    node: t,
                    paragraph: first.id,
                    runs,
                }],
                Scope::SLIDE,
                vec![OfficeCheck::Markup {
                    slide: 1,
                    contains: "b=\"1\"".to_owned(),
                }],
            )
        }
        Recipe::SetGeometry => {
            let geometry = shifted(deck.nodes[&t].geometry);
            Plan::of(
                vec![DeckOp::SetGeometry { node: t, geometry }],
                Scope::SLIDE,
                vec![OfficeCheck::Shape {
                    slide: 1,
                    id: subject.anchor.native,
                    offset: geometry.offset,
                }],
            )
        }
        Recipe::SetPreset => Plan::of(
            vec![DeckOp::SetPreset {
                node: t,
                preset: Preset::RoundRect,
            }],
            Scope::SLIDE,
            vec![OfficeCheck::Markup {
                slide: 1,
                contains: "prst=\"roundRect\"".to_owned(),
            }],
        ),
        _ => return born(recipe, subject, ids, assets),
    })
}

/// The mutations that create, move or remove nodes.
fn born(recipe: Recipe, subject: &Subject<'_>, ids: &mut Ids, assets: &OracleAssets) -> Res<Plan> {
    let (s, t) = (subject.anchor.slide, subject.anchor.shape);
    let n = ids.mint();
    Ok(match recipe {
        Recipe::AddShape => Plan::of(
            vec![
                add(
                    n,
                    s,
                    NodeKind::Shape,
                    "Oracle shape",
                    Some(Preset::Ellipse),
                    None,
                ),
                DeckOp::SetGeometry {
                    node: n,
                    geometry: frame(4_572_000, 3_657_600, 1_828_800, 914_400),
                },
                DeckOp::SetText {
                    node: n,
                    body: body(ids, "Live-born shape"),
                },
            ],
            Scope::SLIDE,
            vec![
                OfficeCheck::Text {
                    slide: 1,
                    contains: "Live-born shape".to_owned(),
                },
                markup("prst=\"ellipse\""),
            ],
        ),
        Recipe::AddGroup => group(n, s, ids),
        Recipe::AddConnector => connector(n, s, t, ids),
        _ => return carried(recipe, subject, n, ids, assets),
    })
}

/// The mutations that write a payload or change the slide list.
fn carried(
    recipe: Recipe,
    subject: &Subject<'_>,
    n: NodeId,
    ids: &mut Ids,
    assets: &OracleAssets,
) -> Res<Plan> {
    let s = subject.anchor.slide;
    let place = DeckOp::SetGeometry {
        node: n,
        geometry: frame(914_400, 3_657_600, 3_657_600, 1_097_280),
    };
    Ok(match recipe {
        Recipe::AddTable => Plan::of(
            vec![
                add(
                    n,
                    s,
                    NodeKind::GraphicFrame,
                    "Oracle table",
                    None,
                    Some(NodePayload::Table {
                        header: vec!["Region".to_owned(), "Units".to_owned()],
                        rows: vec![
                            vec![Some("North".to_owned()), Some("12".to_owned())],
                            vec![Some("South".to_owned()), None],
                        ],
                    }),
                ),
                place,
            ],
            Scope::SLIDE,
            vec![
                OfficeCheck::Text {
                    slide: 1,
                    contains: "North".to_owned(),
                },
                markup("a:tbl>"),
            ],
        ),
        Recipe::AddChart => Plan::of(
            vec![
                add(
                    n,
                    s,
                    NodeKind::GraphicFrame,
                    "Oracle chart",
                    None,
                    Some(NodePayload::Chart {
                        family: ChartKind::Bar,
                        categories: vec!["Q1".to_owned(), "Q2".to_owned(), "Q3".to_owned()],
                        series: vec![ChartSeries {
                            name: "Units".to_owned(),
                            values: vec![
                                Some(serde_json::Number::from(12_u32)),
                                Some(serde_json::Number::from(15_u32)),
                                None,
                            ],
                            family: None,
                            x: None,
                        }],
                        source: ChartSource::Workbook,
                    }),
                ),
                place,
            ],
            Scope::RELATED,
            vec![markup("c:chart ")],
        ),
        Recipe::AddPicture => Plan::of(
            vec![
                add(
                    n,
                    s,
                    NodeKind::Picture,
                    "Oracle picture",
                    None,
                    Some(NodePayload::Picture {
                        image: assets.image(),
                    }),
                ),
                place,
            ],
            Scope::RELATED,
            vec![markup("p:pic>")],
        ),
        _ => return listed(recipe, subject, n, ids),
    })
}

/// The mutations that move the text shape or change the slide list.
fn listed(recipe: Recipe, subject: &Subject<'_>, n: NodeId, ids: &mut Ids) -> Res<Plan> {
    let (s, t) = (subject.anchor.slide, subject.anchor.shape);
    let deck = &subject.deck.deck;
    let first = deck
        .texts
        .get(&t)
        .and_then(|body| body.paragraphs.first())
        .map(Paragraph::text)
        .unwrap_or_default();
    Ok(match recipe {
        Recipe::AddSlide => new_slide(n, ids),
        Recipe::MoveShape => {
            let top = deck.nodes[&s].children.len() + 1;
            Plan::of(
                vec![
                    add(
                        n,
                        s,
                        NodeKind::Shape,
                        "Under the text",
                        Some(Preset::Rect),
                        None,
                    ),
                    DeckOp::SetGeometry {
                        node: n,
                        geometry: frame(457_200, 457_200, 8_229_600, 2_286_000),
                    },
                    DeckOp::MoveNode {
                        node: t,
                        new_parent: s,
                        index: top,
                    },
                ],
                Scope::SLIDE,
                vec![OfficeCheck::Shape {
                    slide: 1,
                    id: subject.anchor.native,
                    offset: None,
                }],
            )
        }
        Recipe::MoveCrossSlide => Plan::of(
            vec![
                DeckOp::AddSlide { id: Some(n) },
                DeckOp::MoveNode {
                    node: t,
                    new_parent: n,
                    index: 0,
                },
            ],
            Scope::LISTED,
            vec![
                OfficeCheck::Text {
                    slide: 2,
                    contains: first.clone(),
                },
                OfficeCheck::NoText {
                    slide: 1,
                    absent: first,
                },
            ],
        ),
        _ => Plan {
            ops: vec![DeckOp::RemoveNode { node: t }],
            scope: Scope::SLIDE,
            checks: vec![
                OfficeCheck::NoShape {
                    slide: 1,
                    id: subject.anchor.native,
                },
                OfficeCheck::NoText {
                    slide: 1,
                    absent: first,
                },
            ],
            removes_shape: true,
        },
    })
}

/// A group of two live-born shapes, one with text.
fn group(n: NodeId, s: NodeId, ids: &mut Ids) -> Plan {
    let (one, two) = (ids.mint(), ids.mint());
    Plan::of(
        vec![
            add(n, s, NodeKind::Group, "Oracle group", None, None),
            add(
                one,
                n,
                NodeKind::Shape,
                "Group member one",
                Some(Preset::Rect),
                None,
            ),
            DeckOp::SetGeometry {
                node: one,
                geometry: frame(914_400, 3_657_600, 1_828_800, 685_800),
            },
            DeckOp::SetText {
                node: one,
                body: body(ids, "Grouped shape"),
            },
            add(
                two,
                n,
                NodeKind::Shape,
                "Group member two",
                Some(Preset::Triangle),
                None,
            ),
            DeckOp::SetGeometry {
                node: two,
                geometry: frame(3_200_400, 3_657_600, 914_400, 685_800),
            },
        ],
        Scope::SLIDE,
        vec![
            OfficeCheck::Text {
                slide: 1,
                contains: "Grouped shape".to_owned(),
            },
            markup("grpSp>"),
        ],
    )
}

/// A live-born connector glued from the text shape to a live-born shape.
fn connector(n: NodeId, s: NodeId, t: NodeId, ids: &mut Ids) -> Plan {
    let target = ids.mint();
    Plan::of(
        vec![
            add(
                target,
                s,
                NodeKind::Shape,
                "Connector target",
                Some(Preset::Rect),
                None,
            ),
            DeckOp::SetGeometry {
                node: target,
                geometry: frame(5_486_400, 3_657_600, 1_828_800, 914_400),
            },
            add(
                n,
                s,
                NodeKind::Connector,
                "Oracle connector",
                None,
                Some(NodePayload::Connector {
                    preset: None,
                    start: Some(ConnectorEnd { node: t, site: 2 }),
                    end: Some(ConnectorEnd {
                        node: target,
                        site: 0,
                    }),
                }),
            ),
        ],
        Scope::SLIDE,
        vec![markup("cxnSp>"), markup("stCxn")],
    )
}

fn markup(contains: &str) -> OfficeCheck {
    OfficeCheck::Markup {
        slide: 1,
        contains: contains.to_owned(),
    }
}

/// A live-born slide holding one live-born text shape.
fn new_slide(n: NodeId, ids: &mut Ids) -> Plan {
    let shape = ids.mint();
    Plan::of(
        vec![
            DeckOp::AddSlide { id: Some(n) },
            add(
                shape,
                n,
                NodeKind::Shape,
                "Live-born slide shape",
                Some(Preset::Rect),
                None,
            ),
            DeckOp::SetGeometry {
                node: shape,
                geometry: frame(914_400, 914_400, 5_486_400, 914_400),
            },
            DeckOp::SetText {
                node: shape,
                body: body(ids, "Live-born slide"),
            },
        ],
        Scope::LISTED,
        vec![OfficeCheck::Text {
            slide: 2,
            contains: "Live-born slide".to_owned(),
        }],
    )
}

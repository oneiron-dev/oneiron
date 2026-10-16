//! ONE-2534 acceptance: one fixture per primitive and path command with exact
//! EMU geometry, every refused class, and the asset-binding refusals.

use super::*;
use crate::ooxml::{Node, XmlTree};
use crate::retained_opc::XmlLimits;

const PX: i64 = EMU_PER_PX;
const BOUNDS: Rect = Rect {
    x: 0,
    y: 0,
    cx: 200 * PX,
    cy: 100 * PX,
};
const BLACK: Solid = Solid {
    rgb: [0, 0, 0],
    alpha: 100_000,
};

fn svg(body: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" viewBox="0 0 200 100">{body}</svg>"#
    )
}

fn record(media: MediaType, bytes: &[u8], origin: Origin) -> AssetRecord {
    AssetRecord {
        artifact: "artifact-1".to_owned(),
        version: 3,
        content_hash: *blake3::hash(bytes).as_bytes(),
        media,
        origin,
        provenance: vec!["claim-7".to_owned()],
        rights: Vec::new(),
        description: "Flow of the quarter".to_owned(),
    }
}

fn run(
    record: &AssetRecord,
    bytes: Option<&[u8]>,
    requested: AssetKind,
    bounds: Rect,
    limits: GraphicLimits,
) -> Result<CompiledGraphic, GraphicError> {
    let binding = AssetBinding {
        handle: record.artifact.clone(),
        media: record.media,
    };
    compile_graphic(&GraphicInput {
        binding: &binding,
        requested,
        record,
        bytes,
        bounds,
        limits,
    })
}

fn document(bytes: &str, limits: GraphicLimits) -> Result<Drawing, GraphicError> {
    let record = record(MediaType::Svg, bytes.as_bytes(), Origin::Diagram);
    let compiled = run(
        &record,
        Some(bytes.as_bytes()),
        AssetKind::Illustration,
        BOUNDS,
        limits,
    )?;
    match compiled.output {
        Output::Shapes(drawing) => Ok(drawing),
        Output::Image(image) => panic!("an SVG compiled to an image: {image:?}"),
    }
}

fn drawing(body: &str) -> Result<Drawing, GraphicError> {
    document(&svg(body), GraphicLimits::default())
}

fn one(body: &str) -> NativeShape {
    let shapes = drawing(body).unwrap().shapes;
    assert_eq!(shapes.len(), 1, "{body}");
    shapes.into_iter().next().unwrap()
}

fn refusal(result: Result<Drawing, GraphicError>) -> Refused {
    match result {
        Err(GraphicError::Svg { refused, .. }) => refused,
        other => panic!("expected an SVG refusal: {other:?}"),
    }
}

fn refused(body: &str) -> Refused {
    refusal(drawing(body))
}

fn px(x: i64, y: i64, cx: i64, cy: i64) -> Rect {
    Rect {
        x: x * PX,
        y: y * PX,
        cx: cx * PX,
        cy: cy * PX,
    }
}

fn frame(rect: Rect) -> Frame {
    Frame {
        rect,
        rot: 0,
        flip_v: false,
    }
}

fn p(x: i64, y: i64) -> Pt {
    Pt {
        x: x * PX,
        y: y * PX,
    }
}

fn stroke(rgb: [u8; 3]) -> Stroke {
    Stroke {
        width: PX,
        paint: Solid {
            rgb,
            alpha: 100_000,
        },
        cap: Cap::Flat,
        join: Join::Miter { limit: 400_000 },
    }
}

fn spec(w: i64, h: i64, fill: bool, stroke: bool, segments: Vec<Segment>) -> PathSpec {
    PathSpec {
        w: w * PX,
        h: h * PX,
        fill,
        stroke,
        segments,
    }
}

#[test]
fn every_primitive_maps_to_native_geometry_at_9525_emu_per_px() {
    use Segment::{Close, LineTo, MoveTo};
    let shape = |name: &str, frame, geometry, fill, stroke| NativeShape {
        name: name.to_owned(),
        frame,
        geometry,
        fill,
        stroke,
    };
    let red = [0xFF, 0, 0];
    let cases = [
        (
            r#"<rect x="10" y="20" width="30" height="40"/>"#,
            shape(
                "rect",
                frame(px(10, 20, 30, 40)),
                Geometry::Preset(Preset::Rect),
                Some(BLACK),
                None,
            ),
        ),
        (
            r##"<rect id="card" x="10" y="10" width="40" height="20" rx="5" fill="#336699"/>"##,
            shape(
                "card",
                frame(px(10, 10, 40, 20)),
                Geometry::Preset(Preset::RoundRect { adj: 25_000 }),
                Some(Solid {
                    rgb: [0x33, 0x66, 0x99],
                    alpha: 100_000,
                }),
                None,
            ),
        ),
        (
            r#"<circle cx="50" cy="50" r="25"/>"#,
            shape(
                "circle",
                frame(px(25, 25, 50, 50)),
                Geometry::Preset(Preset::Ellipse),
                Some(BLACK),
                None,
            ),
        ),
        (
            r#"<ellipse cx="100" cy="50" rx="40" ry="20"/>"#,
            shape(
                "ellipse",
                frame(px(60, 30, 80, 40)),
                Geometry::Preset(Preset::Ellipse),
                Some(BLACK),
                None,
            ),
        ),
        (
            r##"<line x1="10" y1="90" x2="60" y2="40" stroke="#ff0000"/>"##,
            shape(
                "line",
                Frame {
                    flip_v: true,
                    ..frame(px(10, 40, 50, 50))
                },
                Geometry::Preset(Preset::Line),
                None,
                Some(stroke(red)),
            ),
        ),
        (
            r##"<line x1="10" y1="10" x2="60" y2="40" stroke="#f00"/>"##,
            shape(
                "line",
                frame(px(10, 10, 50, 30)),
                Geometry::Preset(Preset::Line),
                None,
                Some(stroke(red)),
            ),
        ),
        (
            r##"<polyline points="10,10 50,10 50,50" fill="none" stroke="#000"/>"##,
            shape(
                "polyline",
                frame(px(10, 10, 40, 40)),
                Geometry::Custom(vec![spec(
                    40,
                    40,
                    false,
                    true,
                    vec![MoveTo(p(0, 0)), LineTo(p(40, 0)), LineTo(p(40, 40))],
                )]),
                None,
                Some(stroke([0, 0, 0])),
            ),
        ),
        (
            r#"<polygon points="10,10 50,10 30,40"/>"#,
            shape(
                "polygon",
                frame(px(10, 10, 40, 30)),
                Geometry::Custom(vec![spec(
                    40,
                    30,
                    true,
                    true,
                    vec![MoveTo(p(0, 0)), LineTo(p(40, 0)), LineTo(p(20, 30)), Close],
                )]),
                Some(BLACK),
                None,
            ),
        ),
        // A filled open outline fills closed and strokes open, as SVG paints it.
        (
            r##"<polyline points="10,10 50,10 50,50" fill="#00ff00" stroke="#000"/>"##,
            shape(
                "polyline",
                frame(px(10, 10, 40, 40)),
                Geometry::Custom(vec![
                    spec(
                        40,
                        40,
                        true,
                        false,
                        vec![MoveTo(p(0, 0)), LineTo(p(40, 0)), LineTo(p(40, 40)), Close],
                    ),
                    spec(
                        40,
                        40,
                        false,
                        true,
                        vec![MoveTo(p(0, 0)), LineTo(p(40, 0)), LineTo(p(40, 40))],
                    ),
                ]),
                Some(Solid {
                    rgb: [0, 0xFF, 0],
                    alpha: 100_000,
                }),
                Some(stroke([0, 0, 0])),
            ),
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(one(body), expected, "{body}");
    }
}

#[test]
fn a_rounded_rect_below_one_emu_is_a_plain_rect() {
    let shape = one(r#"<rect x="10" y="10" width="0.00001" height="0.00001" rx="0.000005"/>"#);
    assert_eq!(shape.geometry, Geometry::Preset(Preset::Rect));
}

#[test]
fn every_path_command_maps_to_its_drawingml_segment() {
    use Segment::{Close, CubicTo, LineTo, MoveTo, QuadTo};
    let stroked = |d: &str| one(&format!(r##"<path d="{d}" fill="none" stroke="#000"/>"##));
    let all = stroked("M10 10 L50 10 H90 V50 C90 70 70 90 50 90 Q10 90 10 50 Z");
    assert_eq!(all.frame, frame(px(10, 10, 80, 80)));
    assert_eq!(
        all.geometry,
        Geometry::Custom(vec![spec(
            80,
            80,
            false,
            true,
            vec![
                MoveTo(p(0, 0)),
                LineTo(p(40, 0)),
                LineTo(p(80, 0)),
                LineTo(p(80, 40)),
                CubicTo(p(80, 60), p(60, 80), p(40, 80)),
                QuadTo(p(0, 80), p(0, 40)),
                Close,
            ]
        )])
    );
    // Repeated argument sets repeat the command; after M they are lines.
    let repeated = stroked("M10 30 20 40 30 30 C40 20,50 20,60 30 70 40 80 40 90 30");
    let Geometry::Custom(specs) = repeated.geometry else {
        panic!("custom geometry");
    };
    assert_eq!(
        specs[0].segments,
        vec![
            MoveTo(p(0, 10)),
            LineTo(p(10, 20)),
            LineTo(p(20, 10)),
            CubicTo(p(30, 0), p(40, 0), p(50, 10)),
            CubicTo(p(60, 20), p(70, 20), p(80, 10)),
        ]
    );
    // A command after Z starts a new subpath at the closed one's start.
    let reopened = stroked("M10 10 L20 10 L20 20 Z L30 30 M40 40 L50 50");
    let Geometry::Custom(specs) = reopened.geometry else {
        panic!("custom geometry");
    };
    assert_eq!(
        specs[0].segments,
        vec![
            MoveTo(p(0, 0)),
            LineTo(p(10, 0)),
            LineTo(p(10, 10)),
            Close,
            MoveTo(p(0, 0)),
            LineTo(p(20, 20)),
            MoveTo(p(30, 30)),
            LineTo(p(40, 40)),
        ]
    );
    for (d, expected) in [
        ("m10 10 l5 5", Refused::PathCommand('m')),
        ("M10 10 l5 5", Refused::PathCommand('l')),
        ("M10 10 A5 5 0 0 1 20 20", Refused::PathCommand('A')),
        ("M10 10 S20 20 30 30", Refused::PathCommand('S')),
        ("M10 10 T20 20", Refused::PathCommand('T')),
        ("M10 10 L", Refused::Value("d".to_owned())),
        ("M10 10 L20", Refused::Value("d".to_owned())),
        ("M10 10", Refused::Value("d".to_owned())),
    ] {
        assert_eq!(
            refused(&format!(r##"<path d="{d}" fill="none" stroke="#000"/>"##)),
            expected,
            "{d}"
        );
    }
}

#[test]
fn paint_maps_to_solid_fills_alpha_caps_and_joins() {
    let inherited = one(
        r##"<g fill="#123456" stroke="#abcdef" stroke-width="2" stroke-linecap="round" stroke-linejoin="bevel" fill-opacity="0.5" stroke-opacity="0.25"><rect x="10" y="10" width="20" height="20"/></g>"##,
    );
    assert_eq!(
        inherited.fill,
        Some(Solid {
            rgb: [0x12, 0x34, 0x56],
            alpha: 50_000,
        })
    );
    assert_eq!(
        inherited.stroke,
        Some(Stroke {
            width: 2 * PX,
            paint: Solid {
                rgb: [0xAB, 0xCD, 0xEF],
                alpha: 25_000,
            },
            cap: Cap::Round,
            join: Join::Bevel,
        })
    );
    let mitred = one(
        r##"<rect x="10" y="10" width="20" height="20" stroke="#000" stroke-miterlimit="2" stroke-linecap="square"/>"##,
    );
    let mitred = mitred.stroke.unwrap();
    assert_eq!(
        (mitred.join, mitred.cap),
        (Join::Miter { limit: 200_000 }, Cap::Square)
    );
    assert_eq!(
        one(r##"<rect x="10" y="10" width="5" height="5" stroke="#000" stroke-width="0"/>"##)
            .stroke,
        None
    );
    assert!(
        drawing(r#"<rect x="10" y="10" width="5" height="5" fill="none"/>"#)
            .unwrap()
            .shapes
            .is_empty()
    );
    for (attribute, expected) in [
        (r#"fill="red""#, Refused::Value("fill".to_owned())),
        (r#"fill="currentColor""#, Refused::Value("fill".to_owned())),
        (r#"fill="rgb(1,2,3)""#, Refused::Value("fill".to_owned())),
        (
            r#"fill-opacity="1.5""#,
            Refused::Value("fill-opacity".to_owned()),
        ),
        (r#"opacity="0.5""#, Refused::Value("opacity".to_owned())),
        (
            r#"stroke-linejoin="arcs""#,
            Refused::Value("stroke-linejoin".to_owned()),
        ),
        (
            r#"fill-rule="inherit""#,
            Refused::Value("fill-rule".to_owned()),
        ),
        (
            r#"stroke-dasharray="2""#,
            Refused::Attribute("stroke-dasharray".to_owned()),
        ),
        (
            r#"xml:space="preserve""#,
            Refused::Attribute("xml:space".to_owned()),
        ),
    ] {
        assert_eq!(
            refused(&format!(
                r#"<rect x="10" y="10" width="5" height="5" {attribute}/>"#
            )),
            expected,
            "{attribute}"
        );
    }
}

#[test]
fn transforms_compose_and_refuse_what_strokes_cannot_keep() {
    let moved = one(r#"<g transform="translate(10,20)"><rect width="30" height="10"/></g>"#);
    assert_eq!(moved.frame, frame(px(10, 20, 30, 10)));
    let scaled =
        one(r##"<g transform="scale(2)"><circle cx="20" cy="20" r="5" stroke="#000"/></g>"##);
    assert_eq!(scaled.frame, frame(px(30, 30, 20, 20)));
    assert_eq!(scaled.stroke.unwrap().width, 2 * PX);
    // A rotation becomes the preset's own: centre kept, sides unrotated.
    let turned =
        one(r#"<rect x="40" y="40" width="40" height="20" transform="rotate(90 60 50)"/>"#);
    assert_eq!(
        turned.frame,
        Frame {
            rect: px(40, 40, 40, 20),
            rot: 5_400_000,
            flip_v: false,
        }
    );
    // Custom geometry takes the whole transform point by point.
    let path = one(
        r##"<path d="M10 10 L30 10" fill="none" stroke="#000" transform="rotate(90 10 10)"/>"##,
    );
    assert_eq!(
        path.frame.rect,
        Rect {
            x: 10 * PX,
            y: 10 * PX,
            cx: 1,
            cy: 20 * PX,
        }
    );
    // A non-uniform scale keeps an unstroked shape exact.
    let stretched =
        one(r#"<g transform="scale(2,1)"><rect x="10" y="10" width="10" height="10"/></g>"#);
    assert_eq!(stretched.frame, frame(px(20, 10, 20, 10)));
    for (body, expected) in [
        (
            r##"<g transform="scale(2,1)"><rect x="10" y="10" width="10" height="10" stroke="#000"/></g>"##,
            Refused::StrokeTransform,
        ),
        (
            r#"<rect width="5" height="5" transform="skewX(10)"/>"#,
            Refused::Transform,
        ),
        (
            r#"<rect width="5" height="5" transform="matrix(1 0 0 1 0 0)"/>"#,
            Refused::Transform,
        ),
        (
            r#"<rect width="5" height="5" transform="scale(-1,1)"/>"#,
            Refused::Transform,
        ),
        (
            r#"<g transform="rotate(30)"><g transform="scale(2,1)"><rect x="10" y="10" width="5" height="5"/></g></g>"#,
            Refused::Transform,
        ),
        (
            r#"<rect width="5" height="5" transform="translate(1"/>"#,
            Refused::Value("transform".to_owned()),
        ),
    ] {
        assert_eq!(refused(body), expected, "{body}");
    }
}

#[test]
fn every_unsupported_class_is_refused() {
    let shape = r#"width="5" height="5""#;
    let cases = [
        ("<script/>".to_owned(), Refused::Active),
        (
            format!(r#"<rect {shape} onclick="go()"/>"#),
            Refused::Active,
        ),
        (
            r#"<animate attributeName="x"/>"#.to_owned(),
            Refused::Active,
        ),
        (
            format!(r#"<image href="https://example.com/a.png" {shape}/>"#),
            Refused::ExternalReference,
        ),
        (
            format!(r#"<rect {shape} fill="url(https://example.com/p.svg#g)"/>"#),
            Refused::ExternalReference,
        ),
        (
            format!(r#"<foreignObject {shape}/>"#),
            Refused::ForeignObject,
        ),
        ("<style>rect { fill: red }</style>".to_owned(), Refused::Css),
        (
            format!(r#"<rect {shape} style="fill: red"/>"#),
            Refused::Css,
        ),
        (format!(r#"<rect {shape} class="accent"/>"#), Refused::Css),
        (
            r#"<filter id="f"><feGaussianBlur stdDeviation="2"/></filter>"#.to_owned(),
            Refused::Filter,
        ),
        (
            format!(r#"<rect {shape} filter="url(#f)"/>"#),
            Refused::Filter,
        ),
        (r#"<mask id="m"/>"#.to_owned(), Refused::Mask),
        (r#"<pattern id="p"/>"#.to_owned(), Refused::Pattern),
        (r#"<clipPath id="c"/>"#.to_owned(), Refused::ClipPath),
        (
            format!(r#"<rect {shape} clip-path="url(#c)"/>"#),
            Refused::ClipPath,
        ),
        (
            format!(r#"<defs><linearGradient id="g"/></defs><rect {shape} fill="url(#g)"/>"#),
            Refused::Gradient,
        ),
        (r#"<radialGradient id="g"/>"#.to_owned(), Refused::Gradient),
        (
            format!(r#"<rect {shape} fill="url(#g)"/>"#),
            Refused::Value("fill".to_owned()),
        ),
        (r##"<textPath href="#p"/>"##.to_owned(), Refused::TextOnPath),
        (
            r#"<text x="1" y="10">label</text>"#.to_owned(),
            Refused::Text,
        ),
        (
            r#"<polygon points="100,10 120,90 60,40 140,40 80,90"/>"#.to_owned(),
            Refused::FillRule,
        ),
        (r##"<use href="#r"/>"##.to_owned(), Refused::Element),
        ("<defs/>".to_owned(), Refused::Element),
        ("<marker/>".to_owned(), Refused::Element),
        (
            r#"<svg width="5" height="5" viewBox="0 0 5 5"/>"#.to_owned(),
            Refused::Element,
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(refused(&body), expected, "{body}");
    }
    let limits = GraphicLimits::default();
    let linked = format!(r#"<?xml-stylesheet href="a.css"?>{}"#, svg(""));
    assert_eq!(refusal(document(&linked, limits)), Refused::Css);
    let typed = format!(r#"<!DOCTYPE svg [<!ENTITY e "x">]>{}"#, svg(""));
    assert_eq!(
        refusal(document(&typed, limits)),
        Refused::Malformed("DTD is forbidden")
    );
}

#[test]
fn fill_rules_compile_only_where_both_rules_agree() {
    // A simple concave polygon, a convex curved outline, and any stroke-only
    // outline compile, whatever rule they declare.
    for body in [
        r#"<polygon points="10,10 60,10 60,30 30,30 30,60 10,60" fill-rule="evenodd"/>"#,
        r#"<path d="M100 20 C117 20 130 33 130 50 C130 67 117 80 100 80 C83 80 70 67 70 50 C70 33 83 20 100 20 Z"/>"#,
        r##"<polygon points="100,10 120,90 60,40 140,40 80,90" fill="none" stroke="#000"/>"##,
    ] {
        assert_eq!(drawing(body).unwrap().shapes.len(), 1, "{body}");
    }
    for body in [
        // A pentagram: nonzero fills its centre, even-odd leaves it empty.
        r#"<polygon points="100,10 120,90 60,40 140,40 80,90" fill-rule="evenodd"/>"#,
        // A ring: two subpaths.
        r#"<path d="M20 20 L80 20 L80 80 L20 80 Z M40 40 L60 40 L60 60 L40 60 Z"/>"#,
        // A curve whose control polygon is not convex: refused, not proved.
        r#"<path d="M10 10 L90 10 Q50 50 90 90 L10 90 Z"/>"#,
        // A bow tie folds through itself.
        r#"<polygon points="10,10 60,60 60,10 10,60"/>"#,
    ] {
        assert_eq!(refused(body), Refused::FillRule, "{body}");
    }
}

#[test]
fn document_bounds_and_limits_are_checked() {
    let limits = GraphicLimits::default();
    let ns = r#"xmlns="http://www.w3.org/2000/svg""#;
    for root in [
        format!(r#"<svg {ns} width="10" height="10"/>"#),
        format!(r#"<svg {ns} width="20" height="10" viewBox="0 0 10 10"/>"#),
        format!(r#"<svg {ns} width="10mm" height="10mm" viewBox="0 0 10 10"/>"#),
        format!(r#"<svg {ns} viewBox="0 0 10 10"/>"#),
        format!(r#"<g {ns}/>"#),
        r#"<svg width="10" height="10" viewBox="0 0 10 10"/>"#.to_owned(),
    ] {
        assert_eq!(
            refusal(document(&root, limits)),
            Refused::Document,
            "{root}"
        );
    }
    let sized = format!(r#"<svg {ns} width="10px" height="10px" viewBox="5 5 10 10"/>"#);
    assert_eq!(document(&sized, limits).unwrap().child, px(5, 5, 10, 10));
    // SVG clips at the viewport; a DrawingML group would not.
    assert_eq!(
        refused(r#"<rect x="190" y="0" width="20" height="10"/>"#),
        Refused::Bounds
    );
    assert_eq!(
        refused(r##"<rect x="0" y="0" width="10" height="10" stroke="#000"/>"##),
        Refused::Bounds
    );
    assert_eq!(
        refused(r##"<rect x="0.6" y="2" width="10" height="10" stroke="#000"/>"##),
        Refused::Bounds,
        "a miter corner reaches half the width times root two"
    );
    assert_eq!(one(r##"<rect x="3" y="3" width="10" height="10" stroke="#000" stroke-width="4" stroke-linejoin="round"/>"##).frame, frame(px(3, 3, 10, 10)));
    assert_eq!(
        refused("<?php x ?>"),
        Refused::Malformed("processing instruction")
    );
    let three = svg(r##"<path d="M10 10 L20 20 L30 10 L40 20" fill="none" stroke="#000"/>"##);
    let tight = GraphicLimits {
        segments: 2,
        ..limits
    };
    assert_eq!(refusal(document(&three, tight)), Refused::Limit);
    let nodes = GraphicLimits {
        svg_nodes: 2,
        ..limits
    };
    let many = svg(r#"<rect width="5" height="5"/><rect width="5" height="5"/>"#);
    assert_eq!(refusal(document(&many, nodes)), Refused::Limit);
    let bytes = GraphicLimits {
        svg_bytes: 64,
        ..limits
    };
    assert_eq!(document(&many, bytes), Err(GraphicError::ResourceLimit));
}

#[test]
fn the_drawingml_fragment_is_well_formed_and_placed() {
    let source = svg(
        r##"<rect x="10" y="10" width="40" height="20" rx="5" fill="#336699" fill-opacity="0.5"/><line x1="10" y1="90" x2="60" y2="40" stroke="#f00" stroke-linecap="round"/><path d="M100 50 C120 20 140 80 160 50" fill="none" stroke="#000" stroke-linejoin="round"/>"##,
    );
    let record = record(MediaType::Svg, source.as_bytes(), Origin::Diagram);
    // A 400x100 px slot takes the 200x100 viewBox at its full height, centred.
    let slot = px(10, 0, 400, 100);
    let compiled = run(
        &record,
        Some(source.as_bytes()),
        AssetKind::Illustration,
        slot,
        GraphicLimits::default(),
    )
    .unwrap();
    assert_eq!(compiled.record.placed, px(110, 0, 200, 100));
    assert_eq!(
        compiled.record.original,
        Extent {
            cx: 200 * PX,
            cy: 100 * PX,
        }
    );
    let Output::Shapes(drawing) = compiled.output else {
        panic!("shapes");
    };
    let (xml, next) = drawing.drawingml(7, "diagram", "Flow \"Q3\" <draft>\nline two");
    assert_eq!(next, 11);
    let wrapped = format!(
        r#"<p:spTree xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">{xml}</p:spTree>"#
    );
    let tree = XmlTree::parse(
        wrapped.as_bytes(),
        XmlLimits {
            max_depth: 32,
            max_nodes: 10_000,
        },
    )
    .unwrap();
    let ids: Vec<&str> = named(&tree, "cNvPr")
        .map(|node| node.attr("id").unwrap())
        .collect();
    assert_eq!(ids, ["7", "8", "9", "10"]);
    let group = named(&tree, "cNvPr").next().unwrap();
    assert_eq!(group.attr("descr"), Some("Flow \"Q3\" <draft>\nline two"));
    let attrs = |name: &str, keys: [&str; 2]| -> Vec<String> {
        let node = named(&tree, name).next().unwrap();
        keys.iter()
            .map(|key| node.attr(key).unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        attrs("off", ["x", "y"]),
        [(110 * PX).to_string(), "0".to_owned()]
    );
    assert_eq!(attrs("chOff", ["x", "y"]), ["0", "0"]);
    assert_eq!(
        attrs("chExt", ["cx", "cy"]),
        [(200 * PX).to_string(), (100 * PX).to_string()]
    );
    let presets: Vec<&str> = named(&tree, "prstGeom")
        .map(|node| node.attr("prst").unwrap())
        .collect();
    assert_eq!(presets, ["roundRect", "line"]);
    assert_eq!(
        named(&tree, "gd").next().unwrap().attr("fmla"),
        Some("val 25000")
    );
    assert_eq!(
        named(&tree, "alpha").next().unwrap().attr("val"),
        Some("50000")
    );
    assert_eq!(
        named(&tree, "xfrm").nth(2).unwrap().attr("flipV"),
        Some("1")
    );
    assert_eq!(
        named(&tree, "ln")
            .map(|node| node.attr("cap"))
            .collect::<Vec<_>>(),
        [None, Some("rnd"), Some("flat"),]
    );
    let path = named(&tree, "path").next().unwrap();
    assert_eq!(path.attr("fill"), Some("none"));
    let commands: Vec<&str> = tree
        .children(
            tree.nodes
                .iter()
                .position(|node| node.name == "path")
                .unwrap(),
        )
        .map(|(_, node)| node.name.as_str())
        .collect();
    assert_eq!(commands, ["moveTo", "cubicBezTo"]);
    assert_eq!(named(&tree, "round").count(), 1);
}

fn named<'t>(tree: &'t XmlTree, name: &'t str) -> impl Iterator<Item = &'t Node> + 't {
    tree.nodes.iter().filter(move |node| node.name == name)
}

/// A PNG signature and IHDR size only: enough to read, not an image.
fn png_header(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    bytes.extend(width.to_be_bytes());
    bytes.extend(height.to_be_bytes());
    bytes.extend([8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// A whole greyscale PNG: chunks with their CRCs, image data, IEND.
fn png(width: u32, height: u32) -> Vec<u8> {
    use std::io::Write;
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend(u32::try_from(data.len()).unwrap().to_be_bytes());
        let mut crc = crc32fast::Hasher::new();
        crc.update(kind);
        crc.update(data);
        out.extend(kind);
        out.extend(data);
        out.extend(crc.finalize().to_be_bytes());
    }
    let mut header = width.to_be_bytes().to_vec();
    header.extend(height.to_be_bytes());
    header.extend([8, 0, 0, 0, 0]);
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    for _ in 0..height {
        encoder.write_all(&vec![0; width as usize + 1]).unwrap();
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &encoder.finish().unwrap());
    chunk(&mut out, b"IEND", &[]);
    out
}

fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x4A, 0x46];
    bytes.extend([0xFF, 0xC0, 0x00, 0x11, 0x08]);
    bytes.extend(height.to_be_bytes());
    bytes.extend(width.to_be_bytes());
    bytes.extend([3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1, 0xFF, 0xD9]);
    bytes
}

#[test]
fn raster_assets_bind_verified_with_original_and_placed_dimensions() {
    let wide = png(400, 100);
    let held = record(MediaType::Png, &wide, Origin::Held);
    let compiled = run(
        &held,
        Some(&wide),
        AssetKind::Factual,
        BOUNDS,
        GraphicLimits::default(),
    )
    .unwrap();
    assert_eq!(
        compiled.output,
        Output::Image(ImageBinding {
            handle: "artifact-1".to_owned(),
            media: MediaType::Png,
            placed: px(0, 25, 200, 50),
        })
    );
    assert_eq!(
        compiled.record.original,
        Extent {
            cx: 400 * PX,
            cy: 100 * PX,
        }
    );
    assert_eq!(
        (
            compiled.record.version,
            compiled.record.provenance.as_slice()
        ),
        (3, ["claim-7".to_owned()].as_slice())
    );
    let tall = jpeg(100, 200);
    let photo = record(MediaType::Jpeg, &tall, Origin::Held);
    let compiled = run(
        &photo,
        Some(&tall),
        AssetKind::Factual,
        BOUNDS,
        GraphicLimits::default(),
    )
    .unwrap();
    assert_eq!(compiled.record.placed, px(75, 0, 50, 100));
}

#[test]
fn missing_assets_licence_gaps_and_provenance_drift_are_refused() {
    let bytes = png(4, 2);
    let limits = GraphicLimits::default();
    let check = |record: &AssetRecord, bytes: Option<&[u8]>, requested: AssetKind| {
        run(record, bytes, requested, BOUNDS, limits).map(|_| ())
    };
    let held = record(MediaType::Png, &bytes, Origin::Held);
    let illustration = AssetKind::Illustration;
    assert_eq!(
        check(&held, None, illustration),
        Err(GraphicError::MissingBytes)
    );
    assert_eq!(
        check(&held, Some(&png(4, 3)), illustration),
        Err(GraphicError::HashMismatch)
    );
    let binding = AssetBinding {
        handle: "artifact-2".to_owned(),
        media: MediaType::Png,
    };
    let other = compile_graphic(&GraphicInput {
        binding: &binding,
        requested: illustration,
        record: &held,
        bytes: Some(&bytes),
        bounds: BOUNDS,
        limits,
    });
    assert_eq!(other, Err(GraphicError::BindingMismatch));
    let unsourced = AssetRecord {
        provenance: Vec::new(),
        ..held.clone()
    };
    assert_eq!(
        check(&unsourced, Some(&bytes), illustration),
        Err(GraphicError::MissingProvenance)
    );
    let undescribed = AssetRecord {
        description: " ".to_owned(),
        ..held.clone()
    };
    assert_eq!(
        check(&undescribed, Some(&bytes), illustration),
        Err(GraphicError::MissingDescription)
    );
    for origin in [Origin::Web, Origin::Stock] {
        let unlicensed = record(MediaType::Png, &bytes, origin);
        assert_eq!(
            check(&unlicensed, Some(&bytes), illustration),
            Err(GraphicError::MissingLicence)
        );
        let licensed = AssetRecord {
            rights: vec!["licence-claim-3".to_owned()],
            ..unlicensed
        };
        assert_eq!(check(&licensed, Some(&bytes), illustration), Ok(()));
    }
    let stock = AssetRecord {
        rights: vec!["licence-claim-3".to_owned()],
        ..record(MediaType::Png, &bytes, Origin::Stock)
    };
    assert_eq!(
        check(&stock, Some(&bytes), AssetKind::Factual),
        Err(GraphicError::NotFactual)
    );

    let prompt = *blake3::hash(b"reviewed prompt").as_bytes();
    let reference = *blake3::hash(b"reference image").as_bytes();
    let reviewed = ReviewedRequest {
        prompt,
        references: [reference].into(),
    };
    let receipt = GenerationReceipt {
        prompt: Some(prompt),
        references: Some([reference].into()),
        model: Some("image-model@2".to_owned()),
        adapter: Some("adapter@1.4".to_owned()),
        params_hash: Some([9; 32]),
        output_hash: Some(*blake3::hash(&bytes).as_bytes()),
        seed: Some(42),
    };
    let generated = |receipt: GenerationReceipt| {
        record(
            MediaType::Png,
            &bytes,
            Origin::Generated {
                reviewed: reviewed.clone(),
                receipt: Box::new(receipt),
            },
        )
    };
    let complete = run(
        &generated(receipt.clone()),
        Some(&bytes),
        illustration,
        BOUNDS,
        limits,
    )
    .unwrap();
    assert_eq!(complete.record.generated, Some(receipt.clone()));
    assert_eq!(
        check(
            &generated(receipt.clone()),
            Some(&bytes),
            AssetKind::Factual
        ),
        Err(GraphicError::NotFactual)
    );
    let drifts = [
        (
            GenerationReceipt {
                model: None,
                ..receipt.clone()
            },
            GraphicError::AdapterProvenance("model"),
        ),
        (
            GenerationReceipt {
                adapter: Some(String::new()),
                ..receipt.clone()
            },
            GraphicError::AdapterProvenance("adapter"),
        ),
        (
            GenerationReceipt {
                params_hash: None,
                ..receipt.clone()
            },
            GraphicError::AdapterProvenance("params_hash"),
        ),
        (
            GenerationReceipt {
                output_hash: None,
                ..receipt.clone()
            },
            GraphicError::AdapterProvenance("output_hash"),
        ),
        (
            GenerationReceipt {
                references: None,
                ..receipt.clone()
            },
            GraphicError::AdapterProvenance("references"),
        ),
        (
            GenerationReceipt {
                prompt: Some([1; 32]),
                ..receipt.clone()
            },
            GraphicError::ReviewDrift,
        ),
        (
            GenerationReceipt {
                references: Some([reference, [2; 32]].into()),
                ..receipt.clone()
            },
            GraphicError::ReviewDrift,
        ),
        (
            GenerationReceipt {
                output_hash: Some([3; 32]),
                ..receipt.clone()
            },
            GraphicError::OutputHash,
        ),
    ];
    for (receipt, expected) in drifts {
        assert_eq!(
            check(&generated(receipt), Some(&bytes), illustration),
            Err(expected)
        );
    }
    let seedless = GenerationReceipt {
        seed: None,
        ..receipt
    };
    assert_eq!(
        check(&generated(seedless), Some(&bytes), illustration),
        Ok(())
    );

    let photo = jpeg(4, 2);
    let mislabelled = record(MediaType::Png, &photo, Origin::Held);
    assert_eq!(
        check(&mislabelled, Some(&photo), illustration),
        Err(GraphicError::UnsupportedPayload)
    );
    let webp = b"RIFF\x10\0\0\0WEBPVP8 ".to_vec();
    let webp_record = record(MediaType::Jpeg, &webp, Origin::Held);
    assert_eq!(
        check(&webp_record, Some(&webp), illustration),
        Err(GraphicError::UnsupportedPayload)
    );
    let huge = png_header(10_000, 10_000);
    let huge_record = record(MediaType::Png, &huge, Origin::Held);
    assert_eq!(
        check(&huge_record, Some(&huge), illustration),
        Err(GraphicError::ResourceLimit)
    );
    // A header alone, or an image cut short, is not a verified payload.
    let header = png_header(4, 3);
    let header_record = record(MediaType::Png, &header, Origin::Held);
    assert_eq!(
        check(&header_record, Some(&header), illustration),
        Err(GraphicError::UnsupportedPayload)
    );
    let cut = &photo[..photo.len() - 2];
    let cut_record = record(MediaType::Jpeg, cut, Origin::Held);
    assert_eq!(
        check(&cut_record, Some(cut), illustration),
        Err(GraphicError::UnsupportedPayload)
    );
    let small = GraphicLimits {
        raster_bytes: 8,
        ..limits
    };
    assert_eq!(
        run(&held, Some(&bytes), illustration, BOUNDS, small).map(|_| ()),
        Err(GraphicError::ResourceLimit)
    );
}

//! ONE-2529 acceptance, first half (add, delete, reparent): high-water id
//! allocation, the supported delete cascades and the refusals of the rest,
//! identity- and geometry-preserving reparenting, and an independent check
//! that refuses an undeclared removal. Every refusal leaves the package
//! byte-identical.
use super::super::tests::{SLIDE, deck, part, shape_xml, target};
use super::*;

fn ellipse(high_water: u32, seed: &'static [u8]) -> StructureEdit<'static> {
    StructureEdit::AddShape {
        slide: SLIDE,
        shape: NewShape {
            preset: Preset::Ellipse,
            name: "Marker",
            offset: (500_000, 600_000),
            extent: (300_000, 200_000),
            high_water,
            seed,
        },
    }
}

fn delete(package: &Package, shape: u32, cascade: bool) -> StructureEdit<'static> {
    StructureEdit::DeleteShape {
        target: target(package, SLIDE, shape),
        cascade,
    }
}

fn reparent_to(package: &Package, shape: u32, parent: Option<u32>) -> StructureEdit<'static> {
    StructureEdit::Reparent {
        target: target(package, SLIDE, shape),
        parent,
    }
}

/// Refuse on a copy, which must stay byte-identical.
pub(super) fn refuse(package: &Package, op: &StructureEdit<'_>) -> EditRefusal {
    let mut copy = package.clone();
    let before = copy.export().unwrap();
    let refusal = structure_patch(&mut copy, op).unwrap_err();
    assert_eq!(copy.export().unwrap(), before, "a refusal changed the deck");
    refusal
}

/// The fixture deck with its first slide rewritten.
fn with_slide(edit: impl Fn(String) -> String) -> Package {
    let mut package = deck();
    let slide = edit(part(&package, SLIDE));
    package.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    package
}

fn ids(package: &Package) -> Vec<Option<u32>> {
    DeckView::read(package).unwrap().slides[0]
        .shapes
        .iter()
        .map(|shape| shape.id)
        .collect()
}

fn corners_of(package: &Package, id: u32) -> [(f64, f64); 4] {
    let view = DeckView::read(package).unwrap();
    let shape = view.slides[0]
        .shapes
        .iter()
        .find(|shape| shape.id == Some(id))
        .unwrap();
    check::corners(shape).unwrap()
}

fn close(a: [(f64, f64); 4], b: [(f64, f64); 4]) {
    for (p, q) in a.iter().zip(&b) {
        assert!(
            (p.0 - q.0).abs() < 2.0 && (p.1 - q.1).abs() < 2.0,
            "{a:?} != {b:?}"
        );
    }
}

#[test]
fn add_shape_allocates_above_the_high_water_mark() {
    let mut package = deck();
    let input = part(&package, SLIDE);
    let report = structure_patch(&mut package, &ellipse(20, b"one")).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    let [Effect::ShapeAdded { id, creation_id }] = report.effects.as_slice() else {
        panic!("{:?}", report.effects);
    };
    assert_eq!(*id, 21);
    let xml = shape_xml(&package, SLIDE, 21);
    assert!(xml.contains(r#"<a:prstGeom prst="ellipse">"#), "{xml}");
    assert!(xml.contains(r#"<a:fillRef idx="1"><a:schemeClr val="accent1"/>"#));
    assert!(!xml.contains("srgbClr") && xml.contains(creation_id.as_str()));
    // Every input byte is kept; the shape is the one insertion, topmost.
    assert_eq!(part(&package, SLIDE).replacen(&xml, "", 1), input);
    let view = DeckView::read(&package).unwrap();
    let shape = view.slides[0].shapes.last().unwrap();
    assert_eq!(
        (
            shape.id,
            shape.name.as_deref(),
            shape.kind,
            shape.geometry.offset.value
        ),
        (
            Some(21),
            Some("Marker"),
            ShapeKind::Shape,
            Some((500_000, 600_000))
        )
    );
    // Above the surviving ids when the mark is lower; the same seed draws a
    // fresh creation id.
    let report = structure_patch(&mut package, &ellipse(0, b"one")).unwrap();
    let [
        Effect::ShapeAdded {
            id: second,
            creation_id: other,
        },
    ] = report.effects.as_slice()
    else {
        panic!("{:?}", report.effects);
    };
    assert_eq!(*second, 22);
    assert_ne!(other, creation_id);
    let mut fresh = deck();
    structure_patch(&mut fresh, &ellipse(0, b"x")).unwrap();
    assert_eq!(ids(&fresh).last(), Some(&Some(14)));
}

#[test]
fn add_shape_refuses_exhausted_ids_and_bad_frames() {
    let package = deck();
    assert_eq!(
        refuse(&package, &ellipse(u32::MAX, b"x")),
        EditRefusal::IdSpaceExhausted
    );
    let base = NewShape {
        preset: Preset::Rect,
        name: "Box",
        offset: (0, 0),
        extent: (10, 10),
        high_water: 0,
        seed: b"s",
    };
    let add = |shape| {
        refuse(
            &package,
            &StructureEdit::AddShape {
                slide: SLIDE,
                shape,
            },
        )
    };
    assert!(matches!(
        add(NewShape {
            extent: (-1, 10),
            ..base
        }),
        EditRefusal::UnrepresentableTransform(_)
    ));
    assert!(matches!(
        add(NewShape {
            name: "a\u{1}",
            ..base
        }),
        EditRefusal::Invalid(_)
    ));
    let elsewhere = StructureEdit::AddShape {
        slide: "ppt/slides/slide9.xml",
        shape: base,
    };
    assert_eq!(refuse(&package, &elsewhere), EditRefusal::Missing("slide"));
}

#[test]
fn delete_shape_removes_a_group_with_its_members() {
    let mut package = deck();
    let input = part(&package, SLIDE);
    let group = shape_xml(&package, SLIDE, 4);
    let op = delete(&package, 4, false);
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    assert!(report.effects.is_empty());
    assert_eq!(part(&package, SLIDE), input.replacen(&group, "", 1));
    assert_eq!(ids(&package), [2, 3, 10, 11, 12, 13, 6, 7, 8, 9].map(Some));
}

#[test]
fn delete_shape_refuses_dependencies_without_cascade() {
    let package = deck();
    assert_eq!(
        refuse(&package, &delete(&package, 9, false)),
        EditRefusal::AnimationDependencyUnsupported(
            "the shape is animated; a cascade removes its effects"
        )
    );
    for glued in [3, 6] {
        assert_eq!(
            refuse(&package, &delete(&package, glued, false)),
            EditRefusal::GluedConnector(Some(7))
        );
    }
    assert!(matches!(
        refuse(&package, &delete(&package, 5, true)),
        EditRefusal::Invalid(_)
    ));
    let stale = StructureEdit::DeleteShape {
        target: Target {
            expected: [0; 32],
            ..target(&package, SLIDE, 3)
        },
        cascade: true,
    };
    assert_eq!(refuse(&package, &stale), EditRefusal::TargetChanged);
    // Built (8) leads its click step, which keeps Typed's (9) effect.
    assert_eq!(
        refuse(&package, &delete(&package, 8, true)),
        EditRefusal::AnimationDependencyUnsupported("the effect leads its step")
    );
    // A trigger condition is outside the tested subset.
    let triggered = with_slide(|slide| {
        slide.replacen(
            r#"<p:cond delay="indefinite"/>"#,
            r#"<p:cond evt="onClick" delay="0"><p:tgtEl><p:spTgt spid="3"/></p:tgtEl></p:cond>"#,
            1,
        )
    });
    assert_eq!(
        refuse(&triggered, &delete(&triggered, 3, true)),
        EditRefusal::AnimationDependencyUnsupported("a trigger names the shape")
    );
}

#[test]
fn delete_shape_cascades_the_tested_timing_subset() {
    let mut package = deck();
    let op = delete(&package, 9, true);
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    assert_eq!(
        report.effects,
        [Effect::TimingRemoved {
            timing_ids: vec![7, 8]
        }]
    );
    let slide = part(&package, SLIDE);
    assert!(!slide.contains(r#"<p:spTgt spid="9">"#));
    assert!(slide.contains(r#"<p:spTgt spid="8">"#) && slide.contains(r#"<p:bldP spid="8""#));
    // The last effect goes with its click step, the build and the timing.
    let op = delete(&package, 8, true);
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(
        report.effects,
        [Effect::TimingRemoved {
            timing_ids: vec![1, 2, 3, 4, 5, 6]
        }]
    );
    assert!(!part(&package, SLIDE).contains("<p:timing>"));
    let view = DeckView::read(&package).unwrap();
    assert!(view.slides[0].animation.targets.is_empty());
}

#[test]
fn delete_shape_unglues_connectors_and_keeps_relationships() {
    let rels = "ppt/slides/_rels/slide1.xml.rels";
    for (shape, glue, relationship) in [
        (6, r#"<a:endCxn id="6" idx="0"/>"#, "rId3"),
        (3, r#"<a:stCxn id="3" idx="2"/>"#, "rId9"),
    ] {
        let mut package = deck();
        let (input_rels, connector) = (part(&package, rels), shape_xml(&package, SLIDE, 7));
        let op = delete(&package, shape, true);
        let report = structure_patch(&mut package, &op).unwrap();
        assert_eq!(report.changed_parts, [SLIDE]);
        assert_eq!(
            report.effects,
            [
                Effect::Unglued { connector: Some(7) },
                Effect::Unreferenced {
                    relationship: relationship.to_owned()
                }
            ]
        );
        assert_eq!(
            shape_xml(&package, SLIDE, 7),
            connector.replacen(glue, "", 1)
        );
        assert_eq!(part(&package, rels), input_rels);
    }
}

#[test]
fn reparent_keeps_identity_and_slide_geometry() {
    let mut package = deck();
    let (body, before) = (shape_xml(&package, SLIDE, 3), corners_of(&package, 3));
    let op = reparent_to(&package, 3, Some(4));
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    assert!(report.effects.is_empty());
    let moved = shape_xml(&package, SLIDE, 3);
    assert_eq!(
        moved,
        body.replacen(
            r#"<a:off x="1000000" y="2000000"/><a:ext cx="6000000" cy="2000000"/>"#,
            r#"<a:off x="0" y="500000"/><a:ext cx="3000000" cy="1000000"/>"#,
            1
        )
    );
    assert!(shape_xml(&package, SLIDE, 4).ends_with(&format!("{moved}</p:grpSp>")));
    close(corners_of(&package, 3), before);
    // Back to the shape tree: the original frame, now topmost.
    let op = reparent_to(&package, 3, None);
    structure_patch(&mut package, &op).unwrap();
    assert_eq!(shape_xml(&package, SLIDE, 3), body);
    assert_eq!(ids(&package).last(), Some(&Some(3)));
    // Into the turned group: the rotation composes.
    let mut package = deck();
    let op = reparent_to(&package, 3, Some(10));
    structure_patch(&mut package, &op).unwrap();
    let view = DeckView::read(&package).unwrap();
    let shape = view.slides[0]
        .shapes
        .iter()
        .find(|s| s.id == Some(3))
        .unwrap();
    assert_eq!(shape.geometry.rotation.value, Some(16_200_000));
    close(corners_of(&package, 3), before);
    // A group moves with its members.
    let mut package = deck();
    let member = corners_of(&package, 11);
    let op = reparent_to(&package, 10, Some(4));
    structure_patch(&mut package, &op).unwrap();
    close(corners_of(&package, 11), member);
}

#[test]
fn reparent_refuses_illegal_moves() {
    let package = deck();
    let refused = |shape, parent| refuse(&package, &reparent_to(&package, shape, parent));
    assert_eq!(
        refused(4, Some(4)),
        EditRefusal::ReparentUnsupported("into itself or its own descendant")
    );
    assert_eq!(
        refused(5, Some(4)),
        EditRefusal::Invalid("the shape is already in that parent")
    );
    assert_eq!(
        refused(5, None),
        EditRefusal::ReparentUnsupported("the move would empty its group")
    );
    assert_eq!(
        refused(3, Some(6)),
        EditRefusal::ReparentUnsupported("the new parent is not a group")
    );
    assert_eq!(refused(3, Some(99)), EditRefusal::Missing("parent group"));
    assert_eq!(
        refused(3, Some(12)),
        EditRefusal::NonInvertibleGroupTransform
    );
    assert_eq!(
        refused(8, Some(4)),
        EditRefusal::AnimationDependencyUnsupported("an animated shape cannot join a group")
    );
    assert_eq!(refused(2, Some(4)), EditRefusal::InheritedTransform);
    let open = r#"<p:grpSpPr><a:xfrm><a:off x="1000000" y="1000000"/>"#;
    let flipped = with_slide(|slide| {
        slide.replacen(
            open,
            r#"<p:grpSpPr><a:xfrm flipH="1"><a:off x="1000000" y="1000000"/>"#,
            1,
        )
    });
    assert_eq!(
        refuse(&flipped, &reparent_to(&flipped, 3, Some(4))),
        EditRefusal::UnrepresentableTransform("a reflection between the parents")
    );
    let skewed = with_slide(|slide| {
        slide
            .replacen(
                r#"<a:chExt cx="1000000" cy="1000000"/>"#,
                r#"<a:chExt cx="1000000" cy="2000000"/>"#,
                1,
            )
            .replacen(
                r#"<a:xfrm><a:off x="1000000" y="2000000"/>"#,
                r#"<a:xfrm rot="2700000"><a:off x="1000000" y="2000000"/>"#,
                1,
            )
    });
    assert_eq!(
        refuse(&skewed, &reparent_to(&skewed, 3, Some(4))),
        EditRefusal::UnrepresentableTransform("a rotation under a non-uniform scale")
    );
}

#[test]
fn the_check_refuses_an_undeclared_removal() {
    let package = deck();
    let before = DeckView::read(&package).unwrap();
    let (bytes, tree) = xml::read(&package, SLIDE).unwrap();
    let shape = check::find_shape(&tree, 9).unwrap();
    let build = (0..tree.nodes.len())
        .find(|&n| tree.nodes[n].is(P, "bldP"))
        .unwrap();
    let mut next = package.clone();
    let cut = |at: &[usize]| {
        at.iter()
            .map(|&n| (tree.nodes[n].span.clone(), Vec::new()))
            .collect()
    };
    next.replace_xml_part(SLIDE, xml::splice(&bytes, cut(&[shape, build])).unwrap())
        .unwrap();
    let op = delete(&package, 9, true);
    // Built's (8) build entry is not a dependency of Typed (9).
    for removed in [vec![shape, build], vec![shape]] {
        assert!(matches!(
            check::verify(&package, &next, &before, &op, &Plan::Removed(removed)),
            Err(EditRefusal::WriteOutsideTarget { .. })
        ));
    }
}

#[test]
fn delete_shape_refuses_what_its_rules_cannot_see() {
    // A sound timed in the click step does not go with the shape's effect.
    let mut package = deck();
    let op = delete(&package, 9, true);
    structure_patch(&mut package, &op).unwrap();
    let sound = r#"<p:audio><p:cMediaNode><p:cTn id="20"/><p:tgtEl><p:sndTgt r:embed="rId3"/></p:tgtEl></p:cMediaNode></p:audio>"#;
    let slide = part(&package, SLIDE).replacen(
        r#"<p:par><p:cTn id="5" "#,
        &format!(r#"{sound}<p:par><p:cTn id="5" "#),
        1,
    );
    let mut voiced = package.clone();
    voiced.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    assert!(matches!(
        refuse(&voiced, &delete(&voiced, 8, true)),
        EditRefusal::AnimationDependencyUnsupported(_)
    ));

    // A surviving effect that starts when the deleted one's ends.
    let waiting = with_slide(|slide| {
        slide.replacen(
            r#"nodeType="clickEffect"><p:stCondLst><p:cond delay="0"/></p:stCondLst>"#,
            r#"nodeType="clickEffect"><p:stCondLst><p:cond evt="onEnd" delay="0"><p:tn val="7"/></p:cond></p:stCondLst>"#,
            1,
        )
    });
    assert!(matches!(
        refuse(&waiting, &delete(&waiting, 9, true)),
        EditRefusal::AnimationDependencyUnsupported(_)
    ));

    // A group whose member the view does not enter is animated.
    let typed = shape_xml(&deck(), SLIDE, 9);
    let wrapped = format!(
        r#"<p:grpSp><p:nvGrpSpPr><p:cNvPr id="50" name="Wrapper"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="10" cy="10"/><a:chOff x="0" y="0"/><a:chExt cx="10" cy="10"/></a:xfrm></p:grpSpPr><p:sp><p:nvSpPr><p:cNvPr id="51" name="Visible"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="5" cy="5"/></a:xfrm></p:spPr></p:sp><mc:AlternateContent xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><mc:Choice Requires="p14">{typed}</mc:Choice><mc:Fallback>{typed}</mc:Fallback></mc:AlternateContent></p:grpSp>"#
    );
    let hidden = with_slide(|slide| slide.replacen(&typed, &wrapped, 1));
    assert!(matches!(
        refuse(&hidden, &delete(&hidden, 50, false)),
        EditRefusal::AnimationDependencyUnsupported(_)
    ));
}

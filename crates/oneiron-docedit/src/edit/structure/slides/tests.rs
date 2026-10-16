//! Slide-level acceptance: a copy repairs its notes backlink, leaves the
//! comments behind, keeps every relationship id with its target shared,
//! cloned or repointed by the policy, allocates its slide id above the
//! high-water marks and owns a chart isolated from its source's; a reorder
//! rewrites only the slide list and keeps sections whole; what the policy
//! does not cover refuses, and the independent checks refuse an undeclared
//! change. Every refusal leaves the package byte-identical.
use super::super::tests::refuse;
use super::super::{NewShape, Preset, StructureEdit, structure_patch};
use super::*;
use crate::deck::SlideView;
use crate::deck::fixture::{NS, limits};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset, Rect};
use crate::edit::tests::{SLIDE, deck, part, target, timing, with_notes_master};
use crate::edit::{ValueEdit, edit};
use crate::native_patch::{ChartFamily, Frame, NativeEdit, Target as Series, native_patch};
use crate::retained_opc::rels_name;

const SECOND: &str = "ppt/slides/slide2.xml";
const COPY: &str = "ppt/slides/slide3.xml";
const PRESENTATION: &str = "ppt/presentation.xml";
const NOTES: &str = "ppt/notesSlides/notesSlide1.xml";
const NOTES_COPY: &str = "ppt/notesSlides/notesSlide2.xml";
const CHART: &str = "ppt/charts/chart1.xml";
const CHART_COPY: &str = "ppt/charts/chart2.xml";
const BOOK: &str = "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx";
const BOOK_COPY: &str = "ppt/embeddings/Microsoft_Excel_Worksheet2.xlsx";
const STYLES: [(&str, &str, &str); 2] = [
    (
        "ppt/charts/style1.xml",
        "application/vnd.ms-office.chartstyle+xml",
        "chartStyle",
    ),
    (
        "ppt/charts/colors1.xml",
        "application/vnd.ms-office.chartcolorstyle+xml",
        "chartColorStyle",
    ),
];
const LEGACY: &str = "ppt/comments/comment1.xml";
const MODERN: &str = "ppt/comments/modernComment_100_5E1D2A3B.xml";
const P188: &str = "http://schemas.microsoft.com/office/powerpoint/2018/8/main";
const TITLE_GUID: &str = "{6C1F0A52-93E4-4B7D-A1C2-0D9E8F7A6B5C}";
const SECTIONS: &str = r#"<p:extLst><p:ext uri="{521415D9-36F7-43E2-AB2F-B90AF26B5E84}"><p14:sectionLst><p14:section name="Intro" id="{0A1B2C3D-0000-4000-8000-000000000001}"><p14:sldIdLst><p14:sldId id="256"/></p14:sldIdLst></p14:section><p14:section name="Body" id="{0A1B2C3D-0000-4000-8000-000000000002}"><p14:sldIdLst><p14:sldId id="257"/></p14:sldIdLst></p14:section></p14:sectionLst></p:ext></p:extLst>"#;

/// The edit fixture deck plus what a copy must clone, share or leave out: a
/// chart with its workbook, style and colours, legacy and modern comments, a
/// shape creation id, two sections and a custom show.
fn rich() -> Package {
    let mut package = deck();
    let data = Dataset {
        id: "data".into(),
        columns: [("Quarter", ColumnKind::Text), ("North", ColumnKind::Number)]
            .map(|(name, kind)| Column {
                name: name.into(),
                kind,
                unit: None,
            })
            .to_vec(),
        rows: vec![
            vec![Cell::Text("Q1".into()), Cell::Number(10.5)],
            vec![Cell::Text("Q2".into()), Cell::Number(8.25)],
            vec![Cell::Text("Q3".into()), Cell::Number(12.0)],
        ],
        missing: None,
        sources: vec!["source".into()],
    };
    let frame = Frame {
        slide: SLIDE,
        id: 40,
        name: "Chart",
        bounds: Rect {
            x: 457_200,
            y: 457_200,
            cx: 6_000_000,
            cy: 3_000_000,
        },
        placeholder: None,
    };
    native_patch(
        &mut package,
        &NativeEdit::CreateChart {
            frame,
            family: ChartFamily::Bar,
            dataset: &data,
            chart: CHART,
            workbook: BOOK,
            sheet: "Data",
        },
    )
    .unwrap();
    let cs = "http://schemas.microsoft.com/office/drawing/2012/chartStyle";
    for ((name, content_type, kind), root) in STYLES.into_iter().zip([
        format!(r#"<cs:chartStyle xmlns:cs="{cs}" id="201"/>"#),
        format!(r#"<cs:colorStyle xmlns:cs="{cs}" meth="cycle" id="10"/>"#),
    ]) {
        package
            .add_part(name, content_type, root.into_bytes())
            .unwrap();
        let kind = format!("http://schemas.microsoft.com/office/2011/relationships/{kind}");
        package.relate(CHART, &kind, name).unwrap();
    }
    package
        .add_part(
            LEGACY,
            "application/vnd.openxmlformats-officedocument.presentationml.comments+xml",
            format!("<p:cmLst {NS}/>").into_bytes(),
        )
        .unwrap();
    package
        .relate(SLIDE, &format!("{R}/comments"), LEGACY)
        .unwrap();
    package
        .add_part(
            MODERN,
            "application/vnd.ms-powerpoint.comments+xml",
            format!(r#"<p188:cmLst xmlns:p188="{P188}"/>"#).into_bytes(),
        )
        .unwrap();
    let modern = package.relate(SLIDE, MODERN_COMMENTS, MODERN).unwrap();
    let slide = part(&package, SLIDE)
        .replacen(
            r#"<p:cNvPr id="2" name="Title 1"/>"#,
            &format!(
                r#"<p:cNvPr id="2" name="Title 1"><a:extLst><a:ext uri="{{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}}"><a16:creationId id="{TITLE_GUID}"/></a:ext></a:extLst></p:cNvPr>"#
            ),
            1,
        )
        .replace(
            "</p:sld>",
            &format!(
                r#"<p:extLst><p:ext uri="{COMMENT_EXT}"><p188:commentRel xmlns:p188="{P188}" r:id="{modern}"/></p:ext></p:extLst></p:sld>"#
            ),
        );
    package.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    let presentation = part(&package, PRESENTATION).replace(
        "</p:presentation>",
        &format!(
            r#"<p:custShowLst><p:custShow name="Short" id="0"><p:sldLst><p:sld r:id="rId2"/></p:sldLst></p:custShow></p:custShowLst>{SECTIONS}</p:presentation>"#
        ),
    );
    package
        .replace_xml_part(PRESENTATION, presentation.into_bytes())
        .unwrap();
    Package::open(&package.export().unwrap(), limits()).unwrap()
}

/// Copy `slide`, read with its current render fingerprint.
fn duplicate(
    package: &Package,
    slide: &'static str,
    high_water: u32,
    seed: &'static [u8],
) -> StructureEdit<'static> {
    let view = DeckView::read(package).unwrap();
    let expected = view
        .slides
        .iter()
        .find(|s| s.part == slide)
        .unwrap()
        .render_fingerprint;
    StructureEdit::DuplicateSlide {
        slide,
        expected,
        high_water,
        seed,
    }
}

/// `(id, kind suffix, target)` of each relationship of `source`.
fn rels(package: &Package, source: &str) -> Vec<(String, String, String)> {
    package
        .relationships(source)
        .unwrap()
        .into_iter()
        .map(|r| {
            let kind = r.kind.rsplit('/').next().unwrap().to_owned();
            (r.id, kind, r.target)
        })
        .collect()
}

fn set<'a>(chart: &'a str, values: &'a [Cell]) -> NativeEdit<'a> {
    NativeEdit::SetSeries {
        chart,
        series: 0,
        target: Series::Values,
        values,
    }
}

fn sld_ids(package: &Package) -> Vec<u32> {
    let view = DeckView::read(package).unwrap();
    view.slides.iter().map(|s| s.sld_id).collect()
}

#[test]
fn duplicate_slide_clones_notes_and_charts_and_shares_the_rest() {
    let mut package = rich();
    let input = package.clone();
    let report = structure_patch(&mut package, &duplicate(&input, SLIDE, 300, b"copy")).unwrap();
    let mut changed = report.changed_parts.clone();
    changed.sort();
    let mut want = vec![
        "[Content_Types].xml",
        "ppt/_rels/presentation.xml.rels",
        "ppt/charts/_rels/chart2.xml.rels",
        CHART_COPY,
        "ppt/charts/colors2.xml",
        "ppt/charts/style2.xml",
        BOOK_COPY,
        "ppt/notesSlides/_rels/notesSlide2.xml.rels",
        NOTES_COPY,
        PRESENTATION,
        "ppt/slides/_rels/slide3.xml.rels",
        COPY,
    ];
    want.sort_unstable();
    assert_eq!(changed, want);

    let view = DeckView::read(&package).unwrap();
    let parts: Vec<&str> = view.slides.iter().map(|s| s.part.as_str()).collect();
    assert_eq!(parts, [SLIDE, COPY, SECOND]);
    let (source, copy) = (&view.slides[0], &view.slides[1]);
    assert_eq!(copy.sld_id, 301);
    assert!(
        copy.creation_id
            .is_some_and(|id| ![1001, 1002].contains(&id))
    );
    assert_eq!(copy.layout, source.layout);
    let who = |s: &SlideView| -> Vec<_> {
        s.shapes
            .iter()
            .map(|x| (x.id, x.kind, x.name.clone(), x.group_path.clone()))
            .collect()
    };
    assert_eq!(who(copy), who(source));
    let title = |s: &SlideView| s.shapes[0].creation_id.clone();
    assert_eq!(title(source).as_deref(), Some(TITLE_GUID));
    assert!(title(copy).is_some_and(|guid| guid != TITLE_GUID));
    assert_eq!(
        report.effects[0],
        Effect::SlideAdded {
            part: COPY.into(),
            sld_id: 301,
            creation_id: copy.creation_id,
        }
    );

    // Same ids; layout, picture and link shared; notes and chart cloned;
    // both comment relationships left with the source.
    let source_rels = rels(&package, SLIDE);
    let kept: Vec<_> = source_rels
        .iter()
        .filter(|(_, kind, _)| kind != "comments")
        .map(|(id, kind, target)| {
            let target = match target.as_str() {
                NOTES => NOTES_COPY,
                CHART => CHART_COPY,
                other => other,
            };
            (id.clone(), kind.clone(), target.to_owned())
        })
        .collect();
    assert_eq!(rels(&package, COPY), kept);
    let omitted: Vec<_> = source_rels
        .iter()
        .filter(|(_, kind, _)| kind == "comments")
        .map(|(id, ..)| Effect::CommentsOmitted {
            relationship: id.clone(),
        })
        .collect();
    assert_eq!(omitted.len(), 2);
    assert!(omitted.iter().all(|effect| report.effects.contains(effect)));
    assert!(!part(&package, COPY).contains("commentRel"));
    assert!(part(&package, SLIDE).contains("commentRel"));

    // The copied notes point back at the copy; the source's still at the
    // source.
    assert_eq!(part(&package, NOTES_COPY), part(&input, NOTES));
    let backlink = |source: &str| -> Vec<String> {
        rels(&package, source)
            .into_iter()
            .filter(|(_, kind, _)| kind == "slide")
            .map(|(.., target)| target)
            .collect()
    };
    assert_eq!(backlink(NOTES_COPY), [COPY]);
    assert_eq!(backlink(NOTES), [SLIDE]);

    // The chart's closure is cloned whole, byte for byte.
    let targets: Vec<String> = rels(&package, CHART_COPY)
        .into_iter()
        .map(|(.., target)| target)
        .collect();
    assert_eq!(
        targets,
        [BOOK_COPY, "ppt/charts/style2.xml", "ppt/charts/colors2.xml"]
    );
    for (from, to) in [
        (CHART, CHART_COPY),
        (BOOK, BOOK_COPY),
        (STYLES[0].0, "ppt/charts/style2.xml"),
        (STYLES[1].0, "ppt/charts/colors2.xml"),
    ] {
        assert_eq!(package.part(to).unwrap(), input.part(from).unwrap(), "{to}");
        assert!(report.effects.contains(&Effect::PartCloned {
            from: from.into(),
            to: to.into(),
        }));
    }

    // After the source in the slide list and in its section; the custom
    // show is not given the copy.
    let presentation = part(&package, PRESENTATION);
    assert!(presentation.contains(
        r#"<p:sldIdLst><p:sldId id="256" r:id="rId2"/><p:sldId id="301" r:id="rId6"/><p:sldId id="257" r:id="rId3"/></p:sldIdLst>"#
    ));
    assert!(
        presentation
            .contains(r#"<p14:sldIdLst><p14:sldId id="256"/><p14:sldId id="301"/></p14:sldIdLst>"#)
    );
    assert!(presentation.contains(r#"<p:sldLst><p:sld r:id="rId2"/></p:sldLst>"#));
    assert!(report.effects.contains(&Effect::NotInCustomShow {
        show: "Short".into()
    }));
    let edited = [
        PRESENTATION,
        "ppt/_rels/presentation.xml.rels",
        "[Content_Types].xml",
    ];
    for name in input.names().filter(|name| !edited.contains(name)) {
        assert_eq!(
            package.part(name).unwrap(),
            input.part(name).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_copied_chart_is_isolated_from_its_source() {
    let mut package = rich();
    let op = duplicate(&package, SLIDE, 0, b"copy");
    structure_patch(&mut package, &op).unwrap();
    let values = [1.0, 2.0, 3.0].map(Cell::Number);
    let before = package.clone();
    native_patch(&mut package, &set(CHART_COPY, &values)).unwrap();
    for name in [CHART, BOOK] {
        assert_eq!(package.part(name).unwrap(), before.part(name).unwrap());
    }
    for name in [CHART_COPY, BOOK_COPY] {
        assert_ne!(package.part(name).unwrap(), before.part(name).unwrap());
    }
    let before = package.clone();
    let values = [7.0, 8.0, 9.0].map(Cell::Number);
    native_patch(&mut package, &set(CHART, &values)).unwrap();
    for name in [CHART_COPY, BOOK_COPY] {
        assert_eq!(package.part(name).unwrap(), before.part(name).unwrap());
    }
}

#[test]
fn duplicate_slide_allocates_above_the_high_water_marks() {
    let package = deck();
    let mut copied = package.clone();
    structure_patch(&mut copied, &duplicate(&package, SECOND, 0, b"a")).unwrap();
    assert_eq!(sld_ids(&copied), [256, 257, 258]);
    let op = duplicate(&copied, SLIDE, 0, b"b");
    structure_patch(&mut copied, &op).unwrap();
    assert_eq!(sld_ids(&copied), [256, 259, 257, 258]);

    let mut high = package.clone();
    structure_patch(&mut high, &duplicate(&package, SECOND, 400, b"a")).unwrap();
    assert_eq!(sld_ids(&high), [256, 257, 401]);
    let op = duplicate(&package, SECOND, (1 << 31) - 1, b"a");
    assert_eq!(refuse(&package, &op), EditRefusal::IdSpaceExhausted);

    // The copy's creation id comes from the seed and is drawn again when
    // another slide already holds it.
    let first = mint_creation_id(b"a", &[]).unwrap();
    let mut taken = package.clone();
    let slide = part(&taken, SLIDE).replace(r#"val="1001""#, &format!(r#"val="{first}""#));
    taken.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    let op = duplicate(&taken, SECOND, 0, b"a");
    structure_patch(&mut taken, &op).unwrap();
    let view = DeckView::read(&taken).unwrap();
    let ids: Vec<Option<u32>> = view.slides.iter().map(|s| s.creation_id).collect();
    assert_eq!(ids[0], Some(first));
    assert!(ids[2].is_some_and(|id| id != first && id != 1002));

    // A part name at the end of the counter refuses instead of wrapping.
    let mut full = package.clone();
    full.add_part(
        "ppt/slides/slide18446744073709551615.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
        part(&package, SECOND).into_bytes(),
    )
    .unwrap();
    let op = duplicate(&full, SECOND, 0, b"a");
    assert_eq!(refuse(&full, &op), EditRefusal::IdSpaceExhausted);
}

#[test]
fn duplicate_slide_keeps_repeated_creation_ids_paired() {
    let mut package = deck();
    let tagged = |id: u32, name: &str, spelled: &str| {
        (
            format!(r#"<p:cNvPr id="{id}" name="{name}"/>"#),
            format!(
                r#"<p:cNvPr id="{id}" name="{name}"><a:extLst><a:ext uri="{{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}}"><a16:creationId id="{spelled}"/></a:ext></a:extLst></p:cNvPr>"#
            ),
        )
    };
    let mut slide = part(&package, SLIDE);
    let lower = TITLE_GUID.to_ascii_lowercase();
    for (from, to) in [tagged(2, "Title 1", TITLE_GUID), tagged(3, "Body", &lower)] {
        assert!(slide.contains(&from));
        slide = slide.replacen(&from, &to, 1);
    }
    package.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    let op = duplicate(&package, SLIDE, 0, b"pair");
    structure_patch(&mut package, &op).unwrap();
    let view = DeckView::read(&package).unwrap();
    let ids = |s: &SlideView| -> Vec<Option<String>> {
        s.shapes[..2]
            .iter()
            .map(|x| x.creation_id.clone())
            .collect()
    };
    let (source, copy) = (ids(&view.slides[0]), ids(&view.slides[1]));
    assert_eq!(source[0], source[1]);
    assert_eq!(copy[0], copy[1]);
    assert!(copy[0].is_some() && copy[0] != source[0]);
}

#[test]
fn duplicate_slide_refuses_what_it_cannot_clone() {
    let package = rich();
    let mut op = duplicate(&package, SLIDE, 0, b"x");
    if let StructureEdit::DuplicateSlide { expected, .. } = &mut op {
        expected[0] ^= 1;
    }
    assert_eq!(refuse(&package, &op), EditRefusal::TargetChanged);
    let op = StructureEdit::DuplicateSlide {
        slide: "ppt/slides/slide9.xml",
        expected: [0; 32],
        high_water: 0,
        seed: b"x",
    };
    assert_eq!(refuse(&package, &op), EditRefusal::Missing("slide"));

    // Dependencies outside the tested policy: slide tags, chart drawings.
    let mut tagged = package.clone();
    tagged
        .add_part(
            "ppt/tags/tag1.xml",
            "application/vnd.openxmlformats-officedocument.presentationml.tags+xml",
            format!("<p:tagLst {NS}/>").into_bytes(),
        )
        .unwrap();
    let tags = format!("{R}/tags");
    tagged.relate(SLIDE, &tags, "ppt/tags/tag1.xml").unwrap();
    let op = duplicate(&tagged, SLIDE, 0, b"x");
    assert_eq!(
        refuse(&tagged, &op),
        EditRefusal::CloneDependencyUnsupported(tags)
    );
    let mut drawn = package.clone();
    drawn
        .add_part(
            "ppt/drawings/drawing1.xml",
            "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml",
            br#"<c:userShapes xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"/>"#
                .to_vec(),
        )
        .unwrap();
    let shapes = format!("{R}/chartUserShapes");
    drawn
        .relate(CHART, &shapes, "ppt/drawings/drawing1.xml")
        .unwrap();
    let op = duplicate(&drawn, SLIDE, 0, b"x");
    assert_eq!(
        refuse(&drawn, &op),
        EditRefusal::CloneDependencyUnsupported(shapes)
    );
}

#[test]
fn reorder_slides_rewrites_only_the_slide_list() {
    let mut package = deck();
    let input = package.clone();
    let op = StructureEdit::ReorderSlides { order: &[257, 256] };
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [PRESENTATION]);
    assert!(report.effects.is_empty());
    let view = DeckView::read(&package).unwrap();
    let parts: Vec<&str> = view.slides.iter().map(|s| s.part.as_str()).collect();
    assert_eq!(parts, [SECOND, SLIDE]);
    assert!(part(&package, PRESENTATION).contains(
        r#"<p:sldIdLst><p:sldId id="257" r:id="rId3"/><p:sldId id="256" r:id="rId2"/></p:sldIdLst>"#
    ));
    for order in [&[256, 257][..], &[257], &[257, 257], &[257, 256, 258]] {
        let op = StructureEdit::ReorderSlides { order };
        assert!(matches!(refuse(&input, &op), EditRefusal::Invalid(_)));
    }
}

#[test]
fn reorder_slides_keeps_each_section_whole_and_in_order() {
    let mut package = rich();
    let op = duplicate(&package, SLIDE, 300, b"copy");
    structure_patch(&mut package, &op).unwrap();
    // Intro holds 256 and 301, Body 257.
    for order in [[256, 257, 301], [257, 256, 301]] {
        let op = StructureEdit::ReorderSlides { order: &order };
        assert!(matches!(
            refuse(&package, &op),
            EditRefusal::ReorderUnsupported(_)
        ));
    }
    let input = package.clone();
    let op = StructureEdit::ReorderSlides {
        order: &[301, 256, 257],
    };
    let report = structure_patch(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [PRESENTATION]);
    assert_eq!(sld_ids(&package), [301, 256, 257]);
    let presentation = part(&package, PRESENTATION);
    assert!(
        presentation
            .contains(r#"<p14:sldIdLst><p14:sldId id="301"/><p14:sldId id="256"/></p14:sldIdLst>"#)
    );
    assert!(presentation.contains(r#"<p14:sldIdLst><p14:sldId id="257"/></p14:sldIdLst>"#));

    // A slide in no section leaves the order unprovable.
    let mut loose = input.clone();
    let presentation = part(&input, PRESENTATION).replace(r#"<p14:sldId id="257"/>"#, "");
    loose
        .replace_xml_part(PRESENTATION, presentation.into_bytes())
        .unwrap();
    let op = StructureEdit::ReorderSlides {
        order: &[301, 256, 257],
    };
    assert!(matches!(
        refuse(&loose, &op),
        EditRefusal::ReorderUnsupported(_)
    ));

    // Entries spelled apart keep their own bytes when they trade places.
    let mut spelled = rich();
    let presentation = part(&spelled, PRESENTATION).replace(
        r#"<p14:sldId id="256"/></p14:sldIdLst></p14:section><p14:section name="Body" id="{0A1B2C3D-0000-4000-8000-000000000002}"><p14:sldIdLst><p14:sldId id="257"/>"#,
        r#"<p14:sldId id="256"/><p14:sldId id="257" /></p14:sldIdLst></p14:section><p14:section name="Body" id="{0A1B2C3D-0000-4000-8000-000000000002}"><p14:sldIdLst>"#,
    );
    assert!(presentation.contains(r#"<p14:sldId id="257" />"#));
    spelled
        .replace_xml_part(PRESENTATION, presentation.into_bytes())
        .unwrap();
    let op = StructureEdit::ReorderSlides { order: &[257, 256] };
    structure_patch(&mut spelled, &op).unwrap();
    assert!(
        part(&spelled, PRESENTATION).contains(
            r#"<p14:sldIdLst><p14:sldId id="257" /><p14:sldId id="256"/></p14:sldIdLst>"#
        )
    );
}

#[test]
fn the_slide_checks_refuse_undeclared_changes() {
    let package = rich();
    let before = DeckView::read(&package).unwrap();
    let op = duplicate(&package, SLIDE, 0, b"copy");
    let StructureEdit::DuplicateSlide {
        slide,
        expected,
        high_water,
        seed,
    } = op
    else {
        unreachable!()
    };
    let mut next = package.clone();
    let (Plan::Duplicated(copy), _) =
        super::duplicate(&mut next, &before, slide, expected, high_water, seed).unwrap()
    else {
        panic!("not a copy plan")
    };
    assert!(check::duplicated(&package, &next, &before, &op, &copy).is_ok());

    // A write to the source's notes is outside the copy's parts.
    let mut touched = next.clone();
    let notes = part(&next, NOTES).replace("Speak slowly", "Speak fast");
    touched.replace_xml_part(NOTES, notes.into_bytes()).unwrap();
    assert_eq!(
        check::duplicated(&package, &touched, &before, &op, &copy),
        Err(EditRefusal::PartDiffOutsideTransaction(NOTES.into()))
    );
    // A copy that shares its source's chart instead of owning a clone.
    let mut shared = next.clone();
    let copy_rels = rels_name(COPY);
    let repointed = part(&next, &copy_rels).replace("chart2.xml", "chart1.xml");
    shared
        .replace_xml_part(&copy_rels, repointed.into_bytes())
        .unwrap();
    assert!(matches!(
        check::duplicated(&package, &shared, &before, &op, &copy),
        Err(EditRefusal::WriteOutsideTarget { .. })
    ));

    // A reordered slide list beside another presentation write.
    let package = deck();
    let before = DeckView::read(&package).unwrap();
    let swapped = part(&package, PRESENTATION)
        .replace(
            r#"<p:sldId id="256" r:id="rId2"/><p:sldId id="257" r:id="rId3"/>"#,
            r#"<p:sldId id="257" r:id="rId3"/><p:sldId id="256" r:id="rId2"/>"#,
        )
        .replace(r#"cx="12192000""#, r#"cx="9144000""#);
    let mut next = package.clone();
    next.replace_xml_part(PRESENTATION, swapped.into_bytes())
        .unwrap();
    assert!(matches!(
        check::reordered(&package, &next, &before, &[257, 256]),
        Err(EditRefusal::WriteOutsideTarget { .. })
    ));
}

/// The emitted oracle deck with a notes master, a click and a with effect on
/// slide 4 and notes on the chart slide, then each structural verb once: the
/// copy of the chart slide clones its notes and both charts, and the reorder
/// moves the last slide second.
#[test]
#[ignore = "writes the Office-oracle candidate to $ONEIRON_EDIT_CANDIDATE"]
fn office_oracle_candidate() {
    let slide = |n: u32| format!("ppt/slides/slide{n}.xml");
    let (four, five, nine) = (slide(4), slide(5), slide(9));
    let emitted = crate::emit::tests::oracle_deck().bytes;
    let mut package = Package::open(&emitted, limits()).unwrap();
    with_notes_master(&mut package);
    let effects = timing()
        .replace(r#"spid="8""#, r#"spid="3""#)
        .replace(r#"spid="9""#, r#"spid="4""#);
    let animated = part(&package, &four).replace("</p:sld>", &format!("{effects}</p:sld>"));
    package
        .replace_xml_part(&four, animated.into_bytes())
        .unwrap();
    let op = ValueEdit::SetNotes {
        slide: "ppt/slides/slide3.xml",
        expected: None,
        text: "Read the two charts side by side.",
    };
    edit(&mut package, &op).unwrap();
    let base = package.export().unwrap();
    let mut package = Package::open(&base, limits()).unwrap();

    let shape = NewShape {
        preset: Preset::RoundRect,
        name: "Callout",
        offset: (5_486_400, 4_572_000),
        extent: (2_743_200, 1_143_000),
        high_water: 3,
        seed: b"oracle shape",
    };
    let add = StructureEdit::AddShape {
        slide: &five,
        shape,
    };
    let delete = StructureEdit::DeleteShape {
        target: target(&package, &four, 4),
        cascade: true,
    };
    let reparent = StructureEdit::Reparent {
        target: target(&package, &nine, 5),
        parent: None,
    };
    for (verb, op) in [
        ("add_shape", add),
        ("delete_shape", delete),
        ("reparent", reparent),
    ] {
        let report = structure_patch(&mut package, &op).unwrap();
        println!("{verb} {:?}", report.effects);
    }
    let op = duplicate(&package, "ppt/slides/slide3.xml", 264, b"oracle copy");
    let report = structure_patch(&mut package, &op).unwrap();
    println!("duplicate_slide {:?}", report.effects);
    let mut order = sld_ids(&package);
    let last = order.pop().unwrap();
    order.insert(1, last);
    let op = StructureEdit::ReorderSlides { order: &order };
    let report = structure_patch(&mut package, &op).unwrap();
    println!("reorder_slides {order:?} {:?}", report.effects);
    assert_eq!(sld_ids(&package), order);

    let path = std::env::var("ONEIRON_EDIT_CANDIDATE").unwrap();
    std::fs::write(format!("{path}.base"), &base).unwrap();
    std::fs::write(&path, package.export().unwrap()).unwrap();
}

//! ONE-2536 acceptance: an end-to-end plan over the ONE-2533 template is
//! emitted into a candidate that places and traces every block, writes only
//! what the plan's package row allows, never writes `fontScale`, and reports
//! `FitUnverified` for laid-out text; the independent checks refuse a
//! tampered candidate. The opt-in last test writes the Office-oracle
//! candidate over the oracle's own clean deck.
use super::*;
use crate::deck::fixture::{archive, limits};
use crate::deck::{DeckView, ShapeKind, ShapeView, SlideView};
use crate::design_plan::tests::{bare_parts, brief, bytes, kept, page, template_parts, title};
use crate::design_plan::{AssetBinding, Cell, Content, DesignPlan, Destination, MediaType};
use crate::design_plan::{CompileError, Outcome, TraceOutcome, compile};
use crate::graphic::{AssetRecord, GraphicLimits};
use crate::graphic::{GraphicError, Origin};
use crate::native_patch::chart_data;
use crate::retained_opc::Package;
use crate::retained_opc::{Relationship, rels_name};
use flate2::{Compression, write::ZlibEncoder};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{Read, Write};

/// Configured names, deliberately not English: nothing is a constant.
const NAMES: Names<'static> = Names {
    text: "Zone de texte",
    table: "Tableau",
    chart: "Graphique",
    picture: "Image",
    figure: "Groupe",
    sheet: "Feuil1",
};
const VERSION: &str = "brief@7";
const FLOW: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" viewBox="0 0 200 100"><rect x="10" y="20" width="80" height="60" fill="#4F81BD"/><circle cx="150" cy="50" r="30" fill="#C0504D"/></svg>"##;

/// A decodable RGB PNG, so the oracle has pixels to render.
fn png(width: u32, height: u32, rgb: [u8; 3]) -> Vec<u8> {
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
    header.extend([8, 2, 0, 0, 0]);
    let row: Vec<u8> = std::iter::once(0)
        .chain(rgb.iter().copied().cycle().take(3 * width as usize))
        .collect();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    for _ in 0..height {
        encoder.write_all(&row).unwrap();
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &encoder.finish().unwrap());
    chunk(&mut out, b"IEND", &[]);
    out
}

fn record(handle: &str, media: MediaType, bytes: &[u8], origin: Origin) -> AssetRecord {
    AssetRecord {
        artifact: handle.to_owned(),
        version: 1,
        content_hash: *blake3::hash(bytes).as_bytes(),
        media,
        origin,
        provenance: vec!["claim:site-survey".to_owned()],
        rights: Vec::new(),
        description: format!("Described {handle}"),
    }
}

/// ONE-2533's brief plus a page carrying an SVG diagram.
fn the_brief() -> Value {
    let mut brief = brief();
    brief["pages"].as_array_mut().unwrap().push(page(
        "process",
        "fixed",
        vec![
            title("i-title", "How work flows"),
            json!({"id": "i-flow", "kind": "asset", "asset": "flow"}),
        ],
    ));
    brief["assets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "flow", "kind": "factual", "content": "Flow of work"}));
    brief
}

struct Fixture {
    template: Package,
    brief: Vec<u8>,
    bindings: BTreeMap<String, AssetBinding>,
    records: BTreeMap<String, (AssetRecord, Vec<u8>)>,
}

impl Fixture {
    fn new(template: Package, brief: &Value) -> Self {
        let site = png(64, 48, [0x4F, 0x81, 0xBD]);
        let records = BTreeMap::from([
            (
                "plan".to_owned(),
                (
                    record("blob:site-plan", MediaType::Png, &site, Origin::Held),
                    site,
                ),
            ),
            (
                "flow".to_owned(),
                (
                    record(
                        "blob:flow",
                        MediaType::Svg,
                        FLOW.as_bytes(),
                        Origin::Diagram,
                    ),
                    FLOW.as_bytes().to_vec(),
                ),
            ),
        ]);
        let bindings = records
            .iter()
            .map(|(id, (record, _))| {
                (
                    id.clone(),
                    AssetBinding {
                        handle: record.artifact.clone(),
                        media: record.media,
                    },
                )
            })
            .collect();
        Self {
            template,
            brief: bytes(brief),
            bindings,
            records,
        }
    }

    fn parts(parts: &[(&str, String)]) -> Self {
        Self::new(
            Package::open(&archive(parts), limits()).unwrap(),
            &the_brief(),
        )
    }

    fn plan(&self) -> DesignPlan {
        match compile(&kept(VERSION, &self.brief), &self.template, &self.bindings).unwrap() {
            Outcome::Plan(plan) => *plan,
            Outcome::Ask(decisions) => panic!("expected a plan, got {decisions:?}"),
        }
    }

    fn stored(&self) -> BTreeMap<String, StoredAsset<'_>> {
        self.records
            .iter()
            .map(|(id, (record, bytes))| {
                (
                    id.clone(),
                    StoredAsset {
                        record,
                        bytes: Some(bytes),
                    },
                )
            })
            .collect()
    }

    fn emit_with(
        &self,
        plan: &DesignPlan,
        brief: &[u8],
        assets: &BTreeMap<String, StoredAsset<'_>>,
    ) -> Result<Candidate, EmitError> {
        emit(
            plan,
            &EmitInputs {
                kept: kept(VERSION, brief),
                template: &self.template,
                assets,
                names: NAMES,
                limits: GraphicLimits::default(),
            },
        )
    }

    fn emit(&self, plan: &DesignPlan) -> Candidate {
        self.emit_with(plan, &self.brief, &self.stored()).unwrap()
    }
}

fn unit<'r>(report: &'r Report, block: &str) -> (&'r EmittedSlide, &'r Unit) {
    report
        .slides
        .iter()
        .find_map(|slide| {
            slide
                .units
                .iter()
                .find(|unit| unit.block == block)
                .map(|unit| (slide, unit))
        })
        .unwrap()
}

fn shape<'v>(view: &'v DeckView, slide: &str, id: u32) -> &'v ShapeView {
    let slide: &SlideView = view.slides.iter().find(|s| s.part == slide).unwrap();
    slide.shapes.iter().find(|s| s.id == Some(id)).unwrap()
}

fn text(shape: &ShapeView) -> Vec<String> {
    shape
        .text
        .as_ref()
        .unwrap()
        .paragraphs
        .iter()
        .map(|paragraph| paragraph.runs.iter().map(|run| run.text.as_str()).collect())
        .collect()
}

fn reopen(candidate: &Candidate) -> Package {
    Package::open(&candidate.bytes, limits()).unwrap()
}

#[test]
fn every_planned_block_is_placed_traced_and_read_back() {
    let fixture = Fixture::parts(&bare_parts());
    let plan = fixture.plan();
    let candidate = fixture.emit(&plan);
    let report = &candidate.report;
    assert_eq!(report.born_from, *plan.approved());
    assert_eq!(report.template, *plan.template());
    assert_eq!(candidate.hash, *blake3::hash(&candidate.bytes).as_bytes());

    // One unit per placement, in plan order, on its planned slide: emission
    // adds nothing the plan does not hold.
    assert_eq!(report.slides.len(), plan.slides().len());
    for (planned, emitted) in plan.slides().iter().zip(&report.slides) {
        assert_eq!(
            (emitted.part.as_str(), emitted.layout.as_str()),
            (planned.part.as_str(), planned.layout.as_str())
        );
        let units: Vec<_> = emitted
            .units
            .iter()
            .map(|unit| (&unit.block, &unit.content, &unit.destination))
            .collect();
        let placements: Vec<_> = planned
            .placements
            .iter()
            .map(|placement| (&placement.block, &placement.content, &placement.destination))
            .collect();
        assert_eq!(units, placements);
    }
    for entry in plan.trace() {
        match &entry.outcome {
            TraceOutcome::Placed(at) => {
                for &(slide, placement) in at {
                    assert_eq!(report.slides[slide].units[placement].block, entry.block);
                }
            }
            TraceOutcome::Omitted => assert!(report.omitted.contains(&entry.block)),
        }
    }
    assert_eq!(report.omitted, ["f-detail"]);

    // Claims carry their evidence pins; a drifted pin stays marked.
    let (_, claim) = unit(report, "a-claim");
    let trace = claim.claim.as_ref().unwrap();
    assert!(trace.drifted);
    assert_eq!(
        trace.evidence[0].quote,
        "Revenue grew from 4.1 to 8.3 million."
    );
    assert!(unit(report, "a-title").1.claim.is_none());

    // The candidate reads back slide by slide, in plan order, with the
    // planned text in the planned placeholders.
    let package = reopen(&candidate);
    let view = DeckView::read(&package).unwrap();
    assert!(view.ambiguities.is_empty());
    let parts: Vec<&str> = view.slides.iter().map(|s| s.part.as_str()).collect();
    let planned: Vec<&str> = plan.slides().iter().map(|s| s.part.as_str()).collect();
    assert_eq!(parts, planned);
    let ids: Vec<u32> = view.slides.iter().map(|s| s.sld_id).collect();
    assert_eq!(ids, (256..256 + planned.len() as u32).collect::<Vec<_>>());
    let (slide, heading) = unit(report, "a-title");
    let read = shape(&view, &slide.part, heading.shape);
    assert_eq!(text(read), ["Revenue doubled"]);
    assert_eq!(read.placeholder.as_ref().unwrap().kind, "title");
    assert_eq!(read.name.as_deref(), Some("Title 1"));
    let (slide, claim) = unit(report, "a-claim");
    assert_eq!(
        text(shape(&view, &slide.part, claim.shape)),
        ["Revenue grew from 4.1 to 8.3 million.", "Unaudited."]
    );

    // The picture is its verified bytes over the planned media part.
    let (slide, picture) = unit(report, "g-plan");
    assert_eq!(
        shape(&view, &slide.part, picture.shape).kind,
        ShapeKind::Picture
    );
    let media: Vec<Relationship> = package
        .relationships(&slide.part)
        .unwrap()
        .into_iter()
        .filter(|rel| rel.kind.ends_with("/image"))
        .collect();
    assert_eq!(media.len(), 1);
    assert_eq!(
        package.part(&media[0].target).unwrap().unwrap(),
        fixture.records["plan"].1
    );
    // The diagram is one native group of its two shapes.
    let (slide, figure) = unit(report, "i-flow");
    let group = shape(&view, &slide.part, figure.shape);
    assert_eq!(group.kind, ShapeKind::Group);
    let read: &SlideView = view.slides.iter().find(|s| s.part == slide.part).unwrap();
    assert_eq!(
        read.shapes
            .iter()
            .filter(|s| !s.group_path.is_empty())
            .count(),
        2
    );
    let used: BTreeSet<(&str, &str)> = report
        .assets
        .iter()
        .map(|asset| (asset.asset.as_str(), asset.record.artifact.as_str()))
        .collect();
    assert_eq!(
        used,
        BTreeSet::from([("flow", "blob:flow"), ("plan", "blob:site-plan")])
    );

    // Charts carry their dataset: categories and values, missing kept missing.
    let (slide, chart) = unit(report, "b-revenue");
    assert_eq!(
        shape(&view, &slide.part, chart.shape).kind,
        ShapeKind::GraphicFrame
    );
    let target = package
        .relationships(&slide.part)
        .unwrap()
        .into_iter()
        .find(|rel| rel.kind.ends_with("/chart"))
        .unwrap()
        .target;
    let data = chart_data(&package, &target).unwrap();
    let values = data.series[0].values.as_ref().unwrap();
    assert_eq!(values.cache, values.workbook);
    assert_eq!(values.cache[2], Cell::Missing);
    let lines: Vec<String> = package
        .names()
        .filter(|name| name.starts_with("ppt/charts/chart") && name.ends_with(".xml"))
        .map(|name| String::from_utf8(package.part(name).unwrap().unwrap()).unwrap())
        .filter(|xml| xml.contains("<c:lineChart>"))
        .collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains(r#"<c:smooth val="0"/>"#));
    let (slide, table) = unit(report, "d-table");
    assert_eq!(
        shape(&view, &slide.part, table.shape).kind,
        ShapeKind::GraphicFrame
    );
    assert_eq!(report.native.len(), 3);

    // Same plan, same template, same inputs: the same bytes.
    assert_eq!(fixture.emit(&plan).hash, candidate.hash);
}

#[test]
fn the_write_set_and_relationships_are_the_plans() {
    let fixture = Fixture::parts(&bare_parts());
    let plan = fixture.plan();
    let candidate = fixture.emit(&plan);
    let package = reopen(&candidate);
    let template = &fixture.template;
    let row = plan.package();
    let allowed: BTreeSet<String> = row
        .new_parts
        .iter()
        .map(|part| part.part.clone())
        .chain(row.changed_parts.iter().cloned())
        .chain(row.relationships.iter().map(|rel| rels_name(&rel.source)))
        .collect();
    let written: BTreeSet<String> = package
        .names()
        .filter(|name| template.part(name).unwrap() != package.part(name).unwrap())
        .map(str::to_owned)
        .collect();
    assert_eq!(written, allowed);
    assert_eq!(
        candidate
            .report
            .write_set
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        written
    );
    // Every other template part is still there, byte for byte.
    for name in template.names() {
        if !allowed.contains(name) {
            assert_eq!(template.part(name).unwrap(), package.part(name).unwrap());
        }
    }
    // The relationships created are exactly the planned ones.
    let sources: BTreeSet<&str> = row
        .relationships
        .iter()
        .map(|rel| rel.source.as_str())
        .collect();
    let mut created = Vec::new();
    for source in sources {
        let before = template.relationships(source).unwrap();
        for rel in package.relationships(source).unwrap() {
            if !before.contains(&rel) {
                let kind = rel.kind.rsplit('/').next().unwrap().to_owned();
                created.push((source.to_owned(), kind, rel.target));
            }
        }
    }
    let mut planned: Vec<(String, String, String)> = row
        .relationships
        .iter()
        .map(|rel| (rel.source.clone(), rel.kind.to_owned(), rel.target.clone()))
        .collect();
    created.sort();
    planned.sort();
    assert_eq!(created, planned);
}

#[test]
fn fit_is_never_certified_and_font_scale_is_never_written() {
    // The layout's own metrics are retained and inherited, never restated.
    let metrics =
        r#"<a:bodyPr><a:normAutofit fontScale="62500" lnSpcReduction="20000"/></a:bodyPr>"#;
    let parts: Vec<(&str, String)> = bare_parts()
        .into_iter()
        .map(|(name, body)| match name {
            "ppt/slideLayouts/slideLayout2.xml" => (name, body.replace("<a:bodyPr/>", metrics)),
            _ => (name, body),
        })
        .collect();
    let fixture = Fixture::parts(&parts);
    let plan = fixture.plan();
    let candidate = fixture.emit(&plan);
    let package = reopen(&candidate);
    for part in &candidate.report.write_set {
        let bytes = package.part(part).unwrap().unwrap();
        for word in [&b"fontScale"[..], b"lnSpcReduction"] {
            assert!(!bytes.windows(word.len()).any(|w| w == word), "{part}");
        }
    }
    assert!(
        candidate
            .report
            .slides
            .iter()
            .any(|slide| slide.layout == "ppt/slideLayouts/slideLayout2.xml")
    );

    // Laid-out text, tables and charts stay FitUnverified; geometry decides
    // pictures and figures, inside their planned bounds.
    let unverified = candidate.fit.as_ref().unwrap_err();
    let mut expected = BTreeSet::new();
    for (index, slide) in candidate.report.slides.iter().enumerate() {
        for unit in &slide.units {
            let bounds = match &unit.destination {
                Destination::Placeholder { bounds, .. } | Destination::Shape { bounds } => *bounds,
            };
            match (&unit.content, &unit.fit) {
                (Content::Picture(_) | Content::Figure(_), FitTrace::Exact { placed }) => {
                    assert!(placed.x >= bounds.x && placed.y >= bounds.y);
                    assert!(placed.x + placed.cx <= bounds.x + bounds.cx);
                    assert!(placed.y + placed.cy <= bounds.y + bounds.cy);
                }
                (Content::Picture(_) | Content::Figure(_), fit) => panic!("{fit:?}"),
                (_, FitTrace::Unverified { estimate }) => {
                    let planned = plan.slides()[index]
                        .fit
                        .estimates
                        .iter()
                        .find(|e| e.block == unit.block);
                    assert_eq!(estimate.as_ref(), planned);
                    expected.insert((slide.part.clone(), unit.block.clone(), unit.shape));
                }
                (_, fit) => panic!("{} certified as {fit:?}", unit.block),
            }
        }
    }
    let reported: BTreeSet<_> = unverified
        .units
        .iter()
        .map(|u| (u.slide.clone(), u.block.clone(), u.shape))
        .collect();
    assert_eq!(reported, expected);
}

#[test]
fn emission_refuses_stale_plans_held_slides_and_missing_assets() {
    let fixture = Fixture::parts(&bare_parts());
    let plan = fixture.plan();
    let stored = fixture.stored();
    let mut edited = the_brief();
    edited["communication"]["outcome"] = json!("Reject the budget");
    assert!(matches!(
        fixture.emit_with(&plan, &bytes(&edited), &stored),
        Err(EmitError::Plan(CompileError::StaleBrief))
    ));

    let mut unstored = fixture.stored();
    unstored.get_mut("plan").unwrap().bytes = None;
    assert!(matches!(
        fixture.emit_with(&plan, &fixture.brief, &unstored),
        Err(EmitError::Graphic { block, error: GraphicError::MissingBytes }) if block == "g-plan"
    ));
    let mut unrecorded = fixture.stored();
    unrecorded.remove("flow");
    assert!(matches!(
        fixture.emit_with(&plan, &fixture.brief, &unrecorded),
        Err(EmitError::MissingAsset(asset)) if asset == "flow"
    ));

    // A template that already holds slides would put unplanned content in
    // the new deck.
    let held = Fixture::parts(&template_parts(crate::design_plan::tests::NAMES));
    let plan = held.plan();
    assert!(matches!(
        held.emit_with(&plan, &held.brief, &held.stored()),
        Err(EmitError::TemplateSlides(slides)) if slides == ["ppt/slides/slide1.xml"]
    ));
}

#[test]
fn the_candidate_checks_refuse_what_the_plan_does_not_allow() {
    let fixture = Fixture::parts(&bare_parts());
    let plan = fixture.plan();
    let candidate = fixture.emit(&plan);
    let slides = &candidate.report.slides;
    let first = slides[0].part.clone();
    let verify = |bytes: &[u8]| check::verify(&plan, &fixture.template, bytes, slides);
    assert_eq!(
        verify(&candidate.bytes).unwrap(),
        candidate.report.write_set
    );
    let tampered = |edit: &dyn Fn(&mut Package)| {
        let mut package = reopen(&candidate);
        edit(&mut package);
        match verify(&package.export().unwrap()) {
            Err(EmitError::Check { fault, .. }) => fault,
            other => panic!("expected a check fault, got {other:?}"),
        }
    };
    let rewrite = |package: &mut Package, from: &str, to: &str| {
        let xml = String::from_utf8(package.part(&first).unwrap().unwrap()).unwrap();
        assert!(xml.contains(from));
        package
            .replace_xml_part(&first, xml.replacen(from, to, 1).into_bytes())
            .unwrap();
    };

    assert_eq!(
        tampered(&|p| p
            .add_part("ppt/extra.xml", "application/xml", b"<x/>".to_vec())
            .unwrap()),
        CheckFault::OutsideWriteSet
    );
    assert_eq!(
        tampered(&|p| {
            p.relate(&first, &format!("{REL}/slide"), &slides[1].part)
                .unwrap();
        }),
        CheckFault::UnplannedRelationship
    );
    assert_eq!(
        tampered(&|p| rewrite(
            p,
            "<a:bodyPr/>",
            r#"<a:bodyPr><a:normAutofit fontScale="90000"/></a:bodyPr>"#
        )),
        CheckFault::AutofitMetrics
    );
    let second = slides[0].units[1].shape;
    assert_eq!(
        tampered(&|p| rewrite(p, &format!(r#"id="{second}""#), r#"id="2""#)),
        CheckFault::IdScope
    );
    assert_eq!(
        tampered(&|p| rewrite(p, "Revenue doubled", "Revenue tripled")),
        CheckFault::Reimport
    );
}

/// The oracle's clean deck without its one slide: a real PowerPoint
/// template (python-pptx's default masters, layouts and theme).
fn oracle_template() -> Package {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/office/fixtures/clean.pptx"
    );
    let source = std::fs::read(path).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(source)).unwrap();
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let cut = |text: &str, start: &str, end: &str| -> String {
        let at = text.find(start).unwrap();
        let to = at + text[at..].find(end).unwrap() + end.len();
        format!("{}{}", &text[..at], &text[to..])
    };
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).unwrap();
        let name = entry.name().to_owned();
        if name.starts_with("ppt/slides/") {
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body).unwrap();
        let body = match name.as_str() {
            "ppt/presentation.xml" => cut(
                &String::from_utf8(body).unwrap(),
                "<p:sldIdLst>",
                "</p:sldIdLst>",
            )
            .into_bytes(),
            "ppt/_rels/presentation.xml.rels" => {
                let text = String::from_utf8(body).unwrap();
                let slide = text.find("relationships/slide\"").unwrap();
                let at = text[..slide].rfind("<Relationship ").unwrap();
                cut(&text, &text[at..slide], "/>").into_bytes()
            }
            "[Content_Types].xml" => cut(
                &String::from_utf8(body).unwrap(),
                r#"<Override PartName="/ppt/slides/slide1.xml""#,
                "/>",
            )
            .into_bytes(),
            _ => body,
        };
        writer.start_file(name, options).unwrap();
        writer.write_all(&body).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    Package::open(&bytes, limits()).unwrap()
}

#[test]
#[ignore = "writes the Office-oracle candidate to $ONEIRON_EMIT_CANDIDATE"]
fn office_oracle_candidate() {
    // Three regions: the 4:3 template's table room holds no more.
    let mut brief = the_brief();
    let regions = &mut brief["datasets"][2];
    assert_eq!(regions["id"], "by-region");
    regions["columns"].as_array_mut().unwrap().truncate(4);
    for row in regions["rows"].as_array_mut().unwrap() {
        row.as_array_mut().unwrap().truncate(4);
    }
    let fixture = Fixture::new(oracle_template(), &brief);
    let plan = fixture.plan();
    let candidate = fixture.emit(&plan);
    assert!(candidate.fit.is_err());
    let path = std::env::var("ONEIRON_EMIT_CANDIDATE").unwrap();
    std::fs::write(&path, &candidate.bytes).unwrap();
    println!(
        "candidate {} blake3 {} slides {}",
        path,
        blake3::Hash::from(candidate.hash).to_hex(),
        candidate.report.slides.len()
    );
}

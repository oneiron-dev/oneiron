//! ONE-2533 acceptance: the brief schema refuses design choices; content,
//! boundaries, units and pins are checked; layouts are chosen by capability;
//! each rung of the fallback ladder is exercised; the plan stays bound to the
//! kept brief and template. The template follows ECMA-376 part 1 and
//! PowerPoint's default 16:9 geometry; expected rectangles are derived from
//! those placeholder bounds.
use super::*;
use crate::deck::Placeholder;
use crate::deck::fixture::*;
use crate::retained_opc::Package;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MASTER: &str = "ppt/slideMasters/slideMaster1.xml";
const TITLE_SLIDE: &str = "ppt/slideLayouts/slideLayout1.xml";
const TITLE_AND_CONTENT: &str = "ppt/slideLayouts/slideLayout2.xml";
const TWO_CONTENT: &str = "ppt/slideLayouts/slideLayout3.xml";
const TITLE_ONLY: &str = "ppt/slideLayouts/slideLayout4.xml";
pub(crate) const NAMES: [&str; 4] = [
    "Title Slide",
    "Title and Content",
    "Two Content",
    "Title Only",
];
const TEXT_BODY: &str = "<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>";

/// PowerPoint's 16:9 master title and body placeholder bounds.
const MASTER_TITLE: Rect = Rect {
    x: 838_200,
    y: 365_125,
    cx: 10_515_600,
    cy: 1_325_563,
};
const MASTER_BODY: Rect = Rect {
    x: 838_200,
    y: 1_825_625,
    cx: 10_515_600,
    cy: 4_351_338,
};

fn master() -> String {
    let shapes = [
        placeholder(
            2,
            "Title Placeholder 1",
            r#"<p:ph type="title"/>"#,
            &xfrm(838_200, 365_125, 10_515_600, 1_325_563),
            TEXT_BODY,
        ),
        placeholder(
            3,
            "Text Placeholder 2",
            r#"<p:ph type="body" idx="1"/>"#,
            &xfrm(838_200, 1_825_625, 10_515_600, 4_351_338),
            TEXT_BODY,
        ),
        placeholder(
            4,
            "Date Placeholder 3",
            r#"<p:ph type="dt" sz="half" idx="2"/>"#,
            &xfrm(838_200, 6_356_350, 2_743_200, 365_125),
            TEXT_BODY,
        ),
    ]
    .concat();
    let layouts = (1..=4)
        .map(|n| {
            format!(
                r#"<p:sldLayoutId id="{}" r:id="rId{n}"/>"#,
                2_147_483_648u32 + n
            )
        })
        .collect::<String>();
    format!(
        r#"<p:sldMaster {NS}><p:cSld><p:spTree>{GROUP_ROOT}{shapes}</p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst>{layouts}</p:sldLayoutIdLst><p:txStyles><p:titleStyle><a:lvl1pPr algn="l"><a:defRPr sz="4400"><a:latin typeface="+mj-lt"/></a:defRPr></a:lvl1pPr></p:titleStyle><p:bodyStyle><a:lvl1pPr marL="228600" indent="-228600"><a:buChar char="•"/><a:defRPr sz="2800"><a:latin typeface="+mn-lt"/></a:defRPr></a:lvl1pPr></p:bodyStyle><p:otherStyle><a:lvl1pPr marL="0"><a:defRPr sz="1800"/></a:lvl1pPr></p:otherStyle></p:txStyles></p:sldMaster>"#
    )
}

fn layout(name: &str, shapes: &[String]) -> String {
    let shapes = shapes.concat();
    format!(
        r#"<p:sldLayout {NS} preserve="1"><p:cSld name="{name}"><p:spTree>{GROUP_ROOT}{shapes}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"#
    )
}

fn title_placeholder() -> String {
    placeholder(2, "Title 1", r#"<p:ph type="title"/>"#, "", TEXT_BODY)
}

/// Four layouts, named `names` in master order; selection must not care.
pub(crate) fn template_parts(names: [&str; 4]) -> Vec<(&'static str, String)> {
    let subtitle = r#"<p:txBody><a:bodyPr/><a:lstStyle><a:lvl1pPr marL="0" indent="0" algn="ctr"><a:buNone/><a:defRPr sz="2400"/></a:lvl1pPr></a:lstStyle><a:p/></p:txBody>"#;
    let layouts = [
        layout(
            names[0],
            &[
                placeholder(
                    2,
                    "Title 1",
                    r#"<p:ph type="ctrTitle"/>"#,
                    &xfrm(1_524_000, 1_122_363, 9_144_000, 2_387_600),
                    TEXT_BODY,
                ),
                placeholder(
                    3,
                    "Subtitle 2",
                    r#"<p:ph type="subTitle" idx="1"/>"#,
                    &xfrm(1_524_000, 3_602_038, 9_144_000, 1_655_762),
                    subtitle,
                ),
            ],
        ),
        layout(
            names[1],
            &[
                title_placeholder(),
                placeholder(
                    3,
                    "Content Placeholder 2",
                    r#"<p:ph idx="1"/>"#,
                    "",
                    TEXT_BODY,
                ),
                placeholder(
                    4,
                    "Date Placeholder 3",
                    r#"<p:ph type="dt" sz="half" idx="10"/>"#,
                    "",
                    TEXT_BODY,
                ),
            ],
        ),
        // Two text-only placeholders: they do not prove two charts fit.
        layout(
            names[2],
            &[
                title_placeholder(),
                placeholder(
                    3,
                    "Text Placeholder 2",
                    r#"<p:ph type="body" sz="half" idx="1"/>"#,
                    &xfrm(838_200, 1_825_625, 5_181_600, 4_351_338),
                    TEXT_BODY,
                ),
                placeholder(
                    4,
                    "Text Placeholder 3",
                    r#"<p:ph type="body" sz="half" idx="2"/>"#,
                    &xfrm(6_172_800, 1_825_625, 5_181_600, 4_351_338),
                    TEXT_BODY,
                ),
            ],
        ),
        layout(names[3], &[title_placeholder()]),
    ];
    let [title_slide, title_and_content, two_content, title_only] = layouts;
    let layout_rels = rels(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]);
    let sample = placeholder(
        2,
        "Title 1",
        r#"<p:ph type="ctrTitle"/>"#,
        "",
        r#"<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-GB"/><a:t>Sample</a:t></a:r></a:p></p:txBody>"#,
    );
    vec![
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>"#.to_owned(),
        ),
        ("_rels/.rels", rels(&[("rId1", "officeDocument", "ppt/presentation.xml")])),
        (
            "ppt/presentation.xml",
            format!(
                r#"<p:presentation {NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/><p:defaultTextStyle><a:lvl1pPr marL="0"><a:defRPr sz="1800"/></a:lvl1pPr></p:defaultTextStyle></p:presentation>"#
            ),
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            rels(&[
                ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                ("rId2", "slide", "slides/slide1.xml"),
                ("rId3", "theme", "theme/theme1.xml"),
            ]),
        ),
        (MASTER, master()),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "slideLayout", "../slideLayouts/slideLayout2.xml"),
                ("rId3", "slideLayout", "../slideLayouts/slideLayout3.xml"),
                ("rId4", "slideLayout", "../slideLayouts/slideLayout4.xml"),
                ("rId5", "theme", "../theme/theme1.xml"),
            ]),
        ),
        (TITLE_SLIDE, title_slide),
        ("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels.clone()),
        (TITLE_AND_CONTENT, title_and_content),
        ("ppt/slideLayouts/_rels/slideLayout2.xml.rels", layout_rels.clone()),
        (TWO_CONTENT, two_content),
        ("ppt/slideLayouts/_rels/slideLayout3.xml.rels", layout_rels.clone()),
        (TITLE_ONLY, title_only),
        ("ppt/slideLayouts/_rels/slideLayout4.xml.rels", layout_rels),
        ("ppt/theme/theme1.xml", theme()),
        (
            "ppt/slides/slide1.xml",
            format!(
                r#"<p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{sample}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#
            ),
        ),
        (
            "ppt/slides/_rels/slide1.xml.rels",
            rels(&[("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")]),
        ),
    ]
}

/// The template without its sample slide, as emission takes it: a new deck
/// holds only planned slides.
pub(crate) fn bare_parts() -> Vec<(&'static str, String)> {
    template_parts(NAMES)
        .into_iter()
        .filter(|(name, _)| !name.starts_with("ppt/slides/"))
        .map(|(name, body)| match name {
            "ppt/presentation.xml" => (
                name,
                body.replace(
                    r#"<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>"#,
                    "",
                ),
            ),
            "ppt/_rels/presentation.xml.rels" => (
                name,
                rels(&[
                    ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                    ("rId3", "theme", "theme/theme1.xml"),
                ]),
            ),
            _ => (name, body),
        })
        .collect()
}

fn template_named(names: [&str; 4]) -> Package {
    Package::open(&archive(&template_parts(names)), limits()).unwrap()
}

fn template() -> Package {
    template_named(NAMES)
}

fn hex(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

fn pin(quote: &str) -> Value {
    json!({
        "document": "doc:annual-report",
        "version": "v3",
        "start": "cursor:10",
        "end": "cursor:47",
        "quote": quote,
        "quote_hash": hex(quote),
    })
}

pub(crate) fn title(id: &str, text: &str) -> Value {
    json!({"id": id, "kind": "title", "text": text})
}

fn claim(id: &str, text: &str) -> Value {
    json!({"id": id, "kind": "claim", "text": text, "evidence": [pin(text)]})
}

fn data(id: &str, dataset: &str, carriers: &[&str]) -> Value {
    json!({"id": id, "kind": "data", "dataset": dataset, "carriers": carriers})
}

pub(crate) fn page(id: &str, division: &str, blocks: Vec<Value>) -> Value {
    json!({"id": id, "job": "explain", "division": division, "blocks": blocks})
}

/// `n` four-letter words: `5n - 1` characters.
fn words(n: usize) -> String {
    vec!["word"; n].join(" ")
}

pub(crate) fn brief() -> Value {
    let mut results = claim("a-claim", "Revenue grew from 4.1 to 8.3 million.");
    results["qualifications"] = json!(["Unaudited."]);
    results["evidence"][0]["drift"] = json!(true);
    let mut optional = claim("f-detail", &words(400));
    optional["priority"] = json!("optional");
    let regions = [
        "Northwest",
        "Northeast",
        "Southwest",
        "Southeast",
        "Highlands",
        "Lowlands",
        "Midlands",
    ];
    let mut columns = vec![json!({"name": "Region", "type": "text"})];
    columns.extend(
        regions
            .iter()
            .map(|name| json!({"name": name, "type": "number", "unit": "EUR k"})),
    );
    json!({
        "communication": {
            "audience": "Board",
            "outcome": "Approve the budget",
            "main_message": "Revenue doubled",
        },
        "language": "en-GB",
        "accessibility": ["Describe every figure"],
        "pages": [
            page("results", "fixed", vec![title("a-title", "Revenue doubled"), results]),
            page("points", "fixed", vec![
                title("h-title", "Two points"),
                claim("h-one", "Margins held."),
                claim("h-two", "Churn fell."),
            ]),
            page("mix", "fixed", vec![
                title("b-title", "Quarterly mix"),
                data("b-revenue", "revenue", &["chart"]),
                data("b-cost", "cost", &["chart", "table"]),
            ]),
            page("findings", "split", vec![
                title("c-title", "Three findings"),
                claim("c-one", &words(90)),
                claim("c-two", &words(90)),
                claim("c-three", &words(90)),
            ]),
            page("regions", "fixed", vec![
                title("d-title", "Cost by region"),
                data("d-table", "by-region", &["table"]),
                claim("d-claim", "Costs fell in every region."),
            ]),
            page("costs", "fixed", vec![
                title("f-title", "Costs"),
                claim("f-claim", "Costs fell."),
                optional,
            ]),
            page("site", "fixed", vec![
                title("g-title", "Site plan"),
                json!({"id": "g-plan", "kind": "asset", "asset": "plan"}),
            ]),
        ],
        "datasets": [
            {
                "id": "revenue",
                "columns": [
                    {"name": "Quarter", "type": "text"},
                    {"name": "Revenue", "type": "number", "unit": "EUR m"},
                ],
                "rows": [["Q1", 4.1], ["Q2", 5.0], ["Q3", null], ["Q4", 8.3]],
                "missing": "not reported",
                "sources": ["ledger 2026"],
            },
            {
                "id": "cost",
                "columns": [
                    {"name": "Month", "type": "date"},
                    {"name": "Cost", "type": "number", "unit": "EUR m"},
                ],
                "rows": [["2026-01-31", 2.0], ["2026-02-28", 1.9], ["2026-03-31", 1.7], ["2026-04-30", 1.6]],
                "sources": ["ledger 2026"],
            },
            {
                "id": "by-region",
                "columns": columns,
                "rows": [
                    ["Coastal", 1200, 1300, 1100, 900, 800, 700, 600],
                    ["Inland", 1000, 1100, 900, 800, 700, 600, 500],
                ],
                "sources": ["regional ledgers"],
            },
        ],
        "assets": [{"id": "plan", "kind": "factual", "content": "Site plan of the new depot"}],
    })
}

pub(crate) fn bytes(brief: &Value) -> Vec<u8> {
    serde_json::to_vec(brief).unwrap()
}

pub(crate) fn kept<'a>(version: &'a str, bytes: &'a [u8]) -> KeptBrief<'a> {
    KeptBrief {
        version,
        content_hash: *blake3::hash(bytes).as_bytes(),
        bytes,
    }
}

fn assets() -> BTreeMap<String, AssetBinding> {
    BTreeMap::from([(
        "plan".to_owned(),
        AssetBinding {
            handle: "blob:site-plan".to_owned(),
            media: MediaType::Png,
        },
    )])
}

fn plan_for(brief: &Value, template: &Package) -> DesignPlan {
    let bytes = bytes(brief);
    match compile(&kept("brief@7", &bytes), template, &assets()).unwrap() {
        Outcome::Plan(plan) => *plan,
        Outcome::Ask(decisions) => panic!("expected a plan, got {decisions:?}"),
    }
}

fn parse_error(brief: &Value) -> BriefError {
    Brief::parse(&bytes(brief)).unwrap_err()
}

fn at(path: &str) -> String {
    path.to_owned()
}

fn bounds(destination: &Destination) -> Rect {
    match destination {
        Destination::Placeholder { bounds, .. } | Destination::Shape { bounds } => *bounds,
    }
}

fn filled(destination: &Destination) -> Option<(&str, u32)> {
    match destination {
        Destination::Placeholder {
            placeholder: Placeholder { kind, idx },
            ..
        } => Some((kind.as_str(), *idx)),
        Destination::Shape { .. } => None,
    }
}

fn slide<'p>(plan: &'p DesignPlan, page: &str, nth: usize) -> &'p SlidePlan {
    plan.slides()
        .iter()
        .filter(|slide| slide.page == page)
        .nth(nth)
        .unwrap()
}

fn blocks(slide: &SlidePlan) -> Vec<&str> {
    slide
        .placements
        .iter()
        .map(|placement| placement.block.as_str())
        .collect()
}

#[test]
fn the_brief_schema_refuses_design_choices() {
    assert!(Brief::parse(&bytes(&brief())).is_ok());
    let cases: [(&[&str], &str, Value); 8] = [
        (&[], "master", json!("Office Theme")),
        (&["pages", "0"], "layout", json!("Title and Content")),
        (&["pages", "0"], "shape_count", json!(3)),
        (&["pages", "0", "blocks", "1"], "x", json!(914_400)),
        (&["pages", "0", "blocks", "1"], "font_size", json!(28)),
        (&["pages", "0", "blocks", "1"], "font", json!("Calibri")),
        (&["datasets", "0"], "chart_style", json!(26)),
        (&["assets", "0"], "geometry", json!("roundRect")),
    ];
    for (path, key, value) in cases {
        let mut brief = brief();
        let mut node = &mut brief;
        for step in path {
            node = match step.parse::<usize>() {
                Ok(index) => &mut node[index],
                Err(_) => &mut node[*step],
            };
        }
        node[key] = value;
        let pointer = path
            .iter()
            .fold(String::new(), |out, step| out + "/" + step)
            + "/"
            + key;
        assert_eq!(
            parse_error(&brief),
            BriefError::UnknownField { path: pointer },
            "{key}"
        );
    }

    // The same refusal through compile: nothing is planned from such a brief.
    let mut named = brief();
    named["pages"][1]["layout"] = json!("Two Content");
    let bytes = bytes(&named);
    assert_eq!(
        compile(&kept("brief@7", &bytes), &template(), &assets()).unwrap_err(),
        CompileError::Brief(BriefError::UnknownField {
            path: at("/pages/1/layout")
        })
    );
}

#[test]
fn the_brief_checks_content_units_and_pins() {
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut brief = brief();
        edit(&mut brief);
        parse_error(&brief)
    };
    // Content.
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1]["text"] = json!("  ")),
        BriefError::Empty {
            path: at("/pages/0/blocks/1/text")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1]["evidence"] = json!([])),
        BriefError::Empty {
            path: at("/pages/0/blocks/1/evidence")
        }
    );
    assert_eq!(
        refused(&|b| {
            b["pages"][0]["blocks"][1]
                .as_object_mut()
                .unwrap()
                .remove("evidence");
        }),
        BriefError::Missing {
            path: at("/pages/0/blocks/1/evidence")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][1]["blocks"][2]["id"] = json!("results")),
        BriefError::DuplicateId { id: at("results") }
    );
    assert_eq!(
        refused(&|b| b["pages"][2]["blocks"][1]["dataset"] = json!("nope")),
        BriefError::UnknownReference {
            path: at("/pages/2/blocks/1/dataset")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][6]["blocks"][1]["asset"] = json!("nope")),
        BriefError::UnknownReference {
            path: at("/pages/6/blocks/1/asset")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1] = title("second", "Another title")),
        BriefError::SecondTitle {
            path: at("/pages/0/blocks/1")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][0]["kind"] = json!("slide")),
        BriefError::Invalid {
            path: at("/pages/0/blocks/0/kind")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][0]["evidence"] = json!([])),
        BriefError::UnknownField {
            path: at("/pages/0/blocks/0/evidence")
        }
    );

    // Units, cell types and missing values: a missing value is not zero.
    assert_eq!(
        refused(&|b| {
            b["datasets"][0]["columns"][1]
                .as_object_mut()
                .unwrap()
                .remove("unit");
        }),
        BriefError::MissingUnit {
            path: at("/datasets/0/columns/1")
        }
    );
    assert_eq!(
        refused(&|b| b["datasets"][0]["columns"][0]["unit"] = json!("quarter")),
        BriefError::UnexpectedUnit {
            path: at("/datasets/0/columns/0/unit")
        }
    );
    assert_eq!(
        refused(&|b| {
            b["datasets"][0].as_object_mut().unwrap().remove("missing");
        }),
        BriefError::MissingMeaning {
            path: at("/datasets/0/rows/2/1")
        }
    );
    assert_eq!(
        refused(&|b| b["datasets"][0]["rows"][1][1] = json!("5.0")),
        BriefError::Cell {
            path: at("/datasets/0/rows/1/1")
        }
    );
    assert_eq!(
        refused(&|b| b["datasets"][0]["rows"][3] = json!(["Q4"])),
        BriefError::Cell {
            path: at("/datasets/0/rows/3")
        }
    );
    assert_eq!(
        refused(&|b| b["datasets"][1]["rows"][1][0] = json!("2026-02-30")),
        BriefError::Cell {
            path: at("/datasets/1/rows/1/0")
        }
    );
    assert_eq!(
        refused(&|b| b["datasets"][1]["sources"] = json!([])),
        BriefError::Empty {
            path: at("/datasets/1/sources")
        }
    );
    // A chart needs a category column and number series.
    assert_eq!(
        refused(&|b| {
            b["datasets"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id": "labels", "columns": [{"name": "Label", "type": "text"}], "rows": [["north"]], "sources": ["survey"]}));
            b["pages"][4]["blocks"][1] = data("d-table", "labels", &["table", "chart"]);
        }),
        BriefError::Carrier {
            path: at("/pages/4/blocks/1/carriers/1")
        }
    );

    // Pins: the kept quote must match its hash.
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1]["evidence"][0]["quote"] = json!("Revenue tripled.")),
        BriefError::QuoteHash {
            path: at("/pages/0/blocks/1/evidence/0")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1]["evidence"][0]["quote_hash"] = json!("abc")),
        BriefError::Invalid {
            path: at("/pages/0/blocks/1/evidence/0/quote_hash")
        }
    );
    assert_eq!(
        refused(&|b| b["pages"][0]["blocks"][1]["evidence"][0]["start"] = json!("")),
        BriefError::Empty {
            path: at("/pages/0/blocks/1/evidence/0/start")
        }
    );
}

#[test]
fn the_plan_is_bound_to_the_kept_brief_and_template() {
    let brief_bytes = bytes(&brief());
    let template = template();
    let mut stale = kept("brief@7", &brief_bytes);
    stale.content_hash[0] ^= 1;
    assert_eq!(
        compile(&stale, &template, &assets()).unwrap_err(),
        CompileError::StaleBrief
    );
    assert_eq!(
        compile(&kept("brief@7", &brief_bytes), &template, &BTreeMap::new()).unwrap_err(),
        CompileError::UnboundAsset(at("plan"))
    );

    let plan = plan_for(&brief(), &template);
    assert_eq!(
        plan.approved(),
        &ApprovedInput {
            version: at("brief@7"),
            content_hash: *blake3::hash(&brief_bytes).as_bytes(),
        }
    );
    assert_eq!(
        plan,
        plan_for(&brief(), &template),
        "compile is deterministic"
    );
    assert_eq!(
        plan.check(&kept("brief@7", &brief_bytes), &template),
        Ok(())
    );

    // A later keep, even of the same bytes, is another approval.
    assert_eq!(
        plan.check(&kept("brief@8", &brief_bytes), &template),
        Err(CompileError::StaleBrief)
    );
    let mut edited = brief();
    edited["communication"]["main_message"] = json!("Revenue tripled");
    let edited = bytes(&edited);
    assert_eq!(
        plan.check(&kept("brief@7", &edited), &template),
        Err(CompileError::StaleBrief)
    );
    let mut claimed = kept("brief@7", &edited);
    claimed.content_hash = plan.approved().content_hash;
    assert_eq!(
        plan.check(&claimed, &template),
        Err(CompileError::StaleBrief)
    );
    let renamed = template_named(["Opening", NAMES[1], NAMES[2], NAMES[3]]);
    assert_eq!(
        plan.check(&kept("brief@7", &brief_bytes), &renamed),
        Err(CompileError::StaleTemplate)
    );
}

#[test]
fn layouts_are_chosen_by_capability_and_every_rung_is_exercised() {
    let plan = plan_for(&brief(), &template());
    let pages: Vec<&str> = plan
        .slides()
        .iter()
        .map(|slide| slide.page.as_str())
        .collect();
    assert_eq!(
        pages,
        [
            "results", "points", "mix", "findings", "findings", "regions", "costs", "site"
        ]
    );
    assert_eq!(plan.visual().master, MASTER);
    assert_eq!(plan.visual().theme.as_deref(), Some("ppt/theme/theme1.xml"));
    assert_eq!(plan.visual().major_font.as_deref(), Some("Calibri Light"));

    // Capability match: title by role, the claim and its qualification in
    // the one content placeholder; Title Slide's subtitle also qualifies but
    // offers less room.
    let results = slide(&plan, "results", 0);
    assert_eq!(
        (results.layout.as_str(), results.fallback),
        (TITLE_AND_CONTENT, None)
    );
    assert_eq!(
        filled(&results.placements[0].destination),
        Some(("title", 0))
    );
    assert_eq!(bounds(&results.placements[0].destination), MASTER_TITLE);
    assert_eq!(
        results.placements[1].content,
        Content::Text(vec![
            at("Revenue grew from 4.1 to 8.3 million."),
            at("Unaudited.")
        ])
    );
    assert_eq!(filled(&results.placements[1].destination), Some(("obj", 1)));
    assert_eq!(bounds(&results.placements[1].destination), MASTER_BODY);
    assert_eq!(
        results.fit.alternatives,
        [
            Fallback::OrdinaryShapes,
            Fallback::Composition(Composition::Rows),
            Fallback::Ask
        ]
    );

    // Two text placeholders hold two claims, left to right in argument order.
    let points = slide(&plan, "points", 0);
    assert_eq!(
        (points.layout.as_str(), points.fallback),
        (TWO_CONTENT, None)
    );
    assert_eq!(
        points.placements[1..]
            .iter()
            .map(|placement| (placement.block.as_str(), filled(&placement.destination)))
            .collect::<Vec<_>>(),
        [("h-one", Some(("body", 1))), ("h-two", Some(("body", 2)))]
    );

    // Fallback 1: two body placeholders do not prove two charts fit, so the
    // charts become ordinary shapes in the theme's body area.
    let mix = slide(&plan, "mix", 0);
    assert_eq!(
        (mix.layout.as_str(), mix.fallback),
        (TITLE_ONLY, Some(Fallback::OrdinaryShapes))
    );
    assert_eq!(filled(&mix.placements[0].destination), Some(("title", 0)));
    let column = (MASTER_BODY.cx - 182_880) / 2;
    assert_eq!(
        mix.placements[1..]
            .iter()
            .map(|placement| (placement.content.clone(), placement.destination.clone()))
            .collect::<Vec<_>>(),
        [
            (
                Content::Chart(at("revenue")),
                Destination::Shape {
                    bounds: Rect {
                        cx: column,
                        ..MASTER_BODY
                    }
                }
            ),
            (
                Content::Chart(at("cost")),
                Destination::Shape {
                    bounds: Rect {
                        x: MASTER_BODY.x + column + 182_880,
                        cx: column,
                        ..MASTER_BODY
                    }
                }
            ),
        ]
    );

    // Fallback 2: three long claims fit no single slide; the page allows a
    // split, which keeps argument order and repeats the title.
    let (first, second) = (slide(&plan, "findings", 0), slide(&plan, "findings", 1));
    assert_eq!(
        (first.fallback, first.split, second.fallback, second.split),
        (
            Some(Fallback::Split),
            Some((0, 2)),
            Some(Fallback::Split),
            Some((1, 2))
        )
    );
    assert_eq!(blocks(first), ["c-title", "c-one", "c-two"]);
    assert_eq!(blocks(second), ["c-title", "c-three"]);
    assert_eq!(
        first.fit.alternatives,
        [Fallback::Composition(Composition::Rows), Fallback::Ask]
    );

    // Fallback 3: the fixed page's wide table does not fit half the body
    // area, so a supported composition stacks it above the claim.
    let regions = slide(&plan, "regions", 0);
    assert_eq!(
        (regions.layout.as_str(), regions.fallback),
        (TITLE_ONLY, Some(Fallback::Composition(Composition::Rows)))
    );
    let row = (MASTER_BODY.cy - 182_880) / 2;
    assert_eq!(
        regions.placements[1].content,
        Content::Table(at("by-region"))
    );
    assert_eq!(
        bounds(&regions.placements[1].destination),
        Rect {
            cy: row,
            ..MASTER_BODY
        }
    );
    assert_eq!(
        bounds(&regions.placements[2].destination),
        Rect {
            y: MASTER_BODY.y + row + 182_880,
            cy: row,
            ..MASTER_BODY
        }
    );
    assert_eq!(regions.fit.alternatives, [Fallback::Ask]);

    // An optional block that fits nowhere is omitted and traced, never lost.
    let costs = slide(&plan, "costs", 0);
    assert_eq!(blocks(costs), ["f-title", "f-claim"]);
    let site = slide(&plan, "site", 0);
    assert_eq!(site.placements[1].content, Content::Picture(at("plan")));
    assert_eq!(filled(&site.placements[1].destination), Some(("obj", 1)));

    for slide in plan.slides() {
        assert_eq!(slide.fit.policy, FitPolicy::NoShrink);
        for estimate in &slide.fit.estimates {
            assert!(estimate.need <= estimate.room, "{estimate:?}");
        }
    }

    // Names are display only: renaming every layout changes nothing chosen.
    let shuffled = plan_for(
        &brief(),
        &template_named([
            "Title Only",
            "Two Content",
            "Title Slide",
            "Title and Content",
        ]),
    );
    assert_eq!(shuffled.slides(), plan.slides());
}

#[test]
fn fallback_four_asks_through_a_typed_decision() {
    let mut brief = brief();
    brief["pages"] = json!([
        page(
            "results",
            "fixed",
            vec![
                title("a-title", "Revenue doubled"),
                claim("a-claim", "Revenue grew.")
            ]
        ),
        page(
            "essay",
            "fixed",
            vec![
                title("e-title", "Everything"),
                claim("e-claim", &words(400))
            ]
        ),
    ]);
    let bytes = bytes(&brief);
    let Outcome::Ask(decisions) =
        compile(&kept("brief@7", &bytes), &template(), &assets()).unwrap()
    else {
        panic!("a required block that fits nowhere must not be planned");
    };
    assert_eq!(
        decisions,
        [Decision {
            page: at("essay"),
            options: vec![DecisionOption::OtherTemplate, DecisionOption::DesignChange],
            shortfalls: vec![Shortfall {
                block: at("e-claim"),
                reason: ShortfallReason::Overflow,
            }],
        }]
    );
}

#[test]
fn the_trace_covers_every_block_and_the_check_refuses_drift_from_it() {
    let brief_value = brief();
    let brief_bytes = bytes(&brief_value);
    let kept = kept("brief@7", &brief_bytes);
    let template = template();
    let plan = plan_for(&brief_value, &template);

    let trace: BTreeMap<&str, &TraceEntry> = plan
        .trace()
        .iter()
        .map(|entry| (entry.block.as_str(), entry))
        .collect();
    let parsed = Brief::parse(&brief_bytes).unwrap();
    let every: Vec<&str> = parsed
        .pages
        .iter()
        .flat_map(|page| page.blocks.iter().map(|block| block.id.as_str()))
        .collect();
    assert_eq!(trace.len(), every.len());
    assert!(every.iter().all(|block| trace.contains_key(block)));
    assert_eq!(trace["f-detail"].outcome, TraceOutcome::Omitted);
    assert_eq!(
        trace["c-title"].outcome,
        TraceOutcome::Placed(vec![(3, 0), (4, 0)])
    );
    assert!(trace["a-claim"].drifted);
    assert!(!trace["h-one"].drifted);
    assert_eq!(
        plan.data()
            .iter()
            .map(|dataset| dataset.id.as_str())
            .collect::<Vec<_>>(),
        ["revenue", "cost", "by-region"]
    );

    let refused = |edit: &dyn Fn(&mut DesignPlan)| {
        let mut plan = plan.clone();
        edit(&mut plan);
        plan.check(&kept, &template).unwrap_err()
    };
    let fault = |block: &str, fault| CompileError::Trace {
        block: at(block),
        fault,
    };
    assert_eq!(
        refused(&|plan| plan.trace.retain(|entry| entry.block != "a-claim")),
        fault("a-claim", TraceFault::Untraced)
    );
    assert_eq!(
        refused(&|plan| {
            let entry = plan
                .trace
                .iter_mut()
                .find(|entry| entry.block == "f-claim")
                .unwrap();
            entry.outcome = TraceOutcome::Omitted;
        }),
        fault("f-claim", TraceFault::RequiredOmitted)
    );
    assert_eq!(
        refused(&|plan| {
            let stray = plan.slides[4].placements[1].clone();
            plan.slides[0].placements.push(stray);
        }),
        fault("c-three", TraceFault::OutsidePage)
    );
    assert_eq!(
        refused(&|plan| {
            let estimate = &mut plan.slides[1].fit.estimates[1];
            estimate.need = estimate.room + 1;
        }),
        fault("h-one", TraceFault::Overflow)
    );
    assert_eq!(
        refused(&|plan| plan.slides.swap(0, 1)),
        fault("a-title", TraceFault::OutOfOrder)
    );
}

#[test]
fn part_names_that_leave_no_room_refuse() {
    let mut parts = template_parts(NAMES);
    parts.push(("ppt/media/image4294967295.png", String::new()));
    let template = Package::open(&archive(&parts), limits()).unwrap();
    let bytes = bytes(&brief());
    assert_eq!(
        compile(&kept("brief@7", &bytes), &template, &assets()).unwrap_err(),
        CompileError::PartNames
    );
}

#[test]
fn the_package_row_names_every_part_and_relationship_to_create() {
    let plan = plan_for(&brief(), &template());
    let package = plan.package();
    // The template's sample slide keeps its name; new parts never collide.
    let slides: Vec<&str> = plan
        .slides()
        .iter()
        .map(|slide| slide.part.as_str())
        .collect();
    assert_eq!(
        slides,
        (2..=9)
            .map(|n| format!("ppt/slides/slide{n}.xml"))
            .collect::<Vec<_>>()
    );
    let new: Vec<(&str, &str)> = package
        .new_parts
        .iter()
        .map(|part| (part.part.as_str(), part.content_type))
        .collect();
    for slide in &slides {
        assert!(new.contains(&(
            slide,
            "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"
        )));
    }
    for n in 1..=2 {
        assert!(new.contains(&(
            format!("ppt/charts/chart{n}.xml").as_str(),
            "application/vnd.openxmlformats-officedocument.drawingml.chart+xml"
        )));
        assert!(new.contains(&(
            format!("ppt/embeddings/Microsoft_Excel_Worksheet{n}.xlsx").as_str(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )));
    }
    assert!(new.contains(&("ppt/media/image1.png", "image/png")));
    assert_eq!(new.len(), slides.len() + 4 + 1);

    let rel = |source: &str, kind: &'static str, target: &str| PlannedRelationship {
        source: at(source),
        kind,
        target: at(target),
    };
    let relationships = &package.relationships;
    assert!(relationships.contains(&rel(
        "ppt/presentation.xml",
        "slide",
        "ppt/slides/slide2.xml"
    )));
    assert!(relationships.contains(&rel(
        "ppt/slides/slide2.xml",
        "slideLayout",
        TITLE_AND_CONTENT
    )));
    assert!(relationships.contains(&rel(
        "ppt/slides/slide4.xml",
        "chart",
        "ppt/charts/chart1.xml"
    )));
    assert!(relationships.contains(&rel(
        "ppt/charts/chart1.xml",
        "package",
        "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx"
    )));
    assert!(relationships.contains(&rel(
        "ppt/slides/slide9.xml",
        "image",
        "ppt/media/image1.png"
    )));
    assert_eq!(
        package.changed_parts,
        [
            "ppt/presentation.xml",
            "ppt/_rels/presentation.xml.rels",
            "[Content_Types].xml"
        ]
    );
    assert_eq!(
        plan.assets()
            .get("plan")
            .map(|binding| binding.handle.as_str()),
        Some("blob:site-plan")
    );
}

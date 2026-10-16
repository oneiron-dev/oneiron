use super::*;
use crate::deck::fixture::{NS, archive, limits};
use crate::design_plan::{Column, ColumnKind};
use crate::ooxml::XmlTree;
use std::io::Write;

const SLIDE: &str = "ppt/slides/slide1.xml";
const CHART: &str = "ppt/charts/chart1.xml";
const BOOK: &str = "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx";
const DML: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";

fn deck() -> Package {
    let types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>"#;
    let slide = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld {NS}><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld></p:sld>"#
    );
    Package::open(
        &archive(&[("[Content_Types].xml", types.to_owned()), (SLIDE, slide)]),
        limits(),
    )
    .unwrap()
}

fn dataset(columns: &[(&str, ColumnKind, Option<&str>)], rows: Vec<Vec<Cell>>) -> Dataset {
    Dataset {
        id: "data".into(),
        columns: columns
            .iter()
            .map(|(name, kind, unit)| Column {
                name: (*name).into(),
                kind: *kind,
                unit: unit.map(Into::into),
            })
            .collect(),
        rows,
        missing: Some("not reported".into()),
        sources: vec!["source".into()],
    }
}

fn sales() -> Dataset {
    use Cell::*;
    dataset(
        &[
            ("Quarter", ColumnKind::Text, None),
            ("North", ColumnKind::Number, Some("EUR")),
            ("South", ColumnKind::Number, Some("EUR")),
        ],
        vec![
            vec![Text("Q1".into()), Number(10.5), Number(7.0)],
            vec![Text("Q2".into()), Missing, Number(8.25)],
            vec![Text("Q3".into()), Number(12.0), Number(-3.0)],
        ],
    )
}

fn frame(id: u32) -> Frame<'static> {
    Frame {
        slide: SLIDE,
        id,
        name: "frame",
        bounds: Rect {
            x: 457_200,
            y: 457_200,
            cx: 6_000_000,
            cy: 3_000_000,
        },
        placeholder: None,
    }
}

fn reopen(package: &Package) -> Package {
    Package::open(&package.export().unwrap(), limits()).unwrap()
}

fn with_chart() -> Package {
    let mut package = deck();
    let data = sales();
    native_patch(
        &mut package,
        &NativeEdit::CreateChart {
            frame: frame(2),
            family: ChartFamily::Bar,
            dataset: &data,
            chart: CHART,
            workbook: BOOK,
            sheet: "Data",
        },
    )
    .unwrap();
    reopen(&package)
}

fn values(data: &ChartData, series: usize) -> &Sequence {
    data.series[series].values.as_ref().unwrap()
}

/// Rewrite the chart part's text, as a corrupt or foreign producer would.
fn edit_chart(package: &mut Package, from: &str, to: &str) {
    let xml = String::from_utf8(package.part(CHART).unwrap().unwrap()).unwrap();
    assert!(xml.contains(from));
    package
        .replace_xml_part(CHART, xml.replace(from, to).into_bytes())
        .unwrap();
}

/// Rewrite one part of the embedded workbook, or add a part to it.
fn edit_workbook(package: &mut Package, part: &str, body: impl Fn(String) -> String) {
    let inner = Package::open(&package.part(BOOK).unwrap().unwrap(), limits()).unwrap();
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let mut names: Vec<String> = inner.names().map(str::to_owned).collect();
    if !names.iter().any(|name| name == part) {
        names.push(part.to_owned());
    }
    for name in names {
        let bytes = inner.part(&name).unwrap().unwrap_or_default();
        let bytes = if name == part {
            body(String::from_utf8(bytes).unwrap()).into_bytes()
        } else {
            bytes
        };
        writer
            .start_file(name, zip::write::FileOptions::default())
            .unwrap();
        writer.write_all(&bytes).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    package.replace_nested_package(BOOK, bytes).unwrap();
}

fn set_values<'a>(values: &'a [Cell]) -> NativeEdit<'a> {
    NativeEdit::SetSeries {
        chart: CHART,
        series: 0,
        target: Target::Values,
        values,
    }
}

/// Refuse with `expected` and leave the exact package bytes behind.
fn refuses(package: &mut Package, edit: &NativeEdit<'_>, expected: &NativeRefusal) {
    let before = package.export().unwrap();
    assert_eq!(native_patch(package, edit).unwrap_err(), *expected);
    assert_eq!(package.export().unwrap(), before);
}

#[test]
fn tables_write_merge_anchors_and_refuse_continuation_writes() {
    use Cell::*;
    let data = dataset(
        &[
            ("Region", ColumnKind::Text, None),
            ("Plan", ColumnKind::Number, Some("units")),
            ("Actual", ColumnKind::Number, Some("units")),
        ],
        vec![
            vec![Text("North".into()), Number(4.0), Missing],
            vec![Missing, Missing, Missing],
            vec![Text("South".into()), Number(2.5), Number(3.0)],
        ],
    );
    let merges = [
        Merge {
            row: 1,
            col: 2,
            rows: 2,
            cols: 1,
        },
        Merge {
            row: 2,
            col: 0,
            rows: 1,
            cols: 2,
        },
    ];
    let mut package = deck();
    let edit = NativeEdit::CreateTable {
        frame: frame(5),
        dataset: &data,
        merges: &merges,
    };
    let report = native_patch(&mut package, &edit).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    let package = &mut reopen(&package);
    let slide = package.part(SLIDE).unwrap().unwrap();
    let tree = XmlTree::parse(&slide, limits().xml).unwrap();
    let cells: Vec<_> = tree
        .nodes
        .iter()
        .filter(|node| node.is(DML, "tc"))
        .collect();
    assert_eq!(cells.len(), 12);
    let attrs = |at: usize, name: &str| cells[at].attr(name).map(str::to_owned);
    // Row 1 col 2 anchors two rows; row 2 col 0 anchors two columns.
    assert_eq!(attrs(5, "rowSpan").as_deref(), Some("2"));
    assert_eq!(attrs(6, "gridSpan").as_deref(), Some("2"));
    assert_eq!(attrs(7, "hMerge").as_deref(), Some("1"));
    assert_eq!(attrs(8, "vMerge").as_deref(), Some("1"));
    let text = |at: usize| -> String {
        tree.nodes
            .iter()
            .filter(|node| node.is(DML, "t") && cells[at].span.contains(&node.span.start))
            .map(|node| node.text.as_str())
            .collect()
    };
    assert_eq!(
        [text(0), text(1), text(4), text(5), text(6)],
        [
            "Region",
            "Plan (units)",
            "4",
            "not reported",
            "not reported"
        ]
    );
    let write = |row, col, expected, value| NativeEdit::SetTableCell {
        slide: SLIDE,
        table: 5,
        row,
        col,
        expected,
        value,
    };
    native_patch(package, &write(1, 1, "4", "4.5\nrevised")).unwrap();
    native_patch(package, &write(1, 1, "4.5\nrevised", "5")).unwrap();
    refuses(
        package,
        &write(2, 1, "", "x"),
        &NativeRefusal::MergedContinuationCell,
    );
    refuses(
        package,
        &write(2, 2, "", "x"),
        &NativeRefusal::MergedContinuationCell,
    );
    refuses(
        package,
        &write(1, 1, "4", "6"),
        &NativeRefusal::Stale("cell text changed"),
    );
    for merges in [
        [
            Merge {
                row: 0,
                col: 0,
                rows: 2,
                cols: 2,
            },
            Merge {
                row: 1,
                col: 1,
                rows: 2,
                cols: 1,
            },
        ],
        [
            Merge {
                row: 3,
                col: 0,
                rows: 1,
                cols: 2,
            },
            Merge {
                row: 0,
                col: 2,
                rows: 5,
                cols: 1,
            },
        ],
        // Endpoints past the address space refuse rather than wrap.
        [
            Merge {
                row: usize::MAX,
                col: 0,
                rows: 1,
                cols: 2,
            },
            Merge {
                row: 0,
                col: 0,
                rows: usize::MAX,
                cols: usize::MAX,
            },
        ],
    ] {
        let edit = NativeEdit::CreateTable {
            frame: frame(6),
            dataset: &data,
            merges: &merges,
        };
        assert!(matches!(
            native_patch(package, &edit),
            Err(NativeRefusal::UnsupportedMergeTopology(_))
        ));
    }
    // A broken topology in an existing table refuses every write.
    let xml = String::from_utf8(package.part(SLIDE).unwrap().unwrap()).unwrap();
    let broken = xml.replacen(" vMerge=\"1\"", "", 1);
    package
        .replace_xml_part(SLIDE, broken.into_bytes())
        .unwrap();
    assert!(matches!(
        native_patch(package, &write(0, 0, "Region", "Area")),
        Err(NativeRefusal::UnsupportedMergeTopology(_))
    ));
}

#[test]
fn created_charts_reimport_with_caches_equal_to_their_workbook() {
    let package = with_chart();
    let names: Vec<&str> = package.names().collect();
    for part in [
        CHART,
        BOOK,
        "ppt/charts/_rels/chart1.xml.rels",
        "ppt/slides/_rels/slide1.xml.rels",
    ] {
        assert!(names.contains(&part), "{part}");
    }
    let types = String::from_utf8(package.part("[Content_Types].xml").unwrap().unwrap()).unwrap();
    assert!(types.contains(r#"<Override PartName="/ppt/charts/chart1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>"#));
    assert!(types.contains(r#"PartName="/ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx""#));
    let slide_rels = package.relationships(SLIDE).unwrap();
    assert_eq!(slide_rels[0].target, CHART);
    let data = chart_data(&package, CHART).unwrap();
    assert_eq!(data.series.len(), 2);
    for series in &data.series {
        for sequence in [&series.name, &series.categories, &series.values] {
            let sequence = sequence.as_ref().unwrap();
            assert_eq!(sequence.cache, sequence.workbook, "{}", sequence.reference);
        }
    }
    let north = values(&data, 0);
    assert_eq!(north.reference, "'Data'!$B$2:$B$4");
    // Missing is a gap, not zero, in the cache and the workbook alike.
    assert_eq!(
        north.cache,
        [Cell::Number(10.5), Cell::Missing, Cell::Number(12.0)]
    );
    assert_eq!(
        data.series[1].name.as_ref().unwrap().cache,
        [Cell::Text("South (EUR)".into())]
    );
    let categories = data.series[0].categories.as_ref().unwrap();
    assert_eq!(categories.workbook[2], Cell::Text("Q3".into()));
}

#[test]
fn same_length_updates_write_caches_and_cells_together() {
    let mut package = with_chart();
    let new = [Cell::Number(1.25), Cell::Number(0.0), Cell::Missing];
    let report = native_patch(&mut package, &set_values(&new)).unwrap();
    assert_eq!(report.changed_parts, [BOOK, CHART]);
    let workbook = report.workbook.unwrap();
    assert_eq!(workbook.part, BOOK);
    assert_eq!(workbook.changed_parts, ["xl/worksheets/sheet1.xml"]);
    let cells: Vec<&str> = workbook
        .cells
        .iter()
        .map(|write| write.cell.as_str())
        .collect();
    assert_eq!(cells, ["B2", "B3", "B4"]);
    let package = &mut reopen(&package);
    let data = chart_data(package, CHART).unwrap();
    assert_eq!(values(&data, 0).cache, new);
    assert_eq!(values(&data, 0).workbook, new);
    // The other series is untouched.
    assert_eq!(values(&data, 1).cache[1], Cell::Number(8.25));
    // Categories are shared by both series' caches.
    let quarters = [
        Cell::Text("H1".into()),
        Cell::Date("2026-07-01".into()),
        Cell::Number(2027.0),
    ];
    let edit = NativeEdit::SetSeries {
        chart: CHART,
        series: 1,
        target: Target::Categories,
        values: &quarters,
    };
    native_patch(package, &edit).unwrap();
    let rename = [Cell::Text("Nord".into())];
    let edit = NativeEdit::SetSeries {
        chart: CHART,
        series: 0,
        target: Target::Name,
        values: &rename,
    };
    native_patch(package, &edit).unwrap();
    let data = chart_data(&reopen(package), CHART).unwrap();
    let expected = [
        Cell::Text("H1".into()),
        Cell::Text("2026-07-01".into()),
        Cell::Text("2027".into()),
    ];
    for series in &data.series {
        let categories = series.categories.as_ref().unwrap();
        assert_eq!(categories.cache, expected);
        assert_eq!(categories.workbook, expected);
    }
    assert_eq!(data.series[0].name.as_ref().unwrap().workbook, rename);
}

#[test]
fn length_changes_and_mistyped_values_refuse() {
    let mut package = with_chart();
    let short = [Cell::Number(1.0), Cell::Number(2.0)];
    refuses(
        &mut package,
        &set_values(&short),
        &NativeRefusal::LengthChange { have: 3, want: 2 },
    );
    let long = vec![Cell::Number(1.0); 4];
    refuses(
        &mut package,
        &set_values(&long),
        &NativeRefusal::LengthChange { have: 3, want: 4 },
    );
    let text = [Cell::Number(1.0), Cell::Text("x".into()), Cell::Missing];
    refuses(
        &mut package,
        &set_values(&text),
        &NativeRefusal::Invalid("text in a number sequence"),
    );
}

#[test]
fn formula_backed_external_and_shared_sources_refuse() {
    let new = [Cell::Number(1.0), Cell::Number(2.0), Cell::Number(3.0)];
    // A formula in a source cell, and one elsewhere in the workbook.
    let mut package = with_chart();
    edit_workbook(&mut package, "xl/worksheets/sheet1.xml", |sheet| {
        sheet.replace(
            "<c r=\"B2\"><v>10.5</v></c>",
            "<c r=\"B2\"><f>1+9.5</f><v>10.5</v></c>",
        )
    });
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::FormulaBackedSeries("a source cell holds a formula"),
    );
    let mut package = with_chart();
    edit_workbook(&mut package, "xl/worksheets/sheet1.xml", |sheet| {
        sheet.replace(
            "<c r=\"C4\"><v>-3</v></c>",
            "<c r=\"C4\"><f>B2-15.5</f><v>-3</v></c>",
        )
    });
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::FormulaBackedSeries("the workbook holds formulas a write could make stale"),
    );
    // A reference into another workbook.
    let mut package = with_chart();
    edit_chart(
        &mut package,
        "<c:f>&apos;Data&apos;!$B$2:$B$4</c:f>",
        "<c:f>[1]Data!$B$2:$B$4</c:f>",
    );
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::ExternalChartSource("the reference names another workbook"),
    );
    // Chart data linked outside the package.
    let types = r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>"#;
    let chart = String::from_utf8(with_chart().part(CHART).unwrap().unwrap()).unwrap();
    let rels = r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="file:///C:/data.xlsx" TargetMode="External"/></Relationships>"#;
    let mut package = Package::open(
        &archive(&[
            ("[Content_Types].xml", types.to_owned()),
            (CHART, chart),
            ("ppt/charts/_rels/chart1.xml.rels", rels.to_owned()),
        ]),
        limits(),
    )
    .unwrap();
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::ExternalChartSource("the chart data links outside the package"),
    );
    // A second chart over the same workbook.
    let mut package = with_chart();
    let chart = package.part(CHART).unwrap().unwrap();
    package
        .add_part("ppt/charts/chart2.xml", CHART_TYPE, chart)
        .unwrap();
    package
        .relate("ppt/charts/chart2.xml", &format!("{REL}/package"), BOOK)
        .unwrap();
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::SharedChartData,
    );
    // A chart-level reference the model does not own, and ChartEx.
    let mut package = with_chart();
    edit_chart(
        &mut package,
        "<c:autoTitleDeleted val=\"1\"/>",
        "<c:title><c:tx><c:strRef><c:f>'Data'!$A$1</c:f></c:strRef></c:tx></c:title>",
    );
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::AmbiguousChartData("a cell reference outside the series data"),
    );
    let mut package = with_chart();
    edit_chart(
        &mut package,
        "<c:chartSpace xmlns:c=\"http://schemas.openxmlformats.org/drawingml/2006/chart\"",
        "<c:chartSpace xmlns:c=\"http://schemas.microsoft.com/office/drawing/2014/chartex\"",
    );
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::UnsupportedChartFamily("not a classic chart part"),
    );
}

#[test]
fn a_workbook_failure_lands_nothing() {
    let mut package = with_chart();
    edit_workbook(&mut package, "_xmlsignatures/sig1.xml", |_| {
        "<Signature/>".to_owned()
    });
    let new = [Cell::Number(1.0), Cell::Number(2.0), Cell::Number(3.0)];
    refuses(
        &mut package,
        &set_values(&new),
        &NativeRefusal::Workbook(retained_opc::Error::Edit(
            "signed or unsupported metadata is read-only",
        )),
    );
    let data = chart_data(&package, CHART).unwrap();
    assert_eq!(values(&data, 0).cache[0], Cell::Number(10.5));
}

#[test]
fn creation_refuses_charts_the_dataset_cannot_carry() {
    let mut package = deck();
    let data = sales();
    let edit = |family, sheet| NativeEdit::CreateChart {
        frame: frame(2),
        family,
        dataset: &data,
        chart: CHART,
        workbook: BOOK,
        sheet,
    };
    refuses(
        &mut package,
        &edit(ChartFamily::Pie, "Data"),
        &NativeRefusal::Invalid("a pie chart carries one series"),
    );
    refuses(
        &mut package,
        &edit(ChartFamily::Line, "Da:ta"),
        &NativeRefusal::Invalid("sheet name"),
    );
    let edit = NativeEdit::CreateChart {
        frame: frame(1),
        family: ChartFamily::Line,
        dataset: &data,
        chart: CHART,
        workbook: BOOK,
        sheet: "Data",
    };
    refuses(
        &mut package,
        &edit,
        &NativeRefusal::Invalid("shape id already used in the slide"),
    );
}

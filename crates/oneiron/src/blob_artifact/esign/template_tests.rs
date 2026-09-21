//! Parsed output tests of the actual native HTML renderer and upload bypass.
use super::*;
use lopdf::Document;
fn template(html: &str) -> HtmlContentTemplate {
    HtmlContentTemplate {
        html: html.into(),
        page: TemplatePage::default(),
    }
}
#[test]
fn html_merge_typography_tables_and_pagination_are_real_deterministic_pdf_content() {
    let input = template(
        r#"<!doctype html><html><head><style>h1 {color:#0000ff;} .next {break-before:page;}</style></head><body><h1>Agreement for {{party.name}}</h1><p>Fee: <strong>{{fee}}</strong>; accepted by José.</p><table><tr><th>Service</th><th>Amount</th></tr><tr><td>Review</td><td>100</td></tr></table><section class="next"><h2>Conditions</h2><ol><li>First term</li><li>Second term</li></ol></section></body></html>"#,
    );
    let values = BTreeMap::from([
        ("party.name".into(), "<Client & Co>".into()),
        ("fee".into(), "EUR 100".into()),
    ]);
    let bytes = render_html_template(&input, &values).unwrap();
    assert_eq!(bytes, render_html_template(&input, &values).unwrap());
    let pdf = Document::load_mem(&bytes).unwrap();
    assert_eq!(pdf.get_pages().len(), 2);
    let first = pdf.extract_text(&[1]).unwrap();
    assert!(first.contains("<Client & Co>"));
    assert!(first.contains("EUR 100"));
    assert!(first.contains("José"));
    assert!(first.contains("Review"));
    assert!(pdf.extract_text(&[2]).unwrap().contains("Second term"));
    let ops = pdf
        .get_and_decode_page_content(pdf.get_pages()[&1])
        .unwrap()
        .operations;
    assert_eq!(ops.iter().filter(|o| o.operator == "re").count(), 4);
    assert!(
        ops.iter()
            .any(|o| o.operator == "Tf" && o.operands[0].as_name().unwrap() == b"F1")
    );
    assert_eq!(render::inspect_pdf_pages(&bytes).unwrap().len(), 2);
}
#[test]
fn geography_is_data_and_uploads_bypass_template_generation_byte_for_byte() {
    let original =
        render_html_template(&template("<p>Pristine original</p>"), &BTreeMap::new()).unwrap();
    let pack = FieldGeographyPack {
        schema_version: 1,
        fields: vec![EsignField {
            id: crate::EntityId::now().to_hex(),
            item: 0,
            recipient: crate::EntityId::now().to_hex(),
            required: true,
            geometry: super::super::FieldGeometry {
                page: 1,
                x_percent: 10.,
                y_percent: 80.,
                width_percent: 30.,
                height_percent: 10.,
            },
            meta: super::super::FieldMeta::Signature,
        }],
    };
    let uploaded = prepare_content(ContentSource::Upload(&original), &pack, 0).unwrap();
    assert_eq!(uploaded.bytes, original);
    assert_eq!(uploaded.fields, pack.fields);
    assert!(!uploaded.generated_from_template);
    let generated = prepare_content(
        ContentSource::Template {
            template: &template("<p>{{repo.value}}</p>"),
            merge_fields: &BTreeMap::from([("repo.value".into(), "Generated original".into())]),
        },
        &pack,
        0,
    )
    .unwrap();
    assert!(generated.generated_from_template);
    assert!(
        Document::load_mem(&generated.bytes)
            .unwrap()
            .extract_text(&[1])
            .unwrap()
            .contains("Generated original")
    );
    let mut bad = pack;
    bad.fields[0].geometry.page = 2;
    assert!(matches!(
        prepare_content(ContentSource::Upload(&original), &bad, 0),
        Err(ContentTemplateError::Geometry)
    ));
}
#[test]
fn template_does_not_execute_fetch_or_silently_drop_unsupported_visual_content() {
    for html in [
        "<script>alert(1)</script>",
        "<img src='https://outside.test/a'>",
        "<p onclick='evil()'>x</p>",
        "<p style='position:absolute'>x</p>",
        "<style>@import url(https://outside.test)</style><p>x</p>",
    ] {
        assert_eq!(
            render_html_template(&template(html), &BTreeMap::new()).unwrap_err(),
            ContentTemplateError::UnsupportedHtml
        );
    }
    assert_eq!(
        render_html_template(&template("<p>{{missing}}</p>"), &BTreeMap::new()).unwrap_err(),
        ContentTemplateError::MergeField
    );
    assert_eq!(
        render_html_template(
            &template("<p title='{{value}}'>x</p>"),
            &BTreeMap::from([("value".into(), "x".into())])
        )
        .unwrap_err(),
        ContentTemplateError::UnsupportedHtml
    );
    let bytes = render_html_template(
        &template("<p>{{value}}</p>"),
        &BTreeMap::from([("value".into(), "<script>not executed</script>".into())]),
    )
    .unwrap();
    assert!(
        Document::load_mem(&bytes)
            .unwrap()
            .extract_text(&[1])
            .unwrap()
            .contains("<script>not executed</script>")
    );
}

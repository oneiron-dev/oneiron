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

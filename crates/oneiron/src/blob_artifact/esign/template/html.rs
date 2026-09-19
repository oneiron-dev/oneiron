//! HTML5 DOM merge and safe, deterministic document typography.
use super::layout::{Flow, Style};
use super::*;
use dom_query::{Document, NodeRef};

pub(super) fn parse(html: &str, values: &BTreeMap<String, String>) -> Result<Document> {
    if html.len() > 1024 * 1024
        || values.len() > 4096
        || values.values().map(String::len).sum::<usize>() > 1024 * 1024
    {
        return Err(ContentTemplateError::Limit);
    }
    let document = Document::from(html);
    let mut count = 0;
    let mut total = 0;
    let mut stack = vec![(document.root(), 0)];
    while let Some((node, depth)) = stack.pop() {
        count += 1;
        if count > 50_000 || depth > 64 {
            return Err(ContentTemplateError::Limit);
        }
        if node.is_text() {
            let text = merge(&node.text(), values)?;
            total += text.len();
            if total > 2 * 1024 * 1024 {
                return Err(ContentTemplateError::Limit);
            }
            node.set_text(text);
        } else if node.is_element() {
            let name = node
                .node_name()
                .ok_or(ContentTemplateError::UnsupportedHtml)?;
            if !matches!(
                name.as_ref(),
                "html"
                    | "head"
                    | "title"
                    | "meta"
                    | "style"
                    | "body"
                    | "main"
                    | "article"
                    | "section"
                    | "header"
                    | "footer"
                    | "div"
                    | "p"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "span"
                    | "strong"
                    | "b"
                    | "em"
                    | "i"
                    | "small"
                    | "br"
                    | "hr"
                    | "ul"
                    | "ol"
                    | "li"
                    | "table"
                    | "thead"
                    | "tbody"
                    | "tfoot"
                    | "tr"
                    | "td"
                    | "th"
                    | "blockquote"
                    | "pre"
                    | "code"
                    | "a"
            ) {
                return Err(ContentTemplateError::UnsupportedHtml);
            }
            for attr in node.attrs() {
                let key = attr.name.local.as_ref();
                let value = attr.value.as_ref();
                if value.contains("{{")
                    || !attr.name.ns.is_empty()
                    || !matches!(
                        key,
                        "id" | "class"
                            | "style"
                            | "lang"
                            | "dir"
                            | "title"
                            | "charset"
                            | "href"
                            | "colspan"
                            | "rowspan"
                    )
                    || (key == "dir" && value != "ltr")
                    || (matches!(key, "colspan" | "rowspan") && value != "1")
                    || (key == "href" && !(value.starts_with("https://") || value.starts_with('#')))
                {
                    return Err(ContentTemplateError::UnsupportedHtml);
                }
            }
            // A style element is code, not a merge context.
            if name.as_ref() == "style" && node.text().contains("{{") {
                return Err(ContentTemplateError::MergeField);
            }
        }
        stack.extend(node.children_it(false).map(|n| (n, depth + 1)));
    }
    Ok(document)
}
fn merge(text: &str, values: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let end = rest.find("}}").ok_or(ContentTemplateError::MergeField)?;
        let key = rest[..end].trim();
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(ContentTemplateError::MergeField);
        }
        let value = values.get(key).ok_or(ContentTemplateError::MergeField)?;
        if out.len() + value.len() > 2 * 1024 * 1024 {
            return Err(ContentTemplateError::Limit);
        }
        out.push_str(value);
        rest = &rest[end + 2..];
    }
    if rest.contains("}}") {
        return Err(ContentTemplateError::MergeField);
    }
    out.push_str(rest);
    Ok(out)
}
struct Rule {
    selector: String,
    matcher: dom_query::Matcher,
    declarations: String,
}
pub(super) fn render(document: &Document, flow: &mut Flow) -> Result<()> {
    let mut rules = Vec::new();
    for node in document.select("style").nodes() {
        let text = node.text();
        let mut rest = text.as_ref();
        while !rest.trim().is_empty() {
            let (selectors, body) = rest
                .split_once('{')
                .ok_or(ContentTemplateError::UnsupportedHtml)?;
            let (declarations, remaining) = body
                .split_once('}')
                .ok_or(ContentTemplateError::UnsupportedHtml)?;
            // Only static simple selectors. No @import, URLs, pseudo state, or
            // renderer-dependent cascade features are silently ignored.
            for selector in selectors.split(',') {
                let selector = selector.trim();
                if selector.is_empty()
                    || selector.len() > 128
                    || !selector
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".#_-".contains(&b))
                {
                    return Err(ContentTemplateError::UnsupportedHtml);
                }
                declarations_apply(declarations, Style::default())?;
                let matcher = dom_query::Matcher::new(selector)
                    .map_err(|_| ContentTemplateError::UnsupportedHtml)?;
                rules.push(Rule {
                    selector: selector.into(),
                    matcher,
                    declarations: declarations.into(),
                });
                if rules.len() > 1024 {
                    return Err(ContentTemplateError::Limit);
                }
            }
            rest = remaining;
        }
    }
    if document
        .root()
        .descendants_it()
        .count()
        .saturating_mul(rules.len().max(1))
        > 500_000
    {
        return Err(ContentTemplateError::Limit);
    }
    walk(document.root(), flow, Style::default(), &rules, 0)?;
    flow.flush()
}
#[derive(Default)]
struct BoxStyle {
    before: bool,
    after: bool,
    top: f64,
    bottom: f64,
}
fn declarations_apply(css: &str, mut style: Style) -> Result<(Style, BoxStyle)> {
    let mut block = BoxStyle::default();
    for declaration in css.split(';').filter(|s| !s.trim().is_empty()) {
        let (key, value) = declaration
            .split_once(':')
            .ok_or(ContentTemplateError::UnsupportedHtml)?;
        let value = value.trim();
        match key.trim() {
            "font-size" => {
                style.size = length(value)?;
                if !(6.0..=72.0).contains(&style.size) {
                    return Err(ContentTemplateError::UnsupportedHtml);
                }
            }
            "font-family"
                if matches!(
                    value,
                    "monospace" | "Courier" | "Courier New" | "'Courier New'" | "\"Courier New\""
                ) => {}
            "font-weight" => {
                style.bold = match value {
                    "bold" | "700" => true,
                    "normal" | "400" => false,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "font-style" => {
                style.italic = match value {
                    "italic" | "oblique" => true,
                    "normal" => false,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "text-align" => {
                style.align = match value {
                    "left" | "start" => 0,
                    "center" => 1,
                    "right" | "end" => 2,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "white-space" => {
                style.pre = match value {
                    "pre" | "pre-wrap" => true,
                    "normal" => false,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "color" => style.color = color(value)?,
            "margin-top" | "padding-top" => block.top = length(value)?,
            "margin-bottom" | "padding-bottom" => block.bottom = length(value)?,
            "page-break-before" | "break-before" => {
                block.before = match value {
                    "always" | "page" => true,
                    "auto" => false,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "page-break-after" | "break-after" => {
                block.after = match value {
                    "always" | "page" => true,
                    "auto" => false,
                    _ => return Err(ContentTemplateError::UnsupportedHtml),
                }
            }
            "border-collapse" if value == "collapse" => {}
            _ => return Err(ContentTemplateError::UnsupportedHtml),
        }
    }
    Ok((style, block))
}
fn length(value: &str) -> Result<f64> {
    let (number, scale) = if let Some(v) = value.strip_suffix("pt") {
        (v, 1.)
    } else if let Some(v) = value.strip_suffix("px") {
        (v, 0.75)
    } else if let Some(v) = value.strip_suffix("mm") {
        (v, 72. / 25.4)
    } else if let Some(v) = value.strip_suffix("in") {
        (v, 72.)
    } else if value == "0" {
        ("0", 1.)
    } else {
        return Err(ContentTemplateError::UnsupportedHtml);
    };
    let value = number
        .parse::<f64>()
        .map_err(|_| ContentTemplateError::UnsupportedHtml)?
        * scale;
    if !value.is_finite() || !(0.0..=720.).contains(&value) {
        return Err(ContentTemplateError::UnsupportedHtml);
    }
    Ok(value)
}
fn color(value: &str) -> Result<[f64; 3]> {
    let hex = match value {
        "black" => "000000",
        "white" => "ffffff",
        "red" => "ff0000",
        "blue" => "0000ff",
        _ => value
            .strip_prefix('#')
            .ok_or(ContentTemplateError::UnsupportedHtml)?,
    };
    if hex.len() != 6 || !hex.is_ascii() {
        return Err(ContentTemplateError::UnsupportedHtml);
    }
    let mut rgb = [0.; 3];
    for (i, v) in rgb.iter_mut().enumerate() {
        *v = f64::from(
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ContentTemplateError::UnsupportedHtml)?,
        ) / 255.;
    }
    Ok(rgb)
}
fn walk(
    node: NodeRef<'_>,
    flow: &mut Flow,
    mut style: Style,
    rules: &[Rule],
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(ContentTemplateError::Limit);
    }
    if node.is_text() {
        return flow.text(&node.text(), style);
    }
    if node.is_comment() || node.is_doctype() {
        return Ok(());
    }
    let name = node.node_name().map(|n| n.to_string()).unwrap_or_default();
    if matches!(name.as_str(), "head" | "title" | "meta" | "style") {
        return Ok(());
    }
    match name.as_str() {
        "h1" => {
            style.size = 24.;
            style.bold = true;
        }
        "h2" => {
            style.size = 18.;
            style.bold = true;
        }
        "h3" | "h4" | "h5" | "h6" => {
            style.size = 14.;
            style.bold = true;
        }
        "strong" | "b" | "th" => style.bold = true,
        "em" | "i" => style.italic = true,
        "small" => style.size = (style.size * 0.8).max(6.),
        "pre" => style.pre = true,
        _ => {}
    }
    // Simple selectors use normal CSS specificity and source-order precedence.
    let mut matched: Vec<_> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| node.is_match(&r.matcher))
        .collect();
    matched.sort_by_key(|(i, r)| {
        (
            r.selector.bytes().filter(|b| *b == b'#').count(),
            r.selector.bytes().filter(|b| *b == b'.').count(),
            *i,
        )
    });
    let mut css = String::new();
    for (_, rule) in matched {
        css.push_str(&rule.declarations);
        css.push(';');
    }
    if let Some(inline) = node.attr("style") {
        css.push_str(&inline);
    }
    let (style, block) = declarations_apply(&css, style)?;
    if block.before {
        flow.page_break()?;
    }
    let is_block = matches!(
        name.as_str(),
        "body"
            | "main"
            | "article"
            | "section"
            | "header"
            | "footer"
            | "div"
            | "p"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "ul"
            | "ol"
            | "li"
            | "table"
            | "blockquote"
            | "pre"
    );
    if is_block {
        flow.flush()?;
    }
    if block.top > 0. {
        flow.gap(block.top)?;
    }
    match name.as_str() {
        "br" => flow.flush()?,
        "hr" => flow.rule()?,
        "table" => table(node, flow, style, rules, depth + 1)?,
        _ => {
            if name == "li" {
                let ordered = node.parent().is_some_and(|p| p.has_name("ol"));
                let prefix = if ordered {
                    format!(
                        "{}. ",
                        node.parent()
                            .map_or(1, |p| p
                                .element_children()
                                .iter()
                                .take_while(|n| n.id != node.id)
                                .count()
                                + 1)
                    )
                } else {
                    "- ".into()
                };
                flow.text(&prefix, style)?;
            }
            for child in node.children_it(false) {
                walk(child, flow, style, rules, depth + 1)?;
            }
        }
    }
    if is_block {
        flow.flush()?;
    }
    let default_gap = if matches!(
        name.as_str(),
        "p" | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "ul"
            | "ol"
            | "table"
            | "blockquote"
            | "pre"
    ) {
        6.
    } else {
        0.
    };
    if block.bottom + default_gap > 0. {
        flow.gap(block.bottom + default_gap)?;
    }
    if block.after {
        flow.page_break()?;
    }
    Ok(())
}
fn table(
    node: NodeRef<'_>,
    flow: &mut Flow,
    style: Style,
    rules: &[Rule],
    depth: usize,
) -> Result<()> {
    let mut rows = Vec::new();
    for child in node.element_children() {
        if child.has_name("tr") {
            rows.push(child);
        } else if matches!(
            child.node_name().as_deref(),
            Some("thead" | "tbody" | "tfoot")
        ) {
            rows.extend(child.element_children());
        } else {
            return Err(ContentTemplateError::UnsupportedHtml);
        }
    }
    for row in rows {
        if !row.has_name("tr") {
            return Err(ContentTemplateError::UnsupportedHtml);
        }
        let cells = row.element_children();
        if cells.is_empty() || cells.len() > 32 {
            return Err(ContentTemplateError::Limit);
        }
        let width = flow.width() / cells.len() as f64 - 6.;
        if width < 12. {
            return Err(ContentTemplateError::Overflow);
        }
        let mut rendered = Vec::new();
        for cell in cells {
            if !cell.has_name("td") && !cell.has_name("th") {
                return Err(ContentTemplateError::UnsupportedHtml);
            }
            let mut output = Flow::new(TemplatePage {
                width,
                height: flow.page.height,
                margin: 0.,
            });
            walk(cell, &mut output, style, rules, depth + 1)?;
            output.flush()?;
            rendered.push(output);
        }
        flow.table_row(rendered)?;
    }
    Ok(())
}

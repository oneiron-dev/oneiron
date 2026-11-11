//! HTML5 DOM merge and safe, deterministic document typography.
use super::layout::{Flow, Style};
use super::*;
use dom_query::{Document, NodeRef};

/// Parses and merges a template of any size, with merge values of any number
/// and length (Rule 5). DOM validation and rendering use explicit worklists.
pub(super) fn parse(html: &str, values: &BTreeMap<String, String>) -> Result<Document> {
    let document = Document::from(html);
    let mut stack = vec![document.root()];
    while let Some(node) = stack.pop() {
        if node.is_text() {
            let text = merge(&node.text(), values)?;
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
        stack.extend(node.children_it(false));
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
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(ContentTemplateError::MergeField);
        }
        let value = values.get(key).ok_or(ContentTemplateError::MergeField)?;
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
            }
            rest = remaining;
        }
    }
    walk(document.root(), flow, Style::default(), &rules)?;
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
enum WalkTask<'tree> {
    Enter(NodeRef<'tree>, Style),
    Exit {
        is_block: bool,
        default_gap: f64,
        block: BoxStyle,
    },
    Rows(std::vec::IntoIter<NodeRef<'tree>>, Style),
    Bands {
        cells: std::vec::IntoIter<NodeRef<'tree>>,
        band_size: usize,
        style: Style,
    },
    Cell(CellBand<'tree>),
    CellDone(CellBand<'tree>),
}
struct CellBand<'tree> {
    cells: std::vec::IntoIter<NodeRef<'tree>>,
    rendered: Vec<Flow>,
    width: f64,
    style: Style,
}
fn walk(node: NodeRef<'_>, root: &mut Flow, style: Style, rules: &[Rule]) -> Result<()> {
    let mut tasks = vec![WalkTask::Enter(node, style)];
    let mut cell_flows = Vec::<Flow>::new();
    while let Some(task) = tasks.pop() {
        let flow = cell_flows.last_mut().unwrap_or(&mut *root);
        match task {
            WalkTask::Enter(node, mut style) => {
                if node.is_text() {
                    flow.text(&node.text(), style)?;
                    continue;
                }
                if node.is_comment() || node.is_doctype() {
                    continue;
                }
                let name = node.node_name().map(|n| n.to_string()).unwrap_or_default();
                if matches!(name.as_str(), "head" | "title" | "meta" | "style") {
                    continue;
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
                tasks.push(WalkTask::Exit {
                    is_block,
                    default_gap,
                    block,
                });
                match name.as_str() {
                    "br" => flow.flush()?,
                    "hr" => flow.rule()?,
                    "table" => {
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
                        tasks.push(WalkTask::Rows(rows.into_iter(), style));
                    }
                    _ => {
                        if name == "li" {
                            let ordered = node.parent().is_some_and(|p| p.has_name("ol"));
                            let prefix = if ordered {
                                format!(
                                    "{}. ",
                                    node.parent().map_or(1, |p| p
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
                        tasks.extend(
                            node.children_it(true)
                                .map(|child| WalkTask::Enter(child, style)),
                        );
                    }
                }
            }
            WalkTask::Exit {
                is_block,
                default_gap,
                block,
            } => {
                if is_block {
                    flow.flush()?;
                }
                if block.bottom + default_gap > 0. {
                    flow.gap(block.bottom + default_gap)?;
                }
                if block.after {
                    flow.page_break()?;
                }
            }
            WalkTask::Rows(mut rows, style) => {
                let Some(row) = rows.next() else {
                    continue;
                };
                if !row.has_name("tr") {
                    return Err(ContentTemplateError::UnsupportedHtml);
                }
                let cells = row.element_children();
                tasks.push(WalkTask::Rows(rows, style));
                if cells.is_empty() {
                    continue;
                }
                // Preserve the existing equal-width column bands for each row.
                let fit = ((flow.width() / (MIN_CELL_POINTS + 6.)).floor() as usize).max(1);
                let bands = cells.len().div_ceil(fit);
                let band_size = cells.len().div_ceil(bands);
                tasks.push(WalkTask::Bands {
                    cells: cells.into_iter(),
                    band_size,
                    style,
                });
            }
            WalkTask::Bands {
                mut cells,
                band_size,
                style,
            } => {
                let band: Vec<_> = cells.by_ref().take(band_size).collect();
                if band.is_empty() {
                    continue;
                }
                let width = flow.width() / band.len() as f64 - 6.;
                if width < MIN_CELL_POINTS {
                    return Err(ContentTemplateError::Overflow);
                }
                tasks.push(WalkTask::Bands {
                    cells,
                    band_size,
                    style,
                });
                tasks.push(WalkTask::Cell(CellBand {
                    cells: band.into_iter(),
                    rendered: Vec::new(),
                    width,
                    style,
                }));
            }
            WalkTask::Cell(mut band) => {
                if let Some(cell) = band.cells.next() {
                    if !cell.has_name("td") && !cell.has_name("th") {
                        return Err(ContentTemplateError::UnsupportedHtml);
                    }
                    let output = Flow::new(flow.cell_page(band.width));
                    let style = band.style;
                    cell_flows.push(output);
                    tasks.push(WalkTask::CellDone(band));
                    tasks.push(WalkTask::Enter(cell, style));
                } else {
                    flow.table_row(band.rendered)?;
                }
            }
            WalkTask::CellDone(mut band) => {
                let mut output = cell_flows.pop().expect("active table cell");
                output.flush()?;
                band.rendered.push(output);
                tasks.push(WalkTask::Cell(band));
            }
        }
    }
    Ok(())
}
/// The narrowest a table cell's content is laid out, in points.
const MIN_CELL_POINTS: f64 = 12.;

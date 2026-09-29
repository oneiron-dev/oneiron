//! Typed formula caches as checked byte patches, preserving unmodelled XML.
use std::ops::Range;

use formualizer_common::{DateSystem, LiteralValue};

use crate::engine::{CellValue, from_literal_for_date_system};
use crate::xml::{MAIN, Xml, escaped, invalid, unsupported};
use crate::{Result, storage_form};

pub(crate) struct Patch {
    span: Range<usize>,
    replacement: Vec<u8>,
}

pub(crate) fn cache_patches(
    source: &[u8],
    xml: &Xml,
    cell_index: usize,
    formula_index: usize,
    literal: LiteralValue,
    date_system: DateSystem,
    patches: &mut Vec<Patch>,
) -> Result<()> {
    let cell = &xml.nodes[cell_index];
    let formula_node = &xml.nodes[formula_index];
    let value = from_literal_for_date_system(literal, date_system);
    let (kind, text) = encode(value)?;
    // Retain all unknown attributes on <c>, <f> and <v>. Only the cell's
    // value type, the formula text and its cached value are ours to replace.
    if cell.attr("t") != kind {
        match cell.attr_spans.get("t") {
            Some(span) => patches.push(Patch {
                span: span.clone(),
                replacement: kind.map_or_else(Vec::new, |t| format!("t=\"{t}\"").into_bytes()),
            }),
            None => {
                if let Some(kind) = kind {
                    patches.push(Patch {
                        span: cell.open_end - 1..cell.open_end - 1,
                        replacement: format!(" t=\"{kind}\"").into_bytes(),
                    });
                }
            }
        }
    }
    if xml.child(cell_index, MAIN, "is")?.is_some() {
        return Err(unsupported("formula with inline-string cache"));
    }
    let formula = formula_node.text.as_str();
    let storage = storage_form(formula.strip_prefix('=').unwrap_or(formula));
    if formula_node.text != storage {
        text_patch(source, xml, formula_index, &escaped(&storage), patches)?;
    }
    if let Some((index, _)) = xml.child(cell_index, MAIN, "v")? {
        text_patch(source, xml, index, &escaped(&text), patches)?;
    } else {
        let name = cell.child_name("v");
        patches.push(Patch {
            span: formula_node.span.end..formula_node.span.end,
            replacement: format!("<{name}>{}</{name}>", escaped(&text)).into_bytes(),
        });
    }
    Ok(())
}

fn encode(value: CellValue) -> Result<(Option<&'static str>, String)> {
    Ok(match value {
        CellValue::Number(number) if number.is_finite() => (None, number.to_string()),
        CellValue::Bool(flag) => (Some("b"), if flag { "1" } else { "0" }.into()),
        CellValue::Text(text) => {
            if !text.chars().all(|c| matches!(c, '\t' | '\n' | '\r' | ' '..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')) {
                return Err(unsupported("XML-invalid cached text"));
            }
            if text.as_bytes().windows(7).any(|w| {
                w[0..2] == *b"_x" && w[6] == b'_' && w[2..6].iter().all(u8::is_ascii_hexdigit)
            }) {
                return Err(unsupported("OOXML escaped cached text"));
            }
            (Some("str"), text)
        }
        CellValue::Error(error)
            if matches!(
                error.as_str(),
                "#NULL!"
                    | "#DIV/0!"
                    | "#VALUE!"
                    | "#REF!"
                    | "#NAME?"
                    | "#NUM!"
                    | "#N/A"
                    | "#SPILL!"
                    | "#CALC!"
            ) =>
        {
            (Some("e"), error)
        }
        CellValue::Blank => (None, String::new()),
        CellValue::Array(mut rows) if rows.len() == 1 && rows[0].len() == 1 => {
            let value = rows
                .pop()
                .and_then(|mut row| row.pop())
                .ok_or_else(|| invalid("empty scalar array"))?;
            return encode(value);
        }
        _ => return Err(unsupported("non-scalar or unrepresentable formula cache")),
    })
}

fn text_patch(
    source: &[u8],
    xml: &Xml,
    index: usize,
    text: &str,
    patches: &mut Vec<Patch>,
) -> Result<()> {
    let node = &xml.nodes[index];
    if xml.children(index).next().is_some() {
        return Err(unsupported("opaque content in formula or cache"));
    }
    if node.empty {
        let mut replacement = source[node.span.start..node.open_end - 2].to_vec();
        replacement.extend_from_slice(format!(">{text}</{}>", node.qualified).as_bytes());
        patches.push(Patch {
            span: node.span.clone(),
            replacement,
        });
    } else if source[node.content.clone()] != *text.as_bytes() {
        // Do not erase comments, CDATA, or extension nodes embedded in a
        // text slot. A different serialization requires the fallback writer.
        if source[node.content.clone()].contains(&b'<') {
            return Err(unsupported("opaque markup in formula or cache"));
        }
        patches.push(Patch {
            span: node.content.clone(),
            replacement: text.as_bytes().to_vec(),
        });
    }
    Ok(())
}

pub(crate) fn apply_patches(source: &[u8], mut patches: Vec<Patch>) -> Result<Vec<u8>> {
    patches.sort_by_key(|patch| (patch.span.start, patch.span.end));
    let mut cursor = 0;
    let mut output = Vec::with_capacity(source.len());
    for patch in patches {
        if patch.span.start < cursor
            || patch.span.end < patch.span.start
            || patch.span.end > source.len()
        {
            return Err(invalid("overlapping cache edits"));
        }
        output.extend_from_slice(&source[cursor..patch.span.start]);
        output.extend_from_slice(&patch.replacement);
        cursor = patch.span.end;
    }
    output.extend_from_slice(&source[cursor..]);
    Ok(output)
}

//! A chart's data-label ranges (`c15:datalabelsRange`, Office 2013's
//! "Value From Cells") unlinked when its data moves to a workbook of its
//! own (OF-510, FIX 3701): the range reads cells of the workbook the chart
//! no longer reads.

use super::held::{self, C, children};
use crate::edit::xml::{self, A};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::pptx_comments::guid;
use std::collections::BTreeMap;

/// The chart extensions of Office 2013: data-label ranges among them.
const C15: &str = "http://schemas.microsoft.com/office/drawing/2012/chart";

/// The separator Office puts between a label's parts when it names none.
const SEPARATOR: &str = ", ";

/// The parts a label shows after its cell-range text, in Office's order:
/// the flag that shows each, its field's type and its placeholder text. A
/// scatter or bubble series shows its x and y values as category and value.
fn label_parts(xy: bool) -> [(&'static str, &'static str, &'static str); 5] {
    [
        ("showSerName", "SERIESNAME", "[SERIES NAME]"),
        if xy {
            ("showCatName", "XVALUE", "[X VALUE]")
        } else {
            ("showCatName", "CATEGORYNAME", "[CATEGORY NAME]")
        },
        if xy {
            ("showVal", "YVALUE", "[Y VALUE]")
        } else {
            ("showVal", "VALUE", "[VALUE]")
        },
        ("showPercent", "PERCENTAGE", "[PERCENTAGE]"),
        ("showBubbleSize", "BUBBLESIZE", "[BUBBLE SIZE]"),
    ]
}

/// A chart boolean's value: `val` is true when absent.
fn on(node: &Node) -> bool {
    !matches!(node.attr("val").map(str::trim), Some("0" | "false"))
}

/// Whether a label (or a series' labels) shows the range, as its own
/// extension list says (`extLst/ext/c15:showDataLabelsRange`).
fn range_flag(tree: &XmlTree, owner: usize) -> Option<bool> {
    held::within(tree, owner)
        .find(|&at| {
            tree.nodes[at].is(C15, "showDataLabelsRange")
                && tree.nodes[at]
                    .parent
                    .and_then(|ext| tree.nodes[ext].parent)
                    .and_then(|list| tree.nodes[list].parent)
                    == Some(owner)
        })
        .map(|at| on(&tree.nodes[at]))
}

/// Unlink each series' data-label range (`c15:datalabelsRange`), whose
/// cells live in the workbook the chart no longer reads: where a label
/// shows the range, its point's cached range text becomes the label's own
/// text, followed by the value, category, series, percentage and bubble-size
/// fields the label shows, joined by its separator (a point's own label
/// overriding its series' flags), so the label reads as it did. A label
/// that already carries text keeps it, a cell-range field in it taking the
/// cached text as a run. The range goes, and no label shows a range any
/// more. The count of labels written.
pub(super) fn unlink_ranges(bytes: &[u8], tree: &XmlTree, edits: &mut Vec<xml::Splice>) -> u32 {
    const FLAGS: &[&str] = &[
        "showLegendKey",
        "showVal",
        "showCatName",
        "showSerName",
        "showPercent",
        "showBubbleSize",
        "separator",
    ];
    let piece = |at: usize| &bytes[tree.nodes[at].span.clone()];
    let mut written = 0u32;
    for ser in (0..tree.nodes.len()).filter(|&at| tree.nodes[at].is(C, "ser")) {
        let Some(range) =
            held::within(tree, ser).find(|&at| tree.nodes[at].is(C15, "datalabelsRange"))
        else {
            continue;
        };
        let cached: BTreeMap<u64, String> = held::within(tree, range)
            .filter(|&at| tree.nodes[at].is(C, "pt"))
            .filter_map(|pt| {
                let idx = tree.nodes[pt].attr("idx")?.trim().parse().ok()?;
                let value = xml::child(tree, pt, C, "v")?;
                Some((idx, tree.nodes[value].text.clone()))
            })
            .collect();
        // The range element goes, with its extension when it held only it.
        let gone = tree.nodes[range]
            .parent
            .filter(|&ext| tree.nodes[ext].is(C, "ext") && tree.nodes[ext].children.len() == 1)
            .unwrap_or(range);
        edits.push((tree.nodes[gone].span.clone(), Vec::new()));
        for flag in
            held::within(tree, ser).filter(|&at| tree.nodes[at].is(C15, "showDataLabelsRange"))
        {
            edits.push(xml::set_attribute(bytes, &tree.nodes[flag], "val", "0"));
        }
        let Some(labels) = xml::child(tree, ser, C, "dLbls") else {
            continue;
        };
        // Shown when the series' labels name the range (dLbls/extLst/ext).
        let shown = range_flag(tree, labels).unwrap_or(false);
        let xy = tree.nodes[ser].parent.is_some_and(|kind| {
            ["scatterChart", "bubbleChart"]
                .iter()
                .any(|name| tree.nodes[kind].is(C, name))
        });
        // A point's own label overrides its series' flag or separator.
        let setting = |label: Option<usize>, name: &str| {
            label
                .and_then(|label| xml::child(tree, label, C, name))
                .or_else(|| xml::child(tree, labels, C, name))
        };
        // The label's text: the cached range text, then each part it shows.
        let compose = |label: Option<usize>, idx: u64, text: &str| {
            let separator =
                setting(label, "separator").map_or(SEPARATOR, |at| tree.nodes[at].text.as_str());
            let mut runs = run(text);
            for (flag, kind, shown_as) in label_parts(xy) {
                if !setting(label, flag).is_some_and(|at| on(&tree.nodes[at])) {
                    continue;
                }
                for (n, part) in separator.split('\n').enumerate() {
                    if n > 0 {
                        runs.push_str("<a:br/>");
                    }
                    if !part.is_empty() {
                        runs.push_str(&run(part));
                    }
                }
                let seed = blake3::hash(format!("{ser}:{idx}:{kind}").as_bytes());
                let mut id = [0u8; 16];
                id.copy_from_slice(&seed.as_bytes()[..16]);
                runs.push_str(&format!(
                    r#"<a:fld id="{}" type="{kind}"><a:t>{shown_as}</a:t></a:fld>"#,
                    guid(id)
                ));
            }
            runs
        };
        let c = xml::prefix(&tree.nodes[labels]);
        let q = |name: &str| xml::qualify(c, name);
        let flags: Vec<u8> = tree.nodes[labels]
            .children
            .iter()
            .copied()
            .filter(|&at| {
                tree.nodes[at].namespace == C && FLAGS.contains(&tree.nodes[at].name.as_str())
            })
            .flat_map(|at| piece(at).to_vec())
            .collect();
        let held_labels: BTreeMap<u64, usize> = children(tree, labels, C, "dLbl")
            .filter_map(|label| {
                let idx = xml::child(tree, label, C, "idx")?;
                Some((tree.nodes[idx].attr("val")?.trim().parse().ok()?, label))
            })
            .collect();
        let mut fresh = Vec::new();
        for (idx, text) in &cached {
            let label = held_labels.get(idx).copied();
            let rich = |label: Option<usize>| {
                format!(
                    r#"<{tx}><{rich}><a:bodyPr xmlns:a="{A}"/><a:p xmlns:a="{A}">{}</a:p></{rich}></{tx}>"#,
                    compose(label, *idx, text),
                    tx = q("tx"),
                    rich = q("rich"),
                )
            };
            match label {
                Some(label) if xml::child(tree, label, C, "tx").is_some() => {
                    // A cell-range field keeps the point's cached text.
                    let fields: Vec<usize> = held::within(tree, label)
                        .filter(|&at| {
                            tree.nodes[at].is(A, "fld")
                                && tree.nodes[at].attr("type") == Some("CELLRANGE")
                        })
                        .collect();
                    for field in &fields {
                        let a = xml::prefix(&tree.nodes[*field]);
                        let mut run = format!("<{}>", xml::qualify(a, "r")).into_bytes();
                        if let Some(r_pr) = xml::child(tree, *field, A, "rPr") {
                            run.extend_from_slice(piece(r_pr));
                        }
                        run.extend(
                            format!(
                                "<{t}>{}</{t}></{r}>",
                                escape_text(text),
                                t = xml::qualify(a, "t"),
                                r = xml::qualify(a, "r"),
                            )
                            .into_bytes(),
                        );
                        edits.push((tree.nodes[*field].span.clone(), run));
                    }
                    if !fields.is_empty() {
                        written += 1;
                    }
                }
                Some(label) if xml::child(tree, label, C, "delete").is_some() => {}
                // The point's own label may show or hide the range.
                _ if !label
                    .and_then(|label| range_flag(tree, label))
                    .unwrap_or(shown) => {}
                Some(label) => {
                    // CT_DLbl: idx, layout?, tx?, ...
                    let after = xml::child(tree, label, C, "layout")
                        .or_else(|| xml::child(tree, label, C, "idx"));
                    let at = after.map_or(tree.nodes[label].open_end, |at| tree.nodes[at].span.end);
                    edits.push((at..at, rich(Some(label)).into_bytes()));
                    written += 1;
                }
                None => {
                    fresh.extend(
                        format!(
                            r#"<{}><{} val="{idx}"/>{}"#,
                            q("dLbl"),
                            q("idx"),
                            rich(None)
                        )
                        .into_bytes(),
                    );
                    fresh.extend_from_slice(&flags);
                    fresh.extend(format!("</{}>", q("dLbl")).into_bytes());
                    written += 1;
                }
            }
        }
        if !fresh.is_empty() {
            // Point labels come first in dLbls, after any it holds.
            edits.push(match children(tree, labels, C, "dLbl").last() {
                Some(last) => {
                    let at = tree.nodes[last].span.end;
                    (at..at, fresh)
                }
                None => {
                    xml::insert_first(bytes, &tree.nodes[labels], &String::from_utf8_lossy(&fresh))
                }
            });
        }
    }
    written
}

/// A plain text run.
fn run(text: &str) -> String {
    format!("<a:r><a:t>{}</a:t></a:r>", escape_text(text))
}

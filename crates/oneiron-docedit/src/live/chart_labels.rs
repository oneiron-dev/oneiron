//! A chart's data-label ranges (`c15:datalabelsRange`, Office 2013's
//! "Value From Cells") unlinked when its data moves to a workbook of its
//! own (OF-510, FIX 3701): the range reads cells of the workbook the chart
//! no longer reads.

use super::held::{self, C, children};
use crate::edit::xml::{self, A};
use crate::ooxml::{XmlTree, escape_text};
use std::collections::BTreeMap;

/// The chart extensions of Office 2013: data-label ranges among them.
const C15: &str = "http://schemas.microsoft.com/office/drawing/2012/chart";

/// Unlink each series' data-label range (`c15:datalabelsRange`), whose
/// cells live in the workbook the chart no longer reads: where the labels
/// show the range, each point's cached range text becomes its own label's
/// text (a label that already carries text keeps it, a cell-range field in
/// it taking the cached text as a run), the range goes, and no label shows
/// a range any more. The count of labels written.
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
        let shown = held::within(tree, labels).any(|at| {
            let node = &tree.nodes[at];
            node.is(C15, "showDataLabelsRange")
                && matches!(node.attr("val"), Some("1" | "true"))
                && node
                    .parent
                    .and_then(|ext| tree.nodes[ext].parent)
                    .and_then(|list| tree.nodes[list].parent)
                    == Some(labels)
        });
        if !shown {
            continue;
        }
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
            let rich = format!(
                r#"<{tx}><{rich}><a:bodyPr xmlns:a="{A}"/><a:p xmlns:a="{A}"><a:r><a:t>{}</a:t></a:r></a:p></{rich}></{tx}>"#,
                escape_text(text),
                tx = q("tx"),
                rich = q("rich"),
            );
            match held_labels.get(idx) {
                Some(&label) if xml::child(tree, label, C, "tx").is_some() => {
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
                Some(&label) if xml::child(tree, label, C, "delete").is_some() => {}
                Some(&label) => {
                    // CT_DLbl: idx, layout?, tx?, ...
                    let after = xml::child(tree, label, C, "layout")
                        .or_else(|| xml::child(tree, label, C, "idx"));
                    let at = after.map_or(tree.nodes[label].open_end, |at| tree.nodes[at].span.end);
                    edits.push((at..at, rich.into_bytes()));
                    written += 1;
                }
                None => {
                    fresh.extend(
                        format!(r#"<{}><{} val="{idx}"/>{rich}"#, q("dLbl"), q("idx")).into_bytes(),
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

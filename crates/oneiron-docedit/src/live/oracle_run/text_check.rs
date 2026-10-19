//! Step 3's text comparison: a model text body against its re-import, by
//! paragraph text and level and by the declared character properties over
//! aligned character spans. Run partitions match one for one, except where
//! the writer split a run for a reason the text shows: new text beside a
//! field (a field's text is computed, so the writer never makes one the host
//! of new text, and the new text lands in a run of its own), allowed only at
//! the edge of a field the baseline held on the same shape, which this
//! asserts is still there; and a line break (U+000B) in new text, written as
//! an `a:br` between copies of its run.

use super::record::{Res, text};
use super::variants::{A, part_text, xml_tree};
use crate::deck::{DeckView, soft_breaks};
use crate::edit::BREAK;
use crate::live::{LiveDeck, NodeId, Paragraph, Run, TextBody};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::cell::OnceCell;
use std::collections::BTreeMap;

/// A text field (`a:fld`) as its slide holds it.
#[derive(Debug, PartialEq, Eq)]
struct Field {
    id: Option<String>,
    kind: Option<String>,
    text: String,
}

/// Per text shape (slide part, native id), per paragraph, per run in the
/// live reader's order (a soft break is a run): the field the run is, when
/// it is one.
type FieldMap = BTreeMap<(String, u32), Vec<Vec<Option<Field>>>>;

/// The fields of the baseline an export was projected over and of the
/// export, read only when a run split needs them.
pub(super) struct Fields<'a> {
    /// The model as projected, still bound to `base`.
    edited: &'a LiveDeck,
    base: &'a Package,
    output: &'a Package,
    maps: OnceCell<Option<(FieldMap, FieldMap)>>,
}

impl<'a> Fields<'a> {
    pub(super) fn new(edited: &'a LiveDeck, base: &'a Package, output: &'a Package) -> Self {
        Self {
            edited,
            base,
            output,
            maps: OnceCell::new(),
        }
    }

    /// Whether run `run` of paragraph `paragraph` of the shape the output
    /// binds at (`part`, `native`) is a field, and one the baseline held on
    /// the shape `node` was bound to there: the same id, type and text.
    pub(super) fn kept(
        &self,
        node: NodeId,
        (part, native): (&str, u32),
        paragraph: usize,
        run: usize,
    ) -> bool {
        let Some((base, output)) = self
            .maps
            .get_or_init(|| Some((field_map(self.base).ok()?, field_map(self.output).ok()?)))
            .as_ref()
        else {
            return false;
        };
        let Some(Some(field)) = output
            .get(&(part.to_owned(), native))
            .and_then(|paragraphs| paragraphs.get(paragraph))
            .and_then(|runs| runs.get(run))
        else {
            return false;
        };
        let Some(binding) = self
            .edited
            .nodes
            .get(&node)
            .and_then(|found| found.binding.as_ref())
        else {
            return false;
        };
        binding.native_id.is_some_and(|held| {
            base.get(&(binding.slide_part.clone(), held))
                .is_some_and(|paragraphs| {
                    paragraphs
                        .iter()
                        .flatten()
                        .flatten()
                        .any(|was| was == field)
                })
        })
    }
}

/// Every text shape's fields, through the reader the live import uses.
fn field_map(package: &Package) -> Res<FieldMap> {
    let view = DeckView::read(package).map_err(text)?;
    let mut out = FieldMap::new();
    for slide in &view.slides {
        let xml = part_text(package, &slide.part)?;
        let tree = xml_tree(package, &xml)?;
        for shape in &slide.shapes {
            let (Some(native), Some(body)) = (shape.id, &shape.text) else {
                continue;
            };
            // In the live reader's order: a soft break is a run of its own.
            let paragraphs = body
                .paragraphs
                .iter()
                .map(|paragraph| {
                    let mut breaks = soft_breaks(&tree, paragraph.node.index)
                        .into_iter()
                        .peekable();
                    let mut runs = Vec::with_capacity(paragraph.runs.len());
                    for (at, run) in paragraph.runs.iter().enumerate() {
                        while breaks.next_if_eq(&at).is_some() {
                            runs.push(None);
                        }
                        runs.push(field(&tree, run.node.index));
                    }
                    runs.extend(breaks.map(|_| None));
                    runs
                })
                .collect();
            out.insert((slide.part.clone(), native), paragraphs);
        }
    }
    Ok(out)
}

fn field(tree: &XmlTree, at: usize) -> Option<Field> {
    let node = tree.nodes.get(at)?;
    if !node.is(A, "fld") {
        return None;
    }
    let text = tree
        .child(at, A, "t")
        .ok()
        .flatten()
        .map_or_else(String::new, |(_, t)| t.text.clone());
    Some(Field {
        id: node.attr("id").map(str::to_owned),
        kind: node.attr("type").map(str::to_owned),
        text,
    })
}

/// Text compares by paragraph text, level and runs; paragraph identities
/// are the model's own and a standalone re-import mints new ones. A run
/// property the model leaves unset may read back with any value. `kept`
/// says whether a re-read run (paragraph, run) is a field the baseline held.
pub(super) fn same_text(
    a: Option<&TextBody>,
    b: Option<&TextBody>,
    kept: &dyn Fn(usize, usize) -> bool,
) -> Res<()> {
    let (Some(a), Some(b)) = (a, b) else {
        return if a.is_none_or(|body| body.paragraphs.is_empty()) {
            Ok(())
        } else {
            Err("the text body is gone".to_owned())
        };
    };
    if a.paragraphs.len() != b.paragraphs.len() {
        let runs = |body: &TextBody| -> usize {
            body.paragraphs
                .iter()
                .map(|paragraph| paragraph.runs.len())
                .sum()
        };
        return Err(format!(
            "text {:?} ({} paragraphs, {} runs) reads back as {:?} ({} paragraphs, {} runs)",
            a.plain(),
            a.paragraphs.len(),
            runs(a),
            b.plain(),
            b.paragraphs.len(),
            runs(b)
        ));
    }
    for (at, (pa, pb)) in a.paragraphs.iter().zip(&b.paragraphs).enumerate() {
        let shown = || {
            format!(
                "paragraph {at} of {} {:?} (level {}, {} runs) reads back as {:?} (level {}, {} runs)",
                a.paragraphs.len(),
                pa.text(),
                pa.level,
                pa.runs.len(),
                pb.text(),
                pb.level,
                pb.runs.len()
            )
        };
        if pa.level != pb.level || pa.text() != pb.text() {
            return Err(shown());
        }
        same_runs(pa, pb, &|run| kept(at, run)).map_err(|why| format!("{}: {why}", shown()))?;
    }
    Ok(())
}

/// The model's runs over the re-read ones, aligned by character: each model
/// run reads back as one run or, split at a kept field's edge or a line
/// break, as several, and every run under it reads the properties it
/// declares.
fn same_runs(a: &Paragraph, b: &Paragraph, kept: &dyn Fn(usize) -> bool) -> Res<()> {
    let mut next = 0;
    for ra in &a.runs {
        let start = next;
        let mut covered = String::new();
        while next < b.runs.len() && (next == start || covered.len() < ra.text.len()) {
            covered.push_str(&b.runs[next].text);
            next += 1;
        }
        let under = &b.runs[start..next];
        if under.is_empty() || covered != ra.text {
            return Err(format!("run {ra:?} reads back as {under:?}"));
        }
        let edge = |at: usize| kept(at) || soft_break(&b.runs[at]);
        if let Some(cut) = (start + 1..next).find(|&cut| !edge(cut - 1) && !edge(cut)) {
            return Err(format!(
                "run {ra:?} reads back split between {:?} and {:?}, at no field the baseline held or line break",
                b.runs[cut - 1].text,
                b.runs[cut].text
            ));
        }
        // A soft break (U+000B) is no character the writer formats: run
        // properties count no break, so a break's run declares nothing.
        if !soft_break(ra)
            && let Some(rb) = under
                .iter()
                .find(|rb| !soft_break(rb) && !declared_hold(ra, rb))
        {
            return Err(format!("run {ra:?} reads back as {rb:?}"));
        }
    }
    if next < b.runs.len() {
        return Err(format!(
            "runs {:?} read back past the model's",
            &b.runs[next..]
        ));
    }
    Ok(())
}

/// A run of nothing but line breaks: no character the writer formats.
fn soft_break(run: &Run) -> bool {
    !run.text.is_empty() && run.text.chars().all(|c| c == BREAK)
}

/// Every character property the model run declares reads back.
fn declared_hold(ra: &Run, rb: &Run) -> bool {
    (ra.bold.is_none() || ra.bold == rb.bold)
        && (ra.italic.is_none() || ra.italic == rb.italic)
        && (ra.size.is_none() || ra.size == rb.size)
        && (ra.latin.is_none() || ra.latin == rb.latin)
}

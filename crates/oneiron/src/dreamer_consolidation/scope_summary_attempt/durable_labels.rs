//! Summary text in durable names (FIX 10359), as a nightly narrative's is
//! (FIX 7576). A summary call shows each record by a call-local label that
//! means nothing once the call is over, so before a summary lands each
//! label its text or keep writes as a whole word becomes what it stood for:
//! a TURN, NOTE, sitting or entity its id, a claim `[predicate = value]`.
//! Each line keeps its TURNs, its range counted again over the text so
//! written; every other byte stays as the model wrote it.

use std::collections::BTreeMap;

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::nightly_merge::narrative_labels::durable_text;
use super::arc_evidence::ArcView;
use super::arc_output::ArcLines;
use crate::scope_summary::SummaryLineSources;

/// What each label `labels` assigned stands for once its call is over: its
/// id, or a claim `view` shows its predicate and value.
pub(super) fn label_names(
    labels: &CallLabelMap,
    view: Option<&ArcView>,
) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for kind in [
        LabelKind::Turn,
        LabelKind::Note,
        LabelKind::Conversation,
        LabelKind::Source,
        LabelKind::Entity,
        LabelKind::Claim,
    ] {
        for (label, id) in labels.labelled(kind) {
            names.insert(label.to_string(), id.to_hex());
        }
    }
    for entry in view.into_iter().flat_map(|view| &view.claim_entries) {
        names.insert(entry.label.clone(), entry.named.clone());
    }
    names
}

/// `text` and `keep` in durable names. A summary written in lines has
/// `line_sources`, one per line, each line's range counted again; a text
/// whose lines do not match its sources stays as it is, ranges and all.
pub(super) fn durable_summary(
    text: String,
    keep: &str,
    line_sources: Option<Vec<SummaryLineSources>>,
    names: &BTreeMap<String, String>,
) -> (String, String, Option<Vec<SummaryLineSources>>) {
    let keep = durable_text(keep, names);
    let Some(mut lines) = line_sources else {
        return (durable_text(&text, names), keep, None);
    };
    if text.split('\n').count() != lines.len() {
        return (text, keep, Some(lines));
    }
    let mut out = String::with_capacity(text.len());
    let mut scalars = 0_usize;
    for (index, (words, source)) in text.split('\n').zip(lines.iter_mut()).enumerate() {
        if index > 0 {
            out.push('\n');
            scalars += 1;
        }
        let written = durable_text(words, names);
        source.output_start = scalars;
        scalars += written.chars().count();
        source.output_end = scalars;
        out.push_str(&written);
    }
    (out, keep, Some(lines))
}

/// An Arc's lines in durable names, through `view`'s labels.
pub(super) fn durable_arc(lines: ArcLines, view: &ArcView) -> ArcLines {
    let names = label_names(&view.labels, Some(view));
    let (text, keep, line_sources) =
        durable_summary(lines.text, &lines.keep, Some(lines.line_sources), &names);
    ArcLines {
        text,
        keep,
        line_sources: line_sources.unwrap_or_default(),
    }
}

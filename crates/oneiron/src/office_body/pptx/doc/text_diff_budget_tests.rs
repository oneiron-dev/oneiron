//! A large deck paragraph synced to unrelated runs is refused within the whole-text diff
//! budget.

use super::{LoroDoc, NodeId, PARAS, Paragraph, Run, TEXT, TEXTS, configure, sync_paragraph};
use std::time::{Duration, Instant};

/// Before the diff budget this ran for many minutes. Past the budget the
/// paragraph keeps the text it held.
#[test]
fn syncing_a_large_paragraph_to_unrelated_runs_is_refused_within_the_budget() {
    let old = format!("{} tail \u{2713}", "x".repeat(1 << 20));
    let doc = LoroDoc::new();
    configure(&doc);
    let entry = doc.get_map(TEXTS).ensure_mergeable_map("1").unwrap();
    let paras = entry.ensure_mergeable_map(PARAS).unwrap();
    let para = paras.ensure_mergeable_map("2").unwrap();
    let mut paragraph = Paragraph {
        id: NodeId(2),
        level: 0,
        runs: vec![Run {
            text: old.clone(),
            bold: None,
            italic: None,
            size: None,
            latin: None,
        }],
    };
    sync_paragraph(&para, &paragraph).unwrap();
    doc.commit();
    let new = "\u{e9}dited tail \u{2713}";
    paragraph.runs[0].text = new.to_owned();
    let started = Instant::now();
    let result = sync_paragraph(&para, &paragraph);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "syncing the paragraph took {elapsed:?}"
    );
    assert!(result.is_err(), "the sync is refused past the budget");
    assert_eq!(para.ensure_mergeable_text(TEXT).unwrap().to_string(), old);
}

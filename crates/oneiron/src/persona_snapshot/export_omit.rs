//! Both persona copy renders for a copy made without its vault refs
//! (FIX 1199, `CopyRefs::Omit`): the same rows, text and compile stamp as
//! the renders in `export.rs`, without the subject, audience and provenance
//! refs, and with copy-local labels in place of row ids and take authors.

use std::collections::BTreeMap;

use super::compile::markdown_safe_line;
use super::types::{
    MEMORY_PACK_LITE_SCHEMA_VERSION, PersonaSnapshotCompile, PersonaSnapshotRow,
    PersonaSnapshotRowKind,
};
use crate::share_travel::CopyRefs;

/// The vault ref slots a copy made without its refs leaves out, as its
/// export record names them: `subject_ref`, `audience_ref` and
/// `provenance_refs` are dropped; `row_id` and `attribution` carry
/// copy-local labels instead.
const OMITTED_REF_SLOTS: [&str; 5] = [
    "subject_ref",
    "audience_ref",
    "row_id",
    "provenance_refs",
    "attribution",
];

/// The ref slots the export record names for `refs`; none for a copy that
/// carries its refs.
pub(super) fn omitted_ref_slots(refs: CopyRefs) -> Vec<String> {
    match refs {
        CopyRefs::Preserve => Vec::new(),
        CopyRefs::Omit => OMITTED_REF_SLOTS.map(str::to_owned).into(),
    }
}

/// Copy-local labels for take authors, `agent-1`, `agent-2`, ... in order of
/// first appearance among the included rows, so both renders name each
/// author alike.
fn author_labels<'a>(included: &[&'a PersonaSnapshotRow]) -> BTreeMap<&'a str, String> {
    let mut labels = BTreeMap::new();
    for row in included.iter().copied() {
        if let Some(attribution) = row.attribution.as_deref() {
            let next = labels.len() + 1;
            labels
                .entry(attribution)
                .or_insert_with(|| format!("agent-{next}"));
        }
    }
    labels
}

/// The MemoryPack-lite JSON without vault refs: rows are labelled `row-1`,
/// `row-2`, ... in render order; relationship rows stay coarse as today.
pub(super) fn render_memory_pack_lite_omit(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let authors = author_labels(included);
    let rows: Vec<serde_json::Value> = included
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let mut entry = serde_json::json!({
                "row_id": format!("row-{}", index + 1),
                "kind": row.kind.as_str(),
                "text": row.text,
            });
            if row.kind == PersonaSnapshotRowKind::Relationship {
                return entry;
            }
            if let Some(salience) = row.salience {
                entry["salience"] = serde_json::json!(salience);
            }
            if let Some(author) = row
                .attribution
                .as_deref()
                .and_then(|attribution| authors.get(attribution))
            {
                entry["attribution"] = serde_json::json!(author);
            }
            entry
        })
        .collect();

    let pack = serde_json::json!({
        "schema": MEMORY_PACK_LITE_SCHEMA_VERSION,
        "kind": "persona_snapshot",
        "identity_line": identity_included
            .then(|| compile.identity_line.clone()),
        "takes_included": compile.takes_included,
        "compiled_at_secs": compile.compiled_at_secs,
        "stale_after_secs": compile.stale_after_secs,
        "persona_compile_stamp": compile.stamp.identity(),
        "rows": rows,
    });
    pack.to_string()
}

/// The markdown card without vault refs: no subject or audience line, no
/// provenance spans, and take authors by their copy-local labels.
pub(super) fn render_markdown_card_omit(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let authors = author_labels(included);
    let mut out = String::new();
    if identity_included {
        out.push_str(&format!(
            "# {}\n",
            markdown_safe_line(&compile.identity_line)
        ));
    } else {
        out.push_str("# Persona snapshot\n");
    }
    out.push('\n');
    out.push_str(&format!(
        "- compiled_at_secs: {}\n",
        compile.compiled_at_secs
    ));
    out.push_str(&format!(
        "- stale_after_secs: {}\n",
        compile.stale_after_secs
    ));
    out.push_str(&format!(
        "- persona_compile_stamp: {}\n",
        compile.stamp.identity()
    ));

    let mut push_section = |title: &str, kind: PersonaSnapshotRowKind| {
        let rows: Vec<&&PersonaSnapshotRow> =
            included.iter().filter(|row| row.kind == kind).collect();
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("\n## {title}\n\n"));
        for row in rows {
            let text = markdown_safe_line(&row.text);
            match row
                .attribution
                .as_deref()
                .and_then(|attribution| authors.get(attribution))
            {
                Some(author) => out.push_str(&format!("- {author} (take): {text}\n")),
                None => out.push_str(&format!("- {text}\n")),
            }
        }
    };

    push_section("Key relationships", PersonaSnapshotRowKind::Relationship);
    push_section("Claims", PersonaSnapshotRowKind::SubjectClaim);
    push_section(
        "Third-party details",
        PersonaSnapshotRowKind::ThirdPartyClaim,
    );
    push_section("Agent takes", PersonaSnapshotRowKind::AgentTake);
    out
}

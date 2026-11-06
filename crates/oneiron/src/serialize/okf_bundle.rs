//! Core half of `serialize::okf_bundle`: its store-layer items live in `oneiron_store::serialize::okf_bundle` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::okf_bundle::*;

use crate::batch::export::{ArchiveRecordKind, RecordSpool};
use crate::error::{Error, Result};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Seek, Write};

/// The bundle as one ZIP written to `sink`: `index.md`, one `index.md` per
/// kind, and one concept per entity. It is cut from the document's spooled
/// rows (FIX 2766): each concept's row is read back when it is rendered, so
/// only titles, links and citations are held.
pub(super) fn write_okf_bundle<W: Write + Seek>(
    sink: W,
    groups: &mut BTreeMap<String, RecordSpool>,
    exported_at: u64,
) -> Result<W> {
    let mut concepts = Vec::new();
    let mut links: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut citations: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (path, spool) in groups.iter_mut() {
        let kind = spool.kind;
        if !matches!(
            kind,
            ArchiveRecordKind::Entity
                | ArchiveRecordKind::Claim
                | ArchiveRecordKind::Skill
                | ArchiveRecordKind::Edge
                | ArchiveRecordKind::DerivationEnvelope
        ) {
            continue;
        }
        let mut rows = spool.rows()?;
        while let Some((at, row)) = rows.next_row()? {
            match kind {
                ArchiveRecordKind::Edge => {
                    let (Some(source), Some(target), Some(edge_kind)) = (
                        row.get("source").and_then(Value::as_str),
                        row.get("target").and_then(Value::as_str),
                        row.get("kind").and_then(Value::as_u64),
                    ) else {
                        continue;
                    };
                    let name = u8::try_from(edge_kind)
                        .ok()
                        .and_then(crate::edge::EdgeKind::try_from_u8)
                        .map_or_else(
                            || format!("edge {edge_kind}"),
                            |kind| kind.name().replace('_', " "),
                        );
                    links
                        .entry(source.to_owned())
                        .or_default()
                        .push((name, target.to_owned()));
                }
                ArchiveRecordKind::DerivationEnvelope => {
                    if let (Some(id), Some(evidence)) =
                        (row.get("id").and_then(Value::as_str), row.get("evidence"))
                    {
                        match plain(evidence) {
                            Value::Array(items) => {
                                citations.entry(id.to_owned()).or_default().extend(items);
                            }
                            Value::Null => {}
                            item => citations.entry(id.to_owned()).or_default().push(item),
                        }
                    }
                }
                _ => {
                    let entity = if kind == ArchiveRecordKind::Skill {
                        row.get("entity").ok_or_else(encode_failed)?
                    } else {
                        &row
                    };
                    // The body is read again when the concept is rendered.
                    concepts.push((concept(entity)?, path.clone(), at));
                }
            }
        }
    }
    concepts.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let titles: BTreeMap<&str, (&str, &str)> = concepts
        .iter()
        .map(|(c, _, _)| (c.id.as_str(), (c.title.as_str(), c.path.as_str())))
        .collect();

    let stamp = rfc3339(exported_at);
    let mut zip = zip::ZipWriter::new(sink);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let member = |zip: &mut zip::ZipWriter<W>, name: &str, text: &str| -> Result<()> {
        zip.start_file(name, options).map_err(|_| encode_failed())?;
        zip.write_all(text.as_bytes()).map_err(|_| encode_failed())
    };

    let mut kinds: BTreeMap<&str, Vec<&Concept>> = BTreeMap::new();
    for (concept, group, at) in &concepts {
        kinds
            .entry(concept.kind.as_str())
            .or_default()
            .push(concept);
        let spool = groups.get_mut(group).ok_or_else(encode_failed)?;
        let row: Value =
            serde_json::from_slice(&spool.line_at(*at)?).map_err(|_| encode_failed())?;
        let row = if spool.kind == ArchiveRecordKind::Skill {
            row.get("entity").cloned().unwrap_or(Value::Null)
        } else {
            row
        };
        let body = row.get("body").map(plain_body).unwrap_or(Value::Null);
        let text = render_concept(
            concept,
            &body,
            links
                .get(concept.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            citations
                .get(concept.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            &titles,
        );
        member(&mut zip, &concept.path, &text)?;
    }
    for (kind, list) in &kinds {
        let mut text = frontmatter(
            "Index",
            &format!("{} ({})", kind_title(kind), list.len()),
            &format!("Every {kind} record in this lossy OKF view of an Oneiron vault."),
            &stamp,
            &[],
        );
        let _ = writeln!(text, "# {}\n", kind_title(kind));
        for concept in list {
            let _ = writeln!(
                text,
                "- [{}](/{}) {}",
                link_text(&concept.title),
                concept.path,
                concept.description
            );
        }
        member(&mut zip, &format!("{kind}/index.md"), &text)?;
    }
    let mut root = frontmatter(
        "Index",
        "Oneiron vault (OKF export, not a full copy)",
        "A lossy Open Knowledge Format view of an Oneiron vault, for other tools.",
        &stamp,
        &[("okf_version", OKF_SPEC_VERSION)],
    );
    let _ = writeln!(
        root,
        "# Not a full copy\n\n{LOSS_DECLARATION}\n\n# Contents\n"
    );
    for (kind, list) in &kinds {
        let _ = writeln!(
            root,
            "- [{}](/{kind}/index.md) {} records",
            kind_title(kind),
            list.len()
        );
    }
    member(&mut zip, "index.md", &root)?;
    zip.finish().map_err(|_| encode_failed())
}

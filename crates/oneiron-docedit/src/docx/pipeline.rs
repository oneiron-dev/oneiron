//! Native docx round trip: inspect, tracked-change write, link, prepare.
//!
//! The pure pipeline behind the Word oracle example. It edits a copy of the
//! input bytes through the retained OPC substrate — untouched parts re-emit
//! byte-for-byte — then runs the docx linker plus the passthrough gate over
//! the output before committing to a manifest and a prepared handoff. A
//! rejected plan carries no bytes forward. No storage, no clock, no I/O:
//! the caller supplies the revision mark (author + date) so output is
//! deterministic for a given input, plan, and mark.

use super::comments::{apply_comment, comments_override_row, comments_rel_row, next_comment_id};
use super::inspect::{DocxStructure, inspect_docx};
use super::linker::{DocxLinkReport, check_docx_links};
use super::ops::{DocxAnchorEffect, DocxOp};
use super::stamp::DocxEngineStamp;
use super::writer::{RevisionMark, apply_text_op, next_revision_id};
use crate::opc::{self, OpcPackage};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Serialization version for [`DocxManifest`].
pub const DOCX_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The agent's requested docx edit: narrow ops plus the revision mark.
#[derive(Debug, Clone)]
pub struct DocxPlan {
    pub ops: Vec<DocxOp>,
    pub mark: RevisionMark,
}

impl DocxPlan {
    #[must_use]
    pub fn new(ops: Vec<DocxOp>, mark: RevisionMark) -> Self {
        Self { ops, mark }
    }
}

/// One docx gate check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocxValidationCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The docx corruption-gate report. `ok` is the conjunction of all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocxValidationReport {
    pub ok: bool,
    pub checks: Vec<DocxValidationCheck>,
}

/// The canonical docx edit manifest: the diff plus the re-anchoring input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocxManifest {
    pub schema_version: u32,
    pub engine: DocxEngineStamp,
    pub ops: Vec<DocxOp>,
    pub touched_parts: BTreeSet<String>,
    pub revision_ids: Vec<i64>,
    pub comment_ids: Vec<i64>,
}

impl DocxManifest {
    /// The anchor-remapping effects, in op order, for comment replay.
    #[must_use]
    pub fn anchor_effects(&self) -> Vec<DocxAnchorEffect> {
        self.ops.iter().filter_map(DocxOp::anchor_effect).collect()
    }

    /// One diff line per op; the viewer never re-parses two binaries.
    #[must_use]
    pub fn render_diff(&self) -> Vec<String> {
        self.ops.iter().map(DocxOp::render).collect()
    }

    /// Field-name-tagged MessagePack encoding for durable storage.
    pub fn to_msgpack(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidManifest("docx manifest failed to encode"))
    }

    /// Decodes a manifest from [`DocxManifest::to_msgpack`] bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| Error::InvalidManifest("docx manifest failed to decode"))?;
        if manifest.schema_version != DOCX_MANIFEST_SCHEMA_VERSION {
            return Err(Error::InvalidManifest(
                "docx manifest schema version is unsupported",
            ));
        }
        Ok(manifest)
    }
}

/// Docx uses the same checked commitment as all document formats.
pub type DocxPrepared = crate::PreparedEdit;

/// The retained-output docx proposal: new bytes plus everything settle or the
/// viewer needs, committing nothing.
#[derive(Debug, Clone)]
pub struct DocxProposal {
    pub run_ref: String,
    pub new_bytes: Vec<u8>,
    pub manifest: DocxManifest,
    pub inspection: DocxStructure,
    pub validation: DocxValidationReport,
    pub linker: DocxLinkReport,
    pub base_content_hash: [u8; 32],
    pub prepared: DocxPrepared,
}

/// The pipeline result: a settle-ready proposal, or a rejection whose report
/// says which check failed. A rejection never carries proposal bytes.
#[derive(Debug, Clone)]
pub enum DocxOutcome {
    Proposed(Box<DocxProposal>),
    Rejected {
        inspection: DocxStructure,
        report: DocxValidationReport,
        linker: DocxLinkReport,
    },
}

/// Runs the full native docx round trip against a copy of `input_bytes`.
pub fn run_docx_roundtrip(
    input_bytes: &[u8],
    plan: &DocxPlan,
    run_ref: &str,
) -> Result<DocxOutcome> {
    if run_ref.trim().is_empty() {
        return Err(Error::EditFailed("run_ref must be non-empty"));
    }
    if plan.ops.is_empty() {
        return Err(Error::InvalidManifest("docx plan carries no ops"));
    }
    for op in &plan.ops {
        op.validate()?;
    }
    check_single_touch_per_paragraph(&plan.ops)?;

    let before = opc::read(input_bytes)?;
    super::inspect_docx_settings(&before)?.require_editable()?;
    let inspection = inspect_docx(
        before.part("word/document.xml"),
        before.names().map(str::to_owned),
    )?;
    for op in &plan.ops {
        let ordinal = op.span().paragraph;
        if ordinal == 0 || ordinal > inspection.paragraphs {
            return Err(Error::InvalidManifest(
                "docx span paragraph is past the last paragraph",
            ));
        }
    }

    let source = before
        .part("word/document.xml")
        .ok_or(Error::InvalidPackage("missing Word document"))?;
    if oneiron_stemma::has_paragraph_mark_revision(source)
        .map_err(|_| Error::InvalidPackage("malformed Word document"))?
    {
        return Err(Error::InvalidManifest(
            "resolve pending paragraph-mark revisions before ordinal editing",
        ));
    }
    let applied = apply_plan(&before, plan)?;
    let current = stage_package(input_bytes, &before, applied.document, applied.comments)?;

    let after = match opc::read(&current) {
        Ok(parsed) => parsed,
        Err(_) => {
            let report = DocxValidationReport {
                ok: false,
                checks: vec![DocxValidationCheck {
                    name: "well_formed_opc",
                    passed: false,
                    detail: "docx output is not a readable OPC package".to_owned(),
                }],
            };
            let linker = check_docx_links(&before);
            return Ok(DocxOutcome::Rejected {
                inspection,
                report,
                linker,
            });
        }
    };

    let manifest = DocxManifest {
        schema_version: DOCX_MANIFEST_SCHEMA_VERSION,
        engine: DocxEngineStamp::current(),
        ops: plan.ops.clone(),
        touched_parts: diff_parts(&before, &after),
        revision_ids: applied.revision_ids,
        comment_ids: applied.comment_ids,
    };
    let mut report = validate_docx(&before, &after);
    let linker = check_docx_links(&after);
    report
        .checks
        .extend(linker.checks.iter().map(|check| DocxValidationCheck {
            name: check.name,
            passed: check.passed,
            detail: check.detail.clone(),
        }));
    report.ok = report.checks.iter().all(|check| check.passed);
    if !report.ok || !linker.ok {
        return Ok(DocxOutcome::Rejected {
            inspection,
            report,
            linker,
        });
    }

    let base_content_hash = *blake3::hash(input_bytes).as_bytes();
    let prepared = crate::prepare(crate::PrepareInput {
        base_content_hash,
        base_version: None,
        run_ref,
        output: &current,
        writes: &manifest,
        report: &report,
        engine: &manifest.engine.engine_id(),
    })?;
    Ok(DocxOutcome::Proposed(Box::new(DocxProposal {
        run_ref: run_ref.to_owned(),
        new_bytes: current,
        manifest,
        inspection,
        validation: report,
        linker,
        base_content_hash,
        prepared,
    })))
}

struct AppliedPlan {
    document: Vec<u8>,
    comments: Option<Vec<u8>>,
    revision_ids: Vec<i64>,
    comment_ids: Vec<i64>,
}

fn apply_plan(before: &OpcPackage, plan: &DocxPlan) -> Result<AppliedPlan> {
    let mut document = before
        .part("word/document.xml")
        .ok_or(Error::InvalidPackage("docx is missing word/document.xml"))?
        .to_vec();
    let mut comments = before.part("word/comments.xml").map(<[u8]>::to_vec);
    let mut revision_ids: Vec<i64> = Vec::new();
    let mut comment_ids: Vec<i64> = Vec::new();
    for op in &plan.ops {
        match op {
            DocxOp::AddComment { .. } => {
                let id = next_comment_id(&document, comments.as_deref())?;
                let write = apply_comment(&document, comments.as_deref(), op, &plan.mark, id)?;
                document = write.document_xml;
                comments = Some(write.comments_xml);
                comment_ids.push(id);
            }
            _ => {
                let first = next_revision_id(&document)?;
                let write = apply_text_op(&document, op, &plan.mark, first)?;
                document = write.document_xml;
                revision_ids.extend(write.revision_ids);
            }
        }
    }
    Ok(AppliedPlan {
        document,
        comments,
        revision_ids,
        comment_ids,
    })
}

fn stage_package(
    input_bytes: &[u8],
    before: &OpcPackage,
    document: Vec<u8>,
    comments: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut package = crate::opc::Package::open(input_bytes, crate::opc::Limits::default())?;
    package.replace("word/document.xml", document)?;
    if let Some(comments_xml) = comments {
        if before.contains("word/comments.xml") {
            package.replace("word/comments.xml", comments_xml)?;
        } else {
            bootstrap_comments(&mut package, before, comments_xml)?;
        }
    }
    package.write()
}

/// Structural guard: one op per paragraph per plan. A second op on the same
/// paragraph would resolve its span against pre-edit text, so it is refused
/// here rather than silently misplaced; the caller splits such edits into
/// sequential proposals.
fn check_single_touch_per_paragraph(ops: &[DocxOp]) -> Result<()> {
    if ops.len() > 1
        && ops
            .iter()
            .any(|op| matches!(op, DocxOp::JoinParagraphs { .. }))
    {
        return Err(Error::InvalidManifest(
            "paragraph joins require a standalone proposal",
        ));
    }
    let mut seen = BTreeSet::new();
    for op in ops {
        let ordinal = op.span().paragraph;
        if !seen.insert(ordinal) {
            return Err(Error::InvalidManifest(
                "docx plan touches one paragraph twice; split into sequential proposals",
            ));
        }
    }
    Ok(())
}

fn bootstrap_comments(
    package: &mut crate::opc::Package,
    before: &OpcPackage,
    comments_xml: Vec<u8>,
) -> Result<()> {
    let content_types = before
        .part(opc::CONTENT_TYPES_PART)
        .ok_or(Error::InvalidPackage("docx is missing [Content_Types].xml"))?;
    let types_text = std::str::from_utf8(content_types)
        .map_err(|_| Error::InvalidPackage("[Content_Types].xml is not UTF-8"))?;
    let anchor = types_text.find("</Types>").ok_or(Error::InvalidPackage(
        "[Content_Types].xml has no closing tag",
    ))?;
    let mut updated_types = types_text.to_owned();
    updated_types.insert_str(anchor, comments_override_row());
    package.replace(opc::CONTENT_TYPES_PART, updated_types.into_bytes())?;

    let rels_name = "word/_rels/document.xml.rels";
    let rels = before.part(rels_name).ok_or(Error::InvalidManifest(
        "docx comments bootstrap needs word/_rels/document.xml.rels",
    ))?;
    let rels_text = std::str::from_utf8(rels)
        .map_err(|_| Error::InvalidPackage("document rels are not UTF-8"))?;
    let anchor = rels_text
        .find("</Relationships>")
        .ok_or(Error::InvalidPackage("document rels have no closing tag"))?;
    let rid = next_rid(rels_text)?;
    let mut updated_rels = rels_text.to_owned();
    updated_rels.insert_str(anchor, &comments_rel_row(&rid));
    package.replace(rels_name, updated_rels.into_bytes())?;
    package.insert("word/comments.xml", comments_xml)?;
    Ok(())
}

fn next_rid(rels_xml: &str) -> Result<String> {
    let mut max: u64 = 0;
    let mut rest = rels_xml;
    while let Some(pos) = rest.find("Id=\"rId") {
        let after = &rest[pos + "Id=\"rId".len()..];
        let digits: String = after.chars().take_while(|c| c.is_numeric()).collect();
        if let Ok(id) = digits.parse::<u64>() {
            max = max.max(id);
        }
        rest = after;
    }
    let next = max.checked_add(1).ok_or(Error::InvalidManifest(
        "docx relationship id space exhausted",
    ))?;
    Ok(format!("rId{next}"))
}

fn validate_docx(before: &OpcPackage, after: &OpcPackage) -> DocxValidationReport {
    let mut checks = Vec::new();
    let content_types_present = after.contains(opc::CONTENT_TYPES_PART);
    checks.push(DocxValidationCheck {
        name: "content_types_present",
        passed: content_types_present,
        detail: if content_types_present {
            "output retains [Content_Types].xml".to_owned()
        } else {
            "output is missing [Content_Types].xml".to_owned()
        },
    });
    let spine_present = after.contains("word/document.xml");
    checks.push(DocxValidationCheck {
        name: "spine_present",
        passed: spine_present,
        detail: if spine_present {
            "output retains word/document.xml".to_owned()
        } else {
            "output is missing word/document.xml".to_owned()
        },
    });
    let passthrough = passthrough_violations(before, after);
    let passthrough_ok = passthrough.is_empty();
    checks.push(DocxValidationCheck {
        name: "passthrough_unknown_parts",
        passed: passthrough_ok,
        detail: if passthrough_ok {
            "all unknown parts survived byte-for-byte".to_owned()
        } else {
            format!(
                "unknown parts were altered or dropped: {}",
                passthrough.join(", ")
            )
        },
    });
    let ok = checks.iter().all(|c| c.passed);
    DocxValidationReport { ok, checks }
}

fn passthrough_violations(before: &OpcPackage, after: &OpcPackage) -> Vec<String> {
    let mut violations = Vec::new();
    for part in before.parts() {
        if opc::classify(&part.name) != opc::PartClass::Unknown {
            continue;
        }
        match after.part(&part.name) {
            Some(bytes) if bytes == part.data.as_slice() => {}
            Some(_) => violations.push(format!("{} (altered)", part.name)),
            None => violations.push(format!("{} (dropped)", part.name)),
        }
    }
    for part in after.parts() {
        if opc::classify(&part.name) == opc::PartClass::Unknown && !before.contains(&part.name) {
            violations.push(format!("{} (injected)", part.name));
        }
    }
    violations
}

fn diff_parts(before: &OpcPackage, after: &OpcPackage) -> BTreeSet<String> {
    let mut touched = BTreeSet::new();
    for part in after.parts() {
        match before.part(&part.name) {
            Some(bytes) if bytes == part.data.as_slice() => {}
            _ => {
                touched.insert(part.name.clone());
            }
        }
    }
    for part in before.parts() {
        if !after.contains(&part.name) {
            touched.insert(part.name.clone());
        }
    }
    touched
}

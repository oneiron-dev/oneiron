//! Edit session seam and validation.

use super::inspect::{attr_value, scan_tag_attr};
use super::opc::{self, OpcPackage, PartClass};
use super::{EditOp, EditWarning, OfficeFormat};
use crate::error::Result;
use serde::Serialize;
use std::collections::BTreeSet;

/// The office file passed across the [`EditSession`] seam: the raw bytes plus
/// the pipeline's decomposition of them.
#[derive(Debug, Clone)]
pub struct OfficeDoc {
    pub format: OfficeFormat,
    pub bytes: Vec<u8>,
    package: OpcPackage,
}

impl OfficeDoc {
    pub(super) fn new(format: OfficeFormat, bytes: Vec<u8>, package: OpcPackage) -> Self {
        Self {
            format,
            bytes,
            package,
        }
    }

    /// Read-only view of the decomposed parts, for a session that reasons in
    /// Rust (a session shelling out to Python uses [`OfficeDoc::bytes`]).
    pub fn parts(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.package
            .parts()
            .iter()
            .map(|p| (p.name.as_str(), p.data.as_slice()))
    }
}

/// The agent's requested edit.
#[derive(Debug, Clone)]
pub struct EditPlan {
    pub ops: Vec<EditOp>,
    /// Force recalc on/off; `None` auto-detects from the applied ops.
    pub request_recalc: Option<bool>,
}

impl EditPlan {
    #[must_use]
    pub fn new(ops: Vec<EditOp>) -> Self {
        Self {
            ops,
            request_recalc: None,
        }
    }

    pub(super) fn needs_recalc(&self, applied: &[EditOp]) -> bool {
        self.request_recalc
            .unwrap_or_else(|| applied.iter().any(EditOp::may_affect_values))
    }
}

/// What a session applied: the output bytes, the ops it actually performed
/// (drives the no-phantom/no-missing manifest guarantee), and any warnings.
#[derive(Debug, Clone)]
pub struct AppliedEdit {
    pub bytes: Vec<u8>,
    pub applied_ops: Vec<EditOp>,
    pub warnings: Vec<EditWarning>,
}

/// The seam behind which the external session binaries live. In production:
/// openpyxl for [`EditSession::apply_edits`] and LibreOffice headless for
/// [`EditSession::recalc`], both inside a foreign-tier microVM. In CI: a
/// fixture implementation, so the full gate passes without either binary.
pub trait EditSession {
    /// Stage 2: apply the plan to a copy and return the edited bytes.
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit>;

    /// Stage 3: refresh cached formula values in the edited bytes. Must
    /// preserve unknown parts; the corruption gate re-checks regardless.
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>>;

    /// Whether this session image can recalc (LibreOffice present).
    fn supports_recalc(&self) -> bool {
        true
    }
}

/// One corruption-gate check result. Serializes into receipts/viewer payloads;
/// the `&'static str` check name means it does not round-trip back through
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The corruption-gate report. `ok` is the conjunction of all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
}

impl ValidationReport {
    pub(super) fn single_failure(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            checks: vec![ValidationCheck {
                name,
                passed: false,
                detail: detail.into(),
            }],
        }
    }
}

/// Runs the corruption + passthrough gate over the parsed input/output
/// packages. Never trusts the session's self-report: it re-derives the part
/// diff from the actual output bytes.
pub(super) fn validate(
    before: &OpcPackage,
    after: &OpcPackage,
    format: OfficeFormat,
) -> ValidationReport {
    let mut checks = Vec::new();

    let content_types_present = after.contains(opc::CONTENT_TYPES_PART);
    checks.push(ValidationCheck {
        name: "content_types_present",
        passed: content_types_present,
        detail: if content_types_present {
            "output retains [Content_Types].xml".to_owned()
        } else {
            "output is missing [Content_Types].xml".to_owned()
        },
    });

    let spine_present = after.contains(format.spine_part());
    checks.push(ValidationCheck {
        name: "spine_present",
        passed: spine_present,
        detail: if spine_present {
            format!("output retains the {} spine part", format.spine_part())
        } else {
            format!("output is missing the {} spine part", format.spine_part())
        },
    });

    let referential = referential_integrity_violations(after);
    let referential_ok = referential.is_empty();
    checks.push(ValidationCheck {
        name: "referential_integrity",
        passed: referential_ok,
        detail: if referential_ok {
            "every relationship target and content-type override resolves to a part".to_owned()
        } else {
            format!("dangling references: {}", referential.join(", "))
        },
    });

    let passthrough = passthrough_violations(before, after);
    let passthrough_ok = passthrough.is_empty();
    checks.push(ValidationCheck {
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
    ValidationReport { ok, checks }
}

/// Names of unknown parts that were dropped, altered, or newly injected — any
/// of which violates the passthrough law.
fn passthrough_violations(before: &OpcPackage, after: &OpcPackage) -> Vec<String> {
    let mut violations = Vec::new();
    for part in before.parts() {
        if opc::classify(&part.name) != PartClass::Unknown {
            continue;
        }
        match after.part(&part.name) {
            Some(bytes) if bytes == part.data.as_slice() => {}
            Some(_) => violations.push(format!("{} (altered)", part.name)),
            None => violations.push(format!("{} (dropped)", part.name)),
        }
    }
    for part in after.parts() {
        if opc::classify(&part.name) == PartClass::Unknown && !before.contains(&part.name) {
            violations.push(format!("{} (injected)", part.name));
        }
    }
    violations
}

/// Output-package references that no longer resolve to a part: a `.rels`
/// relationship Target or a `[Content_Types].xml` Override PartName whose part
/// was dropped. Office rejects such a package outright, so a dangling reference
/// is corruption even when the dropped part itself was editable.
fn referential_integrity_violations(after: &OpcPackage) -> Vec<String> {
    let mut violations = Vec::new();
    for part in after.parts() {
        if !part.name.ends_with(".rels") {
            continue;
        }
        let Some(base) = rels_base_dir(&part.name) else {
            continue;
        };
        let xml = String::from_utf8_lossy(&part.data);
        for (target, mode) in relationship_targets(&xml) {
            // External targets name a URI, not a package part.
            if mode.as_deref() == Some("External") {
                continue;
            }
            match resolve_part_path(&base, &target) {
                Some(resolved) if after.contains(&resolved) => {}
                Some(resolved) => {
                    violations.push(format!("{} -> missing part {resolved}", part.name));
                }
                None => {
                    violations.push(format!("{} -> unresolvable target {target}", part.name));
                }
            }
        }
    }
    if let Some(content_types) = after.part(opc::CONTENT_TYPES_PART) {
        let xml = String::from_utf8_lossy(content_types);
        for part_name in scan_tag_attr(&xml, "<Override", "PartName") {
            let resolved = part_name.strip_prefix('/').unwrap_or(&part_name);
            if !after.contains(resolved) {
                violations.push(format!(
                    "[Content_Types].xml override -> missing part {resolved}"
                ));
            }
        }
    }
    violations
}

/// The directory a `.rels` part's targets resolve against: for
/// `<dir>/_rels/<name>.rels` that is `<dir>/`, and for the package-root
/// `_rels/.rels` it is the empty string.
fn rels_base_dir(rels_name: &str) -> Option<String> {
    let idx = rels_name.rfind("_rels/")?;
    Some(rels_name[..idx].to_owned())
}

/// Resolves an OPC relationship Target against a base directory, collapsing
/// `.`/`..` segments. Returns `None` when `..` escapes the package root.
pub(super) fn resolve_part_path(base_dir: &str, target: &str) -> Option<String> {
    let combined = target
        .strip_prefix('/')
        .map_or_else(|| format!("{base_dir}{target}"), str::to_owned);
    let mut segments: Vec<&str> = Vec::new();
    for segment in combined.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

/// Extracts `(Target, TargetMode?)` from every `<Relationship>` in a `.rels`
/// part.
fn relationship_targets(xml: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<Relationship") {
        let after_tag = &rest[pos + "<Relationship".len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let Some(target) = attr_value(body, "Target=\"") {
            out.push((target, attr_value(body, "TargetMode=\"")));
        }
        rest = &after_tag[tag_end..];
    }
    out
}

pub(super) fn diff_parts(before: &OpcPackage, after: &OpcPackage) -> BTreeSet<String> {
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

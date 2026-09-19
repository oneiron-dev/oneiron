//! docx linker: cross-part reference checks after a native edit.
//!
//! The writer touches `word/document.xml` and, for the first comment,
//! `word/comments.xml` plus its content-type override and relationship row.
//! The linker re-derives from the output bytes that every relationship
//! target, content-type override, comment id, and numbering reference still
//! resolves. A dangling reference is corruption even when the edited XML
//! itself is well-formed.

use crate::opc::{CONTENT_TYPES_PART, OpcPackage};
use serde::Serialize;

/// One linker check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocxLinkCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The linker report. `ok` is the conjunction of all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocxLinkReport {
    pub ok: bool,
    pub checks: Vec<DocxLinkCheck>,
}

impl DocxLinkReport {
    #[must_use]
    pub fn single_failure(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            checks: vec![DocxLinkCheck {
                name,
                passed: false,
                detail: detail.into(),
            }],
        }
    }
}

/// Runs the docx linker over an already-parsed output package.
#[must_use]
pub fn check_docx_links(after: &OpcPackage) -> DocxLinkReport {
    let checks = vec![
        check_spine(after),
        check_stemma(after),
        check_relationships(after),
        check_content_types(after),
        check_comment_ids(after),
        check_numbering_refs(after),
    ];
    let ok = checks.iter().all(|c| c.passed);
    DocxLinkReport { ok, checks }
}

fn check_spine(after: &OpcPackage) -> DocxLinkCheck {
    let present = after.contains("word/document.xml");
    DocxLinkCheck {
        name: "docx_spine_present",
        passed: present,
        detail: if present {
            "output retains word/document.xml".to_owned()
        } else {
            "output is missing word/document.xml".to_owned()
        },
    }
}

fn check_relationships(after: &OpcPackage) -> DocxLinkCheck {
    let mut dangling = Vec::new();
    for part in after.parts() {
        if !part.name.ends_with(".rels") {
            continue;
        }
        let Some(base) = rels_base_dir(&part.name) else {
            continue;
        };
        let xml = String::from_utf8_lossy(&part.data);
        for (target, mode) in relationship_targets(&xml) {
            if mode.as_deref() == Some("External") {
                continue;
            }
            match resolve_part_path(&base, &target) {
                Some(resolved) if after.contains(&resolved) => {}
                Some(resolved) => dangling.push(format!("{} -> missing {resolved}", part.name)),
                None => dangling.push(format!("{} -> unresolvable {target}", part.name)),
            }
        }
    }
    DocxLinkCheck {
        name: "docx_relationships_resolve",
        passed: dangling.is_empty(),
        detail: if dangling.is_empty() {
            "every relationship target resolves to a part".to_owned()
        } else {
            format!("dangling references: {}", dangling.join(", "))
        },
    }
}

fn check_content_types(after: &OpcPackage) -> DocxLinkCheck {
    let Some(content_types) = after.part(CONTENT_TYPES_PART) else {
        return DocxLinkCheck {
            name: "docx_content_types_resolve",
            passed: false,
            detail: "output is missing [Content_Types].xml".to_owned(),
        };
    };
    let xml = String::from_utf8_lossy(content_types);
    let mut dangling = Vec::new();
    for part_name in scan_tag_attr(&xml, "<Override", "PartName") {
        let resolved = part_name.strip_prefix('/').unwrap_or(&part_name);
        if !after.contains(resolved) {
            dangling.push(format!("override -> missing part {resolved}"));
        }
    }
    DocxLinkCheck {
        name: "docx_content_types_resolve",
        passed: dangling.is_empty(),
        detail: if dangling.is_empty() {
            "every content-type override resolves to a part".to_owned()
        } else {
            format!("dangling overrides: {}", dangling.join(", "))
        },
    }
}

fn check_comment_ids(after: &OpcPackage) -> DocxLinkCheck {
    let Some(document) = after.part("word/document.xml") else {
        return DocxLinkCheck {
            name: "docx_comment_ids_resolve",
            passed: true,
            detail: "no document part; spine check reports it".to_owned(),
        };
    };
    let xml = String::from_utf8_lossy(document);
    let range_ids = scan_ids(&xml, "<w:commentRangeStart")
        .into_iter()
        .chain(scan_ids(&xml, "<w:commentRangeEnd"))
        .collect::<Vec<_>>();
    if range_ids.is_empty() {
        return DocxLinkCheck {
            name: "docx_comment_ids_resolve",
            passed: true,
            detail: "no comment ranges in document.xml".to_owned(),
        };
    }
    let Some(comments) = after.part("word/comments.xml") else {
        return DocxLinkCheck {
            name: "docx_comment_ids_resolve",
            passed: false,
            detail: "document ranges reference comments but word/comments.xml is missing"
                .to_owned(),
        };
    };
    let defined = scan_ids(&String::from_utf8_lossy(comments), "<w:comment ");
    let missing = range_ids
        .iter()
        .filter(|id| !defined.contains(id))
        .map(|id| format!("comment {id}"))
        .collect::<Vec<_>>();
    DocxLinkCheck {
        name: "docx_comment_ids_resolve",
        passed: missing.is_empty(),
        detail: if missing.is_empty() {
            "every comment range id has a comment definition".to_owned()
        } else {
            format!("ranges without definitions: {}", missing.join(", "))
        },
    }
}

fn check_numbering_refs(after: &OpcPackage) -> DocxLinkCheck {
    let Some(document) = after.part("word/document.xml") else {
        return DocxLinkCheck {
            name: "docx_numbering_present",
            passed: true,
            detail: "no document part; spine check reports it".to_owned(),
        };
    };
    let xml = String::from_utf8_lossy(document);
    if !xml.contains("<w:numPr") {
        return DocxLinkCheck {
            name: "docx_numbering_present",
            passed: true,
            detail: "no numbering references in document.xml".to_owned(),
        };
    }
    let present = after.contains("word/numbering.xml");
    DocxLinkCheck {
        name: "docx_numbering_present",
        passed: present,
        detail: if present {
            "numbering references resolve to word/numbering.xml".to_owned()
        } else {
            "document references numbering but word/numbering.xml is missing".to_owned()
        },
    }
}

fn rels_base_dir(rels_name: &str) -> Option<String> {
    let idx = rels_name.rfind("_rels/")?;
    Some(rels_name[..idx].to_owned())
}

fn resolve_part_path(base_dir: &str, target: &str) -> Option<String> {
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

fn relationship_targets(xml: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<Relationship") {
        let after = &rest[pos + "<Relationship".len()..];
        let end = after.find('>').unwrap_or(after.len());
        let body = &after[..end];
        if let Some(target) = attr_value(body, "Target=\"") {
            out.push((target, attr_value(body, "TargetMode=\"")));
        }
        rest = &after[end..];
    }
    out
}

fn scan_ids(xml: &str, tag: &str) -> Vec<String> {
    scan_tag_attr(xml, tag, "w:id")
}

fn scan_tag_attr(xml: &str, tag: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=\"");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(tag) {
        let after = &rest[pos + tag.len()..];
        let end = after.find('>').unwrap_or(after.len());
        if let Some(value) = attr_value(&after[..end], &needle) {
            out.push(value);
        }
        rest = &after[end..];
    }
    out
}

fn attr_value(tag_body: &str, needle: &str) -> Option<String> {
    let start = tag_body.find(needle)? + needle.len();
    let end = tag_body[start..].find('"')?;
    Some(tag_body[start..start + end].to_owned())
}

fn check_stemma(after: &OpcPackage) -> DocxLinkCheck {
    let result = after
        .part("word/document.xml")
        .ok_or_else(|| "missing document part".to_owned())
        .and_then(oneiron_stemma::validate_document);
    let errors = match result {
        Ok(findings) => findings
            .into_iter()
            .filter(|finding| {
                finding.severity == oneiron_stemma::docx_validate::ValidationSeverity::Error
            })
            .map(|finding| format!("{}: {}", finding.rule_id, finding.message))
            .collect::<Vec<_>>(),
        Err(error) => vec![error],
    };
    DocxLinkCheck {
        name: "stemma_post_serialization",
        passed: errors.is_empty(),
        detail: errors.join("; "),
    }
}

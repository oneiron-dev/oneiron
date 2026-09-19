//! Deterministic native-only DOCX corpus measurement and paragraph-join oracle input.
//!
//! Usage: docx_corpus <input-dir> <new-output-dir> <report.json>
//! Recurses through DOCX inputs in sorted relative-path order. Refusals are never
//! counted as proposals. This does not run Word or LibreOffice or mint goldens.
use oneiron_docedit::docx::{
    DocxEngineStamp, DocxOp, DocxOutcome, DocxPlan, DocxSpan, RevisionMark, apply_text_op,
    check_docx_links, inspect_docx, inspect_docx_settings, next_revision_id, run_docx_roundtrip,
};
use oneiron_docedit::opc::{self, Limits, OpcPackage, OpcPart, Package, PartClass};
use oneiron_docedit::{Error, Result};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const FIXTURE_MANIFEST: &str = include_str!("../tests/fixtures/docx-corpus/manifest.json");
const INSERTION: &str = "[Native corpus insert] ";
const MARK_DATE: &str = "2026-09-19T00:00:00Z";

struct Measurement {
    report: Value,
    output: Option<Vec<u8>>,
}

fn error_value(error: &Error) -> Value {
    let kind = match error {
        Error::InvalidPackage(_) => "InvalidPackage",
        Error::InvalidManifest(_) => "InvalidManifest",
        Error::EditFailed(_) => "EditFailed",
        Error::CommitMismatch => "CommitMismatch",
    };
    json!({"kind": kind, "reason": error.reason()})
}
fn refused(report: &mut Value, stage: &str, error: &Error) {
    report["status"] = json!("refused");
    report["refusal"] = json!({"stage": stage, "error": error_value(error)});
}
fn mark() -> Result<RevisionMark> {
    RevisionMark::new(DocxEngineStamp::current().author(), MARK_DATE)
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn stemma_inspection(bytes: Option<&[u8]>) -> Value {
    let Some(bytes) = bytes else {
        return json!({"status": "missing_document"});
    };
    match oneiron_stemma::validate_document(bytes) {
        Err(error) => json!({"status": "parse_refused", "reason": error}),
        Ok(findings) => {
            let mut errors = 0;
            let rows: Vec<_> = findings.into_iter().map(|finding| {
                let severity = match finding.severity {
                    oneiron_stemma::docx_validate::ValidationSeverity::Error => { errors += 1; "error" }
                    oneiron_stemma::docx_validate::ValidationSeverity::Warning => "warning",
                };
                json!({"rule": finding.rule_id, "severity": severity, "message": finding.message, "location": finding.location})
            }).collect();
            json!({"status": "inspected", "error_count": errors, "warning_count": rows.len() - errors, "finding_count": rows.len(), "findings": rows})
        }
    }
}

fn select_insert(
    document: &[u8],
    paragraphs: u32,
    revision: &RevisionMark,
) -> (Option<DocxOp>, Vec<Value>) {
    let mut attempts = Vec::new();
    let id = match next_revision_id(document) {
        Ok(id) => id,
        Err(error) => return (None, vec![error_value(&error)]),
    };
    for paragraph in 1..=paragraphs {
        let op = DocxOp::InsertText {
            span: DocxSpan {
                paragraph,
                start: 0,
                end: 0,
            },
            text: INSERTION.to_owned(),
        };
        match apply_text_op(document, &op, revision, id) {
            Ok(_) => return (Some(op), attempts),
            Err(error) => {
                attempts.push(json!({"paragraph": paragraph, "error": error_value(&error)}));
            }
        }
    }
    (None, attempts)
}

fn measure(input: &[u8], run_ref: &str) -> Measurement {
    let mut result = Measurement {
        report: json!({
            "status": "refused", "input_blake3": digest(input), "input_bytes": input.len(),
            "engine": DocxEngineStamp::current(), "output_blake3": null,
            "word_oracle": "not_run", "libreoffice_baseline": "not_run"
        }),
        output: None,
    };
    let noop = Package::open(input, Limits::default()).and_then(|package| package.write());
    let noop_exact = noop.as_ref().is_ok_and(|bytes| bytes == input);
    result.report["noop"] = match noop {
        Ok(bytes) => json!({"archive_exact": noop_exact, "output_blake3": digest(&bytes)}),
        Err(error) => json!({"archive_exact": false, "error": error_value(&error)}),
    };
    let before = match opc::read(input) {
        Ok(package) => package,
        Err(error) => {
            refused(&mut result.report, "package_inspection", &error);
            return result;
        }
    };
    let document = before.part("word/document.xml");
    result.report["stemma_input"] = stemma_inspection(document);
    result.report["native_input_links"] = json!(check_docx_links(&before));
    let inspection = inspect_docx(document, before.names().map(str::to_owned));
    result.report["native_input"] = match &inspection {
        Ok(value) => json!({"status": "inspected", "structure": value,
            "revision_id_count": value.revision_ids.len(), "comment_id_count": value.comment_ids.len(),
            "unknown_part_count": value.unknown_parts.len(), "part_count": before.parts().len()}),
        Err(error) => json!({"status": "refused", "error": error_value(error)}),
    };
    let settings = inspect_docx_settings(&before);
    result.report["settings"] = match &settings {
        Ok(value) => json!({"status": "inspected", "value": value}),
        Err(error) => json!({"status": "refused", "error": error_value(error)}),
    };
    if !noop_exact {
        refused(
            &mut result.report,
            "noop_identity",
            &Error::EditFailed("no-op archive identity not established"),
        );
        return result;
    }
    let inspection = match inspection {
        Ok(value) => value,
        Err(error) => {
            refused(&mut result.report, "native_inspection", &error);
            return result;
        }
    };
    if let Err(error) = settings.and_then(|value| value.require_editable()) {
        refused(&mut result.report, "settings_admission", &error);
        return result;
    }
    choose_and_apply(&before, input, inspection.paragraphs, run_ref, &mut result);
    result
}

fn choose_and_apply(
    before: &OpcPackage,
    input: &[u8],
    paragraphs: u32,
    run_ref: &str,
    result: &mut Measurement,
) {
    let (document, revision) = match (before.part("word/document.xml"), mark()) {
        (Some(document), Ok(revision)) => (document, revision),
        (_, Err(error)) => {
            refused(&mut result.report, "revision_mark", &error);
            return;
        }
        (None, _) => {
            refused(
                &mut result.report,
                "spine",
                &Error::InvalidPackage("missing document"),
            );
            return;
        }
    };
    let (op, attempts) = select_insert(document, paragraphs, &revision);
    result.report["paragraph_refusals"] = json!(attempts);
    let Some(op) = op else {
        refused(
            &mut result.report,
            "candidate_selection",
            &Error::InvalidManifest("no paragraph accepts the standalone plain-text insert"),
        );
        return;
    };
    result.report["operation"] = json!(op);
    apply_measurement(
        before,
        input,
        DocxPlan::new(vec![op], revision),
        run_ref,
        result,
    );
}

fn apply_measurement(
    before: &OpcPackage,
    input: &[u8],
    plan: DocxPlan,
    run_ref: &str,
    result: &mut Measurement,
) {
    match run_docx_roundtrip(input, &plan, run_ref) {
        Err(error) => refused(&mut result.report, "native_edit", &error),
        Ok(DocxOutcome::Rejected { report, linker, .. }) => {
            result.report["status"] = json!("gate_rejected");
            result.report["validation"] = json!(report);
            result.report["linker"] = json!(linker);
        }
        Ok(DocxOutcome::Proposed(proposal)) => {
            let after = match opc::read(&proposal.new_bytes) {
                Ok(after) => after,
                Err(error) => {
                    refused(&mut result.report, "output_read", &error);
                    return;
                }
            };
            let identity = identity_report(before, &after);
            result.report["part_identity"] = identity.clone();
            if identity["unknown_parts_identical"] != true
                || identity["all_non_document_parts_identical"] != true
            {
                refused(
                    &mut result.report,
                    "output_identity",
                    &Error::EditFailed("standalone text edit changed an unrelated part"),
                );
                return;
            }
            result.report["status"] = json!("proposed_native_only");
            result.report["output_blake3"] = json!(digest(&proposal.new_bytes));
            result.report["output_bytes"] = json!(proposal.new_bytes.len());
            result.report["manifest"] = json!(proposal.manifest);
            result.report["validation"] = json!(proposal.validation);
            result.report["linker"] = json!(proposal.linker);
            result.report["stemma_output"] = stemma_inspection(after.part("word/document.xml"));
            result.report["native_output"] = match inspect_docx(
                after.part("word/document.xml"),
                after.names().map(str::to_owned),
            ) {
                Ok(value) => json!(value),
                Err(error) => error_value(&error),
            };
            result.output = Some(proposal.new_bytes);
        }
    }
}

fn identity_report(before: &OpcPackage, after: &OpcPackage) -> Value {
    let mut names: Vec<_> = before.names().chain(after.names()).collect();
    names.sort_unstable();
    names.dedup();
    let mut unknown_ok = true;
    let mut untouched_ok = true;
    let rows: Vec<_> = names
        .into_iter()
        .filter(|name| *name != "word/document.xml")
        .map(|name| {
            let original = before.part(name);
            let changed = after.part(name);
            let unknown = opc::classify(name) == PartClass::Unknown;
            let identical = original == changed;
            unknown_ok &= !unknown || identical;
            untouched_ok &= identical;
            json!({"part": name, "classified_unknown": unknown, "identical": identical,
            "input_blake3": original.map(digest), "output_blake3": changed.map(digest)})
        })
        .collect();
    json!({"unknown_parts_identical": unknown_ok, "all_non_document_parts_identical": untouched_ok, "parts": rows})
}

fn docx_paths(base: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut pending = vec![base.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(std::io::Error::other("corpus symlinks are not supported"));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if entry
                .path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("docx"))
            {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)
}
fn relative_text(path: &Path) -> std::io::Result<String> {
    path.to_str()
        .map(|text| text.replace('\\', "/"))
        .ok_or_else(|| std::io::Error::other("corpus paths must be UTF-8"))
}

fn run(
    input_dir: &Path,
    output_dir: &Path,
    report_path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let input_dir = input_dir.canonicalize()?;
    let paths = docx_paths(&input_dir)?;
    if paths.is_empty() {
        return Err("input directory contains no DOCX files".into());
    }
    // A fresh output directory prevents stale proposals from appearing in a new run.
    fs::create_dir(output_dir)?;
    let output_dir = output_dir.canonicalize()?;
    if output_dir.starts_with(&input_dir) {
        return Err("output directory must be outside input directory".into());
    }
    let fixture_manifest: Value = serde_json::from_str(FIXTURE_MANIFEST)?;
    let mut entries = Vec::new();
    for path in paths {
        let relative = path.strip_prefix(&input_dir)?;
        let relative_name = relative_text(relative)?;
        let source = fixture_manifest["cases"].as_array().and_then(|cases| {
            cases.iter().find(|case| {
                case["file"]
                    .as_str()
                    .and_then(|name| name.strip_prefix(".w7/docx-corpus/"))
                    == Some(relative_name.as_str())
            })
        });
        let mut measured = match fs::read(&path) {
            Ok(bytes) => measure(&bytes, &format!("corpus:{relative_name}")),
            Err(error) => Measurement {
                report: json!({"status": "io_refused", "error": error.to_string()}),
                output: None,
            },
        };
        measured.report["input"] = json!(relative_name);
        measured.report["pinned_fixture"] = json!(source);
        if let Some(bytes) = measured.output {
            let out = Path::new("edited").join(relative);
            write_new(&output_dir.join(&out), &bytes)?;
            measured.report["output"] = json!(relative_text(&out)?);
        }
        entries.push(measured.report);
    }
    let join = write_join_case(&output_dir)?;
    let proposed = entries
        .iter()
        .filter(|entry| entry["status"] == "proposed_native_only")
        .count();
    let noop_exact = entries
        .iter()
        .filter(|entry| entry["noop"]["archive_exact"] == true)
        .count();
    let report = json!({"schema_version": 1, "measurement": "native_only_not_word_acceptance",
        "engine": DocxEngineStamp::current(), "fixed_revision_date": MARK_DATE,
        "fixture_manifest_blake3": digest(FIXTURE_MANIFEST.as_bytes()), "fixture_pins": fixture_manifest["pins"],
        "fixture_integrity": "input blake3 measured; compare pinned sha256 separately before oracle use",
        "counts": {"inputs": entries.len(), "noop_archive_exact": noop_exact,
            "native_proposals": proposed, "not_proposed": entries.len() - proposed},
        "entries": entries, "join_oracle_input": join,
        "word_oracle": "not_run", "libreoffice_baseline": "not_run"});
    write_new(report_path, &serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn join_input() -> Vec<u8> {
    let document = concat!(
        "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" ",
        "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:u=\"urn:unfamiliar\" mc:Ignorable=\"u\">",
        "<w:body><w:p><w:pPr><w:spacing w:after=\"120\"/></w:pPr>",
        "<w:r w:rsidR=\"12345678\"><w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">First </w:t></w:r>",
        "<u:preserve u:key=\"join-fixture\"/></w:p>",
        "<w:p><w:r><w:rPr><w:i/></w:rPr><w:t>second.</w:t></w:r></w:p>",
        "<w:p><w:r><w:t>Untouched third.</w:t></w:r></w:p><w:sectPr/></w:body></w:document>"
    );
    let types = concat!(
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">",
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>",
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>",
        "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>",
        "</Types>"
    );
    let rels = concat!(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>",
        "</Relationships>"
    );
    let parts = [
        (opc::CONTENT_TYPES_PART, types),
        ("word/document.xml", document),
        ("_rels/.rels", rels),
        ("customXml/opaque.xml", "<opaque>Keep unchanged.</opaque>"),
    ];
    opc::write(&OpcPackage::from_parts(
        parts
            .into_iter()
            .map(|(name, text)| OpcPart {
                name: name.to_owned(),
                data: text.as_bytes().to_vec(),
            })
            .collect(),
    ))
}
fn write_join_case(output: &Path) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let input = join_input();
    let before = opc::read(&input)?;
    let op = DocxOp::JoinParagraphs {
        span: DocxSpan::new(1, 6, 6)?,
    };
    let mut result = Measurement {
        report: json!({"input_blake3": digest(&input), "operation": op,
        "status": "refused", "engine": DocxEngineStamp::current(), "word_oracle": "not_run"}),
        output: None,
    };
    apply_measurement(
        &before,
        &input,
        DocxPlan::new(vec![op], mark()?),
        "corpus:standalone-join",
        &mut result,
    );
    write_new(&output.join("join/base.docx"), &input)?;
    if let Some(bytes) = result.output {
        write_new(&output.join("join/output.docx"), &bytes)?;
    }
    let expectations = json!({"kind": "authored_expectations_not_oracle_goldens",
        "baseline_paragraphs": ["First ", "second.", "Untouched third."],
        "accepted_paragraphs": ["First second.", "Untouched third."],
        "rejected_paragraphs": ["First ", "second.", "Untouched third."],
        "expected_native_revision_count": 1, "expected_comment_count": 0,
        "formatting_checks": ["First remains bold", "second. remains italic", "Untouched third. is unchanged"],
        "oracle_checks": ["Word opens both files with zero repairs", "Accept joins only first and second paragraphs", "Reject restores baseline paragraph boundaries", "Compare content and rendering outside the join"]});
    write_new(
        &output.join("join/expected.json"),
        &serde_json::to_vec_pretty(&expectations)?,
    )?;
    for (name, text) in [
        ("baseline.txt", "First \nsecond.\nUntouched third.\n"),
        ("expected-accepted.txt", "First second.\nUntouched third.\n"),
        (
            "expected-rejected.txt",
            "First \nsecond.\nUntouched third.\n",
        ),
    ] {
        write_new(&output.join("join").join(name), text.as_bytes())?;
    }
    result.report["baseline"] = json!("join/base.docx");
    result.report["expected"] = expectations;
    Ok(result.report)
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        let _ = writeln!(
            std::io::stderr(),
            "usage: docx_corpus <input-dir> <new-output-dir> <report.json>"
        );
        return std::process::ExitCode::FAILURE;
    }
    match run(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "docx_corpus: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_is_deterministic_and_keeps_unrelated_parts() {
        let input = join_input();
        let first = measure(&input, "driver-test");
        let second = measure(&input, "driver-test");
        assert_eq!(first.report, second.report);
        assert_eq!(first.output, second.output);
        assert!(first.output.is_some());
        assert_eq!(first.report["status"], "proposed_native_only");
        assert_eq!(first.report["noop"]["archive_exact"], true);
        assert_eq!(
            first.report["part_identity"]["unknown_parts_identical"],
            true
        );
        assert_eq!(
            first.report["part_identity"]["all_non_document_parts_identical"],
            true
        );
    }

    #[test]
    fn malformed_input_is_a_refusal_without_output() {
        let measured = measure(b"not a zip", "driver-test");
        assert!(measured.output.is_none());
        assert_eq!(measured.report["status"], "refused");
        assert_eq!(
            measured.report["refusal"]["error"]["kind"],
            "InvalidPackage"
        );
    }

    #[test]
    fn pending_join_is_not_counted_as_a_successful_insert() {
        let input = join_input();
        let plan = DocxPlan::new(
            vec![DocxOp::JoinParagraphs {
                span: DocxSpan::new(1, 6, 6).expect("span"),
            }],
            mark().expect("mark"),
        );
        let DocxOutcome::Proposed(joined) =
            run_docx_roundtrip(&input, &plan, "join-test").expect("join")
        else {
            panic!("join refused");
        };
        let measured = measure(&joined.new_bytes, "driver-test");
        assert!(measured.output.is_none());
        assert_eq!(measured.report["status"], "refused");
        assert_eq!(
            measured.report["refusal"]["error"]["kind"],
            "InvalidManifest"
        );
    }
}

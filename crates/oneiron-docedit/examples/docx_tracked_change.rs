//! Deterministic native-docx oracle input: tracked changes + span comment.
//!
//! Builds a small synthetic package in memory, applies one insert, one
//! delete, and one span comment through [`run_docx_roundtrip`], and writes
//! the resulting `.docx` bytes to the path given as the first argument:
//!
//! ```text
//! cargo run -p oneiron-docedit --example docx_tracked_change -- /tmp/docx-oracle.docx
//! ```
//!
//! Deterministic: same bytes on every run (fixed author, fixed date, fixed
//! ops, retained-OPC write). Representative only: no Word pass is claimed
//! until the Mac oracle opens the output without repair and renders the
//! marks as Word's own. Unknown parts and unknown XML inside the fixture
//! survive the round trip byte-for-byte; the oracle checks content outside
//! the edit is unchanged.

use oneiron_docedit::docx::{DocxOp, DocxPlan, DocxSpan, RevisionMark, run_docx_roundtrip};
use oneiron_docedit::opc::{self, OpcPackage, OpcPart};
use std::io::Write;

const DOCUMENT: &str = concat!(
    "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" ",
    "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" ",
    "mc:Ignorable=\"u\" xmlns:u=\"urn:unknown\"><w:body>",
    "<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Quarterly report</w:t></w:r>",
    "<u:keep key=\"draft\"/></w:p>",
    "<w:p><w:r><w:t>Revenue grew in every region.</w:t></w:r></w:p>",
    "<w:p><w:r><w:t>Risks remain in supply.</w:t></w:r></w:p>",
    "<w:sectPr/></w:body></w:document>",
);

const CONTENT_TYPES: &str = concat!(
    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">",
    "<Default Extension=\"xml\" ContentType=\"application/xml\"/>",
    "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>",
    "<Override PartName=\"/word/document.xml\" ",
    "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>",
    "</Types>",
);

const RELS: &str = concat!(
    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
    "<Relationship Id=\"rId1\" ",
    "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" ",
    "Target=\"word/document.xml\"/>",
    "</Relationships>",
);

fn input_package() -> Vec<u8> {
    let pkg = OpcPackage::from_parts(vec![
        OpcPart {
            name: opc::CONTENT_TYPES_PART.to_owned(),
            data: CONTENT_TYPES.as_bytes().to_vec(),
        },
        OpcPart {
            name: "word/document.xml".to_owned(),
            data: DOCUMENT.as_bytes().to_vec(),
        },
        OpcPart {
            name: "_rels/.rels".to_owned(),
            data: RELS.as_bytes().to_vec(),
        },
        OpcPart {
            name: "word/_rels/document.xml.rels".to_owned(),
            data: b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>".to_vec(),
        },
        OpcPart {
            name: "customXml/item1.xml".to_owned(),
            data: b"<unknown>opaque oracle fixture, preserved verbatim</unknown>".to_vec(),
        },
    ]);
    opc::write(&pkg)
}

fn plan() -> Option<DocxPlan> {
    let mark = RevisionMark::new("oneiron-docedit-docx/0.1.0", "2026-09-19T00:00:00Z").ok()?;
    let ops = vec![
        DocxOp::InsertText {
            span: DocxSpan::new(1, 16, 16).ok()?,
            text: " (draft)".to_owned(),
        },
        DocxOp::DeleteSpan {
            span: DocxSpan::new(2, 13, 24).ok()?,
        },
        DocxOp::AddComment {
            span: DocxSpan::new(3, 0, 5).ok()?,
            body: "Oracle: confirm this span stays anchored.".to_owned(),
        },
    ];
    Some(DocxPlan::new(ops, mark))
}

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: docx_tracked_change <output.docx>"
        );
        return std::process::ExitCode::FAILURE;
    };
    let Some(plan) = plan() else {
        let _ = writeln!(
            std::io::stderr(),
            "docx_tracked_change: fixture plan is invalid"
        );
        return std::process::ExitCode::FAILURE;
    };
    let input = input_package();
    let base_path = std::path::PathBuf::from(&path).with_extension("base.docx");
    if let Err(error) = std::fs::write(&base_path, &input) {
        let _ = writeln!(
            std::io::stderr(),
            "docx_tracked_change: base write failed: {error}"
        );
        return std::process::ExitCode::FAILURE;
    }
    let outcome = match run_docx_roundtrip(&input, &plan, "run:docx-oracle") {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "docx_tracked_change: pipeline refused: {error}"
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let bytes = match outcome {
        oneiron_docedit::docx::DocxOutcome::Proposed(proposal) => proposal.new_bytes,
        oneiron_docedit::docx::DocxOutcome::Rejected { report, linker, .. } => {
            let _ = writeln!(
                std::io::stderr(),
                "docx_tracked_change: gate rejected: {report:?} {linker:?}"
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    match std::fs::write(&path, &bytes) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "docx_tracked_change: write failed: {error}"
            );
            std::process::ExitCode::FAILURE
        }
    }
}

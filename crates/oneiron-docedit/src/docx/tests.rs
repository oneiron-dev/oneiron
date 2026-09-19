//! Native docx writer tests: observable XML, guards, and determinism.
//!
//! Every assertion reads caller-observable output: revision-mark XML, preserved
//! unknown bytes, typed refusal variants, linker verdicts, and manifest rows.
//! Nothing here claims Word acceptance; the Mac oracle judges that.

use super::*;
use crate::opc::{self, OpcPackage, OpcPart};

const DOCUMENT: &str = "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:u=\"urn:unknown\"><w:body><w:p><w:pPr><w:spacing w:after=\"120\"/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t>Hello </w:t></w:r><w:r><w:t>world</w:t></w:r><u:keep key=\"x\"/></w:p><w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p><w:sectPr/></w:body></w:document>";
const CONTENT_TYPES: &str = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>";
const RELS: &str = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"document.xml\"/></Relationships>";
const UNKNOWN_PART: &str = "customXml/item1.xml";
const UNKNOWN_BYTES: &[u8] = b"<unknown>opaque, preserve me byte-for-byte</unknown>";

fn mark() -> RevisionMark {
    RevisionMark::new("oneiron-docedit-docx/0.1.0", "2026-09-19T00:00:00Z").expect("mark")
}

fn package_bytes(document: &str) -> Vec<u8> {
    let pkg = OpcPackage::from_parts(vec![
        OpcPart {
            name: opc::CONTENT_TYPES_PART.to_owned(),
            data: CONTENT_TYPES.as_bytes().to_vec(),
        },
        OpcPart {
            name: "word/document.xml".to_owned(),
            data: document.as_bytes().to_vec(),
        },
        OpcPart {
            name: "word/_rels/document.xml.rels".to_owned(),
            data: RELS.as_bytes().to_vec(),
        },
        OpcPart {
            name: UNKNOWN_PART.to_owned(),
            data: UNKNOWN_BYTES.to_vec(),
        },
    ]);
    opc::write(&pkg)
}

#[test]
fn insert_emits_tracked_mark_and_preserves_unknowns() {
    let span = DocxSpan::new(1, 6, 6).expect("span");
    let op = DocxOp::InsertText {
        span,
        text: "brave ".to_owned(),
    };
    let write = apply_text_op(DOCUMENT.as_bytes(), &op, &mark(), 1).expect("insert");
    assert_eq!(write.revision_ids, vec![1]);
    let xml = String::from_utf8(write.document_xml).expect("utf8");
    assert!(
        xml.contains("<w:ins w:author=\"oneiron-docedit-docx/0.1.0\" w:date=\"2026-09-19T00:00:00Z\" w:id=\"1\">"),
        "insert mark carries author/date/id: {xml}"
    );
    assert!(
        xml.contains("<w:t xml:space=\"preserve\">brave </w:t>"),
        "insert text: {xml}"
    );
    assert!(
        xml.contains("<u:keep key=\"x\"/>"),
        "unknown sibling survives: {xml}"
    );
    assert!(
        xml.contains("<w:t>Second paragraph.</w:t>"),
        "second paragraph verbatim: {xml}"
    );
    assert!(
        xml.contains("<w:pPr><w:spacing w:after=\"120\"/></w:pPr>"),
        "paragraph properties verbatim: {xml}"
    );
}

#[test]
fn delete_wraps_del_text_and_keeps_run_properties() {
    let span = DocxSpan::new(1, 0, 5).expect("span");
    let op = DocxOp::DeleteSpan { span };
    let xml = String::from_utf8(
        apply_text_op(DOCUMENT.as_bytes(), &op, &mark(), 7)
            .expect("delete")
            .document_xml,
    )
    .expect("utf8");
    assert!(
        xml.contains("<w:del w:author=\"oneiron-docedit-docx/0.1.0\""),
        "del mark: {xml}"
    );
    assert!(xml.contains("w:id=\"7\""), "del id: {xml}");
    assert!(
        xml.contains("<w:delText>Hello</w:delText>"),
        "deleted text: {xml}"
    );
    assert!(
        xml.contains("<w:b/>"),
        "run properties copied onto survivors: {xml}"
    );
    assert!(
        xml.contains("<w:t>Second paragraph.</w:t>"),
        "untouched paragraph: {xml}"
    );
}

#[test]
fn replace_emits_delete_then_insert_with_sequential_ids() {
    let span = DocxSpan::new(1, 6, 11).expect("span");
    let op = DocxOp::ReplaceSpan {
        span,
        text: "Word".to_owned(),
    };
    let write = apply_text_op(DOCUMENT.as_bytes(), &op, &mark(), 3).expect("replace");
    assert_eq!(write.revision_ids, vec![3, 4]);
    let xml = String::from_utf8(write.document_xml).expect("utf8");
    let del = xml.find("<w:del ").expect("del block");
    let ins = xml.find("<w:ins ").expect("ins block");
    assert!(del < ins, "delete precedes insert: {xml}");
    assert!(
        xml.contains("<w:delText>world</w:delText>"),
        "old text: {xml}"
    );
    assert!(xml.contains("<w:t>Word</w:t>"), "new text: {xml}");
}

#[test]
fn mid_run_split_preserves_both_halves() {
    let span = DocxSpan::new(2, 6, 6).expect("span");
    let op = DocxOp::InsertText {
        span,
        text: "X".to_owned(),
    };
    let xml = String::from_utf8(
        apply_text_op(DOCUMENT.as_bytes(), &op, &mark(), 1)
            .expect("insert")
            .document_xml,
    )
    .expect("utf8");
    assert!(xml.contains("<w:t>Second</w:t>"), "before half: {xml}");
    assert!(
        xml.contains("<w:t> paragraph.</w:t>")
            || xml.contains("<w:t xml:space=\"preserve\"> paragraph.</w:t>"),
        "after half: {xml}"
    );
    assert!(xml.contains("<w:t>X</w:t>"), "inserted run: {xml}");
}

#[test]
fn inserted_text_is_escaped_and_space_preserved() {
    for (payload, expected) in [
        ("a&b", "a&amp;b"),
        ("a<b", "a&lt;b"),
        ("a>b", "a&gt;b"),
        (" lead", "<w:t xml:space=\"preserve\"> lead</w:t>"),
        ("trail ", "<w:t xml:space=\"preserve\">trail </w:t>"),
    ] {
        let span = DocxSpan::new(2, 0, 0).expect("span");
        let op = DocxOp::InsertText {
            span,
            text: payload.to_owned(),
        };
        let xml = String::from_utf8(
            apply_text_op(DOCUMENT.as_bytes(), &op, &mark(), 1)
                .expect("insert")
                .document_xml,
        )
        .expect("utf8");
        assert!(
            xml.contains(expected),
            "payload {payload:?} escapes to {expected}: {xml}"
        );
    }
}

#[test]
fn narrow_guards_refuse_complex_and_malformed_plans() {
    let with_ins = DOCUMENT.replace(
        "<w:t>world</w:t>",
        "<w:ins w:author=\"a\" w:date=\"d\" w:id=\"1\"><w:r><w:t>world</w:t></w:r></w:ins>",
    );
    let span = DocxSpan::new(1, 0, 1).expect("span");
    let err = apply_text_op(
        with_ins.as_bytes(),
        &DocxOp::DeleteSpan { span },
        &mark(),
        2,
    )
    .expect_err("existing revisions are refused");
    assert!(matches!(err, crate::Error::InvalidManifest(_)));

    let with_link = DOCUMENT.replace(
        "<w:r><w:t>world</w:t></w:r>",
        "<w:hyperlink r:id=\"rId9\"><w:r><w:t>world</w:t></w:r></w:hyperlink>",
    );
    let err = apply_text_op(
        with_link.as_bytes(),
        &DocxOp::DeleteSpan { span },
        &mark(),
        2,
    )
    .expect_err("hyperlinks are refused");
    assert!(matches!(err, crate::Error::InvalidManifest(_)));

    assert!(DocxSpan::new(0, 0, 0).is_err(), "paragraph is 1-based");
    assert!(DocxSpan::new(1, 5, 4).is_err(), "inverted span refused");
    assert_eq!(DocxSpan::parse("body/p2", 1, 3).expect("path").paragraph, 2);
    assert!(
        DocxSpan::parse("sheet/A1", 0, 0).is_err(),
        "non-docx path refused"
    );
    assert!(
        DocxSpan::parse("body/p0", 0, 0).is_err(),
        "zero ordinal refused"
    );

    let caret = DocxSpan::new(1, 2, 2).expect("caret");
    assert!(
        DocxOp::DeleteSpan { span: caret }.validate().is_err(),
        "delete needs a range"
    );
    assert!(
        DocxOp::InsertText {
            span,
            text: "x".to_owned()
        }
        .validate()
        .is_err(),
        "insert needs a caret"
    );
    assert!(
        DocxOp::InsertText {
            span: caret,
            text: String::new()
        }
        .validate()
        .is_err(),
        "empty payload refused"
    );
    assert!(
        DocxOp::InsertText {
            span: caret,
            text: "a\u{0007}b".to_owned()
        }
        .validate()
        .is_err(),
        "control chars refused"
    );

    let past_para = DocxSpan::new(9, 0, 0).expect("span");
    assert!(
        apply_text_op(
            DOCUMENT.as_bytes(),
            &DocxOp::InsertText {
                span: past_para,
                text: "x".to_owned()
            },
            &mark(),
            1
        )
        .is_err(),
        "paragraph past the end refused"
    );
    let past_text = DocxSpan::new(1, 0, 99).expect("span");
    assert!(
        apply_text_op(
            DOCUMENT.as_bytes(),
            &DocxOp::DeleteSpan { span: past_text },
            &mark(),
            1
        )
        .is_err(),
        "span past the text refused"
    );
    assert!(RevisionMark::new("", "2026-09-19T00:00:00Z").is_err());
    assert!(RevisionMark::new("ok", "not-a-date").is_err());
    assert!(RevisionMark::new("bad\"author", "2026-09-19T00:00:00Z").is_err());
}

#[test]
fn revision_ids_allocate_past_existing_marks() {
    let used = DOCUMENT.replace(
        "<w:sectPr/></w:body>",
        "<w:p><w:ins w:author=\"a\" w:date=\"d\" w:id=\"41\"><w:r><w:t>z</w:t></w:r></w:ins></w:p><w:sectPr/></w:body>",
    );
    assert_eq!(next_revision_id(used.as_bytes()).expect("next"), 42);
    assert_eq!(next_revision_id(DOCUMENT.as_bytes()).expect("next"), 1);
}

#[test]
fn comment_anchors_ranges_reference_and_row() {
    let span = DocxSpan::new(2, 0, 6).expect("span");
    let op = DocxOp::AddComment {
        span,
        body: "Check this".to_owned(),
    };
    let write = apply_comment(DOCUMENT.as_bytes(), None, &op, &mark(), 1).expect("comment");
    assert!(write.comments_created);
    assert_eq!(write.comment_id, 1);
    let document = String::from_utf8(write.document_xml).expect("utf8");
    assert!(
        document.contains("<w:commentRangeStart w:id=\"1\"/>"),
        "start: {document}"
    );
    assert!(
        document.contains("<w:commentRangeEnd w:id=\"1\"/>"),
        "end: {document}"
    );
    assert!(
        document.contains("<w:commentReference w:id=\"1\"/>"),
        "reference: {document}"
    );
    let comments = String::from_utf8(write.comments_xml).expect("utf8");
    assert!(
        comments.contains("<w:comment w:id=\"1\""),
        "row: {comments}"
    );
    assert!(
        comments.contains("<w:t>Check this</w:t>"),
        "body: {comments}"
    );
    assert_eq!(next_comment_id(DOCUMENT.as_bytes(), None).expect("next"), 1);
}

#[test]
fn linker_catches_dangling_refs_and_missing_comment_parts() {
    let base = package_bytes(DOCUMENT);
    let parsed = opc::read(&base).expect("fixture");
    assert!(check_docx_links(&parsed).ok, "clean package links");

    let mut dangling = parsed.clone();
    dangling.upsert(
        "word/_rels/document.xml.rels",
        b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId9\" Type=\"t\" Target=\"gone.xml\"/></Relationships>".to_vec(),
    );
    assert!(
        !check_docx_links(&dangling).ok,
        "dangling rel target fails the linker"
    );

    let span = DocxSpan::new(1, 0, 1).expect("span");
    let op = DocxOp::AddComment {
        span,
        body: "orphan".to_owned(),
    };
    let write = apply_comment(DOCUMENT.as_bytes(), None, &op, &mark(), 5).expect("comment");
    let mut orphan = parsed.clone();
    orphan.upsert("word/document.xml", write.document_xml);
    assert!(
        !check_docx_links(&orphan).ok,
        "ranges without comments.xml fail the linker"
    );
}

#[test]
fn pipeline_roundtrip_marks_revisions_and_preserves_unknown_bytes() {
    let input = package_bytes(DOCUMENT);
    let plan = DocxPlan::new(
        vec![
            DocxOp::InsertText {
                span: DocxSpan::new(1, 11, 11).expect("caret"),
                text: "!".to_owned(),
            },
            DocxOp::DeleteSpan {
                span: DocxSpan::new(2, 0, 6).expect("range"),
            },
        ],
        mark(),
    );
    let proposal = match run_docx_roundtrip(&input, &plan, "run:docx").expect("pipeline") {
        DocxOutcome::Proposed(proposal) => proposal,
        DocxOutcome::Rejected { report, linker, .. } => {
            panic!("expected a proposal: {report:?} {linker:?}")
        }
    };
    assert!(proposal.validation.ok);
    assert!(proposal.linker.ok);
    assert_eq!(proposal.manifest.revision_ids, vec![1, 2]);
    assert_eq!(proposal.manifest.engine, DocxEngineStamp::current());
    assert!(
        proposal
            .manifest
            .touched_parts
            .contains("word/document.xml")
    );
    assert!(!proposal.manifest.touched_parts.contains(UNKNOWN_PART));
    assert_eq!(proposal.manifest.anchor_effects().len(), 2);
    assert_eq!(proposal.manifest.render_diff().len(), 2);

    let after = opc::read(&proposal.new_bytes).expect("output parses");
    assert_eq!(
        after.part(UNKNOWN_PART),
        Some(UNKNOWN_BYTES),
        "unknown part survives byte-for-byte"
    );
    let xml =
        String::from_utf8(after.part("word/document.xml").expect("spine").to_vec()).expect("utf8");
    assert!(xml.contains("<w:ins "), "insert mark present: {xml}");
    assert!(xml.contains("<w:del "), "delete mark present: {xml}");
    assert!(
        xml.contains("<u:keep key=\"x\"/>"),
        "unknown XML in place: {xml}"
    );

    let bytes = proposal.manifest.to_msgpack().expect("encode");
    let decoded = DocxManifest::from_msgpack(&bytes).expect("decode");
    assert_eq!(decoded, proposal.manifest);

    // Deterministic: same input, plan, and mark mint the same bytes + commit.
    let again = match run_docx_roundtrip(&input, &plan, "run:docx").expect("pipeline") {
        DocxOutcome::Proposed(proposal) => proposal,
        DocxOutcome::Rejected { report, .. } => panic!("deterministic retry: {report:?}"),
    };
    assert_eq!(again.new_bytes, proposal.new_bytes);
    assert_eq!(
        again.prepared.commit_hash(),
        proposal.prepared.commit_hash()
    );
}

#[test]
fn pipeline_bootstraps_first_comment_with_links() {
    let input = package_bytes(DOCUMENT);
    let plan = DocxPlan::new(
        vec![DocxOp::AddComment {
            span: DocxSpan::new(1, 0, 5).expect("range"),
            body: "First".to_owned(),
        }],
        mark(),
    );
    let proposal = match run_docx_roundtrip(&input, &plan, "run:comment").expect("pipeline") {
        DocxOutcome::Proposed(proposal) => proposal,
        DocxOutcome::Rejected { report, linker, .. } => {
            panic!("expected a proposal: {report:?} {linker:?}")
        }
    };
    assert_eq!(proposal.manifest.comment_ids, vec![1]);
    let after = opc::read(&proposal.new_bytes).expect("output parses");
    assert!(after.contains("word/comments.xml"), "comments part created");
    assert_eq!(
        after.part(UNKNOWN_PART),
        Some(UNKNOWN_BYTES),
        "unknown part bytes survive the comments bootstrap"
    );
    let types = String::from_utf8(after.part(opc::CONTENT_TYPES_PART).expect("types").to_vec())
        .expect("utf8");
    assert!(
        types.contains("/word/comments.xml"),
        "override row: {types}"
    );
    let rels = String::from_utf8(
        after
            .part("word/_rels/document.xml.rels")
            .expect("rels")
            .to_vec(),
    )
    .expect("utf8");
    assert!(rels.contains("comments"), "relationship row: {rels}");
    assert!(proposal.linker.ok, "linker accepts the bootstrap");
}

#[test]
fn pipeline_refuses_same_paragraph_twice_and_empty_plans() {
    let input = package_bytes(DOCUMENT);
    let twice = DocxPlan::new(
        vec![
            DocxOp::InsertText {
                span: DocxSpan::new(1, 0, 0).expect("caret"),
                text: "a".to_owned(),
            },
            DocxOp::InsertText {
                span: DocxSpan::new(1, 1, 1).expect("caret"),
                text: "b".to_owned(),
            },
        ],
        mark(),
    );
    assert!(
        run_docx_roundtrip(&input, &twice, "run:twice").is_err(),
        "same paragraph twice is refused"
    );
    let empty = DocxPlan::new(vec![], mark());
    assert!(
        run_docx_roundtrip(&input, &empty, "run:empty").is_err(),
        "empty plans are refused"
    );
    assert!(
        run_docx_roundtrip(&input, &twice, "  ").is_err(),
        "blank run_ref is refused"
    );
}

#[test]
fn engine_stamp_is_pinned_and_stable() {
    let stamp = DocxEngineStamp::current();
    assert_eq!(stamp.engine, "oneiron-docedit-docx");
    assert_eq!(stamp.version, "0.1.0");
    assert_eq!(
        stamp.stemma_pin,
        "v0.6.0 ad1e70deac0a828d5162ac3b3f2186c2bb0c075e"
    );
    assert_eq!(stamp.author(), "oneiron-docedit-docx/0.1.0");
}

#[test]
fn shared_commitment_binds_docx_base_stamp_and_bytes() {
    let bytes = package_bytes(DOCUMENT);
    let plan = DocxPlan::new(
        vec![DocxOp::InsertText {
            span: DocxSpan::new(1, 0, 0).expect("span"),
            text: "new ".to_owned(),
        }],
        mark(),
    );
    let DocxOutcome::Proposed(native) =
        run_docx_roundtrip(&bytes, &plan, "run:checked").expect("pipeline")
    else {
        panic!("valid native edit must propose");
    };
    let proposal = native.into_edit_proposal(Some(9)).expect("shared handoff");
    let verify = |version, engine: &crate::calc::EngineId, output: &[u8]| {
        proposal.prepared.verify(crate::PrepareInput {
            base_content_hash: proposal.base_content_hash,
            base_version: version,
            run_ref: &proposal.run_ref,
            output,
            writes: &proposal.manifest,
            report: &proposal.validation,
            engine,
        })
    };
    assert!(verify(Some(9), &proposal.engine, &proposal.new_bytes).is_ok());
    assert_eq!(
        verify(Some(10), &proposal.engine, &proposal.new_bytes),
        Err(crate::Error::CommitMismatch)
    );
    assert_eq!(
        verify(
            Some(9),
            &crate::calc::EngineId::imported(),
            &proposal.new_bytes
        ),
        Err(crate::Error::CommitMismatch)
    );
    assert_eq!(
        verify(Some(9), &proposal.engine, b"tampered"),
        Err(crate::Error::CommitMismatch)
    );
}

#[test]
fn paragraph_join_is_a_tracked_mark_deletion_and_moves_final_view_spans() {
    let plan = DocxPlan::new(
        vec![DocxOp::JoinParagraphs {
            span: DocxSpan::new(1, 11, 11).expect("end caret"),
        }],
        mark(),
    );
    let DocxOutcome::Proposed(proposal) =
        run_docx_roundtrip(&package_bytes(DOCUMENT), &plan, "run:join").expect("join")
    else {
        panic!("join must pass linker");
    };
    let package = opc::read(&proposal.new_bytes).expect("package");
    let xml =
        std::str::from_utf8(package.part("word/document.xml").expect("document")).expect("utf8");
    assert!(xml.contains("<w:rPr><w:del "));
    assert!(xml.contains("<w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p>"));
    let effect = &proposal.manifest.anchor_effects()[0];
    assert_eq!(
        replay_span(DocxSpan::new(2, 0, 6).expect("span"), effect),
        Some(DocxSpan::new(1, 11, 17).expect("joined span"))
    );
    assert_eq!(
        replay_span(DocxSpan::new(3, 2, 4).expect("span"), effect),
        Some(DocxSpan::new(2, 2, 4).expect("shifted span"))
    );
    assert!(run_docx_roundtrip(&proposal.new_bytes, &plan, "run:join-again").is_err());
}

#[test]
fn retained_run_attrs_survive_and_unknown_children_refuse_lossy_split() {
    let source = DOCUMENT.replace(
        "<w:r><w:t>world</w:t></w:r>",
        "<w:r u:run=\"keep\"><w:t u:text=\"keep\">world</w:t></w:r>",
    );
    let op = DocxOp::DeleteSpan {
        span: DocxSpan::new(1, 7, 9).expect("span"),
    };
    let output = apply_text_op(source.as_bytes(), &op, &mark(), 1).expect("delete");
    let xml = String::from_utf8(output.document_xml).expect("utf8");
    assert_eq!(xml.matches("u:run=\"keep\"").count(), 3);
    assert_eq!(xml.matches("u:text=\"keep\"").count(), 3);
    let opaque = source.replace("world</w:t>", "world</w:t><u:unsupported/>");
    assert!(apply_text_op(opaque.as_bytes(), &op, &mark(), 1).is_err());
    let crossing = DOCUMENT.replace("</w:r><w:r><w:t>world", "</w:r><u:between/><w:r><w:t>world");
    let op = DocxOp::DeleteSpan {
        span: DocxSpan::new(1, 3, 8).expect("span"),
    };
    assert!(apply_text_op(crossing.as_bytes(), &op, &mark(), 1).is_err());
}

#[test]
fn docx_span_replay_drifts_replacements_and_shifts_survivors() {
    let effect = DocxAnchorEffect::ShiftWithinParagraph {
        paragraph: 1,
        at: 3,
        removed: 2,
        inserted: 4,
    };
    assert_eq!(
        replay_span(DocxSpan::new(1, 3, 5).expect("span"), &effect),
        None
    );
    assert_eq!(
        replay_span(DocxSpan::new(1, 6, 8).expect("span"), &effect),
        Some(DocxSpan::new(1, 8, 10).expect("shifted"))
    );
    assert_eq!(
        replay_span(DocxSpan::new(2, 3, 5).expect("span"), &effect),
        Some(DocxSpan::new(2, 3, 5).expect("untouched"))
    );
}

#[test]
fn stemma_linker_rejects_illegal_tracked_content_and_malformed_xml() {
    let illegal = DOCUMENT.replace(
        "<w:t>world</w:t>",
        "<w:t>world</w:t></w:r><w:ins w:id=\"9\"><w:hyperlink/></w:ins><w:r><w:t>tail</w:t>",
    );
    assert!(!check_docx_links(&opc::read(&package_bytes(&illegal)).expect("package")).ok);
    let malformed = DOCUMENT.replace("<w:sectPr/></w:body>", "");
    assert!(!check_docx_links(&opc::read(&package_bytes(&malformed)).expect("package")).ok);
}

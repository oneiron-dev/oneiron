//! Protection refuses at the package door; settings bytes never change.
use super::*;
use crate::docx::{DocxOp, DocxOutcome, DocxPlan, DocxSpan, RevisionMark, run_docx_roundtrip};
use crate::opc::{self, OpcPart};

fn package(settings: &str, name: &str) -> OpcPackage {
    let types = r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
    let document = format!(
        r#"<w:document xmlns:w="{WORD}"><w:body><w:p><w:r><w:t>First.</w:t></w:r></w:p><w:p><w:r><w:t>Second.</w:t></w:r></w:p><w:sectPr/></w:body></w:document>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{RELS}"><Relationship Id="rId1" Type="{SETTINGS_REL}" Target="/{name}"/></Relationships>"#
    );
    OpcPackage::from_parts(vec![
        OpcPart {
            name: opc::CONTENT_TYPES_PART.into(),
            data: types.as_bytes().to_vec(),
        },
        OpcPart {
            name: "word/document.xml".into(),
            data: document.into_bytes(),
        },
        OpcPart {
            name: "word/_rels/document.xml.rels".into(),
            data: rels.into_bytes(),
        },
        OpcPart {
            name: name.into(),
            data: settings.as_bytes().to_vec(),
        },
        OpcPart {
            name: "customXml/unfamiliar.xml".into(),
            data: b"<opaque/>".to_vec(),
        },
    ])
}
fn settings(body: &str) -> String {
    format!(r#"<s:settings xmlns:s="{WORD}" xmlns:u="urn:unknown">{body}</s:settings>"#)
}
fn plan(op: DocxOp) -> DocxPlan {
    DocxPlan::new(
        vec![op],
        RevisionMark::new("Protection fixture", "2026-09-19T00:00:00Z").expect("mark"),
    )
}
fn insert() -> DocxOp {
    DocxOp::InsertText {
        span: DocxSpan::new(1, 0, 0).expect("span"),
        text: "New ".into(),
    }
}

#[test]
fn every_enforced_mode_refuses_every_native_verb_before_output() {
    let range = DocxSpan::new(1, 0, 1).expect("range");
    for mode in ["readOnly", "comments", "trackedChanges", "forms", "none"] {
        for op in [
            insert(),
            DocxOp::DeleteSpan { span: range },
            DocxOp::ReplaceSpan {
                span: range,
                text: "R".into(),
            },
            DocxOp::AddComment {
                span: range,
                body: "Note".into(),
            },
            DocxOp::JoinParagraphs {
                span: DocxSpan::new(1, 6, 6).expect("join"),
            },
        ] {
            let xml = settings(&format!(
                r#"<s:documentProtection s:enforcement="1" s:edit="{mode}"/>"#
            ));
            let bytes = opc::write(&package(&xml, "word/settings.xml"));
            assert!(matches!(
                run_docx_roundtrip(&bytes, &plan(op), "protection"),
                Err(Error::EditFailed(_))
            ));
        }
    }
}

#[test]
fn unlocked_controls_edit_without_changing_unfamiliar_settings() {
    for protection in [
        "",
        r#"<s:documentProtection s:edit="readOnly"/>"#,
        r#"<s:documentProtection s:edit="readOnly" s:enforcement="0"/>"#,
        r#"<s:documentProtection s:enforcement="false"/>"#,
        r#"<s:documentProtection s:enforcement="off"/>"#,
    ] {
        let xml = settings(&format!(
            r#"{protection}<u:unfamiliar u:attribute="preserve"><u:text>opaque</u:text></u:unfamiliar>"#
        ));
        let before = package(&xml, "word/settings.xml");
        let bytes = opc::write(&before);
        let DocxOutcome::Proposed(proposal) =
            run_docx_roundtrip(&bytes, &plan(insert()), "unlocked").expect("editable")
        else {
            panic!("unlocked edit rejected");
        };
        let after = opc::read(&proposal.new_bytes).expect("output");
        assert_eq!(
            after.part("word/settings.xml"),
            before.part("word/settings.xml")
        );
        assert_eq!(
            after.part("customXml/unfamiliar.xml"),
            before.part("customXml/unfamiliar.xml")
        );
        assert!(
            String::from_utf8_lossy(after.part("word/document.xml").expect("document"))
                .contains("New ")
        );
    }
}

#[test]
fn malformed_protection_fails_closed() {
    for body in [
        r#"<s:documentProtection s:enforcement="maybe"/>"#,
        r#"<s:documentProtection enforcement="false"/>"#,
        r#"<s:documentProtection s:edit="invalid"/>"#,
        r#"<s:documentProtection s:enforcement="0" s:enforcement="1"/>"#,
        r#"<s:documentProtection/><s:documentProtection s:enforcement="0"/>"#,
        r#"<s:documentProtection><u:child/></s:documentProtection>"#,
        r#"<u:wrap><s:documentProtection s:enforcement="1"/></u:wrap>"#,
        r#"<u:documentProtection u:enforcement="0"/>"#,
        r#"<s:documentProtection s:enforcement="&unknown;"/>"#,
        r#"<s:documentProtection>not-empty</s:documentProtection>"#,
        r#"<s:documentProtection s:enforcement="0" u:unknown="&#0;"/>"#,
        r#"<s:documentProtection s:enforcement="0" u:unknown="<invalid"/>"#,
        r#"<s:documentProtection s:enforcement="0"/><?xml version="1.0"?>"#,
        r#"<s:documentProtection>"#,
    ] {
        let bytes = opc::write(&package(&settings(body), "word/settings.xml"));
        assert!(
            matches!(
                run_docx_roundtrip(&bytes, &plan(insert()), "malformed"),
                Err(Error::InvalidPackage(_))
            ),
            "{body}"
        );
    }
    for xml in [
        "",
        "<!DOCTYPE settings><settings/>",
        "<settings/>",
        "<a></b>",
        "<a/><a/>",
    ] {
        assert!(matches!(
            inspect_docx_settings(&package(xml, "word/settings.xml")),
            Err(Error::InvalidPackage(_))
        ));
    }
}

#[test]
fn relationship_targets_and_namespace_aliases_do_not_bypass_protection() {
    for ns in [WORD, STRICT_WORD] {
        let xml = format!(
            r#"<s:settings xmlns:s="{ns}" xmlns:p="{ns}"><p:documentProtection p:enforcement="on"/></s:settings>"#
        );
        let pkg = package(&xml, "configuration/options.xml");
        let settings = inspect_docx_settings(&pkg).expect("settings");
        assert_eq!(settings.part.as_deref(), Some("configuration/options.xml"));
        assert!(settings.document_protection.expect("protection").enforced);
        assert!(matches!(
            run_docx_roundtrip(&opc::write(&pkg), &plan(insert()), "renamed"),
            Err(Error::EditFailed(_))
        ));
    }
    let mut missing = package(&settings(""), "configuration/options.xml");
    missing.upsert("word/_rels/document.xml.rels", format!(r#"<Relationships xmlns="{RELS}"><Relationship Type="{SETTINGS_REL}" Target="missing.xml"/></Relationships>"#).into_bytes());
    assert!(matches!(
        inspect_docx_settings(&missing),
        Err(Error::InvalidPackage(_))
    ));
}

#[test]
fn tracking_mode_is_independent_of_existing_revision_marks() {
    for (body, expected) in [
        ("", false),
        ("<s:trackRevisions/>", true),
        (r#"<s:trackRevisions s:val="true"/>"#, true),
        (r#"<s:trackRevisions s:val="false"/>"#, false),
    ] {
        let inspected =
            inspect_docx_settings(&package(&settings(body), "word/settings.xml")).expect("inspect");
        assert_eq!(inspected.track_revisions, expected);
        inspected
            .require_editable()
            .expect("tracking is not protection");
    }
    let inspected = inspect_docx_settings(&package(
        &settings("<s:writeProtection/>"),
        "word/settings.xml",
    ))
    .expect("inspect");
    assert!(matches!(
        inspected.require_editable(),
        Err(Error::EditFailed(_))
    ));
}

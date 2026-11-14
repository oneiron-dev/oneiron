//! Comment-anchor scenarios across the three office locators (owner ask
//! 2026-10-16; the cases come from tdoc's anchor tests, not its matcher): a
//! one-character and a CJK selection, repeated identical text, a selection
//! across markup, a deleted or rewritten sentence, an element that disappears
//! and returns, and anchors on an old version.
//!
//! The DOCX cases that need only public paths run in the integration test
//! `crates/oneiron/tests/anchor_docx_scenarios.rs`: the OF-368 re-anchor
//! cases (one-character and CJK selections, repeated text, a selection across
//! runs), the "never invent an anchor" cases, and a returning paragraph that
//! is offered for a one-click reattach, never bound on a guess. The DOCX case
//! here reads an old thread head through the crate's codec.
//!
//! A DOCX `para_path` here is the docedit block id (`p_1`, `p_2`, ..., the
//! handle the DOCX edit door targets), and characters are Unicode scalar
//! values, as in docedit's own spans.

use super::*;
use crate::claim::ClaimLifecycleStatus;
use crate::edit_roundtrip::pptx::inspect_pptx;
use crate::edit_roundtrip::pptx::tests::support;
use crate::test_util::open_test_vault_with;

const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const PPTX_MIME: &str = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
const SLIDE: &str = "ppt/slides/slide9.xml";

/// A minimal DOCX whose body holds `paragraphs`, each a list of
/// `(text, bold)` runs.
fn docx(paragraphs: &[&[(&str, bool)]]) -> Vec<u8> {
    use std::io::Write;

    let mut body = String::new();
    for runs in paragraphs {
        body.push_str("<w:p>");
        for (text, bold) in *runs {
            let props = if *bold { "<w:rPr><w:b/></w:rPr>" } else { "" };
            body.push_str(&format!(
                r#"<w:r>{props}<w:t xml:space="preserve">{text}</w:t></w:r>"#
            ));
        }
        body.push_str("</w:p>");
    }
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}<w:sectPr/></w:body></w:document>"#
    );
    let parts = [
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#.to_owned(),
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#.to_owned(),
        ),
        (
            "word/_rels/document.xml.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"#.to_owned(),
        ),
        ("word/document.xml", document),
    ];
    let mut out = Vec::new();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
    for (name, data) in parts {
        zip.start_file(name, zip::write::FileOptions::default())
            .unwrap();
        zip.write_all(data.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    drop(zip);
    out
}

/// The text a DOCX locator selects in `bytes`, read through docedit; `None`
/// when the paragraph or the span is not there.
fn docx_span(bytes: &[u8], locator: &Locator) -> Option<String> {
    let Locator::Docx {
        para_path,
        char_start,
        char_end,
    } = locator
    else {
        return None;
    };
    let doc = oneiron_docedit::Document::parse(bytes).expect("fixture parses");
    let block = doc
        .read()
        .blocks
        .into_iter()
        .find(|block| block.id.to_string() == *para_path)?;
    let start = usize::try_from(*char_start).ok()?;
    let len = usize::try_from(char_end - char_start).ok()?;
    let text: String = block.text.chars().skip(start).take(len).collect();
    (text.chars().count() == len).then_some(text)
}

fn docx_at(para_path: &str, char_start: u64, char_end: u64) -> Locator {
    Locator::docx(para_path, char_start, char_end).expect("docx locator")
}

/// An artifact of `mime` holding `v1`, and the human who reviews it.
fn put_artifact(vault: &Vault, name: &str, mime: &str, v1: &[u8]) -> (EntityId, WriteActor) {
    let actor = put_actor(vault, 10);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(name, mime),
            test_time(10),
            10,
        )
        .expect("put artifact");
    assert_eq!(upload(vault, &artifact, actor, v1, 10), 1);
    (artifact, actor)
}

fn upload(vault: &Vault, artifact: &EntityId, actor: WriteActor, bytes: &[u8], at: u64) -> u64 {
    vault
        .append_blob_artifact_version(
            artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(at),
            at,
        )
        .expect("append version")
        .version
}

fn open(
    vault: &Vault,
    artifact: EntityId,
    version: u64,
    locator: &Locator,
    actor: WriteActor,
) -> AnnotationThread {
    vault
        .open_annotation_thread(
            &Anchor::new(artifact, version, locator.clone()),
            actor,
            "Check this.",
            test_time(11),
            11,
        )
        .expect("open thread")
}

fn sweep(
    vault: &Vault,
    artifact: &EntityId,
    from: u64,
    to: u64,
    ops: &[ReanchorOp],
    actor: WriteActor,
) -> ReanchorSummary {
    // After the upload of `to` (at 2 * to + 8), before the next one.
    let at = 2 * to + 9;
    vault
        .reanchor_annotation_threads(artifact, from, to, ops, actor, test_time(at), at)
        .expect("reanchor sweep")
}

fn live(vault: &Vault, artifact: &EntityId, thread: &AnnotationThread) -> AnnotationThread {
    vault
        .get_annotation_thread(artifact, &thread.thread_id)
        .expect("read thread")
        .expect("thread is live")
}

/// The thread reads back visibly unanchored: drifted at `drifted_at`, pinned to
/// `pinned` with `locator` unchanged, still listed and still holding its
/// comment.
fn assert_pinned(
    vault: &Vault,
    artifact: &EntityId,
    thread: &AnnotationThread,
    locator: &Locator,
    pinned: u64,
    drifted_at: u64,
) {
    let now = live(vault, artifact, thread);
    assert_eq!(
        now.drift,
        Some(DriftMarker {
            drifted_at_version: drifted_at,
            pinned_version: pinned,
        })
    );
    assert_eq!(now.anchor.version, pinned);
    assert_eq!(&now.anchor.locator, locator);
    assert_eq!(now.origin_version, thread.origin_version);
    let listed = vault
        .annotation_threads_for_artifact(artifact)
        .expect("list threads");
    assert!(
        listed
            .iter()
            .any(|t| t.thread_id == thread.thread_id && t.is_drifted())
    );
    let comments = vault
        .annotation_thread_comments(artifact, &thread.thread_id)
        .expect("comments");
    assert_eq!(comments.len(), 1);
}

/// The thread re-anchored onto `version` at `locator`, with no drift.
fn assert_mapped(
    vault: &Vault,
    artifact: &EntityId,
    thread: &AnnotationThread,
    version: u64,
    locator: &Locator,
) {
    let now = live(vault, artifact, thread);
    assert_eq!(now.drift, None);
    assert_eq!(now.anchor.version, version);
    assert_eq!(&now.anchor.locator, locator);
}

/// The head a thread was opened with, decoded from its claim after later
/// sweeps superseded it.
fn old_head(vault: &Vault, thread: &AnnotationThread) -> (ThreadHead, ClaimLifecycleStatus) {
    let claim = vault
        .get_claim(&thread.head_claim_id)
        .expect("read claim")
        .expect("old head claim kept");
    (
        decode_thread_head(&claim.value).expect("old head decodes"),
        claim.lifecycle,
    )
}

// ---------------------------------------------------------------------------
// 1. A one-character and a CJK selection
// ---------------------------------------------------------------------------

#[test]
fn xlsx_single_cell_on_a_cjk_sheet_follows_only_its_own_sheet() {
    let cell = Locator::xlsx("売上", "C3").unwrap();
    // Sheets whose names share a prefix with the anchor's are other sheets.
    let elsewhere = [
        ReanchorOp::InsertRows {
            sheet: "売上高".to_owned(),
            at_row: 1,
            count: 5,
        },
        ReanchorOp::DeleteRows {
            sheet: "売".to_owned(),
            at_row: 3,
            count: 1,
        },
    ];
    assert_eq!(
        replay_locator(&cell, &elsewhere),
        ReanchorOutcome::Mapped(cell.clone())
    );
    let insert_above = [ReanchorOp::InsertRows {
        sheet: "売上".to_owned(),
        at_row: 2,
        count: 1,
    }];
    assert_eq!(
        replay_locator(&cell, &insert_above),
        ReanchorOutcome::Mapped(Locator::xlsx("売上", "C4").unwrap())
    );
    // Deleting its row destroys the one cell; no neighbour takes its place.
    let delete_row = [ReanchorOp::DeleteRows {
        sheet: "売上".to_owned(),
        at_row: 3,
        count: 1,
    }];
    assert_eq!(replay_locator(&cell, &delete_row), ReanchorOutcome::Drifted);
}

// ---------------------------------------------------------------------------
// 2. Repeated identical text
// ---------------------------------------------------------------------------

#[test]
fn pptx_duplicated_shape_never_rebinds_to_either_copy() {
    let mut v2 = support::parts(false);
    let slide = String::from_utf8(v2[SLIDE].clone()).unwrap();
    let start = slide.find("<p:sp>").unwrap();
    let end = slide.find("</p:sp>").unwrap() + "</p:sp>".len();
    // A pasted copy: same text, same creation GUID, a new native id.
    let copy = slide[start..end].replace(r#"id="2""#, r#"id="3""#);
    support::with_text(&mut v2, SLIDE, "</p:spTree>", &format!("{copy}</p:spTree>"));
    let v2 = support::bytes(&v2);
    let copies = inspect_pptx(&v2).unwrap().slides[0]
        .shapes
        .iter()
        .filter(|shape| shape.creation_id.as_deref() == Some(support::SHAPE))
        .count();
    assert_eq!(copies, 2);

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let v1 = support::bytes(&support::parts(false));
    let (artifact, actor) = put_artifact(&vault, "deck.pptx", PPTX_MIME, &v1);
    let shape = Locator::pptx(1, support::SHAPE).unwrap();
    let thread = open(&vault, artifact, 1, &shape, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.remapped.is_empty());
    assert_pinned(&vault, &artifact, &thread, &shape, 1, 2);
}

// ---------------------------------------------------------------------------
// 4. A sentence that is deleted or rewritten
// ---------------------------------------------------------------------------

#[test]
fn pptx_rewritten_shape_text_drifts_a_shape_thread() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut parts = support::parts(false);
    let (artifact, actor) = put_artifact(&vault, "deck.pptx", PPTX_MIME, &support::bytes(&parts));
    let shape = Locator::pptx(1, support::SHAPE).unwrap();
    let thread = open(&vault, artifact, 1, &shape, actor);
    // An unrelated part changes first: the shape thread follows, so the drift
    // below comes from the rewrite alone.
    parts.insert(
        "customXml/unreachable.xml".into(),
        b"changed unrelated data".to_vec(),
    );
    upload(&vault, &artifact, actor, &support::bytes(&parts), 12);
    assert_eq!(sweep(&vault, &artifact, 1, 2, &[], actor).remapped.len(), 1);
    assert_mapped(&vault, &artifact, &thread, 2, &shape);

    support::with_text(&mut parts, SLIDE, "Original text", "Rewritten text");
    upload(&vault, &artifact, actor, &support::bytes(&parts), 14);
    let summary = sweep(&vault, &artifact, 2, 3, &[], actor);
    assert!(summary.remapped.is_empty());
    assert_pinned(&vault, &artifact, &thread, &shape, 2, 3);
}

// ---------------------------------------------------------------------------
// 5. An element that disappears and later returns
// ---------------------------------------------------------------------------

#[test]
fn xlsx_removed_sheet_that_returns_by_name_never_rebinds_a_lost_anchor() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    let cell = Locator::xlsx("Q3", "B2").unwrap();
    let thread = open(&vault, artifact, 1, &cell, actor);
    upload(&vault, &artifact, actor, b"workbook bytes v2", 12);
    let removed = [ReanchorOp::RemoveSheet {
        sheet: "Q3".to_owned(),
    }];
    assert_eq!(
        sweep(&vault, &artifact, 1, 2, &removed, actor)
            .drifted
            .len(),
        1
    );
    assert_pinned(&vault, &artifact, &thread, &cell, 1, 2);
    let lost_head = live(&vault, &artifact, &thread).head_claim_id;

    // A sheet named Q3 is back in v3 and gets edited. The 1 -> 3 manifest names
    // the removal too; the lost thread sits on version 1, so only its drift
    // keeps it out of this sweep.
    upload(&vault, &artifact, actor, b"workbook bytes v3", 14);
    let edited = [
        ReanchorOp::RemoveSheet {
            sheet: "Q3".to_owned(),
        },
        ReanchorOp::InsertRows {
            sheet: "Q3".to_owned(),
            at_row: 1,
            count: 1,
        },
    ];
    let summary = sweep(&vault, &artifact, 1, 3, &edited, actor);
    assert!(summary.remapped.is_empty());
    assert!(summary.drifted.is_empty());
    assert_pinned(&vault, &artifact, &thread, &cell, 1, 2);
    assert_eq!(live(&vault, &artifact, &thread).head_claim_id, lost_head);
}

#[test]
fn pptx_removed_shape_that_returns_under_its_old_native_id_never_rebinds() {
    let v1 = support::parts(false);
    let slide = String::from_utf8(v1[SLIDE].clone()).unwrap();
    let start = slide.find("<p:sp>").unwrap();
    let end = slide.find("</p:sp>").unwrap() + "</p:sp>".len();
    let mut v2 = v1.clone();
    support::with_text(&mut v2, SLIDE, &slide[start..end], "");
    // The same name, text and native id 2 come back on a new shape.
    let mut v3 = v1.clone();
    support::with_text(
        &mut v3,
        SLIDE,
        support::SHAPE,
        "{22222222-3333-4444-8555-666666666666}",
    );
    let (v1, v2, v3) = (
        support::bytes(&v1),
        support::bytes(&v2),
        support::bytes(&v3),
    );
    let shapes = |bytes: &[u8]| inspect_pptx(bytes).unwrap().slides[0].shapes.clone();
    assert!(
        !shapes(&v2).iter().any(
            |shape| shape.shape_id == 2 || shape.creation_id.as_deref() == Some(support::SHAPE)
        )
    );
    let returned: Vec<_> = shapes(&v3)
        .into_iter()
        .filter(|shape| shape.shape_id == 2)
        .collect();
    assert_eq!(returned.len(), 1);
    assert_ne!(returned[0].creation_id.as_deref(), Some(support::SHAPE));

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "deck.pptx", PPTX_MIME, &v1);
    let native = Locator::pptx(1, "2").unwrap();
    let thread = open(&vault, artifact, 1, &native, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    assert_eq!(sweep(&vault, &artifact, 1, 2, &[], actor).drifted.len(), 1);
    assert_pinned(&vault, &artifact, &thread, &native, 1, 2);
    let lost_head = live(&vault, &artifact, &thread).head_claim_id;

    // A thread opened on v1 now is still live, so the 1 -> 3 sweep shows it the
    // new shape under native id 2; the lost thread it must pass over.
    let late = open(&vault, artifact, 1, &native, actor);
    upload(&vault, &artifact, actor, &v3, 14);
    let summary = sweep(&vault, &artifact, 1, 3, &[], actor);
    assert!(summary.remapped.is_empty());
    assert_eq!(summary.drifted.len(), 1);
    assert_eq!(summary.drifted[0].thread_id, late.thread_id);
    assert_pinned(&vault, &artifact, &late, &native, 1, 3);
    assert_pinned(&vault, &artifact, &thread, &native, 1, 2);
    assert_eq!(live(&vault, &artifact, &thread).head_claim_id, lost_head);
}

// ---------------------------------------------------------------------------
// 6. Anchors on an old version stay intact
// ---------------------------------------------------------------------------

#[test]
fn docx_old_version_bytes_heads_and_late_anchors_stay_intact() {
    let v1 = docx(&[&[("Draft one.", false)]]);
    let v2 = docx(&[&[("Draft two.", false)]]);
    let v3 = docx(&[&[("Draft three.", false)]]);
    let word = docx_at("p_1", 0, 5);
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let early = open(&vault, artifact, 1, &word, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    sweep(&vault, &artifact, 1, 2, &[], actor);

    // Whatever the sweep did to the live head, the version-1 record is as it
    // was written.
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 1).unwrap(),
        Some(v1.clone())
    );
    let (head, lifecycle) = old_head(&vault, &early);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(head.anchor_version, 1);
    assert_eq!(head.locator, word);
    assert_eq!(head.drift, None);

    // A thread opened on version 1 after version 2 exists stays on version 1
    // through a later sweep.
    let late = open(&vault, artifact, 1, &word, actor);
    upload(&vault, &artifact, actor, &v3, 14);
    sweep(&vault, &artifact, 2, 3, &[], actor);
    let now = live(&vault, &artifact, &late);
    assert_eq!(now.head_claim_id, late.head_claim_id);
    assert_eq!(now.anchor, late.anchor);
    assert_eq!(now.drift, None);
    assert_eq!(
        docx_span(&v1, &now.anchor.locator).as_deref(),
        Some("Draft")
    );
}

#[test]
fn xlsx_remapped_anchor_keeps_its_old_version_record() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    let b2 = Locator::xlsx("Sheet1", "B2").unwrap();
    let early = open(&vault, artifact, 1, &b2, actor);
    upload(&vault, &artifact, actor, b"workbook bytes v2", 12);
    let two_rows = [ReanchorOp::InsertRows {
        sheet: "Sheet1".to_owned(),
        at_row: 1,
        count: 2,
    }];
    assert_eq!(
        sweep(&vault, &artifact, 1, 2, &two_rows, actor)
            .remapped
            .len(),
        1
    );
    assert_mapped(
        &vault,
        &artifact,
        &early,
        2,
        &Locator::xlsx("Sheet1", "B4").unwrap(),
    );

    // The live head moved; the version-1 head and bytes did not.
    let (head, lifecycle) = old_head(&vault, &early);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(head.anchor_version, 1);
    assert_eq!(head.locator, b2);
    assert_eq!(head.drift, None);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 1).unwrap(),
        Some(b"workbook bytes v1".to_vec())
    );

    // A thread opened on version 1 now is not moved by the 2 -> 3 sweep that
    // moves the first thread again.
    let late = open(&vault, artifact, 1, &b2, actor);
    upload(&vault, &artifact, actor, b"workbook bytes v3", 14);
    let one_row = [ReanchorOp::InsertRows {
        sheet: "Sheet1".to_owned(),
        at_row: 1,
        count: 1,
    }];
    assert_eq!(
        sweep(&vault, &artifact, 2, 3, &one_row, actor)
            .remapped
            .len(),
        1
    );
    assert_mapped(
        &vault,
        &artifact,
        &early,
        3,
        &Locator::xlsx("Sheet1", "B5").unwrap(),
    );
    let now = live(&vault, &artifact, &late);
    assert_eq!(now.head_claim_id, late.head_claim_id);
    assert_eq!(now.anchor, late.anchor);
    assert_eq!(now.drift, None);
}

#[test]
fn pptx_numeric_locator_history_survives_its_rebind_to_the_guid() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut parts = support::parts(false);
    let v1 = support::bytes(&parts);
    let (artifact, actor) = put_artifact(&vault, "deck.pptx", PPTX_MIME, &v1);
    let native = Locator::pptx(1, "2").unwrap();
    let thread = open(&vault, artifact, 1, &native, actor);
    parts.insert(
        "customXml/unreachable.xml".into(),
        b"changed unrelated data".to_vec(),
    );
    upload(&vault, &artifact, actor, &support::bytes(&parts), 12);
    assert_eq!(sweep(&vault, &artifact, 1, 2, &[], actor).remapped.len(), 1);
    // The live head names the shape by its creation GUID from now on...
    assert_mapped(
        &vault,
        &artifact,
        &thread,
        2,
        &Locator::pptx(1, support::SHAPE).unwrap(),
    );
    // ...and the version-1 head still holds the native id it was opened with.
    let (head, lifecycle) = old_head(&vault, &thread);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(head.anchor_version, 1);
    assert_eq!(head.locator, native);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 1).unwrap(),
        Some(v1)
    );
}

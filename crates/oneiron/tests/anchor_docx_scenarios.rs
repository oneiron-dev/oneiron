//! Word comment-anchor scenarios across a version bump (owner ask 2026-10-16;
//! OF-368, owner ruling 2026-10-17): a one-character and a CJK selection,
//! repeated identical text, a selection across markup, a deleted or rewritten
//! sentence, and a paragraph that disappears and returns.
//!
//! Moved from the lib module `anchored_annotation/tests/anchor_scenarios.rs`,
//! whose test target does not compile, so none of these ran. Two kinds of case:
//! - re-anchor cases: the selected words survive the edit, and the thread
//!   moves with them onto the new version; a small edit inside the selection
//!   (a typo fix, one word swapped, a partial delete, an insert) keeps it;
//! - "never invent an anchor" cases: the selected words are gone, but
//!   something a weaker matcher would take for them is still there (the same
//!   offsets, an identical copy, the same run layout, the same paragraph
//!   slot, letters a rewrite happens to share); the thread stays visibly
//!   drifted on its old version. Survival is judged by words, not letters
//!   (ruling L4-19-REWRITTEN-SPAN-SURVIVAL = A, 14 Nov 00:01).
//!
//! A lost anchor reattaches only by exact identity (undo or a restore) or a
//! person's click on an offer of the exact words (OF-368 = A); the engine
//! never reattaches on a guess, so a paragraph that returns in a new upload
//! is offered, not bound.
//!
//! A `para_path` is the docedit block id (`p_1`, `p_2`, ...), and characters
//! are Unicode scalar values, as in docedit's own spans.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test anchor_docx_scenarios`.
#![cfg(oneiron_test_support)]

use std::io::Write as _;

use oneiron::anchored_annotation::{
    Anchor, AnnotationThread, DriftMarker, Locator, ReanchorOp, ReanchorSummary,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::SecretSight;
use oneiron::test_doors::untangle_regressions::{embedding_test_config, open_test_vault_with};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};

const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A minimal DOCX whose body holds `paragraphs`, each a list of
/// `(text, bold)` runs.
fn docx(paragraphs: &[&[(&str, bool)]]) -> Vec<u8> {
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

/// The human who reviews the artifact.
fn put_actor(vault: &Vault, at: u64) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
        .expect("put actor");
    WriteActor::new(actor_id, EdgeActorClass::Human)
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

// ---------------------------------------------------------------------------
// 1. A one-character and a CJK selection
// ---------------------------------------------------------------------------

#[test]
fn docx_one_char_and_cjk_selections_drift_when_their_text_is_replaced() {
    let v1 = docx(&[&[("Hello world", false)], &[("東京は晴れ", false)]]);
    // Same lengths, so the old offsets now select "t" and "大阪".
    let v2 = docx(&[&[("Hello there", false)], &[("大阪は晴れ", false)]]);
    let one = docx_at("p_1", 6, 7);
    let cjk = docx_at("p_2", 0, 2);
    assert_eq!(docx_span(&v1, &one).as_deref(), Some("w"));
    assert_eq!(docx_span(&v1, &cjk).as_deref(), Some("東京"));
    assert_eq!(docx_span(&v2, &one).as_deref(), Some("t"));
    assert_eq!(docx_span(&v2, &cjk).as_deref(), Some("大阪"));

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let threads = [
        open(&vault, artifact, 1, &one, actor),
        open(&vault, artifact, 1, &cjk, actor),
    ];
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    assert_eq!(summary.drifted.len(), 2);
    for thread in &threads {
        assert_pinned(&vault, &artifact, thread, &thread.anchor.locator, 1, 2);
    }
    // The pinned version still holds both selections.
    let pinned = vault
        .read_blob_artifact_version(&artifact, 1)
        .unwrap()
        .unwrap();
    assert_eq!(docx_span(&pinned, &one).as_deref(), Some("w"));
    assert_eq!(docx_span(&pinned, &cjk).as_deref(), Some("東京"));
}

#[test]
fn docx_one_char_and_cjk_selections_follow_an_insert_before_them() {
    let v1 = docx(&[&[("Hello world", false)], &[("東京は晴れ", false)]]);
    let v2 = docx(&[
        &[("Oh, Hello world", false)],
        &[("今日、東京は晴れ", false)],
    ]);
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let one = open(&vault, artifact, 1, &docx_at("p_1", 6, 7), actor);
    let cjk = open(&vault, artifact, 1, &docx_at("p_2", 0, 2), actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.drifted.is_empty(), "{summary:?}");
    assert_eq!(summary.remapped.len(), 2);

    let moved_one = docx_at("p_1", 10, 11);
    let moved_cjk = docx_at("p_2", 3, 5);
    assert_mapped(&vault, &artifact, &one, 2, &moved_one);
    assert_mapped(&vault, &artifact, &cjk, 2, &moved_cjk);
    assert_eq!(docx_span(&v2, &moved_one).as_deref(), Some("w"));
    assert_eq!(docx_span(&v2, &moved_cjk).as_deref(), Some("東京"));
}

// ---------------------------------------------------------------------------
// 2. Repeated identical text
// ---------------------------------------------------------------------------

#[test]
fn docx_repeated_text_anchor_never_jumps_to_the_surviving_copy() {
    let v1 = docx(&[&[("the cat and the dog", false)]]);
    // The second "the" goes; the first stays where it was.
    let v2 = docx(&[&[("the cat and a dog", false)]]);
    let second = docx_at("p_1", 12, 15);
    let first = docx_at("p_1", 0, 3);
    assert_eq!(docx_span(&v1, &second).as_deref(), Some("the"));
    assert_eq!(docx_span(&v2, &first).as_deref(), Some("the"));

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let thread = open(&vault, artifact, 1, &second, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    assert_pinned(&vault, &artifact, &thread, &second, 1, 2);
}

#[test]
fn docx_repeated_text_anchors_keep_their_own_occurrence() {
    let v1 = docx(&[&[("the cat and the dog", false)]]);
    let v2 = docx(&[&[("So the cat and the dog", false)]]);
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let first = open(&vault, artifact, 1, &docx_at("p_1", 0, 3), actor);
    let second = open(&vault, artifact, 1, &docx_at("p_1", 12, 15), actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.drifted.is_empty(), "{summary:?}");

    // Both copies read "the" in v2; each thread keeps the one it was on.
    let moved_first = docx_at("p_1", 3, 6);
    let moved_second = docx_at("p_1", 15, 18);
    assert_eq!(docx_span(&v2, &moved_first).as_deref(), Some("the"));
    assert_eq!(docx_span(&v2, &moved_second).as_deref(), Some("the"));
    assert_mapped(&vault, &artifact, &first, 2, &moved_first);
    assert_mapped(&vault, &artifact, &second, 2, &moved_second);
}

// ---------------------------------------------------------------------------
// 3. A selection that crosses markup
// ---------------------------------------------------------------------------

#[test]
fn docx_selection_across_runs_drifts_when_the_same_run_layout_holds_other_text() {
    let v1 = docx(&[&[("Plain ", false), ("bold", true), (" tail", false)]]);
    // Same run lengths and the same bold run, all of it new text.
    let v2 = docx(&[&[("Fresh ", false), ("copy", true), (" here", false)]]);
    let across = docx_at("p_1", 4, 12);
    assert_eq!(docx_span(&v1, &across).as_deref(), Some("n bold t"));
    assert_eq!(docx_span(&v2, &across).as_deref(), Some("h copy h"));

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let thread = open(&vault, artifact, 1, &across, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    assert_pinned(&vault, &artifact, &thread, &across, 1, 2);
}

#[test]
fn docx_selection_across_runs_survives_a_markup_only_change() {
    let v1 = docx(&[&[("Plain ", false), ("bold", true), (" tail", false)]]);
    // The bold goes and the three runs merge; the text is the same.
    let v2 = docx(&[&[("Plain bold tail", false)]]);
    let across = docx_at("p_1", 4, 12);
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let thread = open(&vault, artifact, 1, &across, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.drifted.is_empty(), "{summary:?}");
    assert_mapped(&vault, &artifact, &thread, 2, &across);
    assert_eq!(docx_span(&v2, &across).as_deref(), Some("n bold t"));
}

// ---------------------------------------------------------------------------
// 4. A sentence that is deleted or rewritten
// ---------------------------------------------------------------------------

#[test]
fn docx_deleted_and_rewritten_sentences_stay_visibly_unanchored() {
    let v1 = docx(&[
        &[("Keep this. Rewrite this one.", false)],
        &[("Keep that. Delete this one.", false)],
    ]);
    let v2 = docx(&[
        &[("Keep this. Something else now.", false)],
        &[("Keep that.", false)],
    ]);
    let rewritten = docx_at("p_1", 11, 28);
    let deleted = docx_at("p_2", 11, 27);
    assert_eq!(
        docx_span(&v1, &rewritten).as_deref(),
        Some("Rewrite this one.")
    );
    assert_eq!(
        docx_span(&v1, &deleted).as_deref(),
        Some("Delete this one.")
    );

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let threads = [
        open(&vault, artifact, 1, &rewritten, actor),
        open(&vault, artifact, 1, &deleted, actor),
    ];
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    for thread in &threads {
        assert_pinned(&vault, &artifact, thread, &thread.anchor.locator, 1, 2);
    }
}

/// The other side of the line above (OF-368 = A, "on small changes you
/// should keep the spot"): a typo fix, one word swapped, a partial delete,
/// an insert inside the selection, and two words replaced by one (one
/// replaced, one deleted) all keep the anchor.
#[test]
fn docx_small_edits_inside_a_selection_keep_its_spot() {
    let v1 = docx(&[
        &[("We recieve the goods.", false)],
        &[("the red fox ran home", false)],
        &[("the quick brown fox jumps", false)],
        &[("the fox ran", false)],
        &[("Keep red blue.", false)],
    ]);
    let v2 = docx(&[
        &[("We receive the goods.", false)],
        &[("the blue fox ran home", false)],
        &[("the fox jumps", false)],
        &[("the quick brown fox ran", false)],
        &[("Keep gold.", false)],
    ]);
    let cases = [
        (
            docx_at("p_1", 3, 10),
            "recieve",
            docx_at("p_1", 3, 10),
            "receive",
        ),
        (
            docx_at("p_2", 0, 15),
            "the red fox ran",
            docx_at("p_2", 0, 16),
            "the blue fox ran",
        ),
        (
            docx_at("p_3", 0, 19),
            "the quick brown fox",
            docx_at("p_3", 0, 7),
            "the fox",
        ),
        (
            docx_at("p_4", 0, 7),
            "the fox",
            docx_at("p_4", 0, 19),
            "the quick brown fox",
        ),
        (
            docx_at("p_5", 0, 14),
            "Keep red blue.",
            docx_at("p_5", 0, 10),
            "Keep gold.",
        ),
    ];
    for (was, was_text, now, now_text) in &cases {
        assert_eq!(docx_span(&v1, was).as_deref(), Some(*was_text));
        assert_eq!(docx_span(&v2, now).as_deref(), Some(*now_text));
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let threads: Vec<AnnotationThread> = cases
        .iter()
        .map(|(was, ..)| open(&vault, artifact, 1, was, actor))
        .collect();
    upload(&vault, &artifact, actor, &v2, 12);
    let summary = sweep(&vault, &artifact, 1, 2, &[], actor);
    assert!(summary.drifted.is_empty(), "{summary:?}");
    assert_eq!(summary.remapped.len(), cases.len());
    for (thread, (_, _, now, _)) in threads.iter().zip(&cases) {
        assert_mapped(&vault, &artifact, thread, 2, now);
    }
}

// ---------------------------------------------------------------------------
// 5. A paragraph that disappears and later returns
// ---------------------------------------------------------------------------

#[test]
fn docx_paragraph_slot_taken_by_other_text_never_rebinds_a_lost_anchor() {
    let v1 = docx(&[&[("Intro.", false)], &[("Budget: 40k.", false)]]);
    let v2 = docx(&[&[("Intro.", false)]]);
    // A different paragraph arrives in the old slot, the same length.
    let v3 = docx(&[&[("Intro.", false)], &[("Timeline: Q3", false)]]);
    let budget = docx_at("p_2", 0, 12);
    assert_eq!(docx_span(&v1, &budget).as_deref(), Some("Budget: 40k."));
    assert_eq!(docx_span(&v2, &budget), None);
    assert_eq!(docx_span(&v3, &budget).as_deref(), Some("Timeline: Q3"));

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let thread = open(&vault, artifact, 1, &budget, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    assert_eq!(sweep(&vault, &artifact, 1, 2, &[], actor).drifted.len(), 1);
    assert_pinned(&vault, &artifact, &thread, &budget, 1, 2);
    let lost_head = live(&vault, &artifact, &thread).head_claim_id;

    // A thread opened on v1 now is still live, so the 1 -> 3 sweep shows it the
    // other paragraph in the old slot; the lost thread it must pass over.
    let late = open(&vault, artifact, 1, &budget, actor);
    upload(&vault, &artifact, actor, &v3, 14);
    let summary = sweep(&vault, &artifact, 1, 3, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    assert_eq!(summary.drifted.len(), 1);
    assert_eq!(summary.drifted[0].thread_id, late.thread_id);
    assert_pinned(&vault, &artifact, &late, &budget, 1, 3);
    // Still lost, and no new head per bump while it stays lost.
    assert_pinned(&vault, &artifact, &thread, &budget, 1, 2);
    assert_eq!(live(&vault, &artifact, &thread).head_claim_id, lost_head);
}

/// OF-368 = A: the paragraph's exact words return in a new upload (not a
/// restore: a third paragraph makes the bytes differ from v1). The sweep
/// leaves the thread unattached; the reattach list offers the one exact place,
/// and a person's click on that offer binds it.
#[test]
fn docx_returning_paragraph_is_offered_and_rebinds_only_on_a_click() {
    let v1 = docx(&[&[("Intro.", false)], &[("Budget: 40k.", false)]]);
    let v2 = docx(&[&[("Intro.", false)]]);
    let v3 = docx(&[
        &[("Intro.", false)],
        &[("Budget: 40k.", false)],
        &[("Notes.", false)],
    ]);
    let budget = docx_at("p_2", 0, 12);
    assert_eq!(docx_span(&v3, &budget).as_deref(), Some("Budget: 40k."));
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (artifact, actor) = put_artifact(&vault, "notes.docx", DOCX_MIME, &v1);
    let thread = open(&vault, artifact, 1, &budget, actor);
    upload(&vault, &artifact, actor, &v2, 12);
    sweep(&vault, &artifact, 1, 2, &[], actor);
    assert_pinned(&vault, &artifact, &thread, &budget, 1, 2);
    let unattached = vault
        .unattached_annotation_threads(&artifact)
        .expect("unattached list");
    assert_eq!(unattached.len(), 1);
    assert_eq!(unattached[0].thread.thread_id, thread.thread_id);
    assert_eq!(unattached[0].snapshot.as_deref(), Some("Budget: 40k."));
    assert_eq!(unattached[0].detached_at_version, 2);

    assert_eq!(upload(&vault, &artifact, actor, &v3, 14), 3);
    let summary = sweep(&vault, &artifact, 2, 3, &[], actor);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    // No guess: the words are back, the thread is still where it was.
    assert_pinned(&vault, &artifact, &thread, &budget, 1, 2);

    let offers = vault
        .annotation_reattach_offers(&artifact)
        .expect("reattach offers");
    assert_eq!(offers.len(), 1, "{offers:?}");
    assert_eq!(offers[0].thread_id, thread.thread_id);
    assert_eq!(offers[0].version, 3);
    assert_eq!(offers[0].locator, budget);

    let bound = vault
        .reattach_annotation_thread(
            &artifact,
            &thread.thread_id,
            offers[0].version,
            &offers[0].locator,
            SecretSight::Owner,
            actor,
            test_time(16),
            16,
        )
        .expect("one-click reattach");
    assert_eq!(bound.drift, None);
    assert_mapped(&vault, &artifact, &thread, 3, &budget);
    assert!(
        vault
            .unattached_annotation_threads(&artifact)
            .expect("unattached list")
            .is_empty()
    );
}

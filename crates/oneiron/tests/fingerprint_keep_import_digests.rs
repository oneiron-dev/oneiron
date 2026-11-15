//! K-proof (oracle) for PLAN-UC-04 stage 6.2b: four import digests keep their bytes.
//!
//! A claim import batch's content hash (`purposes::ingest::CLAIM_IMPORT_CONTENT`), a note
//! import batch's (`purposes::note::IMPORT_CONTENT`, with each note's Markdown hash now
//! `ContentHash::of`) and a history message's hash (`purposes::ingest::HISTORY_MESSAGE`) now
//! start through the fingerprint crate's K door, and a blob version's hash is
//! `ContentHash::of`. The owner's approval of an import batch and the batch's decision slot
//! bind its content hash, and the vault stores and compares both; the ingest ledger stores a
//! message's hash and a re-import compares it; a blob version's hash is stored in its version
//! rows and compared on export and append. So each must give main's bytes for every input.
//! The `base_*` modules hold main's lines at 709cd244c3eb, copied by range (each range is named
//! above its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are the
//! imports main's lines name and, for the blob hash, a one-variant stand-in of main's private
//! `VersionBody` around the copied match arm.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_import_digests`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::TimeRange;
use oneiron::ingest::history::{HistoryMessage, HistoryRole};
use oneiron::ingest::{ImportedClaimBatch, ImportedClaimBatchEntry};
use oneiron::note::{
    FileFacts, ImportedNote, ImportedNoteBatch, ImportedNoteLink, NameOnlyFile, NameOnlyReason,
    OriginalBytes,
};
use oneiron::test_doors::fingerprint_keep_import_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use serde_json::{Value, json};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_claim {
    use oneiron::ingest::ImportedClaimBatch;
    use oneiron::{Error, Result};

    // main 709cd244c3eb: crates/oneiron/src/ingest/bulk_review.rs:243-265
    /// The batch's claims, hashed: every member, subject, value and time.
    fn content_hash(batch: &ImportedClaimBatch) -> Result<blake3::Hash> {
        let content = serde_json::to_vec(
            &batch
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.claim_id.to_hex(),
                        entry.subject.to_hex(),
                        &entry.source_record_id,
                        &entry.predicate,
                        &entry.value,
                        entry.occurred.start,
                        entry.occurred.end,
                        entry.learned_at,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::InvalidClaimBody("import batch encoding failed"))?;
        Ok(blake3::hash(&content))
    }

    /// Main's content hash, which is private there.
    pub(crate) fn main_claim_import_content_hash(batch: &ImportedClaimBatch) -> [u8; 32] {
        *content_hash(batch).expect("the batch encodes").as_bytes()
    }
}

#[rustfmt::skip]
mod base_note {
    use oneiron::note::ImportedNoteBatch;
    use oneiron::{Error, Result};

    // main 709cd244c3eb: crates/oneiron/src/note/import.rs:663-703
    /// Every note, link and name-only file of the batch, hashed.
    fn content_hash(batch: &ImportedNoteBatch) -> Result<blake3::Hash> {
        let notes = batch
            .notes
            .iter()
            .map(|note| {
                (
                    &note.path,
                    &note.kind,
                    &note.title,
                    note.written_at,
                    blake3::hash(note.markdown.as_bytes()).to_hex().to_string(),
                    note.original
                        .as_ref()
                        .map(|original| (original.media_type.as_str(), original.content_hash())),
                )
            })
            .collect::<Vec<_>>();
        let links = batch
            .links
            .iter()
            .map(|link| (&link.from, &link.to))
            .collect::<Vec<_>>();
        let name_only = batch
            .name_only
            .iter()
            .map(|file| {
                (
                    &file.path,
                    file.why,
                    file.facts,
                    file.original
                        .as_ref()
                        .map(|original| (original.media_type.as_str(), original.content_hash())),
                )
            })
            .collect::<Vec<_>>();
        let content = serde_json::to_vec(&(&batch.folder, notes, links, name_only))
            .map_err(|_| Error::InvalidClaimBody("note import batch encoding failed"))?;
        Ok(blake3::hash(&content))
    }

    /// Main's content hash, which is private there.
    pub(crate) fn main_note_import_content_hash(batch: &ImportedNoteBatch) -> [u8; 32] {
        *content_hash(batch).expect("the batch encodes").as_bytes()
    }
}

#[rustfmt::skip]
mod base_ledger {
    use oneiron::ingest::history::{HistoryMessage, HistoryRole};

    /// Main's hash, which is private there.
    pub(crate) fn main_history_message_hash(message: &HistoryMessage, unknown_speaker: bool) -> String {
        hash(message, unknown_speaker)
    }

    // main 709cd244c3eb: crates/oneiron/src/ingest/history/ledger.rs:156-167
    fn hash(message: &HistoryMessage, unknown_speaker: bool) -> String {
        let mut hasher = blake3::Hasher::new();
        if unknown_speaker {
            hasher.update(b"unknown\0");
        }
        hasher.update(match message.role {
            HistoryRole::User => b"user\0",
            HistoryRole::Assistant => b"asst\0",
        });
        hasher.update(message.text.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

#[rustfmt::skip]
mod base_blob {
    /// A stand-in for main's private `VersionBody`, with its in-memory variant only.
    pub(crate) enum VersionBody<'b> {
        Bytes(&'b [u8]),
    }

    impl VersionBody<'_> {
        /// Main's arm for a body held in memory.
        pub(crate) fn content_hash(self) -> [u8; 32] {
            match self {
                // main 709cd244c3eb: crates/oneiron/src/blob_artifact/versions.rs:65-65
                            Self::Bytes(bytes) => *blake3::hash(bytes).as_bytes(),
            }
        }
    }
}

fn id(n: u8) -> EntityId {
    EntityId::from_hex(&format!("{n:02x}{}", "ab".repeat(15))).expect("a valid id")
}

fn values() -> Vec<Value> {
    vec![
        Value::Null,
        json!(1),
        json!(-2.5),
        json!("words with \"quotes\", ünïcode and a \u{0} byte"),
        json!({"b": 1, "a": [true, null, {"nested": "x"}]}),
        json!([]),
    ]
}

fn claim_batches() -> Vec<ImportedClaimBatch> {
    let mut out = Vec::new();
    for (source, request) in [("source.alpha", 1_u8), ("", 2), ("ソース", 3)] {
        for count in 0..=3_usize {
            for (at, value) in values().into_iter().enumerate() {
                let entries = (0..count)
                    .map(|n| ImportedClaimBatchEntry {
                        claim_id: id(0x10 + u8::try_from(n).expect("small")),
                        subject: id(0x20 + u8::try_from(at).expect("small")),
                        source_record_id: format!("record-{n}"),
                        predicate: if n % 2 == 0 {
                            "likes".into()
                        } else {
                            String::new()
                        },
                        value: value.clone(),
                        occurred: TimeRange {
                            start: u64::try_from(n).expect("small"),
                            end: u64::MAX - u64::try_from(at).expect("small"),
                        },
                        learned_at: 1_700_000_000 + u64::try_from(n * 7).expect("small"),
                    })
                    .collect();
                out.push(ImportedClaimBatch {
                    request_id: id(request),
                    source_id: source.into(),
                    entries,
                });
            }
        }
    }
    out
}

fn original(n: usize) -> Option<OriginalBytes> {
    match n % 3 {
        0 => None,
        1 => Some(OriginalBytes {
            media_type: "application/pdf".into(),
            bytes: vec![0, 1, 2, 255],
        }),
        _ => Some(OriginalBytes {
            media_type: "image/png".into(),
            bytes: Vec::new(),
        }),
    }
}

fn note_batches() -> Vec<ImportedNoteBatch> {
    let markdowns = [
        "",
        "# Title\n\nBody.\n",
        "ünïcode — 日本語 🦀",
        "nul \0 and\r\nCRLF",
    ];
    let reasons = [
        NameOnlyReason::Unsupported,
        NameOnlyReason::NotText,
        NameOnlyReason::Unreadable,
        NameOnlyReason::Empty,
        NameOnlyReason::Linked,
    ];
    let mut out = Vec::new();
    for folder in ["notes", "", "Ordner/ünter"] {
        for count in 0..=3_usize {
            let notes = (0..count)
                .map(|n| ImportedNote {
                    path: format!("dir/note-{n}.md"),
                    kind: if n % 2 == 0 {
                        "note".into()
                    } else {
                        "page".into()
                    },
                    title: (n % 2 == 1).then(|| format!("Title {n}")),
                    written_at: 1_700_000_000 + u64::try_from(n).expect("small"),
                    markdown: markdowns[n % markdowns.len()].repeat(n + 1),
                    original: original(n),
                })
                .collect();
            let links = (0..count)
                .map(|n| ImportedNoteLink {
                    from: format!("dir/note-{n}.md"),
                    to: format!("dir/note-{}.md", n + 1),
                })
                .collect();
            let name_only = (0..count + 2)
                .map(|n| NameOnlyFile {
                    path: format!("files/file-{n}.bin"),
                    why: reasons[n % reasons.len()],
                    facts: FileFacts {
                        bytes: u64::try_from(n * 1000).expect("small"),
                        modified_at: u64::MAX - u64::try_from(n).expect("small"),
                    },
                    original: original(n + 1),
                })
                .collect();
            out.push(ImportedNoteBatch {
                request_id: id(u8::try_from(count).expect("small") + 1),
                folder: folder.into(),
                notes,
                links,
                name_only,
            });
        }
    }
    out
}

fn messages() -> Vec<HistoryMessage> {
    let texts = [
        "",
        "hello",
        "ünïcode — 日本語 🦀",
        "nul \0 inside",
        "line\r\nbreak",
    ];
    let mut out = Vec::new();
    for role in [HistoryRole::User, HistoryRole::Assistant] {
        for text in texts {
            for repeat in [1, 300] {
                out.push(HistoryMessage {
                    native_id: format!("m-{}", out.len()),
                    parent_id: None,
                    role,
                    text: text.repeat(repeat),
                    at_ms: None,
                    said_by: None,
                    tools: Vec::new(),
                    alias: None,
                });
            }
        }
    }
    out
}

#[test]
fn the_import_purposes_keep_main_s_recipes() {
    for (purpose, name) in [
        (
            purposes::ingest::CLAIM_IMPORT_CONTENT,
            "oneiron.ingest.claim_import_content.v1",
        ),
        (
            purposes::ingest::HISTORY_MESSAGE,
            "oneiron.ingest.history_message.v1",
        ),
        (
            purposes::note::IMPORT_CONTENT,
            "oneiron.note.import_content.v1",
        ),
    ] {
        // Main's three hashes write no tag: the tag is the registry name only.
        assert_eq!(purpose.tag(), name);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
    }
}

#[test]
fn the_claim_import_content_hash_keeps_its_bytes() {
    let batches = claim_batches();
    assert_eq!(batches.len(), 72);
    for batch in &batches {
        assert_eq!(
            door::claim_import_content_hash(batch).expect("the batch encodes"),
            base_claim::main_claim_import_content_hash(batch),
            "{batch:?}"
        );
    }
}

#[test]
fn the_note_import_content_hash_keeps_its_bytes() {
    let batches = note_batches();
    assert_eq!(batches.len(), 12);
    for batch in &batches {
        assert_eq!(
            door::note_import_content_hash(batch).expect("the batch encodes"),
            base_note::main_note_import_content_hash(batch),
            "{batch:?}"
        );
    }
}

#[test]
fn the_history_message_hash_keeps_its_bytes() {
    let messages = messages();
    assert_eq!(messages.len(), 20);
    for message in &messages {
        for unknown_speaker in [false, true] {
            assert_eq!(
                door::history_message_hash(message, unknown_speaker),
                base_ledger::main_history_message_hash(message, unknown_speaker),
                "{message:?} unknown speaker {unknown_speaker}"
            );
        }
    }
}

#[test]
fn the_blob_version_hash_keeps_its_bytes() {
    let mut bodies: Vec<Vec<u8>> = vec![Vec::new(), b"body".to_vec(), (0..=255).collect()];
    for len in [63, 64, 65, 1023, 1024, 1025, 70_000] {
        bodies.push(
            (0..len)
                .map(|n| u8::try_from(n % 251).expect("below 251"))
                .collect(),
        );
    }
    for body in &bodies {
        // The head's arm, `*ContentHash::of(bytes).as_bytes()`, through its cfg seam.
        assert_eq!(
            door::blob_version_content_hash(body),
            base_blob::VersionBody::Bytes(body).content_hash(),
            "{} bytes",
            body.len()
        );
    }
}

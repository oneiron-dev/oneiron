//! Fix list row 15412, slice 3a: words brought in from outside that neither
//! the vault's owner nor its companion spoke land as a counterparty's. An
//! external coding-session export's assistant replies land Counterparty, not
//! Companion, beside the owner's own prompts (User); every TURN of a file-drop
//! transcript speaks as a counterparty, never as the vault's user.
//!
//! Red on the PR's base (slice 2): the history landing maps the export's
//! assistant to Companion, and the file-drop transcript stamps every TURN
//! `user`.
//!
//! Public paths only: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test imported_speech_counterparty`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::ingest::history::{HistoryFile, HistorySource};
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const IMPORTED_AT: u64 = 1_800_000_000;
const SESSION: &str = "5c2d8e41-1111-4222-8333-944455556666";
/// One coding session as its tool logged it: the owner's prompt, then the
/// tool's assistant reply.
const LOG: [&str; 2] = [
    r#"{"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"user","message":{"role":"user","content":"Repot the basil."},"uuid":"e3000000-0000-4000-8000-000000000001","timestamp":"2026-09-25T06:00:00.000Z"}"#,
    r#"{"parentUuid":"e3000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The basil is repotted."}]},"uuid":"e3000000-0000-4000-8000-000000000002","timestamp":"2026-09-25T06:00:20.000Z"}"#,
];

/// Any error the engine answers, boxed by its debug text.
fn boxed<E: std::fmt::Debug>(error: E) -> Box<dyn std::error::Error> {
    format!("{error:?}").into()
}

/// A body's string field `key`, read from its msgpack map.
fn body_field(body: &[u8], key: &str) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    value.as_map()?.iter().find_map(|(field, value)| {
        (field.as_str() == Some(key))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

#[test]
fn history_import_assistant_lands_counterparty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default()).map_err(boxed)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().map_err(boxed)?;
    let actor = vault.ensure_embedded_owner_actor().map_err(boxed)?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(boxed)?;
    let file = HistoryFile {
        stem: SESSION.to_owned(),
        parent: None,
    };
    for conversation in HistorySource::ClaudeCode
        .decode(&LOG.join("\n"), &file)
        .map_err(boxed)?
    {
        let report = vault
            .import_history(
                &owner,
                HistorySource::ClaudeCode,
                &conversation,
                IMPORTED_AT,
            )
            .map_err(boxed)?;
        assert_eq!(report.new, 2, "{report:?}");
    }
    let mut authors = Vec::new();
    for message in vault.entities_by_type(ENTITY_TYPE_MESSAGE).map_err(boxed)? {
        let body = vault
            .get(&message)
            .map_err(boxed)?
            .expect("a listed MESSAGE has a body");
        authors.push(body_field(&body, "author").expect("a MESSAGE names its author"));
    }
    authors.sort();
    assert_eq!(authors, ["counterparty", "user"]);
    Ok(())
}

#[test]
fn file_drop_transcript_turns_speak_as_counterparty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault =
        Vault::open_unseeded_for_test(directory.path(), VaultConfig::default()).map_err(boxed)?;
    let TranscriptIngestOutcome::Session { turn_refs, .. } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: hello\nBob: hi",
            arrived_at_ms: 200_000,
        },
    )
    .map_err(boxed)?
    else {
        panic!("a turn-bearing transcript mints a session");
    };
    assert_eq!(turn_refs.len(), 2);
    for turn in &turn_refs {
        let body = vault
            .get(turn)
            .map_err(boxed)?
            .expect("a persisted TURN has a body");
        for key in ["speaker", "spkr", "role"] {
            assert_eq!(
                body_field(&body, key).as_deref(),
                Some("counterparty"),
                "TURN {key}"
            );
        }
    }
    Ok(())
}

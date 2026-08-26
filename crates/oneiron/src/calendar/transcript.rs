use crate::edge::EdgeActorClass;
use crate::ingest::{
    FILE_DROP_TRANSCRIPT_SOURCE_ID, IngestError, IngestResult, IngestSource, NormalizedIngestBatch,
    NormalizedIngestRecord,
};
use crate::note::TakeTarget;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MACHINE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub struct FileDropTranscriptSource;
impl IngestSource for FileDropTranscriptSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let records = input
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let (occurred_at, line) = parse_time_prefix(line);
                let (speaker, text) = line
                    .split_once(':')
                    .map_or((None, line), |(a, b)| (Some(a.trim().to_owned()), b.trim()));
                if text.is_empty() {
                    return None;
                }
                Some(NormalizedIngestRecord {
                    source_record_id: (i + 1).to_string(),
                    thread_id: None,
                    speaker,
                    occurred_at,
                    text: text.to_owned(),
                })
            })
            .collect();
        Ok(NormalizedIngestBatch {
            source_id: FILE_DROP_TRANSCRIPT_SOURCE_ID,
            records,
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: None,
        })
    }
}
fn parse_time_prefix(line: &str) -> (Option<u64>, &str) {
    let Some(rest) = line.strip_prefix('[') else {
        return (None, line);
    };
    let Some((stamp, rest)) = rest.split_once(']') else {
        return (None, line);
    };
    (stamp.trim().parse().ok(), rest.trim())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTranscriptTurn {
    pub ordinal: u32,
    pub speaker_label: Option<String>,
    pub claimed_start_ms: Option<u64>,
    pub claimed_end_ms: Option<u64>,
    pub text: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTranscript {
    pub claimed_started_ms: Option<u64>,
    pub claimed_ended_ms: Option<u64>,
    pub turns: Vec<ParsedTranscriptTurn>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptParse {
    Turns(ParsedTranscript),
    NoteFallback { text: String },
}
pub fn parse_file_drop_transcript(input: &str) -> IngestResult<TranscriptParse> {
    if input.trim().is_empty() {
        return Err(IngestError::EmptyText {
            source_id: FILE_DROP_TRANSCRIPT_SOURCE_ID,
            line: 1,
        });
    }
    let normalized = FileDropTranscriptSource.normalize(input)?;
    let mut turns = Vec::new();
    for (i, rec) in normalized.records.into_iter().enumerate() {
        turns.push(ParsedTranscriptTurn {
            ordinal: i as u32,
            speaker_label: rec.speaker,
            claimed_start_ms: rec.occurred_at,
            claimed_end_ms: rec.occurred_at,
            text: rec.text,
        });
    }
    if turns.is_empty() {
        Ok(TranscriptParse::NoteFallback {
            text: input.trim().to_owned(),
        })
    } else {
        let started = turns.iter().filter_map(|t| t.claimed_start_ms).min();
        let ended = turns.iter().filter_map(|t| t.claimed_end_ms).max();
        Ok(TranscriptParse::Turns(ParsedTranscript {
            claimed_started_ms: started,
            claimed_ended_ms: ended,
            turns,
        }))
    }
}

/// Request for the atomic file-drop transcript landing path.
pub struct TranscriptFileDropRequest<'a> {
    pub source_blob_ref: crate::EntityId,
    pub decoded_text: &'a str,
    pub arrived_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptIngestOutcome {
    Session {
        session_ref: crate::EntityId,
        turn_refs: Vec<crate::EntityId>,
        /// IDs carried by the same in-transaction SessionEnd wake plan.
        wake_turn_refs: Vec<crate::EntityId>,
        extraction_enqueued: bool,
    },
    RetryOpenSession {
        open_session_ref: crate::EntityId,
    },
    /// A nonempty file with no usable turns remains explicit caller-owned NOTE input.
    NoteFallback {
        note_ref: crate::EntityId,
    },
}

/// Mints (or detects) the session before persisting transcript turns, then
/// atomically closes it through the standard lifecycle path.
pub fn ingest_file_drop_transcript(
    vault: &crate::Vault,
    request: TranscriptFileDropRequest<'_>,
) -> crate::Result<TranscriptIngestOutcome> {
    ingest_file_drop_transcript_inner(vault, request, false)
}

fn ingest_file_drop_transcript_inner(
    vault: &crate::Vault,
    request: TranscriptFileDropRequest<'_>,
    fail_after_turns: bool,
) -> crate::Result<TranscriptIngestOutcome> {
    let _normalized = crate::ingest::INGEST_SOURCE_REGISTRY
        .normalize(FILE_DROP_TRANSCRIPT_SOURCE_ID, request.decoded_text)
        .map_err(|_| crate::Error::InvalidClaimBody("invalid file-drop transcript"))?;
    let parsed = match parse_file_drop_transcript(request.decoded_text)
        .map_err(|_| crate::Error::InvalidClaimBody("invalid file-drop transcript"))?
    {
        TranscriptParse::Turns(turns) => turns,
        TranscriptParse::NoteFallback { .. } => {
            return persist_note_fallback(vault, request);
        }
    };
    vault.with_write_txn(|wtxn| {
        let hint = crate::session_lifecycle::SessionHintTimestamp {
            claimed_ms: parsed.claimed_started_ms,
            arrival_ms: request.arrived_at_ms,
            effective_ms: request.arrived_at_ms,
        };
        match vault.mint_session_from_hint_in_txn(wtxn, hint)? {
            crate::session_lifecycle::SessionMintOutcome::AlreadyOpen(id) => {
                Ok(TranscriptIngestOutcome::RetryOpenSession {
                    open_session_ref: id,
                })
            }
            crate::session_lifecycle::SessionMintOutcome::Minted(session_ref) => {
                let turn_refs = persist_turns(
                    vault,
                    wtxn,
                    request.source_blob_ref,
                    session_ref,
                    &parsed.turns,
                    request.arrived_at_ms,
                )?;
                let wake = vault.plan_session_end_wake_in_txn(wtxn)?;
                let wake_turn_refs = wake.planned_turn_ids.clone();
                let end_hint = crate::session_lifecycle::SessionHintTimestamp {
                    claimed_ms: parsed.claimed_ended_ms,
                    arrival_ms: request.arrived_at_ms,
                    effective_ms: request.arrived_at_ms,
                };
                vault
                    .end_session_with_wake_and_hint_in_txn(
                        wtxn,
                        &session_ref,
                        crate::session_lifecycle::SessionClosePredicate::Explicit,
                        request.arrived_at_ms / 1000,
                        &wake,
                        Some(end_hint),
                    )?
                    .ok_or(crate::Error::InvariantViolation(
                        "file-drop session was not closed",
                    ))?;
                // Exercise transaction rollback only after close and its wake writes landed.
                if fail_after_turns {
                    return Err(crate::Error::InvariantViolation(
                        "file-drop transcript test failure injection",
                    ));
                }
                Ok(TranscriptIngestOutcome::Session {
                    session_ref,
                    turn_refs,
                    wake_turn_refs,
                    extraction_enqueued: !wake.plans.is_empty(),
                })
            }
        }
    })
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn ingest_file_drop_transcript_fail_after_turns_for_test(
    vault: &crate::Vault,
    request: TranscriptFileDropRequest<'_>,
) -> crate::Result<TranscriptIngestOutcome> {
    ingest_file_drop_transcript_inner(vault, request, true)
}

fn persist_turns(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    source_blob_ref: crate::EntityId,
    _session_ref: crate::EntityId,
    turns: &[ParsedTranscriptTurn],
    arrived_at_ms: u64,
) -> crate::Result<Vec<crate::EntityId>> {
    let conversation_ref = crate::EntityId::now();
    vault
        .batch_in()
        .put(
            &conversation_ref,
            ENTITY_TYPE_CONVERSATION,
            crate::temporal::TimeRange {
                start: arrived_at_ms / 1000,
                end: arrived_at_ms / 1000,
            },
            arrived_at_ms / 1000,
            &[],
        )
        .apply(wtxn)?;
    let mut ids = Vec::with_capacity(turns.len());
    for turn in turns {
        let id = crate::EntityId::now();
        // GATE-10 keys carry the ROLE, never the display name: the shared
        // turn-body decoder is first-wins across the `speaker|spkr` alias set,
        // so a human label parked in `speaker` would decode as the turn's role
        // and classify as `Unknown` — inadmissible, i.e. invisible to every
        // dirty scan. The source label stays verbatim beside them under
        // `speaker_label`, which is provenance-only and outside the alias set.
        let body = rmp_serde::to_vec_named(&serde_json::json!({
            "ordinal": turn.ordinal, "speaker": "user", "spkr": "user",
            "role": "user", "speaker_label": turn.speaker_label,
            "text": turn.text, "txt": turn.text, "source_blob_ref": source_blob_ref.to_hex(),
            "claimed_start_ms": turn.claimed_start_ms, "claimed_end_ms": turn.claimed_end_ms,
            "arrived_at_ms": arrived_at_ms,
        }))
        .map_err(|_| crate::Error::InvariantViolation("transcript TURN encode"))?;
        let time = turn.claimed_start_ms.unwrap_or(arrived_at_ms) / 1000;
        vault
            .batch_in()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_TURN,
                crate::temporal::TimeRange {
                    start: time,
                    end: turn.claimed_end_ms.unwrap_or(arrived_at_ms) / 1000,
                },
                arrived_at_ms / 1000,
                &body,
            )
            .edge(&id, crate::edge::EdgeKind::ChildOf, &conversation_ref, 1.0)
            .apply(wtxn)?;
        ids.push(id);
    }
    Ok(ids)
}

/// Stable dedicated actor for file-drop import NOTE authorship.
fn file_drop_import_actor(vault: &crate::Vault, at: u64) -> crate::Result<crate::EntityId> {
    let digest = Sha256::digest(b"oneiron:calendar:file-drop-import-machine:v1");
    let actor = crate::EntityId::from_bytes(digest[..16].try_into().expect("sha256 prefix"))?;
    let _ = at;
    // Provision the deterministic machine in the same owned vault when this
    // import path is first used; author_take then receives a real actor.
    if vault.get_entity_type(&actor)? != Some(ENTITY_TYPE_MACHINE) {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_MACHINE,
            crate::temporal::TimeRange { start: at, end: at },
            at,
            b"file-drop import machine",
        )?;
    }
    Ok(actor)
}

#[cfg(feature = "test-support")]
/// Test-only fixture that provisions the deterministic file-drop MACHINE actor
/// and its narrowly scoped standing write policy.
pub fn seed_file_drop_machine_fixture(
    vault: &crate::Vault,
    at: u64,
) -> crate::Result<crate::EntityId> {
    let digest = Sha256::digest(b"oneiron:calendar:file-drop-import-machine:v1");
    let actor = crate::EntityId::from_bytes(digest[..16].try_into().expect("sha256 prefix"))?;
    if vault.get_entity_type(&actor)? != Some(ENTITY_TYPE_MACHINE) {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_MACHINE,
            crate::temporal::TimeRange { start: at, end: at },
            at,
            b"file-drop import machine",
        )?;
    }
    let manifest = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.1"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("calendar-transcript-test"),
        ),
        (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
        (
            rmpv::Value::from("min_engine_version"),
            rmpv::Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            rmpv::Value::from("defaults"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("normal"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ),
        (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
        (
            rmpv::Value::from("actor_ceilings"),
            rmpv::Value::Array(vec![
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("actor_class"),
                        rmpv::Value::from("system"),
                    ),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ]),
                rmpv::Value::Map(vec![
                    (rmpv::Value::from("actor_class"), rmpv::Value::from("human")),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ]),
            ]),
        ),
    ]);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &manifest)
        .map_err(|_| crate::Error::InvariantViolation("fixture policy manifest encode"))?;
    let id = crate::EntityId::now();
    let mut raw = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + body.len());
    raw.push(crate::registry::ENTITY_TYPE_POLICY_MANIFEST);
    raw.extend_from_slice(&at.to_be_bytes());
    raw.extend_from_slice(&at.to_be_bytes());
    raw.extend_from_slice(&at.to_be_bytes());
    raw.extend_from_slice(&body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
        vault.store.type_index.put(
            wtxn,
            &crate::store::Store::encode_type_key(
                crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                &id,
            ),
            &[],
        )?;
        Ok(())
    })?;
    Ok(actor)
}

/// KNOWN DEBT (ONE-1790 G4, LOW): the NOTE this authors is clocked by
/// [`crate::memory::Memory::author_take`]'s own observation time
/// (`unix_seconds_now()`), NOT by `request.arrived_at_ms`. A fallback NOTE
/// therefore reads as "observed when the import ran", not "stamped at the
/// import's arrival instant". Turn-bearing imports are unaffected — they carry
/// `arrived_at_ms` and the claimed transcript stamps explicitly. Arrival-stamped
/// NOTE authorship needs a facade-level clock seam and is a separate ticket.
fn persist_note_fallback(
    vault: &crate::Vault,
    request: TranscriptFileDropRequest<'_>,
) -> crate::Result<TranscriptIngestOutcome> {
    let at = request.arrived_at_ms / 1_000;
    let actor = file_drop_import_actor(vault, at)?;
    let receipt = vault
        .memory(actor, EdgeActorClass::System)
        .author_take(
            TakeTarget::Subject(request.source_blob_ref),
            request.decoded_text.trim().to_owned(),
        )
        .map_err(|_| crate::Error::InvalidClaimBody("file-drop NOTE fallback refused"))?;
    let note_ref = crate::EntityId::from_hex(&receipt.id_hex)?;
    Ok(TranscriptIngestOutcome::NoteFallback { note_ref })
}

//! The Dreamer's check of a conversation's self-written summary (FIX 4465
//! D), on the same maintenance queue and with the same verdicts as a run's.
//! The landing declares refs, hashes and pins only: the SUMMARY and its
//! epoch, the SESSION, conversation and branch, each retained turn of the
//! span with its projection's fingerprint, the writer, the artifact, the
//! filed step, the receipt's digest and the ref of the check material, the
//! accepted try's gate input (FIX 5040, the remainder of FIX 4819).
//!
//! The check reads the landing's durable receipt, the check material, the
//! summary's words while they stand, and the span's turns as the Dreamer, in
//! one snapshot, never the home the call wore. A receipt that changed, a
//! material other than the one the receipt binds, a withdrawn summary or a
//! turn whose fingerprint moved is `stale_evidence`. A material that is
//! missing, erased or does not decode, or a span it cannot read, is
//! `unreadable_evidence`. A turn whose MESSAGE is away from this replica
//! waits. Before any judgment the six gate checks run again on the kept
//! request, reply and policy (FIX 5040): a check that fails, or prose other
//! than the landed summary's, is a `mismatch` that names it, never
//! `supported`. A judge input past the window the host lends the judge's
//! model is `unreadable_evidence`, `span_past_judge_room`, and no call goes
//! out ([`super::judge_room`]). Only then is the verdict reached as a run's is
//! ([`super::support`]). The span and the material are read again after the
//! judgment, so drift during the judgment is stale too. A mismatch reaches
//! the agent's inbox; nothing here rewrites its words or its byline.
//!
//! A span whose one turn its writer read in pieces is judged per piece
//! (FIX-LIST COMPACTION-CHECK-JUDGES-PER-CHUNK; Engine answer 21 Nov 07:39):
//! each piece summary, read back out of the kept entry under the byte range
//! the receipt names, against exactly those bytes of the turn as the Dreamer
//! reads it now, and then the landed summary against that entry, the text
//! its writer was given. A turn whose entry fell back to its head is judged
//! against that head. Every part is sized against the judge's window before
//! any call, so `span_past_judge_room` stays only for a part that does not
//! fit. The first part the judge does not find supported decides the check,
//! and the finding lists each piece judged with its bytes.

use std::ops::Range;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    COMPACTION_CHECK_FACET, CompactionCheckModel, CompactionCheckVerdict, NO_DIAGNOSTIC, Settled,
    ask_judge, emit_finding, judge_call, judge_locality, judge_room, support,
};
use crate::attempt_queue::AttemptId;
use crate::compaction::{
    CheckMaterialFault, CompactionCheckMaterial, CompactionCheckMaterialRef, CompactionEvidence,
    CompactionExecution, CompactionStepRef, ConversationTurnReading, ConversationTurnSpan,
    check_material_in, entry_piece_summaries,
};
use crate::dreamer_consolidation::{ConversationSpanRead, conversation_span_text};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, Error, Result, Vault};
use oneiron_model::llm::{ContentPart, LlmRequest, LlmResponse};

#[doc(hidden)]
use oneiron_records::dreamer_runner::maintenance::compaction_check::conversation::CONVERSATION_DECLARATION_KEY;

/// Why a check waits: a turn of its span is away from this replica.
const SPAN_NOT_RESIDENT: &str = "a turn of the checked span is not resident here";

/// The reason a check settles with when its receipt names a reading of the
/// span's turn that the span or the kept entry does not bear out.
const TURN_READING_UNREADABLE: &str = "turn_reading_unreadable";

/// What one conversation landing asks the Dreamer to check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationCheckDeclaration {
    summary: EntityId,
    epoch: u64,
    session: EntityId,
    conversation: EntityId,
    #[serde(default)]
    branch: Option<EntityId>,
    /// The span's retained turns in order, each with its pin.
    turns: Vec<ConversationTurnSpan>,
    writer: EntityId,
    artifact_hash: String,
    artifact_len: u64,
    #[serde(default)]
    step: Option<CompactionStepRef>,
    receipt_digest: String,
    /// The check material the receipt binds (FIX 5040): the accepted try's
    /// gate input, which the check judges again.
    material: CompactionCheckMaterialRef,
}

impl ConversationCheckDeclaration {
    fn of(summary: EntityId, epoch: u64, execution: &CompactionExecution) -> Result<Self> {
        let missing =
            || Error::InvariantViolation("a conversation landing carries no checkable receipt");
        let Some(CompactionEvidence::Conversation(evidence)) = execution.evidence.as_ref() else {
            return Err(missing());
        };
        Ok(Self {
            summary,
            epoch,
            session: evidence.session,
            conversation: evidence.conversation,
            branch: evidence.branch,
            turns: evidence.turns.clone(),
            writer: execution.writer,
            artifact_hash: execution.snapshot_hash.clone().ok_or_else(missing)?,
            artifact_len: execution.snapshot_len.ok_or_else(missing)?,
            step: execution.step.clone(),
            receipt_digest: execution.receipt_digest_hex()?,
            material: evidence.check_material.clone().ok_or_else(missing)?,
        })
    }

    /// The queue key the landing fixes: one check per SUMMARY.
    fn landing_key(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:compaction-check:conversation:v1");
        hasher.update(self.session.as_bytes());
        hasher.update(self.summary.as_bytes());
        format!("{COMPACTION_CHECK_FACET}:{}", hasher.finalize().to_hex())
    }

    fn input(&self) -> Result<Value> {
        let json = serde_json::to_string(self)
            .map_err(|_| Error::InvariantViolation("a conversation check did not encode"))?;
        Ok(Value::Map(vec![(
            Value::from(CONVERSATION_DECLARATION_KEY),
            Value::from(json),
        )]))
    }

    /// The declaration `input` carries, or `None` when it declares no
    /// conversation.
    pub(crate) fn from_input(input: &Value) -> Result<Option<Self>> {
        let Some((_, value)) = input.as_map().and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(CONVERSATION_DECLARATION_KEY))
        }) else {
            return Ok(None);
        };
        let invalid = || Error::InvalidConfig("invalid conversation check declaration".into());
        let json = value.as_str().ok_or_else(invalid)?;
        serde_json::from_str(json).map(Some).map_err(|_| invalid())
    }

    /// Each turn with the fingerprint its landing pinned; `None` for a pin
    /// that is not a 32-byte hex digest.
    fn pins(&self) -> Option<Vec<(EntityId, [u8; 32])>> {
        self.turns
            .iter()
            .map(|span| Some((span.turn, span.pinned_fingerprint()?)))
            .collect()
    }

    /// The records a finding cites: the writer, its filed step and, while
    /// `words_live`, the summary.
    pub(crate) fn cited(&self, words_live: bool) -> Vec<EntityId> {
        let mut evidence = vec![self.writer];
        if let Some(step) = &self.step {
            evidence.push(step.claim);
        }
        if words_live {
            evidence.push(self.summary);
        }
        evidence
    }

    /// One digest over every pin, in order: what the finding names as the
    /// evidence it declared and read.
    fn pins_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        for span in &self.turns {
            hasher.update(span.turn.as_bytes());
            hasher.update(span.fingerprint.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// Declares the check of one conversation landing in the landing's own
/// write: a rolled-back landing declares nothing, and a replayed one finds
/// the check it declared.
pub(crate) fn declare_conversation_check_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    summary: EntityId,
    epoch: u64,
    execution: &CompactionExecution,
) -> Result<()> {
    let declaration = ConversationCheckDeclaration::of(summary, epoch, execution)?;
    DreamerRunnerStore::new(vault).enqueue_compaction_check_in_txn(
        txn,
        declaration.input()?,
        declaration.landing_key(),
        crate::unix_seconds_now(),
    )?;
    Ok(())
}

/// One judgment the check asks: a summary and exactly the text it was
/// written from.
struct Part {
    /// For a piece summary, the bytes of the turn's window text it covers
    /// and that text's length; `None` for the landed summary.
    piece: Option<(Range<usize>, usize)>,
    summary: String,
    evidence: String,
}

/// What the deterministic reads found.
enum Reading {
    /// The parts the judge reads, the landed summary's last.
    Ready(Vec<Part>),
    Settled(Settled),
    Deferred,
}

/// One part's judgment, as the finding records it.
struct PartJudged {
    verdict: CompactionCheckVerdict,
    reason: String,
    conflicts: Vec<serde_json::Value>,
    judge: serde_json::Value,
    diagnostic: Option<CompactionCheckVerdict>,
    decision: Option<serde_json::Value>,
}

impl PartJudged {
    /// The piece's entry in the finding's `pieces`: its bytes and its
    /// judgment.
    fn piece(&self, bytes: &Range<usize>) -> serde_json::Value {
        serde_json::json!({
            "bytes": [bytes.start, bytes.end],
            "verdict": self.verdict.as_str(),
            "reason": self.reason,
            "conflicts": self.conflicts,
            "judge": self.judge,
            "diagnostic_verdict": self.diagnostic.map(CompactionCheckVerdict::as_str),
            "decision": self.decision,
        })
    }
}

/// Runs one admitted conversation check.
pub(super) async fn run_conversation_check(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: CompactionCheckModel<'_>,
    declaration: ConversationCheckDeclaration,
) -> Result<DreamerAttemptExecution> {
    let attempt_id = attempt.status.attempt.id;
    let now = ctx.now_ms / 1_000;
    let parts = match read(ctx.vault, &declaration)? {
        Reading::Ready(parts) => parts,
        Reading::Settled(settled) => {
            record(ctx.vault, attempt_id, &declaration, &settled, &[], now)?;
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings: Vec::new(),
            });
        }
        Reading::Deferred => {
            return Ok(DreamerAttemptExecution::Park {
                reason: SPAN_NOT_RESIDENT.to_owned(),
                cause: DreamerParkCause::Signal,
            });
        }
    };
    let locality = judge_locality(&model)?;
    let keyless = model.inference.selected_keyless();
    let paid = model.inference.selected_paid();
    // Every part is sized before any call: one past the judge's window
    // settles the check unjudged, with nothing spent.
    let mut asks = Vec::with_capacity(parts.len());
    for part in &parts {
        let input = judge_input(&declaration, part);
        let request = judge_request(&model, &input, locality, keyless, paid)?;
        if let Some(settled) = judge_room::exceeded(&model, &request, &declaration.pins_digest()) {
            record(ctx.vault, attempt_id, &declaration, &settled, &[], now)?;
            return Ok(judge_room::completed_without_judge());
        }
        asks.push((part, input, request));
    }
    let cited = declaration.cited(true);
    let mut spend = support::Spend::default();
    let mut pieces = Vec::new();
    let mut decided = None;
    for (part, input, request) in asks {
        let asked = ask_judge(attempt, ctx, &model, request, declaration.writer, &spend).await;
        let judging = match asked.map_err(|error| {
            spend.note_before_error(ctx);
            error
        })? {
            Ok(judging) => judging,
            Err(parked) => return Ok(parked),
        };
        let judged = judgment(&judging.response, &declaration);
        let diagnostic = judged.as_ref().map(|judged| judged.verdict);
        let ask = support::Ask {
            kind: "conversation",
            subject: declaration.writer,
            evidence: &cited,
            state: &input,
            locality,
            keyless,
            paid,
        };
        let verdict =
            match support::verdict(attempt, ctx, &model, &judging, diagnostic, &ask).await? {
                Ok(verdict) => verdict,
                Err(parked) => return Ok(parked),
            };
        spend = verdict.spend;
        let (reason, mut conflicts) = judged.map_or_else(
            || (NO_DIAGNOSTIC.to_owned(), Vec::new()),
            |judged| (judged.reason, judged.conflicts),
        );
        if let Some((bytes, _)) = &part.piece {
            for conflict in &mut conflicts {
                conflict["bytes"] = serde_json::json!([bytes.start, bytes.end]);
            }
        }
        let judged = PartJudged {
            verdict: verdict.verdict,
            reason,
            conflicts,
            judge: judging.judge(&model),
            diagnostic,
            decision: verdict.decision,
        };
        if let Some((bytes, _)) = &part.piece {
            pieces.push(judged.piece(bytes));
        }
        // A part the judge does not find supported decides the check.
        let decides = judged.verdict != CompactionCheckVerdict::Supported;
        decided = Some(judged);
        if decides {
            break;
        }
    }
    let Some(decided) = decided else {
        spend.note_before_error(ctx);
        return Err(Error::InvariantViolation(
            "a conversation check judges no part",
        ));
    };
    let mut settled = match read(ctx.vault, &declaration).map_err(|error| {
        spend.note_before_error(ctx);
        error
    })? {
        Reading::Ready(_) => Settled {
            verdict: decided.verdict,
            reason: decided.reason,
            conflicts: decided.conflicts,
            evidence_now: Some(declaration.pins_digest()),
            words_live: true,
            judge: None,
            diagnostic: decided.diagnostic,
            decision: decided.decision,
        },
        Reading::Settled(settled) => settled,
        Reading::Deferred => {
            return Ok(spend.park_with_spend(SPAN_NOT_RESIDENT, DreamerParkCause::Signal));
        }
    };
    settled.judge = Some(decided.judge);
    if let Err(error) = record(ctx.vault, attempt_id, &declaration, &settled, &pieces, now) {
        spend.note_before_error(ctx);
        return Err(error);
    }
    Ok(spend.completed())
}

/// Reads the landing's receipt, the check material, the summary's words
/// and the span, checks them against the declaration, and runs the six gate
/// checks again on the material (FIX 5040).
fn read(vault: &Vault, declaration: &ConversationCheckDeclaration) -> Result<Reading> {
    use CompactionCheckVerdict::{StaleEvidence, UnreadableEvidence};
    let settled = |verdict, reason| Ok(Reading::Settled(Settled::new(verdict, reason)));
    let (words, material, reading) = {
        let txn = vault.store.env.read_txn()?;
        let Some(receipt) =
            crate::compaction::conversation_receipt_in(&vault.store, &txn, &declaration.summary)?
        else {
            return settled(UnreadableEvidence, "landing_not_found");
        };
        let evidence = receipt.evidence();
        if receipt.execution.writer != declaration.writer
            || receipt.epoch != declaration.epoch
            || receipt.execution.receipt_digest_hex()? != declaration.receipt_digest
            || evidence.map(|evidence| &evidence.turns) != Some(&declaration.turns)
            || evidence.and_then(|evidence| evidence.check_material.as_ref())
                != Some(&declaration.material)
        {
            return settled(StaleEvidence, "receipt_changed");
        }
        let reading = evidence.and_then(|evidence| evidence.reading.clone());
        let words = crate::ports::EntityStoreRead::port_entity_record(
            &vault.store,
            &txn,
            &declaration.summary,
        )?
        .and_then(|record| crate::compaction::decode_epoch_summary_body(&record.body).ok())
        .map(|body| body.text);
        let material = check_material_in(
            &vault.store,
            &txn,
            &declaration.summary,
            &declaration.material,
        )?;
        (words, material, reading)
    };
    let Some(words) = words else {
        return settled(StaleEvidence, "summary_withdrawn");
    };
    if words.len() as u64 != declaration.artifact_len
        || bytes_to_hex_lower(blake3::hash(words.as_bytes()).as_bytes())
            != declaration.artifact_hash
    {
        return settled(StaleEvidence, "artifact_changed");
    }
    let material = match material {
        Ok(material) => material,
        Err(CheckMaterialFault::Changed) => {
            return settled(StaleEvidence, CheckMaterialFault::Changed.as_str());
        }
        Err(fault) => return settled(UnreadableEvidence, fault.as_str()),
    };
    let Some(pins) = declaration.pins() else {
        return settled(UnreadableEvidence, "evidence_pin_unreadable");
    };
    match conversation_span_text(vault, &pins)? {
        ConversationSpanRead::Ready(texts) => Ok(gate_again(
            declaration,
            &material,
            reading.as_ref(),
            words,
            &texts,
        )),
        ConversationSpanRead::Drifted => {
            let mut stale = Settled::new(StaleEvidence, "evidence_revision_moved");
            stale.words_live = true;
            Ok(Reading::Settled(stale))
        }
        ConversationSpanRead::Unreadable => settled(UnreadableEvidence, "span_unreadable"),
        ConversationSpanRead::Deferred => Ok(Reading::Deferred),
    }
}

/// The six gate checks run again on the kept request, reply and policy,
/// before any judgment (FIX 5040). A check that fails, or accepted prose
/// other than the landed summary's words, is a mismatch that names it.
/// Otherwise the span is ready for the judge, in the parts `reading` names,
/// or `unreadable_evidence` when the span or the kept entry does not bear
/// that reading out.
fn gate_again(
    declaration: &ConversationCheckDeclaration,
    material: &CompactionCheckMaterial,
    reading: Option<&ConversationTurnReading>,
    words: String,
    texts: &[String],
) -> Reading {
    let reason = match material.rerun_gate() {
        Ok(prose) if prose == words => {
            if let Some(parts) = parts(declaration, material, reading, words, texts) {
                return Reading::Ready(parts);
            }
            let mut unreadable = Settled::new(
                CompactionCheckVerdict::UnreadableEvidence,
                TURN_READING_UNREADABLE,
            );
            unreadable.evidence_now = Some(declaration.pins_digest());
            unreadable.words_live = true;
            return Reading::Settled(unreadable);
        }
        Ok(_) => "gate_summary_differs".to_owned(),
        Err(failure) => format!("gate_failed:{}", failure.check.as_str()),
    };
    let mut mismatch = Settled::new(CompactionCheckVerdict::Mismatch, &reason);
    mismatch.evidence_now = Some(declaration.pins_digest());
    mismatch.words_live = true;
    Reading::Settled(mismatch)
}

/// The parts the judge reads, the landed summary's last. With no `reading`,
/// that summary against the span whole. For the span's one turn read in
/// pieces, first each piece summary, read back out of the kept entry,
/// against exactly its bytes of the turn's window text, then the landed
/// summary against that entry, as its writer read it. For a turn whose
/// entry fell back to its head, the landed summary against that head.
/// `None` when the span or the kept entry does not bear `reading` out.
fn parts(
    declaration: &ConversationCheckDeclaration,
    material: &CompactionCheckMaterial,
    reading: Option<&ConversationTurnReading>,
    words: String,
    texts: &[String],
) -> Option<Vec<Part>> {
    let Some(reading) = reading else {
        let evidence = render(&declaration.turns, texts);
        return Some(vec![Part {
            piece: None,
            summary: words,
            evidence,
        }]);
    };
    let ([span], [text]) = (declaration.turns.as_slice(), texts) else {
        return None;
    };
    // The turn's window text, as its writer's pieces cut it.
    let window = format!("{}: {text}", span.role);
    let total = window.len();
    match reading {
        ConversationTurnReading::Head { end } => {
            let end = usize::try_from(*end).ok()?;
            let head = window.get(..end)?;
            let evidence =
                format!("[0] {head}\n[cut: only bytes 0..{end} of this turn's {total} were given]");
            Some(vec![Part {
                piece: None,
                summary: words,
                evidence,
            }])
        }
        ConversationTurnReading::Pieces { pieces } => {
            let sealed = material.sealed_request();
            let [entry] = sealed.window.as_slice() else {
                return None;
            };
            let summaries = entry_piece_summaries(&entry.content, total, pieces)?;
            let mut parts = Vec::with_capacity(pieces.len() + 1);
            for (piece, summary) in pieces.iter().zip(summaries) {
                let bytes = usize::try_from(piece.start).ok()?..usize::try_from(piece.end).ok()?;
                let evidence = format!(
                    "[0] [bytes {}..{} of this turn's {total}]\n{}",
                    bytes.start,
                    bytes.end,
                    window.get(bytes.clone())?
                );
                parts.push(Part {
                    piece: Some((bytes, total)),
                    summary: summary.to_owned(),
                    evidence,
                });
            }
            let evidence = format!("[0] {}: {}", span.role, entry.content);
            parts.push(Part {
                piece: None,
                summary: words,
                evidence,
            });
            Some(parts)
        }
    }
}

/// The span as the judge reads it: each turn by its place in the span, who
/// it speaks for, and its exact words.
fn render(turns: &[ConversationTurnSpan], texts: &[String]) -> String {
    turns
        .iter()
        .zip(texts)
        .enumerate()
        .map(|(at, (span, text))| format!("[{at}] {}: {text}", span.role))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The judge's call: the host's rubric, then the summary and the span it
/// was cut from, its conflicts citing turns by their place in the span.
fn judge_request(
    model: &CompactionCheckModel<'_>,
    input: &serde_json::Value,
    locality: oneiron_model::llm::ModelLocality,
    keyless: bool,
    paid: bool,
) -> Result<LlmRequest> {
    let schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["verdict", "conflicts", "reason"],
        "properties": {
            "verdict": {"type": "string"},
            "conflicts": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["assertion", "turns"],
                "properties": {
                    "assertion": {"type": "integer"},
                    "turns": {"type": "array", "items": {"type": "integer"}}
                }
            }},
            "reason": {"type": "string"}
        }
    });
    judge_call(model, schema, input, locality, keyless, paid)
}

/// What the judge reads for `part`: the span's length in turns and, for a
/// piece summary, the bytes of the turn it covers; the summary; and the text
/// it was written from, whole.
fn judge_input(declaration: &ConversationCheckDeclaration, part: &Part) -> serde_json::Value {
    let turns = declaration.turns.len();
    let span = match &part.piece {
        None => serde_json::json!({"turns": turns}),
        Some((bytes, total)) => {
            serde_json::json!({"turns": turns, "bytes": [bytes.start, bytes.end], "of": total})
        }
    };
    serde_json::json!({
        "span": span,
        "summary": part.summary,
        "evidence": part.evidence,
    })
}

/// The judge's verdict and its reason, each conflict citing the span's
/// turns by id; `None` for a reply that is not one. A conflict keeps only
/// turns of the checked span.
struct Judged {
    verdict: CompactionCheckVerdict,
    conflicts: Vec<serde_json::Value>,
    reason: String,
}

fn judgment(response: &LlmResponse, declaration: &ConversationCheckDeclaration) -> Option<Judged> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let reply: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let verdict = match reply.get("verdict")?.as_str()? {
        "supported" => CompactionCheckVerdict::Supported,
        "mismatch" => CompactionCheckVerdict::Mismatch,
        _ => return None,
    };
    let mut conflicts = Vec::new();
    for conflict in reply.get("conflicts")?.as_array()? {
        let assertion = conflict.get("assertion")?.as_u64()?;
        let turns: Vec<String> = conflict
            .get("turns")?
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .filter_map(|at| usize::try_from(at).ok())
            .filter_map(|at| declaration.turns.get(at))
            .map(|span| span.turn.to_hex())
            .collect();
        conflicts.push(serde_json::json!({"assertion": assertion, "turns": turns}));
    }
    Some(Judged {
        verdict,
        conflicts,
        reason: reply.get("reason")?.as_str()?.to_owned(),
    })
}

/// Records one verdict as the Dreamer's finding about the writer, citing
/// the writer, its filed step and, while its words stand, the summary. A
/// turn judged per piece lists each piece judged, with its bytes.
fn record(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ConversationCheckDeclaration,
    settled: &Settled,
    pieces: &[serde_json::Value],
    now: u64,
) -> Result<EntityId> {
    let mut value = serde_json::json!({
        "verdict": settled.verdict.as_str(),
        "session": declaration.session.to_hex(),
        "conversation": declaration.conversation.to_hex(),
        "branch": declaration.branch.map(|branch| branch.to_hex()),
        "landing": {
            "kind": "epoch",
            "summary": declaration.summary.to_hex(),
            "epoch": declaration.epoch,
        },
        "turns": declaration
            .turns
            .iter()
            .map(|span| span.turn.to_hex())
            .collect::<Vec<_>>(),
        "writer": declaration.writer.to_hex(),
        "artifact": {"hash": declaration.artifact_hash, "len": declaration.artifact_len},
        "evidence": {
            "declared": declaration.pins_digest(),
            "read": settled.evidence_now,
        },
        "step": declaration.step,
        "receipt_digest": declaration.receipt_digest,
        "check_material": declaration.material,
        "conflicts": settled.conflicts,
        "judge": settled.judge,
        "reason": settled.reason,
        "diagnostic_verdict": settled.diagnostic.map(CompactionCheckVerdict::as_str),
        "decision": settled.decision,
    });
    if !pieces.is_empty() {
        value["pieces"] = serde_json::Value::from(pieces.to_vec());
    }
    emit_finding(
        vault,
        attempt,
        declaration.writer,
        &value,
        &declaration.cited(settled.words_live),
        settled.verdict,
        now,
    )
}

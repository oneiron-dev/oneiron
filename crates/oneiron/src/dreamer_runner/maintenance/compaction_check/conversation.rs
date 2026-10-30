//! The Dreamer's check of a conversation's self-written summary (FIX 4465
//! D), on the same maintenance queue and with the same verdicts as a run's.
//! The landing declares refs, hashes and pins only: the SUMMARY and its
//! epoch, the SESSION, conversation and branch, each retained turn of the
//! span with its projection's fingerprint, the writer, the artifact, the
//! filed step and the receipt's digest.
//!
//! The check reads the landing's durable receipt, the summary's words while
//! they stand, and the span's turns as the Dreamer in one snapshot, never
//! the home the call wore. A receipt that changed, a withdrawn summary or a
//! turn whose fingerprint moved is `stale_evidence`; a span it cannot read is
//! `unreadable_evidence`; a turn whose MESSAGE is away from this replica
//! waits. The verdict is reached as a run's is ([`super::support`]). The
//! span is read again once it was, so drift during the judgment is stale
//! too. A mismatch reaches the agent's inbox; nothing here rewrites its
//! words or its byline.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    COMPACTION_CHECK_FACET, CompactionCheckModel, CompactionCheckVerdict, NO_DIAGNOSTIC, Settled,
    ask_judge, emit_finding, judge_call, judge_locality, support, unix_now,
};
use crate::attempt_queue::AttemptId;
use crate::compaction::{
    CompactionEvidence, CompactionExecution, CompactionStepRef, ConversationTurnSpan,
};
use crate::dreamer_consolidation::{ConversationSpanRead, conversation_span_text};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{ContentPart, LlmRequest, LlmResponse};
use crate::{EntityId, Error, Result, Vault};

/// The payload key a conversation's declaration rides under.
const CONVERSATION_DECLARATION_KEY: &str = "conversation_declaration";

/// Why a check waits: a turn of its span is away from this replica.
const SPAN_NOT_RESIDENT: &str = "a turn of the checked span is not resident here";

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
            .map(|span| Some((span.turn, hex32(&span.fingerprint)?)))
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
        unix_now(),
    )?;
    Ok(())
}

/// What the deterministic reads found.
enum Reading {
    Ready { summary: String, evidence: String },
    Settled(Settled),
    Deferred,
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
    let (summary, evidence) = match read(ctx.vault, &declaration)? {
        Reading::Ready { summary, evidence } => (summary, evidence),
        Reading::Settled(settled) => {
            record(ctx.vault, attempt_id, &declaration, &settled, now)?;
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
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
    let input = judge_input(&declaration, &summary, &evidence);
    let request = judge_request(&model, &input, locality, keyless)?;
    let judging = match ask_judge(attempt, ctx, &model, request, declaration.writer).await? {
        Ok(judging) => judging,
        Err(parked) => return Ok(parked),
    };
    let judged = judgment(&judging.response, &declaration);
    let diagnostic = judged.as_ref().map(|judged| judged.verdict);
    let cited = declaration.cited(true);
    let ask = support::Ask {
        kind: "conversation",
        subject: declaration.writer,
        evidence: &cited,
        state: &input,
        locality,
        keyless,
    };
    let verdict = match support::verdict(attempt, ctx, &model, &judging, diagnostic, &ask).await? {
        Ok(verdict) => verdict,
        Err(parked) => return Ok(parked),
    };
    let mut settled = match read(ctx.vault, &declaration).map_err(|error| {
        verdict.spend.note_before_error(ctx);
        error
    })? {
        Reading::Ready { .. } => {
            let (reason, conflicts) = judged.map_or_else(
                || (NO_DIAGNOSTIC.to_owned(), Vec::new()),
                |judged| (judged.reason, judged.conflicts),
            );
            Settled {
                verdict: verdict.verdict,
                reason,
                conflicts,
                evidence_now: Some(declaration.pins_digest()),
                words_live: true,
                judge: None,
                diagnostic,
                decision: verdict.decision,
            }
        }
        Reading::Settled(settled) => settled,
        Reading::Deferred => {
            return Ok(verdict
                .spend
                .park_with_spend(SPAN_NOT_RESIDENT, DreamerParkCause::Signal));
        }
    };
    settled.judge = Some(judging.judge(&model));
    if let Err(error) = record(ctx.vault, attempt_id, &declaration, &settled, now) {
        verdict.spend.note_before_error(ctx);
        return Err(error);
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: verdict.spend.units,
        step_hashes: Vec::new(),
    })
}

/// Reads the landing's receipt, the summary's words and the span, and
/// checks them against the declaration.
fn read(vault: &Vault, declaration: &ConversationCheckDeclaration) -> Result<Reading> {
    use CompactionCheckVerdict::{StaleEvidence, UnreadableEvidence};
    let settled = |verdict, reason| Ok(Reading::Settled(Settled::new(verdict, reason)));
    let words = {
        let txn = vault.store.env.read_txn()?;
        let Some(receipt) =
            crate::compaction::conversation_receipt_in(&vault.store, &txn, &declaration.summary)?
        else {
            return settled(UnreadableEvidence, "landing_not_found");
        };
        if receipt.execution.writer != declaration.writer
            || receipt.epoch != declaration.epoch
            || receipt.execution.receipt_digest_hex()? != declaration.receipt_digest
            || receipt.evidence().map(|evidence| &evidence.turns) != Some(&declaration.turns)
        {
            return settled(StaleEvidence, "receipt_changed");
        }
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, &txn, &declaration.summary)?
            .and_then(|record| crate::compaction::decode_epoch_summary_body(&record.body).ok())
            .map(|body| body.text)
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
    let Some(pins) = declaration.pins() else {
        return settled(UnreadableEvidence, "evidence_pin_unreadable");
    };
    match conversation_span_text(vault, &pins)? {
        ConversationSpanRead::Ready(texts) => Ok(Reading::Ready {
            summary: words,
            evidence: render(&declaration.turns, &texts),
        }),
        ConversationSpanRead::Drifted => {
            let mut stale = Settled::new(StaleEvidence, "evidence_revision_moved");
            stale.words_live = true;
            Ok(Reading::Settled(stale))
        }
        ConversationSpanRead::Unreadable => settled(UnreadableEvidence, "span_unreadable"),
        ConversationSpanRead::Deferred => Ok(Reading::Deferred),
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
    locality: crate::llm::ModelLocality,
    keyless: bool,
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
    judge_call(model, schema, input, locality, keyless)
}

/// What the judge reads: the span's length in turns, the summary and the
/// span's words, whole.
fn judge_input(
    declaration: &ConversationCheckDeclaration,
    summary: &str,
    evidence: &str,
) -> serde_json::Value {
    serde_json::json!({
        "span": {"turns": declaration.turns.len()},
        "summary": summary,
        "evidence": evidence,
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
            ContentPart::Text { text } => Some(text.as_str()),
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
/// the writer, its filed step and, while its words stand, the summary.
fn record(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ConversationCheckDeclaration,
    settled: &Settled,
    now: u64,
) -> Result<EntityId> {
    let value = serde_json::json!({
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
        "conflicts": settled.conflicts,
        "judge": settled.judge,
        "reason": settled.reason,
        "diagnostic_verdict": settled.diagnostic.map(CompactionCheckVerdict::as_str),
        "decision": settled.decision,
    });
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

/// A 64-character lowercase hex digest's bytes.
fn hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

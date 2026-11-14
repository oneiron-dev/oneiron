//! Typed questions over paragraphs (ARCH-0076 §2, "Paragraph or clause"):
//! each selected paragraph of a DOCX head is one decide() call over its
//! text, and every answer lands as a native comment quoting that paragraph,
//! all in one tracked revision on a copy, settled once on Keep. The display
//! words are the caller's, as a slide review's are; no provider output
//! writes document prose.

use super::artifact_question::{ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, invalid};
use super::slides_review::SlideReviewLabels;
use super::{EditOp, EditOutcome, EditProposal, OfficeFormat};
use crate::llm::decision::questions::keep_artifact_unit_ask;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionRung, EvidenceVersion, PairedReading, TypedDecision,
};
use crate::{EntityId, Error, Result, Vault};
use oneiron_docedit::docx_body::{DocxBlockKind, DocxStoryScope, read_docx_scoped_blocks};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

#[doc(hidden)]
pub use oneiron_records::edit_roundtrip::paragraph_review::ParagraphJudgment;

/// One typed ask over paragraphs, by their stable block ids.
#[derive(Clone, Copy)]
pub struct ParagraphAsk<'a> {
    pub ask: ArtifactAsk<'a>,
    pub blocks: &'a [String],
    /// The one story whose local paragraph ids `blocks` names; `None` is BODY.
    pub scope: Option<&'a DocxStoryScope>,
    /// The comments' author name.
    pub author: &'a str,
    pub labels: &'a SlideReviewLabels,
}

impl Vault {
    /// Ask one typed question of each selected paragraph of a document head,
    /// one decide() call per paragraph under the run's deadline. Answered
    /// paragraphs become comments in one tracked revision held for Keep; a
    /// paragraph with no text abstains without a call, and one the native
    /// writer keeps read-only (pending redlines, inline anchors) is refused.
    pub fn ask_blob_artifact_paragraphs(
        &self,
        artifact: &EntityId,
        request: &ParagraphAsk<'_>,
    ) -> Result<ArtifactAskRun> {
        let ask = &request.ask;
        ask.validate()?;
        request.labels.validate()?;
        let author = request.author.trim();
        if author.is_empty() || author.len() > 256 || request.blocks.is_empty() {
            return Err(invalid("invalid paragraph ask selection"));
        }
        // A document with a live body is read there at its head, pinned with
        // it; each paragraph's kind, lock and quoted text are the version's,
        // where its comment lands (FIX 11981).
        let live = match request.scope {
            None => self.live_head_blocks(artifact)?.map(|(pin, blocks)| {
                (
                    pin,
                    blocks
                        .into_iter()
                        .map(|block| (block.id, block.text))
                        .collect::<Vec<_>>(),
                )
            }),
            Some(scope) => {
                self.live_head_story_paragraphs(artifact, scope)?
                    .map(|(pin, paragraphs)| {
                        (
                            pin,
                            paragraphs
                                .into_iter()
                                .map(|paragraph| (paragraph.id, paragraph.text))
                                .collect::<Vec<_>>(),
                        )
                    })
            }
        };
        let judged_live = live.as_ref().map(|(pin, _)| pin.clone());
        let (version, bytes, read_rows) = self.office_head(artifact, OfficeFormat::Docx)?;
        let limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(ask.principal))?
        };
        // The DOCX read runs in the host's memory (FIX 10651); a resource
        // refusal is the engine's error, never an invalid document (FIX 10587).
        let resources = crate::office_body::document_resources();
        let blocks = resources
            .docx(|| read_docx_scoped_blocks(&bytes, limits, request.scope))
            .map_err(|error| {
                crate::office_body::document_error(error.resource(), "paragraph ask document")
            })?;
        let frontier = *blake3::hash(&bytes).as_bytes();
        let sources = [EvidenceVersion {
            id: *artifact,
            body_hash: frontier,
        }];
        let mut seen = HashSet::new();
        let mut judgments = Vec::new();
        let mut ops = Vec::new();
        let mut abstained = Vec::new();
        let mut refused = Vec::new();
        for id in request.blocks {
            let unit = paragraph_unit(request.scope, id);
            if !seen.insert(id.as_str()) {
                return Err(invalid("a paragraph is asked twice"));
            }
            let Some(block) = blocks.iter().find(|block| block.id == *id) else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "missing_block".into(),
                    judged_live: judged_live.clone(),
                });
                continue;
            };
            if !matches!(
                block.kind,
                DocxBlockKind::Paragraph | DocxBlockKind::Heading(_)
            ) || block.locked.is_some()
            {
                refused.push(UnitRefusal {
                    unit,
                    reason: "read_only_block".into(),
                    judged_live: judged_live.clone(),
                });
                continue;
            }
            let text = match &live {
                None => block.text.as_str(),
                Some((_, live)) => match live.iter().find(|(live_id, _)| live_id == id) {
                    Some((_, text)) => text.as_str(),
                    None => {
                        refused.push(UnitRefusal {
                            unit,
                            reason: "missing_block".into(),
                            judged_live: judged_live.clone(),
                        });
                        continue;
                    }
                },
            };
            if text.trim().is_empty() {
                abstained.push(UnitAbstention {
                    unit,
                    decision: None,
                    judged_live: judged_live.clone(),
                });
                continue;
            }
            let mut state_unit = unit.clone();
            state_unit["kind"] = json!(block.kind);
            state_unit["role"] = json!(block.role);
            let state = json!({ "unit": state_unit, "text": text });
            let Some(decision) = ask.decide(&state, &sources, &[])? else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "evidence_budget".into(),
                    judged_live: judged_live.clone(),
                });
                continue;
            };
            if decision.answer == DecisionAnswer::Abstain {
                // A unit asked of its role holder keeps its ask (FIX 11231).
                keep_artifact_unit_ask(self, &sources[0], &unit, &decision);
                abstained.push(UnitAbstention {
                    unit,
                    decision: Some(decision),
                    judged_live: judged_live.clone(),
                });
                continue;
            }
            let probability = decision
                .probability
                .ok_or_else(|| invalid("missing paragraph answer probability"))?;
            let comment =
                request
                    .labels
                    .comment(&decision.answer, probability, decision.receipt.band);
            ops.push(paragraph_comment_op(
                request.scope,
                id,
                &block.text,
                &comment,
                author,
            ));
            judgments.push(ParagraphJudgment {
                block: id.clone(),
                scope: request.scope.cloned(),
                text_hash: *blake3::hash(block.text.as_bytes()).as_bytes(),
                decision,
                answer_contract: ask.question.contract.clone(),
                comment,
                author: author.to_owned(),
                labels: request.labels.clone(),
                frontier,
                judged_version: Some(version),
                judged_live: judged_live.clone(),
            });
        }
        if judgments.is_empty() {
            return Ok(ArtifactAskRun {
                proposal: None,
                sheet_answers: None,
                deferred_floor: None,
                abstained,
                refused,
                read_rows,
                next_sheet_row: None,
            });
        }
        let transaction = json!({ "ops": ops, "revision": { "author": author } }).to_string();
        let proposal = match super::docx::run_docx_revision_with_limits(
            &bytes,
            &transaction,
            ask.run_ref,
            limits,
        )? {
            EditOutcome::Proposed(mut proposal) => {
                proposal.base_version = Some(version);
                proposal.manifest.paragraph_judgments = judgments;
                proposal.manifest.paragraph_question = Some(ask.question.clone());
                *proposal
            }
            EditOutcome::Rejected { .. } => {
                return Err(Error::Artifact(
                    crate::error::ArtifactError::EditRoundtripFailed(
                        "the commented copy failed validation",
                    ),
                ));
            }
        };
        verify_paragraph_judgments(&proposal)?;
        Ok(ArtifactAskRun {
            proposal: Some(proposal),
            sheet_answers: None,
            deferred_floor: None,
            abstained,
            refused,
            read_rows,
            next_sheet_row: None,
        })
    }
}

/// The untouched answers of a held paragraph ask, carried onto a newer head
/// of the document (ARCH-0075 §4): each comment again quotes its paragraph,
/// whose text is the text its call read, in one tracked revision on a copy
/// of `head`. Each answer keeps the revision it was judged against.
pub(crate) fn carry_paragraph_judgments(
    head: &[u8],
    head_version: u64,
    carried: Vec<ParagraphJudgment>,
    run_ref: &str,
    limits: oneiron_docedit::ArchiveLimits,
) -> Result<EditProposal> {
    // The DOCX read runs in the host's memory (FIX 10651); a resource
    // refusal is the engine's error, never an invalid document (FIX 10587).
    let resources = crate::office_body::document_resources();
    let blocks = resources
        .docx(|| {
            read_docx_scoped_blocks(
                head,
                limits,
                carried.first().and_then(|row| row.scope.as_ref()),
            )
        })
        .map_err(|error| {
            crate::office_body::document_error(error.resource(), "paragraph carry document")
        })?;
    let author = carried
        .first()
        .map(|row| row.author.clone())
        .ok_or_else(|| invalid("no paragraph answer to carry"))?;
    let ops = carried
        .iter()
        .map(|row| {
            let block = blocks
                .iter()
                .find(|block| block.id == row.block)
                .filter(|block| *blake3::hash(block.text.as_bytes()).as_bytes() == row.text_hash)
                .ok_or_else(|| invalid("a carried paragraph changed"))?;
            Ok(paragraph_comment_op(
                row.scope.as_ref(),
                &row.block,
                &block.text,
                &row.comment,
                &row.author,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let transaction = json!({ "ops": ops, "revision": { "author": author } }).to_string();
    let mut proposal =
        match super::docx::run_docx_revision_with_limits(head, &transaction, run_ref, limits)? {
            EditOutcome::Proposed(proposal) => *proposal,
            EditOutcome::Rejected { .. } => {
                return Err(Error::Artifact(
                    crate::error::ArtifactError::EditRoundtripFailed(
                        "the carried comments failed validation",
                    ),
                ));
            }
        };
    proposal.base_version = Some(head_version);
    proposal.manifest.paragraph_judgments = carried;
    verify_carried_paragraph_judgments(&proposal)?;
    Ok(proposal)
}

/// Validate the receipts against the actual comment ops at the settle door.
/// A public manifest is not a source of authority to invent judgment receipts.
pub(crate) fn verify_paragraph_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, false)
}

/// [`verify_paragraph_judgments`] for answers the engine carried onto a
/// newer head at Keep: each still names the revision it was judged against,
/// which may be older than the proposal's base, and its comment still quotes
/// exactly the text its call read.
pub(crate) fn verify_carried_paragraph_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, true)
}

fn paragraph_unit(scope: Option<&DocxStoryScope>, block: &str) -> Value {
    let mut unit = json!({ "block": block });
    if let Some(scope) = scope {
        unit["scope"] = json!(scope);
    }
    unit
}

fn paragraph_comment_op(
    scope: Option<&DocxStoryScope>,
    block: &str,
    expect: &str,
    body: &str,
    author: &str,
) -> Value {
    let mut op = json!({
        "op": "comment_create",
        "target": block,
        "expect": expect,
        "occurrence": 1,
        "body": body,
        "author": author,
    });
    if let Some(scope) = scope {
        op["scope"] = json!(scope);
    }
    op
}

fn verify_rows(proposal: &EditProposal, carried: bool) -> Result<()> {
    let rows = &proposal.manifest.paragraph_judgments;
    if rows.is_empty() {
        return Ok(());
    }
    let mismatch = || invalid("paragraph receipt/comment mismatch");
    let [EditOp::DocxRevision { transaction }] = proposal.manifest.ops.as_slice() else {
        return Err(mismatch());
    };
    let transaction: Value = serde_json::from_str(transaction).map_err(|_| mismatch())?;
    let ops = transaction
        .get("ops")
        .and_then(Value::as_array)
        .ok_or_else(mismatch)?;
    if proposal.format != OfficeFormat::Docx || ops.len() != rows.len() {
        return Err(mismatch());
    }
    let text = |op: &Value, key: &str| op.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut blocks = HashSet::new();
    for (row, op) in rows.iter().zip(ops) {
        let decision = &row.decision;
        let receipt = &decision.receipt;
        let probability = decision.probability.ok_or_else(mismatch)?;
        if text(op, "op").as_deref() != Some("comment_create")
            || text(op, "target").as_deref() != Some(row.block.as_str())
            || row.scope != rows[0].scope
            || op.get("scope").filter(|value| !value.is_null())
                != row.scope.as_ref().map(|scope| json!(scope)).as_ref()
            || text(op, "expect").map(|quote| *blake3::hash(quote.as_bytes()).as_bytes())
                != Some(row.text_hash)
            || text(op, "body").as_deref() != Some(row.comment.as_str())
            || text(op, "author").as_deref() != Some(row.author.as_str())
            || !blocks.insert(row.block.as_str())
            || decision.answer == DecisionAnswer::Abstain
            || decision.human_ask.is_some()
            || !probability.is_finite()
            || !(0.0..=1.0).contains(&probability)
            || row.labels.validate().is_err()
            || row.answer_contract.validate().is_err()
            || !row.answer_contract.accepts(&decision.answer)
            || row.comment
                != row
                    .labels
                    .comment(&decision.answer, probability, receipt.band)
            || receipt.question_version == 0
            || receipt.band.validate().is_err()
            || receipt.providers.is_empty()
            || receipt
                .providers
                .iter()
                .any(|pin| pin.rung == DecisionRung::Human)
            || !PairedReading::readings_valid(
                &receipt.paired,
                &receipt.person,
                receipt.question,
                &receipt.providers,
            )
            || receipt.evidence_versions.is_empty()
            || receipt
                .evidence_versions
                .iter()
                .any(|version| version.body_hash != row.frontier)
            || (!carried
                && (row.frontier != proposal.base_content_hash
                    || row.judged_version != proposal.base_version))
        {
            return Err(mismatch());
        }
    }
    Ok(())
}

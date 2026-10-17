//! Typed questions over paragraphs (ARCH-0076 §2, "Paragraph or clause"):
//! each selected paragraph of a DOCX head is one decide() call over its
//! text, and every answer lands as a native comment quoting that paragraph,
//! all in one tracked revision on a copy, settled once on Keep. The display
//! words are the caller's, as a slide review's are; no provider output
//! writes document prose.

use super::artifact_question::{ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, invalid};
use super::slides_review::SlideReviewLabels;
use super::{EditOp, EditOutcome, EditProposal, OfficeFormat};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionRung, EvidenceVersion, PairedReading, TypedDecision,
};
use crate::{EntityId, Error, Result, Vault};
use oneiron_docedit::docx_body::{DocxBlockKind, read_docx_blocks};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

/// Persisted-row structural ceiling; a decoder must accept every row we write.
pub(crate) const MAX_PARAGRAPH_JUDGMENTS: usize = 4096;

/// One answered paragraph, bound to its native comment and the exact source
/// version. Settlement keeps it with the consume-once receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParagraphJudgment {
    /// The paragraph's stable block id: the comment's target.
    pub block: String,
    /// Hash of the paragraph text the call read, which the comment quotes.
    pub text_hash: [u8; 32],
    /// The shared ladder's decision and receipt.
    pub decision: TypedDecision,
    /// The immutable primitive selected by the question version for this run.
    pub answer_contract: AnswerContract,
    pub comment: String,
    pub author: String,
    /// Runtime display words pinned so settle can recheck comment semantics.
    pub labels: SlideReviewLabels,
    pub frontier: [u8; 32],
    pub judged_version: Option<u64>,
}

/// One typed ask over paragraphs, by their stable block ids.
#[derive(Clone, Copy)]
pub struct ParagraphAsk<'a> {
    pub ask: ArtifactAsk<'a>,
    pub blocks: &'a [String],
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
        if author.is_empty()
            || author.len() > 256
            || request.blocks.is_empty()
            || request.blocks.len() > MAX_PARAGRAPH_JUDGMENTS
        {
            return Err(invalid("invalid paragraph ask selection"));
        }
        let (version, bytes) = self.office_head(artifact, OfficeFormat::Docx)?;
        let limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(ask.principal))?
        };
        let blocks =
            read_docx_blocks(&bytes, limits).map_err(|_| invalid("paragraph ask document"))?;
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
            let unit = json!({ "block": id });
            if !seen.insert(id.as_str()) {
                return Err(invalid("a paragraph is asked twice"));
            }
            let Some(block) = blocks.iter().find(|block| block.id == *id) else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "missing_block".into(),
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
                });
                continue;
            }
            if block.text.trim().is_empty() {
                abstained.push(UnitAbstention {
                    unit,
                    decision: None,
                });
                continue;
            }
            let state = json!({
                "unit": { "block": id, "kind": block.kind, "role": block.role },
                "text": block.text,
            });
            let Some(decision) = ask.decide(&state, &sources, &[])? else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "evidence_budget".into(),
                });
                continue;
            };
            if decision.answer == DecisionAnswer::Abstain {
                abstained.push(UnitAbstention {
                    unit,
                    decision: Some(decision),
                });
                continue;
            }
            let probability = decision
                .probability
                .ok_or_else(|| invalid("missing paragraph answer probability"))?;
            let comment = request
                .labels
                .comment(&decision.answer, probability, decision.receipt.band);
            ops.push(json!({
                "op": "comment_create",
                "target": id,
                "expect": block.text,
                "occurrence": 1,
                "body": comment,
                "author": author,
            }));
            judgments.push(ParagraphJudgment {
                block: id.clone(),
                text_hash: *blake3::hash(block.text.as_bytes()).as_bytes(),
                decision,
                answer_contract: ask.question.contract.clone(),
                comment,
                author: author.to_owned(),
                labels: request.labels.clone(),
                frontier,
                judged_version: Some(version),
            });
        }
        if judgments.is_empty() {
            return Ok(ArtifactAskRun {
                proposal: None,
                abstained,
                refused,
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
            abstained,
            refused,
        })
    }
}

/// Validate the receipts against the actual comment ops at the settle door.
/// A public manifest is not a source of authority to invent judgment receipts.
pub(crate) fn verify_paragraph_judgments(proposal: &EditProposal) -> Result<()> {
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
    if proposal.format != OfficeFormat::Docx
        || rows.len() > MAX_PARAGRAPH_JUDGMENTS
        || ops.len() != rows.len()
    {
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
            || row.frontier != proposal.base_content_hash
            || row.judged_version != proposal.base_version
        {
            return Err(mismatch());
        }
    }
    Ok(())
}

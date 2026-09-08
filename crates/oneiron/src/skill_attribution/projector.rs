//! Evidence door and ordered idempotent projection from evidence to judgments and edit proposals.

use crate::Vault;
use crate::error::Result;

use super::codec::{
    CURSOR_KEY, EDIT_PROPOSAL_PREFIX, EVIDENCE_PREFIX, JUDGMENT_PREFIX, decode_edit_proposal,
    decode_judgment, decode_u64, encode_edit_proposal, encode_evidence, encode_judgment,
    encode_value, evidence_after, next_evidence_sequence_in_txn, sequenced_key, validate_evidence,
};
use super::judge::{AttributionJudge, RuleAttributionJudge, verdict_subject};
use super::types::{AttributionJudgment, OutcomeEvidence, SkillEditProposal};

// ---------------------------------------------------------------------------
// Evidence door + projector
// ---------------------------------------------------------------------------

/// Records one outcome for later attribution, returning its sequence.
///
/// Recording never classifies: the projector owns the verdict, so evidence can
/// be captured on the hot path and routed in a later pass (the ARCH-0035
/// posture, and the reason a re-run can be replayed against a fixed judge).
pub fn record_attribution_evidence(vault: &Vault, evidence: &OutcomeEvidence) -> Result<u64> {
    validate_evidence(vault, evidence)?;
    vault.with_write_txn(|wtxn| {
        let sequence = next_evidence_sequence_in_txn(vault, wtxn)?;
        let encoded = encode_value(&encode_evidence(evidence, sequence))?;
        vault
            .store
            .vault_meta
            .put(wtxn, &sequenced_key(EVIDENCE_PREFIX, sequence), &encoded)?;
        Ok(sequence)
    })
}

/// Reads the projector cursor: the highest evidence sequence already routed.
/// An absent row IS cursor 0 (bootstrap).
pub fn read_attribution_cursor(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, CURSOR_KEY)? else {
        return Ok(0);
    };
    decode_u64(&raw, "attribution cursor")
}

/// Runs one ordered, idempotent attribution pass over evidence recorded after
/// `since_cursor`, using the deterministic tier.
///
/// Returns the judgments minted by THIS pass. Re-running with the same cursor
/// re-routes the same evidence to the same verdicts; running with the persisted
/// cursor ([`read_attribution_cursor`]) processes only what is new.
pub fn run_attribution_projector(
    vault: &Vault,
    since_cursor: u64,
) -> Result<Vec<AttributionJudgment>> {
    run_attribution_projector_with_judge(vault, since_cursor, &RuleAttributionJudge)
}

/// [`run_attribution_projector`] with an explicit judge — the seam the LLM
/// tier and the audit harness both use.
///
/// Abstained evidence is left unjudged but still ADVANCES the cursor: an
/// abstention is a completed routing decision ("this evidence attributes to
/// nobody"), not a retryable failure, so it must not re-enter every pass.
pub fn run_attribution_projector_with_judge(
    vault: &Vault,
    since_cursor: u64,
    judge: &dyn AttributionJudge,
) -> Result<Vec<AttributionJudgment>> {
    let pending = evidence_after(vault, since_cursor)?;
    let mut judgments = Vec::new();
    let mut highest = since_cursor;
    for (sequence, evidence) in pending {
        highest = highest.max(sequence);
        let Some(verdict) = judge.judge(&evidence)? else {
            continue;
        };
        let Some(subject) = verdict_subject(verdict, &evidence) else {
            continue;
        };
        judgments.push(AttributionJudgment {
            sequence,
            verdict,
            subject,
            evidence_receipts: vec![evidence.receipt_ref.clone()],
            at: evidence.at,
        });
    }

    vault.with_write_txn(|wtxn| {
        for judgment in &judgments {
            let encoded = encode_value(&encode_judgment(judgment));
            vault.store.vault_meta.put(
                wtxn,
                &sequenced_key(JUDGMENT_PREFIX, judgment.sequence),
                &encoded?,
            )?;
            if let Some(proposal) = edit_proposal_for(judgment) {
                let encoded = encode_value(&encode_edit_proposal(&proposal))?;
                vault.store.vault_meta.put(
                    wtxn,
                    &sequenced_key(EDIT_PROPOSAL_PREFIX, proposal.judgment_sequence),
                    &encoded,
                )?;
            }
        }
        if highest > since_cursor {
            vault
                .store
                .vault_meta
                .put(wtxn, CURSOR_KEY, &highest.to_be_bytes())?;
        }
        Ok(())
    })?;

    Ok(judgments)
}

/// Every persisted judgment, in routing order. ONE-1738 and ONE-1739 consume
/// this: it is the stack seam.
pub fn attribution_judgments(vault: &Vault) -> Result<Vec<AttributionJudgment>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, JUDGMENT_PREFIX)? {
        let (_, raw) = row?;
        out.push(decode_judgment(&raw)?);
    }
    Ok(out)
}

/// Every minted skill EDIT PROPOSAL awaiting the gated apply, in mint order.
///
/// These are PERSISTED rows, not a filtered view of the judgments: a
/// discovery's consequence is a durable artifact that survives this process,
/// so the surface that applies it (the `dreamer_promotion` envelope precedent
/// / `supersede_skill_record` archive law) has something to pick up. Minting
/// is not applying — ONE-1737 stops at the proposal.
pub fn pending_edit_proposals(vault: &Vault) -> Result<Vec<SkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, EDIT_PROPOSAL_PREFIX)?
    {
        let (_, raw) = row?;
        out.push(decode_edit_proposal(&raw)?);
    }
    Ok(out)
}

/// The proposal a judgment mints, or `None` when its verdict routes to a
/// claim instead (§4: only discovery becomes an edit proposal).
fn edit_proposal_for(judgment: &AttributionJudgment) -> Option<SkillEditProposal> {
    judgment
        .verdict
        .mints_edit_proposal()
        .then(|| SkillEditProposal {
            judgment_sequence: judgment.sequence,
            skill: judgment.subject,
            evidence_receipts: judgment.evidence_receipts.clone(),
            at: judgment.at,
        })
}

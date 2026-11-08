//! Where one re-checked claim's verdict lands (FIX 15414): a rung through
//! the curator's own door, applied with its receipt and the inverse the
//! owner reverts, or held in the run tray on a critical claim, where the
//! owner's approval applies it through the curator's approved door; a plain
//! finding for a claim the verdict leaves as it stands, or one that waits
//! for the owner's review. Each lands in one write with the claim's settled
//! mark, and only while the re-check is still owed. A rung applies only on a
//! claim that write still reads as not critical: one made critical since its
//! read waits for the owner as one read critical does.

use super::super::applied::MaintenanceInverse;
use super::super::{CURATOR_PROPOSAL_PREDICATE, CuratorRubric, curator, proposals};
use super::read::{self, Ask};
use super::{
    CLAIM_SOURCE_RECHECK_FACET, CLAIM_SOURCE_RECHECK_PREDICATE, ClaimSourceRecheckDeclaration,
    Verdict,
};
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimDemotionRung;
use crate::entity_id::bytes_to_hex_lower;
use crate::mail_pack::claim_recheck::MailClaimRecheckOutcome;
use crate::{EntityId, Error, Result, Vault};

/// The rung a verdict takes the claim down its ladder, the least force
/// first and never past the stale mark: a weaker support moves it one rung
/// (decay, then weaken, then stale, as the curator's ladder runs), no
/// support left marks it stale. `None` for a claim the verdict leaves as it
/// stands, and for one already stale.
fn rung_action(verdict: Verdict, ask: &Ask, rubric: &CuratorRubric) -> Option<serde_json::Value> {
    match (verdict, ask.rung) {
        (Verdict::Supported, _) | (_, Some(ClaimDemotionRung::Stale)) => None,
        (Verdict::Unsupported, _) | (Verdict::Weakened, Some(ClaimDemotionRung::Weakened)) => {
            Some(serde_json::json!({"kind": "stale"}))
        }
        (Verdict::Weakened, None) => Some(serde_json::json!({
            "kind": "claim_of_weight",
            "factor": rubric.edge_weight_factor,
        })),
        (Verdict::Weakened, Some(ClaimDemotionRung::Decayed)) => Some(serde_json::json!({
            "kind": "confidence",
            "new_confidence": ask.confidence * rubric.confidence_factor,
        })),
    }
}

/// Lands one claim's verdict with its settled mark. Answers what it did;
/// `None` when the re-check went moot meanwhile.
#[expect(
    clippy::too_many_arguments,
    reason = "one claim's verdict: its attempt, declaration, ask, judge and rubric"
)]
pub(super) fn land(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ClaimSourceRecheckDeclaration,
    ask: &Ask,
    verdict: Option<Verdict>,
    judge: &serde_json::Value,
    rubric: &CuratorRubric,
    now: u64,
) -> Result<Option<MailClaimRecheckOutcome>> {
    let recheck = serde_json::json!({
        "verdict": verdict.map_or("unread", Verdict::as_str),
        "mail_source": declaration.source.to_hex(),
        "occurrence": bytes_to_hex_lower(&declaration.occurrence),
        "generation": declaration.generation,
        "judge": judge,
    });
    let finding = |action: Option<&serde_json::Value>, door_refused: bool| {
        serde_json::json!({
            "target": ask.head.to_hex(),
            "source_hash": ask.source_hash,
            "action": action,
            "refused": door_refused,
            "recheck": recheck,
        })
    };
    let Some(action) = verdict.and_then(|verdict| rung_action(verdict, ask, rubric)) else {
        // A reply that is no verdict waits for the owner's review.
        return land_plain(
            vault,
            attempt,
            declaration,
            ask.head,
            &finding(None, false),
            verdict.is_none(),
            now,
        );
    };
    // The curator's own finding shape: its approved door applies it.
    let rung = serde_json::json!({
        "target": ask.head.to_hex(),
        "source_hash": ask.source_hash,
        "action": action,
        "recheck": recheck,
    });
    if ask.critical {
        return hold(
            vault,
            attempt,
            declaration,
            &proposals::Finding {
                subject: ask.head,
                predicate: CURATOR_PROPOSAL_PREDICATE,
                value: &rung,
                evidence: std::slice::from_ref(&ask.head),
            },
            now,
        );
    }
    match apply_rung(vault, attempt, declaration, ask, &rung, now) {
        // The head moved since it was read: this verdict was about another
        // revision, so it settles changing nothing.
        Err(Error::ConcurrentWrite(_)) => vault.with_write_txn_grouped(|txn| {
            Ok(
                crate::mail_pack::claim_recheck::record_claims_rechecked_in_txn(
                    vault,
                    txn,
                    declaration,
                    &[ask.head],
                    MailClaimRecheckOutcome::Unchanged,
                )?
                .then_some(MailClaimRecheckOutcome::Unchanged),
            )
        }),
        // A rung the ladder's door refuses (out of order, no ClaimOf edge
        // to decay, user truth no generated successor may close) waits for
        // the owner's review.
        Err(error) if refused(&error) => land_plain(
            vault,
            attempt,
            declaration,
            ask.head,
            &finding(Some(&action), true),
            true,
            now,
        ),
        landed => landed,
    }
}

/// Whether the demotion door refused the rung itself.
fn refused(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidClaimBody(_)
            | Error::InvalidEdgeWeight { .. }
            | Error::InvalidConfig(_)
            | Error::Artifact(_)
    )
}

/// Applies one rung as the Dreamer through the curator's door, with its
/// finding, receipt and inverse, in one write with the claim's settled
/// mark: the head, and a weakening's successor, which carries the same
/// evidence. A rung on a claim this write reads as critical (its class, or
/// a critical confirm not settled), and one the Gate parks, lands held in
/// the run tray instead.
fn apply_rung(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ClaimSourceRecheckDeclaration,
    ask: &Ask,
    value: &serde_json::Value,
    now: u64,
) -> Result<Option<MailClaimRecheckOutcome>> {
    let head = ask.head;
    let finding = proposals::Finding {
        subject: head,
        predicate: CURATOR_PROPOSAL_PREDICATE,
        value,
        evidence: std::slice::from_ref(&head),
    };
    let tray = proposals::run_tray_envelope(vault, CLAIM_SOURCE_RECHECK_FACET, attempt)?;
    proposals::land(vault, CLAIM_SOURCE_RECHECK_FACET, attempt, |landing| {
        vault.with_write_txn_grouped(|txn| {
            if !owed_in(vault, txn, declaration)? {
                return Ok(None);
            }
            if read::critical_in(vault, txn, &head, &ask.predicate)? {
                return hold_in_txn(vault, txn, declaration, &finding, &tray, now).map(Some);
            }
            let mut moved = None;
            landing.land_in_txn(vault, txn, &finding, now, |txn| {
                let inverse = curator::apply_in_txn(vault, txn, value, now)?;
                moved = Some(match &inverse {
                    MaintenanceInverse::Curator(rung) => vec![head, rung.after()],
                    _ => vec![head],
                });
                Ok(inverse)
            })?;
            let (claims, outcome) = match moved {
                Some(claims) => (claims, MailClaimRecheckOutcome::Changed),
                // Held: the rung waits for the owner's approval.
                None => (vec![head], MailClaimRecheckOutcome::ReviewNeeded),
            };
            crate::mail_pack::claim_recheck::record_claims_rechecked_in_txn(
                vault,
                txn,
                declaration,
                &claims,
                outcome,
            )?;
            Ok(Some(outcome))
        })
    })
}

/// Lands the plain finding `value` about `head`: applied, with the revert
/// that retracts it, for a claim the verdict leaves as it stands; held for
/// the owner's review when `review`.
fn land_plain(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ClaimSourceRecheckDeclaration,
    head: EntityId,
    value: &serde_json::Value,
    review: bool,
    now: u64,
) -> Result<Option<MailClaimRecheckOutcome>> {
    let finding = proposals::Finding {
        subject: head,
        predicate: CLAIM_SOURCE_RECHECK_PREDICATE,
        value,
        evidence: std::slice::from_ref(&head),
    };
    if review {
        return hold(vault, attempt, declaration, &finding, now);
    }
    proposals::land(vault, CLAIM_SOURCE_RECHECK_FACET, attempt, |landing| {
        vault.with_write_txn_grouped(|txn| {
            if !owed_in(vault, txn, declaration)? {
                return Ok(None);
            }
            landing.land_in_txn(vault, txn, &finding, now, |_| {
                Ok(MaintenanceInverse::Finding)
            })?;
            crate::mail_pack::claim_recheck::record_claims_rechecked_in_txn(
                vault,
                txn,
                declaration,
                &[head],
                MailClaimRecheckOutcome::Unchanged,
            )?;
            Ok(Some(MailClaimRecheckOutcome::Unchanged))
        })
    })
}

/// Lands `finding` Proposed in the owner's run tray, in one write with its
/// claim's settled mark: it waits for the owner's review.
fn hold(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &ClaimSourceRecheckDeclaration,
    finding: &proposals::Finding<'_>,
    now: u64,
) -> Result<Option<MailClaimRecheckOutcome>> {
    let envelope = proposals::run_tray_envelope(vault, CLAIM_SOURCE_RECHECK_FACET, attempt)?;
    vault.with_write_txn_grouped(|txn| {
        if !owed_in(vault, txn, declaration)? {
            return Ok(None);
        }
        hold_in_txn(vault, txn, declaration, finding, &envelope, now).map(Some)
    })
}

/// Lands `finding` Proposed under the run tray's `envelope` in the caller's
/// write, with its claim's settled mark.
fn hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    declaration: &ClaimSourceRecheckDeclaration,
    finding: &proposals::Finding<'_>,
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<MailClaimRecheckOutcome> {
    proposals::emit_fresh_in_txn(vault, txn, finding, envelope, now)?;
    crate::mail_pack::claim_recheck::record_claims_rechecked_in_txn(
        vault,
        txn,
        declaration,
        &[finding.subject],
        MailClaimRecheckOutcome::ReviewNeeded,
    )?;
    Ok(MailClaimRecheckOutcome::ReviewNeeded)
}

/// Whether the re-check is still owed in this write: the message still the
/// source-deleted copy at the declaration's generation, and the re-check
/// waiting.
fn owed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    declaration: &ClaimSourceRecheckDeclaration,
) -> Result<bool> {
    Ok(crate::mail_pack::claim_recheck::claim_recheck_owed_in(
        vault,
        txn,
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    )?
    .is_some())
}

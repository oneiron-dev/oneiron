//! The original Coach request's optional native-source capture.

use crate::claim::{ClaimReadStatus, ScopedReadActorKey, ScopedReadReceipt};
use crate::memory::Memory;
use crate::{Result, Vault};

use super::gate::{
    CanonicalSkillEditVerdict, HeldOutVerdict, canonical_skill_edit_verdicts_in_txn,
    skill_edit_verdicts,
};

/// A witnessed native family, not the whole brief's read set and not a grant
/// to a later reader. It is deliberately absent from the id-only source union.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NativeFamilySources {
    pub(crate) source: crate::store::attempt_sources::NativeReadSource,
    pub(crate) receipt: ScopedReadReceipt,
}

/// Opened only at the actual job boundary, before ranking starts. A failed
/// optional opener never changes an ordinary optimizer read or its error.
pub(super) struct CoachReadRequest {
    key: Option<ScopedReadActorKey>,
}

impl CoachReadRequest {
    pub(super) fn from_memory(memory: &Memory<'_>) -> Self {
        Self {
            key: memory
                .read_lane_if_granted(ClaimReadStatus::Recorded)
                .ok()
                .flatten()
                .map(|lane| lane.actor_key().clone()),
        }
    }

    /// The original DEV basis, with every amendment, primary and conditional
    /// displacement dependency captured before its same-skill split filter.
    pub(super) fn dev_receipts(
        &self,
        vault: &Vault,
        skill: &crate::EntityId,
    ) -> Result<(Vec<String>, Option<NativeFamilySources>)> {
        use crate::skill_reliability::canonical_attributed_outcomes_in_txn;
        let unknown = || super::gate::dev_receipts(vault, skill).map(|rows| (rows, None));
        let Some(key) = &self.key else {
            return unknown();
        };
        let lane = vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        if lane.persist_grant_clock().is_err() {
            return unknown();
        }
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
        let Ok(_custody) = vault.store.gate_custody_read_guard() else {
            return unknown();
        };
        let txn = vault.store.env.read_txn()?;
        let (outcomes, reads) = canonical_attributed_outcomes_in_txn(vault, &txn, skill)?;
        let captured = reads.rows().iter().all(|row| {
            matches!(
                lane.native_outcome_dependency_admitted_in_txn(&txn, row),
                Ok(true)
            )
        });
        let receipt = captured
            .then(|| lane.read_projected_in_txn(&txn, &[], None, |_, _| Ok(())))
            .and_then(std::result::Result::ok)
            .map(|read| read.receipt);
        let sources = receipt.map(|receipt| NativeFamilySources {
            source: crate::store::attempt_sources::NativeReadSource::AttributedOutcomeScan {
                skill: *skill,
                prefixes: reads.prefixes().to_vec(),
                rows: reads.sources(),
            },
            receipt,
        });
        Ok((
            outcomes
                .into_iter()
                .map(|(receipt, _)| receipt)
                .filter(|receipt| !super::gate::receipt_is_held_out(skill, receipt))
                .collect(),
            sources,
        ))
    }

    /// The rule scanner reads all raw rows before membership and brief filters.
    pub(super) fn rule_outcome_receipts(
        &self,
        vault: &Vault,
        skill: &crate::EntityId,
    ) -> Result<(Vec<String>, Option<NativeFamilySources>)> {
        use crate::skill_reliability::{
            CanonicalRuleOutcome, canonical_rule_outcomes_in_txn, rule_outcome_receipts_in_txn,
        };
        let unknown = || {
            let txn = vault.store.env.read_txn()?;
            rule_outcome_receipts_in_txn(vault, &txn, skill).map(|rows| (rows, None))
        };
        let Some(key) = &self.key else {
            return unknown();
        };
        let lane = vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        if lane.persist_grant_clock().is_err() {
            return unknown();
        }
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
        let Ok(_custody) = vault.store.gate_custody_read_guard() else {
            return unknown();
        };
        let txn = vault.store.env.read_txn()?;
        let (rows, prefix) = canonical_rule_outcomes_in_txn(vault, &txn, skill)?;
        let captured = rows.iter().all(|row| {
            matches!(
                lane.native_rule_outcome_admitted_in_txn(&txn, skill, row),
                Ok(true)
            )
        });
        let receipt = captured
            .then(|| lane.read_projected_in_txn(&txn, &[], None, |_, _| Ok(())))
            .and_then(std::result::Result::ok)
            .map(|read| read.receipt);
        let sources = receipt.map(|receipt| NativeFamilySources {
            source: crate::store::attempt_sources::NativeReadSource::RuleOutcomeScan {
                skill: *skill,
                prefix,
                rows: rows.iter().map(CanonicalRuleOutcome::source).collect(),
            },
            receipt,
        });
        Ok((
            rows.iter()
                .filter_map(|row| row.receipt().map(str::to_owned))
                .collect(),
            sources,
        ))
    }

    /// The original eager judgment scan, before its brief filters. Every
    /// decoded row, including a later rejected candidate, is witnessed.
    pub(super) fn attribution_judgments(
        &self,
        vault: &Vault,
    ) -> Result<(
        Vec<crate::skill_attribution::AttributionJudgment>,
        Option<NativeFamilySources>,
    )> {
        use crate::skill_attribution::{
            CanonicalAttributionJudgment, attribution_judgments,
            canonical_attribution_judgments_in_txn,
        };
        let unknown = || attribution_judgments(vault).map(|rows| (rows, None));
        let Some(key) = &self.key else {
            return unknown();
        };
        let lane = vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        if lane.persist_grant_clock().is_err() {
            return unknown();
        }
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
        let Ok(_custody) = vault.store.gate_custody_read_guard() else {
            return unknown();
        };
        let txn = vault.store.env.read_txn()?;
        let (rows, prefix) = canonical_attribution_judgments_in_txn(vault, &txn)?;
        let captured = rows.iter().all(|row| {
            matches!(
                lane.native_attribution_judgment_admitted_in_txn(&txn, row),
                Ok(true)
            )
        });
        let receipt = captured
            .then(|| lane.read_projected_in_txn(&txn, &[], None, |_, _| Ok(())))
            .and_then(std::result::Result::ok)
            .map(|read| read.receipt);
        let sources = receipt.map(|receipt| NativeFamilySources {
            source: crate::store::attempt_sources::NativeReadSource::AttributionJudgmentScan {
                prefix: prefix.to_vec(),
                rows: rows
                    .iter()
                    .map(CanonicalAttributionJudgment::source)
                    .collect(),
            },
            receipt,
        });
        Ok((
            rows.into_iter()
                .map(CanonicalAttributionJudgment::into_judgment)
                .collect(),
            sources,
        ))
    }

    /// The original eager discovery scan, before its brief filters. Every
    /// decoded row, including a later rejected candidate, is witnessed.
    pub(super) fn discovery_proposals(
        &self,
        vault: &Vault,
    ) -> Result<(
        Vec<crate::skill_attribution::SkillEditProposal>,
        Option<NativeFamilySources>,
    )> {
        use crate::skill_attribution::{
            CanonicalSkillEditProposal, canonical_skill_edit_proposals_in_txn,
            pending_edit_proposals,
        };
        let unknown = || pending_edit_proposals(vault).map(|rows| (rows, None));
        let Some(key) = &self.key else {
            return unknown();
        };
        let lane = vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        if lane.persist_grant_clock().is_err() {
            return unknown();
        }
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
        let Ok(_custody) = vault.store.gate_custody_read_guard() else {
            return unknown();
        };
        let txn = vault.store.env.read_txn()?;
        let (rows, prefix) = canonical_skill_edit_proposals_in_txn(vault, &txn)?;
        let captured = rows.iter().all(|row| {
            matches!(
                lane.native_skill_edit_proposal_admitted_in_txn(&txn, row),
                Ok(true)
            )
        });
        let receipt = captured
            .then(|| lane.read_projected_in_txn(&txn, &[], None, |_, _| Ok(())))
            .and_then(std::result::Result::ok)
            .map(|read| read.receipt);
        let sources = receipt.map(|receipt| NativeFamilySources {
            source: crate::store::attempt_sources::NativeReadSource::SkillEditProposalScan {
                prefix: prefix.to_vec(),
                rows: rows
                    .iter()
                    .map(CanonicalSkillEditProposal::source)
                    .collect(),
            },
            receipt,
        });
        Ok((
            rows.into_iter()
                .map(CanonicalSkillEditProposal::into_proposal)
                .collect(),
            sources,
        ))
    }

    /// The brief's actual verdict read, with its original reader. Only the
    /// capture is optional: primary/marker scan and decode errors propagate.
    pub(super) fn verdicts(
        &self,
        vault: &Vault,
    ) -> Result<(Vec<HeldOutVerdict>, Option<NativeFamilySources>)> {
        let unknown = || skill_edit_verdicts(vault).map(|verdicts| (verdicts, None));
        let Some(key) = &self.key else {
            return unknown();
        };
        let lane = vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        // The clock can write. It runs before the guard, and both precede
        // the native source snapshot, as on the native label read surface.
        if lane.persist_grant_clock().is_err() {
            return unknown();
        }
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
        let Ok(_custody) = vault.store.gate_custody_read_guard() else {
            return unknown();
        };
        let txn = vault.store.env.read_txn()?;
        let (rows, prefix) = canonical_skill_edit_verdicts_in_txn(vault, &txn)?;
        let captured = rows.iter().all(|row| {
            matches!(
                lane.native_skill_edit_verdict_admitted_in_txn(&txn, row),
                Ok(true)
            )
        });
        let receipt = captured
            .then(|| lane.read_projected_in_txn(&txn, &[], None, |_, _| Ok(())))
            .and_then(std::result::Result::ok)
            .map(|read| read.receipt);
        if let Some(receipt) = receipt {
            let verdicts = rows.iter().map(|row| row.verdict().clone()).collect();
            Ok((
                verdicts,
                Some(NativeFamilySources {
                    source: crate::store::attempt_sources::NativeReadSource::SkillEditVerdictScan {
                        prefix: prefix.to_vec(),
                        rows: rows.iter().map(CanonicalSkillEditVerdict::source).collect(),
                    },
                    receipt,
                }),
            ))
        } else {
            Ok((
                rows.into_iter()
                    .map(CanonicalSkillEditVerdict::into_verdict)
                    .collect(),
                None,
            ))
        }
    }
}

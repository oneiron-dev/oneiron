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
pub(crate) struct NativeVerdictSources {
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

    /// The brief's actual verdict read, with its original reader. Only the
    /// capture is optional: primary/marker scan and decode errors propagate.
    pub(super) fn verdicts(
        &self,
        vault: &Vault,
    ) -> Result<(Vec<HeldOutVerdict>, Option<NativeVerdictSources>)> {
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
                Some(NativeVerdictSources {
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

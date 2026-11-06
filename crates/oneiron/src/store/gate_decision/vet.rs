//! Core half of `store::gate_decision::vet`: its store-layer items live in `oneiron_store::gate_decision::vet` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::gate_decision::vet::*;

use super::types::{
    GATE_DECISION_LEDGER_VERSION, GATE_DECISION_LEDGER_VERSION_REDACTED, GATE_DIFF_HANDLE_MAX_LEN,
    GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN, GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN,
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN, GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
    GATE_SYSTEM_NOTICE_PLANE_MAX_LEN, GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN,
    GATE_SYSTEM_NOTICE_VERSION_MAX_LEN, GateDecisionRecord, GateSystemNoticeRecord,
};
use crate::error::{Error, Result};

/// Version-dispatched ledger vet. Version 0 is the live row shape; version 1 is
/// the retention skeleton left behind by an in-place redaction (ONE-1638), whose
/// claim-bearing fields are required to be scrubbed. Only version 0 may be
/// APPENDED — decode accepts both.
///
/// ASYMMETRY, DELIBERATE: `actor_class` is required non-empty on the version-1
/// skeleton ONLY, though E-A's D1 table lists it non-empty for both columns.
/// The v0 exemption is load-bearing, not an oversight:
///
/// * On v0 the field is caller-asserted, attacker-influenced input. The
///   external-effect door records the class the caller SENT
///   (`record_external_effect_policy`), and `evaluate_gate` answers an empty
///   one with `DenyMissingActorClass` — a recorded, auditable denial. Vetting
///   it here would turn that fail-closed deny into
///   `CorruptedIndex("gate decision ledger")`, i.e. let any caller abort the
///   write txn (and, once a denial row is on disk, poison every later ledger
///   scan) with an empty string. Recording what was actually asserted is the
///   point of a decision ledger; the deny is the enforcement.
/// * On v1 the field is ours. A skeleton is minted only by the erase coupling,
///   from an already-vetted row, and `actor_class` is one of the few
///   accountability fields the retention design keeps. Empty there means the
///   redactor scrubbed something it must have retained — a real invariant
///   break, correctly fatal.
///
/// `diff_handle` on the v1 skeleton must be EMPTY. This TIGHTENS E-A's D1
/// table, which read "≤ `GATE_DIFF_HANDLE_MAX_LEN`, empty ALLOWED" and left the
/// sentinel bytes to E-B (open question 4). A length cap alone cannot tell a
/// fixed sentinel from a live handle, and the handle is a content binding — a
/// pointer at the very body the redaction exists to scrub — so "empty allowed"
/// let a redacted row keep one. Empty is the only self-evidently scrubbed
/// value. E-B may still mint a sentinel, but only by pinning its bytes in a vet
/// amendment here, which makes the sentinel checkable rather than assumed.
///
/// Pinned by `record_schema_v0_bytes_stable_and_v1_skeleton_vets` (empty-class
/// v1 rejected, empty-class v0 accepted),
/// `redacted_skeleton_must_not_retain_a_diff_handle`, and
/// `gate::tests::effect_actor_class_spoof_fails_closed` (the deny path stays a
/// deny). Tightening v0's `actor_class` is an E-B vet amendment, and needs the
/// effect door to stop recording caller-asserted classes verbatim first.
pub(super) fn vet_gate_decision_record(record: &GateDecisionRecord) -> Result<()> {
    let shared_ok = !record.outcome.is_empty()
        && !record.content_kind.is_empty()
        && !record.policy_manifest_version.is_empty()
        && record.diff_handle.len() <= GATE_DIFF_HANDLE_MAX_LEN;
    let version_ok = match record.version {
        GATE_DECISION_LEDGER_VERSION => {
            record.redacted_at.is_none()
                && !record.reason_codes.is_empty()
                && record
                    .grant_ref
                    .as_deref()
                    .is_none_or(|grant_ref| !grant_ref.trim().is_empty())
                && !record.diff_handle.is_empty()
                && record
                    .reason_codes
                    .iter()
                    .all(|reason| reason.starts_with("gate."))
                && record
                    .receipt_reasons
                    .iter()
                    .all(|reason| valid_gate_receipt_reason(reason))
                && record
                    .system_notices
                    .iter()
                    .all(valid_gate_system_notice_record)
                && record
                    .context
                    .analysis
                    .as_ref()
                    .is_none_or(|analysis| !analysis.rules.is_empty())
        }
        // The skeleton keeps only the accountability fields the retention
        // design retains; everything claim-bearing must already be gone.
        // `actor_class` is required here and NOT on v0 — see the asymmetry
        // note above. `diff_handle` must be EMPTY, not merely bounded — see the
        // handle note above.
        GATE_DECISION_LEDGER_VERSION_REDACTED => {
            record.redacted_at.is_some_and(|at| at > 0)
                && !record.actor_class.is_empty()
                && record.reason_codes.is_empty()
                && record.receipt_reasons.is_empty()
                && record.system_notices.is_empty()
                && record.actor_ref.is_none()
                && record.grant_ref.is_none()
                && record.diff_handle.is_empty()
                && record.context.is_empty()
        }
        _ => false,
    };
    if !shared_ok || !version_ok {
        return Err(Error::CorruptedIndex("gate decision ledger"));
    }
    Ok(())
}

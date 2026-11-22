//! The snapshot read's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use super::evidence_spans::EVIDENCE_SPANS_MAX_RANGES;
use super::policy_preflight::POLICY_PREFLIGHT_MAX_REFS;
use super::snapshot::SNAPSHOT_MAX_KINDS;
use crate::setting::{Kind, lower_is_tighter};

/// 16: an open naming more kinds is refused.
fn snapshot_max_kinds_default() -> u32 {
    u32::try_from(SNAPSHOT_MAX_KINDS).unwrap_or(u32::MAX)
}

/// 100: a preflight naming more refs is refused.
fn policy_preflight_max_refs_default() -> u32 {
    u32::try_from(POLICY_PREFLIGHT_MAX_REFS).unwrap_or(u32::MAX)
}

/// 64: a request naming more ranges is refused.
fn evidence_spans_max_ranges_default() -> u32 {
    u32::try_from(EVIDENCE_SPANS_MAX_RANGES).unwrap_or(u32::MAX)
}

crate::setting::setting_keys! {
    /// The most kinds one snapshot open names. 16 by default: an open naming more is refused.
    /// A raise is the looser direction, so an agent's raise waits on the owner's answer. A
    /// stored 0 reads as 1.
    pub(crate) SNAPSHOT_MAX_KINDS_SETTING: u32 = "snapshot_read.open.max_kinds" {
        kind: Kind::new(snapshot_max_kinds_default)
            .strictest(snapshot_max_kinds_default)
            .tighter(lower_is_tighter::<u32>),
    };
    /// The most refs one policy preflight names. 100 by default: a preflight naming more is
    /// refused. A raise is the looser direction, so an agent's raise waits on the owner's
    /// answer. A stored 0 reads as 1.
    pub(crate) POLICY_PREFLIGHT_MAX_REFS_SETTING: u32 = "snapshot_read.preflight.max_refs" {
        kind: Kind::new(policy_preflight_max_refs_default)
            .strictest(policy_preflight_max_refs_default)
            .tighter(lower_is_tighter::<u32>),
    };
    /// The most byte ranges one evidence spans request names. 64 by default: a request naming
    /// more is refused. A raise is the looser direction, so an agent's raise waits on the
    /// owner's answer. A stored 0 reads as 1.
    pub(crate) EVIDENCE_SPANS_MAX_RANGES_SETTING: u32 = "snapshot_read.evidence.max_ranges" {
        kind: Kind::new(evidence_spans_max_ranges_default)
            .strictest(evidence_spans_max_ranges_default)
            .tighter(lower_is_tighter::<u32>),
    };
}

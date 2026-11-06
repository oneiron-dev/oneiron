//! Owner-work no-vouch report-only diagnostic (FIX 4633).
//!
//! `NoVouch::cap` records which owner-work requests count on this install
//! only because a vouch admits them: counted in the install's fold,
//! uncounted in the fold with no vouch, and not fresh after a settled
//! handoff. The report carries hashes only and is unavailable when no
//! comparison ran; it never holds execution, never withholds, and never
//! changes what counts. Setting the switch below to `false` only disables
//! the report.

use std::collections::BTreeSet;

use super::{AuthorityEntryHash, AuthorityFold};

/// Report-only switch for the vouch-only owner-work diagnostic.
///
/// `true` lets `NoVouch::cap` store the comparison result; `false` only
/// leaves the report unavailable. Neither value changes authority,
/// counting, or execution.
pub const OWNER_WORK_NO_VOUCH_DIAGNOSTIC_ONLY: bool = true;

/// Borrowed vouch-only owner-work report: hashes only, unavailable on
/// failure (FIX 4633).
///
/// [`AuthorityFold::owner_work_no_vouch_diagnostic`] is the only read
/// surface. The report never holds execution: it names requests, it does
/// not withhold them.
#[derive(Debug, Clone, Copy)]
pub enum OwnerWorkNoVouchDiagnostic<'a> {
    /// No report: `NoVouch::cap` never ran, or the switch is off. A
    /// missing comparison is never reported as an empty available set.
    Unavailable,
    /// The comparison ran: owner-work requests counted here only because
    /// a vouch admits them. Empty means none, not unknown.
    Available(&'a BTreeSet<AuthorityEntryHash>),
}

impl AuthorityFold {
    /// Vouch-only owner-work hashes counted on this install (FIX 4633).
    ///
    /// Diagnostic only, borrowed, hashes only:
    /// [`OwnerWorkNoVouchDiagnostic::Available`] carries every request hash
    /// counted in this fold but uncounted in the fold with no vouch
    /// (fresh-after-settled-handoff rows excluded), and
    /// [`OwnerWorkNoVouchDiagnostic::Unavailable`] means no comparison ran.
    /// Reading this changes nothing it reports on.
    #[must_use]
    pub fn owner_work_no_vouch_diagnostic(&self) -> OwnerWorkNoVouchDiagnostic<'_> {
        match &self.install.vouch_only_owner_work {
            None => OwnerWorkNoVouchDiagnostic::Unavailable,
            Some(hashes) => OwnerWorkNoVouchDiagnostic::Available(hashes),
        }
    }
}

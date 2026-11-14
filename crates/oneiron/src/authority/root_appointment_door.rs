//! The root appointment door's receipt (row OWNER-ANCHOR-ROOT-RECOVERY, PLAN
//! v3 section 7; Engine RULINGs 14 Nov 21:01, 21:47 and 22:32).

use std::collections::BTreeSet;

use super::*;

/// What a counted appointment answers, once it committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAppointmentReceipt {
    /// The appointment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The pinned root whose anchor signed it.
    pub root: RecoveryRootId,
    /// The successor root key: this install's owner signing key from now on.
    pub successor: [u8; 32],
    /// The successor's binding of the owner as `human`.
    pub binding: AuthorityEntryHash,
    /// That binding's epoch.
    pub epoch: u64,
    /// The rows this install held valid before the appointment that no
    /// longer stand: an old roster key signed them, or one below them,
    /// outside the appointment's line, and its fence seals them.
    pub sealed: BTreeSet<AuthorityEntryHash>,
}

//! The self-host shipper's counts (TL-6): what a pass did, logged once at
//! its end in counts and classes only, never a code, a scope or a body.

use super::stream::Unreadable;

/// Pieces whose files did not read, by why.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Unread {
    /// A file not there, or not readable.
    missing: usize,
    /// A file not what its manifest says, or a manifest not its piece's.
    mismatched: usize,
}

impl Unread {
    /// Counts one piece that did not read.
    pub(super) fn add(&mut self, unreadable: Unreadable) {
        match unreadable {
            Unreadable::Missing => self.missing += 1,
            Unreadable::Mismatch => self.mismatched += 1,
        }
    }
}

/// What one pass did, in counts.
#[derive(Debug, Default)]
pub(super) struct Tally {
    /// Requests answered.
    pub(super) requests: usize,
    /// Piece windows answered.
    pub(super) windows: usize,
    /// Withdrawals answered.
    pub(super) withdrawals: usize,
    /// Codes whose receipts were asked and answered.
    pub(super) asked: usize,
    /// Signed receipts applied.
    pub(super) applied: usize,
    /// Signed receipts that repeated what a piece held.
    pub(super) repeated: usize,
    /// Pieces a signed receipt contradicted.
    pub(super) contradicted: usize,
    /// Receipts no key verified, or that matched no piece.
    pub(super) unverified: usize,
    /// Entries the intake refused alone.
    pub(super) refused: usize,
    /// Pieces handed back to be offered anew under a new C.
    pub(super) refreshed: usize,
    /// Pieces whose files were not there.
    pub(super) missing: usize,
    /// Pieces whose files were not what their manifests say.
    pub(super) mismatched: usize,
}

impl Tally {
    /// Counts the pieces that did not read.
    pub(super) fn unread(&mut self, unread: Unread) {
        self.missing += unread.missing;
        self.mismatched += unread.mismatched;
    }

    /// Logs the pass, in counts.
    pub(super) fn log(&self) {
        if self.missing + self.mismatched > 0 {
            tracing::warn!(
                missing = self.missing,
                mismatched = self.mismatched,
                "released training offers whose files are missing or are not what their manifests \
                 say ship nothing this pass; they are read again next pass"
            );
        }
        if self.unverified + self.contradicted > 0 {
            tracing::warn!(
                unverified = self.unverified,
                contradicted = self.contradicted,
                "the intake answered with receipts the receipt keys do not verify, or that \
                 contradict one applied; they applied nothing"
            );
        }
        if self.requests > 0 {
            tracing::info!(
                requests = self.requests,
                windows = self.windows,
                withdrawals = self.withdrawals,
                asked = self.asked,
                applied = self.applied,
                repeated = self.repeated,
                refused = self.refused,
                refreshed = self.refreshed,
                "the self-host training shipper reached the intake"
            );
        }
    }
}

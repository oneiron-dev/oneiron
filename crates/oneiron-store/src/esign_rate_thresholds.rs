//! The e-sign send-rate thresholds a policy manifest resolves to.

/// The e-sign send-rate thresholds a policy manifest resolves to: sends per
/// window for one recipient, and for one document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsignRateThresholds {
    /// Sends per window to one recipient.
    pub recipient: u64,
    /// Sends per window of one document.
    pub document: u64,
}

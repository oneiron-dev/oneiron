//! Judge takeover results and the measured honesty axis.

/// The takeover ladder's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverVerdict {
    /// Divergence sits within the old judge's own retest noise in every
    /// source family: the new judge governs.
    TakeOver,
    /// Divergence exceeds the noise floor somewhere: the incumbent holds.
    Hold,
    /// Too few cases, or no measured noise: the incumbent holds with no
    /// automatic takeover and no tie-breaker until more arrive.
    Unknown,
}

/// One overlap case for a judge takeover: did the new judge diverge from the
/// old one, and which source family did the case come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceCase {
    pub source_family: String,
    pub diverged: bool,
}

pub const HONESTY_AXIS: &str = "honesty";

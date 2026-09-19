//! Peer-relative write velocity and structural-failure streaks for automatic verdicts.

/// Observations, not an admission limit. The host checker chooses the verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NormalizedBurstInputs {
    /// Recent rate divided by the peer baseline and `sqrt(1 + vault_size)`.
    /// Finite and nonnegative when produced by [`normalized_burst_inputs`].
    pub rate_ratio: f32,
    /// Consecutive known structural failures. Success resets this count;
    /// transient failures, including timeouts and rate limits, do not change it.
    pub streak: u32,
}

/// Computes comparable peer-relative signals without an absolute write-rate cap.
///
/// `window_secs` is the observation duration, not a policy window. Zero means
/// one clock tick at the caller's seconds resolution. With no valid positive
/// baseline, one observation per observation window seeds the cold-start rate.
/// Vault size scales that rate by `sqrt(1 + vault_size)`. The only saturation
/// is the floating-point representation limit; no admission decision is made.
#[must_use]
pub fn normalized_burst_inputs(
    recent_writes: u64,
    window_secs: u64,
    peer_baseline_per_sec: f64,
    vault_size: u64,
    streak: u32,
) -> NormalizedBurstInputs {
    let window = window_secs.max(1) as f64;
    let baseline = if peer_baseline_per_sec.is_finite() && peer_baseline_per_sec > 0.0 {
        peer_baseline_per_sec
    } else {
        window.recip()
    };
    let vault_scale = (1.0 + vault_size as f64).sqrt();
    let ratio = (recent_writes as f64 / window) / baseline / vault_scale;
    NormalizedBurstInputs {
        rate_ratio: ratio.min(f64::from(f32::MAX)) as f32,
        streak,
    }
}

#[cfg(test)]
mod tests;

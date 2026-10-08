use super::*;

#[test]
fn signals_follow_peer_baseline_and_vault_growth_without_a_verdict() {
    let quiet = normalized_burst_inputs(60, 10, 0.1, 10, 7);
    let busy = normalized_burst_inputs(60, 10, 10.0, 10, 7);
    let grown = normalized_burst_inputs(60, 10, 0.1, 1_000, 7);
    assert!(quiet.rate_ratio > busy.rate_ratio);
    assert!(quiet.rate_ratio > grown.rate_ratio);
    assert_eq!(quiet.streak, 7);
    assert_eq!(busy.streak, 7);
    assert_eq!(grown.streak, 7);
}

#[test]
fn empty_history_invalid_baselines_and_extreme_counts_stay_finite() {
    for writes in [0, 1, u64::MAX] {
        for window in [0, 1, u64::MAX] {
            for baseline in [-1.0, 0.0, f64::NAN, f64::INFINITY, f64::MIN_POSITIVE, 1.0] {
                for size in [0, 1, u64::MAX] {
                    let signal = normalized_burst_inputs(writes, window, baseline, size, u32::MAX);
                    assert!(signal.rate_ratio.is_finite());
                    assert!(signal.rate_ratio >= 0.0);
                    assert_eq!(signal.streak, u32::MAX);
                    if writes == 0 {
                        assert_eq!(signal.rate_ratio, 0.0);
                    }
                }
            }
        }
    }
}

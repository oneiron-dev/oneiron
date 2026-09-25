//! Revision debounce clock precision.
use super::unix_millis_at;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn revision_clock_preserves_milliseconds_at_second_boundaries() {
    for millis in [1, 999, 1000, 1001, 1999] {
        assert_eq!(
            unix_millis_at(UNIX_EPOCH + Duration::from_millis(millis)),
            millis
        );
    }
    assert_eq!(unix_millis_at(UNIX_EPOCH - Duration::from_millis(1)), 0);
}

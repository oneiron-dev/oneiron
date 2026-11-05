//! The machine's original memory refusal in the core API error envelope.

use super::{ApiError, ApiErrorDetails};
use oneiron_contracts::host_memory::MemoryRefusal;

impl ApiError {
    pub(crate) fn memory_refused(refusal: MemoryRefusal) -> Self {
        let (message, details) = match refusal {
            MemoryRefusal::Floor { needed, available } => (
                "required memory does not fit this machine past its reserve",
                ApiErrorDetails::MemoryFloor { needed, available },
            ),
            MemoryRefusal::WaitedOut { needed, waited } => (
                "waiting for memory ended before admission",
                ApiErrorDetails::MemoryWaitedOut {
                    needed,
                    waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                },
            ),
        };
        Self::new(message, details, std::iter::empty::<&str>())
    }
}

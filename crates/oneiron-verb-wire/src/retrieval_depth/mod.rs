pub use crate::retrieval_depth::controls::RecallTelemetry;
pub use oneiron_store::retrieval_deadline::RetrievalDeadline;
#[cfg(any(test, feature = "test-hooks"))]
pub use oneiron_store::retrieval_deadline::SlowRetrievalStage;
#[cfg(any(test, feature = "test-hooks"))]
pub use oneiron_store::retrieval_deadline::still_deadline_clock_for_test;

pub mod controls;

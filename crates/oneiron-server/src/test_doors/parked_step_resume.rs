//! Door for `tests/model_step_health_rest.rs` (STEP-PARK-BOOT-RESUME), red
//! pin: main has no start pass that resumes the owner's parked model steps,
//! so the door does nothing, as main's serve start does.

use std::sync::Arc;

use crate::server::SyncServer;

/// Main resumes nothing at start.
pub fn resume_parked_model_steps(server: &Arc<SyncServer>) {
    let _ = server;
}

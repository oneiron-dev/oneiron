//! Door for `tests/model_step_health_rest.rs` (STEP-PARK-BOOT-RESUME): the
//! start pass that resumes the owner's parked model steps, as serve's
//! workers run it (`crate::api::resume_parked_model_steps`).

use std::sync::Arc;

use crate::server::SyncServer;

/// Resumes the owner's model steps parked before `server` started.
pub fn resume_parked_model_steps(server: &Arc<SyncServer>) {
    crate::api::resume_parked_model_steps(server);
}

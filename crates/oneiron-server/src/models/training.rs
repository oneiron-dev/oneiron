//! The trainer connectors `[models.training]` names (FIX 7263), as the
//! runtime keeps them for the host's training arm.
use super::ModelRuntime;
use crate::config::models::TrainingSettings;

impl ModelRuntime {
    /// The trainer connectors this host dispatches authorized training runs
    /// through; none without `[models]` or by default.
    #[must_use]
    pub fn training(&self) -> &TrainingSettings {
        &self.training
    }
}

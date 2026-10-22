//! The wording a run is asked for its confession in (OF-544, FIX 8696):
//! `[models.dreamer.wording]`'s, else the shipped default. The engine lists
//! the objectives before it and parses the answer; this host only words the
//! ask, for its workflow steps, its agent runs and the Dreamer's TASK
//! realizations alike.

use std::sync::Arc;

use super::AiHandle;
use crate::config::models::{DreamerWording, ModelsConfig};

/// The confession wording `models` configures; with no `[models]`, the
/// shipped default.
pub(super) fn of(models: Option<&ModelsConfig>) -> Arc<str> {
    models.map_or_else(
        || Arc::from(DreamerWording::default().confession()),
        |models| Arc::from(models.dreamer.wording.confession()),
    )
}

impl AiHandle {
    /// The wording an agent run's confession ask goes out in.
    pub(crate) fn confession_instruction(&self) -> &str {
        &self.confession
    }
}

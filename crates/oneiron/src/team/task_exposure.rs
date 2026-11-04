use crate::EntityId;
use serde::{Deserialize, Serialize};

/// One skill body the host put in a run's task, and where it went: the byte
/// span in the task, separator included, and the hash of those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskExposure {
    /// The entity whose body loaded.
    pub skill: EntityId,
    /// The revision that loaded, `skill_id@version`.
    pub revision: String,
    /// BLAKE3 of the task bytes in `start..end`.
    pub content_hash: [u8; 32],
    pub start: usize,
    pub end: usize,
}

impl TaskExposure {
    /// Appends `body` to `task` after `separator`, as a host puts a skill's
    /// body in a run's task, and returns where it went. A control fork
    /// removes the separator and the body together, leaving the task as it
    /// was before.
    #[must_use]
    pub fn append(
        task: &mut String,
        separator: &str,
        body: &str,
        skill: EntityId,
        revision: String,
    ) -> Self {
        let start = task.len();
        task.push_str(separator);
        task.push_str(body);
        let end = task.len();
        Self {
            skill,
            revision,
            content_hash: *blake3::hash(&task.as_bytes()[start..end]).as_bytes(),
            start,
            end,
        }
    }
}

//! `[models.sessions]`: early computation of a conversation's next turn on
//! this host's native model sessions (I1 = C, ARCH-0067 "exact early
//! computation"). Once a reply's canonical successor is published, the
//! session prefills, as background work, the part of the next turn already
//! known: the published path, then the state-only board. At send time the
//! turn's own tokens are compared with it and only the identical beginning
//! is reused; the rest is computed fresh. A stale tail is wasted work, never
//! a stale fact.
//!
//! The fixed policy runs by default. A learned planner sits beside it and
//! decides, per conversation, whether to prepare at all from what earlier
//! preparations gave; it is off until it beats the fixed policy on the real
//! machine (owner, 3 Nov).
//!
//! ```toml
//! [models.sessions]
//! prepare_tail = true
//! planner = "off"   # or "learned"
//! ```
use serde::Deserialize;

/// Whether the fixed policy prepares the next turn's tail when the config
/// says nothing.
pub const DEFAULT_PREPARE_TAIL: bool = true;

/// `[models.sessions]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionsFile {
    prepare_tail: Option<bool>,
    planner: Option<PlannerMode>,
}

/// Which decides whether a published session prepares its next turn's tail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerMode {
    /// The fixed policy alone.
    #[default]
    Off,
    /// The learned planner, over the fixed policy's own checks.
    Learned,
}

/// The resolved `[models.sessions]` policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPreparePolicy {
    /// Whether a published session prepares its next turn's tail at all.
    pub prepare_tail: bool,
    pub planner: PlannerMode,
}

impl Default for SessionPreparePolicy {
    fn default() -> Self {
        Self {
            prepare_tail: DEFAULT_PREPARE_TAIL,
            planner: PlannerMode::Off,
        }
    }
}

impl SessionsFile {
    pub(crate) fn resolve(self) -> SessionPreparePolicy {
        SessionPreparePolicy {
            prepare_tail: self.prepare_tail.unwrap_or(DEFAULT_PREPARE_TAIL),
            planner: self.planner.unwrap_or_default(),
        }
    }
}

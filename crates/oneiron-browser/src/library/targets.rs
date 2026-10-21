//! The elements a batch step names (CUA E6 split): a program names them by
//! locator, and its proposal's handles go back to locators here. A Fill's
//! references are texts, never elements.

use crate::BatchStep;

impl BatchStep {
    /// Every element the step names, by handle or locator.
    pub(super) fn targets(&self) -> Vec<&String> {
        match self {
            Self::Click { target }
            | Self::Type { target, .. }
            | Self::Select { target, .. }
            | Self::Fill { target, .. } => vec![target],
            Self::WaitFor { targets, .. } => targets.iter().collect(),
            Self::Expect { target, .. }
            | Self::Key { target, .. }
            | Self::Scroll { target, .. } => target.iter().collect(),
            Self::Decide(step) => step.targets.iter().collect(),
            Self::Open { .. } | Self::Screenshot { .. } | Self::Hotkey { .. } => Vec::new(),
        }
    }

    /// The same, to put back to locators.
    #[cfg(feature = "driver")]
    pub(super) fn targets_mut(&mut self) -> Vec<&mut String> {
        match self {
            Self::Click { target }
            | Self::Type { target, .. }
            | Self::Select { target, .. }
            | Self::Fill { target, .. } => vec![target],
            Self::WaitFor { targets, .. } => targets.iter_mut().collect(),
            Self::Expect { target, .. }
            | Self::Key { target, .. }
            | Self::Scroll { target, .. } => target.iter_mut().collect(),
            Self::Decide(step) => step.targets.iter_mut().collect(),
            Self::Open { .. } | Self::Screenshot { .. } | Self::Hotkey { .. } => Vec::new(),
        }
    }
}

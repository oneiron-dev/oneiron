//! The cancellation of one code step (FIX 600): a flag its owner sets and
//! its runtime reads, linked one way to the step that started it.
//!
//! A clone shares one flag. A child sees its own flag and every ancestor's,
//! so a cancelled step stops the steps it started; a child's cancel reaches
//! no ancestor and no sibling. Nothing here waits: a runtime reads the
//! token at its own checkpoints, and every loop that waits on a guest, a
//! host event or a foreign process waits in slices of [`CANCEL_POLL_SLICE`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::CodeError;
use crate::{Error, Result};

/// The longest a runtime waits before it reads its step's cancellation
/// again. It bounds the time from a cancel to the next check while the
/// waiting loop is runnable; it does not bound a host callback already
/// admitted, which settles first.
pub const CANCEL_POLL_SLICE: Duration = Duration::from_millis(10);

/// One link of a cancellation chain: its own flag and the link it was made
/// a child of.
#[derive(Debug)]
struct Link {
    cancelled: AtomicBool,
    parent: Option<Arc<Link>>,
}

/// The cancellation of one code step. Clones share it.
#[derive(Debug, Clone)]
pub struct StepCancellation {
    link: Option<Arc<Link>>,
}

impl StepCancellation {
    /// A root its holder may cancel.
    #[must_use]
    pub fn new() -> Self {
        Self::linked(None)
    }

    /// A root nothing cancels: the token of a step whose owner keeps no
    /// handle on it. Its child is a real token all the same.
    #[must_use]
    pub const fn never() -> Self {
        Self { link: None }
    }

    /// A token of its own, cancelled with this one or by itself.
    #[must_use]
    pub fn child(&self) -> Self {
        Self::linked(self.link.clone())
    }

    fn linked(parent: Option<Arc<Link>>) -> Self {
        Self {
            link: Some(Arc::new(Link {
                cancelled: AtomicBool::new(false),
                parent,
            })),
        }
    }

    /// Cancels this token and every token made a child of it. A
    /// [`Self::never`] token has nothing to cancel.
    pub fn cancel(&self) {
        if let Some(link) = &self.link {
            link.cancelled.store(true, Ordering::Release);
        }
    }

    /// Whether this token or any token it descends from is cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        let mut link = self.link.as_deref();
        while let Some(current) = link {
            if current.cancelled.load(Ordering::Acquire) {
                return true;
            }
            link = current.parent.as_deref();
        }
        false
    }

    /// The step's checkpoint.
    ///
    /// # Errors
    ///
    /// [`CodeError::CodeStepCancelled`] once the step is cancelled.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(Error::Code(CodeError::CodeStepCancelled));
        }
        Ok(())
    }
}

impl Default for StepCancellation {
    fn default() -> Self {
        Self::new()
    }
}

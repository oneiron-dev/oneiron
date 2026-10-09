//! Pass-scoped host attachments: work a host serves alongside one wake pass.
//!
//! The supervisor knows nothing about what an attachment does. A host (the
//! server's voice adapter is one) hands the factory a [`PassAttachmentSource`];
//! each pass asks it for an attachment AFTER the pass meter exists, so the
//! attached work spends the same budget as the pass it rides. A refusal stops
//! the pass before any attempt is admitted.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oneiron::{BudgetGuard, LlmBackend, Result, Vault, WakePassReport};

/// The engine's wake pass, unpolled, as handed to an attachment.
pub type WakePassFuture<'p> = Pin<Box<dyn Future<Output = Result<WakePassReport>> + 'p>>;

/// An attachment's join: the pass result beside the attachment's own outcome.
pub type AttachedPassFuture<'p> =
    Pin<Box<dyn Future<Output = (Result<WakePassReport>, std::result::Result<(), String>)> + 'p>>;

/// One claimed attachment for one pass.
pub trait PassAttachment {
    /// Serves alongside `pass` and must drive `pass` to completion: the pass
    /// is never dropped mid-await (H-S5/R2), so neither may its wrapper.
    fn serve<'p>(self: Box<Self>, pass: WakePassFuture<'p>) -> AttachedPassFuture<'p>;
}

/// Host configuration that may attach work to each pass.
pub trait PassAttachmentSource: Send {
    /// `Ok(None)` attaches nothing this pass. An error refuses the pass
    /// before admission. `backend` is the factory's own backend allocation.
    fn attach(
        &self,
        vault: &Vault,
        backend: &Arc<dyn LlmBackend>,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>>;

    /// A lifecycle signal the attachment's host owns. The supervisor links it
    /// both ways with its own shutdown: either one stops both.
    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        None
    }
}

/// A host-owned stop signal the supervisor honours beside its own handle.
pub trait LinkedShutdown: Send + Sync {
    /// Trips the signal. Idempotent.
    fn trigger(&self);

    fn is_triggered(&self) -> bool;

    /// Resolves once tripped, including when tripped before the call.
    fn triggered(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

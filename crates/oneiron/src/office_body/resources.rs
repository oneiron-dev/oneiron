//! The host's document memory (Rule 5; FIX 8569, 8574, 8596, 8598, 9617).
//!
//! Every office read and edit the engine runs reserves the memory its
//! package and XML representations take before it allocates them, through
//! one operation's [`Resources`]. A host with a machine memory line
//! registers it here once ([`register_document_memory`]); the server binds
//! its own line. Each document operation then takes its port from
//! [`document_resources`]: a reservation that cannot be met at once waits
//! its fair turn for the host's queue wait, and only then refuses typed. A
//! process without a registered host (a command line, a test) measures and
//! reserves nothing, as before.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use oneiron_docedit::resource::{ResourcePort, ResourceRefusal, Resources};

/// A host's machine memory, as document operations take it: one port per
/// operation.
pub trait DocumentMemory: Send + Sync {
    /// The port of one operation. `deadline` is one the caller itself gave
    /// the operation, when it has one: the port's checkpoint stops the work
    /// at it, and without one never does.
    fn operation(&self, deadline: Option<Instant>) -> Arc<dyn ResourcePort>;
}

static DOCUMENT_MEMORY: OnceLock<Arc<dyn DocumentMemory>> = OnceLock::new();

/// Registers the host's document memory, once per process.
///
/// # Errors
/// When one is registered already.
pub fn register_document_memory(memory: Arc<dyn DocumentMemory>) -> Result<(), &'static str> {
    DOCUMENT_MEMORY
        .set(memory)
        .map_err(|_| "document memory is already registered")
}

/// The port of one document operation without a deadline of its caller's:
/// the registered host's, else the measuring port.
#[must_use]
pub fn document_resources() -> Resources {
    document_resources_until(None)
}

/// [`document_resources`] for an operation whose caller gave it `deadline`.
#[must_use]
pub fn document_resources_until(deadline: Option<Instant>) -> Resources {
    DOCUMENT_MEMORY
        .get()
        .map_or_else(Resources::measuring, |memory| {
            Resources::new(memory.operation(deadline))
        })
}

/// A refusal of a document operation's memory as the engine's error, never
/// an invalid document: the machine's floor as the typed memory-floor
/// refusal the engine already answers decks with, and a wait or deadline
/// that ran out as a timed-out read, which a caller may run again.
pub(crate) fn document_refused(refusal: ResourceRefusal) -> crate::error::Error {
    match refusal {
        ResourceRefusal::MemoryFloor { .. } => {
            crate::error::Error::Artifact(crate::error::ArtifactError::LiveDeckRefused {
                refusal: crate::error::LiveDeckRefusal::MemoryFloor,
                detail: refusal.to_string(),
                nodes: Vec::new(),
            })
        }
        ResourceRefusal::Deadline => crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            refusal.to_string(),
        )),
    }
}

/// A DOCX read's or projection's failure as the engine's error: a resource
/// refusal as itself ([`document_refused`]), a ceiling the package passed as
/// a refusal naming it (FIX 5354), any other one invalid under `message`.
pub(crate) fn docx_error(
    error: &oneiron_docedit::DoceditError,
    message: &str,
) -> crate::error::Error {
    if let Some(refusal) = error.resource() {
        return document_refused(refusal);
    }
    error.parse_limit_refusal().map_or_else(
        || super::invalid(message),
        |refusal| crate::error::Error::Refused(refusal.to_owned()),
    )
}

/// A document read's failure as the engine's error: a resource refusal as
/// itself ([`document_refused`]), any other one invalid under `message`.
pub(crate) fn document_error(
    refusal: Option<ResourceRefusal>,
    message: &str,
) -> crate::error::Error {
    refusal.map_or_else(|| super::invalid(message), document_refused)
}

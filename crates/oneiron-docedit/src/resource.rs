//! The memory one document operation reserves before it allocates, and the
//! deadline it runs within (Rule 5; FIX 8569, 8574, 8596, 8598).
//!
//! A count in a document (XML nodes and attributes, namespaces, depth, ZIP
//! entries, SVG segments and outline points) is an observation, never a
//! reason to stop. What the work costs is memory: each reader reserves the
//! bytes its representation takes through the operation's [`ResourcePort`]
//! before it allocates them, and long work asks the port at its checkpoints
//! whether the operation's deadline has passed. The port refuses only at a
//! real machine floor or that deadline, typed as [`ResourceRefusal`], and
//! every error of this crate carries the refusal as its own variant, never
//! as a malformed document.
//!
//! A host implements the port over its machine memory line: a reservation
//! that cannot be met at once waits its fair turn for the host's existing
//! queue wait, and only then refuses; a checkpoint stops work only at a
//! deadline the caller itself gave the operation. A caller without a host
//! passes [`Resources::measuring`], over [`MeasuringPort`]: it measures, and
//! reserves and refuses nothing.
//!
//! [`Resources`] is one operation's handle on its port, shared by its
//! clones: a package keeps it for its later reads, edits and copies, and a
//! standalone XML or DOCX root takes and forwards it. A [`Hold`] reserves
//! the bytes of one allocation, or of one growing structure, before they
//! are allocated, and lasts until they are: from then on the machine's live
//! reading shows them in use, as the host's memory line counts a reservation
//! named allocated (its pending bytes, FIX 8240), so nothing is counted
//! twice while it lives.

use std::fmt;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The least one reservation asks its port for, so a reader does not ask
/// once per node: what a hold has left serves the next allocations.
/// Reserved, never a bound: nothing is refused for its size.
pub const RESERVE_STEP: u64 = 1 << 20;

/// Why the work's memory was not reserved, or why the work stopped.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, thiserror::Error,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceRefusal {
    /// The machine cannot hold `needed` more bytes: past the memory it keeps
    /// free and every other holder, it has `available` at most.
    #[error("the machine's memory floor: {needed} bytes needed, {available} available")]
    MemoryFloor { needed: u64, available: u64 },
    /// The host's wait for memory ran out, or a deadline the caller gave
    /// the operation passed. A caller may ask again.
    #[error("the work's resource wait or deadline passed")]
    Deadline,
}

/// One operation's port to the memory it runs in and the deadline it runs
/// within. A host answers it from its machine memory line; a caller without
/// one uses [`MeasuringPort`].
pub trait ResourcePort: Send + Sync {
    /// Reserves `bytes` more, before they are allocated, waiting its fair
    /// turn for room as long as the host waits for one. What it returns
    /// holds them; dropping it gives them back.
    ///
    /// # Errors
    /// The machine's floor, or the wait running out.
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, ResourceRefusal>;

    /// A cooperative checkpoint between units of long work.
    ///
    /// # Errors
    /// [`ResourceRefusal::Deadline`] once a deadline the caller itself gave
    /// the operation passed; without one, never.
    fn checkpoint(&self) -> Result<(), ResourceRefusal>;
}

/// The port of a caller without a host (a command line, an example, the
/// contract served without a host port). It measures each reservation
/// against the memory the machine has free now and keeps the largest
/// shortfall it saw as an observation, but it reserves nothing and refuses
/// nothing: such a caller had no memory refusal before, and has none now
/// (Engine 10-22 14:1x). It has no deadline of its own.
#[derive(Debug, Default)]
pub struct MeasuringPort {
    /// The most bytes one reservation asked past the free memory read then.
    shortfall: std::sync::atomic::AtomicU64,
}

impl MeasuringPort {
    /// The most bytes one reservation asked past the machine's free memory.
    #[must_use]
    pub fn shortfall(&self) -> u64 {
        self.shortfall.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ResourcePort for MeasuringPort {
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, ResourceRefusal> {
        if let Some(free) = oneiron_contracts::limit_ask::available_memory_bytes() {
            self.shortfall.fetch_max(
                bytes.saturating_sub(free),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(Box::new(()))
    }

    fn checkpoint(&self) -> Result<(), ResourceRefusal> {
        Ok(())
    }
}

/// Bytes reserved from one port: grown by each [`Self::take`], in steps of
/// at least [`RESERVE_STEP`], and given back whole when it drops.
#[must_use = "a hold gives its memory back as soon as it drops"]
pub struct Hold {
    port: Arc<dyn ResourcePort>,
    /// Reserved, and not yet taken by an allocation.
    spare: u64,
    held: Vec<Box<dyn Send + Sync>>,
}

impl Hold {
    /// Takes `bytes` about to be allocated: from what this hold has left, or
    /// reserved first.
    ///
    /// # Errors
    /// The port's refusal; the hold stays as it was.
    pub fn take(&mut self, bytes: u64) -> Result<(), ResourceRefusal> {
        if bytes <= self.spare {
            self.spare -= bytes;
            return Ok(());
        }
        let step = (bytes - self.spare).max(RESERVE_STEP);
        self.held.push(self.port.reserve(step)?);
        self.spare = self.spare.saturating_add(step).saturating_sub(bytes);
        Ok(())
    }

    /// Takes the bytes of `len` values of `T`, about to be allocated.
    ///
    /// # Errors
    /// As [`Self::take`].
    pub fn take_len<T>(&mut self, len: usize) -> Result<(), ResourceRefusal> {
        self.take(bytes_of::<T>(len))
    }
}

impl fmt::Debug for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hold")
            .field("reservations", &self.held.len())
            .field("spare", &self.spare)
            .finish()
    }
}

/// One operation's handle on its port. Clones share the port.
#[derive(Clone)]
pub struct Resources {
    port: Arc<dyn ResourcePort>,
}

impl Resources {
    /// The handle of one operation over `port`.
    #[must_use]
    pub fn new(port: Arc<dyn ResourcePort>) -> Self {
        Self { port }
    }

    /// The handle of a caller without a host, over [`MeasuringPort`]: it
    /// measures, and reserves and refuses nothing.
    #[must_use]
    pub fn measuring() -> Self {
        Self::new(Arc::new(MeasuringPort::default()))
    }

    /// Reserves `bytes` one allocation is about to take; the hold it
    /// returns lasts until the caller drops it, once the bytes exist.
    ///
    /// # Errors
    /// The port's refusal.
    pub fn reserve(&self, bytes: u64) -> Result<Hold, ResourceRefusal> {
        let mut hold = self.hold();
        hold.take(bytes)?;
        Ok(hold)
    }

    /// An empty reservation of its own over this operation's port.
    pub fn hold(&self) -> Hold {
        Hold {
            port: Arc::clone(&self.port),
            spare: 0,
            held: Vec::new(),
        }
    }

    /// The operation's checkpoint.
    ///
    /// # Errors
    /// [`ResourceRefusal::Deadline`] once the operation's deadline passed.
    pub fn checkpoint(&self) -> Result<(), ResourceRefusal> {
        self.port.checkpoint()
    }
}

impl fmt::Debug for Resources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resources").finish_non_exhaustive()
    }
}

/// The bytes of `len` values of `T`, saturated.
#[must_use]
pub fn bytes_of<T>(len: usize) -> u64 {
    u64::try_from(len.saturating_mul(std::mem::size_of::<T>())).unwrap_or(u64::MAX)
}

/// `bytes` as reserved, saturated.
#[must_use]
pub fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

// Where each error of this crate carries a refusal, so a mapper names it as
// itself (the contract's memory_floor and resource_deadline), never as an
// invalid document or a refused edit.

impl crate::deck::DeckError {
    /// The refusal, when memory or a deadline stopped the read.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Package(error) => error.resource(),
            Self::Xml(error) => error.resource(),
            Self::Invalid(_) => None,
        }
    }
}

impl crate::edit::EditRefusal {
    /// The refusal, when memory or a deadline stopped the edit.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Picture(error) => error.resource(),
            Self::Package(error) => error.resource(),
            Self::Xml(error) => error.resource(),
            Self::Deck(error) => error.resource(),
            _ => None,
        }
    }
}

impl crate::native_patch::NativeRefusal {
    /// The refusal, when memory or a deadline stopped the edit.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Workbook(error) | Self::Package(error) => error.resource(),
            Self::Xml(error) => error.resource(),
            _ => None,
        }
    }
}

impl crate::edit::transaction::TransactionError {
    /// The refusal, when memory or a deadline stopped the transaction.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        use crate::edit::transaction::StepRefusal;
        match self {
            Self::Step { refusal, .. } => match refusal {
                StepRefusal::Edit(error) => error.resource(),
                StepRefusal::Native(error) => error.resource(),
                StepRefusal::Asset(_) => None,
            },
            Self::Package(error) => error.resource(),
            Self::Deck(error) => error.resource(),
            _ => None,
        }
    }
}

impl crate::emit::EmitError {
    /// The refusal, when memory or a deadline stopped the deck's creation.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Graphic { error, .. } => error.resource(),
            Self::Native { refusal, .. } => refusal.resource(),
            Self::Package(error) => error.resource(),
            Self::Xml(error) => error.resource(),
            Self::Deck(error) => error.resource(),
            _ => None,
        }
    }
}

impl crate::xlsx_body::XlsxBodyError {
    /// The refusal, when memory or a deadline stopped the workbook's read.
    #[must_use]
    pub fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Package(error) => error.resource(),
            Self::Xml(error) => error.resource(),
            Self::Refused(_) => None,
        }
    }
}

//! The memory one DOCX operation reserves before it allocates, and the
//! deadline it runs within (Rule 5; FIX 8570).
//!
//! A count in a package (ZIP entries, XML nodes) is an observation, never a
//! reason to stop. What a read costs is memory: the archive reader reserves
//! each entry's record, name and bytes, and parse admission the bytes of the
//! trees the parts build, through the operation's [`MemoryPort`] before they
//! are allocated; both ask the port at each part whether the operation's
//! deadline has passed. The port refuses only at a real machine floor or that
//! deadline, typed as [`Refusal`].
//!
//! A host hands its port in with [`Operation::run`]: every archive read and
//! parse the work runs on its thread reserves through that port, under the
//! operation's archive limits, and so does work it hands another thread that
//! re-enters the operation ([`Operation::current`], then `run` there). Outside
//! an operation, or without a port, a read reserves nothing and refuses
//! nothing, as the standalone fork always has, under
//! [`ArchiveLimits::DEFAULT`] unless the operation names its own.

use std::cell::RefCell;
use std::fmt;
use std::sync::Arc;

use crate::docx::ArchiveLimits;

/// The least one reservation asks its port for, so a reader does not ask
/// once per node: what a hold has left serves the next allocations. Reserved,
/// never a bound, and never measured: the port sees only the measured need.
pub const RESERVE_STEP: u64 = 1 << 20;

/// Why the work's memory was not reserved, or why the work stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The machine cannot hold `needed` more measured bytes: past the memory
    /// it keeps free and every other holder, it has `available` at most.
    MemoryFloor { needed: u64, available: u64 },
    /// The host's wait for memory ran out, or a deadline the caller gave the
    /// operation passed. A caller may ask again.
    Deadline,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryFloor { needed, available } => write!(
                f,
                "the machine's memory floor: {needed} bytes needed, {available} available"
            ),
            Self::Deadline => f.write_str("the work's resource wait or deadline passed"),
        }
    }
}

impl std::error::Error for Refusal {}

/// One operation's port to the memory it runs in and the deadline it runs
/// within.
pub trait MemoryPort: Send + Sync {
    /// Reserves `bytes` more, before they are allocated, waiting its fair
    /// turn for room as long as the host waits for one. `measured` of them
    /// the work measured it needs; the rest is its estimate (a declared ZIP
    /// size, a tree's node overhead, a reservation step), which never meets
    /// the machine's floor at once. What it returns holds them; dropping it
    /// gives them back.
    ///
    /// # Errors
    /// The machine's floor, or the wait running out.
    fn reserve(&self, bytes: u64, measured: u64) -> Result<Box<dyn Send + Sync>, Refusal>;

    /// A cooperative checkpoint between units of long work.
    ///
    /// # Errors
    /// [`Refusal::Deadline`] once a deadline the caller itself gave the
    /// operation passed; without one, never.
    fn checkpoint(&self) -> Result<(), Refusal>;
}

/// The operation DOCX work runs in: its port, when a host gave one, and the
/// archive limits its reads run under. Clones share the port.
#[derive(Clone, Default)]
pub struct Operation {
    port: Option<Arc<dyn MemoryPort>>,
    limits: Option<ArchiveLimits>,
}

thread_local! {
    static CURRENT: RefCell<Operation> = RefCell::new(Operation::default());
}

impl Operation {
    /// The operation this thread runs in; outside any, the standalone one.
    #[must_use]
    pub fn current() -> Self {
        CURRENT.with(|current| current.borrow().clone())
    }

    /// This operation over `port`.
    #[must_use]
    pub fn with_port(mut self, port: Arc<dyn MemoryPort>) -> Self {
        self.port = Some(port);
        self
    }

    /// This operation, its reads under `limits`.
    #[must_use]
    pub fn with_limits(mut self, limits: ArchiveLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Runs `work` in this operation, then gives the thread back the one it
    /// ran in before, also when `work` panics.
    pub fn run<T>(self, work: impl FnOnce() -> T) -> T {
        struct Restore(Option<Operation>);
        impl Drop for Restore {
            fn drop(&mut self) {
                if let Some(previous) = self.0.take() {
                    CURRENT.with(|current| *current.borrow_mut() = previous);
                }
            }
        }
        let previous = CURRENT.with(|current| current.replace(self));
        let _restore = Restore(Some(previous));
        work()
    }

    /// The archive limits this operation's reads run under: its own, else
    /// [`ArchiveLimits::DEFAULT`].
    #[must_use]
    pub fn limits(&self) -> ArchiveLimits {
        self.limits.unwrap_or(ArchiveLimits::DEFAULT)
    }

    /// The operation's checkpoint.
    ///
    /// # Errors
    /// [`Refusal::Deadline`] once the operation's deadline passed.
    pub fn checkpoint(&self) -> Result<(), Refusal> {
        self.port.as_ref().map_or(Ok(()), |port| port.checkpoint())
    }

    /// An empty reservation of its own over this operation's port.
    #[must_use]
    pub fn hold(&self) -> Hold {
        Hold {
            port: self.port.clone(),
            spare: 0,
            held: Vec::new(),
        }
    }
}

impl fmt::Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Operation")
            .field("port", &self.port.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

/// Bytes reserved from one operation's port: grown by each take, in steps of
/// at least [`RESERVE_STEP`], and given back whole when it drops. Once the
/// bytes it held are allocated, the machine's live reading carries them.
#[must_use = "a hold gives its memory back as soon as it drops"]
#[derive(Default)]
pub struct Hold {
    port: Option<Arc<dyn MemoryPort>>,
    /// Reserved, and not yet taken by an allocation.
    spare: u64,
    held: Vec<Box<dyn Send + Sync>>,
}

impl Hold {
    /// Takes `bytes` about to be allocated, all of them measured.
    ///
    /// # Errors
    /// The port's refusal; the hold stays as it was.
    pub fn take(&mut self, bytes: u64) -> Result<(), Refusal> {
        self.take_estimate(bytes, bytes)
    }

    /// Takes `bytes` about to be allocated, of which the work measured only
    /// `measured`: from what this hold has left, or reserved first. What the
    /// hold has left serves the estimate first, so only measured bytes past
    /// it reach the port as measured.
    ///
    /// # Errors
    /// The port's refusal; the hold stays as it was.
    pub fn take_estimate(&mut self, bytes: u64, measured: u64) -> Result<(), Refusal> {
        let Some(port) = &self.port else {
            return Ok(());
        };
        if bytes <= self.spare {
            self.spare -= bytes;
            return Ok(());
        }
        let need = bytes - self.spare;
        let measured = measured.min(bytes).saturating_sub(self.spare).min(need);
        let step = need.max(RESERVE_STEP);
        self.held.push(port.reserve(step, measured)?);
        self.spare = self.spare.saturating_add(step).saturating_sub(bytes);
        Ok(())
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

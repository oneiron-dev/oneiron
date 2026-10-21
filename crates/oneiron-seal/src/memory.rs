//! Memory the native seal reserves before its PDF decodes allocate it
//! (FIX 7654).
//!
//! Before a decode allocates or grows a buffer, the vendored lopdf asks its
//! `DecodeAdmission` hook for the bytes; here that hook is one operation's
//! [`MemoryLedger`] over the [`SealMemory`] service the configuration names
//! ([`SealMemoryProvider`]). Each seal and each verification is one
//! operation with a ledger of its own, opened before it parses anything. The
//! ledger reserves at least [`RESERVE_STEP`] at a time and serves smaller
//! admissions from what it has left. It never gives anything back while its
//! operation runs: it holds the sum of every allocation the operation's
//! decodes asked for, not only what is live, which is sound and
//! conservative. Everything it reserved goes back when the operation ends.
//!
//! A refusal is typed: the machine's memory floor or a deadline, or a
//! cancelled call or a service that cannot answer. It is never a count or a
//! size of the seal's own, and never reads as a malformed PDF.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lopdf::{DecodeAdmission, DecodeAdmissionError};

use crate::api::{Counter, SealObservations, SealResourceLimits};
use crate::error::{FatalCode, RetryableCode, SealError, SealStage};

/// The least a ledger reserves from its service at once, so an operation
/// does not ask once per small allocation: an admission the ledger cannot
/// serve from what it has left reserves the larger of this and what it
/// lacks. Reserved, never a bound: nothing is refused for its size.
pub(crate) const RESERVE_STEP: u64 = 4 * 1024 * 1024;

/// A real memory service the native seal reserves from before it
/// allocates: in the organ, the engine host's machine memory floor
/// (`memory.grow`); in another embedder, its own live service. Without one,
/// a native engine does not start.
pub trait SealMemory: Send + Sync {
    /// Reserves `bytes` more, before they are allocated. What it returns
    /// holds them; dropping it gives them back. It may wait, within the
    /// service's own deadline.
    ///
    /// # Errors
    /// The service's typed refusal.
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send>, SealMemoryRefusal>;
}

/// Why memory was not reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealMemoryRefusal {
    /// The machine cannot hold `needed` bytes: past the memory it keeps
    /// free, it has `available` for them at most.
    #[error("the machine's memory floor: {needed} bytes needed, {available} available")]
    Floor { needed: u64, available: u64 },
    /// The bytes did not fit before the deadline.
    #[error("the wait for memory passed its deadline")]
    Deadline,
    /// The call was cancelled while the reservation waited.
    #[error("the call was cancelled while it waited for memory")]
    Cancelled,
    /// The service could not answer this time; it may if asked again.
    #[error("the memory service could not answer")]
    Failed,
    /// No memory service answers: none is configured, or none is granted.
    #[error("no memory service is configured")]
    Unavailable,
}

impl SealMemoryRefusal {
    /// The seal's error at `stage`: the floor and the deadline retryable
    /// under their own codes; a service that cannot be asked a
    /// configuration error.
    pub(crate) fn seal_error(self, stage: SealStage) -> SealError {
        let retryable = |code| SealError::Retryable {
            stage,
            code,
            retry_after_ms: None,
        };
        match self {
            Self::Floor { .. } => retryable(RetryableCode::MemoryFloor),
            Self::Deadline => retryable(RetryableCode::ResourceDeadline),
            Self::Cancelled => retryable(RetryableCode::IoInterrupted),
            Self::Failed => retryable(RetryableCode::ResourceBusy),
            Self::Unavailable => SealError::Fatal {
                stage,
                code: FatalCode::InvalidConfiguration,
            },
        }
    }

    /// lopdf's own refusal: an allocator that refused bytes the ledger had
    /// admitted is the floor with nothing available.
    fn of_decode(err: &DecodeAdmissionError) -> Self {
        match err {
            DecodeAdmissionError::MemoryFloor { needed, available } => Self::Floor {
                needed: *needed,
                available: *available,
            },
            DecodeAdmissionError::Deadline => Self::Deadline,
            DecodeAdmissionError::Cancelled => Self::Cancelled,
        }
    }

    /// As lopdf carries it. lopdf has no word for a service that cannot
    /// answer: the ledger keeps the refusal itself, and reads it back.
    fn to_decode(self) -> DecodeAdmissionError {
        match self {
            Self::Floor { needed, available } => {
                DecodeAdmissionError::MemoryFloor { needed, available }
            }
            Self::Deadline => DecodeAdmissionError::Deadline,
            Self::Cancelled | Self::Failed | Self::Unavailable => DecodeAdmissionError::Cancelled,
        }
    }
}

/// The memory service a [`SealResourceLimits`] names, and, on the limits one
/// operation runs under, that operation's ledger. Clones share both. Two are
/// equal when they name the same service and the same ledger. The default
/// names no service: a native engine refuses to start on it.
#[derive(Clone, Default)]
pub struct SealMemoryProvider {
    service: Option<Arc<dyn SealMemory>>,
    ledger: Option<Arc<MemoryLedger>>,
}

impl SealMemoryProvider {
    /// The provider over `service`.
    #[must_use]
    pub fn new(service: Arc<dyn SealMemory>) -> Self {
        Self {
            service: Some(service),
            ledger: None,
        }
    }

    /// Whether a service is configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.service.is_some()
    }

    /// The ledger of the operation these limits run under.
    ///
    /// # Errors
    /// [`SealMemoryRefusal::Unavailable`] outside an operation, where no
    /// ledger was opened: nothing is decoded unreserved.
    pub(crate) fn ledger(&self) -> Result<Arc<MemoryLedger>, SealMemoryRefusal> {
        self.ledger.clone().ok_or(SealMemoryRefusal::Unavailable)
    }

    /// Admits `len` values of `T`, about to be allocated, to the operation's
    /// ledger.
    pub(crate) fn admit<T>(&self, len: usize) -> Result<(), SealMemoryRefusal> {
        self.ledger()?.admit_len::<T>(len)
    }
}

impl fmt::Debug for SealMemoryProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealMemoryProvider")
            .field("configured", &self.service.is_some())
            .field("operation", &self.ledger.is_some())
            .finish()
    }
}

impl PartialEq for SealMemoryProvider {
    fn eq(&self, other: &Self) -> bool {
        let service = match (&self.service, &other.service) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        let ledger = match (&self.ledger, &other.ledger) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        service && ledger
    }
}

impl Eq for SealMemoryProvider {}

impl SealResourceLimits {
    /// These limits for one operation: the same bounds and counts, and a
    /// fresh ledger over the configured memory service, which the operation
    /// holds until it ends.
    ///
    /// # Errors
    /// A configuration error at `stage` when no memory service is
    /// configured, before anything is parsed.
    pub(crate) fn operation(&self, stage: SealStage) -> Result<Self, SealError> {
        let Some(service) = &self.memory.service else {
            return Err(SealMemoryRefusal::Unavailable.seal_error(stage));
        };
        let ledger = MemoryLedger {
            service: Arc::clone(service),
            observed: self.observed.clone(),
            state: Mutex::default(),
        };
        Ok(Self {
            memory: SealMemoryProvider {
                service: Some(Arc::clone(service)),
                ledger: Some(Arc::new(ledger)),
            },
            ..self.clone()
        })
    }
}

/// One operation's reservations: grown by every admission, never shrunk
/// while the operation runs, and given back whole when the last of the
/// operation's handles drops. It is lopdf's `DecodeAdmission` for every
/// decode the operation runs.
pub(crate) struct MemoryLedger {
    service: Arc<dyn SealMemory>,
    /// Where each finished decode's length goes.
    observed: SealObservations,
    state: Mutex<LedgerState>,
}

#[derive(Default)]
struct LedgerState {
    /// Reserved, and not yet admitted to an allocation.
    spare: u64,
    /// What the service holds for each reservation.
    held: Vec<Box<dyn Send>>,
    /// The refusal that ended an admission. Every later admission refuses
    /// with it, so the operation cannot go on half refused.
    refused: Option<SealMemoryRefusal>,
}

impl MemoryLedger {
    /// Admits `bytes` about to be allocated: from what the ledger has left,
    /// or reserved first, at least [`RESERVE_STEP`] at a time.
    pub(crate) fn take(&self, bytes: u64) -> Result<(), SealMemoryRefusal> {
        let mut state = lock(&self.state);
        if let Some(refused) = state.refused {
            return Err(refused);
        }
        if bytes <= state.spare {
            state.spare -= bytes;
            return Ok(());
        }
        let step = (bytes - state.spare).max(RESERVE_STEP);
        match self.service.reserve(step) {
            Ok(held) => {
                state.held.push(held);
                state.spare = state.spare.saturating_add(step) - bytes;
                Ok(())
            }
            Err(refusal) => {
                state.refused = Some(refusal);
                Err(refusal)
            }
        }
    }

    /// Admits `len` values of `T`, about to be allocated.
    pub(crate) fn admit_len<T>(&self, len: usize) -> Result<(), SealMemoryRefusal> {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        self.take(u64::try_from(bytes).unwrap_or(u64::MAX))
    }

    /// Whether memory refused the decode that failed with `err`, and how:
    /// the refusal this ledger kept (the service's own words, which lopdf's
    /// error cannot carry), else lopdf's. A refusal is never read as a
    /// malformed PDF.
    pub(crate) fn refusal_of(&self, err: &lopdf::Error) -> Option<SealMemoryRefusal> {
        let kept = lock(&self.state).refused;
        match err {
            lopdf::Error::DecodeAdmission(admission) => {
                Some(kept.unwrap_or_else(|| SealMemoryRefusal::of_decode(admission)))
            }
            _ => kept,
        }
    }
}

impl DecodeAdmission for MemoryLedger {
    fn admit(&self, bytes: usize) -> Result<(), DecodeAdmissionError> {
        self.take(u64::try_from(bytes).unwrap_or(u64::MAX))
            .map_err(SealMemoryRefusal::to_decode)
    }

    fn decoded(&self, bytes: usize) {
        self.observed.note(Counter::StreamDecodeBytes, bytes);
    }
}

/// The ledger changes in one step under its lock, so a holder that panicked
/// left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

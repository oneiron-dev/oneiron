//! Memory the native seal reserves before its PDF decodes allocate it
//! (FIX 7654).
//!
//! Before a decode allocates or grows a buffer, the vendored lopdf asks its
//! `DecodeAdmission` hook for the bytes; here that hook is one operation's
//! [`MemoryLedger`] over the [`SealMemory`] service the configuration names
//! ([`SealMemoryProvider`]). Each seal and each verification is one
//! operation with a ledger of its own, opened before it parses anything. The
//! ledger reserves at least [`RESERVE_STEP`] at a time and serves smaller
//! admissions from what it has left. A replacement is admitted at its full
//! size while the old buffer is still alive, and the old bytes go back only
//! after the new allocation succeeds, so simultaneous peaks stay charged;
//! what a finished parse pass held ([`LedgerPass`]) returns to what it has
//! left for the operation's later admissions (FIX 8448). A copy the seal
//! keeps past a pass takes a [`LedgerHold`] before it is made, and its bytes
//! return when the hold drops with its copy (FIX 12260). Everything reserved
//! goes back to the service when the operation ends.
//!
//! A refusal is typed: the machine's memory floor or a deadline, or a
//! cancelled call or a service that cannot answer. It is never a count or a
//! size of the seal's own, and never reads as a malformed PDF.
//!
//! Fetched bytes (FIX 7655) can outlive the operation that fetched them: a
//! response a caller keeps, the fetcher's cache, a CRL gathered for the DSS.
//! They reserve from the same service, but each owner takes a [`Lease`] of
//! its own rather than the operation's ledger: [`AdmittedBytes`], shared as
//! [`SharedBytes`], holds its buffer and its lease together, and gives both
//! back when its last owner drops it.

use std::fmt;
use std::ops::Deref;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lopdf::{DecodeAdmission, DecodeAdmissionError};

use crate::api::{Counter, SealObservations, SealResourceLimits};
pub(crate) use crate::buffers::{AdmittedBytes, AdmittedStr, SharedBytes, SharedStr};
pub(crate) use crate::buffers::{Lease, SHARED_CONTROL_BYTES};
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

    /// A parse pass over the operation's ledger (FIX 8448); none outside an
    /// operation. Open it before a load whose document, and every buffer its
    /// decodes made, drops before the pass does.
    pub(crate) fn pass(&self) -> Option<LedgerPass> {
        let ledger = self.ledger.clone()?;
        let opened_at = lock(&ledger.state).live;
        Some(LedgerPass { ledger, opened_at })
    }

    /// Holds `bytes` for one copy the seal keeps on the operation's ledger,
    /// until the hold drops with the copy (FIX 12260).
    ///
    /// # Errors
    /// [`SealMemoryRefusal::Unavailable`] outside an operation; else the
    /// ledger's refusal.
    pub(crate) fn hold(&self, bytes: usize) -> Result<LedgerHold, SealMemoryRefusal> {
        self.ledger()?.hold(bytes)
    }

    /// Reserves `bytes` from the configured service for an owner that may
    /// outlive any one operation (a fetched body, a cache entry): the
    /// reservation is the owner's, not an operation ledger's, and goes back
    /// when the owner drops it. It may wait, within the service's own
    /// deadline. No bytes ask for nothing.
    ///
    /// # Errors
    /// [`SealMemoryRefusal::Unavailable`] when no service is configured;
    /// else the service's refusal.
    pub(crate) fn lease(&self, bytes: usize) -> Result<Lease, SealMemoryRefusal> {
        let service = self
            .service
            .as_ref()
            .ok_or(SealMemoryRefusal::Unavailable)?;
        let held: Box<dyn Send> = if bytes == 0 {
            Box::new(())
        } else {
            service.reserve(wide(bytes))?
        };
        Ok(Lease::new(held))
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
            state: Arc::default(),
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

/// One operation's reservations: admissions take spare room or reserve more
/// (at least [`RESERVE_STEP`] at a time); what decodes and passes give back
/// refills its spare, and everything reserved goes back when the last of the
/// operation's handles drops. It is lopdf's `DecodeAdmission` for every
/// decode the operation runs.
pub(crate) struct MemoryLedger {
    service: Arc<dyn SealMemory>,
    /// Where each finished decode's length goes.
    observed: SealObservations,
    /// Shared with the holds of the copies the seal keeps (FIX 12260),
    /// which keep it, and its reservations, while they live.
    state: Arc<Mutex<LedgerState>>,
}

#[derive(Default)]
struct LedgerState {
    /// Reserved, and available to a later admission: what is left plus what
    /// was released.
    spare: u64,
    /// Admitted to decoded or scoped allocations and not given back. The
    /// seal's own persistent copies and holds are not counted: they outlive
    /// the passes they are made in.
    live: u64,
    /// What the service holds for each reservation.
    held: Vec<Box<dyn Send>>,
    /// The refusal that ended an admission. Every later admission refuses
    /// with it, so the operation cannot go on half refused.
    refused: Option<SealMemoryRefusal>,
}

impl MemoryLedger {
    /// Admits `bytes` about to be allocated: from what the ledger has left,
    /// or reserved first, at least [`RESERVE_STEP`] at a time. A decode's
    /// allocation counts as `live`, which its decode or its pass gives back.
    fn take(&self, bytes: u64, decode: bool) -> Result<(), SealMemoryRefusal> {
        let mut state = lock(&self.state);
        if let Some(refused) = state.refused {
            return Err(refused);
        }
        if bytes > state.spare {
            let step = (bytes - state.spare).max(RESERVE_STEP);
            match self.service.reserve(step) {
                Ok(held) => {
                    state.held.push(held);
                    state.spare = state.spare.saturating_add(step);
                }
                Err(refusal) => {
                    state.refused = Some(refusal);
                    return Err(refusal);
                }
            }
        }
        state.spare -= bytes;
        if decode {
            state.live = state.live.saturating_add(bytes);
        }
        Ok(())
    }

    /// Takes back `bytes` admitted earlier and no longer allocated: they
    /// serve the operation's later admissions. Never more than is live.
    fn give_back(state: &mut LedgerState, bytes: u64) {
        let bytes = bytes.min(state.live);
        state.live -= bytes;
        state.spare = state.spare.saturating_add(bytes);
    }

    /// Admits `len` values of `T`, about to be allocated by the seal's own
    /// code: never given back by a parse pass. The owner may return freed
    /// bytes with [`Self::release_admitted`]; otherwise held until the
    /// operation ends.
    pub(crate) fn admit_len<T>(&self, len: usize) -> Result<(), SealMemoryRefusal> {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        self.take(u64::try_from(bytes).unwrap_or(u64::MAX), false)
    }

    /// Admits a scoped allocation alongside the decodes it owns. Its scope
    /// returns what remains live through [`Self::release`].
    pub(crate) fn admit_transient(&self, bytes: usize) -> Result<(), SealMemoryRefusal> {
        self.take(wide(bytes), true)
    }

    /// Returns freed bytes previously charged through [`Self::admit_len`].
    /// These are not decoder bytes: returning them never debits `live` or
    /// releases service reservations. Each owner returns its credit once,
    /// only after the old allocation has been freed.
    pub(crate) fn release_admitted(&self, bytes: u64) {
        let mut state = lock(&self.state);
        state.spare = state.spare.saturating_add(bytes);
    }

    /// Holds `bytes` for one copy the seal keeps, about to be made or just
    /// built (FIX 12260): from what the ledger has left, or reserved first,
    /// and back in what it has left when the hold drops with its copy. Never
    /// a decode's, so no pass gives it back early.
    pub(crate) fn hold(&self, bytes: usize) -> Result<LedgerHold, SealMemoryRefusal> {
        let bytes = wide(bytes);
        self.take(bytes, false)?;
        Ok(LedgerHold {
            state: Arc::clone(&self.state),
            bytes,
        })
    }

    /// Adds bytes to a hold from this same ledger before an allocation.
    /// These are not decode bytes, so a parse pass cannot return them early.
    pub(crate) fn extend_hold(
        &self,
        hold: &mut LedgerHold,
        additional: u64,
    ) -> Result<(), SealMemoryRefusal> {
        self.take(additional, false)?;
        hold.bytes = hold.bytes.saturating_add(additional);
        Ok(())
    }

    /// Adopts `bytes` ALREADY taken from this ledger's spare (FIX 14217):
    /// no second take, no service call, infallible. The hold returns the
    /// bytes to spare when it drops with the adopted value.
    /// Contract (caller-proved): `bytes` were charged to THIS ledger
    /// exactly once for an allocation still live, never released or adopted
    /// twice, and dropped BEFORE the hold (as [`Held`] orders fields).
    /// Over-adopt forges spare; under-adopt stays conservative. Only proven
    /// callers: `walk::pages` output, `revision_ends` ends.
    pub(crate) fn adopt_charged(&self, bytes: usize) -> LedgerHold {
        LedgerHold {
            state: Arc::clone(&self.state),
            bytes: wide(bytes),
        }
    }

    /// Returns `bytes` from decoded or scoped allocations that were freed,
    /// to spare room for a later admission. Never more than is live: held
    /// service reservations and a kept refusal stay as they are, and this
    /// never returns host memory.
    pub(crate) fn release(&self, bytes: u64) {
        Self::give_back(&mut lock(&self.state), bytes);
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
        self.take(wide(bytes), true)
            .map_err(SealMemoryRefusal::to_decode)
    }

    fn release(&self, bytes: usize) {
        Self::give_back(&mut lock(&self.state), wide(bytes));
    }

    fn decoded(&self, bytes: usize) {
        self.observed.note(Counter::StreamDecodeBytes, bytes);
    }
}

/// One parse pass over an operation's ledger (FIX 8448): when it drops,
/// every byte admitted since it opened and not given back returns to the
/// ledger's spare, so the operation's next parse reuses it rather than
/// reserving it again. Sound only when everything allocated under it is
/// gone by then: the passes wrap one load and the checks over its document.
pub(crate) struct LedgerPass {
    ledger: Arc<MemoryLedger>,
    /// What was live when the pass opened.
    opened_at: u64,
}

impl Drop for LedgerPass {
    fn drop(&mut self) {
        let mut state = lock(&self.ledger.state);
        let spent = state.live.saturating_sub(self.opened_at);
        MemoryLedger::give_back(&mut state, spent);
    }
}

/// What one copy the seal keeps holds on its operation's ledger (FIX
/// 12260): taken before the copy is made, or as soon as it is built, and
/// back in what the ledger has left when it drops with the copy, for the
/// operation's later admissions.
pub(crate) struct LedgerHold {
    /// The ledger's state, kept with its reservations while the copy lives.
    state: Arc<Mutex<LedgerState>>,
    bytes: u64,
}

impl LedgerHold {
    /// Returns only bytes this hold charged, after their allocation is freed.
    /// The ledger's refusal, if any, stays latched.
    pub(crate) fn shrink(&mut self, freed: u64) {
        let freed = freed.min(self.bytes);
        self.bytes -= freed;
        let mut state = lock(&self.state);
        state.spare = state.spare.saturating_add(freed);
    }
}

impl Drop for LedgerHold {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        state.spare = state.spare.saturating_add(self.bytes);
    }
}

impl fmt::Debug for LedgerHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerHold")
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// A copy the seal keeps with the hold that admits it (FIX 12260): the
/// copy drops first, then the hold. It reads as the copy.
pub(crate) struct Held<T> {
    value: T,
    _hold: LedgerHold,
}

impl<T> Held<T> {
    /// `value`, admitted by `hold`.
    pub(crate) fn new(value: T, hold: LedgerHold) -> Self {
        Self { value, _hold: hold }
    }
}

impl<T> Deref for Held<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

/// A length as a service counts bytes.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// The ledger changes in one step under its lock, so a holder that panicked
/// left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

//! Memory the native seal reserves before its PDF decodes allocate it
//! (FIX 7654).
//!
//! Before a decode allocates or grows a buffer, the vendored lopdf asks its
//! `DecodeAdmission` hook for the bytes; here that hook is one operation's
//! [`MemoryLedger`] over the [`SealMemory`] service the configuration names
//! ([`SealMemoryProvider`]). Each seal and each verification is one
//! operation with a ledger of its own, opened before it parses anything. The
//! ledger reserves at least [`RESERVE_STEP`] at a time and serves smaller
//! admissions from what it has left. What a decode gives back (a buffer's
//! old allocation once it grew, a dropped layer of a filter chain) and what
//! a finished parse pass held ([`LedgerPass`]) return to what it has left,
//! for the operation's later admissions (FIX 8448): it holds about what its
//! decodes keep alive at once, not the sum of every allocation they asked
//! for. Its reservations stay with it, and everything it reserved goes back
//! to the service when the operation ends.
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
        Ok(Lease {
            _held: Mutex::new(held),
        })
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

/// One operation's reservations: grown by every admission its spare cannot
/// serve, never shrunk while the operation runs, and given back whole when
/// the last of the operation's handles drops. What its decodes give back
/// refills its spare. It is lopdf's `DecodeAdmission` for every decode the
/// operation runs.
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
    /// Admitted to the decodes' allocations and not given back. The seal's
    /// own copies are not counted: they outlive the passes they are made in.
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
    /// code: held until the operation ends, never given back by a pass.
    pub(crate) fn admit_len<T>(&self, len: usize) -> Result<(), SealMemoryRefusal> {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        self.take(u64::try_from(bytes).unwrap_or(u64::MAX), false)
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

    fn decoded(&self, bytes: usize) {
        self.observed.note(Counter::StreamDecodeBytes, bytes);
    }

    fn release(&self, bytes: usize) {
        Self::give_back(&mut lock(&self.state), wide(bytes));
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

/// What a memory service holds for one owner's bytes, until the owner drops
/// it (see [`SealMemoryProvider::lease`]).
pub(crate) struct Lease {
    /// The service's hold, never read: the lock only lets an owner shared
    /// across threads carry it.
    _held: Mutex<Box<dyn Send>>,
}

/// Bytes whose memory was reserved before they were allocated, with the
/// lease that holds the reservation (FIX 7655). The buffer and its lease
/// drop together, so the memory goes back when the last owner lets go and
/// never before. It is shared as [`SharedBytes`] and has no clone: a copy
/// would be memory nothing reserved.
pub struct AdmittedBytes {
    bytes: Vec<u8>,
    /// Holds the buffer's whole capacity; none while it has none. Never
    /// read: it is dropped with the buffer.
    _lease: Option<Lease>,
    /// Another owner's bytes this one shares rather than copies (a cache
    /// hit's body); its own buffer is then empty.
    of: Option<SharedBytes>,
    /// Holds what the bytes' owner keeps beside them: a response's content
    /// type and the shared header around its body (FIX 8455).
    _beside: Option<Lease>,
}

/// Admitted bytes, shared by every owner that keeps them: a fetch response,
/// the fetcher's cache, a gathered CRL.
pub type SharedBytes = Arc<AdmittedBytes>;

impl AdmittedBytes {
    /// No bytes, and nothing reserved.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            _lease: None,
            of: None,
            _beside: None,
        }
    }

    /// `of`'s bytes, shared with no copy, and `beside` held for what this
    /// owner keeps next to them (FIX 8455): a cache hit is a new response
    /// over the cached body.
    #[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
    pub(crate) fn share(of: &SharedBytes, beside: Lease) -> Self {
        Self {
            of: Some(Arc::clone(of)),
            _beside: Some(beside),
            ..Self::empty()
        }
    }

    /// What a response keeps beside its body (FIX 8455): its content type's
    /// bytes, and the header of the `Arc` its body is shared in.
    #[cfg_attr(not(any(unix, feature = "network-fetch")), allow(dead_code))]
    pub(crate) fn beside_bytes(content_type: Option<&str>) -> usize {
        content_type
            .map_or(0, str::len)
            .saturating_add(2 * std::mem::size_of::<usize>() + std::mem::size_of::<Self>())
    }

    /// Holds `lease` beside the bytes until they drop: it covers what their
    /// owner keeps next to them (see [`Self::beside_bytes`]).
    #[cfg_attr(not(any(unix, feature = "network-fetch")), allow(dead_code))]
    pub(crate) fn hold_beside(&mut self, lease: Lease) {
        self._beside = Some(lease);
    }

    /// A copy of `bytes`, its memory reserved from `memory`'s service before
    /// the copy is made. The reservation is the copy's own: it goes back
    /// when the copy drops, not when an operation ends.
    ///
    /// # Errors
    /// The service's refusal; [`SealMemoryRefusal::Unavailable`] when
    /// `memory` names no service. An allocator that refuses bytes the
    /// service reserved is the floor with nothing available.
    pub fn copy_from(memory: &SealMemoryProvider, bytes: &[u8]) -> Result<Self, SealMemoryRefusal> {
        let mut copy = Self::empty();
        if !bytes.is_empty() {
            copy.regrow(bytes.len(), memory.lease(bytes.len())?)?;
            copy.extend(bytes)?;
        }
        Ok(copy)
    }

    /// `bytes` as they are, adopted with no second copy (FIX 8454): `held`
    /// when something already holds their memory (the organ runtime's
    /// reservation, made before it copied them), else a lease of their own
    /// from `memory`'s service, taken now. The lease covers the buffer's
    /// whole capacity and drops with it.
    ///
    /// # Errors
    /// The service's refusal, when the bytes need a lease of their own.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn adopt(
        memory: &SealMemoryProvider,
        bytes: Vec<u8>,
        held: Option<Box<dyn Send>>,
    ) -> Result<Self, SealMemoryRefusal> {
        if bytes.capacity() == 0 {
            return Ok(Self::empty());
        }
        let lease = match held {
            Some(held) => Lease {
                _held: Mutex::new(held),
            },
            None => memory.lease(bytes.capacity())?,
        };
        Ok(Self {
            bytes,
            _lease: Some(lease),
            ..Self::empty()
        })
    }

    /// The capacity the buffer must grow to before `extra` more bytes go in,
    /// or `None` when they fit: twice what it holds, or what they need when
    /// that is more.
    #[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
    pub(crate) fn growth(&self, extra: usize) -> Option<usize> {
        let needed = self.bytes.len().saturating_add(extra);
        let capacity = self.bytes.capacity();
        (needed > capacity).then(|| needed.max(capacity.saturating_mul(2)))
    }

    /// Grows the buffer to `capacity`, which `lease` holds. The old lease
    /// goes back only once the bytes have moved, so the moment both
    /// allocations are live is reserved too.
    ///
    /// # Errors
    /// The floor with nothing available when the allocator refuses.
    pub(crate) fn regrow(
        &mut self,
        capacity: usize,
        lease: Lease,
    ) -> Result<(), SealMemoryRefusal> {
        let additional = capacity.saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| SealMemoryRefusal::Floor {
                needed: wide(capacity),
                available: 0,
            })?;
        self._lease = Some(lease);
        Ok(())
    }

    /// The spare capacity the buffer holds past its bytes.
    #[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
    pub(crate) fn slack(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    /// Drops the buffer's spare capacity, `lease` (taken for its length)
    /// holding what is left (FIX 8457). The old lease goes back only once
    /// the bytes sit in their exact allocation, so a move's moment with both
    /// alive is reserved too. Should the allocator keep spare room, the old
    /// lease stays.
    #[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
    pub(crate) fn shrink(&mut self, lease: Lease) {
        self.bytes.shrink_to_fit();
        if self.bytes.capacity() == self.bytes.len() {
            self._lease = Some(lease);
        }
    }

    /// Appends `chunk` inside the capacity already reserved: it never grows
    /// the buffer unreserved.
    ///
    /// # Errors
    /// The floor when the reserved capacity cannot take `chunk`.
    pub(crate) fn extend(&mut self, chunk: &[u8]) -> Result<(), SealMemoryRefusal> {
        let spare = self.bytes.capacity() - self.bytes.len();
        if chunk.len() > spare {
            return Err(SealMemoryRefusal::Floor {
                needed: wide(chunk.len()),
                available: wide(spare),
            });
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
}

impl Deref for AdmittedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.of {
            Some(of) => &of[..],
            None => &self.bytes[..],
        }
    }
}

impl AsRef<[u8]> for AdmittedBytes {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl fmt::Debug for AdmittedBytes {
    /// The length only: fetched bytes stay out of every debug string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedBytes")
            .field("len", &self.len())
            .finish()
    }
}

impl PartialEq for AdmittedBytes {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for AdmittedBytes {}

/// A length as a service counts bytes.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// The ledger changes in one step under its lock, so a holder that panicked
/// left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

//! Shared output buffers; native accounting constructors are feature-gated.
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

#[cfg(feature = "native")]
use crate::memory::{SealMemoryProvider, SealMemoryRefusal};

/// The fixed `Arc` control header a shared owner holds beside its bytes: the
/// strong and weak counts. A model of the allocation, not a content ceiling:
/// it is reserved once at creation, never per `Arc::clone`.
pub(crate) const SHARED_CONTROL_BYTES: usize = 2 * std::mem::size_of::<usize>();

/// What a memory service holds for one owner's bytes, until the owner drops
/// it. Native accounting supplies the service reservation.
pub(crate) struct Lease {
    /// The service's hold, never read: the lock only lets an owner shared
    /// across threads carry it.
    _held: Mutex<Box<dyn Send>>,
}

impl Lease {
    pub(crate) fn new(held: Box<dyn Send>) -> Self {
        Self {
            _held: Mutex::new(held),
        }
    }
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

    /// No bytes, with the shared `Arc` control header reserved.
    #[cfg(feature = "native")]
    pub fn shared_empty(memory: &SealMemoryProvider) -> Result<Self, SealMemoryRefusal> {
        Ok(Self {
            bytes: Vec::new(),
            _lease: Some(memory.lease(SHARED_CONTROL_BYTES)?),
            of: None,
            _beside: None,
        })
    }

    /// No bytes, with an already reserved shared header.
    pub(crate) fn from_leased_empty(lease: Lease) -> Self {
        Self {
            bytes: Vec::new(),
            _lease: Some(lease),
            of: None,
            _beside: None,
        }
    }

    /// A copy of `bytes`, its memory plus the shared header reserved from
    /// `memory`'s service before the copy is made. The reservation is the
    /// copy's own: it goes back when the copy drops, not when an operation
    /// ends. The header ([`SHARED_CONTROL_BYTES`]) is reserved once here,
    /// never per `Arc::clone`.
    ///
    /// # Errors
    /// The service's refusal; [`SealMemoryRefusal::Unavailable`] when
    /// `memory` names no service. An allocator that refuses bytes the
    /// service reserved is the floor with nothing available.
    #[cfg(feature = "native")]
    pub fn copy_from(memory: &SealMemoryProvider, bytes: &[u8]) -> Result<Self, SealMemoryRefusal> {
        if bytes.is_empty() {
            return Self::shared_empty(memory);
        }
        let mut copy = Self::empty();
        let held = memory.lease(bytes.len().saturating_add(SHARED_CONTROL_BYTES))?;
        copy.regrow(bytes.len(), held)?;
        copy.extend(bytes)?;
        Ok(copy)
    }

    /// `bytes` as they are, adopted with no second copy (FIX 8454): `held`
    /// when something already holds their memory (the organ runtime's
    /// reservation, made before it copied them), else a lease of their own
    /// from `memory`'s service, taken now. The lease covers the buffer's
    /// whole capacity plus the shared header ([`SHARED_CONTROL_BYTES`],
    /// once, never per `Arc::clone`) and drops with it.
    ///
    /// # Errors
    /// The service's refusal, when the bytes need a lease of their own.
    #[cfg_attr(not(unix), allow(dead_code))]
    #[cfg(feature = "native")]
    pub(crate) fn adopt(
        memory: &SealMemoryProvider,
        bytes: Vec<u8>,
        held: Option<Box<dyn Send>>,
    ) -> Result<Self, SealMemoryRefusal> {
        let lease = match held {
            Some(held) => {
                // The runtime already holds the bytes; the header is leased
                // beside them and both are held together.
                let control = memory.lease(SHARED_CONTROL_BYTES)?;
                Lease {
                    _held: Mutex::new(Box::new((held, control)) as Box<dyn Send>),
                }
            }
            None => memory.lease(bytes.capacity().saturating_add(SHARED_CONTROL_BYTES))?,
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
    #[cfg(feature = "native")]
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
    #[cfg(feature = "native")]
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

#[cfg(not(feature = "native"))]
impl From<Vec<u8>> for AdmittedBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ..Self::empty()
        }
    }
}

/// The wire form is the bytes alone, exactly as the `Vec<u8>` this
/// replaces: a wire receipt arrives without a lease, like every other
/// received buffer, and its receiver admits before use.
impl serde::Serialize for AdmittedBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bytes.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AdmittedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            bytes: Vec::<u8>::deserialize(deserializer)?,
            _lease: None,
            of: None,
            _beside: None,
        })
    }
}

impl AdmittedBytes {
    /// The buffer for a sole owner without copying (FIX 8452): a shared
    /// buffer is copied instead, so callers reserve the copy's bytes first —
    /// a copy is memory nothing reserved.
    pub(crate) fn into_vec(shared: SharedBytes) -> Vec<u8> {
        Arc::try_unwrap(shared)
            .map(|owned| owned.bytes)
            .unwrap_or_else(|shared| shared.bytes.clone())
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

/// Text whose memory was reserved before it was allocated, with the lease
/// that holds the reservation (FIX 8455). The string and its lease drop
/// together, so the memory goes back when the last owner lets go and never
/// before. It is shared as [`SharedStr`] and has no clone: a copy would be
/// memory nothing reserved.
pub struct AdmittedStr {
    text: String,
    /// Holds the text's bytes plus the shared header; none while it holds
    /// nothing. Never read: it is dropped with the text.
    _lease: Option<Lease>,
}

/// Admitted text, shared by every owner that keeps it: a fetch response,
/// the fetcher's cache, a hit.
pub type SharedStr = Arc<AdmittedStr>;

impl AdmittedStr {
    /// No text, and nothing reserved.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            text: String::new(),
            _lease: None,
        }
    }

    /// No text, with the shared `Arc` control header reserved.
    #[cfg(feature = "native")]
    pub fn shared_empty(memory: &SealMemoryProvider) -> Result<Self, SealMemoryRefusal> {
        Ok(Self {
            text: String::new(),
            _lease: Some(memory.lease(SHARED_CONTROL_BYTES)?),
        })
    }

    /// A copy of `text`, its bytes plus the shared header reserved from
    /// `memory`'s service before the copy is made. The reservation is the
    /// copy's own: it goes back when the copy drops, not when an operation
    /// ends. Empty text reserves the shared header.
    ///
    /// # Errors
    /// The service's refusal; [`SealMemoryRefusal::Unavailable`] when
    /// `memory` names no service.
    #[cfg(feature = "native")]
    pub fn copy_from(memory: &SealMemoryProvider, text: &str) -> Result<Self, SealMemoryRefusal> {
        if text.is_empty() {
            return Self::shared_empty(memory);
        }
        let lease = memory.lease(text.len().saturating_add(SHARED_CONTROL_BYTES))?;
        Ok(Self {
            text: text.to_owned(),
            _lease: Some(lease),
        })
    }

    /// `text` with `lease`, already reserved for its bytes plus the shared
    /// header (the native fetcher's deadline-bound reservation).
    pub(crate) fn from_leased(text: String, lease: Lease) -> Self {
        Self {
            text,
            _lease: Some(lease),
        }
    }
}

impl Deref for AdmittedStr {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for AdmittedStr {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for AdmittedStr {
    /// The length only: fetched headers stay out of every debug string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedStr")
            .field("len", &self.text.len())
            .finish()
    }
}

impl PartialEq for AdmittedStr {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for AdmittedStr {}

#[cfg(feature = "native")]
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

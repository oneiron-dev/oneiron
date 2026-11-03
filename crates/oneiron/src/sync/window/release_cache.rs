//! One masked, projected window release shared by every socket it fans
//! out to (FIX 10477). A home sending one window blob to N machines used
//! to mask it, copy the whole window for its update slice, project its
//! pads and, for a carrier socket, inflate it N times. The masked bytes
//! and the pad projection are the same for every recipient at equal vault
//! state; only the seal is per machine. This cache makes the shared half
//! once per (window, payload, secret pass, pad namespace, shallow floor)
//! and inflates the carrier once per entry; the seal, the recipients read
//! and every withholding verdict stay per socket.
//!
//! The secret pass is re-read on every call and its fingerprint is part
//! of the key, never cached itself: a mark landing mid-fanout changes the
//! pass, so the next socket misses and masks again. A blob that cannot be
//! masked is not cached either; it is withheld per socket as today.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use loro::LoroDoc;

use super::PreparedWindowPads;
use super::pad_custody::{
    SealFallback, SharedPadProjection, inflate_window_carrier, project_window_shared,
    seal_projected_to, seal_recipient,
};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::sync::selector::secret_projection::SyncSecretProjection;
use crate::sync::types::WindowKey;

/// Releases kept at once; past it, the oldest made goes.
const MAX_ENTRIES: usize = 128;
/// The kept releases' charged size: each entry charges its masked bytes
/// three times (masked, projected, carrier), an upper estimate of what
/// its lazy halves can add.
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// Which vault state one shared release was made under.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ReleaseKey {
    window: WindowKey,
    /// BLAKE3 of the raw frame payload: an update and a replacement of
    /// one window are different releases.
    payload: [u8; 32],
    /// The fresh secret pass this call read: a changed mark misses.
    secret_pass: [u8; 32],
    /// The current pad namespace the projection is made under.
    namespace: Option<[u8; 16]>,
    /// The context's shallow floor: a later folded context misses rather
    /// than reuse bytes its own release would withhold.
    shallow: Vec<u8>,
}

/// One window blob as every socket of a fan-out releases it: masked once,
/// projected once when a sealed send first asks, inflated once when a
/// carrier send first asks. The seal is made per machine in
/// [`SharedWindowRelease::prepare`] and never stored here.
pub struct SharedWindowRelease {
    /// The masked payload (the raw payload when nothing was masked).
    masked: Vec<u8>,
    /// The namespace of its key, the one its projection is made under.
    namespace: Option<[u8; 16]>,
    projection: OnceLock<SharedPadProjection>,
    carrier: OnceLock<Vec<u8>>,
}

impl SharedWindowRelease {
    /// The carrier bytes of this release, inflated on the first ask.
    fn carrier_of(&self, vault: &Vault, window: &WindowKey, context: Option<&LoroDoc>) -> &[u8] {
        self.carrier
            .get_or_init(|| inflate_window_carrier(vault, window, &self.masked, context))
    }

    fn carrier_prepared(
        &self,
        vault: &Vault,
        window: &WindowKey,
        context: Option<&LoroDoc>,
    ) -> PreparedWindowPads {
        PreparedWindowPads::carrier(self.carrier_of(vault, window, context))
    }

    /// The carrier, with the value-free `why` a kept send tells.
    fn keep_carrier(
        &self,
        vault: &Vault,
        window: &WindowKey,
        context: Option<&LoroDoc>,
        why: &'static str,
    ) -> PreparedWindowPads {
        tracing::warn!(%window, why, "window pads not sealed; the carrier goes as today");
        self.carrier_prepared(vault, window, context)
    }

    /// This release made ready for one socket: as today's carrier when
    /// `recipient` is `None` (a socket that answered `NotReady`) or names
    /// no machine the world's pads go to; pad-free as it is; else its
    /// shared projection sealed here, for that machine alone, from pads
    /// gathered fresh. `context` holds an update's dependencies.
    pub fn prepare(
        &self,
        vault: &Vault,
        window: &WindowKey,
        context: Option<&LoroDoc>,
        recipient: Option<PeerMachine>,
    ) -> PreparedWindowPads {
        let Some(recipient) = recipient else {
            return self.carrier_prepared(vault, window, context);
        };
        let Some(world) = window.world() else {
            return PreparedWindowPads::pad_free(&self.masked);
        };
        let (machine, to) = match seal_recipient(vault, window, world, recipient) {
            Ok(seal) => seal,
            Err(SealFallback::Carrier) => return self.carrier_prepared(vault, window, context),
            Err(SealFallback::Keep(why)) => return self.keep_carrier(vault, window, context, why),
        };
        let projection = self
            .projection
            .get_or_init(|| project_window_shared(window, &self.masked, context, self.namespace));
        let (bytes, items) = match projection {
            SharedPadProjection::PadFree => return PreparedWindowPads::pad_free(&self.masked),
            SharedPadProjection::Projected { bytes, items } => (bytes, items),
            SharedPadProjection::Keep(why) => {
                return self.keep_carrier(vault, window, context, why);
            }
        };
        match seal_projected_to(vault, window, world, bytes.clone(), items, machine, &to) {
            Ok(prepared) => prepared,
            Err(SealFallback::Carrier) => self.carrier_prepared(vault, window, context),
            Err(SealFallback::Keep(why)) => self.keep_carrier(vault, window, context, why),
        }
    }
}

/// One kept release, when it was made, and what it charges.
struct Entry {
    seq: u64,
    charge: usize,
    release: Arc<SharedWindowRelease>,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<ReleaseKey, Entry>,
    bytes: usize,
}

/// The shared window releases of one serving vault, held by its server
/// across sockets. Bounded by count and charged bytes; no entry is ever
/// invalidated in place — a changed pass, namespace or shallow floor is
/// a different key and computes fresh.
#[derive(Default)]
pub struct WindowReleaseCache {
    inner: Mutex<CacheInner>,
    seq: AtomicU64,
}

impl WindowReleaseCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The shared release of `payload`, a window blob of `window` leaving
    /// this vault, masked under the secret pass read for this call;
    /// `context` holds an update's dependencies. A hit does no Loro work
    /// at all; a miss masks once, outside the lock, and racing misses may
    /// both mask — the first stored wins.
    ///
    /// # Errors
    /// A store failure, or a blob carrying a marked item that cannot be
    /// masked: the caller withholds it, and nothing is cached.
    pub fn get_or_compute(
        &self,
        vault: &Vault,
        window: &WindowKey,
        payload: &[u8],
        context: Option<&LoroDoc>,
    ) -> Result<Arc<SharedWindowRelease>> {
        let projection = SyncSecretProjection::read(vault)?;
        let key = ReleaseKey {
            window: window.clone(),
            payload: *blake3::hash(payload).as_bytes(),
            secret_pass: projection.pass_fingerprint(),
            namespace: vault.store.world_pad_namespace(),
            shallow: context
                .map(|doc| doc.shallow_since_vv().to_vv().encode())
                .unwrap_or_default(),
        };
        if let Some(hit) = self
            .lock()
            .map
            .get(&key)
            .map(|entry| Arc::clone(&entry.release))
        {
            return Ok(hit);
        }
        let masked = projection
            .release_window_blob(&vault.store, payload, context, false)?
            .unwrap_or_else(|| payload.to_vec());
        let release = Arc::new(SharedWindowRelease {
            masked,
            namespace: key.namespace,
            projection: OnceLock::new(),
            carrier: OnceLock::new(),
        });
        Ok(self.insert(key, release))
    }

    /// Keeps `release` under `key`, or the one a racing miss stored first.
    fn insert(
        &self,
        key: ReleaseKey,
        release: Arc<SharedWindowRelease>,
    ) -> Arc<SharedWindowRelease> {
        let charge = release
            .masked
            .len()
            .saturating_mul(3)
            .saturating_add(key.shallow.len())
            .saturating_add(128);
        let mut inner = self.lock();
        if let Some(held) = inner.map.get(&key) {
            return Arc::clone(&held.release);
        }
        if charge > MAX_BYTES {
            return release;
        }
        while inner.map.len() >= MAX_ENTRIES || inner.bytes + charge > MAX_BYTES {
            let Some(oldest) = inner
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.seq)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = inner.map.remove(&oldest) {
                inner.bytes = inner.bytes.saturating_sub(entry.charge);
            }
        }
        inner.bytes += charge;
        inner.map.insert(
            key,
            Entry {
                seq: self.seq.fetch_add(1, Ordering::Relaxed),
                charge,
                release: Arc::clone(&release),
            },
        );
        release
    }
}

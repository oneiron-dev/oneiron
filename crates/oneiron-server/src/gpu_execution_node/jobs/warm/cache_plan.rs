//! The cache budget's plan (pass 34, `34-compute-general/DESIGN.md` section 4.1; row P2): which
//! cache keys one pass removes, and why. It is the fleet tool's rule as the pack states it
//! (section 6): first every cache key unused for the idle time; then, while the caches that
//! remain total more than the cap, the least recently used of those not used within the
//! protected time. A busy key never goes: one that a key of the journal that has not ended
//! lists, or that an open order on a live issuer lists. The plan reads and removes nothing.

/// The cache budget in force on this machine: for each figure, the smaller of the box file's
/// and the owner's machine policy (row P0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheBudget {
    /// The most bytes the cache keys may hold together.
    pub cap_bytes: u64,
    /// A cache key unused this long goes, whatever the total.
    pub idle_ms: u64,
    /// A cache key used within this time never goes for the cap.
    pub protect_ms: u64,
}

/// One cache key as a pass sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub key: String,
    /// What its path held at this pass.
    pub bytes: u64,
    /// When an attempt that listed it last ended with exit 0, or when the node first found its
    /// path.
    pub last_used_ms: u64,
    /// A key of the journal that has not ended lists it, or a live issuer's wanted list does.
    pub busy: bool,
}

/// Why a pass removes a cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionCause {
    /// It was unused for `unused_ms`, at least the budget's idle time.
    Idle { unused_ms: u64 },
    /// The cache keys came to `total_bytes`, over the cap, and it was the least recently used
    /// one outside the protected time.
    OverCap { total_bytes: u64 },
}

impl std::fmt::Display for EvictionCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle { unused_ms } => {
                write!(formatter, "unused for {} hours", unused_ms / 3_600_000)
            }
            Self::OverCap { total_bytes } => write!(
                formatter,
                "the caches came to {} MiB, over the cap; the least recently used",
                total_bytes / (1024 * 1024)
            ),
        }
    }
}

/// One cache key a pass removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eviction {
    pub key: String,
    pub cause: EvictionCause,
}

/// What a pass over `entries` at `now_ms` removes under `budget`, in the order it removes them,
/// and the bytes the cache keys hold after it. Ties in last use go by the key, so a plan is the
/// same on every run.
#[must_use]
pub fn cache_plan(
    entries: &[CacheEntry],
    budget: &CacheBudget,
    now_ms: u64,
) -> (Vec<Eviction>, u64) {
    let mut evictions = Vec::new();
    let mut kept: Vec<&CacheEntry> = Vec::new();
    let mut kept_bytes = 0_u64;
    for entry in entries {
        let unused_ms = now_ms.saturating_sub(entry.last_used_ms);
        if !entry.busy && unused_ms >= budget.idle_ms {
            evictions.push(Eviction {
                key: entry.key.clone(),
                cause: EvictionCause::Idle { unused_ms },
            });
        } else {
            kept_bytes = kept_bytes.saturating_add(entry.bytes);
            kept.push(entry);
        }
    }
    kept.sort_by(|left, right| {
        left.last_used_ms
            .cmp(&right.last_used_ms)
            .then_with(|| left.key.cmp(&right.key))
    });
    for entry in kept {
        if kept_bytes <= budget.cap_bytes {
            break;
        }
        if entry.busy || now_ms.saturating_sub(entry.last_used_ms) < budget.protect_ms {
            continue;
        }
        evictions.push(Eviction {
            key: entry.key.clone(),
            cause: EvictionCause::OverCap {
                total_bytes: kept_bytes,
            },
        });
        kept_bytes = kept_bytes.saturating_sub(entry.bytes);
    }
    (evictions, kept_bytes)
}

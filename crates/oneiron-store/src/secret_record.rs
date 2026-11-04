//! Secret custody floor and binding vocabulary used by the store layer.

use std::collections::BTreeMap;

use oneiron_base::error::Result;
pub use oneiron_contracts::secret_custody::{CustodyClass, CustodyTier};
use serde::{Deserialize, Serialize};

/// Per-class allowed tier band (inclusive). Floors narrow the `max` (the most
/// exposure a class may reach), never force exposure — `min` is informational
/// (and `T0Doored` by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierBand {
    /// Least-exposed tier in the band (informational).
    pub min: CustodyTier,
    /// Most-exposed tier the class may reach under this band.
    pub max: CustodyTier,
}

impl TierBand {
    /// A band spanning a single tier.
    #[must_use]
    pub const fn only(tier: CustodyTier) -> Self {
        Self {
            min: tier,
            max: tier,
        }
    }

    /// True when `tier` sits inside this band (inclusive).
    #[must_use]
    pub fn admits(&self, tier: CustodyTier) -> bool {
        self.min <= tier && tier <= self.max
    }

    /// The narrower of two bands (most-restrictive merge).
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            min: self.min.max(other.min),
            max: self.max.min(other.max),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved vault custody floor
// ---------------------------------------------------------------------------

/// The vault's custody floor, resolved from the `secret.custody.*` keys in
/// POLICY_MANIFEST bodies (DEC-0005: floors live in the vault's policy
/// manifests; callers narrow, never widen). Most-restrictive wins per field
/// across packs.
///
/// The tiers grade exposure of the secret VALUE (never a device tier) —
/// under host-root there is no device tier to be "custodial" against; the
/// authority principal is the capability slip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyFloor {
    /// Allowed tier band for `custody-portable` (default `T0..T2`).
    pub portable: TierBand,
    /// Allowed tier band for `custody-device-bound` (default `T0..T2`).
    pub device_bound: TierBand,
    /// Allowed tier band for `cross-vault` (default `T0..T0`, door-only).
    pub cross_vault: TierBand,
    /// Maximum age before a value must be rotated (None = no floor).
    pub rotation_max_age_secs: Option<u64>,
    /// Environment bindings (e.g. `prod` → restriction note), narrowed on
    /// conflicting values.
    pub env_bindings: BTreeMap<String, String>,
}

impl Default for SecretCustodyFloor {
    fn default() -> Self {
        Self {
            portable: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            device_bound: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            cross_vault: TierBand::only(CustodyTier::T0Doored),
            rotation_max_age_secs: None,
            env_bindings: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Bindings, status, record, metadata
// ---------------------------------------------------------------------------

/// The scope verb a binding must declare before the value door will hand over
/// plaintext. Scopes are otherwise free-form: they name what a binding is FOR,
/// and only this one is load-bearing at a door.
pub const SECRET_SCOPE_READ: &str = "read";

/// A binding scoping which effector may use a secret ref, at what tier
/// ceiling. The binding check scopes usage, drives tier admission, and
/// stamps receipts. No binding covering `(secret_ref, effector)` with the
/// required scope ⇒ [`SecretError::SecretBindingDenied`](oneiron_base::error::SecretError::SecretBindingDenied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    /// The effector, e.g. `"connector:gmail"`, `"door:receive-pack"`.
    pub effector: String,
    /// The most-exposed tier this binding may request.
    pub tier_ceiling: CustodyTier,
    /// Declared scopes the binding covers.
    pub scopes: Vec<String>,
}

impl SecretBinding {
    /// Whether this binding carries the [`SECRET_SCOPE_READ`] grant the value
    /// door requires.
    ///
    /// An EMPTY scope list is NOT a wildcard. Reading it as one is how a
    /// declared-but-unenforced field becomes a hole: every binding written
    /// before scopes meant anything would silently grant plaintext reads. A
    /// binding that declares no scope grants no read.
    #[must_use]
    pub fn grants_read(&self) -> bool {
        self.scopes.iter().any(|s| s == SECRET_SCOPE_READ)
    }
}

#[doc(hidden)]
pub trait SecretCustodyFloorSource {
    fn resolve_secret_custody_floor(&self, txn: &heed::RoTxn<'_>) -> Result<SecretCustodyFloor>;
}

impl SecretCustodyFloor {
    /// The tier band for one custody class.
    #[must_use]
    pub fn band_for(&self, class: CustodyClass) -> TierBand {
        match class {
            CustodyClass::CustodyPortable => self.portable,
            CustodyClass::CustodyDeviceBound => self.device_bound,
            CustodyClass::CrossVault => self.cross_vault,
        }
    }

    /// Narrows `self` against `other`, most-restrictive per field.
    #[doc(hidden)]
    pub fn merge(&mut self, other: SecretCustodyFloor) {
        self.portable = self.portable.narrow(other.portable);
        self.device_bound = self.device_bound.narrow(other.device_bound);
        self.cross_vault = self.cross_vault.narrow(other.cross_vault);
        self.rotation_max_age_secs = match (self.rotation_max_age_secs, other.rotation_max_age_secs)
        {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        for (k, v) in other.env_bindings {
            self.env_bindings
                .entry(k)
                .and_modify(|existing| {
                    // Conflicting environment bindings fail closed to the
                    // narrower (lexicographically smaller, deterministic)
                    // restriction note.
                    if v.as_str() < existing.as_str() {
                        *existing = v.clone();
                    }
                })
                .or_insert(v);
        }
    }

    /// Resolves the floor from every POLICY_MANIFEST body in the vault.
    /// Most-restrictive wins per field. An ABSENT floor row takes the default
    /// — that is what "no floor declared" means. A row that is PRESENT but
    /// unreadable is an ERROR: see `decode_floor_keys`.
    ///
    /// The same reasoning governs the INDEX PLANE those bodies are reached
    /// through, and this resolver no longer owns a walk of its own: it consumes
    /// the shared strict one (`policy_manifest_bodies_strict`), so a broken
    /// indexed declaration fails closed here exactly as it does at the
    /// credential door. An unusable type-index key, a dangling entity row, an
    /// unparseable metadata header, an entry naming another entity type, and a
    /// body that will not canonically decode all refuse. Skipping one would
    /// hand back the permissive `T0..T2` default band — the one direction a
    /// floor must never fail.
    pub fn resolve<S: SecretCustodyFloorSource + ?Sized>(
        store: &S,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Self> {
        store.resolve_secret_custody_floor(txn)
    }
}

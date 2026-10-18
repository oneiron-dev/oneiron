//! Secret-domain errors: secret custody, binding and tier refusals, and the
//! secret-lease doors with their declared-path rules.
//!
//! Reached from the root as `Error::Secret(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use crate::entity_id::EntityId;

use super::ErrorKind;

/// Secret-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// A SECRET_CUSTODY body failed structural validation (SECRET-01,
    /// ONE-1919).
    #[error("invalid secret custody body: {0}")]
    InvalidSecretCustodyBody(&'static str),
    /// A live secret name was re-registered while still held by a
    /// non-revoked record (SECRET-01).
    #[error("secret name in use: {name}")]
    SecretNameInUse { name: String },
    /// A value read was attempted on a non-`Active` custody record.
    #[error("secret custody record is not active: {name}")]
    SecretCustodyNotActive { name: String },
    /// No binding covers `(secret_ref, effector)` — the typed deny for a
    /// value read or use without a declared binding (SECRET-01; door/lease
    /// enforcement lands in SECRET-02).
    #[error("no secret binding for effector `{effector}` on secret `{secret_ref}`")]
    SecretBindingDenied {
        effector: String,
        secret_ref: String,
    },
    /// A repo-side manifest asks for more exposure than the vault floor
    /// permits for the entry's class (ARCH-0069 S2 — narrow-only).
    #[error(
        "manifest widens the vault floor for `{secret_ref}` ({class:?}): requested {requested:?} exceeds floor max {floor_max:?}"
    )]
    ManifestWidensFloor {
        secret_ref: String,
        class: crate::secret_custody::CustodyClass,
        requested: crate::secret_custody::CustodyTier,
        floor_max: crate::secret_custody::CustodyTier,
    },
    /// A requested custody tier is outside the admitted set for the
    /// record's class (SECRET-02, ONE-1920): the ONE tier-admission deny —
    /// floor band membership AND binding ceiling, stated once in
    /// `secret_lease::tier_admission`.
    #[error(
        "secret tier admission denied ({class:?}): requested {requested:?} exceeds the floor max {floor_max:?} or the binding ceiling {binding_ceiling:?} (band min {floor_min:?} is informational)"
    )]
    SecretTierDenied {
        class: crate::secret_custody::CustodyClass,
        requested: crate::secret_custody::CustodyTier,
        floor_min: crate::secret_custody::CustodyTier,
        floor_max: crate::secret_custody::CustodyTier,
        binding_ceiling: crate::secret_custody::CustodyTier,
    },
    /// A file the write door could not read whole (an encrypted, malformed or
    /// over-bound container) is stored as it is and served to the vault
    /// owner and to an agent a grant covers; this reader gets no copy of it
    /// (owner ruling C2).
    #[error("a sealed file is withheld: the vault owner and a granted agent read it")]
    SealedFileWithheld,
    /// The credential-door dial no longer admits this door-bound T0/T1
    /// materialization. The reason never contains secret or manifest bytes.
    #[error("secret materialization refused by credential-door policy: {reason}")]
    SecretDoorPolicyRefused { reason: &'static str },
    /// A door/lease call named a secret ref with no live custody record
    /// (SECRET-02).
    #[error("no live secret custody record for ref `{name}`")]
    SecretRefNotFound { name: String },
    /// An owner registration asks for more than the repo manifest declares
    /// for the name: a wider class, a binding the entry does not declare, a
    /// higher tier or another scope (ARCH-0069 S2: the manifest may only
    /// narrow).
    #[error("registration of `{secret_ref}` is wider than the repo manifest: {reason}")]
    SecretWiderThanManifest {
        secret_ref: String,
        reason: &'static str,
    },
    /// The named repository publishes no secret manifest at the named ref.
    #[error("no secret manifest published at `{source_ref}`")]
    SecretManifestNotFound { source_ref: String },
    /// A secret-lease call named a lease id with no row (SECRET-02).
    #[error("no secret lease row for id {}", lease_id.to_hex())]
    SecretLeaseNotFound { lease_id: EntityId },
    /// A secret lease was used while `Expired`/`Revoked` (SECRET-02).
    #[error("secret lease {} is not active: {status:?}", lease_id.to_hex())]
    SecretLeaseNotActive {
        lease_id: EntityId,
        status: crate::secret_lease::SecretLeaseStatus,
    },
    /// A T2 registration named a path the record's manifest entry does not
    /// declare (SECRET-02; SECRET-03 excludes exactly the declared set).
    #[error("path `{path}` is not a manifest-declared secret path for `{secret_ref}`")]
    SecretLeasePathNotDeclared { secret_ref: String, path: String },
    /// A T2 registration named a DIFFERENT declared path under a lease that
    /// already holds a live registration (SECRET-02, SOL-1920-02): one
    /// registration row per lease — overwriting the row would orphan the
    /// first file beyond revoke/expiry. The caller mints a fresh lease for
    /// a new path.
    #[error(
        "secret lease {} already registers `{registered_path}`; requested `{requested_path}` — mint a fresh lease for a new path",
        lease_id.to_hex()
    )]
    SecretLeasePathConflict {
        lease_id: EntityId,
        registered_path: String,
        requested_path: String,
    },
    /// The declared T2 target failed the file policy (SECRET-02,
    /// SOL-1920-03): a symlink the vault never follows, a non-regular
    /// occupant, or a stray file no live registration under this lease
    /// covers — the vault never clobbers a path it did not create.
    #[error("secret lease target path `{path}` refused: {reason}")]
    SecretLeasePathRefused { path: String, reason: &'static str },
    /// The materialization receipt could not be written durable — the
    /// lease row and the value never escape a failed receipt (S3; the
    /// `#[cfg(test)]` fault hook injects this).
    #[error("secret lease materialization receipt write failed: {0}")]
    SecretLeaseReceiptWriteFailed(&'static str),
    /// A secret-lease/receipt/registration row failed structural
    /// validation (SECRET-02).
    #[error("invalid secret lease body: {0}")]
    InvalidSecretLeaseBody(&'static str),
    /// A secret grant was redeemed after its record rotated: it pins the
    /// value generation it was minted at (FIX 4313). Renewing it mints a
    /// fresh grant at the current generation; nothing already delivered is
    /// recalled.
    #[error(
        "secret grant {} was minted at generation {pinned_generation}; the secret has rotated to generation {current_generation}: renew the grant",
        grant_id.to_hex()
    )]
    SecretGrantStale {
        grant_id: EntityId,
        pinned_generation: u32,
        current_generation: u32,
    },
    /// A secret grant was presented for a use it does not bind: another
    /// operation, connector, destination or effector (FIX 4313).
    #[error("secret grant {} does not cover this use: {reason}", grant_id.to_hex())]
    SecretGrantTargetMismatch {
        grant_id: EntityId,
        reason: &'static str,
    },
    /// A door grant has made every send its use count allows (FIX 4313).
    #[error("secret grant {} has made its {sends} sends", grant_id.to_hex())]
    SecretGrantSpent { grant_id: EntityId, sends: u32 },
    /// A T1 grant's bytes could not reach the host destination it names:
    /// the run's host registered no such destination, or refused the
    /// delivery (FIX 4313). The reason never carries value bytes.
    #[error("secret delivery to host destination `{destination}` refused: {reason}")]
    SecretHostDeliveryRefused {
        destination: String,
        reason: &'static str,
    },
    /// A grant's teardown revoked it, but its cleanup kept a copy the vault
    /// wrote (a T2 file that could not be removed, a destination the host
    /// could not clear); the retry sweep keeps trying (FIX 4313).
    #[error(
        "secret grant {} is revoked, but its cleanup kept the copy it delivered",
        grant_id.to_hex()
    )]
    SecretGrantCleanupKept { grant_id: EntityId },
    /// A rotation-receipt row or a stored taint-ref list failed structural
    /// validation (SECRET-04, ONE-1922).
    #[error("invalid secret rotation body: {0}")]
    InvalidSecretRotationBody(&'static str),
    /// A publish was refused because the artifact is secret-tainted by a
    /// record that has since ROTATED or been REVOKED (ARCH-0069 S7,
    /// read-time invalidation). A dial, not a wall: the resolved policy key
    /// `secret.taint.allow_stale_publish` permits the publish anyway, and
    /// the pointer row is stamped when it does.
    #[error(
        "artifact `{artifact}` is secret-tainted by a rotated or revoked record; publish refused (set secret.taint.allow_stale_publish to override)"
    )]
    TaintedArtifactStale { artifact: String },
    /// A world key, one of its wraps, or the recovery root was refused: a wrong
    /// world, generation, owner, policy, recipient or suite, or a key this machine
    /// may not hold. The reason is a fixed name, never key or envelope bytes.
    #[error("world key refused: {0}")]
    WorldKeyRefused(&'static str),
    /// No capsule of a sealed bundle or pad object opens for this key: it was
    /// sealed to other readers, as before this machine was added (FIX 4274).
    /// A world key refusal by kind.
    #[error("world key refused: no capsule of the object opens for this key")]
    SealedBundleNoCapsule,
    /// This install has no this-device-only keystore, so it can hold no machine
    /// secret and open no world key.
    #[error("no this-device-only keystore: {0}")]
    KeystoreUnavailable(&'static str),
    /// A kit seed this install cannot authenticate: fewer than two genuine
    /// stored pieces, no fingerprint from one of the owner's machines, and no
    /// owner confirmation. Refused before any write; the client words it.
    #[error("the kit restore is not verified (root record {record:?})")]
    UnverifiedKitRestore { root: [u8; 32], record: KitRecord },
}

/// What the vault records of a kit seed's root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitRecord {
    /// The seed's own root is stored.
    Stored,
    /// Other roots are stored, none of them the seed's.
    Mismatch,
    /// No root is stored.
    None,
}

impl SecretError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidSecretCustodyBody(_) => ErrorKind::InvalidSecretCustodyBody,
            Self::SecretNameInUse { .. } => ErrorKind::SecretNameInUse,
            Self::SecretCustodyNotActive { .. } => ErrorKind::SecretCustodyNotActive,
            Self::SecretBindingDenied { .. } => ErrorKind::SecretBindingDenied,
            Self::ManifestWidensFloor { .. } => ErrorKind::ManifestWidensFloor,
            Self::SecretTierDenied { .. } => ErrorKind::SecretTierDenied,
            Self::SealedFileWithheld => ErrorKind::SealedFileWithheld,
            Self::SecretDoorPolicyRefused { .. } => ErrorKind::SecretDoorPolicyRefused,
            Self::SecretRefNotFound { .. } => ErrorKind::SecretRefNotFound,
            Self::SecretWiderThanManifest { .. } => ErrorKind::SecretWiderThanManifest,
            Self::SecretManifestNotFound { .. } => ErrorKind::SecretManifestNotFound,
            Self::SecretLeaseNotFound { .. } => ErrorKind::SecretLeaseNotFound,
            Self::SecretLeaseNotActive { .. } => ErrorKind::SecretLeaseNotActive,
            Self::SecretLeasePathNotDeclared { .. } => ErrorKind::SecretLeasePathNotDeclared,
            Self::SecretLeasePathConflict { .. } => ErrorKind::SecretLeasePathConflict,
            Self::SecretLeasePathRefused { .. } => ErrorKind::SecretLeasePathRefused,
            Self::SecretLeaseReceiptWriteFailed(_) => ErrorKind::SecretLeaseReceiptWriteFailed,
            Self::InvalidSecretRotationBody(_) => ErrorKind::InvalidSecretRotationBody,
            Self::TaintedArtifactStale { .. } => ErrorKind::TaintedArtifactStale,
            Self::InvalidSecretLeaseBody(_) => ErrorKind::InvalidSecretLeaseBody,
            Self::SecretGrantStale { .. } => ErrorKind::SecretGrantStale,
            Self::SecretGrantTargetMismatch { .. } => ErrorKind::SecretGrantTargetMismatch,
            Self::SecretGrantSpent { .. } => ErrorKind::SecretGrantSpent,
            Self::SecretHostDeliveryRefused { .. } => ErrorKind::SecretHostDeliveryRefused,
            Self::SecretGrantCleanupKept { .. } => ErrorKind::SecretGrantCleanupKept,
            Self::WorldKeyRefused(_) | Self::SealedBundleNoCapsule => ErrorKind::WorldKeyRefused,
            Self::KeystoreUnavailable(_) => ErrorKind::KeystoreUnavailable,
            Self::UnverifiedKitRestore { .. } => ErrorKind::UnverifiedKitRestore,
        }
    }
}

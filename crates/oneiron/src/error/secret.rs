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
    /// A door/lease call named a secret ref with no live custody record
    /// (SECRET-02).
    #[error("no live secret custody record for ref `{name}`")]
    SecretRefNotFound { name: String },
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
            Self::SecretRefNotFound { .. } => ErrorKind::SecretRefNotFound,
            Self::SecretLeaseNotFound { .. } => ErrorKind::SecretLeaseNotFound,
            Self::SecretLeaseNotActive { .. } => ErrorKind::SecretLeaseNotActive,
            Self::SecretLeasePathNotDeclared { .. } => ErrorKind::SecretLeasePathNotDeclared,
            Self::SecretLeasePathConflict { .. } => ErrorKind::SecretLeasePathConflict,
            Self::SecretLeasePathRefused { .. } => ErrorKind::SecretLeasePathRefused,
            Self::SecretLeaseReceiptWriteFailed(_) => ErrorKind::SecretLeaseReceiptWriteFailed,
            Self::InvalidSecretRotationBody(_) => ErrorKind::InvalidSecretRotationBody,
            Self::TaintedArtifactStale { .. } => ErrorKind::TaintedArtifactStale,
            Self::InvalidSecretLeaseBody(_) => ErrorKind::InvalidSecretLeaseBody,
        }
    }
}

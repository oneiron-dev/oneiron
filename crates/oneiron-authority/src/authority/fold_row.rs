//! A stored AUTHORITY_LOG row as the fold takes it (census L5-22 1a-iii;
//! RULING PLAN-L5-22-ERASED-ROWS = A).
//!
//! A row whose overlay record opens here is the whole entry. A sealed row
//! whose record does not open here (it has not reached this install yet, or
//! its subject's key is retired) still lands, as structure only: its
//! scaffold verifies, and the fold reads from it only what judges its
//! signer and places it (signer, sequence, parents, cosigns, and the public
//! fields a signer rule reads, [`PublicStanding`]). Nothing it made counts.
//! When custody later delivers the key, the same stored bytes open and the
//! fold counts the row from then on.

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

/// The public fields of a sealed row that its kind's signer rule reads
/// before the op's effect. None of them is an overlay leaf
/// ([`OVERLAY_LEAF_CLASSES`]), so each stays readable on a row whose record
/// does not open. A device key, tier and roles are the device's; its
/// attestation and transport binding are not read by a signer rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicStanding {
    /// A slip mint: its issuer is judged on the envelope alone.
    SlipMint,
    /// An agent grant act: the machine whose key signs it.
    AgentGrantAct { machine: EntityId },
    /// A residence result: the machine that ran the directive, and the
    /// directive with its entry.
    ResidenceResult {
        machine: EntityId,
        directive: EntityId,
        directive_entry: AuthorityEntryHash,
    },
    /// An owner work result: the executor and the request it answers.
    OwnerWorkResult {
        executor: EntityId,
        request: AuthorityEntryHash,
    },
    /// A genesis: the root device.
    Genesis {
        key: AuthorityKey,
        tier: AuthorityTier,
        roles: u16,
    },
    /// A device enrollment: the enrolled device.
    EnrollDevice {
        key: AuthorityKey,
        tier: AuthorityTier,
        roles: u16,
    },
    /// A key rotation: the new device.
    RotateKey {
        key: AuthorityKey,
        tier: AuthorityTier,
        roles: u16,
    },
    /// A re-root: the new root device.
    ReRoot {
        key: AuthorityKey,
        tier: AuthorityTier,
        roles: u16,
    },
}

/// A sealed row whose overlay record does not open here, verified without
/// it ([`verify_authority_public_row`]): its scaffold and its
/// [`PublicStanding`]. Only that verifier builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPublicRow {
    pub(super) scaffold: AuthorityEntryScaffold,
    pub(super) standing: PublicStanding,
}

impl AuthorityPublicRow {
    /// The row's verified signed envelope.
    pub fn scaffold(&self) -> &AuthorityEntryScaffold {
        &self.scaffold
    }

    /// The public fields its kind's signer rule reads.
    pub fn standing(&self) -> &PublicStanding {
        &self.standing
    }
}

/// One stored row as the fold takes it.
// A short-lived per-row read result, as `AuthorityEntryRead` is.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldRow {
    /// The whole entry: unsealed, or sealed and opened with its record.
    Open(AuthorityLogEntry),
    /// A sealed row whose record does not open here: structure only.
    PassThrough(AuthorityPublicRow),
}

impl FoldRow {
    /// The row's entry hash: BLAKE3 of its canonical stored bytes.
    ///
    /// # Errors
    /// An open entry that does not encode.
    pub fn hash(&self) -> Result<AuthorityEntryHash> {
        match self {
            Self::Open(entry) => authority_entry_hash(entry),
            Self::PassThrough(row) => Ok(row.scaffold.hash),
        }
    }

    /// The primary signature.
    pub fn signer(&self) -> &AuthoritySignature {
        match self {
            Self::Open(entry) => &entry.signer,
            Self::PassThrough(row) => &row.scaffold.signer,
        }
    }

    /// The quorum co-signatures.
    pub fn cosigns(&self) -> &[AuthoritySignature] {
        match self {
            Self::Open(entry) => &entry.cosigns,
            Self::PassThrough(row) => &row.scaffold.cosigns,
        }
    }

    /// The signer's sequence number.
    pub fn seq(&self) -> u64 {
        match self {
            Self::Open(entry) => entry.seq,
            Self::PassThrough(row) => row.scaffold.seq,
        }
    }

    /// The parent entry hashes.
    pub fn parent_hashes(&self) -> &[AuthorityEntryHash] {
        match self {
            Self::Open(entry) => &entry.parent_hashes,
            Self::PassThrough(row) => &row.scaffold.parent_hashes,
        }
    }

    /// The vault the row names; none for a genesis.
    pub fn vault_id(&self) -> Option<AuthorityVaultId> {
        match self {
            Self::Open(entry) => entry.vault_id,
            Self::PassThrough(row) => row.scaffold.vault_id,
        }
    }

    /// The whole entry, when its record opened here.
    pub fn open(&self) -> Option<&AuthorityLogEntry> {
        match self {
            Self::Open(entry) => Some(entry),
            Self::PassThrough(_) => None,
        }
    }

    /// The primary signer's public key.
    pub fn signer_key(&self) -> &AuthorityKey {
        &self.signer().public_key
    }

    /// The op, when the row's record opened here. A row that passes through
    /// has none: nothing it made counts.
    pub fn op(&self) -> Option<&AuthorityOp> {
        self.open().map(|entry| &entry.op)
    }

    /// The structure-only row, when its record does not open here.
    pub fn public(&self) -> Option<&AuthorityPublicRow> {
        match self {
            Self::Open(_) => None,
            Self::PassThrough(row) => Some(row),
        }
    }
}

impl PublicStanding {
    /// The device a genesis, an enrollment, a rotation or a re-root brings
    /// in: its key, tier and roles.
    pub fn incoming_device(&self) -> Option<(&AuthorityKey, AuthorityTier, u16)> {
        match self {
            Self::Genesis { key, tier, roles }
            | Self::EnrollDevice { key, tier, roles }
            | Self::RotateKey { key, tier, roles }
            | Self::ReRoot { key, tier, roles } => Some((key, *tier, *roles)),
            Self::SlipMint
            | Self::AgentGrantAct { .. }
            | Self::ResidenceResult { .. }
            | Self::OwnerWorkResult { .. } => None,
        }
    }
}

//! A root's purpose-limited delegation of leave-notice verification to its
//! successor (FIX 7932, Engine 19:59 = A), and its wire codec.
//!
//! At each ReRoot it settles, while its key is at hand, the predecessor root
//! signs one [`LeaveNoticeDelegation`] beside the move: the vault, itself, the
//! successor the move names, the move's entry hash, and the digest of the
//! delegation that made the predecessor root, when one did. It hands on one
//! thing only: accepting the vault's loss-of-access notices, and handing that
//! same scope onward. It grants no roster membership, read or sync access,
//! recovery right or checkpoint power, and it changes no recipient or outcome
//! the final key signs.
//!
//! The signature is a separate one made at the handoff, under its own domain
//! ([`LEAVE_NOTICE_DELEGATION_DOMAIN`]) and the existing classical suites of
//! [`AuthoritySignature`]. No signed log row is redacted, hash-projected or
//! signed again. It is a notice-only credential: never presented or counted
//! as root-attestation assurance, whose hash-based signature contract stays
//! as it is.
//!
//! The canonical bytes are one MessagePack map, its keys in field order; the
//! signature transcript is the domain and the same map without `signature`.
//! A decode refuses any other encoding of the same values, so a delegation
//! has one digest ([`leave_notice_delegation_digest`]).

use std::io::Cursor;

use rmpv::Value;

use crate::error::Result;

use super::*;

/// The domain a leave-notice delegation's signature transcript begins with.
pub const LEAVE_NOTICE_DELEGATION_DOMAIN: &[u8] = b"oneiron/leave-notice-delegation/v1";
/// The domain of a leave-notice delegation's digest: BLAKE3 over it and the
/// delegation's canonical bytes.
pub const LEAVE_NOTICE_DELEGATION_DIGEST_DOMAIN: &[u8] =
    b"oneiron/leave-notice-delegation/digest/v1";
/// The schema version every leave-notice delegation carries.
pub const LEAVE_NOTICE_DELEGATION_SCHEMA_VERSION: u64 = 1;
/// The most bytes one leave-notice delegation's canonical encoding takes;
/// a longer one is refused before it is decoded.
pub const MAX_LEAVE_NOTICE_DELEGATION_BYTES: usize = 1024;

const LEAVE_NOTICE_DELEGATION_KEYS: [&str; 8] = [
    "schema_version",
    "authority_vault_id",
    "predecessor",
    "successor",
    "handoff_entry",
    "predecessor_delegation",
    "purpose",
    "signature",
];

/// What a leave-notice delegation hands on: only this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeaveNoticeDelegationPurpose {
    /// Accepting the vault's loss-of-access notices the successor signs,
    /// and handing that same scope onward. Nothing else.
    LeaveNoticesOnly,
}

impl LeaveNoticeDelegationPurpose {
    /// The purpose's wire id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaveNoticesOnly => "leave_notices_only",
        }
    }

    /// The purpose a wire id names; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "leave_notices_only" => Some(Self::LeaveNoticesOnly),
            _ => None,
        }
    }
}

/// One root's delegation of leave-notice verification to the successor its
/// ReRoot names, signed by that root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveNoticeDelegation {
    /// [`LEAVE_NOTICE_DELEGATION_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// The authority vault the ReRoot moves the root of.
    pub authority_vault_id: AuthorityVaultId,
    /// The root that signed the ReRoot, and signs this delegation.
    pub predecessor: AuthorityKey,
    /// The key the ReRoot hands the root on to.
    pub successor: AuthorityKey,
    /// The ReRoot's entry hash.
    pub handoff_entry: AuthorityEntryHash,
    /// The digest of the delegation that made `predecessor` root, when one
    /// did; `None` when no delegation did (a genesis root, or a root made
    /// before delegations were signed).
    pub predecessor_delegation: Option<[u8; 32]>,
    /// What the delegation hands on.
    pub purpose: LeaveNoticeDelegationPurpose,
    /// `predecessor`'s signature over [`Self::transcript`].
    pub signature: AuthoritySignature,
}

impl LeaveNoticeDelegation {
    /// The delegation's own shape: the one schema version, two distinct
    /// valid keys, and a well-formed signature made by `predecessor`.
    ///
    /// # Errors
    ///
    /// Any other shape.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != LEAVE_NOTICE_DELEGATION_SCHEMA_VERSION
            || self.predecessor == self.successor
            || self.signature.public_key != self.predecessor
        {
            return Err(invalid_authority());
        }
        self.predecessor.validate()?;
        self.successor.validate()?;
        self.signature.validate()
    }

    /// What `predecessor` signs: [`LEAVE_NOTICE_DELEGATION_DOMAIN`], then the
    /// canonical map without its signature.
    ///
    /// # Errors
    ///
    /// An encode failure.
    pub fn transcript(&self) -> Result<Vec<u8>> {
        let unsigned = encode_value(&Value::Map(self.unsigned_entries()))?;
        Ok([LEAVE_NOTICE_DELEGATION_DOMAIN, &unsigned].concat())
    }

    /// Whether the delegation is well formed and `predecessor` signed it.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.validate().is_ok()
            && self
                .transcript()
                .is_ok_and(|transcript| verify_authority_signature(&self.signature, &transcript))
    }

    /// The canonical bytes: the signed map, keys in field order.
    ///
    /// # Errors
    ///
    /// A delegation that is not well formed, or an encode failure.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut entries = self.unsigned_entries();
        entries.push((Value::from("signature"), signature_value(&self.signature)));
        encode_value(&Value::Map(entries))
    }

    /// Decodes canonical bytes ([`Self::encode`]); the signature is not
    /// checked here ([`Self::verify`]).
    ///
    /// # Errors
    ///
    /// Bytes past [`MAX_LEAVE_NOTICE_DELEGATION_BYTES`], trailing bytes, an
    /// unknown or missing key, an unknown suite or purpose, a delegation that
    /// is not well formed, or any encoding other than the canonical one.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_LEAVE_NOTICE_DELEGATION_BYTES {
            return Err(invalid_authority());
        }
        let mut cursor = Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_authority())?;
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid_authority());
        }
        let entries = map_entries(&value)?;
        validate_keys(entries, &LEAVE_NOTICE_DELEGATION_KEYS)?;
        let delegation = Self {
            schema_version: required(entries, "schema_version")?
                .as_u64()
                .ok_or_else(invalid_authority)?,
            authority_vault_id: decode_hash(required(entries, "authority_vault_id")?)?,
            predecessor: decode_key(required(entries, "predecessor")?)?,
            successor: decode_key(required(entries, "successor")?)?,
            handoff_entry: decode_hash(required(entries, "handoff_entry")?)?,
            predecessor_delegation: decode_optional_hash(required(
                entries,
                "predecessor_delegation",
            )?)?,
            purpose: required(entries, "purpose")?
                .as_str()
                .and_then(LeaveNoticeDelegationPurpose::parse)
                .ok_or_else(invalid_authority)?,
            signature: super::wire_decode::decode_signature(required(entries, "signature")?)?,
        };
        if delegation.encode()? != bytes {
            return Err(invalid_authority());
        }
        Ok(delegation)
    }

    /// The map's entries but its signature, in field order.
    fn unsigned_entries(&self) -> Vec<(Value, Value)> {
        vec![
            (
                Value::from("schema_version"),
                Value::from(self.schema_version),
            ),
            (
                Value::from("authority_vault_id"),
                binary_value(self.authority_vault_id),
            ),
            (Value::from("predecessor"), key_value(&self.predecessor)),
            (Value::from("successor"), key_value(&self.successor)),
            (
                Value::from("handoff_entry"),
                binary_value(self.handoff_entry),
            ),
            (
                Value::from("predecessor_delegation"),
                self.predecessor_delegation.map_or(Value::Nil, binary_value),
            ),
            (Value::from("purpose"), Value::from(self.purpose.as_str())),
        ]
    }
}

/// The digest of a delegation's canonical bytes `bytes`: BLAKE3 over
/// [`LEAVE_NOTICE_DELEGATION_DIGEST_DOMAIN`] and them. A later delegation
/// names its predecessor's by this digest.
#[must_use]
pub fn leave_notice_delegation_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAVE_NOTICE_DELEGATION_DIGEST_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

//! The one error type. Every parser and policy refusal has its own variant; every
//! cryptographic failure on open is the single opaque [`Error::OpenFailed`].

use crate::envelope::{Purpose, WrapType};
use crate::keys::Argon2Cost;
use crate::record::SigPurpose;
use crate::suite::SuiteKind;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Every refusal the crate can return. Variants carry ids, names and lengths only,
/// never key or plaintext bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input does not start with the expected magic bytes.
    #[error("not a {expected} encoding (bad magic)")]
    BadMagic { expected: &'static str },
    /// The canonical encoding version is not one this build reads.
    #[error("unsupported encoding version {0}")]
    UnsupportedVersion(u16),
    /// The suite id is not in the suite table.
    #[error("unknown suite id {0:#06x}")]
    UnknownSuite(u16),
    /// The suite is in the table and forbidden.
    #[error("suite {0} is forbidden")]
    ForbiddenSuite(&'static str),
    /// The suite is named for a pilot and is not implemented.
    #[error("suite {0} is reserved and not implemented")]
    ReservedSuite(&'static str),
    /// The suite id names a suite of the wrong kind for its slot.
    #[error("suite {suite} is a {actual:?} suite where a {expected:?} suite is required")]
    WrongSuiteKind {
        suite: &'static str,
        expected: SuiteKind,
        actual: SuiteKind,
    },
    /// The reader's policy does not accept this suite.
    #[error("suite {0} is not accepted by the reader's policy")]
    SuiteNotAccepted(&'static str),
    /// The epoch is below the suite's minimum epoch.
    #[error("epoch {epoch} is below the minimum epoch {min} of suite {suite}")]
    EpochBelowSuiteMinimum {
        suite: &'static str,
        epoch: u64,
        min: u64,
    },
    /// The epoch is below the reader's minimum accepted epoch.
    #[error("epoch {epoch} is below the reader's minimum epoch {min}")]
    EpochBelowPolicyMinimum { epoch: u64, min: u64 },
    /// The wrap type byte is not registered.
    #[error("unknown wrap type {0}")]
    UnknownWrap(u8),
    /// The KDF id byte is not registered.
    #[error("unknown kdf id {0}")]
    UnknownKdf(u8),
    /// The envelope purpose is not registered.
    #[error("unknown envelope purpose {0}")]
    UnknownPurpose(u16),
    /// The signature-record purpose is not registered.
    #[error("unknown signature purpose {0}")]
    UnknownSigPurpose(u16),
    /// The signature-record body tag is not registered.
    #[error("unknown record body tag {0}")]
    UnknownBody(u8),
    /// The KDF does not belong with the wrap type.
    #[error("kdf {kdf} is not allowed with wrap type {wrap:?}")]
    KdfWrapMismatch { wrap: WrapType, kdf: &'static str },
    /// A KDF cost parameter is outside the accepted range.
    #[error("kdf parameter {param} = {value} is outside [{min}, {max}]")]
    KdfParamOutOfRange {
        param: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
    /// The Shamir share-set parameters are invalid.
    #[error("invalid Shamir parameters: threshold {threshold} of {shares}")]
    ShamirParamsInvalid { threshold: u8, shares: u8 },
    /// The input ended inside a field.
    #[error("truncated in field {field}")]
    Truncated { field: &'static str },
    /// A field's length is outside its bound.
    #[error("field {field} has length {len}, allowed {min}..={max}")]
    FieldLength {
        field: &'static str,
        len: usize,
        min: usize,
        max: usize,
    },
    /// Bytes follow the last field.
    #[error("{extra} trailing bytes after the encoding")]
    TrailingBytes { extra: usize },
    /// The envelope purpose is not the one the reader expects.
    #[error("purpose {found:?} where {expected:?} is expected")]
    PurposeMismatch { expected: Purpose, found: Purpose },
    /// The record purpose is not the one the verifier expects.
    #[error("signature purpose {found:?} where {expected:?} is expected")]
    SigPurposeMismatch {
        expected: SigPurpose,
        found: SigPurpose,
    },
    /// The vault id is not the one the reader expects.
    #[error("vault id does not match the reader's vault")]
    VaultMismatch,
    /// The recipient id is not the reader.
    #[error("recipient id does not match the reader")]
    RecipientMismatch,
    /// The key id is not the one the reader holds.
    #[error("key id does not match the reader's key")]
    KeyIdMismatch,
    /// The signer id is not the one the verifier expects.
    #[error("signer id does not match the verifier's expected signer")]
    SignerMismatch,
    /// The key given to open or seal is for another wrap type.
    #[error("the key given is not a key for wrap type {wrap:?}")]
    WrongKeyForWrap { wrap: WrapType },
    /// The same nonce appeared twice under one key id.
    #[error("duplicate nonce under one key id")]
    DuplicateNonce,
    /// Authentication failed: wrong key, tampered metadata or tampered ciphertext.
    /// Deliberately one variant, so a caller cannot learn which part failed.
    #[error("envelope did not open: authentication failed")]
    OpenFailed,
    /// A recipient public key was refused (invalid ML-KEM encapsulation key or a
    /// non-contributory X25519 point).
    #[error("recipient public key refused")]
    KemKeyRejected,
    /// A signature suite named by the policy has no signature in the record.
    #[error("record is missing the required {0} signature")]
    SignatureMissing(&'static str),
    /// A signature suite appears twice in the record.
    #[error("record carries the {0} signature twice")]
    SignatureDuplicate(&'static str),
    /// The record carries a signature the policy does not ask for.
    #[error("record carries a {0} signature the policy does not require")]
    SignatureUnexpected(&'static str),
    /// A signature did not verify.
    #[error("{0} signature did not verify")]
    SignatureInvalid(&'static str),
    /// No verifying key with the entry's suite and key id was given.
    #[error("no verifying key for the {0} signature's key id")]
    VerifyingKeyMissing(&'static str),
    /// No signing key for a suite the record must carry.
    #[error("no signing key for the {0} component")]
    SigningKeyMissing(&'static str),
    /// The record body is a checkpoint reference. v1 never treats one as verified:
    /// it needs a separately verified checkpoint and inclusion proof (E4).
    #[error("checkpoint references need checkpoint verification, which v1 does not perform")]
    CheckpointRefUnverified,
    /// The Argon2id cost in the header is above the reader's budget.
    #[error("argon2id cost {requested:?} is above the reader's budget {budget:?}")]
    Argon2OverBudget {
        requested: Argon2Cost,
        budget: Argon2Cost,
    },
    /// The KDF work memory could not be allocated.
    #[error("could not allocate the KDF work memory")]
    OutOfMemory,
    /// The header parsed, but its bytes are not the one canonical encoding.
    #[error("header is not in canonical encoding")]
    NonCanonical,
    /// The random number generator failed.
    #[error("random number generator failed")]
    Rng,
    /// The reader's policy does not accept this wrap type.
    #[error("wrap type {0:?} is not accepted by the reader's policy")]
    WrapNotAccepted(WrapType),
    /// Signature entries are not in strictly ascending suite order.
    #[error("signature entries are not in canonical suite order")]
    UnsortedSignatures,
    /// A checkpoint reference's leaf index is not below its tree size.
    #[error("checkpoint leaf index {leaf_index} is not below tree size {tree_size}")]
    CheckpointIndexOutOfRange { leaf_index: u64, tree_size: u64 },
    /// A primitive refused its input after the bounds checks (should not happen).
    #[error("primitive refused its input: {0}")]
    Primitive(&'static str),
}

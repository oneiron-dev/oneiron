//! A custody work map: one change to one portable secret's custody (WILL L04
//! row 04), asked of the install the request names.
//!
//! The act's target is the secret's custody record id. The map holds the
//! change, the generation it approves, the digest of the encrypted input an
//! active change needs, the holder that does it and the recipients the owner
//! permits to hold its bytes: ids, digests and a generation only. No name,
//! value, manifest or effector text enters the main log. A revoke needs no
//! byte: it names no input, holder or recipient.
//!
//! Its `authority` says whose say-so carries it (FIX 6053): an install's,
//! whose key signs it as its carrier, or the owner's recovery kit, the one
//! push an install with no machine profile makes (CALLS CUSTODY_KIT_PUSH):
//! the anchor of the root the vault pins signs it, and no machine carries
//! or executes it.

use std::sync::Arc;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

const CUSTODY_WORK_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    "change",
    "generation",
    "input",
    "holder",
    "recipients",
    "authority",
];
const PERMIT_KEYS: [&str; 3] = ["machine", "profile", "encryption_key"];
const PERMIT_PIECES_KEYS: [&str; 3] = ["set", "count", "pieces"];

/// The domain of a custody change's complete-set commitment
/// ([`custody_recipient_set`]): every piece of the transition that enacts it
/// signs it (CALLS `Phase2 custody pieces request bound`).
pub const CUSTODY_RECIPIENT_SET_DOMAIN: &str = "oneiron/custody-recipient-set/v1";

/// The context a custody request's `seen` is hashed under: the live custody
/// request heads of its secret ([`act_revision`]).
pub const CUSTODY_WORK_REVISION_CONTEXT: &[u8] = b"oneiron/custody-work-revision/v1";

/// How a custody body carries the recipients it permits (CALLS
/// CUSTODY_SHARED_BODY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyBodyShape {
    /// Inline in the request's own work map, bounded before allocation. The
    /// shared [`OwnerWorkBody`] and [`OwnerWorkRequest`] are `Clone`, no
    /// longer `Copy`. A set past one row rides as its commitment
    /// ([`CustodyPermitPieces`]) in that map and its permits in numbered
    /// main-log piece rows ([`CustodyPermitPiece`], FIX 11866); no permit
    /// store of its own exists. The permits are one shared set
    /// ([`CustodyRecipientPermits`], FIX 12281): a clone of the body copies
    /// none.
    CloneNotCopy,
}

const CUSTODY_SHARED_BODY: CustodyBodyShape = CustodyBodyShape::CloneNotCopy;

/// The change a custody request asks for: the `change` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CustodyChange {
    /// Register a new portable secret from the encrypted input.
    Register,
    /// Replace the secret's value from the encrypted input, one generation
    /// on.
    Rotate,
    /// Seal the current value again, same generation and status, to the
    /// recipients permitted; with an encrypted input, the owner's bind, whose
    /// holder first takes the bindings it carries.
    Rewrap,
    /// End the secret here and on every replica: terminal for its id. No
    /// byte is needed.
    Revoke,
}

impl CustodyChange {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Rotate => "rotate",
            Self::Rewrap => "rewrap",
            Self::Revoke => "revoke",
        }
    }

    /// The change a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "register" => Self::Register,
            "rotate" => Self::Rotate,
            "rewrap" => Self::Rewrap,
            "revoke" => Self::Revoke,
            _ => return None,
        })
    }
}

/// Whose say-so a custody request stands on (FIX 6053, CALLS `KS-6 kit
/// request authority`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CustodyRequestAuthority {
    /// An install's: its carrier's install key signs it, its executor does
    /// the change, under the one carrier rule.
    Install,
    /// The owner's recovery kit's: the anchor of `root`, the root the vault
    /// pins, signs it from an install with no machine profile. A rewrap
    /// alone, with no input and no holder; no machine carries or executes
    /// it: its carrier and executor fields name the secret itself, and every
    /// reader takes this authority before either.
    PinnedKit { root: RecoveryRootId },
}

impl CustodyRequestAuthority {
    /// The root a kit request names; `None` for an install's.
    #[must_use]
    pub fn kit_root(self) -> Option<RecoveryRootId> {
        match self {
            Self::Install => None,
            Self::PinnedKit { root } => Some(root),
        }
    }
}

/// One install the owner permits to hold a custody change's bytes, bound to
/// the exact profile entry and encryption key he saw.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CustodyRecipientPermit {
    pub machine: EntityId,
    /// The entry hash of the machine profile admitted when he permitted it.
    pub profile: [u8; 32],
    /// The digest of the canonical encryption suite and public key.
    pub encryption_key: [u8; 32],
}

/// The recipients a custody change permits, in its order: one shared,
/// immutable set (FIX 12281). A clone shares it and copies no permit, so
/// every request the fold keeps on one joined set holds the same bytes.
/// Read through the slice it derefs to; its serde form, its ordering, its
/// `Hash` and its `Debug` text are the slice's. Built once from a list,
/// whose buffer it keeps without copying a permit.
#[derive(
    Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct CustodyRecipientPermits(Arc<Vec<CustodyRecipientPermit>>);

impl CustodyRecipientPermits {
    /// The permits, in their order.
    #[must_use]
    pub fn as_slice(&self) -> &[CustodyRecipientPermit] {
        &self.0
    }
}

impl std::ops::Deref for CustodyRecipientPermits {
    type Target = [CustodyRecipientPermit];

    fn deref(&self) -> &[CustodyRecipientPermit] {
        &self.0
    }
}

impl From<Vec<CustodyRecipientPermit>> for CustodyRecipientPermits {
    fn from(permits: Vec<CustodyRecipientPermit>) -> Self {
        Self(Arc::new(permits))
    }
}

impl From<&[CustodyRecipientPermit]> for CustodyRecipientPermits {
    fn from(permits: &[CustodyRecipientPermit]) -> Self {
        Self::from(permits.to_vec())
    }
}

impl std::fmt::Debug for CustodyRecipientPermits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_slice(), f)
    }
}

/// The commitment to a custody change's complete permitted set, in its
/// order: BLAKE3 under [`CUSTODY_RECIPIENT_SET_DOMAIN`] over the count and
/// each permit's machine, profile entry and key digest. A transition that
/// carries the set in pieces signs it in every piece, so no piece stands for
/// a partial set.
#[must_use]
pub fn custody_recipient_set(recipients: &[CustodyRecipientPermit]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CUSTODY_RECIPIENT_SET_DOMAIN);
    hasher.update(&(recipients.len() as u64).to_be_bytes());
    for permit in recipients {
        hasher.update(permit.machine.as_bytes());
        hasher.update(&permit.profile);
        hasher.update(&permit.encryption_key);
    }
    *hasher.finalize().as_bytes()
}

/// What a custody request carries in place of its permits when they
/// outgrow one row (FIX 11866): the commitment to its complete set
/// ([`custody_recipient_set`]), how many permits the set holds and how many
/// numbered piece rows ([`CustodyPermitPiece`]) carry them, each signed by
/// the request's own signer and in its causal past. The fold reads the
/// request's permits only from those pieces, joined, once they hash to the
/// commitment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CustodyPermitPieces {
    /// [`custody_recipient_set`] over the whole set, in its order.
    pub set: [u8; 32],
    /// How many permits the set holds.
    pub count: u32,
    /// How many piece rows carry them.
    pub pieces: u32,
}

impl CustodyPermitPieces {
    /// The commitment to `recipients` carried in `pieces` rows; `None` when
    /// either count is past its wire width.
    #[must_use]
    pub fn of(recipients: &[CustodyRecipientPermit], pieces: usize) -> Option<Self> {
        Some(Self {
            set: custody_recipient_set(recipients),
            count: u32::try_from(recipients.len()).ok()?,
            pieces: u32::try_from(pieces).ok()?,
        })
    }

    /// One permit at least, one piece at least and never more pieces than
    /// permits, and a set that is not zero.
    pub(super) fn validate(self) -> Result<()> {
        if self.count == 0 || self.pieces == 0 || self.pieces > self.count || self.set == [0; 32] {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Whether `recipients` is the whole set this commits to, in its order.
    #[must_use]
    pub fn commits_to(self, recipients: &[CustodyRecipientPermit]) -> bool {
        usize::try_from(self.count).is_ok_and(|count| count == recipients.len())
            && custody_recipient_set(recipients) == self.set
    }
}

/// Whether `recipients` ascend by machine, one each.
fn ascending(recipients: &[CustodyRecipientPermit]) -> bool {
    recipients
        .windows(2)
        .all(|pair| pair[0].machine < pair[1].machine)
}

/// A custody request's shape. A register or rotate states its input and its
/// holder, a rewrap its holder and an input only for a bind, each permitting
/// one or more recipients, ascending by machine, one each, never refused for
/// how many (Phase2 A, FIX 7906): its writer measures them, and its
/// transition carries them in pieces. The holder executes it. A revoke states none of them, and its
/// carrier executes it: a revoke needs no byte. No digest is zero.
///
/// Permits past one row ride in pieces (FIX 11866): the entry carries
/// their commitment and no permit inline, and the request as the fold keeps
/// it carries exactly the set it commits to.
pub(super) fn validate_custody(
    request: &OwnerWorkRequest,
    change: CustodyChange,
    input: Option<[u8; 32]>,
    holder: Option<EntityId>,
    recipients: &[CustodyRecipientPermit],
    pieces: Option<CustodyPermitPieces>,
    authority: CustodyRequestAuthority,
) -> Result<()> {
    let permitted = match pieces {
        None => !recipients.is_empty() && ascending(recipients),
        Some(pieces) => {
            pieces.validate().is_ok()
                && (recipients.is_empty()
                    || (ascending(recipients) && pieces.commits_to(recipients)))
        }
    };
    // A kit request: a rewrap with no input and no holder, to its permits;
    // no machine carries or executes it (FIX 6053).
    let shaped = if authority.kit_root().is_some() {
        change == CustodyChange::Rewrap
            && input.is_none()
            && holder.is_none()
            && permitted
            && request.carrier == request.act.target
            && request.executor == request.act.target
    } else {
        match change {
            CustodyChange::Revoke => {
                input.is_none()
                    && holder.is_none()
                    && recipients.is_empty()
                    && pieces.is_none()
                    && request.executor == request.carrier
            }
            CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap => {
                (input.is_some() || change == CustodyChange::Rewrap)
                    && holder == Some(request.executor)
                    && permitted
            }
        }
    };
    let zero = input.is_some_and(|input| input == [0; 32])
        || recipients
            .iter()
            .any(|permit| permit.profile == [0; 32] || permit.encryption_key == [0; 32]);
    if !shaped || zero {
        return Err(invalid_authority());
    }
    Ok(())
}

/// Canonical field order: kind, change, generation, input, holder,
/// recipients, then authority, each field the change does not state nil
/// (recipients empty); a permit map is machine, profile, then encryption
/// key; the authority is nil for an install's, the pinned root's id for the
/// kit's. Permits in pieces (FIX 11866) state, in recipients' place, their
/// commitment's map: set, count, then pieces.
pub(super) fn custody_work_value(
    change: CustodyChange,
    generation: u32,
    input: Option<[u8; 32]>,
    holder: Option<EntityId>,
    (recipients, pieces): (&[CustodyRecipientPermit], Option<CustodyPermitPieces>),
    authority: CustodyRequestAuthority,
) -> Value {
    let recipients = match (CUSTODY_SHARED_BODY, pieces) {
        (CustodyBodyShape::CloneNotCopy, None) => {
            Value::Array(recipients.iter().map(permit_value).collect())
        }
        (CustodyBodyShape::CloneNotCopy, Some(pieces)) => permit_pieces_value(pieces),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OwnerWorkKind::Custody.as_str()),
        ),
        (Value::from("change"), Value::from(change.as_str())),
        (Value::from("generation"), Value::from(generation)),
        (Value::from("input"), input.map_or(Value::Nil, binary_value)),
        (
            Value::from("holder"),
            holder.map_or(Value::Nil, |holder| Value::from(holder.to_hex())),
        ),
        (Value::from("recipients"), recipients),
        (
            Value::from("authority"),
            authority
                .kit_root()
                .map_or(Value::Nil, |root| binary_value(root.0)),
        ),
    ])
}

/// The bytes `recipients` take encoded as a custody request's row carries
/// them: what its writer measures against one sync frame (FIX 8087).
///
/// # Errors
/// When the codec cannot encode them.
pub fn custody_recipients_encoded_len(recipients: &[CustodyRecipientPermit]) -> Result<usize> {
    let list = recipients.iter().map(permit_value).collect();
    Ok(encode_value(&Value::Array(list))?.len())
}

pub(super) fn permit_value(permit: &CustodyRecipientPermit) -> Value {
    Value::Map(vec![
        (Value::from("machine"), Value::from(permit.machine.to_hex())),
        (Value::from("profile"), binary_value(permit.profile)),
        (
            Value::from("encryption_key"),
            binary_value(permit.encryption_key),
        ),
    ])
}

/// A permit set's commitment map: set, count, then pieces (FIX 11866).
pub(super) fn permit_pieces_value(pieces: CustodyPermitPieces) -> Value {
    Value::Map(vec![
        (Value::from("set"), binary_value(pieces.set)),
        (Value::from("count"), Value::from(pieces.count)),
        (Value::from("pieces"), Value::from(pieces.pieces)),
    ])
}

/// A u32 field of `entries`, strictly.
pub(super) fn decode_u32(entries: &[(Value, Value)], key: &str) -> Result<u32> {
    required(entries, key)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(invalid_authority)
}

/// Strict keys and a commitment of its own shape
/// ([`CustodyPermitPieces::validate`]).
pub(super) fn decode_permit_pieces(value: &Value) -> Result<CustodyPermitPieces> {
    let entries = map_entries(value)?;
    validate_keys(entries, &PERMIT_PIECES_KEYS)?;
    let pieces = CustodyPermitPieces {
        set: decode_hash(required(entries, "set")?)?,
        count: decode_u32(entries, "count")?,
        pieces: decode_u32(entries, "pieces")?,
    };
    pieces.validate()?;
    Ok(pieces)
}

/// Strict keys; every permitted recipient is decoded, however many, or the
/// commitment of a set in pieces, whose permits the entry does not carry
/// (FIX 11866). The shape is the request's ([`validate_custody`]).
pub(super) fn decode_custody_work(work: &[(Value, Value)]) -> Result<OwnerWorkBody> {
    validate_keys(work, &CUSTODY_WORK_KEYS)?;
    let listed = required(work, "recipients")?;
    let (recipients, pieces) = match (CUSTODY_SHARED_BODY, listed) {
        (CustodyBodyShape::CloneNotCopy, Value::Array(permits)) => (
            CustodyRecipientPermits::from(
                permits
                    .iter()
                    .map(decode_permit)
                    .collect::<Result<Vec<_>>>()?,
            ),
            None,
        ),
        (CustodyBodyShape::CloneNotCopy, Value::Map(_)) => (
            CustodyRecipientPermits::default(),
            Some(decode_permit_pieces(listed)?),
        ),
        _ => return Err(invalid_authority()),
    };
    Ok(OwnerWorkBody::Custody {
        change: required(work, "change")?
            .as_str()
            .and_then(CustodyChange::from_name)
            .ok_or_else(invalid_authority)?,
        generation: required(work, "generation")?
            .as_u64()
            .and_then(|generation| u32::try_from(generation).ok())
            .ok_or_else(invalid_authority)?,
        input: decode_optional_hash(required(work, "input")?)?,
        holder: match required(work, "holder")? {
            Value::Nil => None,
            value => Some(decode_canonical_id(value)?),
        },
        recipients,
        pieces,
        authority: match required(work, "authority")? {
            Value::Nil => CustodyRequestAuthority::Install,
            value => CustodyRequestAuthority::PinnedKit {
                root: RecoveryRootId(decode_hash(value)?),
            },
        },
    })
}

pub(super) fn decode_permit(value: &Value) -> Result<CustodyRecipientPermit> {
    let entries = map_entries(value)?;
    validate_keys(entries, &PERMIT_KEYS)?;
    Ok(CustodyRecipientPermit {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        profile: decode_hash(required(entries, "profile")?)?,
        encryption_key: decode_hash(required(entries, "encryption_key")?)?,
    })
}

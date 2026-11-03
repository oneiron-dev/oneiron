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
    /// ([`CustodyPermitSet`], FIX 12281, 12370): a clone of the body copies
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

/// The recipients a custody request permits, in its order: one shared run,
/// or the shared runs of its pieces read in place (FIX 12370).
///
/// A request the fold joins from several pieces holds every kept run under
/// one small `Arc` and reads them in piece order without copying a permit;
/// any other request holds one run. The logical permit sequence is what
/// serde, equality, ordering, hashing, `Debug`, validation and commitment
/// all read, so a segmented set is indistinguishable from its contiguous
/// join. Runs are immutable snapshots: a clone shares them and copies no
/// permit. Decoding lands as one run; stored rows never carry a segmented
/// form, and no set is ever deduped or reordered.
#[derive(Clone)]
pub struct CustodyPermitSet(CustodyPermitSetRuns);

/// One shared run, or several under one `Arc` (see [`CustodyPermitSet`]).
#[derive(Clone)]
enum CustodyPermitSetRuns {
    One(CustodyRecipientPermits),
    Many(Arc<Vec<CustodyRecipientPermits>>),
}

impl CustodyPermitSet {
    /// One run, shared: what an inline, single-piece or decoded set holds.
    #[must_use]
    pub fn from_run(run: CustodyRecipientPermits) -> Self {
        Self(CustodyPermitSetRuns::One(run))
    }

    /// `runs` in order, shared: what a multi-piece join holds, one small
    /// descriptor over the kept runs, copying no permit. One run or none
    /// lands as one run.
    #[must_use]
    pub fn from_runs(runs: Vec<CustodyRecipientPermits>) -> Self {
        if runs.len() <= 1 {
            Self::from_run(runs.into_iter().next().unwrap_or_default())
        } else {
            Self(CustodyPermitSetRuns::Many(Arc::new(runs)))
        }
    }

    /// The one run when this holds exactly one (an inline, staged or decoded
    /// set); `None` for a multi-piece join.
    #[must_use]
    pub fn single_run(&self) -> Option<&CustodyRecipientPermits> {
        match &self.0 {
            CustodyPermitSetRuns::One(run) => Some(run),
            CustodyPermitSetRuns::Many(_) => None,
        }
    }

    /// How many permits the set holds, over all its runs.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.0 {
            CustodyPermitSetRuns::One(run) => run.len(),
            CustodyPermitSetRuns::Many(runs) => runs.iter().map(|run| run.len()).sum(),
        }
    }

    /// Whether the set holds no permit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The permit at `index` in the set's order; `None` past its end.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&CustodyRecipientPermit> {
        match &self.0 {
            CustodyPermitSetRuns::One(run) => run.get(index),
            CustodyPermitSetRuns::Many(runs) => {
                let mut offset = index;
                for run in runs.iter() {
                    if let Some(permit) = run.get(offset) {
                        return Some(permit);
                    }
                    offset -= run.len();
                }
                None
            }
        }
    }

    /// The permits in the set's order, run by run.
    pub fn iter(&self) -> CustodyPermitSetIter<'_> {
        CustodyPermitSetIter {
            set: self,
            run: 0,
            index: 0,
        }
    }

    /// The permits in `start..end` in the set's order; empty past the set's
    /// end. Callers that need exact bounds check `end <= len` first.
    pub fn range(
        &self,
        start: usize,
        end: usize,
    ) -> impl Iterator<Item = &CustodyRecipientPermit> + '_ {
        self.iter().skip(start).take(end.saturating_sub(start))
    }

    /// Whether the set ascends by machine, one each, across every run
    /// boundary too.
    #[must_use]
    pub fn is_ascending(&self) -> bool {
        let mut previous: Option<&CustodyRecipientPermit> = None;
        for permit in self.iter() {
            if previous.is_some_and(|held| held.machine >= permit.machine) {
                return false;
            }
            previous = Some(permit);
        }
        true
    }

    /// Whether any permit names a zero digest.
    #[must_use]
    pub fn has_zero_digest(&self) -> bool {
        self.iter()
            .any(|permit| permit.profile == [0; 32] || permit.encryption_key == [0; 32])
    }

    /// The commitment to the set ([`custody_recipient_set`]), streamed run
    /// by run: the same bytes the contiguous join hashes.
    #[must_use]
    pub fn recipient_set(&self) -> [u8; 32] {
        hash_permit_sequence(self.len(), self.iter())
    }
}

/// Borrowed iteration over a [`CustodyPermitSet`], run by run in order.
#[derive(Debug, Clone)]
pub struct CustodyPermitSetIter<'a> {
    set: &'a CustodyPermitSet,
    run: usize,
    index: usize,
}

impl<'a> Iterator for CustodyPermitSetIter<'a> {
    type Item = &'a CustodyRecipientPermit;

    fn next(&mut self) -> Option<Self::Item> {
        let set: &'a CustodyPermitSet = self.set;
        loop {
            let slice = match &set.0 {
                CustodyPermitSetRuns::One(run) => {
                    if self.run > 0 {
                        return None;
                    }
                    run.as_slice()
                }
                CustodyPermitSetRuns::Many(runs) => runs.get(self.run)?.as_slice(),
            };
            if let Some(permit) = slice.get(self.index) {
                self.index += 1;
                return Some(permit);
            }
            self.run += 1;
            self.index = 0;
        }
    }
}

impl<'a> IntoIterator for &'a CustodyPermitSet {
    type Item = &'a CustodyRecipientPermit;
    type IntoIter = CustodyPermitSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Default for CustodyPermitSet {
    fn default() -> Self {
        Self::from_run(CustodyRecipientPermits::default())
    }
}

impl From<Vec<CustodyRecipientPermit>> for CustodyPermitSet {
    fn from(permits: Vec<CustodyRecipientPermit>) -> Self {
        Self::from_run(CustodyRecipientPermits::from(permits))
    }
}

impl From<&[CustodyRecipientPermit]> for CustodyPermitSet {
    fn from(permits: &[CustodyRecipientPermit]) -> Self {
        Self::from_run(CustodyRecipientPermits::from(permits))
    }
}

impl std::fmt::Debug for CustodyPermitSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for CustodyPermitSet {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for CustodyPermitSet {}

impl PartialOrd for CustodyPermitSet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CustodyPermitSet {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}

impl std::hash::Hash for CustodyPermitSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_length_prefix(self.len());
        for permit in self.iter() {
            permit.hash(state);
        }
    }
}

impl serde::Serialize for CustodyPermitSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for permit in self.iter() {
            seq.serialize_element(permit)?;
        }
        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for CustodyPermitSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<CustodyRecipientPermit>::deserialize(deserializer).map(Self::from)
    }
}

/// The commitment to a custody change's complete permitted set, in its
/// order: BLAKE3 under [`CUSTODY_RECIPIENT_SET_DOMAIN`] over the count and
/// each permit's machine, profile entry and key digest. A transition that
/// carries the set in pieces signs it in every piece, so no piece stands for
/// a partial set.
#[must_use]
pub fn custody_recipient_set(recipients: &[CustodyRecipientPermit]) -> [u8; 32] {
    hash_permit_sequence(recipients.len(), recipients.iter())
}

/// The commitment bytes of `len` permits in `permits`' order: the one
/// engine [`custody_recipient_set`] hashes for one run and
/// [`CustodyPermitSet::recipient_set`] streams for all of them.
fn hash_permit_sequence<'a>(
    len: usize,
    permits: impl Iterator<Item = &'a CustodyRecipientPermit>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CUSTODY_RECIPIENT_SET_DOMAIN);
    hasher.update(&(len as u64).to_be_bytes());
    for permit in permits {
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

    /// Whether `set` is the whole set this commits to, in its order.
    #[must_use]
    pub fn commits_to(self, set: &CustodyPermitSet) -> bool {
        usize::try_from(self.count).is_ok_and(|count| count == set.len())
            && set.recipient_set() == self.set
    }
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
    recipients: &CustodyPermitSet,
    pieces: Option<CustodyPermitPieces>,
    authority: CustodyRequestAuthority,
) -> Result<()> {
    let permitted = match pieces {
        None => !recipients.is_empty() && recipients.is_ascending(),
        Some(pieces) => {
            pieces.validate().is_ok()
                && (recipients.is_empty()
                    || (recipients.is_ascending() && pieces.commits_to(recipients)))
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
    let zero = input.is_some_and(|input| input == [0; 32]) || recipients.has_zero_digest();
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
    (recipients, pieces): (&CustodyPermitSet, Option<CustodyPermitPieces>),
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
            CustodyPermitSet::from(
                permits
                    .iter()
                    .map(decode_permit)
                    .collect::<Result<Vec<_>>>()?,
            ),
            None,
        ),
        (CustodyBodyShape::CloneNotCopy, Value::Map(_)) => (
            CustodyPermitSet::default(),
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

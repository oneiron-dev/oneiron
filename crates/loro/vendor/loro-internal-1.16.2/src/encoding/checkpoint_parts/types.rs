use loro_common::{Counter, Lamport, LoroEncodeError, LoroError, LoroValue, PeerID, ID};
use serde::{Deserialize, Serialize};

use crate::{version::Frontiers, VersionVector};

/// A caller-owned opaque owner handle. It is not a peer id and not a content hash.
pub type OwnerId = u64;

/// The ordinal of one atom in a [`Skeleton`]: an index into [`Skeleton::slots`].
pub type AtomId = u64;

/// Where a value sits in the captured document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// The value written by the retained op with this id.
    Op(ID),
    /// A shallow-root winner whose op is not in the retained history.
    Root,
}

/// One payload the classifier must assign to its rightful holders.
#[derive(Debug, Clone, Copy)]
pub enum Field<'a> {
    /// A map value.
    Value {
        root: &'a str,
        key: &'a str,
        value: &'a LoroValue,
        site: Site,
    },
    /// The commit message of the change starting at `change`.
    Message { change: ID, message: &'a str },
}

/// The caller's ownership and key rules for one capture.
///
/// It runs after the document locks are released, so it may not block on them,
/// but it must not edit the captured document.
pub trait Classify {
    /// Whether `key` of root map `root` is an opaque id or a fixed schema name.
    /// Keys stay plaintext in the skeleton, so any other key must answer false.
    fn plain_key(&mut self, root: &str, key: &str) -> bool;

    /// Every rightful holder of one value or message. `None` or an empty list
    /// leaves the document Unclassified.
    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>>;
}

/// Why a document stays Unclassified. This is not an error: the caller keeps
/// the carrier whole under its own seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    #[error("the document is not quiescent: uncommitted, detached, pending or mid-import")]
    NonQuiescent,
    #[error("a container is not an allowlisted root map")]
    Root,
    #[error("an op or value is not a plain root-map write")]
    Shape,
    #[error("a map key is not a proven opaque id or fixed schema name")]
    Key,
    #[error("a value or message has no rightful holder")]
    Ownership,
}

/// The result of [`LoroDoc::export_root_map_checkpoint`](crate::LoroDoc::export_root_map_checkpoint).
#[derive(Debug, Clone)]
pub enum Capture {
    Classified(Parts),
    Unclassified(Unsupported),
}

/// A classified capture: the skeleton and every atom, one per value or message site.
#[derive(Debug, Clone)]
pub struct Parts {
    pub skeleton: Skeleton,
    pub atoms: Vec<Atom>,
}

/// What a slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    Value,
    Message,
}

/// The skeleton's record of one atom: its kind and rightful holders, no payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub kind: SlotKind,
    pub holders: Vec<OwnerId>,
}

/// One map winner of a captured state: the entry of `key` in root map `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Winner {
    pub root: u32,
    pub key: String,
    pub peer: PeerID,
    pub lamport: Lamport,
    /// `None` is an original deletion; `Some` names the value's atom.
    pub value: Option<AtomId>,
}

/// One retained map op. Its counter is the change counter plus its index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkelOp {
    pub root: u32,
    pub key: String,
    /// `None` is an original delete; `Some` names the inserted value's atom.
    pub value: Option<AtomId>,
}

/// One retained change with its payloads replaced by atom ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkelChange {
    pub peer: PeerID,
    pub counter: Counter,
    pub lamport: Lamport,
    pub timestamp: i64,
    pub deps: Vec<(PeerID, Counter)>,
    pub message: Option<AtomId>,
    pub ops: Vec<SkelOp>,
}

/// The shallow root of a trimmed document: its start version and root-state winners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShallowRoot {
    pub vv: Vec<(PeerID, Counter)>,
    pub frontiers: Vec<(PeerID, Counter)>,
    /// Root maps present in the shallow-root state, empty ones included.
    pub maps: Vec<u32>,
    pub winners: Vec<Winner>,
}

/// The payload-free part of a capture. Keys are plaintext; values and
/// messages are atom ids into [`Skeleton::slots`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skeleton {
    /// Root map names; every `root` field indexes this list.
    pub roots: Vec<String>,
    /// `None` for a full-history document.
    pub shallow: Option<ShallowRoot>,
    pub vv: Vec<(PeerID, Counter)>,
    pub frontiers: Vec<(PeerID, Counter)>,
    /// Root maps present in the latest state, empty ones included.
    pub latest_maps: Vec<u32>,
    /// Every latest-state map entry, deleted keys included.
    pub latest: Vec<Winner>,
    /// The retained history in lamport order.
    pub changes: Vec<SkelChange>,
    /// Indexed by [`AtomId`].
    pub slots: Vec<Slot>,
}

/// An atom's payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Payload {
    Value(LoroValue),
    Message(String),
}

/// One value or message with its rightful holders.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Atom {
    pub id: AtomId,
    pub holders: Vec<OwnerId>,
    pub payload: Payload,
}

/// The output of [`LoroDoc::join_root_map_checkpoint`](crate::LoroDoc::join_root_map_checkpoint).
#[derive(Debug, Clone)]
pub struct Joined {
    /// Native snapshot bytes; `LoroDoc::from_snapshot` opens them.
    pub bytes: Vec<u8>,
    pub report: JoinReport,
}

/// What the join proved against the skeleton before it returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinReport {
    /// Every survivor op keeps its id, lamport, timestamp, deps, message, key
    /// and value; every erased value is a delete at its original id; every
    /// map winner keeps its peer and lamport; the latest and shallow version
    /// vectors and frontiers are unchanged. A join that cannot prove this
    /// returns [`CheckpointError::Diverged`] instead, so this is true.
    pub equivalent: bool,
    pub changes: usize,
    pub ops: usize,
    pub opened: usize,
    pub erased: usize,
    pub root_entries: usize,
    pub latest_entries: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("malformed checkpoint parts: {0}")]
    Malformed(String),
    #[error("joined document diverges from its skeleton: {0}")]
    Diverged(String),
    #[error(transparent)]
    Loro(#[from] LoroError),
    #[error(transparent)]
    Encode(#[from] LoroEncodeError),
}

// The outer codec stores these as bytes. Postcard keeps binary values typed;
// JSON would read them back as lists.
impl Skeleton {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        postcard::to_allocvec(self).map_err(|e| CheckpointError::Malformed(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointError> {
        postcard::from_bytes(bytes).map_err(|e| CheckpointError::Malformed(e.to_string()))
    }
}

impl Atom {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        postcard::to_allocvec(self).map_err(|e| CheckpointError::Malformed(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointError> {
        postcard::from_bytes(bytes).map_err(|e| CheckpointError::Malformed(e.to_string()))
    }
}

pub(super) fn vv_list(vv: &VersionVector) -> Vec<(PeerID, Counter)> {
    let mut list: Vec<_> = vv.iter().map(|(&peer, &counter)| (peer, counter)).collect();
    list.sort_unstable();
    list
}

pub(super) fn frontiers_list(frontiers: &Frontiers) -> Vec<(PeerID, Counter)> {
    let mut list: Vec<_> = frontiers.iter().map(|id| (id.peer, id.counter)).collect();
    list.sort_unstable();
    list
}

pub(super) fn list_vv(list: &[(PeerID, Counter)]) -> VersionVector {
    let mut vv = VersionVector::new();
    for &(peer, counter) in list {
        vv.insert(peer, counter);
    }
    vv
}

pub(super) fn list_frontiers(list: &[(PeerID, Counter)]) -> Frontiers {
    list.iter()
        .map(|&(peer, counter)| ID::new(peer, counter))
        .collect()
}

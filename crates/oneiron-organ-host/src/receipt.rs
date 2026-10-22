//! The engine's receipt for one organ call: facts the host computed, plus
//! the organ's notes, every one of them, whole (Rule 5): how many and how
//! long they run are `[limits]` rows, which ask whether everything is okay.

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron_organ_protocol::{
    AskCode, Hash32, Locator, Notes, OrganIdentity, ProtocolVersion, to_vec,
};
use serde::{Deserialize, Serialize};

use crate::spec::CallClass;

/// What one call read, made and took. Recall and the Dreamer read it as a
/// typed record; a landing writes it into the version's `made_by` envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReceipt {
    pub organ: OrganIdentity,
    /// The version the session speaks: the lower minor of both sides.
    pub protocol: ProtocolVersion,
    pub verb: String,
    pub schema: u32,
    /// blake3 of the call's args, as MessagePack.
    pub args_digest: Hash32,
    pub inputs: Vec<ReceiptInput>,
    /// blake3 of the base body, as MessagePack.
    pub base_body: Option<Hash32>,
    pub result_body: Option<Hash32>,
    pub outputs: Vec<ReceiptOutput>,
    /// The organ's word, every entry whole.
    pub notes: Notes,
    pub class: CallClass,
    pub grant: String,
    /// Waiting for the budget and the inputs.
    pub queue_us: u64,
    /// From sending the call to its verified reply.
    pub run_us: u64,
    /// Every ask the organ made, in order (protocol 1.1). A record written
    /// before 1.1 reads as none.
    #[serde(default)]
    pub asks: Vec<AskReceipt>,
    /// Memory the call took past the host's budget when every live call
    /// waited to grow (the soft-target exception, FIX 5284): fully
    /// accounted, and given back as the call's room drains.
    #[serde(default)]
    pub overcommit_bytes: u64,
    /// Time the call waited for budget room to grow, which its deadline
    /// does not count.
    #[serde(default)]
    pub room_wait_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptInput {
    /// The artifact id, hex; empty for bytes the caller lent.
    pub artifact: String,
    pub version: u64,
    pub content_hash: Hash32,
    pub len: u64,
    /// Bytes the caller held, not a vault version.
    #[serde(default)]
    pub lent: bool,
}

/// One ask, as the host saw it. Digests are blake3 over MessagePack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskReceipt {
    pub id: u32,
    pub verb: String,
    pub value_digest: Hash32,
    /// The refusal, if the ask got one.
    pub refused: Option<AskCode>,
    /// The answer's bytes the organ was lent, value and data.
    #[serde(default)]
    pub answer_len: u64,
    pub answer_digest: Option<Hash32>,
    /// The answer's bytes, hashed by the host as it sent them.
    pub data_hash: Option<Hash32>,
    pub data_len: u64,
    pub fetch: Option<FetchTarget>,
    pub handler_us: u64,
    /// Set when the organ got no answer because its call ended first.
    #[serde(default)]
    pub unanswered: Option<Unanswered>,
    /// What the handler's key was asked to sign, in the host's own words:
    /// set before the key runs, so it stays when the key failed after
    /// signing or the signature was never delivered.
    #[serde(default)]
    pub signed: Option<SignedReceipt>,
}

/// One signature a handler's key made for an ask. The organ supplied none
/// of these values: the host computed each one before the key signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub operation_id: String,
    /// The SHA-256 prehash the key signed.
    pub prehash: [u8; 32],
    /// SHA-256 of the content the prehash commits to: for a seal, the
    /// revision's ByteRange.
    pub content_sha256: [u8; 32],
    /// Which of the call's prepared revisions it signed, if the call has
    /// several.
    pub revision: Option<u32>,
    /// SHA-256 of the signature value; none when the key returned none,
    /// though it may still have signed.
    pub signature_sha256: Option<[u8; 32]>,
}

/// Why an ask got no answer: its call ended (cancelled, revoked, replied,
/// past its caps or its organ gone) before one was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unanswered {
    /// Nothing was decided for it: no handler ran, no refusal was made.
    NotRun,
    /// Its answer or refusal was decided but not sent; a handler that
    /// panicked leaves this too.
    NotSent,
}

/// Where a `net.fetch` went. The full URL is kept only as a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchTarget {
    /// `scheme://host:port` of the first hop.
    pub origin: String,
    pub url_digest: Hash32,
    /// The final HTTP status; 0 when nothing was fetched.
    pub status: u16,
    /// The redirects it followed, each hop checked afresh.
    #[serde(default)]
    pub redirects: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    pub len: u64,
}

/// Measures an organ's notes against the receipt rows and keeps every one,
/// in order and whole: a touched locator, a warning or a loss is never
/// dropped or cut for its count or its length.
pub(crate) fn measured_notes(vault: &Vault, notes: Notes) -> Notes {
    let items = notes
        .touched
        .len()
        .max(notes.warnings.len())
        .max(notes.losses.len());
    vault.measure_limit(EngineLimit::OrganNoteItems, items as u64);
    let longest = notes
        .touched
        .iter()
        .map(encoded_len)
        .chain(notes.warnings.iter().map(String::len))
        .chain(notes.losses.iter().map(|loss| loss.detail.len()))
        .max()
        .unwrap_or(0);
    vault.measure_limit(EngineLimit::OrganNoteBytes, longest as u64);
    let code = notes.losses.iter().map(|loss| loss.code.len()).max();
    vault.measure_limit(EngineLimit::OrganLossCodeBytes, code.unwrap_or(0) as u64);
    notes
}

fn encoded_len(locator: &Locator) -> usize {
    oneiron_organ_protocol::encoded_len(locator)
        .map_or(usize::MAX, |len| usize::try_from(len).unwrap_or(usize::MAX))
}

/// blake3 of a value's MessagePack encoding, in the protocol's codec.
pub(crate) fn digest<T: Serialize>(value: &T) -> Hash32 {
    to_vec(value).map_or_else(|_| Hash32([0; 32]), |bytes| Hash32::of(&bytes))
}

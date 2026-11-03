//! A custody input sealed under its own erasable carrier key (KS-6, FIX
//! 7402; CALLS `KS-6 carrier wire`): input v2, written only while
//! `CUSTODY_CARRIER_LEAF_WIRE` is on.
//!
//! The recorder mints the input's key in the writer that records the
//! request, before any byte is sealed (CALLS `KS-6 leaf deposit`). A body
//! it holds is sealed under the key once, whole, and those bytes are sealed
//! to the holder as before, one envelope or numbered ones (`envelopes`). An
//! input the owner's surface sealed to the holder itself, with what the
//! recorder attached beside it (`attached`), is sealed under the key on top,
//! as no surface holds a key and no deposit carries one. Either way the
//! input opens to no one once its key retires, the holder's permanent
//! machine key included.
//!
//! The input is its head, then those bytes: a label, the input wire
//! version, the layer, the key's reference and the digests a surface's same
//! input is found again by (CALLS CUSTODY_RETRY, [`RetryDigests`]; zero for
//! a recorder's own seal, which is fresh each time). The request's one
//! digest is over the whole, and it splits into numbered parts as before
//! (Rule 5), its head in the first, so every part names the same key, by the
//! digest its list is over, and its own index.
//!
//! The holder opens it only with the key in hand: answered live, in memory
//! (`leaf_delivery`), or in its own custody when it is the recorder. Until
//! then the request stays pending. Once it is answered, the recorder's key
//! retires and the holder's copy goes from memory.
//!
//! Both read the input where it lies (FIX 11140, `stream`). The door seals
//! a body it holds whole, then keeps the sealed input row by row. A
//! surface's input that fits one row is joined and sealed on top whole;
//! one past it is never joined, and is sealed on top in numbered parts as
//! it is read instead, each part within one row, under the same key (FIX
//! 12148, `parts`), read once into the rows kept (FIX 12177). The holder
//! reads the head, then the rest in order: the holder's envelopes as each
//! completes, the key's one seal within one row, or its numbered parts one
//! at a time.

mod parts;

use std::io::{self, Read};

use oneiron_crypto::HybridPublicKey;
use zeroize::Zeroizing;

pub(super) use self::parts::LeafParts;
use self::parts::{open_parts, part_count, read_leaf_rows_in_txn};

use super::super::super::carrier_custody::{
    CARRIER_REF_BYTES, CARRIER_SEAL_BYTES, CUSTODY_CARRIER_LEAF_WIRE, CUSTODY_INPUT_WIRE_VERSION,
    CarrierRef,
};
use super::door_rows::{DoorInput, StreamedDigest};
use super::stream::{KeptInput, open_framed, read_part};
use super::{
    Attached, InputBinding, MAX_PARTS, PART_BYTES, RelayedInput, SealedFrame, held_input_in_txn,
    input_digest, part_digest, part_key, parts_digest, refused,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, OwnerWorkBody, OwnerWorkRequest};
use crate::error::Result;
use crate::store::{CredentialLeaf, CustodyKind, Store};
use crate::world_keys::MachineSecret;

/// The label a leaf-sealed input opens with.
const LEAF_INPUT_LABEL: &[u8] = b"oneiron/custody-input-leaf\0";

/// The bytes a head's retry digests take: the input's own, then its first
/// part's.
const RETRY_BYTES: usize = 64;

/// The bytes a leaf-sealed input's head takes: its label, the input wire
/// version, the layer, the key's reference and the retry digests.
const LEAF_HEAD_BYTES: usize = LEAF_INPUT_LABEL.len() + 2 + CARRIER_REF_BYTES + RETRY_BYTES;

/// Where a leaf-sealed input's head holds its retry digests: its last
/// [`RETRY_BYTES`].
const LEAF_RETRY_AT: usize = LEAF_HEAD_BYTES - RETRY_BYTES;

/// The digests a surface's same input sent again is found by (CALLS
/// CUSTODY_RETRY), as a leaf-sealed input's head keeps them: the input's
/// own, as a request would name it unsealed, and its first part's, as
/// [`part_digest`] takes it of its first [`PART_BYTES`], which tells another
/// input apart once one part of it is read (FIX 12297). Zero for a
/// recorder's own seal, which is fresh each time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetryDigests {
    digest: [u8; 32],
    first: [u8; 32],
}

impl RetryDigests {
    /// A recorder's own seal's.
    const NONE: Self = Self {
        digest: [0; 32],
        first: [0; 32],
    };

    /// Those of `input`, joined within one part.
    fn of_joined(input: &[u8]) -> Self {
        Self {
            digest: input_digest(input),
            first: part_digest(input),
        }
    }

    /// Those of the input `digest` took as it was read through.
    pub(super) fn of_read(digest: StreamedDigest) -> Self {
        Self {
            first: digest.first_part(),
            digest: digest.finish(),
        }
    }

    /// The input's digest, then its first part's, as a head keeps them.
    fn encode(&self) -> [u8; RETRY_BYTES] {
        let mut out = [0; RETRY_BYTES];
        let (digest, first) = out.split_at_mut(32);
        digest.copy_from_slice(&self.digest);
        first.copy_from_slice(&self.first);
        out
    }
}

/// Where an input's carrier key seals it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafLayer {
    /// The recorder held the body: sealed under the key, then to the holder.
    UnderHolder,
    /// The owner's surface sealed to the holder: that, with what the
    /// recorder attached, sealed under the key, whole, within one row.
    OverHolder,
    /// The same past one row: sealed under the key in numbered parts
    /// (FIX 12148, `parts`).
    OverHolderParts,
}

impl LeafLayer {
    const fn byte(self) -> u8 {
        match self {
            Self::UnderHolder => 0,
            Self::OverHolder => 1,
            Self::OverHolderParts => 2,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::UnderHolder),
            1 => Some(Self::OverHolder),
            2 => Some(Self::OverHolderParts),
            _ => None,
        }
    }
}

/// What a recorder seals under its input's carrier key.
pub(crate) enum LeafSource<'a> {
    /// The body it holds: a register's framed record, a rotate's value, a
    /// bind's bindings.
    Body(&'a [u8]),
    /// The input the owner's surface sealed to the holder, with what the
    /// recorder attached beside it, joined within one row
    /// ([`SurfaceLeaf::Joined`]).
    Sealed(&'a [u8]),
}

/// How the input the owner's surface sealed is sealed under its carrier key
/// on top, while the carrier wire is on ([`surface_leaf_input`]).
pub(crate) enum SurfaceLeaf {
    /// One that fits one row, joined: sealed whole
    /// ([`seal_leaf_input_in_txn`]).
    Joined(Vec<u8>),
    /// One past it, read where it lies: sealed in numbered parts as it is
    /// read ([`seal_leaf_parts_in_txn`]).
    Parts,
}

/// What the input the owner's surface sealed is to the surface inputs kept
/// here for its secret (CALLS CUSTODY_RETRY, [`surface_retry_in_txn`]).
pub(crate) enum SurfaceRetry<'a> {
    /// The same input sent again: the live request, by its entry, whose
    /// kept input it is.
    Kept(AuthorityEntryHash),
    /// Another input, with its first part when it was read that far to tell
    /// (FIX 12297): its seal reads on from there.
    Fresh(Option<FirstPartRead<'a>>),
}

/// A surface's input past one row read as far as its first part to tell it
/// from the inputs kept for its secret (FIX 12297): that part's bytes, then
/// a reader of the rest, which its seal reads on from, so the input is read
/// once.
pub(crate) struct FirstPartRead<'a> {
    first: Vec<u8>,
    rest: Box<dyn Read + 'a>,
}

impl<'a> FirstPartRead<'a> {
    /// The input from its start: the part read, then the rest.
    fn into_reader(self) -> impl Read + 'a {
        io::Cursor::new(self.first).chain(self.rest)
    }
}

/// A leaf-sealed input's head as read: its key's reference, its layer and
/// the digests a surface's same input is found by.
struct LeafHead {
    carrier: CarrierRef,
    layer: LeafLayer,
    retry: RetryDigests,
}

/// The input the owner's surface sealed, `frame`, as it is sealed under
/// its carrier key on top while the carrier wire is on: joined when it fits
/// one row; past it not read here (FIX 11140 joins none past one row; FIX
/// 12177 reads it once, as it is kept). `None` while the wire is off.
///
/// # Errors
/// A fault reading the input from its file.
pub(crate) fn surface_leaf_input(frame: &SealedFrame<'_>) -> Result<Option<SurfaceLeaf>> {
    if !CUSTODY_CARRIER_LEAF_WIRE {
        return Ok(None);
    }
    Ok(Some(match frame.joined_within(PART_BYTES)? {
        Some(joined) => SurfaceLeaf::Joined(joined),
        None => SurfaceLeaf::Parts,
    }))
}

/// Seals the input of the request `binding` binds, while the carrier wire
/// is on, under a carrier key minted in `wtxn` before any byte is sealed:
/// `source`'s body under the key, then to the holder's `holder_key`; or a
/// surface's sealed input under the key on top. Returns the input, its head
/// first: what the request names the digest of.
///
/// # Errors
/// The mint's refusals (an archived vault, an erased credential, custody
/// faults); a seal that fails.
pub(crate) fn seal_leaf_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &InputBinding<'_>,
    holder_key: &HybridPublicKey,
    source: LeafSource<'_>,
) -> Result<Vec<u8>> {
    let (instance, leaf) = vault.store.mint_carrier_leaf_in_txn(
        wtxn,
        CustodyKind::CustodyRequestInput,
        &binding.id,
    )?;
    let carrier = CarrierRef::input(binding.id, instance, binding.generation);
    let (layer, retry, sealed) = match source {
        LeafSource::Body(body) => {
            let under = carrier.seal(&leaf, None, body)?;
            (
                LeafLayer::UnderHolder,
                RetryDigests::NONE,
                binding.seal(holder_key, &under)?,
            )
        }
        LeafSource::Sealed(input) => (
            LeafLayer::OverHolder,
            RetryDigests::of_joined(input),
            carrier.seal(&leaf, None, input)?,
        ),
    };
    let mut out = head_bytes(layer, &carrier, &retry);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Seals the input the owner's surface sealed, `frame`, past one row, for
/// the request `binding` binds, while the carrier wire is on, under a
/// carrier key minted in `wtxn` before any byte is sealed: in numbered
/// parts, each sealed as the frame is read (FIX 12148, `parts`). The frame
/// is read once, its rows staged in `wtxn` as they are sealed and digested
/// as they are staged, its own digests ([`RetryDigests`]) set in the head
/// once it is read through (FIX 12177). When the retry check read its first
/// part (`first_part`), the read goes on from there (FIX 12297). Returns
/// those rows.
///
/// # Errors
/// The mint's refusals (an archived vault, an erased credential, custody
/// faults); a frame past the part count's codec or the part list's bound; a
/// fault reading the frame from its file; storage errors.
pub(crate) fn seal_leaf_parts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &InputBinding<'_>,
    frame: SealedFrame<'_>,
    first_part: Option<FirstPartRead<'_>>,
) -> Result<DoorInput<'static>> {
    let plain = frame.input_len();
    let count = part_count(plain)?;
    let (instance, leaf) = vault.store.mint_carrier_leaf_in_txn(
        wtxn,
        CustodyKind::CustodyRequestInput,
        &binding.id,
    )?;
    let carrier = CarrierRef::input(binding.id, instance, binding.generation);
    // Its retry digests are set once the read is through.
    let head = head_bytes(LeafLayer::OverHolderParts, &carrier, &RetryDigests::NONE);
    let parts = LeafParts::new(head, carrier, leaf, count, plain);
    match first_part {
        Some(read) => read_leaf_rows_in_txn(vault, wtxn, parts.reader(read.into_reader()), &parts),
        None => {
            let reader = frame.under_leaf_parts(&parts).reader()?;
            read_leaf_rows_in_txn(vault, wtxn, reader, &parts)
        }
    }
}

/// A leaf-sealed input's head, [`LEAF_HEAD_BYTES`] of it: its label, the
/// input wire version, `layer`, `carrier`'s reference and the digests
/// `retry`.
fn head_bytes(layer: LeafLayer, carrier: &CarrierRef, retry: &RetryDigests) -> Vec<u8> {
    let mut head = Vec::with_capacity(LEAF_HEAD_BYTES);
    head.extend_from_slice(LEAF_INPUT_LABEL);
    head.push(CUSTODY_INPUT_WIRE_VERSION);
    head.push(layer.byte());
    head.extend_from_slice(&carrier.encode());
    head.extend_from_slice(&retry.encode());
    head
}

/// The head of the leaf-sealed input `input` opens with, while the carrier
/// wire is on and it is whole; `None` for any other input, which opens as
/// before.
fn leaf_head(input: &[u8]) -> Option<LeafHead> {
    if !CUSTODY_CARRIER_LEAF_WIRE {
        return None;
    }
    let rest = input.strip_prefix(LEAF_INPUT_LABEL)?;
    let (&[version, layer], rest) = rest.split_first_chunk::<2>()?;
    if version != CUSTODY_INPUT_WIRE_VERSION {
        return None;
    }
    let layer = LeafLayer::from_byte(layer)?;
    let (carrier, rest) = rest.split_first_chunk::<CARRIER_REF_BYTES>()?;
    let carrier = CarrierRef::decode(carrier)?;
    let (digest, rest) = rest.split_first_chunk::<32>()?;
    let (first, _) = rest.split_first_chunk::<32>()?;
    Some(LeafHead {
        carrier,
        layer,
        retry: RetryDigests {
            digest: *digest,
            first: *first,
        },
    })
}

/// Whether `carrier` is the input key of the request `binding` binds: a
/// request input's, of its secret, at the generation it approves.
pub(crate) fn input_carrier_binds(carrier: &CarrierRef, binding: &InputBinding<'_>) -> bool {
    carrier.kind == CustodyKind::CustodyRequestInput
        && carrier.credential == binding.id
        && carrier.generation == binding.generation
}

/// The body the kept leaf-sealed input `kept` holds, opened under
/// `carrier`'s key `leaf` and with the holder's `secret` under `binding`,
/// with what its recorder attached beside a surface's envelope: its rows
/// read in order, its head first (FIX 11140). `None` when its head is not
/// `carrier`'s, a surface's whole seal outgrows one row, a numbered part is
/// missing, out of place or left over, or any layer does not open.
///
/// # Errors
/// Storage errors reading a row.
pub(crate) fn open_leaf_input(
    kept: &KeptInput<'_, '_>,
    carrier: &CarrierRef,
    binding: &InputBinding<'_>,
    leaf: &CredentialLeaf,
    secret: &MachineSecret,
) -> Result<Option<(Zeroizing<Vec<u8>>, Option<Attached>)>> {
    kept.read_rows(|rows, len| {
        let mut head = [0; LEAF_HEAD_BYTES];
        rows.read_exact(&mut head).ok()?;
        let head = leaf_head(&head).filter(|head| head.carrier == *carrier)?;
        let len = len.checked_sub(LEAF_HEAD_BYTES as u64)?;
        match head.layer {
            LeafLayer::UnderHolder => {
                let under = binding.open(rows, len, secret)?;
                Some((carrier.open(leaf, None, &under).ok()?, None))
            }
            LeafLayer::OverHolder => {
                // Only a surface's input that fit one row was sealed on top.
                if len > (PART_BYTES + CARRIER_SEAL_BYTES) as u64 {
                    return None;
                }
                let mut sealed = vec![0; usize::try_from(len).ok()?];
                rows.read_exact(&mut sealed).ok()?;
                let over = carrier.open(leaf, None, &sealed).ok()?;
                open_framed(binding, over.as_slice(), over.len() as u64, secret)
            }
            LeafLayer::OverHolderParts => open_parts(rows, len, carrier, leaf, binding, secret),
        }
    })
}

/// The head row of the input the request names `digest` of, as this vault
/// keeps it: the whole input, or its first part.
fn head_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<RelayedInput>> {
    if let Some(whole) = held_input_in_txn(store, txn, digest)?
        && whole.part.is_none()
        && whole.digest() == *digest
    {
        return Ok(Some(whole));
    }
    Ok(
        held_input_in_txn(store, txn, &part_key(digest, 0))?.filter(|row| {
            row.part
                .as_ref()
                .is_some_and(|part| part.index == 0 && parts_digest(&part.digests) == *digest)
        }),
    )
}

/// The carrier key the input the request names `digest` of is sealed
/// under, read from its head row alone, when it is leaf-sealed and kept
/// here.
///
/// # Errors
/// Storage faults.
pub(crate) fn input_carrier_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<CarrierRef>> {
    if !CUSTODY_CARRIER_LEAF_WIRE {
        return Ok(None);
    }
    Ok(head_row_in_txn(store, txn, digest)?
        .and_then(|row| leaf_head(&row.envelope).map(|head| head.carrier)))
}

/// What the input the owner's surface sealed, `frame`, is to the surface
/// inputs kept here for the secret whose live custody requests are `heads`
/// (CALLS CUSTODY_RETRY): the same input sent again is the request whose
/// kept input sealed it, never a second change. It is read for that only
/// while such an input is kept here, and before its key is minted, so a
/// retry mints none (FIX 12177). One that fits a row is judged by its joined
/// bytes. One past it is read one part first: a first part no kept input
/// has makes it another input, and the part read is handed on for its seal
/// to read on from, so it is read once (FIX 12297); otherwise it is read
/// through for its own digest.
///
/// # Errors
/// Storage faults; a fault reading the input from its file; one past the
/// part list's bound.
pub(crate) fn surface_retry_in_txn<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    heads: Vec<(AuthorityEntryHash, &OwnerWorkRequest)>,
    surface: &SurfaceLeaf,
    frame: SealedFrame<'a>,
) -> Result<SurfaceRetry<'a>> {
    let mut kept = Vec::new();
    for (hash, live) in heads {
        if let OwnerWorkBody::Custody {
            input: Some(named), ..
        } = &live.work
            && let Some(retry) = kept_retry_in_txn(store, txn, named)?
        {
            kept.push((hash, retry));
        }
    }
    if kept.is_empty() {
        return Ok(SurfaceRetry::Fresh(None));
    }
    let digest = match surface {
        SurfaceLeaf::Joined(joined) => input_digest(joined),
        SurfaceLeaf::Parts => {
            let mut rest = frame.reader()?;
            let mut left = frame.input_len();
            let mut first = Vec::new();
            read_part(&mut rest, &mut first, &mut left)?;
            let first_digest = part_digest(&first);
            kept.retain(|(_, retry)| retry.first == first_digest);
            if kept.is_empty() {
                return Ok(SurfaceRetry::Fresh(Some(FirstPartRead { first, rest })));
            }
            read_through(rest, first, left, frame.input_len())?
        }
    };
    Ok(kept
        .into_iter()
        .find(|(_, retry)| retry.digest == digest)
        .map_or(SurfaceRetry::Fresh(None), |(hash, _)| {
            SurfaceRetry::Kept(hash)
        }))
}

/// The digest of an input of `len` bytes, as [`input_digest`] takes it,
/// from its first part `first` already read and `rest`, a reader with `left`
/// bytes of it still to read, read through part by part. Refused past the
/// part list's own bound, as [`SealedFrame::digests`] refuses.
fn read_through(mut rest: impl Read, first: Vec<u8>, mut left: u64, len: u64) -> Result<[u8; 32]> {
    let mut digest = StreamedDigest::new(len);
    digest.update(&first);
    let mut part = first;
    let mut parts = 1_usize;
    while left > 0 {
        read_part(&mut rest, &mut part, &mut left)?;
        digest.update(&part);
        parts += 1;
        if parts > MAX_PARTS {
            return Err(refused(
                "the custody input splits into more parts than one part list names",
            ));
        }
    }
    Ok(digest.finish())
}

/// The retry digests before its carrier seal of the input the request
/// names `named` of, when it is kept here and is a surface's input (CALLS
/// CUSTODY_RETRY): the same protected input sent again has them.
///
/// # Errors
/// Storage faults.
fn kept_retry_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    named: &[u8; 32],
) -> Result<Option<RetryDigests>> {
    Ok(head_row_in_txn(store, txn, named)?.and_then(|row| {
        leaf_head(&row.envelope)
            .filter(|head| {
                matches!(
                    head.layer,
                    LeafLayer::OverHolder | LeafLayer::OverHolderParts
                )
            })
            .map(|head| head.retry)
    }))
}

/// The carrier key of the kept input row `bytes`, when it heads a
/// leaf-sealed input: the whole, or its first part.
pub(crate) fn row_carrier(bytes: &[u8]) -> Option<CarrierRef> {
    let row = RelayedInput::decode(bytes)?;
    if row.part.as_ref().is_some_and(|part| part.index != 0) {
        return None;
    }
    leaf_head(&row.envelope).map(|head| head.carrier)
}

/// Retires each of `carriers`, in `wtxn`: what they sealed is answered or
/// gone (FIX 7402). A key this install's custody holds, as the recorder
/// that minted it, is staged to retire; a copy it was answered goes from
/// memory. A fault staging one is warned and leaves the key to its
/// credential's erase. Returns whether any was staged, for the finisher
/// after the commit.
pub(crate) fn retire_input_carriers_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    carriers: &[CarrierRef],
) -> bool {
    let mut staged = false;
    for carrier in carriers {
        vault.custody_leaves().forget(carrier);
        match vault.store.stage_carrier_retirement_in_txn(
            wtxn,
            carrier.kind,
            &carrier.credential,
            &carrier.instance,
        ) {
            Ok(done) => staged |= done,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an answered custody input's carrier key stays until its credential's erase"
            ),
        }
    }
    staged
}

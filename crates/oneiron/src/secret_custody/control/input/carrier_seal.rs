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
//! version, the layer, the key's reference and the digest a surface's same
//! input is found again by (CALLS CUSTODY_RETRY; zero for a recorder's own
//! seal, which is fresh each time). The request's one digest is over the
//! whole, and it splits into numbered parts as before (Rule 5), its head in
//! the first, so every part names the same key, by the digest its list is
//! over, and its own index.
//!
//! The holder opens it only with the key in hand: answered live, in memory
//! (`leaf_delivery`), or in its own custody when it is the recorder. Until
//! then the request stays pending. Once it is answered, the recorder's key
//! retires and the holder's copy goes from memory.
//!
//! Both read the input where it lies (FIX 11140, `stream`). The door seals
//! a body it holds whole, then keeps the sealed input row by row. A
//! surface's input is joined to be sealed on top, so only one that fits one
//! row is; one past it is kept as it lies, under the holder's key alone, as
//! with the wire off. The holder reads the head, then the rest in order:
//! the holder's envelopes as each completes, or the key's one seal, within
//! one row.

use std::io::Read;

use oneiron_crypto::HybridPublicKey;
use zeroize::Zeroizing;

use super::super::super::carrier_custody::{
    CARRIER_REF_BYTES, CARRIER_SEAL_BYTES, CUSTODY_CARRIER_LEAF_WIRE, CUSTODY_INPUT_WIRE_VERSION,
    CarrierRef,
};
use super::stream::{KeptInput, open_framed};
use super::{
    Attached, InputBinding, PART_BYTES, RelayedInput, SealedFrame, held_input_in_txn, input_digest,
    part_key, parts_digest,
};
use crate::Vault;
use crate::error::Result;
use crate::store::{CredentialLeaf, CustodyKind, Store};
use crate::world_keys::MachineSecret;

/// The label a leaf-sealed input opens with.
const LEAF_INPUT_LABEL: &[u8] = b"oneiron/custody-input-leaf\0";

/// The bytes a leaf-sealed input's head takes: its label, the input wire
/// version, the layer, the key's reference and the retry digest.
const LEAF_HEAD_BYTES: usize = LEAF_INPUT_LABEL.len() + 2 + CARRIER_REF_BYTES + 32;

/// Where an input's carrier key seals it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafLayer {
    /// The recorder held the body: sealed under the key, then to the holder.
    UnderHolder,
    /// The owner's surface sealed to the holder: that, with what the
    /// recorder attached, sealed under the key.
    OverHolder,
}

impl LeafLayer {
    const fn byte(self) -> u8 {
        match self {
            Self::UnderHolder => 0,
            Self::OverHolder => 1,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::UnderHolder),
            1 => Some(Self::OverHolder),
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
    /// recorder attached beside it, joined ([`surface_leaf_input`]).
    Sealed(&'a [u8]),
}

/// A leaf-sealed input's head as read: its key's reference, its layer and
/// the digest a surface's same input is found by.
struct LeafHead {
    carrier: CarrierRef,
    layer: LeafLayer,
    retry: [u8; 32],
}

/// The input the owner's surface sealed, `frame`, joined for its carrier
/// seal on top, while the carrier wire is on and it fits one row; `None`
/// past one row (FIX 11140 joins none), which is kept as it lies.
///
/// # Errors
/// A fault reading the input from its file.
pub(crate) fn surface_leaf_input(frame: &SealedFrame<'_>) -> Result<Option<Vec<u8>>> {
    if !CUSTODY_CARRIER_LEAF_WIRE {
        return Ok(None);
    }
    frame.joined_within(PART_BYTES)
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
                [0; 32],
                binding.seal(holder_key, &under)?,
            )
        }
        LeafSource::Sealed(input) => (
            LeafLayer::OverHolder,
            input_digest(input),
            carrier.seal(&leaf, None, input)?,
        ),
    };
    let mut out = Vec::with_capacity(
        LEAF_INPUT_LABEL.len() + 2 + CARRIER_REF_BYTES + retry.len() + sealed.len(),
    );
    out.extend_from_slice(LEAF_INPUT_LABEL);
    out.push(CUSTODY_INPUT_WIRE_VERSION);
    out.push(layer.byte());
    out.extend_from_slice(&carrier.encode());
    out.extend_from_slice(&retry);
    out.extend_from_slice(&sealed);
    Ok(out)
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
    let (retry, _) = rest.split_first_chunk::<32>()?;
    Some(LeafHead {
        carrier,
        layer,
        retry: *retry,
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
/// `carrier`'s, a surface's seal outgrows one row, or any layer does not
/// open.
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

/// Whether the input the request names `named` of, kept here, is a
/// surface's input whose digest before its carrier seal is `retry` (CALLS
/// CUSTODY_RETRY): the same protected input sent again.
///
/// # Errors
/// Storage faults.
pub(crate) fn leaf_input_retries_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    named: &[u8; 32],
    retry: &[u8; 32],
) -> Result<bool> {
    Ok(head_row_in_txn(store, txn, named)?.is_some_and(|row| {
        leaf_head(&row.envelope)
            .is_some_and(|head| head.layer == LeafLayer::OverHolder && head.retry == *retry)
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

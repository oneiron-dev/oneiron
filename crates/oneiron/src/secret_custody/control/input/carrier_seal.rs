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

use oneiron_crypto::HybridPublicKey;
use zeroize::Zeroizing;

use super::super::super::carrier_custody::{
    CARRIER_REF_BYTES, CUSTODY_CARRIER_LEAF_WIRE, CUSTODY_INPUT_WIRE_VERSION, CarrierRef,
};
use super::{
    Attached, InputBinding, RelayedInput, held_input_in_txn, input_digest, part_key, parts_digest,
    split_attached,
};
use crate::Vault;
use crate::error::Result;
use crate::store::{CredentialLeaf, CustodyKind, Store};
use crate::world_keys::MachineSecret;

/// The label a leaf-sealed input opens with.
const LEAF_INPUT_LABEL: &[u8] = b"oneiron/custody-input-leaf\0";

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
    /// recorder attached beside it.
    Sealed(&'a [u8]),
}

/// A leaf-sealed input as read: its key's reference, its layer, the digest
/// a surface's same input is found by, and the bytes after its head.
pub(crate) struct LeafSealed<'a> {
    pub(crate) carrier: CarrierRef,
    layer: LeafLayer,
    retry: [u8; 32],
    sealed: &'a [u8],
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

/// The leaf-sealed input `input` is, while the carrier wire is on and it
/// opens with a whole head; `None` for any other input, which opens as
/// before.
pub(crate) fn leaf_sealed(input: &[u8]) -> Option<LeafSealed<'_>> {
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
    let (retry, sealed) = rest.split_first_chunk::<32>()?;
    Some(LeafSealed {
        carrier,
        layer,
        retry: *retry,
        sealed,
    })
}

impl LeafSealed<'_> {
    /// Whether its key is the input key of the request `binding` binds: a
    /// request input's, of its secret, at the generation it approves.
    pub(crate) fn binds(&self, binding: &InputBinding<'_>) -> bool {
        self.carrier.kind == CustodyKind::CustodyRequestInput
            && self.carrier.credential == binding.id
            && self.carrier.generation == binding.generation
    }

    /// The body it holds, opened under `leaf` and with the holder's
    /// `secret` under `binding`, with what its recorder attached beside a
    /// surface's envelope; `None` when any layer does not open.
    pub(crate) fn open(
        &self,
        binding: &InputBinding<'_>,
        leaf: &CredentialLeaf,
        secret: &MachineSecret,
    ) -> Option<(Zeroizing<Vec<u8>>, Option<Attached>)> {
        match self.layer {
            LeafLayer::UnderHolder => {
                let under = binding.open(self.sealed, secret)?;
                Some((self.carrier.open(leaf, None, &under).ok()?, None))
            }
            LeafLayer::OverHolder => {
                let over = self.carrier.open(leaf, None, self.sealed).ok()?;
                let (envelope, attached) = split_attached(&over)?;
                Some((binding.open(envelope, secret)?, attached))
            }
        }
    }
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
    Ok(head_row_in_txn(store, txn, digest)?
        .and_then(|row| leaf_sealed(&row.envelope).map(|sealed| sealed.carrier)))
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
        leaf_sealed(&row.envelope)
            .is_some_and(|sealed| sealed.layer == LeafLayer::OverHolder && sealed.retry == *retry)
    }))
}

/// The carrier key of the kept input row `bytes`, when it heads a
/// leaf-sealed input: the whole, or its first part.
pub(crate) fn row_carrier(bytes: &[u8]) -> Option<CarrierRef> {
    let row = RelayedInput::decode(bytes)?;
    if row.part.as_ref().is_some_and(|part| part.index != 0) {
        return None;
    }
    leaf_sealed(&row.envelope).map(|sealed| sealed.carrier)
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

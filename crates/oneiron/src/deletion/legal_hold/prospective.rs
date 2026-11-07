//! A HOST order's explicit prospective capture of new on-record messages
//! (LEGAL-HOLD-USE = B as a clone, owner 2026-11-05; FIX 13866, 13867).
//!
//! Default off: only a `CaptureScope::ProspectiveMessages` request stands one.
//! While it stands and before its `ends_at`, every new base MESSAGE row is
//! sealed to the order's public key inside the writer that stores it and kept
//! in the order's outbox. The clone owns that ciphertext from the moment the
//! message lands, so the user's own erase, scrub or compaction of the message
//! is never gated. The order's connection drains the outbox in batches, each
//! acknowledged on its own. Release or expiry destroys the standing and its
//! outbox. A seal that fails keeps the user's write and records the message
//! as missed, never as captured.

use std::io::{self, Read};

use heed::{RoTxn, RwTxn};
use oneiron_crypto::legal_clone::{
    self, CaptureBinding, ContentBinding, ContentSource, SourceComponent,
};
use oneiron_crypto::{HybridPublicKey, MAX_PLAINTEXT_LEN};
use oneiron_vault_contract::host_legal::{
    CaptureDescriptor, CaptureRequest, CaptureScope, CaptureSource, FrameHeader, FrameKind,
    MessageSelector,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// One order generation: order id and generation.
pub(crate) type OrderKey = ([u8; 16], u64);
type OutboxKey = ([u8; 16], u64, u64);

const STANDINGS: SideTable<OrderKey, Standing, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE);
const OUTBOX: SideTable<OutboxKey, OutboxEntry, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE_OUTBOX);
const RELEASED: SideTable<OrderKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE_RELEASED);

/// How many outbox entries one batch carries at most: a transport chunk, not
/// a limit on what is sealed (CALLS OPUS-LEGALHOLD-13866-batch-entries).
pub(crate) const PROSPECTIVE_BATCH_ENTRIES: usize = 256;

/// A standing prospective order: its exact admitted capture binding, term,
/// public recipient and the next outbox ordinal. Content-free but for the
/// public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Standing {
    covered: CoveredMessages,
    capture: [u8; 16],
    source_vault: [u8; 32],
    request_digest: [u8; 32],
    ends_at: u64,
    recipient: Vec<u8>,
    next_ordinal: u64,
}

/// The order's own selector, kept with its standing and applied to each new
/// message at its landing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CoveredMessages {
    /// Every new base on-record MESSAGE row of this vault.
    Vault,
}

impl CoveredMessages {
    /// Whether this selector covers the new MESSAGE row `id`.
    fn covers(self, _id: &EntityId) -> bool {
        match self {
            Self::Vault => true,
        }
    }
}

impl Standing {
    fn binding(&self, (order, generation): OrderKey) -> CaptureBinding {
        CaptureBinding {
            order,
            source_vault: self.source_vault,
            generation,
            capture: self.capture,
            request_digest: self.request_digest,
        }
    }
}

/// One outbox entry: a message row sealed when it landed, or the truthful
/// record that it landed and could not be sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum OutboxEntry {
    Sealed {
        message: [u8; 16],
        /// The exact Descriptor and Content frames, ciphertext only.
        frames: Vec<u8>,
        /// BLAKE3 of the exact encoded descriptor sealed in `frames`.
        descriptor_digest: [u8; 32],
        plaintext_len: u64,
    },
    Missed {
        message: [u8; 16],
    },
}

fn order_prefix((order, generation): OrderKey) -> Vec<u8> {
    let mut prefix = order.to_vec();
    prefix.extend_from_slice(&generation.to_be_bytes());
    prefix
}

/// Whether any prospective order stands in `txn`: the one read a new base
/// MESSAGE put pays while none does.
pub(crate) fn prospective_standing_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(STANDINGS.iter_raw_from(store, txn, &[])?.next().is_some())
}

/// Seals the new base MESSAGE row `id`, exactly as this writer just staged
/// it, to every prospective order standing at the writer's recorded time,
/// and keeps it in that order's outbox. A seal that fails keeps the user's
/// write: the entry records the message as missed. Only a storage error
/// fails, as any put's would.
pub(crate) fn seal_prospective_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let row = match store.entities().get(wtxn, id.as_bytes())? {
        Some(row) => Zeroizing::new(row.to_vec()),
        None => return Ok(()),
    };
    let now = store.clock.now_recorded_at();
    let message = *id.as_bytes();
    let mut sealed_any = false;
    for (key, mut standing) in STANDINGS.scan(store, wtxn)? {
        if now >= standing.ends_at || !standing.covered.covers(id) {
            continue;
        }
        let ordinal = standing.next_ordinal;
        let entry = seal_row(&standing, key, ordinal, &message, &row).unwrap_or_else(|error| {
            tracing::warn!(
                error = %error,
                "a new message could not be sealed to its prospective legal order; recorded as missed"
            );
            OutboxEntry::Missed { message }
        });
        OUTBOX.put(store, wtxn, &(key.0, key.1, ordinal), &entry)?;
        standing.next_ordinal = ordinal
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("legal prospective ordinal"))?;
        STANDINGS.put(store, wtxn, &key, &standing)?;
        sealed_any = true;
    }
    if sealed_any {
        store.host_legal_prospective.bump();
    }
    Ok(())
}

fn seal_row(
    standing: &Standing,
    key: OrderKey,
    ordinal: u64,
    message: &[u8; 16],
    row: &[u8],
) -> Result<OutboxEntry> {
    let public = HybridPublicKey::from_bytes(&standing.recipient)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "legal prospective recipient"))?;
    let fingerprint = *blake3::hash(row).as_bytes();
    let mut frames = Vec::new();
    let encoded = seal_frames(
        &public,
        &standing.binding(key),
        ordinal,
        SourceComponent::MessageRow,
        CaptureSource::Message(*message),
        "entities",
        message,
        fingerprint,
        row.len() as u64,
        fingerprint,
        &mut &row[..],
        &|| Ok(()),
        &mut |kind, member, part, payload| {
            push_frame(&mut frames, kind, member, part, payload);
            Ok(())
        },
    )?;
    Ok(OutboxEntry::Sealed {
        message: *message,
        frames,
        descriptor_digest: *blake3::hash(&encoded).as_bytes(),
        plaintext_len: row.len() as u64,
    })
}

fn push_frame(out: &mut Vec<u8>, kind: FrameKind, member: u64, part: u64, payload: &[u8]) {
    out.extend_from_slice(
        &FrameHeader {
            kind,
            member,
            part,
            len: payload.len() as u64,
        }
        .bytes(),
    );
    out.extend_from_slice(payload);
}

/// Stands the prospective order of `request`, or finds it standing for a
/// reconnect of the same capture. A released generation never stands again.
pub(crate) fn stand_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    request: &CaptureRequest,
    request_digest: [u8; 32],
) -> Result<()> {
    let key = (request.order, request.generation);
    let CaptureScope::ProspectiveMessages(selector) = &request.scope else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legal capture scope is not prospective",
        )
        .into());
    };
    let covered = match selector {
        MessageSelector::Vault => CoveredMessages::Vault,
    };
    if RELEASED.get_bytes(store, wtxn, &key)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legal prospective order generation released",
        )
        .into());
    }
    match STANDINGS.get(store, wtxn, &key)? {
        Some(standing) => {
            if standing.capture != request.capture
                || standing.request_digest != request_digest
                || standing.covered != covered
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "legal prospective standing differs",
                )
                .into());
            }
            Ok(())
        }
        None => STANDINGS.put(
            store,
            wtxn,
            &key,
            &Standing {
                covered,
                capture: request.capture,
                source_vault: request.source_vault,
                request_digest,
                ends_at: request.ends_at,
                recipient: request.recipient.clone(),
                next_ordinal: 0,
            },
        ),
    }
}

/// The next outbox entries of `key` in ordinal order, at most one batch;
/// `None` once the order generation no longer stands (released or ended).
pub(crate) fn outbox_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    key: OrderKey,
) -> Result<Option<Vec<(u64, OutboxEntry)>>> {
    if STANDINGS.get(store, txn, &key)?.is_none() {
        return Ok(None);
    }
    let mut entries = Vec::new();
    for row in OUTBOX.iter_from(store, txn, &order_prefix(key))? {
        let ((order, generation, ordinal), entry) = row?;
        if (order, generation) != key {
            break;
        }
        entries.push((ordinal, entry));
        if entries.len() == PROSPECTIVE_BATCH_ENTRIES {
            break;
        }
    }
    Ok(Some(entries))
}

/// Deletes the acknowledged entries `first..first + count` of `key`, only if
/// the same capture still stands. Returns whether it did.
pub(crate) fn acknowledge_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    capture: [u8; 16],
    first: u64,
    count: u64,
) -> Result<bool> {
    match STANDINGS.get(store, wtxn, &key)? {
        Some(standing) if standing.capture == capture => {}
        _ => return Ok(false),
    }
    let end = first
        .checked_add(count)
        .ok_or(Error::ArithmeticOverflow("legal prospective batch"))?;
    for ordinal in first..end {
        OUTBOX.delete(store, wtxn, &(key.0, key.1, ordinal))?;
    }
    Ok(true)
}

/// Ends order generation `key`: deletes its standing and every outbox entry
/// (in-transit clone ciphertext), and on `released` records the generation
/// so it never stands again.
pub(crate) fn end_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    released: bool,
) -> Result<()> {
    if released {
        RELEASED.put(store, wtxn, &key, &Vec::new())?;
    }
    STANDINGS.delete(store, wtxn, &key)?;
    let mut ordinals = Vec::new();
    for row in OUTBOX.iter_from(store, wtxn, &order_prefix(key))? {
        let ((order, generation, ordinal), _) = row?;
        if (order, generation) != key {
            break;
        }
        ordinals.push(ordinal);
    }
    for ordinal in ordinals {
        OUTBOX.delete(store, wtxn, &(key.0, key.1, ordinal))?;
    }
    Ok(())
}

/// Ends every prospective order whose term passed at `now`, with its outbox:
/// the maintenance pass's half of expiry, for an order with no live
/// connection. Births after `ends_at` are never sealed either way.
pub(crate) fn end_lapsed_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, now: u64) -> Result<u64> {
    let lapsed: Vec<OrderKey> = STANDINGS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, standing)| now >= standing.ends_at)
        .map(|(key, _)| key)
        .collect();
    for key in &lapsed {
        end_in_txn(store, wtxn, *key, false)?;
    }
    if !lapsed.is_empty() {
        store.host_legal_prospective.bump();
    }
    Ok(lapsed.len() as u64)
}

/// One component sealed under `binding` at `member`: its exact Descriptor
/// frame then its Content frames, handed to `emit` in stream order. Shared by
/// the streaming collector and the prospective outbox, so both seal one
/// format. Returns the exact encoded descriptor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_frames(
    public: &HybridPublicKey,
    binding: &CaptureBinding,
    member: u64,
    component: SourceComponent,
    source: CaptureSource,
    family: &str,
    key: &[u8],
    revision: [u8; 32],
    plaintext_len: u64,
    fingerprint: [u8; 32],
    input: &mut dyn Read,
    check: &dyn Fn() -> Result<()>,
    emit: &mut dyn FnMut(FrameKind, u64, u64, &[u8]) -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    check()?;
    let source_key_digest = source_key_digest(family, key);
    let chunk_count = plaintext_len.div_ceil(MAX_PLAINTEXT_LEN as u64).max(1);
    let content_source = match &source {
        CaptureSource::GateDecision(decision) => ContentSource::GateDecision(*decision),
        CaptureSource::LiveSession(target) => ContentSource::LiveSession {
            session_ref_digest: legal_clone::live_session_ref_digest(&target.session_ref),
            instance: target.instance,
        },
        CaptureSource::Message(message) => ContentSource::Message(*message),
    };
    let descriptor = CaptureDescriptor {
        component: component as u8,
        source,
        source_key: key.to_vec(),
        source_key_digest,
        revision,
        plaintext_fingerprint: fingerprint,
        plaintext_len,
        chunk_count,
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&descriptor).map_err(io::Error::other)?);
    let sealed =
        legal_clone::seal_descriptor(public, binding, member, &encoded, &mut getrandom::SysRng)
            .map_err(crypto_error)?;
    emit(FrameKind::Descriptor, member, 0, &sealed.to_bytes())?;
    let mut actual = blake3::Hasher::new();
    let mut remaining = plaintext_len;
    for chunk_index in 0..chunk_count {
        check()?;
        let len = remaining.min(MAX_PLAINTEXT_LEN as u64) as usize;
        let mut bytes = Zeroizing::new(vec![0; len]);
        input.read_exact(&mut bytes)?;
        actual.update(&bytes);
        let content = ContentBinding {
            capture: *binding,
            member_ordinal: member,
            component,
            source: content_source,
            source_key_digest,
            revision,
            plaintext_fingerprint: fingerprint,
            chunk_index,
            chunk_count,
        };
        let sealed = legal_clone::seal_content(public, &content, &bytes, &mut getrandom::SysRng)
            .map_err(crypto_error)?;
        emit(FrameKind::Content, member, chunk_index, &sealed.to_bytes())?;
        remaining -= len as u64;
    }
    let mut extra = [0];
    if input.read(&mut extra)? != 0 || actual.finalize().as_bytes() != &fingerprint {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "legal source content changed").into(),
        );
    }
    check()?;
    Ok(encoded)
}

/// The digest of a component's exact source key under its native family.
pub(crate) fn source_key_digest(family: &str, key: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.legal-clone.source-key.v1");
    hash.update(&(family.len() as u64).to_be_bytes());
    hash.update(family.as_bytes());
    hash.update(&(key.len() as u64).to_be_bytes());
    hash.update(key);
    *hash.finalize().as_bytes()
}

pub(crate) fn crypto_error(_error: oneiron_crypto::Error) -> io::Error {
    io::Error::other("legal clone encryption")
}

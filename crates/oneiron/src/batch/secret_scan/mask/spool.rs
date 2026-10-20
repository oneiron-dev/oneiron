//! The spool-aware admission adapter (FIX 5718 part 3, Engine ruling 3;
//! CALLS C5718-19). A body that streamed into a raw spool (a run's reply
//! body, a callable skill's spooled answer, an imported result, a shadow
//! arm's stream or spill) is admitted at its write by the side-row wall's
//! own Masker ([`admit_side_parts`]), in the writer that mints its custody
//! records, with the known values that writer reads (KS-3). Only the
//! admitted bytes are published, so a result's digest, path and preview are
//! the admitted bytes'.
//!
//! The spool was read as it streamed: the write door's stream rules, each
//! across frame edges and, within the door's whole-read bound, its
//! structured reading of the whole, marked a hit as it passed. In the
//! writer it is read for the values custody holds. A body the door finds
//! nothing in is taken as it is and never read whole: one the stream already
//! read whole, or one past that bound that is opaque (no text, and no
//! record, owning adapter or container a reader decodes), in which the
//! Masker places nothing. Every other body is read whole and admitted by the
//! plan a side row takes: no known-only sweep, no frame read alone. Nothing
//! is capped, cut or skipped: past the inline bound the spool and the
//! admitted body each spill whole.
//!
//! A hit the plan cannot place (a recovery phrase, a key its copy still
//! shows) mints nothing and is [`SpoolAdmission::Unplaceable`]: the writer
//! names what stands in its place (ruling 4).

use std::sync::Arc;

use heed::RwTxn;

use super::super::{REASON_DETECTED, SecretScanMode, is_container, secret_scan_mode_in_txn};
use super::side_row::{SidePart, admit_side_parts};
use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::secret_custody::{KnownSweep, KnownValues};
use crate::store::{BodyDir, BodyFacts, BodyFile, BodyMeter, BodySink, LINE_INDEX_BLOCK_BYTES};

/// The door's whole-read bound: a body within it was read whole by the
/// door's structured rules as it streamed (the result body store's secret
/// scan reads as much as an LFS object the door reads whole).
const STREAM_READ_WHOLE: u64 = crate::origin::lfs::LFS_WHOLE_SCAN_MAX;

/// The bytes of a spool's head its admission reads to tell an opaque body.
pub(crate) const SPOOL_HEAD_BYTES: usize = 64;

/// Bytes one frame of a spool is read or fed in.
const FRAME_BYTES: usize = LINE_INDEX_BLOCK_BYTES as usize;

/// One body spooled raw for admission: its bytes as they streamed, in
/// memory or in a temp file of its body directory that is never published
/// (sealed under a key held in memory on a sealed vault), and what its
/// stream scan measured. The temp file goes when the spool is dropped.
pub(crate) struct BodySpool {
    facts: BodyFacts,
    head: Vec<u8>,
    held: Held,
}

/// Where a spool's bytes are.
enum Held {
    Bytes(Vec<u8>),
    File {
        file: BodyFile,
        dir: BodyDir,
        temp: String,
    },
}

impl BodySpool {
    /// `bytes`, whole, as a spool, measured now.
    pub(crate) fn of_bytes(bytes: Vec<u8>) -> Self {
        let mut meter = BodyMeter::new();
        meter.feed(&bytes);
        let head = bytes[..bytes.len().min(SPOOL_HEAD_BYTES)].to_vec();
        Self::held(meter.finish(0), head, bytes)
    }

    /// A spool a sink kept in memory: what its scan measured, its head and
    /// its bytes.
    pub(crate) fn held(facts: BodyFacts, head: Vec<u8>, bytes: Vec<u8>) -> Self {
        Self {
            facts,
            head,
            held: Held::Bytes(bytes),
        }
    }

    /// A spool a sink spilled: the temp file `temp` in `dir`, open as
    /// `file`, removed when the spool is dropped.
    pub(crate) fn spilled(
        facts: BodyFacts,
        head: Vec<u8>,
        file: BodyFile,
        dir: BodyDir,
        temp: String,
    ) -> Self {
        Self {
            facts,
            head,
            held: Held::File { file, dir, temp },
        }
    }

    /// The body's length in bytes.
    pub(crate) const fn len(&self) -> u64 {
        self.facts.len
    }

    /// Whether the whole body is UTF-8.
    pub(crate) const fn text(&self) -> bool {
        self.facts.text
    }

    /// Whether the Masker reads nothing in the body: no UTF-8 text, and a
    /// head no record, owning adapter or container starts with, as the
    /// ASSET stager tells an opaque body.
    fn opaque(&self) -> bool {
        !self.facts.text && opaque_head(&self.head)
    }

    /// Each frame of the body, in order.
    fn frames(&self, mut each: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        match &self.held {
            Held::Bytes(bytes) => bytes.chunks(FRAME_BYTES).try_for_each(each),
            Held::File { file, .. } => {
                let mut at = 0;
                while at < self.facts.len {
                    let take = usize::try_from((self.facts.len - at).min(FRAME_BYTES as u64))
                        .map_err(|_| Error::ArithmeticOverflow("spooled body frame"))?;
                    each(&file.read_range(at, take)?)?;
                    at += take as u64;
                }
                Ok(())
            }
        }
    }

    /// The whole body.
    fn whole(&self) -> Result<Vec<u8>> {
        match &self.held {
            Held::Bytes(bytes) => Ok(bytes.clone()),
            Held::File { file, .. } => file.read_range(
                0,
                usize::try_from(self.facts.len)
                    .map_err(|_| Error::ArithmeticOverflow("spooled body length"))?,
            ),
        }
    }

    /// The whole body, a spool held in memory taken as it is.
    ///
    /// # Errors
    ///
    /// A spilled spool's read errors.
    pub(crate) fn into_bytes(mut self) -> Result<Vec<u8>> {
        match &mut self.held {
            Held::Bytes(bytes) => Ok(std::mem::take(bytes)),
            Held::File { .. } => self.whole(),
        }
    }

    /// The digest the known-value sweep leaves the body with: its own while
    /// it holds no value `known` holds.
    fn swept_digest(&self, known: &Arc<KnownValues>) -> Result<[u8; 32]> {
        let mut sweep = KnownSweep::in_writer(Arc::clone(known));
        let mut hasher = blake3::Hasher::new();
        self.frames(|frame| {
            hasher.update(&sweep.feed(frame)?);
            Ok(())
        })?;
        hasher.update(&sweep.tail()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl Drop for BodySpool {
    fn drop(&mut self) {
        if let Held::File { dir, temp, .. } = &self.held {
            dir.discard(temp);
        }
    }
}

/// What the wall admitted a spooled body as.
pub(crate) enum SpoolAdmission<'s> {
    /// The spool's own bytes: the door places nothing in them.
    AsIs(&'s BodySpool),
    /// The admitted copy, whole: each secret the plan placed its custody
    /// handle, and each value custody holds its handle's text.
    Copy(Vec<u8>),
    /// A hit the plan cannot place, by the door's reason. Nothing was
    /// minted.
    Unplaceable(&'static str),
}

impl SpoolAdmission<'_> {
    /// The admitted body's length; `None` for one the wall cannot place.
    pub(crate) fn len(&self) -> Option<u64> {
        match self {
            Self::AsIs(spool) => Some(spool.len()),
            Self::Copy(bytes) => Some(bytes.len() as u64),
            Self::Unplaceable(_) => None,
        }
    }

    /// Feeds the admitted body into `sink`, a frame at a time.
    ///
    /// # Errors
    ///
    /// The spool's read errors and the sink's, and
    /// [`Error::InvariantViolation`] for a body the wall cannot place.
    pub(crate) fn feed(&self, sink: &mut BodySink) -> Result<()> {
        match self {
            Self::AsIs(spool) => spool.frames(|frame| sink.write(frame)),
            Self::Copy(bytes) => bytes
                .chunks(FRAME_BYTES)
                .try_for_each(|frame| sink.write(frame)),
            Self::Unplaceable(_) => Err(Error::InvariantViolation(
                "a body the wall cannot place has no admitted bytes",
            )),
        }
    }
}

/// Admits `spool` in `wtxn`, the writer that publishes it (see the module
/// notes): its own bytes when the door places nothing in them, else the
/// copy the wall's plan masks, custody minted in `wtxn`. `known` is the
/// index of the values custody holds as `wtxn` read it
/// ([`KnownValues::load_in_writer`], KS-3): the plan places each one where
/// it reads text, and with `sweeps` one it does not place is still swept to
/// its handle's text, as a run's result sink swept every body before (a
/// run's reply body, an imported result), whatever the owner's switch says.
/// With the switch off the door masks nothing. `at` names the place and key
/// each custody record's origin names.
///
/// # Errors
///
/// Storage, custody and the spool's read errors. A hit the plan cannot
/// place is no error: it is [`SpoolAdmission::Unplaceable`].
pub(crate) fn admit_spool_in_txn<'s>(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    at: (&str, &[u8]),
    spool: &'s BodySpool,
    (known, sweeps): (Option<&Arc<KnownValues>>, bool),
) -> Result<SpoolAdmission<'s>> {
    let holds_known = match known {
        Some(known) => spool.swept_digest(known)? != spool.facts.digest,
        None => false,
    };
    let swept_known = sweeps && holds_known;
    let sweep = |bytes: Vec<u8>| match known.filter(|_| swept_known) {
        Some(known) => swept(known, &bytes),
        None => Ok(bytes),
    };
    let reads_whole = secret_scan_mode_in_txn(vault, wtxn)? == SecretScanMode::On
        && (spool.facts.secret.is_some()
            || holds_known
            || (spool.len() > STREAM_READ_WHOLE && !spool.opaque()));
    if !reads_whole {
        return Ok(if swept_known {
            SpoolAdmission::Copy(sweep(spool.whole()?)?)
        } else {
            SpoolAdmission::AsIs(spool)
        });
    }
    let mut parts = [SidePart::Body(spool.whole()?)];
    let placed = match admit_side_parts(vault, wtxn, at, &mut parts, |_| true) {
        Ok(placed) => placed,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            let reason = reason_codes.last().copied().unwrap_or(REASON_DETECTED);
            return Ok(SpoolAdmission::Unplaceable(reason));
        }
        Err(error) => return Err(error),
    };
    let [SidePart::Body(bytes)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted spooled body is no longer a body",
        ));
    };
    Ok(if placed || swept_known {
        SpoolAdmission::Copy(sweep(bytes)?)
    } else {
        SpoolAdmission::AsIs(spool)
    })
}

/// `bytes` with each value `known` holds replaced by its handle's text, as
/// a body's sweep replaces it.
fn swept(known: &Arc<KnownValues>, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut sweep = KnownSweep::in_writer(Arc::clone(known));
    let mut out = sweep.feed(bytes)?;
    out.extend(sweep.tail()?);
    Ok(out)
}

/// Whether a body's `head` shows it none of the bodies a reader decodes: no
/// MessagePack map or array, no owning adapter's tag (`oneiron.` at the
/// head, one byte in at most), and no ZIP, gzip or PDF container.
fn opaque_head(head: &[u8]) -> bool {
    let Some(&lead) = head.first() else {
        return false;
    };
    let tagged = |bytes: &[u8]| bytes.starts_with(b"oneiron.");
    !matches!(lead, 0x80..=0x9f | 0xdc..=0xdf)
        && !tagged(head)
        && !head.get(1..).is_some_and(tagged)
        && !is_container(head)
}

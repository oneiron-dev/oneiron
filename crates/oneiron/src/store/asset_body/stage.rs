//! Staging an ASSET body from a reader before the transaction that puts it
//! (FIX 3677): the body streams into the body directory, measured as it
//! passes, and is published as a file only when it is long and opaque. On a
//! sealed vault it spills sealed as it streams and is published as an
//! envelope, whose key row the put commits (FIX 5348). While the file plane
//! is on, the values custody holds are found in the stream too, and marked
//! when the put binds the file (FIX 5395, `secret_scan::stream_known`).

use std::io::{self, Read};
use std::sync::Arc;

use heed::RwTxn;

use super::{
    ASSET_FILE_PLANE, ASSET_INLINE_BODY_BYTES, AssetBodyFacts, AssetFileKind, AssetFileManifest,
};
use crate::batch::secret_scan::{KnownStreamFinder, StreamKnown};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::result_body::ResultBodyPin;
use crate::secret_custody::KnownValues;
use crate::store::body_store::SecretScan;
use crate::store::{
    BodyDir, BodyFile, BodySpill, LINE_INDEX_BLOCK_BYTES, SpilledBody, StagedBodyKey,
};
use crate::temporal::TimeRange;

/// The bytes of a body's head its stream classification reads: enough for
/// every owning adapter's tag and every container's magic.
const HEAD_BYTES: usize = 64;

/// One ASSET body staged for its put: kept in memory when it is to stay in
/// its row, or published under its digest as a body file, pinned until this
/// is dropped so the collector cannot take a file a staged put is about to
/// name. Drop it once the transaction that puts it has committed or aborted.
pub(crate) struct StagedAssetBody {
    facts: AssetBodyFacts,
    mime: Option<String>,
    body: Staged,
    /// A sealed file's key row, committed with the put (FIX 5348).
    key: Option<StagedBodyKey>,
    /// The values custody holds that a published file's stream carries
    /// (FIX 5395).
    known: StreamKnown,
    _pin: Option<ResultBodyPin>,
}

enum Staged {
    Inline(Vec<u8>),
    /// The published file, held open.
    File(BodyFile),
}

impl StagedAssetBody {
    /// The body's length, BLAKE3 and `xxh32`.
    pub(crate) const fn facts(&self) -> AssetBodyFacts {
        self.facts
    }

    /// The whole body, read back from its file when it has one.
    ///
    /// # Errors
    ///
    /// The file's read error.
    pub(crate) fn to_vec(&self) -> Result<Vec<u8>> {
        match &self.body {
            Staged::Inline(bytes) => Ok(bytes.clone()),
            Staged::File(file) => file.read_range(
                0,
                usize::try_from(self.facts.len).map_err(|_| {
                    Error::InvariantViolation("asset body past this machine's memory")
                })?,
            ),
        }
    }
}

/// What a body is, measured as its bytes stream past: what its manifest
/// needs and what its classification reads.
struct StageMeter {
    hasher: blake3::Hasher,
    xxh32: xxhash_rust::xxh32::Xxh32,
    len: u64,
    head: Vec<u8>,
    utf8: Utf8Stream,
    /// The result body store's write-door rules over a body as it streams.
    secrets: SecretScan,
    /// The values custody holds, found as the body streams (FIX 5395).
    known: Option<KnownStreamFinder>,
}

impl StageMeter {
    fn new(known: Option<Arc<KnownValues>>) -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            xxh32: xxhash_rust::xxh32::Xxh32::new(0),
            len: 0,
            head: Vec::with_capacity(HEAD_BYTES),
            utf8: Utf8Stream::default(),
            secrets: SecretScan::default(),
            known: known.map(KnownStreamFinder::new),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.xxh32.update(bytes);
        self.len = self.len.saturating_add(bytes.len() as u64);
        let room = HEAD_BYTES.saturating_sub(self.head.len());
        self.head.extend_from_slice(&bytes[..room.min(bytes.len())]);
        self.utf8.feed(bytes);
        self.secrets.feed(bytes);
        if let Some(known) = &mut self.known {
            known.feed(bytes);
        }
    }

    /// The body's facts, whether its stream shows it opaque, and the values
    /// custody holds that it carries. Opaque: no UTF-8 text, a head no
    /// owning adapter, container or MessagePack record starts with, and no
    /// hit of the write door's stream rules. A body the stream cannot show
    /// opaque is read whole and judged by the batch door.
    fn finish(mut self) -> (AssetBodyFacts, bool, StreamKnown) {
        let facts = AssetBodyFacts {
            blake3: *self.hasher.finalize().as_bytes(),
            len: self.len,
            xxh32: self.xxh32.digest(),
        };
        let opaque =
            !self.utf8.text() && opaque_head(&self.head) && self.secrets.finish().is_none();
        let known = self
            .known
            .map_or_else(StreamKnown::default, KnownStreamFinder::finish);
        (facts, opaque, known)
    }
}

/// Whether a body's `head` shows it none of the bodies a reader interprets:
/// no MessagePack map or array (a record, or a pack source's envelope), no
/// owning adapter's tag (each names itself `oneiron.` at the head, one byte
/// in at most), and no ZIP, gzip or PDF container.
fn opaque_head(head: &[u8]) -> bool {
    let Some(&lead) = head.first() else {
        return false;
    };
    let tagged = |bytes: &[u8]| bytes.starts_with(b"oneiron.");
    !matches!(lead, 0x80..=0x9f | 0xdc..=0xdf)
        && !tagged(head)
        && !head.get(1..).is_some_and(tagged)
        && !crate::batch::secret_scan::is_container(head)
}

/// UTF-8 checked across frames, a character split between two carried.
#[derive(Default)]
struct Utf8Stream {
    broken: bool,
    carry: [u8; 4],
    carry_len: usize,
}

impl Utf8Stream {
    fn feed(&mut self, mut bytes: &[u8]) {
        while self.carry_len > 0 && !self.broken {
            let Some((first, after)) = bytes.split_first() else {
                return;
            };
            self.carry[self.carry_len] = *first;
            self.carry_len += 1;
            bytes = after;
            match std::str::from_utf8(&self.carry[..self.carry_len]) {
                Ok(_) => self.carry_len = 0,
                Err(error) if error.error_len().is_some() || self.carry_len == 4 => {
                    self.broken = true;
                }
                Err(_) => {}
            }
        }
        if self.broken {
            return;
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.broken = true;
            } else {
                let tail = &bytes[error.valid_up_to()..];
                self.carry[..tail.len()].copy_from_slice(tail);
                self.carry_len = tail.len();
            }
        }
    }

    /// Whether every byte fed was UTF-8, the last character whole.
    const fn text(&self) -> bool {
        !self.broken && self.carry_len == 0
    }
}

/// A spill in the body directory, its temp file removed when dropped
/// unfinished.
struct Spill<'a> {
    dir: &'a BodyDir,
    body: Option<BodySpill>,
}

impl Spill<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.body {
            Some(body) => body.write(bytes),
            None => Err(Error::InvariantViolation("asset body spill taken twice")),
        }
    }

    /// The finished spill of the body `facts` names: its temp file is the
    /// caller's to publish or remove.
    fn finish(mut self, facts: &AssetBodyFacts) -> Result<SpilledBody> {
        let body = self
            .body
            .take()
            .ok_or(Error::InvariantViolation("asset body spill taken twice"))?;
        let temp = body.temp().to_owned();
        body.finish(&facts.blake3, facts.len)
            .inspect_err(|_| self.dir.discard(&temp))
    }
}

impl Drop for Spill<'_> {
    fn drop(&mut self) {
        if let Some(body) = self.body.take() {
            self.dir.discard(body.temp());
        }
    }
}

impl crate::Vault {
    /// The known-value index a streamed ASSET body is read against, as
    /// `txn`, the transaction that puts it, holds it (FIX 5395): `None` while
    /// the file plane is off, when every body reaches the batch door whole.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn asset_stream_known_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
    ) -> Result<Option<Arc<KnownValues>>> {
        if !ASSET_FILE_PLANE {
            return Ok(None);
        }
        Ok(KnownValues::load_in_writer(&self.store, txn)?.map(Arc::new))
    }

    /// The body instances ASSET bodies of the lengths `lens` may be filed
    /// under, minted now, before the writer that stages them opens (KS-2A,
    /// FIX 6021): one for each body past [`ASSET_INLINE_BODY_BYTES`], which
    /// [`Self::stage_asset_body`] takes in turn inside that writer. `None`
    /// while the file plane is off, when every body stays in its row, and
    /// when no body is past the bound. One the writer leaves unnamed (a body
    /// the stager keeps in its row) is debris.
    ///
    /// # Errors
    ///
    /// Custody's errors.
    pub(crate) fn asset_body_mint(
        &self,
        lens: impl IntoIterator<Item = u64>,
    ) -> Result<Option<crate::store::BodyMint>> {
        if !ASSET_FILE_PLANE {
            return Ok(None);
        }
        let count = lens
            .into_iter()
            .filter(|len| *len > ASSET_INLINE_BODY_BYTES)
            .count();
        if count == 0 {
            return Ok(None);
        }
        Ok(Some(self.store.body_mint()?.reserve(count)?))
    }

    /// Streams `reader` into one staged ASSET body, before the transaction
    /// that puts it (FIX 3677): a body past [`ASSET_INLINE_BODY_BYTES`]
    /// spills to a temp file in the body directory as it streams, sealed as
    /// it streams on a sealed vault, and is published under its name (synced,
    /// renamed, the directory synced) when its stream shows it opaque. Any
    /// other body is held whole for its row, as a slice put holds it. `mime`
    /// is the body's media type, kept in its manifest. Each value of `known`
    /// a published file carries is found as it streams, for its put to mark
    /// (FIX 5395). Nothing is refused for its size (Rule 5).
    ///
    /// A file is one vault instance (KS-2A), minted from `mint` before the
    /// writer that puts it opens: a stager inside a writer passes the
    /// instances reserved before it opened ([`Self::asset_body_mint`]), or
    /// none, and then its long body is read back whole for its row, which a
    /// checkpoint seals under an instance of its own. A spill no instance
    /// backs is a temp under a key held in memory, never published.
    ///
    /// # Errors
    ///
    /// The reader's error, filesystem and storage errors, and
    /// [`Error::InvalidConfig`] for a media type past 65535 bytes.
    pub(crate) fn stage_asset_body(
        &self,
        mut reader: impl Read,
        mime: Option<&str>,
        known: Option<Arc<KnownValues>>,
        mint: Option<&crate::store::BodyMint>,
    ) -> Result<StagedAssetBody> {
        if mime.is_some_and(|mime| mime.len() > usize::from(u16::MAX)) {
            return Err(Error::InvalidConfig(
                "an asset body's media type is past 65535 bytes".to_owned(),
            ));
        }
        let dir = self.store.body_dir()?;
        let mut meter = StageMeter::new(known);
        let mut inline = Vec::new();
        let mut spill = None::<Spill<'_>>;
        let mut frame = vec![0; LINE_INDEX_BLOCK_BYTES as usize];
        loop {
            let read = match reader.read(&mut frame) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let bytes = &frame[..read];
            meter.feed(bytes);
            if let Some(spill) = &mut spill {
                spill.write(bytes)?;
            } else if (inline.len() + read) as u64 <= ASSET_INLINE_BODY_BYTES {
                inline.extend_from_slice(bytes);
            } else {
                let body = match mint.filter(|_| ASSET_FILE_PLANE) {
                    Some(mint) => BodySpill::create(&dir, Some(mint.mint()?))?,
                    None => BodySpill::ephemeral(&dir)?,
                };
                let mut opened = Spill {
                    dir: &dir,
                    body: Some(body),
                };
                opened.write(&inline)?;
                opened.write(bytes)?;
                inline = Vec::new();
                spill = Some(opened);
            }
        }
        let (facts, opaque, known) = meter.finish();
        let staged = |body| StagedAssetBody {
            facts,
            mime: mime.map(str::to_owned),
            body,
            key: None,
            known: StreamKnown::default(),
            _pin: None,
        };
        let Some(spill) = spill else {
            return Ok(staged(Staged::Inline(inline)));
        };
        let spilled = spill.finish(&facts)?;
        let held = match spilled.reader() {
            Ok(held) => held,
            Err(error) => {
                dir.discard(spilled.temp());
                return Err(error);
            }
        };
        if !opaque || !ASSET_FILE_PLANE || mint.is_none() {
            // Read whole, as a slice put holds it: the batch door judges it.
            dir.discard(spilled.temp());
            let len = usize::try_from(facts.len)
                .map_err(|_| Error::InvariantViolation("asset body past this machine's memory"))?;
            return Ok(staged(Staged::Inline(held.read_range(0, len)?)));
        }
        // Pinned before the name exists, so a collector unlinking a released
        // file of the same digest leaves this one alone.
        let pin = self.pin_result_body(facts.blake3);
        let key = spilled.publish(&dir)?;
        Ok(StagedAssetBody {
            key,
            known,
            _pin: Some(pin),
            ..staged(Staged::File(held))
        })
    }

    /// Puts `staged` as ASSET `id` in the caller's transaction, through the
    /// batch door every ASSET put takes (its checks, staging, indexes and
    /// short id): a published file as its manifest, any other body as its
    /// bytes, which the door may still move to a file. A file whose stream
    /// carried a value custody holds is marked here first, as the batch door
    /// marks a file's (FIX 5395), and stays a file, as does one the secret
    /// mask marked before (FIX 5507): its bytes and digest stay as streamed,
    /// the batch door bands the record by the file's digest, and a serving
    /// door masks the file's bytes by that mark.
    ///
    /// # Errors
    ///
    /// The batch door's errors.
    pub(crate) fn put_asset_body_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        staged: &StagedAssetBody,
    ) -> Result<()> {
        let batch = self.batch_in();
        if let Staged::File(file) = &staged.body {
            staged
                .known
                .mark_in_txn(&self.store, txn, id, &staged.facts.blake3, |at, len| {
                    file.read_range(at, len)
                })?;
        }
        if matches!(staged.body, Staged::File(_)) {
            // A sealed file's key row commits with the row naming it; a
            // digest with a committed pair keeps it (FIX 5348).
            if let Some(key) = &staged.key {
                crate::store::bind_body_key_in_txn(&self.store, txn, &self.store.body_dir()?, key)?;
            }
            let manifest = AssetFileManifest {
                facts: staged.facts,
                kind: AssetFileKind::Opaque,
                mime: staged.mime.clone(),
            }
            .encode()?;
            batch
                .put_asset_file(id, occurred, learned_at, &manifest, staged.facts)
                .apply(txn)?;
            // A file's new mask spans refresh the repo index copies its bytes
            // derive (FIX 7608 slice 3).
            return crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
                self,
                txn,
                &[staged.facts.blake3],
            );
        }
        let bytes = match &staged.body {
            Staged::Inline(bytes) => std::borrow::Cow::Borrowed(bytes.as_slice()),
            Staged::File(_) => std::borrow::Cow::Owned(staged.to_vec()?),
        };
        batch
            .put(id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
            .apply(txn)
    }

    /// [`Self::put_asset_body_in_txn`] for a body a peer sent by reference
    /// (FIX 5489): the same marking, marked files kept as files (FIX 5507)
    /// and sealed-key binding,
    /// through the replicated door at `tier` on both branches, so the row
    /// lands as replay lands it. `birth`, the row's carried Rule A birth, is
    /// stamped in this transaction once the row is live; a malformed or
    /// conflicting one is left out and the row stands. Window ingest stamps
    /// its births itself and passes `None`.
    ///
    /// # Errors
    ///
    /// The replicated door's errors.
    #[cfg(feature = "sync")]
    #[allow(dead_code, reason = "FIX 5489 PR2's staged replay calls this")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the staged put's arguments, its tier and its birth"
    )]
    pub(crate) fn put_replicated_asset_body_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        staged: &StagedAssetBody,
        tier: crate::sync::client::ImportTier,
        birth: Option<&crate::provenance::birth::RowBirth>,
    ) -> Result<()> {
        let batch = self.batch_in().with_import_tier(tier);
        if let Staged::File(file) = &staged.body {
            staged
                .known
                .mark_in_txn(&self.store, txn, id, &staged.facts.blake3, |at, len| {
                    file.read_range(at, len)
                })?;
        }
        let put = if matches!(staged.body, Staged::File(_)) {
            // A sealed file's key row commits with the row naming it; a
            // digest with a committed pair keeps it (FIX 5348).
            if let Some(key) = &staged.key {
                crate::store::bind_body_key_in_txn(&self.store, txn, &self.store.body_dir()?, key)?;
            }
            let manifest = AssetFileManifest {
                facts: staged.facts,
                kind: AssetFileKind::Opaque,
                mime: staged.mime.clone(),
            }
            .encode()?;
            batch.put_replicated_asset_file(id, occurred, learned_at, &manifest, staged.facts)
        } else {
            let bytes = match &staged.body {
                Staged::Inline(bytes) => std::borrow::Cow::Borrowed(bytes.as_slice()),
                Staged::File(_) => std::borrow::Cow::Owned(staged.to_vec()?),
            };
            batch.put_replicated(id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
        };
        put.apply(txn)?;
        if matches!(staged.body, Staged::File(_)) {
            crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
                self,
                txn,
                &[staged.facts.blake3],
            )?;
        }
        if let Some(birth) = birth
            && crate::vault::live_entity_row_in_txn(&self.store, txn, id)?.is_live()
        {
            match crate::provenance::birth::stamp_replicated_row_birth_in_txn(
                &self.store,
                txn,
                id,
                birth,
            ) {
                Ok(()) => {}
                Err(err @ (Error::InvalidConfig(_) | Error::InvariantViolation(_))) => {
                    tracing::warn!(entity = %id.to_hex(), error = %err, "carried row birth refused");
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

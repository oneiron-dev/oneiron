//! Staging an ASSET body from a reader before the transaction that puts it
//! (FIX 3677): the body streams into the body directory, measured as it
//! passes, and is published as a file only when it is long and opaque.

use std::fs::File;
use std::io::{self, Read, Write};

use heed::RwTxn;

use super::{
    ASSET_INLINE_BODY_BYTES, AssetBodyFacts, AssetFileKind, AssetFileManifest, pages_sealed,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::result_body::ResultBodyPin;
use crate::store::body_store::SecretScan;
use crate::store::{BodyDir, LINE_INDEX_BLOCK_BYTES, body_file_name, read_body_range};
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
    _pin: Option<ResultBodyPin>,
}

enum Staged {
    Inline(Vec<u8>),
    /// The published file, held open.
    File(File),
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
            Staged::File(file) => read_body_range(
                file,
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
}

impl StageMeter {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            xxh32: xxhash_rust::xxh32::Xxh32::new(0),
            len: 0,
            head: Vec::with_capacity(HEAD_BYTES),
            utf8: Utf8Stream::default(),
            secrets: SecretScan::default(),
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
    }

    /// The body's facts, and whether its stream shows it opaque: no UTF-8
    /// text, a head no owning adapter, container or MessagePack record
    /// starts with, and no hit of the write door's stream rules. A body the
    /// stream cannot show opaque is read whole and judged by the batch door.
    fn finish(mut self) -> (AssetBodyFacts, bool) {
        let facts = AssetBodyFacts {
            blake3: *self.hasher.finalize().as_bytes(),
            len: self.len,
            xxh32: self.xxh32.digest(),
        };
        let opaque =
            !self.utf8.text() && opaque_head(&self.head) && self.secrets.finish().is_none();
        (facts, opaque)
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

/// A temp file in the body directory, removed when dropped unless taken.
struct Spill<'a> {
    dir: &'a BodyDir,
    file: File,
    temp: Option<String>,
}

impl Spill<'_> {
    /// The temp file and its name, no longer removed on drop.
    fn take(mut self) -> Result<(File, String)> {
        let file = self.file.try_clone()?;
        let temp = self
            .temp
            .take()
            .ok_or(Error::InvariantViolation("asset body spill taken twice"))?;
        Ok((file, temp))
    }
}

impl Drop for Spill<'_> {
    fn drop(&mut self) {
        if let Some(temp) = self.temp.take() {
            self.dir.discard(&temp);
        }
    }
}

impl crate::Vault {
    /// Streams `reader` into one staged ASSET body, before the transaction
    /// that puts it (FIX 3677): a body past [`ASSET_INLINE_BODY_BYTES`]
    /// spills to a temp file in the body directory as it streams, and is
    /// published under its digest (synced, renamed, the directory synced)
    /// when its stream shows it opaque in an unsealed vault. Any other body
    /// is held whole for its row, as a slice put holds it. `mime` is the
    /// body's media type, kept in its manifest. Nothing is refused for its
    /// size (Rule 5).
    ///
    /// # Errors
    ///
    /// The reader's error, filesystem and storage errors, and
    /// [`Error::InvalidConfig`] for a media type past 65535 bytes.
    pub(crate) fn stage_asset_body(
        &self,
        mut reader: impl Read,
        mime: Option<&str>,
    ) -> Result<StagedAssetBody> {
        if mime.is_some_and(|mime| mime.len() > usize::from(u16::MAX)) {
            return Err(Error::InvalidConfig(
                "an asset body's media type is past 65535 bytes".to_owned(),
            ));
        }
        let dir = self.store.body_dir()?;
        let mut meter = StageMeter::new();
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
                spill.file.write_all(bytes)?;
            } else if (inline.len() + read) as u64 <= ASSET_INLINE_BODY_BYTES {
                inline.extend_from_slice(bytes);
            } else {
                let (file, temp) = dir.create_temp()?;
                let mut opened = Spill {
                    dir: &dir,
                    file,
                    temp: Some(temp),
                };
                opened.file.write_all(&inline)?;
                opened.file.write_all(bytes)?;
                inline = Vec::new();
                spill = Some(opened);
            }
        }
        let (facts, opaque) = meter.finish();
        let staged = |body| StagedAssetBody {
            facts,
            mime: mime.map(str::to_owned),
            body,
            _pin: None,
        };
        let Some(spill) = spill else {
            return Ok(staged(Staged::Inline(inline)));
        };
        if !opaque || pages_sealed(&self.store) {
            // Read whole, as a slice put holds it: the batch door judges it.
            let len = usize::try_from(facts.len)
                .map_err(|_| Error::InvariantViolation("asset body past this machine's memory"))?;
            return Ok(staged(Staged::Inline(read_body_range(&spill.file, 0, len)?)));
        }
        // Pinned before the name exists, so a collector unlinking a released
        // file of the same digest leaves this one alone.
        let pin = self.pin_result_body(facts.blake3);
        let (file, temp) = spill.take()?;
        let held = file.try_clone()?;
        dir.publish(file, &temp, &body_file_name(&facts.blake3))?;
        Ok(StagedAssetBody {
            _pin: Some(pin),
            ..staged(Staged::File(held))
        })
    }

    /// Puts `staged` as ASSET `id` in the caller's transaction, through the
    /// batch door every ASSET put takes (its checks, staging, indexes and
    /// short id): a published file as its manifest, any other body as its
    /// bytes, which the door may still move to a file. A file the secret
    /// mask has marked since goes in its row.
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
        if matches!(staged.body, Staged::File(_))
            && crate::secret_custody::masked_file_in_txn(&self.store, txn, &staged.facts.blake3)?
                .is_none()
        {
            let manifest = AssetFileManifest {
                facts: staged.facts,
                kind: AssetFileKind::Opaque,
                mime: staged.mime.clone(),
            }
            .encode()?;
            return batch
                .put_asset_file(id, occurred, learned_at, &manifest, staged.facts)
                .apply(txn);
        }
        let bytes = match &staged.body {
            Staged::Inline(bytes) => std::borrow::Cow::Borrowed(bytes.as_slice()),
            Staged::File(_) => std::borrow::Cow::Owned(staged.to_vec()?),
        };
        batch
            .put(id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
            .apply(txn)
    }
}

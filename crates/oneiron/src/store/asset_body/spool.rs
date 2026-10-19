//! The receive spool of an ASSET body a peer sends by reference (FIX 5489):
//! its frames go, in order, to one temp file in this vault's body directory
//! (`bodies/.tmp-*`), sealed as they come on a sealed vault, and the whole
//! body is staged from it once, at its end, as any streamed body is
//! ([`crate::Vault::stage_asset_body`]). The temp file goes when the spool
//! is dropped, staged or not; a crash leaves it to the writer-open sweep.
//! Its caller gates it on the file plane: nothing makes one while
//! [`super::ASSET_FILE_PLANE`] is off.

use std::io::{self, Read};
use std::sync::Arc;

use super::AssetBodyFacts;
use super::stage::StagedAssetBody;
use crate::error::{Error, Result};
use crate::secret_custody::KnownValues;
use crate::store::{BodyDir, BodyFile, BodySpill};

/// One ASSET body being received: the bytes so far, spilled to a temp file
/// and measured, against the facts its sender offered. Nothing is refused
/// for its length (Rule 5); only a frame out of order, or past the offered
/// length, is.
pub(crate) struct AssetBodySpool {
    dir: BodyDir,
    spill: Option<BodySpill>,
    hasher: blake3::Hasher,
    offered: AssetBodyFacts,
    received: u64,
}

impl AssetBodySpool {
    /// The facts the sender offered for the body.
    pub(crate) const fn offered(&self) -> AssetBodyFacts {
        self.offered
    }

    /// The bytes received so far: the offset the next frame starts at.
    pub(crate) const fn received(&self) -> u64 {
        self.received
    }

    /// Spills one frame, `bytes` from `offset`.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a frame that does not start where the
    /// last one ended, or ends past the offered length; filesystem and
    /// sealing errors.
    pub(crate) fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        if offset != self.received {
            return Err(Error::CorruptedIndex(
                "received asset body frame out of order",
            ));
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.offered.len)
            .ok_or(Error::CorruptedIndex("received asset body past its length"))?;
        let spill = self
            .spill
            .as_mut()
            .ok_or(Error::InvariantViolation("asset body spool staged twice"))?;
        spill.write(bytes)?;
        self.hasher.update(bytes);
        self.received = end;
        Ok(())
    }

    /// Stages the whole body once its last frame is in: it must be exactly
    /// the offered length and BLAKE3, and the staged body's measured facts,
    /// `xxh32` included, the offered ones. `mime` and `known` are as
    /// [`crate::Vault::stage_asset_body`] takes them; `known` is loaded in
    /// the transaction that puts the staged body. The temp file goes either
    /// way.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a body short of its length or of other
    /// facts; the staging errors.
    pub(crate) fn stage(
        mut self,
        vault: &crate::Vault,
        mime: Option<&str>,
        known: Option<Arc<KnownValues>>,
    ) -> Result<StagedAssetBody> {
        let spill = self
            .spill
            .take()
            .ok_or(Error::InvariantViolation("asset body spool staged twice"))?;
        let temp = spill.temp().to_owned();
        let staged = self.stage_spill(spill, vault, mime, known);
        self.dir.discard(&temp);
        staged
    }

    fn stage_spill(
        &self,
        spill: BodySpill,
        vault: &crate::Vault,
        mime: Option<&str>,
        known: Option<Arc<KnownValues>>,
    ) -> Result<StagedAssetBody> {
        let digest = *self.hasher.finalize().as_bytes();
        if self.received != self.offered.len || digest != self.offered.blake3 {
            return Err(Error::CorruptedIndex("received asset body digest"));
        }
        let spilled = spill.finish(&digest, self.received)?;
        let body = FromStart {
            file: spilled.reader()?,
            at: 0,
            len: self.received,
        };
        let staged = vault.stage_asset_body(body, mime, known)?;
        if staged.facts() != self.offered {
            return Err(Error::CorruptedIndex("received asset body digest"));
        }
        Ok(staged)
    }
}

impl Drop for AssetBodySpool {
    fn drop(&mut self) {
        if let Some(spill) = self.spill.take() {
            self.dir.discard(spill.temp());
        }
    }
}

/// A body file read from its start by range, whatever its descriptor's
/// offset: a plain spill's stands at its end once written.
struct FromStart {
    file: BodyFile,
    at: u64,
    len: u64,
}

impl Read for FromStart {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let left = usize::try_from(self.len.saturating_sub(self.at)).unwrap_or(usize::MAX);
        let take = left.min(out.len());
        if take == 0 {
            return Ok(0);
        }
        let bytes = self
            .file
            .read_range(self.at, take)
            .map_err(io::Error::other)?;
        out[..take].copy_from_slice(&bytes);
        self.at += take as u64;
        Ok(take)
    }
}

impl crate::Vault {
    /// A receive spool, in this vault's body directory, for the body a peer
    /// offered with `offered`.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a sealed vault whose key is not admitted.
    pub(crate) fn asset_body_spool(&self, offered: AssetBodyFacts) -> Result<AssetBodySpool> {
        let dir = self.store.body_dir()?;
        let spill = BodySpill::create(&dir)?;
        Ok(AssetBodySpool {
            dir,
            spill: Some(spill),
            hasher: blake3::Hasher::new(),
            offered,
            received: 0,
        })
    }
}

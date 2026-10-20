//! A shadow arm's own body store (PR-S1): one directory, outside any vault,
//! of whole bodies, each a file named by its BLAKE3 digest, written as it
//! streams and measured as a run's result bodies are (its digest, length,
//! lines, preview and secret scan). It is plain: no custody, no seal and no
//! instance rows, since nothing in it is the vault's. The host that owns the
//! arm owns the directory and removes it when the arm is released.
//!
//! What the store holds is kept content of its source run, whose lifetime
//! is the arm's lease (FIX 5718): an erase or actor scrub of the source
//! run's actor releases the arm, and until it does, each read and
//! publication of the arm asks the store's [`ShadowSourceHold`] and meets
//! the erase as typed unavailable.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::types::{ShadowBodyRef, ShadowUnavailable, ShadowUnavailableReason};
use crate::code_run::CodeRunRawOutput;
use crate::compaction::output::OutputRef;
use crate::store::{BodyDir, BodySink, SunkBody, read_body_range};
use crate::{Error, Result};

/// Whether an arm's source still holds its content (FIX 5718): `true`
/// while the source run's actor is here. Asked in a short read of the
/// source's vault at each read and publication of the arm, never held
/// across a model call.
#[derive(Clone)]
pub struct ShadowSourceHold(Arc<dyn Fn() -> bool + Send + Sync>);

impl ShadowSourceHold {
    /// The hold `kept` answers.
    #[must_use]
    pub fn new(kept: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(kept))
    }
}

impl std::fmt::Debug for ShadowSourceHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShadowSourceHold")
    }
}

/// One arm's bodies, in the directory at its root.
#[derive(Debug, Clone)]
pub struct ShadowBodyStore {
    root: PathBuf,
    /// What its source still holds; `None` for a store no source binds.
    hold: Option<ShadowSourceHold>,
}

impl ShadowBodyStore {
    /// The store at `root`, made (0700) when absent. Its parent must be
    /// there already.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a root that is no directory.
    pub fn open(root: PathBuf) -> Result<Self> {
        BodyDir::at_path(&root, true)?
            .ok_or_else(|| Error::InvalidConfig("shadow arm store was not made".to_owned()))?;
        Ok(Self { root, hold: None })
    }

    /// This store, its reads and publications asking `hold` whether its
    /// source still holds its content (FIX 5718).
    #[must_use]
    pub fn held_by(mut self, hold: ShadowSourceHold) -> Self {
        self.hold = Some(hold);
        self
    }

    /// Why the store's content is unavailable now, once an erase or actor
    /// scrub of its source run's actor took it (FIX 5718): `SourceWithheld`
    /// for `response_erased`. `None` while the source holds it.
    #[must_use]
    pub fn source_withheld(&self) -> Option<ShadowUnavailable> {
        let hold = self.hold.as_ref()?;
        if (hold.0)() {
            return None;
        }
        Some(ShadowUnavailable::new(
            ShadowUnavailableReason::SourceWithheld,
            crate::code_run::RESPONSE_ERASED,
        ))
    }

    /// Where the store's bodies are.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The store's directory, held open for one use. A plain directory
    /// whose spills take no instance, as an off-record session's do.
    fn dir(&self) -> Result<BodyDir> {
        let mut dir = BodyDir::at_path(&self.root, false)?
            .ok_or_else(|| Error::InvalidConfig("shadow arm store is gone".to_owned()))?;
        dir.session = true;
        Ok(dir)
    }

    /// A sink for one body, spilled to the store from its first byte.
    pub(crate) fn sink(&self) -> Result<BodySink> {
        Ok(BodySink::new(self.dir()?, 0, None))
    }

    /// Finishes the body `sink` wrote as the store's `path`: its manifest,
    /// and the reason the secret scan marked it with, if it did.
    pub(crate) fn finish(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        let (facts, sunk) = sink.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS)?;
        if let SunkBody::Inline(bytes) = sunk {
            // Only an empty body never spills.
            self.dir()?
                .import(&facts.digest, facts.len, &mut bytes.as_slice())?;
        }
        let output = CodeRunRawOutput::from_facts(path, &facts, complete)?;
        Ok((output, facts.secret))
    }

    /// `bytes`, whole, as the store's `path`: its manifest and its scan.
    pub(crate) fn put_output(
        &self,
        path: impl Into<String>,
        bytes: &[u8],
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        let mut sink = self.sink()?;
        sink.write(bytes)?;
        self.finish(path.into(), sink, true)
    }

    /// `bytes`, whole, as the store's `path`.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a path no result may have.
    pub fn put(&self, path: impl Into<String>, bytes: &[u8]) -> Result<ShadowBodyRef> {
        let (output, secret) = self.put_output(path, bytes)?;
        Ok(ShadowBodyRef::of(&output, secret))
    }

    /// Copies in the body `body` names from `bytes`, checked against its
    /// digest and length, unless the store holds it already.
    pub(crate) fn import(&self, body: OutputRef, bytes: &[u8]) -> Result<()> {
        let mut source = bytes;
        self.dir()?.import(&body.hash, body.byte_len, &mut source)
    }

    /// The whole body `body` names, checked against its digest; `None` when
    /// the store does not hold it.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a body that is not its digest or length.
    pub fn read(&self, body: OutputRef) -> Result<Option<Vec<u8>>> {
        let Some(mut file) = self.dir()?.open_body(&body.hash, body.byte_len)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if *blake3::hash(&bytes).as_bytes() != body.hash {
            return Err(Error::CorruptedIndex("shadow arm body digest"));
        }
        Ok(Some(bytes))
    }

    /// Up to `len` bytes of the body `body` names from `offset`, cut at its
    /// end; `None` when the store does not hold it.
    pub(crate) fn read_range(
        &self,
        body: OutputRef,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.dir()?.open_body(&body.hash, body.byte_len)? else {
            return Ok(None);
        };
        let left = body.byte_len.saturating_sub(offset);
        let take = usize::try_from(left.min(len as u64))
            .map_err(|_| Error::ArithmeticOverflow("shadow arm body range"))?;
        if take == 0 {
            return Ok(Some(Vec::new()));
        }
        read_body_range(&file, offset, take).map(Some)
    }

    /// The sparse line index of the body `body` names, when the store
    /// holds one.
    pub(crate) fn line_index(&self, body: OutputRef) -> Option<Vec<u64>> {
        self.dir().ok()?.read_line_index(&body.hash, body.byte_len)
    }
}

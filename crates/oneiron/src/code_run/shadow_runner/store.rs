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
//!
//! A store its host binds to the source's vault masks each write at write
//! (FIX 5718 part 3, `admit`): a body streams into a raw spool, and only
//! the bytes the side-row wall admits are published, named by their digest.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::admit::ShadowAdmission;
use super::types::{ShadowBodyRef, ShadowUnavailable, ShadowUnavailableReason};
use crate::batch::secret_scan::{BodySpool, SpoolAdmission};
use crate::code_run::{CodeRunRawOutput, ProgramStepFeedback};
use crate::compaction::output::OutputRef;
use crate::engine_executor::{LatestFeedback, RESULT_REPLY_INLINE_BYTES};
use crate::store::{BodyDir, BodySink, SunkBody, read_body_range};
use crate::{EntityId, Error, Result, Vault};

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

/// The type feedback of the program an arm ran (FIX 10389, fork d), as its
/// check stands: one slot every clone of the arm's store shares, read under
/// the arm's lease while the arm's host keeps the store.
#[derive(Clone, Default)]
struct ArmFeedback(Arc<Mutex<Option<LatestFeedback>>>);

impl std::fmt::Debug for ArmFeedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArmFeedback")
    }
}

/// One arm's bodies, in the directory at its root.
#[derive(Debug, Clone)]
pub struct ShadowBodyStore {
    root: PathBuf,
    /// What its source still holds; `None` for a store no source binds.
    hold: Option<ShadowSourceHold>,
    /// The vault its writes are admitted under; `None` for a store no
    /// source binds, whose writes are stored as they come.
    admit: Option<ShadowAdmission>,
    /// The type feedback of the program the arm ran.
    feedback: ArmFeedback,
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
        Ok(Self {
            root,
            hold: None,
            admit: None,
            feedback: ArmFeedback::default(),
        })
    }

    /// This store, its reads and publications asking `hold` whether its
    /// source still holds its content (FIX 5718).
    #[must_use]
    pub fn held_by(mut self, hold: ShadowSourceHold) -> Self {
        self.hold = Some(hold);
        self
    }

    /// This store, each write admitted by the side-row wall under `vault`'s
    /// custody as kept content of its source run `run` (FIX 5718 part 3).
    #[must_use]
    pub fn admitted_in(mut self, vault: Weak<Vault>, run: EntityId) -> Self {
        self.admit = Some(ShadowAdmission::new(vault, run));
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

    /// Keeps `latest`, the type feedback of the program the arm runs, for
    /// the reads under the arm's lease (FIX 10389, fork d).
    pub(crate) fn hold_feedback(&self, latest: LatestFeedback) {
        *self
            .feedback
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(latest);
    }

    /// The type feedback of the program the arm ran, as its check stands
    /// now, a check that landed after the arm answered included, masked as
    /// each write of the arm is (FIX 10389, fork d; FIX 5718 part 3). `None`
    /// once its source's content is gone, and for an arm that ran no
    /// program of its own.
    ///
    /// # Errors
    ///
    /// Storage and custody errors of the masking.
    pub fn latest_feedback(&self) -> Result<Option<ProgramStepFeedback>> {
        if self.source_withheld().is_some() {
            return Ok(None);
        }
        let latest = self
            .feedback
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(mut feedback) = latest.as_ref().map(LatestFeedback::feedback) else {
            return Ok(None);
        };
        if let Some(admit) = &self.admit {
            admit.admit_value(&mut feedback)?;
        }
        Ok(Some(feedback))
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

    /// A sink for one body: a raw spool, in memory up to one reply's size
    /// and past it in a temp file of the store, which its finish admits.
    pub(crate) fn sink(&self) -> Result<BodySink> {
        Ok(BodySink::spooling(
            self.dir()?,
            RESULT_REPLY_INLINE_BYTES as u64,
        ))
    }

    /// Finishes the body `sink` wrote as the store's `path`, as the wall
    /// admits it: its manifest, and the reason the secret scan marked it
    /// with, if it did.
    pub(crate) fn finish(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        self.finish_named(|_| path, sink, complete)
    }

    /// [`Self::finish`] at the path `name` gives the digest of the bytes the
    /// wall admitted. A body with a secret the wall cannot place is stored
    /// as it came and marked by its scan, as before (CALLS C5718-21).
    pub(crate) fn finish_named(
        &self,
        name: impl FnOnce(&[u8; 32]) -> String,
        sink: BodySink,
        complete: bool,
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        let spool = sink.into_spool()?;
        let admitted = match self.admitted(&spool)? {
            SpoolAdmission::Unplaceable(_) => SpoolAdmission::AsIs(&spool),
            admitted => admitted,
        };
        self.publish(name, &admitted, complete)
    }

    /// What the wall admits `spool` as, under the vault this store is bound
    /// to; as it is, for a store no source binds.
    fn admitted<'s>(&self, spool: &'s BodySpool) -> Result<SpoolAdmission<'s>> {
        match &self.admit {
            Some(admit) => admit.admit(spool),
            None => Ok(SpoolAdmission::AsIs(spool)),
        }
    }

    /// Publishes the admitted body under its digest at the path `name`
    /// gives that digest: its manifest and its scan's reason.
    fn publish(
        &self,
        name: impl FnOnce(&[u8; 32]) -> String,
        admitted: &SpoolAdmission<'_>,
        complete: bool,
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        let mut sink = BodySink::new(self.dir()?, 0, None);
        admitted.feed(&mut sink)?;
        let (facts, sunk) = sink.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS)?;
        if let SunkBody::Inline(bytes) = sunk {
            // Only an empty body never spills.
            self.dir()?
                .import(&facts.digest, facts.len, &mut bytes.as_slice())?;
        }
        let output = CodeRunRawOutput::from_facts(name(&facts.digest), &facts, complete)?;
        Ok((output, facts.secret))
    }

    /// `bytes`, whole, as the store's `path`, as the wall admits them: its
    /// manifest and its scan. Bytes with a secret the wall cannot place are
    /// stored as they came and marked, as before.
    pub(crate) fn put_output(
        &self,
        path: impl Into<String>,
        bytes: &[u8],
    ) -> Result<(CodeRunRawOutput, Option<&'static str>)> {
        let mut sink = self.sink()?;
        sink.write(bytes)?;
        self.finish(path.into(), sink, true)
    }

    /// `bytes`, whole, as the store's `path`, as the side-row wall admits
    /// them (FIX 5718 part 3).
    ///
    /// # Errors
    ///
    /// Filesystem errors, a path no result may have, and the wall's storage
    /// and custody errors.
    pub fn put(&self, path: impl Into<String>, bytes: &[u8]) -> Result<ShadowBodyRef> {
        let (output, secret) = self.put_output(path, bytes)?;
        Ok(ShadowBodyRef::of(&output, secret))
    }

    /// [`Self::put`] for an answer an effect that ran returned (a gateway
    /// call's, FIX 5718 part 3, Engine ruling 4): `Err` holds the door's
    /// reason when the answer holds a secret the wall cannot place, and
    /// nothing of it is stored.
    ///
    /// # Errors
    ///
    /// Filesystem errors, a path no result may have, and the wall's storage
    /// and custody errors.
    pub fn put_answer(
        &self,
        path: impl Into<String>,
        bytes: &[u8],
    ) -> Result<std::result::Result<ShadowBodyRef, &'static str>> {
        let spool = BodySpool::of_bytes(bytes.to_vec());
        let admitted = self.admitted(&spool)?;
        if let SpoolAdmission::Unplaceable(reason) = admitted {
            return Ok(Err(reason));
        }
        let path = path.into();
        let (output, secret) = self.publish(|_| path, &admitted, true)?;
        Ok(Ok(ShadowBodyRef::of(&output, secret)))
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

//! Native spill source lifetimes for an admitted exact live-session capture.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, Weak};

use zeroize::Zeroizing;

use super::frames::{FileKey, WrittenBodyPrefix, check_no_written_body, read_written_body_chunk};
use super::rows::BodyKeyRow;
use super::{BodyDir, BodyFile};
use crate::error::OffRecordError;
use crate::{Error, Result};

/// Created once with the actual session entry, never resolved from a reused ref.
pub(crate) struct LiveSpillSources {
    session_ref: String,
    frozen: RwLock<bool>,
    state: Mutex<Sources>,
}

#[derive(Default)]
struct Sources {
    writers: Vec<Weak<WrittenSpillSource>>,
    retained: Vec<Arc<WrittenSpillSource>>,
    retainers: usize,
    directory: Option<BodyDir>,
    published: BTreeMap<String, PublishedCandidate>,
}

#[derive(Clone)]
struct PublishedCandidate {
    digest: [u8; 32],
    len: u64,
    key_row: Option<BodyKeyRow>,
}

/// Source lifetime only. Its private constructor does not admit a hold order.
pub(crate) struct LiveSpillRetention {
    sources: Arc<LiveSpillSources>,
}

pub(super) struct LiveSpillWriter {
    sources: Arc<LiveSpillSources>,
    source: Arc<WrittenSpillSource>,
}

pub(super) struct WrittenSpillSource {
    name: String,
    state: Mutex<WriterState>,
}

enum WriterState {
    Open {
        file: File,
        key: Option<Arc<FileKey>>,
        prefix: Option<WrittenBodyPrefix>,
        complete: Option<([u8; 32], u64)>,
        published_name: Option<String>,
    },
    Published,
}

impl LiveSpillSources {
    pub(crate) fn new(session_ref: &str) -> Arc<Self> {
        Arc::new(Self {
            session_ref: session_ref.to_owned(),
            frozen: RwLock::new(false),
            state: Mutex::new(Sources::default()),
        })
    }

    fn state(&self) -> Result<MutexGuard<'_, Sources>> {
        self.state
            .lock()
            .map_err(|_| Error::InvariantViolation("live spill source mutex poisoned"))
    }

    /// Held for one native filesystem operation, never a producer or network wait.
    pub(crate) fn io(&self) -> Result<RwLockReadGuard<'_, bool>> {
        let guard = self
            .frozen
            .read()
            .map_err(|_| Error::InvariantViolation("live spill IO lock poisoned"))?;
        if *guard {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        Ok(guard)
    }

    /// Caller holds this instance's IO read guard through directory creation.
    pub(crate) fn attach(&self, directory: &BodyDir) -> Result<()> {
        let mut state = self.state()?;
        if state.directory.is_none() {
            state.directory = Some(BodyDir {
                dir: directory.dir.try_clone()?,
                sealed: directory.sealed.clone(),
                session: directory.session,
                live_spill: None,
            });
        }
        Ok(())
    }

    /// Called under the entry's state lock, before the actual HOST insertion.
    /// All short native locks have been dropped before this returns.
    pub(crate) fn retain(self: &Arc<Self>) -> Result<LiveSpillRetention> {
        let _io = self.io()?;
        let mut state = self.state()?;
        if state.retainers == 0 {
            let mut retained: Vec<_> = state.writers.iter().filter_map(Weak::upgrade).collect();
            if let Some(directory) = &state.directory {
                for (name, candidate) in &state.published {
                    if let Some(source) = candidate.open(directory, name)? {
                        retained.push(source);
                    }
                }
            }
            state.retained = retained;
        }
        state.retainers = state
            .retainers
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("live spill retainers"))?;
        Ok(LiveSpillRetention {
            sources: Arc::clone(self),
        })
    }

    /// Called while the writer holds the IO gate, using its actual temp and key.
    pub(super) fn register(
        self: &Arc<Self>,
        file: &File,
        name: &str,
        key: Option<Arc<FileKey>>,
    ) -> Result<LiveSpillWriter> {
        let source = Arc::new(WrittenSpillSource {
            name: name.to_owned(),
            state: Mutex::new(WriterState::Open {
                file: file.try_clone()?,
                key,
                prefix: None,
                complete: None,
                published_name: None,
            }),
        });
        let mut state = self.state()?;
        state.writers.retain(|source| source.strong_count() != 0);
        state.writers.push(Arc::downgrade(&source));
        if state.retainers != 0 {
            state.retained.push(Arc::clone(&source));
        }
        Ok(LiveSpillWriter {
            sources: Arc::clone(self),
            source,
        })
    }

    /// Terminal source cut, after the existing segment seal/drain. The write
    /// guard is released before any file is read or any HOST call is made.
    pub(crate) fn freeze(&self) -> Result<Vec<FrozenSpill>> {
        {
            let mut frozen = self
                .frozen
                .write()
                .map_err(|_| Error::InvariantViolation("live spill IO lock poisoned"))?;
            *frozen = true;
        }
        let (sources, candidates, directory) = {
            let state = self.state()?;
            let mut sources = BTreeMap::new();
            for source in state
                .writers
                .iter()
                .filter_map(Weak::upgrade)
                .chain(state.retained.iter().cloned())
            {
                sources.entry(source.name.clone()).or_insert(source);
            }
            (
                sources,
                state.published.clone(),
                state
                    .directory
                    .as_ref()
                    .map(|dir| -> Result<BodyDir> {
                        Ok(BodyDir {
                            dir: dir.dir.try_clone()?,
                            sealed: dir.sealed.clone(),
                            session: dir.session,
                            live_spill: None,
                        })
                    })
                    .transpose()?,
            )
        };
        let mut frozen = BTreeMap::new();
        for source in sources.into_values() {
            if let Some(body) = source.freeze()? {
                frozen.insert(body.name.clone(), body);
            }
        }
        if let Some(directory) = directory {
            for (name, candidate) in candidates {
                if frozen.contains_key(&name) {
                    continue;
                }
                if let Some(source) = candidate.open(&directory, &name)?
                    && let Some(body) = source.freeze()?
                {
                    frozen.insert(name, body);
                }
            }
        }
        Ok(frozen.into_values().collect())
    }
}

impl Drop for LiveSpillRetention {
    fn drop(&mut self) {
        // No IO/entry lock: an order may be released under the HOST registry lock.
        let released = {
            let mut state = self
                .sources
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.retainers -= 1;
            if state.retainers == 0 {
                std::mem::take(&mut state.retained)
            } else {
                Vec::new()
            }
        };
        drop(released);
    }
}

impl LiveSpillWriter {
    pub(super) fn sources(&self) -> &Arc<LiveSpillSources> {
        &self.sources
    }
    pub(super) fn source(&self) -> Arc<WrittenSpillSource> {
        Arc::clone(&self.source)
    }

    pub(super) fn wrote(&self, prefix: Option<WrittenBodyPrefix>) -> Result<()> {
        let mut state = self
            .source
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("live spill writer mutex poisoned"))?;
        if let WriterState::Open {
            prefix: current, ..
        } = &mut *state
        {
            *current = prefix;
        }
        Ok(())
    }

    pub(super) fn finished(&self, digest: [u8; 32], len: u64) -> Result<()> {
        let mut state = self
            .source
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("live spill writer mutex poisoned"))?;
        if let WriterState::Open { complete, .. } = &mut *state {
            *complete = Some((digest, len));
        }
        Ok(())
    }

    /// A directory fsync can fail after rename. Record only a name proven to
    /// hold this same native file, independently of the publish return code.
    pub(super) fn published(
        &self,
        directory: &BodyDir,
        name: &str,
        digest: [u8; 32],
        len: u64,
        key_row: Option<BodyKeyRow>,
    ) -> Result<()> {
        let Some(named) = directory.open_named(name)? else {
            return Ok(());
        };
        let named = named.metadata()?;
        let mut sources = self.sources.state()?;
        let mut source = self
            .source
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("live spill writer mutex poisoned"))?;
        let WriterState::Open {
            file,
            published_name,
            ..
        } = &mut *source
        else {
            return Ok(());
        };
        let actual = file.metadata()?;
        if actual.dev() != named.dev() || actual.ino() != named.ino() {
            return Ok(());
        }
        sources.published.insert(
            name.to_owned(),
            PublishedCandidate {
                digest,
                len,
                key_row,
            },
        );
        *published_name = Some(name.to_owned());
        if sources.retainers == 0 {
            *source = WriterState::Published;
        }
        Ok(())
    }
}

impl PublishedCandidate {
    fn open(&self, directory: &BodyDir, name: &str) -> Result<Option<Arc<WrittenSpillSource>>> {
        let Some(file) = directory.open_named(name)? else {
            return Ok(None);
        };
        let key = match (&directory.sealed, &self.key_row) {
            (Some(seal), Some(row)) => Some(
                row.open(&self.digest, seal)?
                    .ok_or(Error::CorruptedIndex("live spill candidate key scope"))?,
            ),
            (Some(_), None) => {
                return Err(Error::CorruptedIndex("live spill candidate key missing"));
            }
            (None, _) => None,
        };
        Ok(Some(Arc::new(WrittenSpillSource {
            name: name.to_owned(),
            state: Mutex::new(WriterState::Open {
                file,
                key,
                prefix: None,
                complete: Some((self.digest, self.len)),
                published_name: None,
            }),
        })))
    }
}

/// A source cut from actual frozen native bytes, not a producer occurrence.
pub(crate) struct FrozenSpill {
    name: String,
    file: File,
    key: Option<Arc<FileKey>>,
    extent: FrozenExtent,
}

#[derive(Clone, Copy)]
enum FrozenExtent {
    Plain(u64),
    Chunks(WrittenBodyPrefix),
    Complete([u8; 32], u64),
}

impl WrittenSpillSource {
    fn freeze(&self) -> Result<Option<FrozenSpill>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("live spill writer mutex poisoned"))?;
        let WriterState::Open {
            file,
            key,
            prefix,
            complete,
            published_name,
        } = &*state
        else {
            return Ok(None);
        };
        let extent = if let Some((digest, len)) = complete {
            FrozenExtent::Complete(*digest, *len)
        } else if key.is_none() {
            let len = file.metadata()?.len();
            if len == 0 {
                return Ok(None);
            }
            FrozenExtent::Plain(len)
        } else if let Some(prefix) = prefix {
            if file.metadata()?.len() != prefix.physical()? {
                return Err(Error::CorruptedIndex("live spill incomplete frame"));
            }
            FrozenExtent::Chunks(*prefix)
        } else {
            check_no_written_body(file)?;
            return Ok(None);
        };
        Ok(Some(FrozenSpill {
            name: published_name.as_ref().unwrap_or(&self.name).clone(),
            file: file.try_clone()?,
            key: key.clone(),
            extent,
        }))
    }
}

impl FrozenSpill {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn finished(&self) -> bool {
        matches!(self.extent, FrozenExtent::Complete(..))
    }
    pub(crate) fn physical_len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub(crate) fn reader(&self) -> Result<Box<dyn Read + '_>> {
        match self.extent {
            FrozenExtent::Plain(len) => Ok(Box::new(PreadBody {
                file: &self.file,
                at: 0,
                len,
            })),
            FrozenExtent::Complete(digest, len) => match &self.key {
                Some(key) => Ok(Box::new(BodyFile::sealed(
                    self.file.try_clone()?,
                    Arc::clone(key),
                    &digest,
                    len,
                )?)),
                None => {
                    if self.file.metadata()?.len() != len {
                        return Err(Error::CorruptedIndex("live spill body length"));
                    }
                    Ok(Box::new(PreadBody {
                        file: &self.file,
                        at: 0,
                        len,
                    }))
                }
            },
            FrozenExtent::Chunks(prefix) => Ok(Box::new(PrefixBody {
                file: &self.file,
                key: self
                    .key
                    .as_deref()
                    .ok_or(Error::CorruptedIndex("live spill prefix key"))?,
                prefix,
                next: 0,
                chunk: Zeroizing::new(Vec::new()),
                at: 0,
            })),
        }
    }

    pub(crate) fn measured(&self) -> Result<([u8; 32], u64)> {
        let mut reader = self.reader()?;
        let mut hasher = blake3::Hasher::new();
        let len = io::copy(&mut reader, &mut hasher)?;
        let digest = *hasher.finalize().as_bytes();
        if let FrozenExtent::Complete(expected, expected_len) = self.extent
            && (len != expected_len || digest != expected)
        {
            return Err(Error::CorruptedIndex("live spill body digest"));
        }
        Ok((digest, len))
    }
}

struct PreadBody<'file> {
    file: &'file File,
    at: u64,
    len: u64,
}
impl Read for PreadBody<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let take = out
            .len()
            .min(usize::try_from(self.len - self.at).unwrap_or(usize::MAX));
        if take == 0 {
            return Ok(0);
        }
        let read = self.file.read_at(&mut out[..take], self.at)?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.at += read as u64;
        Ok(read)
    }
}

struct PrefixBody<'file> {
    file: &'file File,
    key: &'file FileKey,
    prefix: WrittenBodyPrefix,
    next: u64,
    chunk: Zeroizing<Vec<u8>>,
    at: usize,
}
impl Read for PrefixBody<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.at == self.chunk.len() {
            if self.next == self.prefix.chunks() {
                return Ok(0);
            }
            self.chunk = read_written_body_chunk(self.file, self.key, &self.prefix, self.next)
                .map_err(io::Error::other)?;
            self.next += 1;
            self.at = 0;
        }
        let take = out.len().min(self.chunk.len() - self.at);
        out[..take].copy_from_slice(&self.chunk[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

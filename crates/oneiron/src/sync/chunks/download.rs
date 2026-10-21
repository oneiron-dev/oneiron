//! One bounded in-flight have/want transfer, driven by real socket replies.

use super::page::ManifestPages;
use super::{
    ChunkMark, ChunkSyncRequest, ChunkSyncResponse, MAX_WANT_CHUNKS, decode, encode_chunk_request,
    invalid,
};
use crate::error::Result;
use crate::origin::lfs::{LfsManifest, LfsOid, LfsPutOutcome};
use crate::{TimeRange, Vault};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

/// One transfer's disk spool and metadata. Dropping it cancels without publication.
/// Hosts bound concurrency by owning a single transfer per connection.
pub struct ChunkDownload {
    request: ChunkSyncRequest,
    /// The manifest's pages as they arrive (FIX 8860).
    pages: ManifestPages,
    manifest: Option<LfsManifest>,
    /// The lift mark its source sent with the object (FIX 2897).
    mark: Option<ChunkMark>,
    spool: File,
    next: usize,
    waiting: Option<[u8; 32]>,
    outcome: Option<LfsPutOutcome>,
    staged: std::collections::BTreeMap<[u8; 32], (u64, u32)>,
    length: u64,
}

impl ChunkDownload {
    /// Starts an owner-to-owner transfer. Transport must use owner-authenticated
    /// full-window chunk protocol. Federated hosts use the selector-bound pull API instead.
    pub fn new(oid: LfsOid) -> Result<Self> {
        Ok(Self {
            request: ChunkSyncRequest {
                request: 0,
                oid: *oid.as_bytes(),
                selector: Vec::new(),
                have: Vec::new(),
                want: None,
                cursor: None,
                read: None,
            },
            pages: ManifestPages::default(),
            manifest: None,
            mark: None,
            spool: tempfile::tempfile()?,
            next: 0,
            waiting: None,
            outcome: None,
            staged: std::collections::BTreeMap::new(),
            length: 0,
        })
    }

    /// This transfer under the id `request`, which each of its requests
    /// carries and each reply must echo (FIX 8864).
    pub(crate) fn numbered(mut self, request: u64) -> Self {
        self.request.request = request;
        self
    }

    /// The id each of this transfer's requests carries.
    pub(crate) fn request_id(&self) -> u64 {
        self.request.request
    }

    /// The first request asks only for the manifest.
    pub fn initial_request(&self) -> Result<Vec<u8>> {
        encode_chunk_request(&self.request)
    }

    /// Accepts one reply and produces the next bounded request, or publishes
    /// the fully verified object and returns None. Unsolicited/reordered
    /// replies fail.
    pub fn accept(&mut self, vault: &Vault, bytes: &[u8], now: u64) -> Result<Option<Vec<u8>>> {
        let reply: ChunkSyncResponse = decode(bytes)?;
        self.accept_reply(vault, reply, now)
    }

    /// [`Self::accept`] for a reply already decoded. A manifest comes in
    /// pages, each asked for by the cursor the one before named (FIX 8860).
    /// An object its source sent with its lift mark installs marked: its
    /// scans mark it rather than refuse it (FIX 2897).
    pub(crate) fn accept_reply(
        &mut self,
        vault: &Vault,
        reply: ChunkSyncResponse,
        now: u64,
    ) -> Result<Option<Vec<u8>>> {
        if self.outcome.is_some() || reply.request() != self.request.request {
            return Err(invalid());
        }
        match (&self.manifest, self.waiting, reply) {
            (None, None, ChunkSyncResponse::Manifest(page)) => {
                let mark = page.mark.clone();
                if let Some(next) = self.pages.take(self.request.request, page)? {
                    self.request.cursor = Some(next);
                    return encode_chunk_request(&self.request).map(Some);
                }
                self.request.cursor = None;
                self.manifest = Some(self.pages.manifest()?);
                self.mark = mark;
            }
            (Some(manifest), Some(expected), ChunkSyncResponse::Chunks(mut page)) => {
                if page.next.is_some() || page.chunks.len() != 1 || page.chunks[0].0 != expected {
                    return Err(invalid());
                }
                let (_, body) = page.chunks.pop().expect("one entry");
                let chunk = &manifest.chunks[self.next];
                if body.len() != chunk.size as usize || blake3::hash(&body).as_bytes() != &expected
                {
                    return Err(invalid());
                }
                self.staged.insert(expected, (self.length, chunk.size));
                self.spool.write_all(&body)?;
                self.length += body.len() as u64;
                self.next += 1;
                self.waiting = None;
            }
            _ => return Err(invalid()),
        }
        let manifest = self.manifest.as_ref().expect("manifest received");
        while self.next < manifest.chunks.len() {
            let chunk = &manifest.chunks[self.next];
            let existing = if let Some((offset, size)) = self.staged.get(&chunk.hash) {
                let mut bytes = vec![0u8; *size as usize];
                self.spool.seek(SeekFrom::Start(*offset))?;
                self.spool.read_exact(&mut bytes)?;
                self.spool.seek(SeekFrom::Start(self.length))?;
                Some(bytes)
            } else {
                vault.lfs_chunk_if_present(chunk)?
            };
            if let Some(bytes) = existing {
                self.staged
                    .entry(chunk.hash)
                    .or_insert((self.length, chunk.size));
                self.spool.write_all(&bytes)?;
                self.length += bytes.len() as u64;
                if self.request.have.len() < MAX_WANT_CHUNKS
                    && !self.request.have.contains(&chunk.hash)
                {
                    self.request.have.push(chunk.hash);
                }
                self.next += 1;
            } else {
                self.waiting = Some(chunk.hash);
                self.request.want = Some(vec![chunk.hash]);
                return encode_chunk_request(&self.request).map(Some);
            }
        }
        self.spool.seek(SeekFrom::Start(0))?;
        let mark = self
            .mark
            .as_ref()
            .map(|mark| (mark.reason.as_str(), mark.marked_at));
        self.outcome = Some(vault.install_lfs_manifest_with_mark(
            LfsOid::from_bytes(self.request.oid),
            manifest,
            mark,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            |chunk| {
                let mut bytes = vec![0u8; chunk.size as usize];
                self.spool.read_exact(&mut bytes)?;
                Ok(bytes)
            },
        )?);
        Ok(None)
    }

    /// The durable result, available only after complete object verification.
    pub fn outcome(&self) -> Option<LfsPutOutcome> {
        self.outcome
    }
}

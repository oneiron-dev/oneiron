//! One bounded in-flight have/want transfer, driven by real socket replies.

use super::{
    ChunkSyncRequest, ChunkSyncResponse, MAX_WANT_CHUNKS, decode, encode_chunk_request, invalid,
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
    manifest: Option<LfsManifest>,
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
                oid: *oid.as_bytes(),
                selector: Vec::new(),
                have: Vec::new(),
                want: None,
            },
            manifest: None,
            spool: tempfile::tempfile()?,
            next: 0,
            waiting: None,
            outcome: None,
            staged: std::collections::BTreeMap::new(),
            length: 0,
        })
    }

    /// The first request asks only for the manifest.
    pub fn initial_request(&self) -> Result<Vec<u8>> {
        encode_chunk_request(&self.request)
    }

    /// Accepts one reply and produces the next bounded want, or publishes the
    /// fully verified object and returns None. Unsolicited/reordered replies fail.
    pub fn accept(&mut self, vault: &Vault, bytes: &[u8], now: u64) -> Result<Option<Vec<u8>>> {
        if self.outcome.is_some() {
            return Err(invalid());
        }
        let reply: ChunkSyncResponse = decode(bytes)?;
        match (&self.manifest, self.waiting, reply) {
            (None, None, ChunkSyncResponse::Manifest(bytes)) => {
                self.manifest = Some(LfsManifest::decode(&bytes)?);
            }
            (Some(manifest), Some(expected), ChunkSyncResponse::Chunks(mut chunks)) => {
                if chunks.len() != 1 || chunks[0].0 != expected {
                    return Err(invalid());
                }
                let (_, body) = chunks.pop().expect("one entry");
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
        self.outcome = Some(vault.install_lfs_manifest(
            LfsOid::from_bytes(self.request.oid),
            manifest,
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

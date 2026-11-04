//! FIX 12086: the owner's starting checkpoint read from one stream, its files
//! one after another, so no door holds the whole checkpoint or a base64 copy
//! of it. Each file is kept as [`super::keep_reader`] keeps one, all in one
//! transaction, and its pin is the version that append returns: nothing reads
//! a kept file back whole. The blob custody's append stages each file from
//! the stream (FIX 12091): once the ASSET file plane files it
//! (`store::asset_body::ASSET_FILE_PLANE`), a long shard goes to its body file
//! and never sits whole in memory; while the plane is off, each file is held
//! once at its write, in its row.
use std::collections::BTreeSet;
use std::io::Read;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::llm::ModelId;
use crate::training_pack::{
    CheckpointFileKind, CheckpointFilePin, PinnedCheckpoint, SourcePin, invalid,
};

use super::{file_name, keep_reader};

/// One file of a streamed checkpoint: what a checkpoint upload says of it,
/// with its length in place of its bytes.
#[derive(Debug, Clone)]
pub struct CheckpointFileStream {
    pub name: String,
    pub kind: CheckpointFileKind,
    pub source: SourcePin,
    /// The producer's BLAKE3 of the file.
    pub blake3: [u8; 32],
    /// The file's length: the next this many bytes of the stream.
    pub bytes: u64,
}

/// A starting checkpoint whose files follow one another in one stream, in
/// the order `files` names them.
#[derive(Debug, Clone)]
pub struct CheckpointStream {
    pub model: ModelId,
    pub files: Vec<CheckpointFileStream>,
}

impl Vault {
    /// [`Vault::keep_training_checkpoint`] over `body`, which carries
    /// `checkpoint`'s files back to back and nothing after them. A body that
    /// ends early, runs past its files, or holds a file whose hash differs
    /// from the producer's keeps nothing. This never changes a role.
    pub fn keep_training_checkpoint_streamed(
        &self,
        owner: &AuthenticatedOwner,
        checkpoint: &CheckpointStream,
        body: &mut dyn Read,
    ) -> Result<PinnedCheckpoint> {
        validate(checkpoint)?;
        // KS-2A (FIX 12091): an instance for each file the asset plane may
        // file, minted before the writer opens.
        let mint = self.asset_body_mint(checkpoint.files.iter().map(|file| file.bytes))?;
        // What each staged file leaves to hold outlives the commit: its pin
        // keeps a published file from the collector until the row naming it
        // is durable. No file's bytes are held past its own append.
        let (pinned, _staged) = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let run = self.store.clock.entity_id()?;
            let mut files = Vec::with_capacity(checkpoint.files.len());
            let mut staged = Vec::with_capacity(checkpoint.files.len());
            for file in &checkpoint.files {
                let mut next = (&mut *body).take(file.bytes);
                let (content, held) =
                    keep_reader(self, txn, actor, run, &file.name, &mut next, mint.as_ref())?;
                staged.push(held);
                if next.limit() != 0 {
                    return Err(invalid("checkpoint body ends before its files do"));
                }
                if content.blake3 != file.blake3 {
                    return Err(invalid("starting checkpoint hash mismatch"));
                }
                files.push(CheckpointFilePin {
                    name: file.name.clone(),
                    kind: file.kind,
                    source: file.source.clone(),
                    content,
                    declared_blake3: file.blake3,
                });
            }
            if body.read(&mut [0u8; 1])? != 0 {
                return Err(invalid("checkpoint body runs past its files"));
            }
            files.sort_by(|a, b| a.name.cmp(&b.name));
            let pinned = PinnedCheckpoint {
                model: checkpoint.model.clone(),
                files,
            };
            Ok((pinned, staged))
        })?;
        Ok(pinned)
    }
}

/// The checks a checkpoint upload's files meet, before a byte is read.
fn validate(checkpoint: &CheckpointStream) -> Result<()> {
    if checkpoint.files.is_empty() {
        return Err(invalid("a checkpoint must pin every loaded file"));
    }
    let mut names = BTreeSet::new();
    for file in &checkpoint.files {
        file.source.validate()?;
        file_name(&file.name, file.kind)?;
        if !names.insert(&file.name) {
            return Err(invalid("duplicate checkpoint file name"));
        }
    }
    if !checkpoint
        .files
        .iter()
        .any(|file| file.kind == CheckpointFileKind::Weights)
    {
        return Err(invalid(
            "a checkpoint needs at least one safetensors weight shard",
        ));
    }
    Ok(())
}

//! The code-run result bodies (OF-597): the sinks a body streams through,
//! the rows and descriptors that publish one, and the reads that open one
//! (moved out of the row-family module whole).

use super::*;
use crate::result_body::ResultBodyPin;

mod reader;

pub(crate) use self::reader::CodeRunResultBodyReader;

impl Vault {
    /// A writer for one result body, into this vault's `bodies/`. Each value
    /// custody knows is replaced by its handle as it streams (OF-560 C).
    pub(crate) fn code_run_output_sink(&self) -> Result<BodySink> {
        Ok(self.code_run_script_sink()?.sweeping(self.known_source()?))
    }

    /// [`Self::code_run_output_sink`] with no sweep, for a step's program:
    /// the stored program is the one a resumed step runs again, byte for
    /// byte.
    pub(crate) fn code_run_script_sink(&self) -> Result<BodySink> {
        Ok(BodySink::new(
            self.store.body_dir()?,
            self.limit_watch().bound(EngineLimit::CodeResultInlineBytes),
            Some(self.store.body_mint()?),
        ))
    }

    /// Publishes the body `sink` wrote as the output at `path`: a spilled
    /// body's file is whole on disk before the row naming it commits. With an
    /// `owner` (the run whose record names it), the same transaction
    /// registers the body as that owner's occurrence, so erasing the owner
    /// releases it.
    pub(crate) fn publish_code_run_output(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        owner: Option<EntityId>,
    ) -> Result<CodeRunRawOutput> {
        let finished = finish_output(path, sink, complete, self.limit_watch(), |digest| {
            self.pin_result_body(digest)
        })?;
        let mut wtxn = self.store.env.write_txn()?;
        self.put_code_run_output_in_txn(&mut wtxn, &finished, &finished.output, owner)?;
        wtxn.commit()?;
        Ok(finished.output)
    }

    /// Writes the row of the body `finished` holds, the secret mark of
    /// `owner`'s occurrence of it, and, with an `owner`, `occurrence` as that
    /// owner's: the manifest of the same bytes at the owner's path. With no
    /// `owner` no descriptor holds the body, so its row holds it on its own
    /// (FIX 5399b).
    pub(crate) fn put_code_run_output_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        finished: &FinishedOutput,
        occurrence: &CodeRunRawOutput,
        owner: Option<EntityId>,
    ) -> Result<()> {
        self.put_code_run_output_row_in_txn(
            wtxn,
            finished,
            occurrence,
            ResultOccurrence::of(owner, occurrence)?,
            owner.is_none(),
        )?;
        if let Some(owner) = owner {
            crate::provenance::body::publish_body_in_txn(
                &self.store,
                wtxn,
                &owned_body(owner, occurrence, &finished.body)?,
            )?;
        }
        Ok(())
    }

    /// Writes the row of the body `finished` holds and, when the secret scan
    /// hit it, the mark of `at`, the occurrence `output` is. `standalone`:
    /// the put publishes no descriptor, so the row holds its body on its
    /// own; a row that held it before keeps holding it (FIX 5399b).
    fn put_code_run_output_row_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        finished: &FinishedOutput,
        output: &CodeRunRawOutput,
        at: ResultOccurrence,
        standalone: bool,
    ) -> Result<()> {
        if output.handle != finished.output.handle {
            return Err(Error::InvariantViolation(
                "code-run output occurrence names other bytes",
            ));
        }
        let held = standalone || code_run_body_held_in_txn(&self.store, wtxn, &output.raw_blake3)?;
        RAW_OUTPUTS.put(
            &self.store,
            wtxn,
            &output.handle,
            &finished.body.holding(held),
        )?;
        // A sealed body file's key commits with the row naming it (FIX 5348).
        if let Some(key) = &finished.key {
            crate::store::bind_body_key_in_txn(&self.store, wtxn, &self.store.body_dir()?, key)?;
        }
        if let Some(reason) = finished.secret {
            self.mark_code_run_output_secret_in_txn(wtxn, output, at, reason)?;
        }
        Ok(())
    }

    /// Writes what `reader` yields, through `sink`, as a complete body at
    /// `path`, a frame at a time as it streams (FIX 3677): a file, past the
    /// inline bound, is whole on disk when this returns, and no row names it
    /// yet.
    pub(crate) fn stage_code_run_output_from<R: std::io::Read>(
        &self,
        path: String,
        mut sink: BodySink,
        mut reader: R,
    ) -> Result<FinishedOutput> {
        let mut frame = vec![0; crate::store::LINE_INDEX_BLOCK_BYTES as usize];
        loop {
            let read = match reader.read(&mut frame) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            sink.write(&frame[..read])?;
        }
        finish_output(path, sink, true, self.limit_watch(), |digest| {
            self.pin_result_body(digest)
        })
    }

    /// [`Self::code_run_output_sink`] as `staged` holds it, prepared before
    /// its caller's write transaction opened (FIX 3678, KS-2A): the
    /// whole-vault import stages each result body inside its one
    /// transaction, spilling into the instances minted then and sweeping the
    /// values `known` holds, which that writer read (KS-3).
    pub(crate) fn code_run_output_sink_knowing(
        &self,
        staged: StagedSinks,
        known: Option<std::sync::Arc<crate::secret_custody::KnownValues>>,
    ) -> Result<BodySink> {
        Ok(BodySink::new(
            self.store.body_dir()?,
            self.limit_watch().bound(EngineLimit::CodeResultInlineBytes),
            Some(staged.mint),
        )
        .sweeping_in_writer(known))
    }

    /// What `count` result bodies a caller stages inside one write
    /// transaction sink through, minted now, before it opens: `count` body
    /// instances, one for each body that may spill. One left unspilled is
    /// debris. The values custody knows are read in that writer (KS-3).
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn staged_result_sinks(&self, count: usize) -> Result<StagedSinks> {
        Ok(StagedSinks {
            mint: self.store.body_mint()?.reserve(count)?,
        })
    }

    /// Whether the result body row of `digest` holds its body inline.
    pub(crate) fn code_run_body_inline_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<bool> {
        Ok(matches!(
            RAW_OUTPUTS.get(&self.store, txn, &body_handle(digest))?,
            Some(StoredBody::Inline { .. })
        ))
    }

    /// The inline bound a result body spills past.
    pub(crate) fn code_result_inline_bytes(&self) -> u64 {
        self.limit_watch().bound(EngineLimit::CodeResultInlineBytes)
    }

    /// Stores a complete body held whole under its content handle; `output`
    /// must be its manifest, and `owner` the run that holds it, if one does.
    pub fn put_code_run_raw_output(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        self.put_code_run_raw_output_tainted(owner, output, raw, &[])
    }

    /// Stores a complete body ALONGSIDE the taint refs of the action that
    /// produced them (SECRET-04, ONE-1922), on the occurrence `owner` holds
    /// (or the bytes' own, with none). With an `owner`, the same writer
    /// publishes the body as that owner's occurrence, so erasing the owner
    /// releases it, and the row takes no hold of its own; a hold its row
    /// kept before stays (FIX 7283). With none, or where
    /// `raw_put_publishes_descriptor` keeps the put as it was, no
    /// descriptor is published and the row holds its body on its own (FIX
    /// 5399b).
    ///
    /// One write transaction carries the sidecar and the body row, so
    /// tainted exhaust can never survive a half-failed write wearing no
    /// mark. An empty ref list is exactly the untainted put (the sidecar is
    /// cleared, not written empty); it clears this occurrence's sidecar only,
    /// never another's of the same bytes.
    pub fn put_code_run_raw_output_tainted(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
        taint_refs: &[SecretTaintRef],
    ) -> Result<()> {
        validate_taint_refs(taint_refs)?;
        let at = ResultOccurrence::of(owner, output)?;
        let mut sink = self.code_run_output_sink()?;
        sink.write(raw)?;
        let finished = finish_output(
            output.path.clone(),
            sink,
            true,
            self.limit_watch(),
            |digest| self.pin_result_body(digest),
        )?;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        let key = at.mark_key(&output.handle);
        let mut wtxn = self.store.env.write_txn()?;
        if taint_refs.is_empty() {
            RAW_OUTPUT_TAINTS.delete(&self.store, &mut wtxn, &key)?;
        } else {
            RAW_OUTPUT_TAINTS.put(&self.store, &mut wtxn, &key, &taint_refs.to_vec())?;
        }
        let publishes = match owner {
            Some(owner) => {
                let body = owned_body(owner, output, &finished.body)?;
                let prior = crate::provenance::body::owned_body_in_txn(
                    &self.store,
                    &wtxn,
                    &owner,
                    &body.occurrence,
                );
                raw_put_publishes_descriptor(&prior, &body)
            }
            None => false,
        };
        if publishes {
            self.put_code_run_output_in_txn(&mut wtxn, &finished, output, owner)?;
        } else {
            self.put_code_run_output_row_in_txn(&mut wtxn, &finished, output, at, true)?;
        }
        Ok(wtxn.commit()?)
    }

    /// [`Self::retain_message_result_in_txn`] for a MESSAGE a save keeps out
    /// of an off-record room, in the save's transaction (FIX 365). The run
    /// that made the body ran in the room, so `room`, the room's composed
    /// view, holds the body's row, the producer's marks and the run's replay
    /// record: the row lands in base unless base holds it already, the marks
    /// land on the MESSAGE's occurrence, and the hold keeps the rows the
    /// run's answers were served from while the room still holds its record.
    /// A spilled body's file is in `bodies/` before this runs.
    pub(crate) fn retain_saved_message_result_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        room: &impl side_table::SideTableDbs,
        message: EntityId,
        attachment: &crate::memory::MessageResultAttachment,
    ) -> Result<()> {
        let output = attachment.output()?;
        let stored = match RAW_OUTPUTS.get(&self.store, wtxn, &output.handle)? {
            Some(stored) => stored,
            None => {
                let stored = RAW_OUTPUTS
                    .get(room, wtxn, &output.handle)?
                    .ok_or(Error::CorruptedIndex("message result body"))?;
                if matches!(stored, StoredBody::File { .. })
                    && !crate::store::keep_promoted_body_key_in_txn(
                        &self.store,
                        wtxn,
                        &output.raw_blake3,
                        output.raw_len,
                        self.result_body_pins.promoted(&output.raw_blake3),
                    )?
                {
                    return Err(Error::CorruptedIndex("message result body file missing"));
                }
                // Base held no row: the MESSAGE's descriptor alone holds the
                // copy, so the room's own hold stays in the room (FIX 5399b).
                let stored = stored.holding(false);
                RAW_OUTPUTS.put(&self.store, wtxn, &output.handle, &stored)?;
                stored
            }
        };
        let producer =
            ResultOccurrence::of(Some(attachment.source.run_id), &output)?.mark_key(&output.handle);
        let key = ResultOccurrence::of(Some(message), &output)?.mark_key(&output.handle);
        if let Some(refs) = RAW_OUTPUT_TAINTS
            .get(room, wtxn, &producer)?
            .filter(|refs| !refs.is_empty())
        {
            RAW_OUTPUT_TAINTS.put(&self.store, wtxn, &key, &refs)?;
        }
        if let Some(reason) = RAW_OUTPUT_SECRETS.get(room, wtxn, &producer)? {
            RAW_OUTPUT_SECRETS.put(&self.store, wtxn, &key, &reason)?;
        }
        let served_rows = REPLAY_RECORDS
            .get(room, wtxn, &attachment.source.run_id)?
            .and_then(|record| record.agent_verb_rows());
        let mut held = owned_body(message, &output, &stored)?;
        held.result = Some(crate::provenance::body::RetainedResultProvenance {
            run_id: attachment.source.run_id,
            occurrence: attachment.source.occurrence,
            path: attachment.source.path.clone(),
            served_rows,
        });
        crate::provenance::body::publish_body_in_txn(&self.store, wtxn, &held)
    }

    /// The whole body of `output` under `rtxn`, checked against its digest;
    /// `None` when no row holds it.
    pub(crate) fn code_run_result_body_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<Vec<u8>>> {
        self.stored_body_in_txn(rtxn, output)?
            .map(|(body, key)| {
                load_whole_body(output, body, key.as_ref(), || {
                    Ok(vec![self.store.body_dir()?])
                })
            })
            .transpose()
    }

    /// The stored row of `output`'s body and, read in the same snapshot, the
    /// key row of its sealed file (FIX 5348).
    fn stored_body_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<(StoredBody, Option<BodyKeyRow>)>> {
        let Some(body) = RAW_OUTPUTS.get(&self.store, rtxn, &output.handle)? else {
            return Ok(None);
        };
        Ok(Some((
            body,
            body_key_row_in_txn(&self.store, rtxn, &output.raw_blake3)?,
        )))
    }

    /// Loads the whole body of `output`, checked against its digest. For
    /// small bodies and explicit whole reads; context reads take ranges.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _custody = self.store.gate_custody_read_guard()?;
        let _pin = self.pin_result_body(output.raw_blake3);
        let body = {
            let rtxn = self.store.env.read_txn()?;
            self.stored_body_in_txn(&rtxn, output)?
        };
        body.map(|(body, key)| {
            load_whole_body(output, body, key.as_ref(), || {
                Ok(vec![self.store.body_dir()?])
            })
        })
        .transpose()
    }

    /// The whole body a context reference names, by its digest and length,
    /// checked against both.
    pub(crate) fn get_raw_body(
        &self,
        source: crate::compaction::output::OutputRef,
    ) -> Result<Option<Vec<u8>>> {
        let output = CodeRunRawOutput::of_ref(source);
        let _custody = self.store.gate_custody_read_guard()?;
        let _pin = self.pin_result_body(source.hash);
        let body = {
            let rtxn = self.store.env.read_txn()?;
            self.stored_body_in_txn(&rtxn, &output)?
        };
        body.map(|(body, key)| {
            load_whole_body(&output, body, key.as_ref(), || {
                Ok(vec![self.store.body_dir()?])
            })
        })
        .transpose()
    }

    /// `len` bytes of `output`'s body from `offset`, cut at its end: an
    /// inline body is read in place, a file by range. Nothing else of the
    /// body is read.
    pub(crate) fn read_code_run_raw_output_range(
        &self,
        output: &CodeRunRawOutput,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _custody = self.store.gate_custody_read_guard()?;
        let _pin = self.pin_result_body(output.raw_blake3);
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = RAW_OUTPUTS.get_borrowed(&self.store, &rtxn, &output.handle)? else {
            return Ok(None);
        };
        let key = body_key_row_in_txn(&self.store, &rtxn, &output.raw_blake3)?;
        read_body_row_range(output, &row, key.as_ref(), offset, len, || {
            Ok(vec![self.store.body_dir()?])
        })
        .map(Some)
    }
}

/// What result bodies staged inside one write transaction spill into,
/// prepared before it opened ([`Vault::staged_result_sinks`]).
#[derive(Clone)]
pub(crate) struct StagedSinks {
    mint: crate::store::BodyMint,
}

/// A finished body: its manifest, its row and the secret scan's hit. A
/// spilled body's file is already whole on disk.
pub(crate) struct FinishedOutput {
    pub(crate) output: CodeRunRawOutput,
    pub(in crate::code_run::storage) body: StoredBody,
    pub(in crate::code_run::storage) secret: Option<&'static str>,
    /// A sealed file's key row, committed with the body's row (FIX 5348).
    pub(in crate::code_run::storage) key: Option<StagedBodyKey>,
    /// The reader pin on the body's final digest, taken before its file was
    /// published under it and held until the row naming it commits or the
    /// write is dropped: the collector leaves the file be meanwhile (FIX
    /// 5399b).
    _pin: ResultBodyPin,
}

impl FinishedOutput {
    /// The manifest of these bytes at `path`, as one owner's occurrence.
    pub(crate) fn at(&self, path: String, complete: bool) -> Result<CodeRunRawOutput> {
        let output = CodeRunRawOutput {
            path,
            complete,
            ..self.output.clone()
        };
        validate_raw_output(&output)?;
        Ok(output)
    }
}

/// Finishes `sink` into the output's manifest, its row and the secret
/// scan's hit. A body that took the disk below `[limits]
/// code_result_disk_floor_bytes` asks that row's question; it is stored
/// whole all the same, as a body the scan marked is. `pin` pins the body's
/// final digest, its sweep's tail written through once, before a spilled
/// file is published under it (FIX 5399b).
pub(in crate::code_run::storage) fn finish_output(
    path: String,
    sink: BodySink,
    complete: bool,
    watch: &LimitWatch,
    pin: impl FnOnce([u8; 32]) -> ResultBodyPin,
) -> Result<FinishedOutput> {
    let (facts, sunk, pin) =
        sink.finish_pinned(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS, pin)?;
    let output = CodeRunRawOutput::from_facts(path, &facts, complete)?;
    let (body, key) = match sunk {
        SunkBody::Inline(bytes) => (StoredBody::Inline { bytes, held: false }, None),
        SunkBody::File { free_bytes, key } => {
            if let Some(free_bytes) = free_bytes {
                watch.floor(EngineLimit::CodeResultDiskFloorBytes, free_bytes);
            }
            (
                StoredBody::File {
                    len: facts.len,
                    held: false,
                },
                key,
            )
        }
    };
    Ok(FinishedOutput {
        output,
        body,
        secret: facts.secret,
        key,
        _pin: pin,
    })
}

/// `output` as an occurrence `owner` holds: one per owner and path.
pub(in crate::code_run::storage) fn owned_body(
    owner: EntityId,
    output: &CodeRunRawOutput,
    body: &StoredBody,
) -> Result<crate::provenance::body::OwnedBody> {
    use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
    let body = BodyRef {
        blake3: output.raw_blake3,
        bytes: output.raw_len,
        location: match body {
            StoredBody::Inline { .. } => BodyLocation::Inline,
            StoredBody::File { .. } => BodyLocation::File,
        },
    };
    Ok(OwnedBody {
        owner,
        occurrence: ResultOccurrence::of(Some(owner), output)?.id(),
        state: if output.complete {
            BodyState::Complete { body }
        } else {
            BodyState::Incomplete {
                retained: Some(body),
            }
        },
        result: None,
    })
}

/// Whether a raw output put publishes `body`, its owner's descriptor of the
/// bytes, over `prior`, the one that occurrence has now (FIX 7283): only
/// where the owned publisher neither refuses nor lets other bytes go. A
/// complete descriptor is final, so one naming other bytes would refuse the
/// put; an incomplete one holding bytes would release them; a prior that
/// does not read would fail it. There the put stays as it was, its row
/// holding its body on its own with no descriptor (FIX 5399b), so no raw
/// put that lands today is refused or costs another body its hold. A
/// session row an on-record route writes in base asks it too (FIX 7363).
pub(in crate::code_run::storage) fn raw_put_publishes_descriptor(
    prior: &Result<Option<crate::provenance::body::OwnedBody>>,
    body: &crate::provenance::body::OwnedBody,
) -> bool {
    use crate::provenance::body::BodyState;
    match prior {
        Ok(None) => true,
        Ok(Some(prior)) => {
            prior == body || matches!(prior.state, BodyState::Incomplete { retained: None })
        }
        Err(_) => false,
    }
}

/// The body file of `output` in the first of `dirs` that holds it, as
/// `key`, its key row in the snapshot that found its row, names it.
pub(in crate::code_run::storage) fn open_body_file(
    output: &CodeRunRawOutput,
    key: Option<&BodyKeyRow>,
    dirs: Vec<BodyDir>,
) -> Result<BodyFile> {
    for dir in dirs {
        if let Some(file) = dir.open_reader(&output.raw_blake3, output.raw_len, key)? {
            return Ok(file);
        }
    }
    Err(Error::CorruptedIndex("code-run result body file missing"))
}

/// The whole body of `output`, from its row or its file, checked against
/// its digest.
pub(in crate::code_run::storage) fn load_whole_body(
    output: &CodeRunRawOutput,
    body: StoredBody,
    key: Option<&BodyKeyRow>,
    dirs: impl FnOnce() -> Result<Vec<BodyDir>>,
) -> Result<Vec<u8>> {
    let bytes = match body {
        StoredBody::Inline { bytes, .. } => bytes,
        StoredBody::File { len, .. } => {
            if len != output.raw_len {
                return Err(drifted());
            }
            let len = usize::try_from(len)
                .map_err(|_| Error::ArithmeticOverflow("code-run result body length"))?;
            open_body_file(output, key, dirs()?)?.read_range(0, len)?
        }
    };
    if u64::try_from(bytes.len()).ok() != Some(output.raw_len)
        || *blake3::hash(&bytes).as_bytes() != output.raw_blake3
    {
        return Err(drifted());
    }
    Ok(bytes)
}

/// A range of the body whose stored row is `row`, cut at the body's end.
pub(in crate::code_run::storage) fn read_body_row_range(
    output: &CodeRunRawOutput,
    row: &[u8],
    key: Option<&BodyKeyRow>,
    offset: u64,
    len: usize,
    dirs: impl FnOnce() -> Result<Vec<BodyDir>>,
) -> Result<Vec<u8>> {
    if offset > output.raw_len {
        return Err(Error::InvalidConfig(
            "result read starts past the body's end".into(),
        ));
    }
    let end = offset.saturating_add(len as u64).min(output.raw_len);
    let take = usize::try_from(end - offset)
        .map_err(|_| Error::ArithmeticOverflow("code-run result range"))?;
    match split_row(row) {
        Some((STORED_INLINE, body)) => {
            if u64::try_from(body.len()).ok() != Some(output.raw_len) {
                return Err(drifted());
            }
            let start = usize::try_from(offset)
                .map_err(|_| Error::ArithmeticOverflow("code-run result range"))?;
            Ok(body[start..start + take].to_vec())
        }
        Some((STORED_FILE, _)) => open_body_file(output, key, dirs()?)?.read_range(offset, take),
        _ => Err(Error::CorruptedIndex("code-run raw output row")),
    }
}

/// The body file a raw `vault_meta` row names, as its digest and length:
/// `Some` only for a result body row stored as a file. A checkpoint reads
/// its rows raw, so this is how it finds the files beside them.
pub(crate) fn code_run_body_file_of_row(key: &[u8], value: &[u8]) -> Option<([u8; 32], u64)> {
    let digest = handle_digest(key)?;
    let StoredBody::File { len, .. } = StoredBody::from_raw(value).ok()? else {
        return None;
    };
    Some((digest, len))
}

/// The inline body a raw `vault_meta` row holds, as its digest and bytes:
/// `Some` only for a result body row stored inline. A checkpoint seals those
/// bytes under the body's instance and carries the row without them
/// (KS-2A).
pub(crate) fn code_run_inline_body_of_row<'v>(
    key: &[u8],
    value: &'v [u8],
) -> Option<([u8; 32], &'v [u8])> {
    let digest = handle_digest(key)?;
    match split_row(value) {
        Some((STORED_INLINE, body)) => Some((digest, body)),
        _ => None,
    }
}

/// Whether a raw result body row holds its body inline, whoever holds the
/// body.
pub(crate) fn code_run_row_inline(value: &[u8]) -> bool {
    matches!(split_row(value), Some((STORED_INLINE, _)))
}

/// Whether the result body row of `digest` holds its body on its own: a raw
/// output no descriptor holds (FIX 5399b). Another holder's release of the
/// same bytes neither queues nor collects it. `false` with no row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn code_run_body_held_in_txn(
    dbs: &impl side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<bool> {
    Ok(RAW_OUTPUTS
        .get_borrowed(dbs, txn, &body_handle(digest))?
        .is_some_and(|row| row_held(&row)))
}

/// An erase's lift of the hold the result body row of `digest` keeps on
/// its file, in the erase's transaction: no hold of its own outlasts an
/// erase, so the file is queued for the collector, which takes it with its
/// row and key row (FIX 5399b). An unheld row, and an inline one, which
/// goes with the erase whole as before, are left as they are.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn lift_code_run_file_hold_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let handle = body_handle(digest);
    let Some(StoredBody::File { len, held: true }) = RAW_OUTPUTS.get(dbs, wtxn, &handle)? else {
        return Ok(());
    };
    RAW_OUTPUTS.put(dbs, wtxn, &handle, &StoredBody::File { len, held: false })?;
    crate::provenance::body::queue_pruned_file_in_txn(dbs, wtxn, digest)
}

/// The raw `vault_meta` key of the result body row of `digest`.
pub(crate) fn code_run_body_row_key(digest: &[u8; 32]) -> Vec<u8> {
    RAW_OUTPUTS.key_bytes(&body_handle(digest))
}

/// The content handle the result body row of `digest` is keyed by.
fn body_handle(digest: &[u8; 32]) -> String {
    CodeRunRawOutput::of_ref(crate::compaction::output::OutputRef {
        hash: *digest,
        byte_len: 0,
    })
    .handle
}

/// The digest a raw result body row's key names by its handle.
fn handle_digest(key: &[u8]) -> Option<[u8; 32]> {
    let handle = key.strip_prefix(RAW_OUTPUTS.decl().prefix)?;
    let hex =
        handle.strip_prefix(crate::code_run::support::CODE_RUN_OUTPUT_HANDLE_PREFIX.as_bytes())?;
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (hex.len() == 64).then_some(digest)
}

/// What [`drifted`] says.
const DRIFTED: &str = "stored raw output bytes drifted from metadata";

fn drifted() -> Error {
    invalid_code_run_replay(DRIFTED)
}

/// Whether `error` says a stored body's bytes drifted from their length or
/// digest ([`drifted`]), not that reading them failed (FIX 4194).
pub(in crate::code_run::storage) fn body_drifted(error: &Error) -> bool {
    matches!(
        error,
        Error::Artifact(crate::error::ArtifactError::InvalidCodeArtifactBody(message))
            if *message == DRIFTED
    )
}

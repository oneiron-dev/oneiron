//! A finished result body and the owned descriptor of one occurrence of it
//! (moved out of the result body module whole).

use super::{
    BodySink, CodeRunRawOutput, EngineLimit, EntityId, LimitWatch, Result, ResultOccurrence,
    StagedBodyKey, StoredBody, SunkBody, validate_raw_output,
};
use crate::result_body::ResultBodyPin;

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
    finish_output_sourced(path, sink, complete, None, watch, pin)
}

/// [`finish_output`] with the occurrence's complete input rows, or `None`
/// when any constituent is unknown (FIX 7104).
pub(in crate::code_run::storage) fn finish_output_sourced(
    path: String,
    sink: BodySink,
    complete: bool,
    input_rows: Option<Vec<EntityId>>,
    watch: &LimitWatch,
    pin: impl FnOnce([u8; 32]) -> ResultBodyPin,
) -> Result<FinishedOutput> {
    let (facts, sunk, pin) =
        sink.finish_pinned(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS, pin)?;
    let mut output = CodeRunRawOutput::from_facts(path, &facts, complete)?;
    output.input_rows = input_rows;
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

/// `output` as an occurrence `owner` holds: one per owner and path, which
/// it names as its code-run output origin (FIX 7365).
pub(in crate::code_run::storage) fn owned_body(
    owner: EntityId,
    output: &CodeRunRawOutput,
    body: &StoredBody,
) -> Result<crate::provenance::body::OwnedBody> {
    use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
    use crate::store::body_descriptor::CodeRunOutputOrigin;
    let body = BodyRef {
        blake3: output.raw_blake3,
        bytes: output.raw_len,
        location: match body {
            StoredBody::Inline { .. } => BodyLocation::Inline,
            StoredBody::File { .. } => BodyLocation::File,
        },
    };
    let occurrence = ResultOccurrence::of(Some(owner), output)?.id();
    Ok(OwnedBody {
        owner,
        occurrence,
        mark_occurrence: occurrence,
        state: if output.complete {
            BodyState::Complete { body }
        } else {
            BodyState::Incomplete {
                retained: Some(body),
            }
        },
        result: None,
        code_run_output: Some(CodeRunOutputOrigin {
            path: output.path.clone(),
        }),
    })
}

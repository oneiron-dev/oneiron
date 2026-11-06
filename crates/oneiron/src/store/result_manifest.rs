//! Result-body manifests, occurrence identifiers and their format bounds.

use crate::error::ArtifactError;
use crate::{EntityId, Error, Result};

pub const CODE_RUN_REPLAY_HASH_LEN: usize = 32;
pub(crate) const CODE_RUN_OUTPUT_HANDLE_PREFIX: &str = "code-run-output:blake3:";
pub(crate) const CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES: usize = 1024;

/// The preview text of a body withheld without a specific reason.
pub(crate) const CODE_RUN_OUTPUT_PREVIEW_WITHHELD: &str = "[preview withheld]";

/// Compact preview stored in a replay record beside a raw output handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunOutputPreview {
    pub codec: String,
    pub text: String,
    pub truncated: bool,
}

/// What a result body holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRunOutputKind {
    /// The whole body is UTF-8.
    Text,
    /// Anything else, kept byte for byte.
    Binary,
}

impl CodeRunOutputKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "binary" => Some(Self::Binary),
            _ => None,
        }
    }
}

/// One result occurrence's manifest (OF-597): what the body is, measured
/// as it was written. The body is stored once by its content handle, inline
/// in LMDB or as a file beside `data.mdb`; authority stays with the
/// occurrence, here, never with the shared bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunRawOutput {
    pub handle: String,
    pub path: String,
    pub raw_blake3: [u8; CODE_RUN_REPLAY_HASH_LEN],
    pub raw_len: u64,
    pub kind: CodeRunOutputKind,
    /// Lines in a text body: its newlines, plus one for an unterminated last
    /// line.
    pub lines: u64,
    /// Whether the producer finished the body. An incomplete one is kept as
    /// far as it got, and says so; it never reads as a success.
    pub complete: bool,
    /// Every row this occurrence's bytes were produced from; `None` when
    /// any constituent is unknown (FIX 7104).
    pub input_rows: Option<Vec<EntityId>>,
    pub preview: CodeRunOutputPreview,
}

impl CodeRunRawOutput {
    /// The manifest of a complete body held whole in memory.
    pub fn from_bytes(path: impl Into<String>, raw: &[u8]) -> Result<Self> {
        let mut meter = crate::store::BodyMeter::new();
        meter.feed(raw);
        Self::from_facts(
            path,
            &meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS),
            true,
        )
    }

    /// The manifest of a body measured as it streamed.
    pub(crate) fn from_facts(
        path: impl Into<String>,
        facts: &crate::store::BodyFacts,
        complete: bool,
    ) -> Result<Self> {
        let path = path.into();
        validate_text(
            &path,
            CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
            "raw output path",
        )?;
        Ok(Self {
            handle: format!(
                "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
                crate::entity_id::bytes_to_hex_lower(&facts.digest)
            ),
            path,
            raw_blake3: facts.digest,
            raw_len: facts.len,
            kind: if facts.text {
                CodeRunOutputKind::Text
            } else {
                CodeRunOutputKind::Binary
            },
            lines: facts.lines,
            complete,
            input_rows: None,
            // A body the secret scan marked shows no preview: the view is
            // redacted, the stored body never rewritten.
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text: match facts.secret {
                    Some(_) => CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned(),
                    None => facts.preview.clone(),
                },
                truncated: facts.preview_truncated || facts.secret.is_some(),
            },
        })
    }

    /// The manifest a context reference names, for reading its body by
    /// digest and length; it carries no occurrence facts.
    pub(crate) fn of_ref(source: crate::compaction::output::OutputRef) -> Self {
        Self {
            handle: format!(
                "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
                crate::entity_id::bytes_to_hex_lower(&source.hash)
            ),
            path: String::new(),
            raw_blake3: source.hash,
            raw_len: source.byte_len,
            kind: CodeRunOutputKind::Binary,
            lines: 0,
            complete: true,
            input_rows: None,
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text: String::new(),
                truncated: false,
            },
        }
    }

    /// The model-context reference of this body: its digest and length.
    #[must_use]
    pub fn output_ref(&self) -> crate::compaction::output::OutputRef {
        crate::compaction::output::OutputRef {
            hash: self.raw_blake3,
            byte_len: self.raw_len,
        }
    }
}

/// One result occurrence (Docs Q08): what a result's taint and secret mark
/// bind, as its authority does, never the bytes it shares with another. An
/// owned output's occurrence is its owner and path, the id its body
/// descriptor carries; an unowned body (a context output) has no occurrence
/// beyond its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultOccurrence(EntityId);

impl ResultOccurrence {
    /// The occurrence of `output` that `owner` holds, or of its bytes alone
    /// when it has no owner. The one derivation of an occurrence id.
    pub fn of(owner: Option<EntityId>, output: &CodeRunRawOutput) -> Result<Self> {
        match owner {
            Some(owner) => Self::owned(owner, &output.path),
            None => Ok(Self(EntityId::derive(
                b"oneiron:code-run-output-unowned:v1",
                &[output.raw_blake3.as_slice()],
            )?)),
        }
    }

    /// The occurrence run `owner` holds at `path`.
    pub fn owned(owner: EntityId, path: &str) -> Result<Self> {
        Ok(Self(EntityId::derive(
            b"oneiron:code-run-output-occurrence:v1",
            &[owner.as_bytes().as_slice(), path.as_bytes()],
        )?))
    }

    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.0
    }

    /// The key of this occurrence's taint and secret rows: the handle of
    /// its body, so a read naming the bytes alone and the body's collector
    /// find every occurrence of them together, then the occurrence.
    pub(crate) fn mark_key(&self, handle: &str) -> String {
        format!("{}{}", Self::marks_prefix(handle), self.0.to_hex())
    }

    /// The key prefix the marks of every occurrence of `handle`'s body
    /// share.
    pub(crate) fn marks_prefix(handle: &str) -> String {
        format!("{handle}/")
    }

    /// The body handle and the occurrence a mark row's key names.
    pub(crate) fn parse_mark_key(key: &str) -> Result<(&str, Self)> {
        let (handle, occurrence) = key
            .rsplit_once('/')
            .ok_or(Error::CorruptedIndex("code-run result mark key"))?;
        Ok((handle, Self(EntityId::from_hex(occurrence)?)))
    }
}

pub(crate) fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid_code_run_replay(field));
    }
    Ok(())
}

pub(crate) fn invalid_code_run_replay(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(message))
}

/// What result bodies staged inside one write transaction spill into,
/// prepared before it opened ([`Vault::staged_result_sinks`]).
#[derive(Clone)]
pub(crate) struct StagedSinks {
    pub(crate) mint: crate::store::BodyMint,
}

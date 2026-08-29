//! Local transcription — opt-in, feature `asr-mlx`, and explicitly NOT
//! MIN-SPEC.
//!
//! An Intel build ships without this module compiled in at all, which is why
//! the deliverable is the seam rather than one model: [`SegmentTranscriber`]
//! is what the recorder knows about, and the shipped implementation shells out
//! to the external transcription tool. No inference crate enters this tree.
//!
//! Transcripts land at the **Imported** trust tier. A machine transcript is a
//! reading of the audio, not the speaker's own statement, and the vault's
//! trust lattice must be told that plainly or every downstream consumer
//! inherits an authority nobody granted.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault,
};
use rmpv::Value;

/// What a transcript claim says about a segment.
///
/// The engine has no `voice.transcript` family: it is a generic claim, checked
/// by the ordinary predicate grammar only. When transcription stops being
/// opt-in it should get a family module beside `voice_segment`, so the shape
/// below is validated at the door rather than only here.
pub const PREDICATE_VOICE_TRANSCRIPT: &str = "voice.transcript";

/// Value key carrying the transcript text.
const KEY_TEXT: &str = "text";
/// Value key naming what produced it.
const KEY_ENGINE: &str = "engine";

/// What one transcription produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptOutcome {
    /// The transcript, as the tool emitted it.
    pub text: String,
    /// What produced it, recorded so a transcript is never anonymous.
    pub engine: String,
}

/// Everything that can stop a transcription.
#[derive(Debug)]
pub enum AsrError {
    /// The segment has no audio in the vault.
    MissingSegment,
    /// The tool could not be run, or its scratch file could not be written.
    Io(std::io::Error),
    /// The tool ran and failed.
    Tool {
        /// Exit status, when there was one.
        status: Option<i32>,
        /// What it printed on stderr.
        stderr: String,
    },
    /// The vault refused the transcript claim.
    Vault(oneiron::Error),
}

impl fmt::Display for AsrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSegment => f.write_str("the segment has no audio to transcribe"),
            Self::Io(err) => write!(f, "could not run the transcription tool: {err}"),
            Self::Tool { status, stderr } => match status {
                Some(code) => write!(f, "the transcription tool exited {code}: {stderr}"),
                None => write!(f, "the transcription tool was terminated: {stderr}"),
            },
            Self::Vault(err) => write!(f, "the vault refused the transcript: {err}"),
        }
    }
}

impl std::error::Error for AsrError {}

impl From<std::io::Error> for AsrError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<oneiron::Error> for AsrError {
    fn from(err: oneiron::Error) -> Self {
        Self::Vault(err)
    }
}

/// Transcription result.
pub type Result<T> = std::result::Result<T, AsrError>;

/// Turns a committed segment into a transcript.
pub trait SegmentTranscriber: Send + Sync {
    /// Transcribes the audio stored under `segment`.
    ///
    /// # Errors
    ///
    /// Whatever stopped the transcription.
    fn transcribe(&self, segment: &EntityId) -> Result<TranscriptOutcome>;
}

/// Runs the external transcription tool over one segment.
///
/// The tool reads a file, so the segment's bytes are written to a scratch
/// path, handed over, and removed again — the vault stays the only durable
/// home for captured audio.
pub struct ExternalTranscriber {
    vault: Arc<Vault>,
    program: PathBuf,
    scratch: PathBuf,
}

impl ExternalTranscriber {
    /// A transcriber that runs `program` and stages audio under `scratch`.
    #[must_use]
    pub fn new(vault: Arc<Vault>, program: PathBuf, scratch: PathBuf) -> Self {
        Self {
            vault,
            program,
            scratch,
        }
    }

    fn engine_name(&self) -> String {
        self.program.file_name().map_or_else(
            || "transcribe".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        )
    }
}

impl SegmentTranscriber for ExternalTranscriber {
    fn transcribe(&self, segment: &EntityId) -> Result<TranscriptOutcome> {
        let audio = self.vault.get(segment)?.ok_or(AsrError::MissingSegment)?;
        std::fs::create_dir_all(&self.scratch)?;
        let staged = self.scratch.join(format!("{}.wav", segment.to_hex()));
        std::fs::write(&staged, &audio)?;

        let outcome = run_tool(&self.program, &staged);
        // The scratch copy goes whether the tool worked or not.
        let _ = std::fs::remove_file(&staged);

        Ok(TranscriptOutcome {
            text: outcome?,
            engine: self.engine_name(),
        })
    }
}

fn run_tool(program: &Path, audio: &Path) -> Result<String> {
    let output = Command::new(program).arg(audio).output()?;
    if !output.status.success() {
        return Err(AsrError::Tool {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Lands `outcome` as a claim about `segment`, at the Imported trust tier.
///
/// # Errors
///
/// Whatever the vault refused the claim with.
pub fn land_transcript(
    vault: &Vault,
    segment: EntityId,
    outcome: &TranscriptOutcome,
    span: TimeRange,
) -> Result<EntityId> {
    let mut body = ClaimBody::new(
        PREDICATE_VOICE_TRANSCRIPT,
        ClaimSubject::Entity(segment),
        Value::Map(vec![
            (Value::from(KEY_TEXT), Value::from(outcome.text.as_str())),
            (
                Value::from(KEY_ENGINE),
                Value::from(outcome.engine.as_str()),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    // A machine reading of audio is imported evidence, never a first-person
    // statement — the lattice bottom is the honest tier.
    body.source = Some(ClaimSource::Imported);

    let learned_at = span.start;
    let claim = EntityId::now();
    vault.put_claim(&claim, &body, span, learned_at)?;
    Ok(claim)
}

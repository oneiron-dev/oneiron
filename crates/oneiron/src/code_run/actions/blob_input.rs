//! An action's verb input whose one base64 member its host holds as a file
//! (FIX 22096, Engine ruling E4 = C on FIX 22074). A host that decoded a
//! large `content_base64` into a file hands the action the input with that
//! member empty, and the file beside it. The action measures, seeds and
//! records the input as the whole one, and its verb's door carries the file
//! on to the row, which reads it there (FIX 22074 PR 3); nothing on the way
//! holds the string.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};

use super::{ActionVerbDefinition, MAX_ACTION_JSON_BYTES, invalid};
use crate::task_verb::sdk::AgentVerb;
use crate::{Error, Result};

/// The member a held input's file stands for.
pub const HELD_MEMBER: &str = "content_base64";

/// One action input whose [`HELD_MEMBER`] its host holds as the file of the
/// bytes the member's string encodes in standard base64. Runtime only: it
/// is never serialized, and no caller's JSON names it.
#[derive(Clone)]
pub struct ActionBlobInput(Arc<Held>);

struct Held {
    verb: AgentVerb,
    /// The input with the member's string empty.
    head: Value,
    file: File,
    /// The bytes of the input as one compact JSON text, in its own member
    /// order: what the action's size cap and seed read.
    original_len: u64,
    /// BLAKE3 of that text: the input a replay record keeps a digest of.
    original_digest: [u8; 32],
    /// [`crate::receipt::call_json_digest`] of the whole input: the digest a
    /// call receipt states, and the input's identity a record keeps.
    receipt_digest: String,
}

impl std::fmt::Debug for ActionBlobInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionBlobInput")
            .field("verb", &self.0.verb)
            .field("original_len", &self.0.original_len)
            .field("receipt_digest", &self.0.receipt_digest)
            .finish_non_exhaustive()
    }
}

impl ActionBlobInput {
    /// `head`, the input of `verb` with its [`HELD_MEMBER`] string empty,
    /// and `file`, the bytes that string encodes. Only
    /// `vault.artifacts.create` takes one.
    ///
    /// # Errors
    ///
    /// Another verb, a head that is not one object with the member empty,
    /// a whole input past [`MAX_ACTION_JSON_BYTES`], and the file's read
    /// errors.
    pub fn new(verb: AgentVerb, head: Value, file: File) -> Result<Self> {
        if verb != AgentVerb::VaultArtifactsCreate {
            return Err(invalid("this verb takes no held input"));
        }
        let Some(members) = head.as_object() else {
            return Err(invalid("a held input is one object"));
        };
        if members.get(HELD_MEMBER) != Some(&Value::String(String::new())) {
            return Err(invalid("a held input's member is empty in its head"));
        }
        let mut held = Held {
            verb,
            head,
            file,
            original_len: 0,
            original_digest: [0; 32],
            receipt_digest: String::new(),
        };
        let mut original = Counted::new(blake3::Hasher::new());
        held.write_original(&mut original)?;
        if original.len > MAX_ACTION_JSON_BYTES as u64 {
            return Err(invalid("action JSON argument is too large"));
        }
        held.original_len = original.len;
        held.original_digest = *original.out.finalize().as_bytes();
        let Some(members) = held.head.as_object() else {
            return Err(invalid("a held input is one object"));
        };
        let file = &held.file;
        held.receipt_digest =
            crate::receipt::call_json_digest_with_member(members, HELD_MEMBER, |hasher| {
                write_member_json(file, hasher)
            })?;
        held.file.seek(SeekFrom::Start(0))?;
        Ok(Self(Arc::new(held)))
    }

    #[must_use]
    pub fn verb(&self) -> AgentVerb {
        self.0.verb
    }

    /// The input with the held member's string empty.
    #[must_use]
    pub fn head(&self) -> &Value {
        &self.0.head
    }

    /// The file of the held member's bytes. Its readers seek it first: its
    /// handles share one offset.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.0.file
    }

    /// The whole input's compact JSON length, in bytes.
    #[must_use]
    pub fn original_len(&self) -> u64 {
        self.0.original_len
    }

    /// The digest a call receipt states for the whole input.
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.0.receipt_digest
    }

    /// Writes the held member's value as JSON text, quotes and all: the
    /// file's bytes in standard base64, the string the caller sent.
    ///
    /// # Errors
    ///
    /// The file's read errors and `out`'s write errors.
    pub fn write_member_json(&self, out: &mut dyn Write) -> io::Result<()> {
        write_member_json(&self.0.file, out)
    }

    /// Whether `verb` and `input` are the call this input was held for.
    #[must_use]
    pub fn holds(&self, verb: AgentVerb, input: &Value) -> bool {
        self.0.verb == verb && &self.0.head == input
    }

    /// The seed of an action of `definition` whose one argument is this
    /// input: BLAKE3 of the bytes `serde_json` writes for the definition and
    /// the argument list, as [`super::execution`] seeds an action whose
    /// input it holds whole.
    ///
    /// # Errors
    ///
    /// The definition's encoding and the file's read errors.
    pub(super) fn action_seed(&self, definition: &ActionVerbDefinition) -> Result<[u8; 32]> {
        let mut seed = Counted::new(blake3::Hasher::new());
        seed.write_all(b"[")?;
        serde_json::to_writer(&mut seed, definition).map_err(|_| invalid("action encoding"))?;
        seed.write_all(br#",[{"kind":"json","value":"#)?;
        self.0.write_original(&mut seed)?;
        seed.write_all(b"}]]")?;
        Ok(*seed.out.finalize().as_bytes())
    }

    /// The request a replay record keeps for this input's call: the verb,
    /// no input text, the whole input's compact JSON digest and its receipt
    /// identity. Host fields only; a caller's JSON never makes this shape.
    #[must_use]
    pub(crate) fn request_value(&self) -> rmpv::Value {
        digest_request(
            self.0.verb.as_str(),
            &self.0.original_digest,
            &self.0.receipt_digest,
        )
    }
}

/// The digest-only request a replay record keeps for a held input's call.
fn digest_request(verb: &str, original_digest: &[u8; 32], receipt_digest: &str) -> rmpv::Value {
    let identity = blake3::Hash::from_hex(receipt_digest)
        .map_or_else(|_| Vec::new(), |hash| hash.as_bytes().to_vec());
    rmpv::Value::Map(vec![
        (rmpv::Value::from("verb"), rmpv::Value::from(verb)),
        (rmpv::Value::from("input"), rmpv::Value::from("")),
        (
            rmpv::Value::from("input_digest"),
            rmpv::Value::Binary(original_digest.to_vec()),
        ),
        (
            rmpv::Value::from("input_identity"),
            rmpv::Value::Binary(identity),
        ),
    ])
}

/// A recorded or offered request of a verb that takes a held input, in the
/// digest-only shape: itself when it is one, else the digests of the whole
/// input text it carries (FIX 22096). The same call meets its row whether
/// its host held the input as a file or sent it whole. `None` for any other
/// request.
#[must_use]
pub(crate) fn held_request_form(request: &rmpv::Value) -> Option<rmpv::Value> {
    let rmpv::Value::Map(fields) = request else {
        return None;
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let verb = field("verb")?.as_str()?;
    if verb != AgentVerb::VaultArtifactsCreate.as_str() {
        return None;
    }
    let input = field("input")?.as_str()?;
    if input.is_empty() {
        return field("input_digest").is_some().then(|| request.clone());
    }
    let value: Value = serde_json::from_str(input).ok()?;
    Some(digest_request(
        verb,
        blake3::hash(input.as_bytes()).as_bytes(),
        &crate::receipt::call_json_digest(&value),
    ))
}

impl Held {
    /// Writes the whole input as `serde_json` writes it compact: the head's
    /// members in their order, the held member's string from the file.
    fn write_original(&self, out: &mut dyn Write) -> Result<()> {
        let Some(members) = self.head.as_object() else {
            return Err(invalid("a held input is one object"));
        };
        write_object(members, &self.file, out)
    }
}

fn write_object(members: &Map<String, Value>, file: &File, out: &mut dyn Write) -> Result<()> {
    out.write_all(b"{")?;
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        serde_json::to_writer(&mut *out, name).map_err(json_write)?;
        out.write_all(b":")?;
        if name == HELD_MEMBER {
            write_member_json(file, out)?;
        } else {
            serde_json::to_writer(&mut *out, value).map_err(json_write)?;
        }
    }
    out.write_all(b"}")?;
    Ok(())
}

/// Writes `file`'s bytes as a JSON string of their standard base64.
fn write_member_json(file: &File, out: &mut dyn Write) -> io::Result<()> {
    let mut source = file.try_clone()?;
    source.seek(SeekFrom::Start(0))?;
    out.write_all(b"\"")?;
    let mut encoder = base64::write::EncoderWriter::new(&mut *out, &STANDARD);
    io::copy(&mut source, &mut encoder)?;
    encoder.finish()?;
    drop(encoder);
    out.write_all(b"\"")
}

fn json_write(error: serde_json::Error) -> Error {
    Error::from(io::Error::other(error))
}

/// A writer that counts what it passes on.
struct Counted<W> {
    out: W,
    len: u64,
}

impl<W> Counted<W> {
    const fn new(out: W) -> Self {
        Self { out, len: 0 }
    }
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.out.write(bytes)?;
        self.len += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

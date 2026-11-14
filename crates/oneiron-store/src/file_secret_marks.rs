//! Value-free file-mask paths, read visibility, and byte-span transformations.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

use oneiron_contracts::error::{Error, GateError, Result, SecretError};

use crate::batch::secret_scan::mask::wipe::wipe_value;

/// The byte a key's span reads as in a masked copy. A run of it is the
/// door's own mask shape (`********`), never secret material.
pub const FILLER: u8 = b'*';

/// One step from a container into a member it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStep {
    /// A ZIP entry, by its place in the central directory.
    Zip { entry: u32 },
    /// A gzip file's payload: every member it chains, read as one.
    Gzip,
    /// A tar entry, by its place in archive order (FIX 2471).
    Tar { entry: u32 },
    /// An xz file's decompressed payload (FIX 2471).
    Xz,
    /// A 7z entry with data, by its place in the archive's file list (FIX
    /// 11575).
    SevenZip { entry: u32 },
    /// A PDF stream other than an object stream, by its object's id (FIX
    /// 11550): a page content stream and the like.
    PdfStream { object: u32, generation: u16 },
    /// A PDF object stream's decoded bytes, by its object's id (FIX 11550):
    /// its header names each object by byte offset.
    PdfObjectStream { object: u32, generation: u16 },
    /// A PDF object's text strings, each decoded, in the object's order
    /// (FIX 2469), by the object's id.
    PdfStrings { object: u32, generation: u16 },
}

/// Where a file's keys sit, without their records: one entry per place, the
/// stored bytes' own (an empty path) and each member's, with its spans.
pub type KeyPlaces = Vec<(Vec<MemberStep>, Vec<(u64, u64)>)>;

/// The handle text each key in [`KeyPlaces`] stands as in a text member of a
/// masked copy (FIX 7944), place for place and span for span; `None` where
/// custody names no handle, and the filler stands in.
pub type PlaceHandles = Vec<Vec<Option<String>>>;

/// How a serving door hands a file's bytes to its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSight {
    /// The vault owner, verified at the door, and the owner's own export:
    /// the stored bytes.
    Owner,
    /// Every other reader (an agent, a contact, a link): each key's span
    /// overwritten, in the file or in the member that holds it.
    Masked,
    /// An agent whose standing or approve-once grant covers the file's keys,
    /// with the read's receipt already written: the stored bytes.
    Granted,
}

/// `bytes` with each span in `spans` overwritten by the filler.
pub fn filled(bytes: &[u8], spans: impl IntoIterator<Item = (u64, u64)>) -> Result<Vec<u8>> {
    let mut copy = bytes.to_vec();
    for (start, end) in spans {
        usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| copy.get_mut(start..end))
            .ok_or(Error::CorruptedIndex("masked file key span"))?
            .fill(FILLER);
    }
    Ok(copy)
}

/// `bytes` with each span in `spans` replaced by its handle text, or by the
/// filler at the span's length where it has none (FIX 7944): a key in a text
/// member reads as the handle custody holds it under. `spans` in byte
/// order; one that overlaps the span before it replaces what is left of it.
pub fn filled_with(bytes: &[u8], spans: &[((u64, u64), Option<&str>)]) -> Result<Vec<u8>> {
    let mut copy = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for &((start, end), handle) in spans {
        let (start, end) = usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .filter(|&(start, end)| start <= end && end <= bytes.len())
            .ok_or(Error::CorruptedIndex("masked file key span"))?;
        let start = start.max(at);
        if end <= start {
            continue;
        }
        copy.extend_from_slice(&bytes[at..start]);
        match handle {
            Some(text) => copy.extend_from_slice(text.as_bytes()),
            None => copy.resize(copy.len() + (end - start), FILLER),
        }
        at = end;
    }
    copy.extend_from_slice(&bytes[at..]);
    Ok(copy)
}

/// A serving door's refusal of a file it cannot serve masked (FIX 2475):
/// `reason` is the scan's code (a hit, or why the walk read no further).
pub fn masked_copy_withheld(reason: &'static str) -> Error {
    Error::Secret(SecretError::MaskedCopyWithheld { reason })
}

/// One key: its byte span in the stored file, or in the decoded member that
/// holds it, and the custody record that holds its value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeySpan {
    pub start: u64,
    pub end: u64,
    pub custody: EntityId,
    /// The scan's reason code: the key's kind.
    pub reason: String,
}

/// The text form a mask leaves in a span, `[secret sc12]`, before the
/// handle. The claim-restore proof recomputes the restored body with it
/// (FIX 11882).
pub const HANDLE_TEXT_OPEN: &str = "[secret ";

/// How a custody record holds the value a found key stands for, and how the
/// record wrote it, so a restore puts back the value as it was written (FIX
/// SEALED-VALUE-RESTORE-KEEPS-ENCODED-TEXT).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldForm {
    /// The value's own bytes: a text or a byte string, or a span of one.
    #[default]
    Raw,
    /// The MessagePack encoding of a whole value that is neither text nor
    /// bytes: a credential field's array, map or number the mask sealed,
    /// a value sealed whole out of a MessagePack body or a claim, or a
    /// whole message part kept sealed.
    Encoded,
    /// The JSON text of a whole value that is neither text nor bytes,
    /// sealed whole out of a JSON body: custody holds it as the body wrote
    /// it, so a revealed value reads as JSON (FIX SEAL-WHOLE-VALUE-HELD-RAW).
    Json,
    /// A recovery phrase, its words one space apart, that the record wrote
    /// one word per string item of an array: the handle stands for that
    /// array whole. Custody holds the phrase, so a later write of it is
    /// known (FIX SEALED-PHRASE-ARRAY-RESTORE-AS-TEXT).
    PhraseWords,
    /// A recovery phrase, its words one space apart, that the record wrote
    /// one word per string item of a run of an array's items: the handle is
    /// one item that stands for that run.
    PhraseWordRun,
    /// A recovery phrase, its words one space apart, that the record wrote
    /// as an array of its byte values: the handle stands for that array
    /// whole.
    PhraseByteValues,
}

impl HeldForm {
    /// Whether the key records no more than the value's own bytes: a
    /// restore puts them back as a text or a byte string.
    #[must_use]
    pub const fn is_raw(&self) -> bool {
        matches!(self, Self::Raw)
    }
}

/// [`unmasked_body`] over one decoded value: whether anything changed. The
/// claim-restore proof recomputes a restored claim body with it (FIX 11882).
/// `held` says how custody holds `value`: a handle standing for a whole
/// encoded value takes back that value, not its encoding, and a handle item
/// standing for a run of a phrase's word items takes back those items.
pub fn unmask_value(
    tree: &mut Value,
    handle: &str,
    text_form: &str,
    value: &[u8],
    held: HeldForm,
) -> Result<bool> {
    let restored = match &*tree {
        Value::String(text) => match text.as_str() {
            Some(text) => unmasked_text(text, handle, text_form, value, held)?,
            None => None,
        },
        Value::Binary(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => unmasked_text(text, handle, text_form, value, held)?,
            Err(_) => None,
        },
        _ => None,
    };
    if let Some(restored) = restored {
        *tree = restored;
        return Ok(true);
    }
    let mut changed = false;
    match tree {
        Value::Array(items) => {
            if held == HeldForm::PhraseWordRun && items.iter().any(|item| is_handle(item, handle)) {
                let mut words = phrase_items(value, held)?.unwrap_or_default();
                let mut spliced = Vec::with_capacity(items.len() + words.len());
                for item in std::mem::take(items) {
                    if is_handle(&item, handle) {
                        spliced.extend(words.iter().cloned());
                    } else {
                        spliced.push(item);
                    }
                }
                words.iter_mut().for_each(wipe_value);
                *items = spliced;
                changed = true;
            }
            for item in items {
                changed |= unmask_value(item, handle, text_form, value, held)?;
            }
        }
        Value::Map(fields) => {
            for (key, member) in fields.iter_mut() {
                changed |= unmask_value(key, handle, text_form, value, held)?;
                changed |= unmask_value(member, handle, text_form, value, held)?;
            }
        }
        _ => {}
    }
    Ok(changed)
}

/// Whether `item` is the string `handle` whole.
fn is_handle(item: &Value, handle: &str) -> bool {
    item.as_str() == Some(handle)
}

/// The items `phrase`, a recovery phrase custody holds as `held`, was
/// written as: its words, one string each, or its byte values; `None` for a
/// form that writes no phrase over an array's items. The mask records such
/// a form only when these items are the ones it replaced.
pub fn phrase_items(phrase: &[u8], held: HeldForm) -> Result<Option<Vec<Value>>> {
    Ok(match held {
        HeldForm::PhraseWords | HeldForm::PhraseWordRun => {
            Some(as_text(phrase)?.split(' ').map(Value::from).collect())
        }
        HeldForm::PhraseByteValues => Some(phrase.iter().copied().map(Value::from).collect()),
        HeldForm::Raw | HeldForm::Encoded | HeldForm::Json => None,
    })
}

/// One string of a body with the value back: the whole of it when it is the
/// handle a credential field, a value sealed whole or a phrase's array keeps
/// (the decoded value when custody holds its encoding or its JSON text, the
/// array's items for a phrase), each span's text form within it otherwise.
fn unmasked_text(
    text: &str,
    handle: &str,
    text_form: &str,
    value: &[u8],
    held: HeldForm,
) -> Result<Option<Value>> {
    if text == handle {
        return Ok(Some(match held {
            HeldForm::Encoded => decoded_whole(value)?,
            HeldForm::Json => json_whole(value)?,
            HeldForm::PhraseWords | HeldForm::PhraseByteValues => {
                Value::Array(phrase_items(value, held)?.unwrap_or_default())
            }
            // A run's handle is an item of its array, which `unmask_value`
            // splices; anywhere else it takes the phrase back as text.
            HeldForm::Raw | HeldForm::PhraseWordRun => match std::str::from_utf8(value) {
                Ok(value) => Value::from(value),
                Err(_) => Value::Binary(value.to_vec()),
            },
        }));
    }
    if text.contains(text_form) {
        return Ok(Some(Value::from(text.replace(text_form, as_text(value)?))));
    }
    Ok(None)
}

/// The one whole value `encoded` holds, as the mask encoded a credential
/// field's value that is neither text nor bytes.
fn decoded_whole(encoded: &[u8]) -> Result<Value> {
    let mut cursor = std::io::Cursor::new(encoded);
    match rmpv::decode::read_value(&mut cursor) {
        Ok(value) if cursor.position() == encoded.len() as u64 => Ok(value),
        _ => Err(Error::InvariantViolation(
            "a sealed value's encoding is not one whole value",
        )),
    }
}

/// The one whole value `json` holds, as the seal held a value it sealed
/// whole out of a JSON body.
fn json_whole(json: &[u8]) -> Result<Value> {
    serde_json::from_slice(json)
        .map_err(|_| Error::InvariantViolation("a sealed value's JSON text is not one whole value"))
}

pub fn as_text(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value).map_err(|_| {
        Error::Gate(GateError::InvalidConsentBound(
            "the key is not text, so it cannot go back into the record's text",
        ))
    })
}

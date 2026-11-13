//! `vault.files.sources.ask` (ARCH-0027 #files-world: "The owner can ask
//! about a file and get an answer with citations"): the engine's half of the
//! owner's cited answers over the Files world. It holds the input and the
//! answer, reads the files a question is asked of and their text, words the
//! request, and checks every citation the answer gives in fixed code: a
//! citation names a file the model was given, and its quote is an exact run
//! of that file's text at the revision it was read at. An answer with no
//! citation that holds is never given. The model call is the server's, on
//! its house chat role.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::files::files_file_view;
use super::files_search::{
    DEFAULT_FILES_SEARCH_LIMIT, FilesSearchHit, FilesSourceSearchAnswer, FilesSourceSearchRequest,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::note::{FileHandle, FileReadiness, FolderFileState, FolderSourceFile};

/// `vault.files.sources.ask`'s input: a question, asked of one named file
/// or of the files a search for it finds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceAskRequest {
    /// The question, in the owner's words. With no `file`, it is also the
    /// search that picks the files the answer reads.
    pub query: String,
    /// The one file to ask about; the search picks the files when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileHandle>,
    /// The Files sources the search covers; every one when absent. Not
    /// taken beside `file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<EntityId>>,
}

/// How many files with text one answer reads at most: the search's first.
pub const FILES_ASK_FILES: usize = 5;

/// How many characters of one file's text an answer reads at most, from
/// its start. A quote is checked against what was read.
pub const FILES_ASK_FILE_CHARS: usize = 12_000;

/// One file an answer read, numbered as its request numbered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesAskedFile {
    /// Its number in the request: `[n]` in the answer, 1 first.
    pub source: u32,
    pub handle: FileHandle,
    /// The revision its text was read at.
    pub revision: String,
    /// The note its text landed as.
    pub note: EntityId,
}

/// One citation of an answer, checked: `quote` is an exact run of the text
/// of file `source` at `revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileCitation {
    /// The `[n]` the answer cites it by.
    pub source: u32,
    pub handle: FileHandle,
    pub revision: String,
    pub quote: String,
}

/// Why an ask gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilesNoCitedAnswer {
    /// No file the question was asked of has text to read: no model was
    /// asked.
    NoTextFile,
    /// The model's answer gave no citation that holds, or cited a file by a
    /// number no citation that holds names.
    NoCitationHeld,
}

/// What an ask came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FilesAskOutcome {
    /// The answer, each `[n]` in it named by a citation that holds.
    Cited {
        answer: String,
        citations: Vec<FileCitation>,
    },
    /// No answer: the owner opens the files themselves.
    NoCitedAnswer { why: FilesNoCitedAnswer },
}

/// `vault.files.sources.ask`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceAskAnswer {
    pub outcome: FilesAskOutcome,
    /// The files whose text the model read, in their `[n]` order.
    pub read: Vec<FilesAskedFile>,
    /// What the search found, best first; empty when the input named one
    /// file.
    pub hits: Vec<FilesSearchHit>,
}

/// One file's text as an answer's request carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesAskText {
    pub file: FilesAskedFile,
    /// At most [`FILES_ASK_FILE_CHARS`] characters of its note, from the
    /// start.
    pub text: String,
}

/// The instruction an answer's request opens with.
pub const FILES_ASK_INSTRUCTION: &str = "You answer the owner's question from the files given \
     to you, and from nothing else. The user message is JSON: `question`, and `files`, each with \
     its number `n`, its `path` and its `text`. Answer with one JSON object and nothing else: \
     {\"answer\": string, \"citations\": [{\"source\": n, \"quote\": string}]}. In `answer`, put \
     [n] after each claim a file supports. Each citation's `quote` is copied exactly, character \
     for character, from the text of file n. Cite only files you were given. If the files do not \
     answer the question, say so in `answer` and give no citations.";

/// The search that picks the files of an ask with no named file; `None`
/// when the input names one.
#[must_use]
pub fn files_ask_search(input: &FilesSourceAskRequest) -> Option<FilesSourceSearchRequest> {
    input.file.is_none().then(|| FilesSourceSearchRequest {
        query: input.query.clone(),
        sources: input.sources.clone(),
        limit: Some(DEFAULT_FILES_SEARCH_LIMIT),
    })
}

/// The ledger rows of each Files source, read once per source.
struct Ledgers<'a> {
    vault: &'a Vault,
    folders: HashMap<EntityId, String>,
    rows: HashMap<EntityId, Vec<FolderSourceFile>>,
}

impl<'a> Ledgers<'a> {
    fn new(vault: &'a Vault) -> MemoryResult<Self> {
        let folders = vault
            .files_sources()?
            .into_iter()
            .filter_map(|source| {
                let placed = source.files.as_ref()?.source;
                Some((placed, source.folder))
            })
            .collect();
        Ok(Self {
            vault,
            folders,
            rows: HashMap::new(),
        })
    }

    /// The text of the file `handle` names, with its number `source`: its
    /// note's words at the ledger's revision, cut to
    /// [`FILES_ASK_FILE_CHARS`]. `None` for a file with no text: held by
    /// name only, gone from its folder, or its note archived.
    fn text(&mut self, handle: &FileHandle, source: u32) -> MemoryResult<Option<FilesAskText>> {
        let Some(folder) = self.folders.get(&handle.source) else {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                format!("no Files source has the id {}", handle.source.to_hex()),
                &["List the Files sources: vault.files.sources.list."],
            ));
        };
        if !self.rows.contains_key(&handle.source) {
            let rows = self.vault.folder_source_files(folder)?;
            self.rows.insert(handle.source, rows);
        }
        let Some(row) = self
            .rows
            .get(&handle.source)
            .and_then(|rows| rows.iter().find(|row| row.path == handle.path))
        else {
            return Ok(None);
        };
        if row.state == FolderFileState::Retracted {
            return Ok(None);
        }
        let view = files_file_view(handle.source, row.clone());
        let (FileReadiness::Text, Some(note), Some(revision)) =
            (view.readiness, view.note, view.revision)
        else {
            return Ok(None);
        };
        let Some(body) = self.vault.read_note(&note)? else {
            return Ok(None);
        };
        Ok(Some(FilesAskText {
            file: FilesAskedFile {
                source,
                handle: handle.clone(),
                revision,
                note,
            },
            text: body.markdown.chars().take(FILES_ASK_FILE_CHARS).collect(),
        }))
    }
}

/// The files an ask reads, under the owner's proof, numbered from 1: the
/// one file the input names, or the first [`FILES_ASK_FILES`] files with
/// text that `searched` found, in its order. Empty when none has text.
///
/// # Errors
/// A proof that no longer holds, a question with no word, a named file and
/// sources both, a named file no Files source holds, or a storage error.
pub fn files_ask_read(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &FilesSourceAskRequest,
    searched: Option<&FilesSourceSearchAnswer>,
) -> MemoryResult<Vec<FilesAskText>> {
    owner.revalidate(vault)?;
    if input.query.trim().is_empty() {
        return Err(MemoryError::bad_request(
            "vault.files.sources.ask needs a question with at least one word",
        ));
    }
    let mut ledgers = Ledgers::new(vault)?;
    if let Some(file) = &input.file {
        if input.sources.is_some() {
            return Err(MemoryError::bad_request(
                "vault.files.sources.ask takes a file or sources to search, not both",
            ));
        }
        let Some(text) = ledgers.text(file, 1)? else {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                format!("{} holds no text to ask about", file.path),
                &["List the source's files and their readiness: vault.files.sources.files."],
            ));
        };
        return Ok(vec![text]);
    }
    let mut texts = Vec::new();
    for hit in searched.map_or(&[][..], |answer| answer.hits.as_slice()) {
        if texts.len() >= FILES_ASK_FILES {
            break;
        }
        let number = u32::try_from(texts.len().saturating_add(1)).unwrap_or(u32::MAX);
        if let Some(text) = ledgers.text(&hit.handle, number)? {
            texts.push(text);
        }
    }
    Ok(texts)
}

/// Whether each file of `texts` still reads as it was read: the same note,
/// revision and text. A citation of a file that changed since is not
/// checked against text the owner no longer has.
///
/// # Errors
/// A storage error.
pub fn files_ask_unchanged(vault: &Vault, texts: &[FilesAskText]) -> MemoryResult<Vec<bool>> {
    let mut ledgers = Ledgers::new(vault)?;
    texts
        .iter()
        .map(|read| {
            Ok(ledgers
                .text(&read.file.handle, read.file.source)
                .or_else(|refusal| {
                    if refusal.code == MEMORY_CODE_NOT_FOUND {
                        Ok(None)
                    } else {
                        Err(refusal)
                    }
                })?
                .is_some_and(|now| now == *read))
        })
        .collect()
}

/// The user message of an ask's request: the question and the files, each
/// with its number, path and text.
#[must_use]
pub fn files_ask_prompt(query: &str, texts: &[FilesAskText]) -> String {
    let files: Vec<_> = texts
        .iter()
        .map(|read| {
            serde_json::json!({
                "n": read.file.source,
                "path": read.file.handle.path,
                "text": read.text,
            })
        })
        .collect();
    serde_json::json!({ "question": query.trim(), "files": files }).to_string()
}

/// The answer a model gives, as [`FILES_ASK_INSTRUCTION`] asks for it.
#[derive(Deserialize)]
struct AskReply {
    answer: String,
    #[serde(default)]
    citations: Vec<AskReplyCitation>,
}

#[derive(Deserialize)]
struct AskReplyCitation {
    source: u32,
    quote: String,
}

/// The `[n]` marks of `answer`, in order.
fn cited_numbers(answer: &str) -> Vec<u32> {
    let mut numbers = Vec::new();
    let mut rest = answer;
    while let Some(open) = rest.find('[') {
        rest = &rest[open + 1..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0
            && rest.as_bytes().get(digits) == Some(&b']')
            && let Ok(number) = rest[..digits].parse::<u32>()
        {
            numbers.push(number);
        }
    }
    numbers
}

/// What a model's `reply` comes to, checked in fixed code against the
/// files it was given (`texts`) and whether each still reads as it did
/// (`unchanged`): a citation holds when it names a file given, still
/// unchanged, and its quote is an exact run of that file's text; any other
/// is dropped. The answer stands only when one citation holds and every
/// `[n]` it carries names a file a citation that holds cites.
#[must_use]
pub fn files_ask_outcome(
    reply: &str,
    texts: &[FilesAskText],
    unchanged: &[bool],
) -> FilesAskOutcome {
    let none_held = FilesAskOutcome::NoCitedAnswer {
        why: FilesNoCitedAnswer::NoCitationHeld,
    };
    let (Some(start), Some(end)) = (reply.find('{'), reply.rfind('}')) else {
        return none_held;
    };
    let Some(parsed) = reply
        .get(start..=end)
        .and_then(|object| serde_json::from_str::<AskReply>(object).ok())
    else {
        return none_held;
    };
    let mut citations: Vec<FileCitation> = Vec::new();
    for cited in parsed.citations {
        let Some(index) = usize::try_from(cited.source)
            .ok()
            .and_then(|source| source.checked_sub(1))
        else {
            continue;
        };
        let (Some(read), Some(true)) = (texts.get(index), unchanged.get(index).copied()) else {
            continue;
        };
        let quote = cited.quote.trim();
        if quote.is_empty() || !read.text.contains(quote) {
            continue;
        }
        if citations
            .iter()
            .any(|held| held.source == read.file.source && held.quote == quote)
        {
            continue;
        }
        citations.push(FileCitation {
            source: read.file.source,
            handle: read.file.handle.clone(),
            revision: read.file.revision.clone(),
            quote: quote.to_owned(),
        });
    }
    let answer = parsed.answer.trim();
    if answer.is_empty()
        || citations.is_empty()
        || cited_numbers(answer)
            .into_iter()
            .any(|number| !citations.iter().any(|held| held.source == number))
    {
        return none_held;
    }
    FilesAskOutcome::Cited {
        answer: answer.to_owned(),
        citations,
    }
}

//! `vault.files.sources.search` (ARCH-0027 #files-world: "Search goes by
//! name first and meaning second"): the owner's search of the Files world's
//! sources. The name tier ranks every file a chosen source's ledger holds by
//! how its name and path match the query; the meaning tier is the owner's
//! recall of the Files world, mapped back to files through the ledger. A
//! server runs the recall through its own recall pipeline, which embeds the
//! query where the host embeds; an embedded handle recalls with no query
//! vector.
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::files::{FilesFileState, files_file_view};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryPack, MemoryResult, RecallRequest,
    RecallScope, RecallWorlds,
};
use crate::note::{
    FileHandle, FileReadiness, FolderFileState, FolderSourceFile, NameMatch, file_path_of,
    name_match, text_excerpt,
};
use crate::{EdgeActorClass, Vault};

/// `vault.files.sources.search`'s input (ARCH-0027 #files-world: "Search
/// goes by name first and meaning second").
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceSearchRequest {
    /// The words to find, in a file's name or path, or in its text.
    pub query: String,
    /// The Files sources to search; every one when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<EntityId>>,
    /// How many files to answer, at most [`MAX_FILES_SEARCH_LIMIT`];
    /// [`DEFAULT_FILES_SEARCH_LIMIT`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// How many files `vault.files.sources.search` answers when its input names
/// no limit.
pub const DEFAULT_FILES_SEARCH_LIMIT: u64 = 20;

/// How many files one `vault.files.sources.search` answer holds at most.
pub const MAX_FILES_SEARCH_LIMIT: u64 = 100;

/// Why a search found a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "by")]
pub enum FilesSearchMatch {
    /// Its name or path matched the query, in this class.
    Name { class: NameMatch },
    /// Its text matched the query in meaning: its place in the owner's
    /// recall of the Files world, 1 first.
    Meaning { rank: u32 },
}

/// One file a search found, as its source's ledger holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSearchHit {
    pub handle: FileHandle,
    /// The install whose Files world holds the file.
    pub machine: EntityId,
    pub state: FilesFileState,
    pub readiness: FileReadiness,
    /// The note its text landed as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<EntityId>,
    /// The revision the vault took; none for a file held by name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// When the file was last written (Unix seconds), at that revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,
    pub matched: FilesSearchMatch,
    /// For a meaning hit, the words of the note the recall found around the
    /// query, at most [`crate::note::FILES_SNIPPET_CHARS`] characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Whether a search's meaning tier ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FilesMeaningState {
    /// The owner's recall of the Files world answered.
    Ran,
    /// No recall answered: this install has no Files world, or the recall
    /// refused. The name tier answers all the same.
    Unavailable { reason: String },
}

/// `vault.files.sources.search`'s answer: the files whose name or path
/// matched, best class first and newer first within a class, then the files
/// whose text matched in meaning, in the recall's order. A file is listed
/// once, by its best tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceSearchAnswer {
    pub hits: Vec<FilesSearchHit>,
    pub meaning: FilesMeaningState,
}

/// One ledger row a search may answer: a file of a chosen Files source that
/// has not left its folder.
struct SearchedFile {
    source: EntityId,
    machine: EntityId,
    file: FolderSourceFile,
}

impl SearchedFile {
    fn modified_at(&self) -> Option<u64> {
        self.file.meta.map(|meta| meta.modified_at)
    }

    /// The hit this row answers for the file at `path`.
    fn hit(
        &self,
        path: &str,
        matched: FilesSearchMatch,
        snippet: Option<String>,
    ) -> FilesSearchHit {
        let view = files_file_view(self.source, self.file.clone());
        FilesSearchHit {
            handle: FileHandle {
                source: self.source,
                path: path.to_owned(),
            },
            machine: self.machine,
            state: view.state,
            readiness: view.readiness,
            note: view.note,
            revision: view.revision,
            bytes: view.bytes,
            modified_at: view.modified_at,
            matched,
            snippet,
        }
    }
}

/// The query a search runs: refused when it holds no word.
fn searched_query(input: &FilesSourceSearchRequest) -> MemoryResult<&str> {
    let query = input.query.trim();
    if query.is_empty() {
        return Err(MemoryError::bad_request(
            "vault.files.sources.search needs a query with at least one word",
        ));
    }
    Ok(query)
}

/// How many files a search answers.
fn search_limit(input: &FilesSourceSearchRequest) -> usize {
    usize::try_from(input.limit.unwrap_or(DEFAULT_FILES_SEARCH_LIMIT))
        .unwrap_or(usize::MAX)
        .clamp(
            1,
            usize::try_from(MAX_FILES_SEARCH_LIMIT).unwrap_or(usize::MAX),
        )
}

/// Every ledger row of the sources `wanted` names (every Files source when
/// `None`), but those of files that left their folder.
fn searched_files(vault: &Vault, wanted: Option<&[EntityId]>) -> MemoryResult<Vec<SearchedFile>> {
    let attached = vault.files_sources()?;
    if let Some(wanted) = wanted {
        for source in wanted {
            if !attached.iter().any(|attached| {
                attached
                    .files
                    .as_ref()
                    .is_some_and(|files| files.source == *source)
            }) {
                return Err(MemoryError::new(
                    MEMORY_CODE_NOT_FOUND,
                    format!("no Files source has the id {}", source.to_hex()),
                    &["List the Files sources: vault.files.sources.list."],
                ));
            }
        }
    }
    let mut searched = Vec::new();
    for source in attached {
        let Some(files) = source.files.as_ref() else {
            continue;
        };
        if wanted.is_some_and(|wanted| !wanted.contains(&files.source)) {
            continue;
        }
        for file in vault.folder_source_files(&source.folder)? {
            if file.state == FolderFileState::Retracted {
                continue;
            }
            searched.push(SearchedFile {
                source: files.source,
                machine: files.machine,
                file,
            });
        }
    }
    Ok(searched)
}

/// The recall a search's meaning tier runs as the owner: the query, over
/// this install's Files world alone with base declined, for twice the
/// search's limit (a recalled row that is no chosen file's note is dropped).
/// `None` when this install has no Files world.
///
/// # Errors
/// A query with no word, or a storage error.
pub fn files_search_recall(
    vault: &Vault,
    input: &FilesSourceSearchRequest,
) -> MemoryResult<Option<RecallRequest>> {
    let query = searched_query(input)?;
    let Some(files) = vault.files_world()? else {
        return Ok(None);
    };
    Ok(Some(RecallRequest {
        query: query.to_owned(),
        scope: Some(RecallScope {
            worlds: Some(RecallWorlds::World {
                world_ref: files.world.to_hex(),
                include_base: false,
            }),
            ..RecallScope::default()
        }),
        limit: Some(search_limit(input).saturating_mul(2)),
        ..RecallRequest::default()
    }))
}

/// `vault.files.sources.search` under the owner's proof, its meaning tier
/// read from `meaning`: the pack the owner's recall of
/// [`files_search_recall`]'s request answered, or its refusal; `None` when
/// no recall ran. The name tier covers every ledger row of the chosen
/// sources but a retracted file's, a file held by name only included; a
/// continuation part's row is its file's. A recalled note maps back to its
/// file through the ledger, and a file the name tier listed is not listed
/// again.
///
/// # Errors
/// A proof that no longer holds, a query with no word, a source that is no
/// Files source, or a storage error. A refused recall is no error: the
/// answer says the meaning tier did not run.
pub fn search_files_sources_with(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FilesSourceSearchRequest,
    meaning: Option<MemoryResult<MemoryPack>>,
) -> MemoryResult<FilesSourceSearchAnswer> {
    owner.revalidate(vault)?;
    let query = searched_query(&input)?;
    let limit = search_limit(&input);
    let searched = searched_files(vault, input.sources.as_deref())?;

    let mut named: Vec<(NameMatch, &SearchedFile)> = searched
        .iter()
        .filter(|found| file_path_of(&found.file.path) == found.file.path)
        .filter_map(|found| name_match(&found.file.path, query).map(|class| (class, found)))
        .collect();
    named.sort_by(|(left_class, left), (right_class, right)| {
        left_class
            .cmp(right_class)
            .then_with(|| right.modified_at().cmp(&left.modified_at()))
            .then_with(|| left.file.path.cmp(&right.file.path))
            .then_with(|| left.source.as_bytes().cmp(right.source.as_bytes()))
    });
    let mut listed: HashSet<(EntityId, &str)> = HashSet::new();
    let mut hits: Vec<FilesSearchHit> = Vec::new();
    for (class, found) in named {
        listed.insert((found.source, found.file.path.as_str()));
        hits.push(found.hit(&found.file.path, FilesSearchMatch::Name { class }, None));
    }

    let meaning = match meaning {
        None => FilesMeaningState::Unavailable {
            reason: "this install has no Files world".to_owned(),
        },
        Some(Err(refusal)) => FilesMeaningState::Unavailable {
            reason: refusal.to_string(),
        },
        Some(Ok(pack)) => {
            let by_note: HashMap<EntityId, &SearchedFile> = searched
                .iter()
                .filter_map(|found| found.file.note.map(|note| (note, found)))
                .collect();
            let by_path: HashMap<(EntityId, &str), &SearchedFile> = searched
                .iter()
                .map(|found| ((found.source, found.file.path.as_str()), found))
                .collect();
            let mut rank: u32 = 0;
            for item in &pack.items {
                let Some(note) = item
                    .record
                    .as_ref()
                    .and_then(|record| EntityId::from_hex(&record.id).ok())
                else {
                    continue;
                };
                let Some(found) = by_note.get(&note).copied() else {
                    continue;
                };
                if hits.len() >= limit {
                    break;
                }
                let path = file_path_of(&found.file.path);
                if !listed.insert((found.source, path)) {
                    continue;
                }
                // A part's hit answers its file's own row when the ledger
                // holds it; its snippet is the recalled note's own words.
                let row = by_path.get(&(found.source, path)).copied().unwrap_or(found);
                let snippet = vault
                    .read_note(&note)?
                    .map(|body| text_excerpt(&body.markdown, query))
                    .filter(|text| !text.is_empty());
                rank = rank.saturating_add(1);
                hits.push(row.hit(path, FilesSearchMatch::Meaning { rank }, snippet));
            }
            FilesMeaningState::Ran
        }
    };
    hits.truncate(limit);
    Ok(FilesSourceSearchAnswer { hits, meaning })
}

/// `vault.files.sources.search` under the owner's proof, its meaning tier
/// the owner's recall on this vault, with no query vector.
///
/// # Errors
/// As [`search_files_sources_with`].
pub fn search_files_sources_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FilesSourceSearchRequest,
) -> MemoryResult<FilesSourceSearchAnswer> {
    let actor = owner.revalidate(vault)?;
    let memory = vault.memory(actor, EdgeActorClass::Human);
    search_files_sources_in(&memory, owner, input)
}

/// A search whose meaning tier is `memory`'s recall, with no query vector.
fn search_files_sources_in(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: FilesSourceSearchRequest,
) -> MemoryResult<FilesSourceSearchAnswer> {
    let meaning = files_search_recall(memory.vault(), &input)?
        .map(|request| super::recall_unembedded(memory, request));
    search_files_sources_with(memory.vault(), owner, input, meaning)
}

/// `vault.files.sources.search` on an embedded handle: the embedded owner's
/// own read, its meaning tier the handle's recall with no query vector.
pub fn search_files_sources_embedded(
    memory: &Memory<'_>,
    input: FilesSourceSearchRequest,
) -> MemoryResult<FilesSourceSearchAnswer> {
    let owner = memory.embedded_owner("vault.files.sources.search")?;
    search_files_sources_in(memory, &owner, input)
}

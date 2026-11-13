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
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryPack, MemoryResult,
    RecallRequest, RecallScope, RecallWorlds,
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
    /// The owner's other devices to search beside this one, over the mesh
    /// (ARCH-0027 #files-world: "Cross-device search over the iroh mesh");
    /// this device alone when absent. With devices, `sources` may name a
    /// source of any device searched, and each device searches the named
    /// sources it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<FilesSearchDevices>,
}

/// Which of the owner's other devices a search asks, beside this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilesSearchDevices {
    /// Every machine of the owner this install may ask: each one whose live
    /// `mesh:alpn:oneiron/files-search/1` grant this vault holds.
    All,
    /// The named machines of the owner.
    Only(Vec<EntityId>),
}

/// The ALPN on which a device of the owner answers another device's Files
/// search ([`FilesSearchDevices`]). A machine is asked, and answered, only
/// while this vault holds its live `mesh:alpn:oneiron/files-search/1` grant.
pub const FILES_SEARCH_ALPN: &[u8] = b"oneiron/files-search/1";

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
    /// The devices the search asked that gave no answer; none of their
    /// files is listed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<FilesUnreachedDevice>,
}

/// A device a cross-device search asked that gave no answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesUnreachedDevice {
    pub machine: EntityId,
    pub why: FilesUnreachedWhy,
}

/// Why a device gave a cross-device search no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilesUnreachedWhy {
    /// This vault holds no live Files search grant for the machine, or the
    /// machine refused this one.
    Refused,
    /// This install has no mesh endpoint, or found no path to the machine.
    Unavailable,
    /// No answer came before the search's deadline.
    TimedOut,
    /// The connection failed, or the device's answer could not be read.
    Failed,
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
fn search_limit(limit: Option<u64>) -> usize {
    usize::try_from(limit.unwrap_or(DEFAULT_FILES_SEARCH_LIMIT))
        .unwrap_or(usize::MAX)
        .clamp(
            1,
            usize::try_from(MAX_FILES_SEARCH_LIMIT).unwrap_or(usize::MAX),
        )
}

/// Every ledger row of the sources `wanted` names (every Files source when
/// `None`), but those of files that left their folder. A named source this
/// install does not hold is refused when `strict`, and skipped otherwise: a
/// cross-device search may name another device's source.
fn searched_files(
    vault: &Vault,
    wanted: Option<&[EntityId]>,
    strict: bool,
) -> MemoryResult<Vec<SearchedFile>> {
    let attached = vault.files_sources()?;
    if let Some(wanted) = wanted.filter(|_| strict) {
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
        limit: Some(search_limit(input.limit).saturating_mul(2)),
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
/// It answers for this install's Files world alone, whatever `devices` says:
/// the host asks the other devices and merges their answers
/// ([`merge_files_search_answers`]). With `devices`, a named source this
/// install does not hold is skipped, not refused.
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
    let strict = input.devices.is_none();
    files_search_here(vault, &input, meaning, strict)
}

/// This install's answer to a search: its name tier, then its meaning tier
/// from `meaning`, cut to the search's limit.
fn files_search_here(
    vault: &Vault,
    input: &FilesSourceSearchRequest,
    meaning: Option<MemoryResult<MemoryPack>>,
    strict: bool,
) -> MemoryResult<FilesSourceSearchAnswer> {
    let query = searched_query(input)?;
    let limit = search_limit(input.limit);
    let searched = searched_files(vault, input.sources.as_deref(), strict)?;

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
    Ok(FilesSourceSearchAnswer {
        hits,
        meaning,
        unreached: Vec::new(),
    })
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
/// own read, its meaning tier the handle's recall with no query vector. An
/// embedded handle has no mesh endpoint, so every device `devices` names is
/// listed unreached, [`FilesUnreachedWhy::Unavailable`].
pub fn search_files_sources_embedded(
    memory: &Memory<'_>,
    input: FilesSourceSearchRequest,
) -> MemoryResult<FilesSourceSearchAnswer> {
    let owner = memory.embedded_owner("vault.files.sources.search")?;
    let Some(devices) = input.devices.clone() else {
        return search_files_sources_in(memory, &owner, input);
    };
    let unreached = files_search_devices(memory.vault(), &devices)?
        .into_iter()
        .map(|machine| FilesUnreachedDevice {
            machine,
            why: FilesUnreachedWhy::Unavailable,
        })
        .collect();
    let limit = input.limit;
    let answer = search_files_sources_in(memory, &owner, input)?;
    Ok(merge_files_search_answers(
        limit,
        answer,
        Vec::new(),
        unreached,
    ))
}

/// The machines a search with `devices` asks, each once, in machine order,
/// never this install: every machine this vault holds the live Files search
/// grant for ([`FILES_SEARCH_ALPN`]), or the machines `devices` names.
///
/// # Errors
/// A storage error.
pub fn files_search_devices(
    vault: &Vault,
    devices: &FilesSearchDevices,
) -> MemoryResult<Vec<EntityId>> {
    let this_install = vault.local_machine()?.map(|machine| machine.id);
    let mut machines = match devices {
        FilesSearchDevices::All => vault.mesh_machines_granted(FILES_SEARCH_ALPN)?,
        FilesSearchDevices::Only(named) => named.clone(),
    };
    machines.retain(|machine| Some(*machine) != this_install);
    machines.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    machines.dedup();
    Ok(machines)
}

/// Another device of the owner's search of this install's Files world
/// (ARCH-0027 #files-world: "Each device ranks its own files and returns
/// metadata and snippets"), for `peer`, the MACHINE whose endpoint key
/// `endpoint_key` the mesh handshake proved. The peer must hold this
/// vault's live Files search grant on that key now
/// ([`Vault::mesh_peer_machine`] on [`FILES_SEARCH_ALPN`]); the grant is the
/// gate (ruling L2-16-MESH-SNIPPETS = B: metadata and snippets go to any
/// machine holding it). The mesh admitted the peer as the owner's own
/// machine, so its search is the owner's, as a peer's model call is: the
/// meaning tier is the vault owner's recall of this install's Files world,
/// read on this install, with no query vector. The answer is this
/// install's own ranking ([`search_files_sources_with`]); a named source
/// this install does not hold is skipped, and `devices` is not followed.
///
/// # Errors
/// A peer without the live grant (forbidden), a query with no word, or a
/// storage error.
pub fn search_files_sources_for_peer(
    vault: &Vault,
    peer: EntityId,
    endpoint_key: [u8; 32],
    input: FilesSourceSearchRequest,
) -> MemoryResult<FilesSourceSearchAnswer> {
    match vault.mesh_peer_machine(endpoint_key, FILES_SEARCH_ALPN)? {
        crate::authority::PeerMachine::Proven { machine, .. } if machine == peer => {}
        _ => {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "machine {} holds no live Files search grant here",
                    peer.to_hex()
                ),
                &[
                    "The owner grants Files search to a machine: vault.mesh.set_alpn_grant with alpn oneiron/files-search/1.",
                ],
            ));
        }
    }
    let owner = crate::vault::embedded_owner_actor_id()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let meaning = files_search_recall(vault, &input)?
        .map(|request| super::recall_unembedded(&memory, request));
    files_search_here(vault, &input, meaning, false)
}

/// One other device's answer to a cross-device search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesDeviceAnswer {
    /// The machine that answered.
    pub machine: EntityId,
    pub answer: FilesSourceSearchAnswer,
}

/// A cross-device search's one answer (ARCH-0027 #files-world: "One
/// calibrated merge orders the results across devices"): `this` install's
/// answer and `others`', cut to the search's `limit`, with the devices that
/// gave none in `unreached`.
///
/// Every name hit comes before any meaning hit. Name hits are ordered by
/// match class, then newer first: a class is the same test on every device,
/// so it compares across devices exactly. Meaning hits are interleaved by
/// each device's own recall rank: a file lives on one device, so its
/// reciprocal-rank fusion score 1/(k + rank) orders by that rank alone, and
/// no score from one device's index is compared with another's. A tie goes
/// to this install, then to the other devices in machine order. Each device
/// answers for its own Files world only: a hit that names another machine is
/// dropped, and a device's hits past `limit` are not read. The meaning tier
/// ran when it ran on any device.
#[must_use]
pub fn merge_files_search_answers(
    limit: Option<u64>,
    this: FilesSourceSearchAnswer,
    mut others: Vec<FilesDeviceAnswer>,
    mut unreached: Vec<FilesUnreachedDevice>,
) -> FilesSourceSearchAnswer {
    let limit = search_limit(limit);
    others.sort_by(|left, right| left.machine.as_bytes().cmp(right.machine.as_bytes()));
    let mut meaning = this.meaning;
    let mut found: Vec<(usize, FilesSearchHit)> = this
        .hits
        .into_iter()
        .take(limit)
        .map(|hit| (0, hit))
        .collect();
    unreached.extend(this.unreached);
    for (index, other) in others.into_iter().enumerate() {
        if other.answer.meaning == FilesMeaningState::Ran {
            meaning = FilesMeaningState::Ran;
        }
        let machine = other.machine;
        found.extend(
            other
                .answer
                .hits
                .into_iter()
                .take(limit)
                .filter(|hit| hit.machine == machine)
                .map(|hit| (index.saturating_add(1), hit)),
        );
    }
    found.sort_by(|(left_device, left), (right_device, right)| {
        merged_order(left, right)
            .then_with(|| left_device.cmp(right_device))
            .then_with(|| left.handle.path.cmp(&right.handle.path))
            .then_with(|| {
                left.handle
                    .source
                    .as_bytes()
                    .cmp(right.handle.source.as_bytes())
            })
    });
    let mut listed: HashSet<(EntityId, EntityId, String)> = HashSet::new();
    let hits: Vec<FilesSearchHit> = found
        .into_iter()
        .map(|(_, hit)| hit)
        .filter(|hit| listed.insert((hit.machine, hit.handle.source, hit.handle.path.clone())))
        .take(limit)
        .collect();
    unreached.sort_by(|left, right| left.machine.as_bytes().cmp(right.machine.as_bytes()));
    unreached.dedup_by(|right, left| right.machine == left.machine);
    FilesSourceSearchAnswer {
        hits,
        meaning,
        unreached,
    }
}

/// Name hits first, by class then newer first; then meaning hits by rank.
fn merged_order(left: &FilesSearchHit, right: &FilesSearchHit) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left.matched, right.matched) {
        (
            FilesSearchMatch::Name { class: left_class },
            FilesSearchMatch::Name { class: right_class },
        ) => left_class
            .cmp(&right_class)
            .then_with(|| right.modified_at.cmp(&left.modified_at)),
        (FilesSearchMatch::Name { .. }, FilesSearchMatch::Meaning { .. }) => Ordering::Less,
        (FilesSearchMatch::Meaning { .. }, FilesSearchMatch::Name { .. }) => Ordering::Greater,
        (
            FilesSearchMatch::Meaning { rank: left_rank },
            FilesSearchMatch::Meaning { rank: right_rank },
        ) => left_rank.cmp(&right_rank),
    }
}

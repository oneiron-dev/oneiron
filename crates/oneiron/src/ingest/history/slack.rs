//! A Slack workspace export (ARCH-0027 #import-audience): `users.json`, the
//! conversation lists `channels.json` (public channels), `groups.json`
//! (private channels), `mpims.json` (group DMs) and `dms.json` (DMs), and one
//! folder per conversation holding one `YYYY-MM-DD.json` file of messages per
//! day. A channel, a private channel or a group DM is found by its name, a DM
//! by its id.
//!
//! The first source that keeps its own sharing. Each conversation carries
//! the members the source shares it with, keyed by the workspace and the
//! conversation (`<workspace>:<conversation id>`). A private channel, a DM
//! and a group DM name their own members. A public channel names every
//! member of the workspace, so it reads to every vault person matched to
//! that workspace (owner ruling IMPORT-PUBLIC = D, 15 Nov 00:43). A folder
//! no list names keeps no members and reads to the importer alone. A listed
//! conversation with no messages is kept too: its import sets its readers
//! again, so a member a later export no longer shares it with reads none of
//! it. A message's id is its conversation's (`<workspace>:<conversation
//! id>:<ts>`), so two workspaces never land as one.
//!
//! Every message stays a source speaker's words: `said_by` is `slack:<member
//! id>`, until the owner's member map says which member they are themselves
//! ([`SlackWorkspace::map_members`]). The decoder mints no PERSON: a member
//! the map gives no PERSON stays a contact, whose name and words are kept
//! and who reads nothing (owner ruling IMPORT-IDENTITY, 15 Nov 00:43; Engine
//! ruling L2-18-CONTACT = A).
//!
//! The reader is pure: the host reads the export's JSON files and hands
//! them over by their path under the export.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use super::text::{MAX_RECORD_BYTES, str_field};
use super::{
    HistoryConversation, HistoryMember, HistoryMessage, HistoryRole, HistorySharing, HistorySkips,
    HistoryThreadKind, UNKNOWN_SPEAKER,
};
use crate::EntityId;
use crate::ingest::{IngestError, IngestResult};

const SOURCE_ID: &str = "slack";

/// The workspace's members.
pub const USERS_FILE: &str = "users.json";

/// What a message's `said_by` starts with: a Slack member's words carry
/// `slack:<member id>`.
pub const SPEAKER_PREFIX: &str = "slack:";

/// The member-map value that names the importer's own member.
pub const OWNER_MAPPING: &str = "owner";

/// Message subtypes that carry a person's own words; every other subtype is
/// the workspace's bookkeeping (a join, a topic, a rename).
const KEPT_SUBTYPES: [&str; 4] = [
    "thread_broadcast",
    "me_message",
    "file_share",
    "bot_message",
];

/// The conversation lists of an export, with how each shares its
/// conversations.
const LISTS: [(&str, ListSharing); 4] = [
    ("channels.json", ListSharing::Workspace),
    ("groups.json", ListSharing::Members),
    ("mpims.json", ListSharing::Members),
    ("dms.json", ListSharing::Members),
];

/// One JSON file of an export: its path under the export's own folder (with
/// `/` between names, as `general/2026-11-01.json`) and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackExportFile {
    pub path: String,
    pub text: String,
}

/// A Slack export as the host read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackExport {
    /// The name the owner knows the workspace by. It keys the workspace
    /// (with `-` for each `:`) when no member names the workspace's Slack id.
    pub workspace: String,
    pub files: Vec<SlackExportFile>,
}

/// One member of the workspace, as `users.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackMember {
    pub id: String,
    /// Display name, else real name, else handle, else the id.
    pub name: String,
    /// The profile's email address, as the export wrote it.
    pub email: Option<String>,
}

/// A decoded workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackWorkspace {
    /// The name the owner knows the workspace by.
    pub name: String,
    /// The key of the workspace: its Slack id (`team_id`), or its name when
    /// no member names one. Every sharing container starts with it.
    pub key: String,
    pub members: Vec<SlackMember>,
    pub conversations: Vec<HistoryConversation>,
    /// Files of the export that are neither a list nor a day file of a
    /// folder, passed over.
    pub passed: Vec<String>,
}

/// What the owner says one member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackMemberMapping {
    /// The importer's own member: it reads as the importer does, and its
    /// words land as the owner's.
    Owner,
    /// A vault PERSON.
    Person(EntityId),
    /// No one in the vault: a contact, who reads nothing.
    Contact,
}

/// The owner's member map: `{ "<member id>": "owner" | "<PERSON hex>" |
/// null }`. A member the map leaves out is a contact.
pub type SlackMemberMap = BTreeMap<String, SlackMemberMapping>;

/// How the members of a workspace stand once mapped, the owner's own
/// member left out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct SlackMemberCounts {
    pub members: u32,
    /// Members mapped to a vault PERSON.
    pub matched: u32,
    /// Members kept as contacts.
    pub contacts: u32,
}

/// How a list's conversations are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListSharing {
    /// A public channel: every member of the workspace.
    Workspace,
    /// The conversation's own members.
    Members,
}

/// `said_by` for the words of the member `id`.
#[must_use]
pub fn said_by(id: &str) -> String {
    format!("{SPEAKER_PREFIX}{id}")
}

fn bad(path: String) -> IngestError {
    IngestError::InvalidDocumentField {
        source_id: SOURCE_ID,
        path,
    }
}

fn document(path: &str, text: &str) -> IngestResult<Value> {
    if text.len() > MAX_RECORD_BYTES {
        return Err(IngestError::InvalidDocument {
            source_id: SOURCE_ID,
            message: format!("{path} is larger than one record may be"),
        });
    }
    serde_json::from_str(text).map_err(|error| IngestError::InvalidDocument {
        source_id: SOURCE_ID,
        message: format!("{path}: {error}"),
    })
}

/// Parses the owner's member map.
///
/// # Errors
///
/// [`IngestError::InvalidDocument`] when the text is not a JSON object, and
/// [`IngestError::InvalidDocumentField`] for a value that is neither
/// `"owner"`, a PERSON id in hex nor `null`.
pub fn parse_member_map(text: &str) -> IngestResult<SlackMemberMap> {
    let Value::Object(entries) = document("the member map", text)? else {
        return Err(IngestError::InvalidDocument {
            source_id: SOURCE_ID,
            message: "the member map is not a JSON object".to_owned(),
        });
    };
    entries
        .into_iter()
        .map(|(member, value)| {
            let mapping = match &value {
                Value::Null => SlackMemberMapping::Contact,
                Value::String(text) if text == OWNER_MAPPING => SlackMemberMapping::Owner,
                Value::String(text) => EntityId::from_hex(text)
                    .map(SlackMemberMapping::Person)
                    .map_err(|_| bad(format!("members.{member}")))?,
                _ => return Err(bad(format!("members.{member}"))),
            };
            Ok((member, mapping))
        })
        .collect()
}

/// Decodes a whole export: every conversation a list names, with or
/// without messages, and every folder of day files.
///
/// # Errors
///
/// [`IngestError::UnsupportedSchema`] when the export holds no `users.json`;
/// [`IngestError::InvalidDocument`] when a list is not JSON;
/// [`IngestError::InvalidDocumentField`] when a list or a member entry is
/// not the layout's. A day file that does not read is counted on its
/// conversation, never fatal.
pub fn decode(export: &SlackExport) -> IngestResult<SlackWorkspace> {
    let files: HashMap<&str, &str> = export
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.text.as_str()))
        .collect();
    let users = files
        .get(USERS_FILE)
        .ok_or_else(|| IngestError::UnsupportedSchema {
            source_id: SOURCE_ID,
            expected: "a Slack workspace export with users.json",
            found: format!("{} file(s), none users.json", export.files.len()),
        })?;
    let (members, team) = decode_users(users)?;
    // A name keys the workspace only when no member names its Slack id; a
    // `:` in it would run into the container's own separator.
    let key = team.unwrap_or_else(|| export.workspace.replace(':', "-"));
    let names: HashMap<&str, &str> = members
        .iter()
        .map(|member| (member.id.as_str(), member.name.as_str()))
        .collect();

    let mut conversations: Vec<HistoryConversation> = Vec::new();
    let mut folders: HashMap<String, usize> = HashMap::new();
    for (list, sharing) in LISTS {
        let Some(text) = files.get(list) else {
            continue;
        };
        let Value::Array(entries) = document(list, text)? else {
            return Err(bad(list.to_owned()));
        };
        for (at, entry) in entries.iter().enumerate() {
            let id = str_field(entry, "id").ok_or_else(|| bad(format!("{list}[{at}].id")))?;
            let listed: Vec<&str> = entry
                .get("members")
                .and_then(Value::as_array)
                .map(|ids| ids.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let ids: Vec<&str> = match sharing {
                ListSharing::Workspace => members.iter().map(|member| member.id.as_str()).collect(),
                ListSharing::Members => listed.clone(),
            };
            let name = str_field(entry, "name");
            let title = name.map_or_else(
                || {
                    listed
                        .iter()
                        .map(|id| names.get(id).copied().unwrap_or(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                str::to_owned,
            );
            let mut conversation = shared_conversation(&key, id, &ids, &names);
            conversation.title = Some(title).filter(|title| !title.is_empty());
            conversation.started_at_ms = entry
                .get("created")
                .and_then(Value::as_u64)
                .map(|seconds| seconds.saturating_mul(1000));
            let index = conversations.len();
            // A DM's folder is its id; every other conversation's is its name.
            folders.entry(id.to_owned()).or_insert(index);
            if let Some(name) = name {
                folders.insert(name.to_owned(), index);
            }
            conversations.push(conversation);
        }
    }

    let mut passed = Vec::new();
    let mut days: Vec<&SlackExportFile> = export
        .files
        .iter()
        .filter(|file| file.path.split('/').count() == 2)
        .collect();
    days.sort_by(|a, b| a.path.cmp(&b.path));
    for file in &export.files {
        let top_level = !file.path.contains('/');
        let list = file.path == USERS_FILE || LISTS.iter().any(|(list, _)| file.path == *list);
        if !list && (top_level || file.path.split('/').count() > 2) {
            passed.push(file.path.clone());
        }
    }
    for file in days {
        let Some((folder, _)) = file.path.split_once('/') else {
            continue;
        };
        let index = match folders.get(folder) {
            Some(index) => *index,
            None => {
                // No list names the folder: its conversation keeps no
                // members, so it reads to the importer alone.
                let index = conversations.len();
                let mut unlisted = shared_conversation(&key, folder, &[], &names);
                unlisted.title = Some(folder.to_owned());
                conversations.push(unlisted);
                folders.insert(folder.to_owned(), index);
                index
            }
        };
        day(&file.path, &file.text, &mut conversations[index]);
    }

    for conversation in &mut conversations {
        conversation
            .messages
            .sort_by(|a, b| (a.at_ms, a.native_id.as_str()).cmp(&(b.at_ms, b.native_id.as_str())));
        if conversation.started_at_ms.is_none() {
            conversation.started_at_ms = conversation.messages.first().and_then(|m| m.at_ms);
        }
    }
    Ok(SlackWorkspace {
        name: export.workspace.clone(),
        key,
        members,
        conversations,
        passed,
    })
}

/// The members `users.json` lists, and the workspace's Slack id when a
/// member names one.
fn decode_users(text: &str) -> IngestResult<(Vec<SlackMember>, Option<String>)> {
    let Value::Array(users) = document(USERS_FILE, text)? else {
        return Err(bad(USERS_FILE.to_owned()));
    };
    let mut team = None;
    let mut seen = BTreeSet::new();
    let mut members = Vec::with_capacity(users.len());
    for (at, user) in users.iter().enumerate() {
        let id = str_field(user, "id").ok_or_else(|| bad(format!("{USERS_FILE}[{at}].id")))?;
        if !seen.insert(id.to_owned()) {
            return Err(IngestError::DuplicateId {
                source_id: SOURCE_ID,
                kind: "member",
                id: id.to_owned(),
            });
        }
        if team.is_none() {
            team = str_field(user, "team_id").map(str::to_owned);
        }
        let profile = user.get("profile");
        let profile_field = |key: &str| profile.and_then(|profile| str_field(profile, key));
        let name = profile_field("display_name")
            .or_else(|| profile_field("real_name"))
            .or_else(|| str_field(user, "real_name"))
            .or_else(|| str_field(user, "name"))
            .unwrap_or(id);
        members.push(SlackMember {
            id: id.to_owned(),
            name: name.to_owned(),
            email: profile_field("email").map(str::to_owned),
        });
    }
    Ok((members, team))
}

/// A conversation with no messages yet, shared with the members `ids`.
fn shared_conversation(
    key: &str,
    id: &str,
    ids: &[&str],
    names: &HashMap<&str, &str>,
) -> HistoryConversation {
    // The id it lands under, and its sharing container: one per Slack
    // conversation of the workspace.
    let native_id = format!("{key}:{id}");
    let mut seen = BTreeSet::new();
    let members = ids
        .iter()
        .filter(|id| seen.insert(**id))
        .map(|id| HistoryMember {
            provider_id: (*id).to_owned(),
            name: names.get(id).map(|name| (*name).to_owned()),
            person: None,
            importer: false,
        })
        .collect();
    let mut conversation =
        HistoryConversation::new(native_id.clone(), HistoryThreadKind::Main, None);
    conversation.sharing = Some(HistorySharing {
        container: native_id,
        members,
    });
    conversation
}

/// A message's Slack time (`<seconds>.<microseconds>`), in milliseconds.
fn ts_ms(ts: &str) -> Option<u64> {
    let (seconds, micros) = ts.split_once('.').unwrap_or((ts, "0"));
    let seconds: u64 = seconds.parse().ok()?;
    let micros: u64 = format!("{micros:0<6}").get(..6)?.parse().ok()?;
    seconds.checked_mul(1000)?.checked_add(micros / 1000)
}

/// Reads one day file into `conversation`, counting what it does not keep.
fn day(path: &str, text: &str, conversation: &mut HistoryConversation) {
    let skipped = &mut conversation.skipped;
    let Ok(Value::Array(messages)) = document(path, text) else {
        skipped.unreadable += 1;
        return;
    };
    for message in &messages {
        let Some(kept) = day_message(&conversation.native_id, message, skipped) else {
            continue;
        };
        conversation.messages.push(kept);
    }
}

/// One message of a day file, kept when it holds a person's words. Its id is
/// the conversation's own id and its Slack time (`<workspace>:<conversation
/// id>:<ts>`), and a thread reply names the message that began its thread as
/// its parent.
fn day_message(id: &str, message: &Value, skipped: &mut HistorySkips) -> Option<HistoryMessage> {
    if !message.is_object() {
        skipped.unreadable += 1;
        return None;
    }
    if message.get("type").and_then(Value::as_str) != Some("message") {
        skipped.other += 1;
        return None;
    }
    if let Some(subtype) = message.get("subtype").and_then(Value::as_str)
        && !KEPT_SUBTYPES.contains(&subtype)
    {
        skipped.system += 1;
        return None;
    }
    let Some(ts) = str_field(message, "ts") else {
        skipped.unreadable += 1;
        return None;
    };
    let Some(at_ms) = ts_ms(ts) else {
        skipped.unreadable += 1;
        return None;
    };
    let files = message
        .get("files")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    skipped.attachments += u32::try_from(files).unwrap_or(u32::MAX);
    let text = message
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if text.is_empty() {
        if files == 0 {
            skipped.empty += 1;
        }
        return None;
    }
    let speaker = str_field(message, "user").or_else(|| str_field(message, "bot_id"));
    let parent_id = str_field(message, "thread_ts")
        .filter(|thread| *thread != ts)
        .map(|thread| format!("{id}:{thread}"));
    Some(HistoryMessage {
        native_id: format!("{id}:{ts}"),
        parent_id,
        role: HistoryRole::User,
        text: text.to_owned(),
        at_ms: Some(at_ms),
        said_by: Some(speaker.map_or_else(|| UNKNOWN_SPEAKER.to_owned(), said_by)),
        tools: Vec::new(),
        alias: None,
    })
}

impl SlackWorkspace {
    /// Applies the owner's member map: a member mapped to a PERSON reads
    /// its conversations, the owner's own member reads as the importer and
    /// its words land as the owner's, and every other member stays a
    /// contact who reads nothing.
    ///
    /// # Errors
    ///
    /// [`IngestError::InvalidDocumentField`] when the map names a member
    /// `users.json` does not list, or names the owner more than once.
    pub fn map_members(&mut self, map: &SlackMemberMap) -> IngestResult<SlackMemberCounts> {
        let listed: BTreeSet<&str> = self.members.iter().map(|m| m.id.as_str()).collect();
        if let Some(unknown) = map.keys().find(|id| !listed.contains(id.as_str())) {
            return Err(bad(format!(
                "members.{unknown} (no member of this workspace)"
            )));
        }
        let owners: Vec<&String> = map
            .iter()
            .filter(|(_, mapping)| **mapping == SlackMemberMapping::Owner)
            .map(|(id, _)| id)
            .collect();
        if owners.len() > 1 {
            return Err(bad(format!(
                "members.{} (\"owner\" names one member)",
                owners[1]
            )));
        }
        let owner_said_by = owners.first().map(|id| said_by(id));
        for conversation in &mut self.conversations {
            if let Some(sharing) = &mut conversation.sharing {
                for member in &mut sharing.members {
                    let mapping = map.get(&member.provider_id).copied();
                    member.person = match mapping {
                        Some(SlackMemberMapping::Person(person)) => Some(person),
                        _ => None,
                    };
                    member.importer = mapping == Some(SlackMemberMapping::Owner);
                }
            }
            if let Some(owner) = &owner_said_by {
                for message in &mut conversation.messages {
                    if message.said_by.as_ref() == Some(owner) {
                        message.said_by = None;
                    }
                }
            }
        }
        let mut counts = SlackMemberCounts::default();
        for member in &self.members {
            match map.get(&member.id) {
                Some(SlackMemberMapping::Owner) => continue,
                Some(SlackMemberMapping::Person(_)) => counts.matched += 1,
                Some(SlackMemberMapping::Contact) | None => counts.contacts += 1,
            }
            counts.members += 1;
        }
        Ok(counts)
    }

    /// The workspace's members as the member table keeps them, mapped as
    /// [`Self::map_members`] maps them.
    #[must_use]
    pub fn mapped_members(&self, map: &SlackMemberMap) -> Vec<HistoryMember> {
        self.members
            .iter()
            .map(|member| {
                let mapping = map.get(&member.id).copied();
                HistoryMember {
                    provider_id: member.id.clone(),
                    name: Some(member.name.clone()),
                    person: match mapping {
                        Some(SlackMemberMapping::Person(person)) => Some(person),
                        _ => None,
                    },
                    importer: mapping == Some(SlackMemberMapping::Owner),
                }
            })
            .collect()
    }
}

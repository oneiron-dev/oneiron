//! `vault.secrets.found.list` (Engine RULING 14 Nov 11:39,
//! PLAN-L6-03-WRITER-FOUND-KEY-LIST = A): the found keys a caller may
//! answer, a page at a time, under a live person's own proof. The owner
//! reads every key, record by record, on the owner's card, as
//! `GET /v1/owner/secrets/found` lists them. Any other person reads only
//! the keys whose values they wrote in their own name, on value-free cards
//! ([`Vault::found_keys_written_by_page`]): a card names its record and its
//! place only while that person can still read the record; otherwise the
//! place reads [`UNREADABLE_PLACE`] and no record is named. No agent Grant
//! reaches the list: an agent's write records no writer, and an agent's
//! handle is refused before the read. An embedded handle reads as the
//! embedded owner, or as the handle's own person.

use serde::{Deserialize, Serialize};

use super::found_key_answer::{FoundKeySettledReply, answerer_proof};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::secret_custody::{
    FoundKeyCard, FoundKeyCursor, FoundKeyNotice, WrittenFoundKeyCard, WrittenFoundKeyCursor,
};
use crate::{EntityId, Vault};

/// The verb that lists the found keys a caller may answer.
const LIST_VERB: &str = "vault.secrets.found.list";

/// A page's size when the request names none, as the owner's route reads.
const DEFAULT_PAGE: u32 = 50;

/// The most keys or records one page lists, as the owner's route reads; a
/// larger limit is served a page of this many.
const MAX_PAGE: u32 = 200;

/// Where a writer's card says the key sat when they can no longer read its
/// record (RULING 11:39).
pub const UNREADABLE_PLACE: &str = "a place you can no longer read";

/// The list's input: the query `GET /v1/owner/secrets/found` takes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeyListRequest {
    /// Only the keys no one has answered yet: for the owner, the records
    /// holding one.
    #[serde(default)]
    pub open_only: bool,
    /// The `next_cursor` of the page before; from the newest when absent.
    #[serde(default)]
    pub after: Option<String>,
    /// At most this many a page, newest first: 50 when unset, and 200 a
    /// page past that.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One page of the found keys the caller may answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeyListReply {
    /// `owner`: every key, record by record, in `notices`. `writer`: the
    /// caller's own keys, in `keys`.
    pub view: String,
    /// The owner's list: each record with its keys, newest first. Empty in
    /// the writer's view.
    pub notices: Vec<FoundKeyNoticeReply>,
    /// The writer's list: each key whose value the caller wrote, newest
    /// first. Empty in the owner's view.
    pub keys: Vec<WrittenFoundKeyReply>,
    /// The next page's `after`; absent once `done`.
    pub next_cursor: Option<String>,
    /// Nothing under this filter is left after this page.
    pub done: bool,
}

/// One record's keys on the owner's card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeyNoticeReply {
    /// The record, or the file's ASSET.
    pub record: EntityId,
    pub keys: Vec<FoundKeyCardReply>,
}

/// One found key on the owner's card: its handle, never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeyCardReply {
    /// The handle the record holds, such as `sc12`.
    pub handle: String,
    /// The custody record's name; the rotate door takes it.
    pub name: String,
    /// The owner's display label, when one is set.
    pub label: Option<String>,
    /// The value-free suggestion derived from the scan kind.
    pub suggested_label: Option<String>,
    /// The scan rule's word for the key, such as `openai_key`.
    pub kind: String,
    /// Where it sat: `body`, `claim`, `text:<field>`, `file`, or a row
    /// outside the entity tables.
    pub place: String,
    pub found_at: u64,
    pub settled: Option<FoundKeySettledReply>,
    /// The native action names: what the owner may still do about it.
    pub actions: Vec<String>,
    /// What is true of one that needs no answer though it is open, such as
    /// a seal of bytes the file no longer holds.
    pub note: Option<String>,
}

/// One found key on its writer's card: no value, custody name, label,
/// receipt or grant, and none of the owner's own answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WrittenFoundKeyReply {
    /// The handle the record holds, such as `sc12`; both answer verbs take
    /// it.
    pub handle: String,
    /// The scan rule's word for the key, such as `openai_key`.
    pub kind: String,
    /// The record it was found in, while the caller can still read it.
    pub record: Option<EntityId>,
    /// Where it sat in that record, or [`UNREADABLE_PLACE`] when no record
    /// is named.
    pub place: String,
    pub found_at: u64,
    pub settled: Option<WrittenFoundKeySettledReply>,
    /// What the writer may still answer: `not_a_secret`, `kept_as_text`.
    pub actions: Vec<String>,
}

/// What was done about a writer's key, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WrittenFoundKeySettledReply {
    /// `rotate`, `delete`, `grant`, `not_a_secret` or `kept_as_text`.
    pub action: String,
    /// When it was settled, on the vault's clock.
    pub at: u64,
}

impl From<FoundKeyNotice> for FoundKeyNoticeReply {
    fn from(notice: FoundKeyNotice) -> Self {
        Self {
            record: notice.record,
            keys: notice
                .keys
                .into_iter()
                .map(FoundKeyCardReply::from)
                .collect(),
        }
    }
}

impl From<FoundKeyCard> for FoundKeyCardReply {
    fn from(card: FoundKeyCard) -> Self {
        Self {
            handle: card.handle,
            name: card.name,
            label: card.label,
            suggested_label: card.suggested_label,
            kind: card.kind,
            place: card.place,
            found_at: card.found_at,
            settled: card.settled.map(FoundKeySettledReply::from),
            actions: card
                .actions
                .into_iter()
                .map(|action| action.as_str().to_owned())
                .collect(),
            note: card.note,
        }
    }
}

impl From<WrittenFoundKeyCard> for WrittenFoundKeyReply {
    fn from(card: WrittenFoundKeyCard) -> Self {
        Self {
            handle: card.handle,
            kind: card.kind,
            place: card.place.unwrap_or_else(|| UNREADABLE_PLACE.to_owned()),
            record: card.record,
            found_at: card.found_at,
            settled: card.settled.map(|settled| WrittenFoundKeySettledReply {
                action: settled.action.as_str().to_owned(),
                at: settled.at,
            }),
            actions: card
                .actions
                .into_iter()
                .map(|action| action.as_str().to_owned())
                .collect(),
        }
    }
}

impl FoundKeyListReply {
    /// The records this page names, each once: every notice's record for
    /// the owner, and for a writer only the records their cards name.
    #[must_use]
    pub fn named_records(&self) -> Vec<EntityId> {
        let mut named: Vec<EntityId> = self
            .notices
            .iter()
            .map(|notice| notice.record)
            .chain(self.keys.iter().filter_map(|key| key.record))
            .collect();
        named.sort_unstable();
        named.dedup();
        named
    }
}

/// `vault.secrets.found.list` under `person`'s proof. A proof that holds at
/// the owner tier reads the owner's list; any other live person's reads
/// their own keys. Each list rechecks its proof live in its own read.
///
/// # Errors
/// A malformed `after`; a proof that is not a live person's of this vault;
/// and every refusal of [`Vault::found_keys_page`] or
/// [`Vault::found_keys_written_by_page`].
pub fn list_found_keys_as(
    vault: &Vault,
    person: &AuthenticatedOwner,
    input: FoundKeyListRequest,
) -> MemoryResult<FoundKeyListReply> {
    let limit =
        usize::try_from(input.limit.unwrap_or(DEFAULT_PAGE).min(MAX_PAGE)).unwrap_or(usize::MAX);
    let after = input.after.as_deref();
    let owner = match person.revalidate(vault) {
        Ok(_) => true,
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))) => false,
        Err(error) => return Err(error.into()),
    };
    if owner {
        let after = after
            .map(|text| FoundKeyCursor::parse(text).ok_or_else(bad_cursor))
            .transpose()?;
        let page = vault.found_keys_page(person, input.open_only, after, limit)?;
        return Ok(FoundKeyListReply {
            view: "owner".to_owned(),
            notices: page.notices.into_iter().map(Into::into).collect(),
            keys: Vec::new(),
            next_cursor: page.next_cursor.map(FoundKeyCursor::to_text),
            done: page.done,
        });
    }
    let after = after
        .map(|text| WrittenFoundKeyCursor::parse(text).ok_or_else(bad_cursor))
        .transpose()?;
    let page = vault.found_keys_written_by_page(person, input.open_only, after.as_ref(), limit)?;
    Ok(FoundKeyListReply {
        view: "writer".to_owned(),
        notices: Vec::new(),
        keys: page.keys.into_iter().map(Into::into).collect(),
        next_cursor: page.next_cursor.map(|cursor| cursor.to_text()),
        done: page.done,
    })
}

/// `vault.secrets.found.list` on an embedded handle: the embedded owner's
/// list, or the handle's own person's keys (their presented slip, or a
/// native call). An agent's handle is refused.
///
/// # Errors
/// A handle that is neither the owner's nor a person's own, and as
/// [`list_found_keys_as`].
pub fn list_found_keys_embedded(
    memory: &Memory<'_>,
    input: FoundKeyListRequest,
) -> MemoryResult<FoundKeyListReply> {
    list_found_keys_as(memory.vault(), &answerer_proof(memory, LIST_VERB)?, input)
}

fn bad_cursor() -> MemoryError {
    MemoryError::bad_request("after is not a found-key page's next_cursor")
}

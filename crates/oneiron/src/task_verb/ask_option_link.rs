//! Per-revision, per-person bearer ingress for generic ask options (no page UI).
//!
//! Only token digests are stored. The bearer can read its own disclosed options,
//! answer once, or void itself; it does not authenticate a general actor session.

use super::ConsultPayloadRef;
use super::ask_record;
use super::{TaskAskAnswer, TaskAskHandle, TaskAskOptionId, TaskAskWord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One bearer row. Key: blake3 hash32 of the token.
const LINKS: SideTable<[u8; 32], LinkRow, Named> =
    SideTable::new(&side_table::TASK_ASK_OPTION_LINK);
/// A person's current bearer. Key: id16 (group) + id16 (person).
const SEATS: SideTable<(EntityId, EntityId), SeatedLink, Raw> =
    SideTable::new(&side_table::TASK_ASK_OPTION_SEAT);
/// `b"1"` marker that a person voided their link. Key: id16 (group) + id16 (person).
const VOIDS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::TASK_ASK_OPTION_VOID);
/// An ask group's void generation. Key: id16 (group).
const VOID_GENERATIONS: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::TASK_ASK_OPTION_VOID_GENERATION);
/// The highest void generation a durable bridge receipt acknowledged. Key: id16 (group).
const VOID_ACKS: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::TASK_ASK_OPTION_VOID_ACK);

/// A seat's value: the full stored key of the person's current bearer row.
struct SeatedLink([u8; 32]);

impl RawValue for SeatedLink {
    fn to_raw(&self) -> Result<Vec<u8>, CodecError> {
        Ok(LINKS.key_bytes(&self.0))
    }

    fn from_raw(bytes: &[u8]) -> Result<Self, CodecError> {
        bytes
            .strip_prefix(LINKS.decl().prefix)
            .and_then(|digest| digest.try_into().ok())
            .map(Self)
            .ok_or_else(|| ask_record::invalid().into())
    }
}

fn counter_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    table: SideTable<EntityId, u64, Raw>,
    group: EntityId,
) -> crate::Result<u64> {
    Ok(table.get(&vault.store, txn, &group)?.unwrap_or(0))
}

/// A local, monotone change generation. It is not an answer or settlement.
pub(super) fn option_void_generation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
) -> crate::Result<u64> {
    counter_in(vault, txn, VOID_GENERATIONS, group)
}

pub(crate) fn option_void_generation(vault: &Vault, group: EntityId) -> crate::Result<u64> {
    let txn = vault.store.env.read_txn()?;
    option_void_generation_in(vault, &txn, group)
}

pub(crate) fn has_option_link_void(vault: &Vault, group: EntityId) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(counter_in(vault, &txn, VOID_GENERATIONS, group)?
        > counter_in(vault, &txn, VOID_ACKS, group)?)
}

/// Only a prior DURABLE code-run bridge receipt can acknowledge a generation.
/// A crashed or unrecorded Changed result never advances this cursor.
pub(crate) fn ack_option_void_generation(
    vault: &Vault,
    group: EntityId,
    observed: u64,
) -> crate::Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    let generation = counter_in(vault, &txn, VOID_GENERATIONS, group)?;
    if observed > generation {
        return Err(ask_record::invalid());
    }
    if observed > counter_in(vault, &txn, VOID_ACKS, group)? {
        VOID_ACKS.put(&vault.store, &mut txn, &group, &observed)?;
    }
    txn.commit()?;
    Ok(())
}

/// A bearer secret; deliver only to the intended person. The host builds the URL.
pub struct TaskAskOptionLink {
    pub token: String,
    pub intended_recipient: EntityId,
}

/// Generic, recipient-bound page data. IDs are the AskSpec's stable option IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskOptionLinkView {
    pub ask: TaskAskHandle,
    pub intended_recipient: EntityId,
    pub revision: u64,
    pub label: Option<String>,
    pub options: BTreeMap<TaskAskOptionId, String>,
    /// Sources the intended recipient may select as provenance for a tap.
    pub disclosed_sources: BTreeSet<ConsultPayloadRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkRow {
    group: EntityId,
    friend: EntityId,
    revision: u64,
    state: LinkState,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LinkState {
    Open,
    Answered {
        option: TaskAskOptionId,
        answer: TaskAskAnswer,
    },
    Voided,
}

/// The stored digest of a bearer token; the token itself is never stored.
fn token_digest(token: &str) -> MemoryResult<[u8; 32]> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MemoryError::bad_request("invalid ask option link"));
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.tasks.ask.option_link.v1\0");
    hash.update(token.as_bytes());
    Ok(*hash.finalize().as_bytes())
}

fn read_row(vault: &Vault, txn: &heed::RoTxn<'_>, digest: &[u8; 32]) -> MemoryResult<LinkRow> {
    let raw = LINKS
        .get_bytes(&vault.store, txn, digest)?
        .ok_or_else(|| MemoryError::bad_request("unknown ask option link"))?;
    LINKS
        .decode_value(&raw)
        .map_err(|_| MemoryError::bad_request("invalid ask option link row"))
}

fn put_row(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
    row: &LinkRow,
) -> MemoryResult<()> {
    LINKS.put(&vault.store, txn, digest, row)?;
    Ok(())
}

fn live_group(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &LinkRow,
    require_open_ask: bool,
) -> MemoryResult<ask_record::AskGroup> {
    let group = ask_record::read_group(vault, txn, row.group)?
        .ok_or_else(|| MemoryError::bad_request("unknown ask"))?;
    if group.effective.what.revision != row.revision
        || !ask_record::owns_revision(vault, txn, row.group, &group)?
        || !group
            .members
            .iter()
            .any(|member| member.actor == row.friend.to_hex())
    {
        return Err(MemoryError::bad_request(
            "ask link is not bound to this revision and person",
        ));
    }
    super::ask_settlement::settle_in(vault, txn, row.group, vault.store.clock.now_recorded_at())?;
    if require_open_ask && super::ask_settlement::read_result(vault, txn, row.group)?.is_some() {
        return Err(MemoryError::bad_request("ask is already settled"));
    }
    Ok(group)
}

pub(super) fn voided_friends_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
    group: &ask_record::AskGroup,
) -> MemoryResult<Vec<EntityId>> {
    let mut voided = Vec::new();
    for member in &group.members {
        let friend = ask_record::entity(&member.actor)?;
        if VOIDS.contains(&vault.store, txn, &(group_ref, friend))? {
            voided.push(friend);
        }
    }
    Ok(voided)
}

impl Memory<'_> {
    /// Issues a new one-person bearer. Reissuing replaces that person's old link.
    pub fn tasks_ask_option_link(
        &self,
        ask: TaskAskHandle,
        friend: EntityId,
    ) -> MemoryResult<TaskAskOptionLink> {
        self.with_verified_actor_write_txn(|txn| {
            let group = ask_record::read_group(self.vault(), txn, ask.group_ref)?
                .ok_or_else(|| MemoryError::bad_request("unknown ask"))?;
            if group.owner != self.actor().to_hex()
                || group.effective.what.options.is_empty()
                || self.vault().get_entity_type_in_txn(txn, &friend)?
                    != Some(crate::registry::ENTITY_TYPE_PERSON)
            {
                return Err(MemoryError::bad_request(
                    "ask option links require an owner and a person with options",
                ));
            }
            let row = LinkRow {
                group: ask.group_ref,
                friend,
                revision: group.effective.what.revision,
                state: LinkState::Open,
            };
            live_group(self.vault(), txn, &row, true)?;
            let mut secret = [0_u8; 32];
            OsRng.fill_bytes(&mut secret);
            let token: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
            let digest = token_digest(&token)?;
            let seat = (ask.group_ref, friend);
            if let Some(SeatedLink(previous)) = SEATS.get(&self.vault().store, txn, &seat)? {
                LINKS.delete(&self.vault().store, txn, &previous)?;
            }
            put_row(self.vault(), txn, &digest, &row)?;
            SEATS.put(&self.vault().store, txn, &seat, &SeatedLink(digest))?;
            Ok(TaskAskOptionLink {
                token,
                intended_recipient: friend,
            })
        })
    }
}

impl Memory<'_> {
    /// Recipient identities whose option links were voided; the agent can
    /// inspect this typed signal after the ask handle wakes.
    pub fn tasks_ask_option_link_voids(&self, ask: TaskAskHandle) -> MemoryResult<Vec<EntityId>> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = ask_record::read_group(self.vault(), &txn, ask.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask"))?;
        if group.owner != self.actor().to_hex() {
            return Err(MemoryError::bad_request(
                "only the asking actor may read link voids",
            ));
        }
        voided_friends_in_txn(self.vault(), &txn, ask.group_ref, &group)
    }
}

impl Vault {
    /// The bearer sees only the named recipient and the options of its pinned ask.
    pub fn ask_option_link_view(&self, token: &str) -> MemoryResult<TaskAskOptionLinkView> {
        let digest = token_digest(token)?;
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let row = read_row(self, &txn, &digest)?;
        if !matches!(row.state, LinkState::Open) {
            return Err(MemoryError::bad_request(
                "ask option link is no longer open",
            ));
        }
        let group = ask_record::read_group(self, &txn, row.group)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask"))?;
        if group.effective.what.revision != row.revision
            || !ask_record::owns_revision(self, &txn, row.group, &group)?
            || !group
                .members
                .iter()
                .any(|member| member.actor == row.friend.to_hex())
            || super::ask_settlement::is_stale(self, &txn, &group)?
        {
            return Err(MemoryError::bad_request(
                "ask option link is no longer open",
            ));
        }
        Ok(TaskAskOptionLinkView {
            ask: TaskAskHandle {
                group_ref: row.group,
            },
            intended_recipient: row.friend,
            revision: row.revision,
            label: group.effective.what.label.clone(),
            options: group.effective.what.options,
            disclosed_sources: std::iter::once(group.effective.what.reference)
                .chain(group.effective.what.context_refs)
                .collect(),
        })
    }

    /// Records a bearer-bound foreign-stated word; never grants effect authority.
    pub fn answer_ask_option_link(
        &self,
        token: &str,
        option: &TaskAskOptionId,
    ) -> MemoryResult<TaskAskAnswer> {
        self.answer_ask_option_link_with_sources(token, option, &BTreeSet::new())
    }

    /// The bearer explicitly selects source refs disclosed on its page; an
    /// answer cannot silently claim to have cited a required source.
    pub fn answer_ask_option_link_with_sources(
        &self,
        token: &str,
        option: &TaskAskOptionId,
        source_refs: &BTreeSet<ConsultPayloadRef>,
    ) -> MemoryResult<TaskAskAnswer> {
        let digest = token_digest(token)?;
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut row = read_row(self, &txn, &digest)?;
        if !matches!(row.state, LinkState::Open) {
            return Err(MemoryError::bad_request(
                "ask option link is no longer open",
            ));
        }
        let group = live_group(self, &mut txn, &row, false)?;
        if !group.effective.what.options.contains_key(option) {
            return Err(MemoryError::bad_request("unknown ask option id"));
        }
        let disclosed: BTreeSet<_> = std::iter::once(group.effective.what.reference)
            .chain(group.effective.what.context_refs.iter().copied())
            .collect();
        if !source_refs.is_subset(&disclosed)
            || group
                .effective
                .class
                .as_ref()
                .is_some_and(|class| !class.required_sources.is_subset(source_refs))
        {
            return Err(MemoryError::bad_request(
                "ask answer needs disclosed source refs",
            ));
        }
        let now = self.store.clock.now_recorded_at();
        let word = TaskAskWord {
            result_ref: row.friend,
            option: Some(option.clone()),
            inform_for: None,
            companion_for: None,
            confirmation: None,
            provenance_refs: source_refs.clone(),
        };
        let answer = ask_record::admit_link_word(
            self,
            &mut txn,
            row.group,
            &group,
            (row.friend, digest),
            &word,
            now,
        )?;
        super::lifecycle_facade::complete_ask_member_in_txn(self, &mut txn, answer, &word, now)?;
        row.state = LinkState::Answered {
            option: option.clone(),
            answer,
        };
        put_row(self, &mut txn, &digest, &row)?;
        super::ask_settlement::settle_in(self, &mut txn, row.group, now)?;
        super::ask_facade::signal_waiters(self, &mut txn, row.group, now.saturating_mul(1000))?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(answer)
    }

    /// "Not you?" revokes this one bearer and wakes the asking agent.
    pub fn void_ask_option_link(&self, token: &str) -> MemoryResult<()> {
        let digest = token_digest(token)?;
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut row = read_row(self, &txn, &digest)?;
        if !matches!(row.state, LinkState::Voided) {
            row.state = LinkState::Voided;
            put_row(self, &mut txn, &digest, &row)?;
            let next = counter_in(self, &txn, VOID_GENERATIONS, row.group)?
                .checked_add(1)
                .ok_or_else(|| MemoryError::bad_request("ask void generation exhausted"))?;
            VOID_GENERATIONS.put(&self.store, &mut txn, &row.group, &next)?;
        }
        let group = row.group;
        VOIDS.put(&self.store, &mut txn, &(group, row.friend), b"1")?;
        super::ask_facade::signal_waiters(
            self,
            &mut txn,
            group,
            self.store.clock.now_recorded_at().saturating_mul(1000),
        )?;
        txn.commit().map_err(crate::Error::from)?;
        // The marker committed first. A crash here is recovered by the peer
        // wait binding's ordinary reconcile pass, including void-before-wait.
        crate::llm::send_peer_result_signal(self, group, self.store.clock.now_recorded_at())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

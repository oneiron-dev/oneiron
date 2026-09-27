//! Per-revision, per-person bearer ingress for generic ask options (no page UI).
//!
//! Only token digests are stored. The bearer can read its own disclosed options,
//! answer once, or void itself; it does not authenticate a general actor session.

use super::ask_record;
use super::{TaskAskAnswer, TaskAskHandle, TaskAskOptionId, TaskAskWord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const TOKEN_PREFIX: &[u8] = b"tasks.ask.option_link.v1:";
const SEAT_PREFIX: &[u8] = b"tasks.ask.option_seat.v1:";
const VOID_PREFIX: &[u8] = b"tasks.ask.option_void.v1:";

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

fn token_key(token: &str) -> MemoryResult<Vec<u8>> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MemoryError::bad_request("invalid ask option link"));
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.tasks.ask.option_link.v1\0");
    hash.update(token.as_bytes());
    let mut key = TOKEN_PREFIX.to_vec();
    key.extend_from_slice(hash.finalize().as_bytes());
    Ok(key)
}

fn seat_key(group: EntityId, friend: EntityId) -> Vec<u8> {
    let mut key = SEAT_PREFIX.to_vec();
    key.extend_from_slice(group.as_bytes());
    key.extend_from_slice(friend.as_bytes());
    key
}

fn void_key(group: EntityId, friend: EntityId) -> Vec<u8> {
    let mut key = VOID_PREFIX.to_vec();
    key.extend_from_slice(group.as_bytes());
    key.extend_from_slice(friend.as_bytes());
    key
}

fn read_row(vault: &Vault, txn: &heed::RoTxn<'_>, key: &[u8]) -> MemoryResult<LinkRow> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, key)?
        .ok_or_else(|| MemoryError::bad_request("unknown ask option link"))?;
    rmp_serde::from_slice(&raw).map_err(|_| MemoryError::bad_request("invalid ask option link row"))
}

fn put_row(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    row: &LinkRow,
) -> MemoryResult<()> {
    let bytes = rmp_serde::to_vec_named(row)
        .map_err(|_| MemoryError::bad_request("invalid ask option link row"))?;
    vault.store.vault_meta.put(txn, key, &bytes)?;
    Ok(())
}

fn live_group(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &LinkRow,
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
    if super::ask_settlement::read_result(vault, txn, row.group)?.is_some() {
        return Err(MemoryError::bad_request("ask is already settled"));
    }
    Ok(group)
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
            live_group(self.vault(), txn, &row)?;
            let mut secret = [0_u8; 32];
            OsRng.fill_bytes(&mut secret);
            let token: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
            let key = token_key(&token)?;
            let seat = seat_key(ask.group_ref, friend);
            if let Some(previous) = self
                .vault()
                .store
                .vault_meta
                .get(txn, &seat)?
                .map(std::borrow::Cow::into_owned)
            {
                self.vault().store.vault_meta.delete(txn, &previous)?;
            }
            put_row(self.vault(), txn, &key, &row)?;
            self.vault().store.vault_meta.put(txn, &seat, &key)?;
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
        let mut voided = Vec::new();
        for member in &group.members {
            let friend = ask_record::entity(&member.actor)?;
            if self
                .vault()
                .store
                .vault_meta
                .get(&txn, &void_key(ask.group_ref, friend))?
                .is_some()
            {
                voided.push(friend);
            }
        }
        Ok(voided)
    }
}

impl Vault {
    /// The bearer sees only the named recipient and the options of its pinned ask.
    pub fn ask_option_link_view(&self, token: &str) -> MemoryResult<TaskAskOptionLinkView> {
        let key = token_key(token)?;
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let row = read_row(self, &txn, &key)?;
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
            || super::ask_settlement::read_result(self, &txn, row.group)?.is_some()
            || group
                .effective
                .until
                .is_some_and(|until| self.store.clock.now_recorded_at() >= until)
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
        })
    }

    /// Records a bearer-bound foreign-stated word; never grants effect authority.
    pub fn answer_ask_option_link(
        &self,
        token: &str,
        option: &TaskAskOptionId,
    ) -> MemoryResult<TaskAskAnswer> {
        let key = token_key(token)?;
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut row = read_row(self, &txn, &key)?;
        if !matches!(row.state, LinkState::Open) {
            return Err(MemoryError::bad_request(
                "ask option link is no longer open",
            ));
        }
        let group = live_group(self, &mut txn, &row)?;
        if !group.effective.what.options.contains_key(option) {
            return Err(MemoryError::bad_request("unknown ask option id"));
        }
        let now = self.store.clock.now_recorded_at();
        let answer = ask_record::admit_link_word(
            self,
            &mut txn,
            row.group,
            &group,
            row.friend,
            &TaskAskWord {
                result_ref: row.friend,
                option: Some(option.clone()),
                inform_for: None,
                provenance_refs: Default::default(),
            },
            now,
        )?;
        row.state = LinkState::Answered {
            option: option.clone(),
            answer,
        };
        put_row(self, &mut txn, &key, &row)?;
        super::ask_settlement::settle_in(self, &mut txn, row.group, now)?;
        super::ask_facade::signal_waiters(self, &mut txn, row.group, now.saturating_mul(1000))?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(answer)
    }

    /// "Not you?" revokes this one bearer and wakes the asking agent.
    pub fn void_ask_option_link(&self, token: &str) -> MemoryResult<()> {
        let key = token_key(token)?;
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut row = read_row(self, &txn, &key)?;
        if !matches!(row.state, LinkState::Voided) {
            row.state = LinkState::Voided;
            put_row(self, &mut txn, &key, &row)?;
        }
        let group = row.group;
        self.store
            .vault_meta
            .put(&mut txn, &void_key(group, row.friend), b"1")?;
        super::ask_facade::signal_waiters(
            self,
            &mut txn,
            group,
            self.store.clock.now_recorded_at().saturating_mul(1000),
        )?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

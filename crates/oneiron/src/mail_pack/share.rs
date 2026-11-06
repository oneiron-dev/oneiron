//! Sharing one mail thread (owner ruling 2026-11-03, ARCH-0063
//! #thread-sharing): connecting a mailbox shares none of its threads; a
//! person who reads a thread shares it by an explicit act, and that act
//! never widens the mailbox itself. The share reaches every row of the
//! thread, its later messages and the facts learned from it included, and
//! nothing else of the source.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::source_audience;
use crate::{EntityId, Vault};

/// `vault.mail.threads.share` and `.unshare`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadShareRequest {
    /// A row of the thread: its CONVERSATION, or any message in it, 32-hex.
    pub record_ref: String,
    /// The PERSON the thread is shared with, or no longer shared with,
    /// 32-hex.
    pub person_ref: String,
}

/// What a share or an unshare did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadShareReceipt {
    /// The thread's audience policy, 32-hex.
    pub thread_ref: String,
    pub person_ref: String,
    /// Whether the thread is shared with the person after this act.
    pub shared: bool,
    /// Whether this act changed anything.
    pub changed: bool,
    /// Everyone the thread is shared with now, 32-hex.
    pub shared_with: Vec<String>,
}

/// The refusal for a thread the caller does not read.
fn unknown_thread() -> MemoryError {
    MemoryError::not_found("no mail thread by that ref")
}

/// The thread policy `record` was born under, if it is a thread's.
fn thread_of_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> MemoryResult<(EntityId, EntityId, BTreeSet<EntityId>)> {
    let thread = source_audience::binding_in(vault, txn, record)?.ok_or_else(unknown_thread)?;
    let (source, shared_with) =
        source_audience::thread_shares_in(vault, txn, &thread)?.ok_or_else(unknown_thread)?;
    Ok((thread, source, shared_with))
}

impl Memory<'_> {
    /// Shares one mail thread with a person, as the bound actor's explicit
    /// act: the actor must read the thread now, and the person must be a
    /// live PERSON. The act is kept as the thread's receipt.
    pub fn mail_threads_share(
        &self,
        input: &MailThreadShareRequest,
    ) -> MemoryResult<MailThreadShareReceipt> {
        self.mail_thread_share_edit(input, true)
    }

    /// Withdraws one share of a mail thread: by a reader of its source, by
    /// the person who shared it with that person, or by that person leaving.
    /// The person reads none of the thread from this commit on.
    pub fn mail_threads_unshare(
        &self,
        input: &MailThreadShareRequest,
    ) -> MemoryResult<MailThreadShareReceipt> {
        self.mail_thread_share_edit(input, false)
    }

    fn mail_thread_share_edit(
        &self,
        input: &MailThreadShareRequest,
        share: bool,
    ) -> MemoryResult<MailThreadShareReceipt> {
        let record = EntityId::from_hex(&input.record_ref)?;
        let person = EntityId::from_hex(&input.person_ref)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            super::pack::require_pack_active_in(vault, txn)?;
            let (thread, source, _) = thread_of_in(vault, txn, &record)?;
            if !source_audience::actor_reads_in(vault, txn, &thread, actor)? {
                return Err(unknown_thread());
            }
            if share {
                if crate::vault::live_entity_row_in_txn(&vault.store, txn, &person)?.live_type()
                    != Some(ENTITY_TYPE_PERSON)
                {
                    return Err(MemoryError::bad_request(
                        "a thread is shared with a live PERSON",
                    ));
                }
            } else {
                let leaving =
                    source_audience::names_reader_in(vault, txn, &BTreeSet::from([person]), actor)?;
                let reads_source = source_audience::actor_reads_in(vault, txn, &source, actor)?;
                let sharer = source_audience::events_in(vault, txn, &thread)?
                    .iter()
                    .rev()
                    .find(|event| {
                        event.op == source_audience::SourceAudienceOp::Shared
                            && event.person_ref.as_deref() == Some(person.to_hex().as_str())
                    })
                    .and_then(|event| event.by_ref.clone())
                    == Some(actor.to_hex());
                if !(leaving || reads_source || sharer) {
                    return Err(MemoryError::bad_request(
                        "a share is withdrawn by a reader of its source, by the person who shared it, or by the person it names",
                    ));
                }
            }
            let at = crate::unix_seconds_now();
            let changed =
                source_audience::share_thread_in_txn(vault, txn, &thread, person, share, actor, at)?;
            let (_, _, shared_with) = thread_of_in(vault, txn, &record)?;
            Ok(MailThreadShareReceipt {
                thread_ref: thread.to_hex(),
                person_ref: person.to_hex(),
                shared: shared_with.contains(&person),
                changed,
                shared_with: shared_with.iter().map(EntityId::to_hex).collect(),
            })
        })
    }
}

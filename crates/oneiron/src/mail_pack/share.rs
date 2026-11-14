//! Sharing one mail thread (owner ruling 2026-11-03, ARCH-0063
//! #thread-sharing): connecting a mailbox shares none of its threads; a
//! person who reads a thread shares it by an explicit act, and that act
//! never widens the mailbox itself. The share reaches every row of the
//! thread, its later messages and the facts learned from it included, and
//! nothing else of the source.

use std::collections::BTreeSet;

use crate::check_in::{self, WidenAct, WidenCheckIn};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::source_audience;
use crate::{EntityId, Error, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::share::{MailThreadShareReceipt, MailThreadShareRequest};

/// The saved verb a share is, as check-in judges it.
const SHARE_VERB: &str = "vault.mail.threads.share";

/// What one share or unshare's writer did.
enum ShareEdit {
    /// The act ran.
    Done(MailThreadShareReceipt),
    /// A member's share of another's thread waits on this pending check-in,
    /// committed alone.
    Waits(EntityId),
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
    ///
    /// Check-in judges a human's share in the same writer (ROLES-CHECKIN
    /// 2k8f; MEMBER-SHARE-OWN = B; `check_in::person_widen_check_in_in_txn`):
    /// the vault's Owner shares on their own proof; a reader of the thread's
    /// source, whose mail it is, shares it at once (`own_item`); a member
    /// who reads it only because it was shared with them is judged under
    /// their role, and a Member's share waits (`CHECK_IN_PENDING`) until the
    /// call that names the approved check-in as `check_in_ref` (a Steward
    /// holds no content write here, so it shares nothing, as on main). A
    /// share with a person the thread already names widens nothing and is
    /// not judged, as on main.
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
        let check_in_ref = match (input.check_in_ref.as_deref(), share) {
            (None, _) => None,
            (Some(_), false) => {
                return Err(MemoryError::bad_request(
                    "check_in_ref names a waiting share; an unshare waits on none",
                ));
            }
            (Some(hex), true) => Some(
                EntityId::from_hex(hex)
                    .map_err(|_| MemoryError::bad_request("check_in_ref is not a check-in id"))?,
            ),
        };
        let actor = self.actor();
        let class = self.actor_class();
        let edit = self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            super::pack::require_pack_active_in(vault, txn)?;
            let (thread, source, shared_before) = thread_of_in(vault, txn, &record)?;
            if !source_audience::actor_reads_in(vault, txn, &thread, actor)? {
                return Err(unknown_thread());
            }
            let check_in = if share {
                if crate::vault::live_entity_row_in_txn(&vault.store, txn, &person)?.live_type()
                    != Some(ENTITY_TYPE_PERSON)
                {
                    return Err(MemoryError::bad_request(
                        "a thread is shared with a live PERSON",
                    ));
                }
                if shared_before.contains(&person) {
                    // A share with a person the thread already names widens
                    // nothing: it is not judged, as on main, and waits on no
                    // check-in.
                    if check_in_ref.is_some() {
                        return Err(MemoryError::bad_request(
                            "check_in_ref names a member's waiting share of another's thread; \
                             this share widens nothing and waits on none",
                        ));
                    }
                    None
                } else {
                    // The source's readers are the people who own it.
                    let owns_item =
                        match source_audience::source_readers_in(vault, txn, &source)? {
                            Some(owners) => {
                                source_audience::names_reader_in(vault, txn, &owners, actor)?
                            }
                            None => false,
                        };
                    let widen = WidenAct {
                        actor,
                        class,
                        owns_item,
                        verb: SHARE_VERB,
                        effect_digest: check_in::mail_thread_share_effect_digest(
                            &thread, &person,
                        ),
                    };
                    match check_in::person_widen_check_in_in_txn(
                        vault,
                        txn,
                        &widen,
                        check_in_ref.as_ref(),
                    )? {
                        WidenCheckIn::Go(decision) => decision,
                        WidenCheckIn::Wait(id) => return Ok(ShareEdit::Waits(id)),
                    }
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
                None
            };
            let at = crate::unix_seconds_now();
            let changed =
                source_audience::share_thread_in_txn(vault, txn, &thread, person, share, actor, at)?;
            let (_, _, shared_with) = thread_of_in(vault, txn, &record)?;
            Ok(ShareEdit::Done(MailThreadShareReceipt {
                thread_ref: thread.to_hex(),
                person_ref: person.to_hex(),
                shared: shared_with.contains(&person),
                changed,
                shared_with: shared_with.iter().map(EntityId::to_hex).collect(),
                check_in,
            }))
        })?;
        match edit {
            ShareEdit::Done(receipt) => Ok(receipt),
            ShareEdit::Waits(id) => Err(Error::CheckInPending(id.to_hex()).into()),
        }
    }
}

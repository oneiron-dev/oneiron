//! Who an identity ask goes to (RECIPIENT-NOTICE-READ-BY-ANY-READER, owner
//! half PR 3; the lead 21 Nov 11:3x, OWNER-NOTICE-EXISTENCE Q2 = C, and
//! 13:2x, OWNER-NOTICE-MEMBER-ASK-ROUTE Q1 = A, Q2 = A).
//!
//! An ask quotes a saved mention, and every door reads it through its
//! caller's lane ([`super::admission`]). An ask every live owner's lane opens
//! goes to the owners, as before. One raised from a source some owner does
//! not read, such as a member's own mailbox, goes to every live person whose
//! lane opens it: the member, who knows who they meant. Each owner whose lane
//! does not open it gets a stub that names no ask, row or word: "a member
//! has a pending question about identity". When no one else opens it either,
//! the owners still get the stub, the ask stays open, and the nightly ladder
//! keeps the names apart.
//!
//! The people an ask may go to are the vault's live owners and every other
//! live person who holds an ordinary credential of their own (a paired
//! person or an accepted member), each judged under their own lane in the
//! sending write's snapshot.

use std::collections::BTreeSet;

use super::{IDENTITY_NOTIFICATION_PRODUCER, IdentityAsk, admission, key_hex};
use crate::authority::ACTOR_CLASS_HUMAN;
use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::voice_identity::HumanCredentialReach;
use crate::{EntityId, Error, Result, Vault};

/// The producer of the stub an owner gets for an ask his lane does not open.
/// It names no ask: `source.result` is empty.
pub const IDENTITY_MEMBER_QUESTION_PRODUCER: &str = "dreamer.identity.member_question";
/// The stub's words, the only words it carries.
const MEMBER_QUESTION_DETAIL: &str = "a member has a pending question about identity";
/// The domain of a stub's event id: a digest of the ask, the turn and the
/// owner, so a stub row is new per ask and turn as an Ask row is, and its
/// event names none of them.
const MEMBER_QUESTION_EVENT_DOMAIN: &[u8] = b"oneiron/identity-ask/member-question/v1";

/// Who one ask goes to, judged in one snapshot.
pub(super) struct AskRoute {
    /// Each live person whose lane opens the ask, who gets the Ask.
    pub(super) readers: Vec<EntityId>,
    /// Each live owner whose lane does not open it, who gets the stub.
    pub(super) closed_owners: Vec<EntityId>,
}

/// Where `ask` goes in `txn`: to the owners when every live owner's lane
/// opens it; else to every live person whose lane opens it, each owner who
/// cannot open it getting the stub.
pub(super) fn route_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<AskRoute> {
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut readers = Vec::new();
    let mut closed_owners = Vec::new();
    for owner in &owners {
        // The owner's own lane, held to the live-owner census in this
        // snapshot: it reads no row his own request would not.
        let read = vault.scoped_read(ScopedReadActorKey::vault_owner_by_census(*owner));
        if opens_in_txn(vault, &read, txn, ask)? {
            readers.push(*owner);
        } else {
            closed_owners.push(*owner);
        }
    }
    if closed_owners.is_empty() {
        return Ok(AskRoute {
            readers,
            closed_owners,
        });
    }
    for member in members_in_txn(vault, txn, &owners)? {
        if opens_in_txn(vault, &member_read(vault, member)?, txn, ask)? {
            readers.push(member);
        }
    }
    Ok(AskRoute {
        readers,
        closed_owners,
    })
}

/// Whether `person` is one an ask may go to beside the owners in `txn`: a
/// live person, no owner, who holds an ordinary credential of their own.
pub(super) fn is_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<bool> {
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    Ok(!owners.contains(&person)
        && crate::consent::person_is_live_in_txn(vault, txn, &person)?
        && vault.holds_live_human_credential_in_txn(txn, person, HumanCredentialReach::Ordinary)?)
}

/// The live people other than `owners` who hold an ordinary credential of
/// their own in `txn`.
fn members_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owners: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let mut members = BTreeSet::new();
    for person in vault.live_human_credential_holders_in_txn(txn, HumanCredentialReach::Ordinary)? {
        if !owners.contains(&person) && crate::consent::person_is_live_in_txn(vault, txn, &person)?
        {
            members.insert(person);
        }
    }
    Ok(members)
}

/// The human lane of `person`, who is no owner, as a credential of their own
/// reads: a row that names a relationship or a private scope only on their
/// live grants, the vault's own unscoped rows open, and a source-bound row
/// only when its source policy names them.
fn member_read(vault: &Vault, person: EntityId) -> Result<ScopedRead<'_>> {
    let key = ScopedReadActorKey::with_actor_class(person.to_hex(), ACTOR_CLASS_HUMAN)
        .ok_or_else(|| Error::InvalidConfig("an identity ask's reader has no read key".into()))?
        .require_relationship_grants(Some(person));
    Ok(vault.scoped_read(key))
}

/// Whether `read` opens `ask` in `txn`, as the doors that list, render and
/// answer it do.
fn opens_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<bool> {
    let admit = admission::Admit::in_txn(read, txn)?;
    Ok(admission::admitted_in_txn(vault, &admit, txn, ask.clone())?.is_some())
}

/// One inbox Ask per reader [`route_in_txn`] finds, in the conversation of
/// `turn`, and one stub per owner who cannot open `ask`: a new row per ask
/// and turn, so a later mention surfaces it again.
pub(super) fn notify_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
    turn: &EntityId,
    now: u64,
) -> Result<()> {
    let route = route_in_txn(vault, txn, ask)?;
    let conversation = crate::conversation_dag::conversation_of(&vault.store, txn, turn).ok();
    let hex = key_hex(key);
    for reader in route.readers {
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: IDENTITY_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{hex}:{}:{}", turn.to_hex(), reader.to_hex()),
                    result: Some(hex.clone()),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(reader),
                created_at: now,
                origin_conversation: conversation,
            },
        )?;
    }
    for owner in route.closed_owners {
        let event = EntityId::derive(
            MEMBER_QUESTION_EVENT_DOMAIN,
            &[
                key.as_slice(),
                turn.as_bytes().as_slice(),
                owner.as_bytes().as_slice(),
            ],
        )?;
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: IDENTITY_MEMBER_QUESTION_PRODUCER.to_owned(),
                    event: event.to_hex(),
                    detail: Some(MEMBER_QUESTION_DETAIL.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(owner),
                created_at: now,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

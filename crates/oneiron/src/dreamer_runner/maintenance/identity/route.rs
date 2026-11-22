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
    route_reading_in_txn(vault, txn, ask, None)
}

/// [`route_in_txn`], where a reader whose lane opens `ask` gets its Ask only
/// when that lane also reads `source` (a turn and its message), when one is
/// named: the later mention a resurfaced Ask is placed at. An owner who
/// opens the ask but not that mention gets nothing this time, as a member
/// who does not; the stubs go as [`route_in_txn`] sends them.
fn route_reading_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
    source: Option<(&EntityId, &EntityId)>,
) -> Result<AskRoute> {
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut readers = Vec::new();
    let mut closed_owners = Vec::new();
    for owner in &owners {
        // The owner's own lane, held to the live-owner census in this
        // snapshot: it reads no row his own request would not.
        let read = vault.scoped_read(ScopedReadActorKey::vault_owner_by_census(*owner));
        match opens_in_txn(vault, &read, txn, ask, source)? {
            Opens::AskAndSource => readers.push(*owner),
            Opens::AskOnly => {}
            Opens::Not => closed_owners.push(*owner),
        }
    }
    if closed_owners.is_empty() {
        return Ok(AskRoute {
            readers,
            closed_owners,
        });
    }
    for member in members_in_txn(vault, txn, &owners)? {
        let read = member_read(vault, member)?;
        if opens_in_txn(vault, &read, txn, ask, source)? == Opens::AskAndSource {
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
/// only when its source policy names them. It reaches every member whose
/// answer door opens the ask. A credential narrowed further (to some records
/// or channels) may read less: such a member gets an Ask their door then
/// finds absent. No word travels with it, and the answer is judged again
/// under their own credential.
fn member_read(vault: &Vault, person: EntityId) -> Result<ScopedRead<'_>> {
    let key = ScopedReadActorKey::with_actor_class(person.to_hex(), ACTOR_CLASS_HUMAN)
        .ok_or_else(|| Error::InvalidConfig("an identity ask's reader has no read key".into()))?
        .require_relationship_grants(Some(person));
    Ok(vault.scoped_read(key))
}

/// What one lane opens of an ask and the mention its Ask is placed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opens {
    /// The ask, and the mention when one is named.
    AskAndSource,
    /// The ask, but not the named mention.
    AskOnly,
    /// Not the ask.
    Not,
}

/// Whether `read` opens `ask` in `txn`, as the doors that list, render and
/// answer it do, and `source` (a turn and its message) when one is named.
fn opens_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
    source: Option<(&EntityId, &EntityId)>,
) -> Result<Opens> {
    let admit = admission::Admit::in_txn(read, txn)?;
    if admission::admitted_in_txn(vault, &admit, txn, ask.clone())?.is_none() {
        return Ok(Opens::Not);
    }
    let Some((turn, message)) = source else {
        return Ok(Opens::AskAndSource);
    };
    Ok(if admit.reads_source(txn, turn, message)? {
        Opens::AskAndSource
    } else {
        Opens::AskOnly
    })
}

/// One inbox Ask per reader [`route_in_txn`] finds, in the conversation of
/// `turn`, and one stub per owner who cannot open `ask`: a new row per ask
/// and turn, so a later mention surfaces it again. The Ask names `turn` and
/// its conversation, so when `turn` is a later mention (with `message`)
/// than the ask's own, it goes only to a reader whose lane reads that
/// mention too.
pub(super) fn notify_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
    (turn, message): (&EntityId, &EntityId),
    now: u64,
) -> Result<()> {
    let later = (*turn, *message) != (ask.turn, ask.message);
    let route = route_reading_in_txn(vault, txn, ask, later.then_some((turn, message)))?;
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

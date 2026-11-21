//! A member's "someone new" (RECIPIENT-NOTICE-READ-BY-ANY-READER, owner half
//! PR 3b; the lead 21 Nov 13:2x, OWNER-NOTICE-MEMBER-ASK-ROUTE Q1 = A).
//!
//! "Someone new" confirms the mention's person and asserts it distinct from
//! every candidate, the ones a member cannot read included, so a member's
//! someone-new answer settles nothing. It is a decision-only proposal to the
//! owners: each live owner gets an inbox Ask that carries the provisional
//! and candidate ids, with no name, excerpt or conversation, and offers one
//! tap while the proposal stands. The tap answers `someone_new` through
//! `self.identity.answer`, which applies the proposal as the owner's own
//! decision without his lane reading the ask.
//!
//! The proposal stands on the ask itself, so whatever closes or opens the
//! ask afresh (an answer, an erase, a changed candidate set) drops it. From
//! the proposal on, the ask waits on a person: the ladder no longer decides
//! it.

use super::{ASKS, IdentityAsk, SOMEONE_NEW, key_hex, parse_key};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::{EntityId, Result, Vault};

/// The producer of an owner's notice of a member's someone-new proposal.
/// `source.result` names the ask the tap answers; `subject_refs` are the
/// ids the decision is about.
pub const IDENTITY_SOMEONE_NEW_PROPOSAL_PRODUCER: &str = "dreamer.identity.someone_new_proposal";
/// The notice's words, the only words it carries.
const SOMEONE_NEW_PROPOSAL_DETAIL: &str =
    "a member answered a pending question about identity: someone new";
/// The domain of a notice's event id: a digest of the ask, the owner and the
/// proposal's time, so a proposal made again after the ask opened afresh
/// gets a notice of its own.
const SOMEONE_NEW_PROPOSAL_EVENT_DOMAIN: &[u8] = b"oneiron/identity-ask/someone-new-proposal/v1";

/// The ids a proposal on `ask` puts to the owner: the mention's own
/// provisional person first, when it has one, then every other candidate.
fn proposal_refs(ask: &IdentityAsk) -> Vec<EntityId> {
    let mut refs: Vec<EntityId> = ask.provisional.into_iter().collect();
    refs.extend(
        ask.candidates
            .iter()
            .copied()
            .filter(|id| Some(*id) != ask.provisional),
    );
    refs
}

/// Records a member's someone-new answer to the ask `key` (`held`, as
/// stored) as a proposal at `now`, and sends it to every live owner. A
/// proposal that already stands is kept as it was.
pub(super) fn propose_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    mut held: IdentityAsk,
    now: u64,
) -> Result<()> {
    if held.someone_new_proposed_at.is_some() {
        return Ok(());
    }
    held.someone_new_proposed_at = Some(now);
    // A person answered: the ask waits on the owner, not on the ladder.
    if held.escalated_at.is_none() {
        held.escalated_at = Some(now);
    }
    // No membership sync (FIX 10376): both stamps name no id the ask's erase
    // reads.
    ASKS.put(&vault.store, txn, key, &held)?;
    let refs = proposal_refs(&held);
    let at = now.to_be_bytes();
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        let event = EntityId::derive(
            SOMEONE_NEW_PROPOSAL_EVENT_DOMAIN,
            &[key.as_slice(), owner.as_bytes().as_slice(), at.as_slice()],
        )?;
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: IDENTITY_SOMEONE_NEW_PROPOSAL_PRODUCER.to_owned(),
                    event: event.to_hex(),
                    result: Some(key_hex(key)),
                    detail: Some(SOMEONE_NEW_PROPOSAL_DETAIL.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: refs.clone(),
                recipient: Some(owner),
                created_at: now,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

/// The ask `key`, as stored, that an owner's `choice` accepts: only "someone
/// new", on an ask a member's proposal stands on.
pub(super) fn accepted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    choice: &str,
) -> Result<Option<IdentityAsk>> {
    if choice != SOMEONE_NEW {
        return Ok(None);
    }
    Ok(ASKS
        .get(&vault.store, txn, key)?
        .filter(|ask| ask.someone_new_proposed_at.is_some()))
}

impl Vault {
    /// The ids a member's someone-new proposal on `ask` (64 hex) puts to the
    /// owner while it stands; none once it is gone.
    pub(crate) fn identity_someone_new_proposal_refs(
        &self,
        ask: &str,
    ) -> Result<Option<Vec<EntityId>>> {
        let Some(key) = parse_key(ask) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        Ok(ASKS
            .get(&self.store, &txn, &key)?
            .filter(|ask| ask.someone_new_proposed_at.is_some())
            .map(|ask| proposal_refs(&ask)))
    }
}

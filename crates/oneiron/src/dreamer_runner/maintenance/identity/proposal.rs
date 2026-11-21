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
//! ask afresh, or changes its options (an answer, an erase, a changed
//! candidate set), drops it. From
//! the proposal on, the ask waits on a person: the ladder no longer decides
//! it. The tap names the proposal its notice showed by a token (the ask,
//! the proposal's time and its ids), and the owner's answer stands only
//! while that proposal does: a tap kept from an earlier notice accepts no
//! later proposal on the same ask.

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
/// The domain of a notice's event id: a digest of the ask, the owner, the
/// proposal's time and the ids it carries, so a proposal made again after
/// the ask changed gets a notice of its own.
const SOMEONE_NEW_PROPOSAL_EVENT_DOMAIN: &[u8] = b"oneiron/identity-ask/someone-new-proposal/v1";
/// The domain of a proposal's token: a digest of the ask, the proposal's
/// time and the ids it puts to the owner.
const SOMEONE_NEW_PROPOSAL_TOKEN_DOMAIN: &[u8] =
    b"oneiron/identity-ask/someone-new-proposal-token/v1";

/// A member's someone-new proposal as it stands on an ask.
pub(crate) struct SomeoneNewProposal {
    /// When it was made: its notices' `created_at`.
    pub(crate) proposed_at: u64,
    /// The ids it puts to the owner: its notices' `subject_refs`.
    pub(crate) refs: Vec<EntityId>,
    /// Its token, as 32 hex: the one an owner's acceptance names.
    pub(crate) token: String,
}

/// The proposal standing on the ask `key` (`ask`, as stored), if any.
fn standing(key: &[u8; 32], ask: &IdentityAsk) -> Result<Option<SomeoneNewProposal>> {
    let Some(proposed_at) = ask.someone_new_proposed_at else {
        return Ok(None);
    };
    let refs = proposal_refs(ask);
    let at = proposed_at.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![key.as_slice(), at.as_slice()];
    parts.extend(refs.iter().map(|id| id.as_bytes().as_slice()));
    let token = EntityId::derive(SOMEONE_NEW_PROPOSAL_TOKEN_DOMAIN, &parts)?.to_hex();
    Ok(Some(SomeoneNewProposal {
        proposed_at,
        refs,
        token,
    }))
}

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
        let mut parts: Vec<&[u8]> =
            vec![key.as_slice(), owner.as_bytes().as_slice(), at.as_slice()];
        parts.extend(refs.iter().map(|id| id.as_bytes().as_slice()));
        let event = EntityId::derive(SOMEONE_NEW_PROPOSAL_EVENT_DOMAIN, &parts)?;
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

/// Whether the proposal `token` names stands on the ask `key` in `txn`.
pub(super) fn stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    token: &str,
) -> Result<bool> {
    let Some(ask) = ASKS.get(&vault.store, txn, key)? else {
        return Ok(false);
    };
    Ok(standing(key, &ask)?.is_some_and(|proposal| proposal.token == token))
}

/// The ask `key`, as stored, that an owner's `choice` accepts: only "someone
/// new", naming by `token` the member's proposal that stands on it.
pub(super) fn accepted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    choice: &str,
    token: Option<&str>,
) -> Result<Option<IdentityAsk>> {
    let Some(token) = token else {
        return Ok(None);
    };
    if choice != SOMEONE_NEW || !stands_in_txn(vault, txn, key, token)? {
        return Ok(None);
    }
    ASKS.get(&vault.store, txn, key)
}

impl Vault {
    /// The member's someone-new proposal on `ask` (64 hex) while it stands;
    /// none once it is gone.
    pub(crate) fn identity_someone_new_proposal(
        &self,
        ask: &str,
    ) -> Result<Option<SomeoneNewProposal>> {
        let Some(key) = parse_key(ask) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        match ASKS.get(&self.store, &txn, &key)? {
            Some(ask) => standing(&key, &ask),
            None => Ok(None),
        }
    }
}

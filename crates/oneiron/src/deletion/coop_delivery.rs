//! Courtesy unsend (OF-273, ARCH-0043 #relationship-lifecycle). After a
//! disconnect the owner may ASK a former peer to drop what it synced: the
//! signed ask is queued, retried while the peer is offline and recorded with
//! its delivery status. It never claims recall, and no remote deletion proof
//! exists. Normal sync stays revoked; the ask rides its own HTTPS route.
//!
//! On the receiving side an authenticated ask is filed for the owner's review
//! and nothing is deleted on receipt. The owner picks from the menu, and may
//! send back a one-line answer that moves the requester's record to
//! `acknowledged` or `declined`.

use serde::{Deserialize, Serialize};

use super::DeleteReason;
use super::coop_reply::{
    CooperativeDeletionReplyOutcome, SignedCooperativeDeletionReply,
    decode_and_verify_cooperative_deletion_reply, encode_signed_cooperative_deletion_reply,
};
use super::coop_request::{
    SignedCooperativeDeletionRequest, decode_and_verify_cooperative_deletion_request,
    encode_signed_cooperative_deletion_request, peek_cooperative_deletion_pact,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    FailAttempt, RetryAttempt,
};
use crate::authority::FederationPactStatus;
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The queue kind carrying both legs: the ask and the answer.
pub const COOP_DELETION_DELIVERY_ATTEMPT_KIND: &str = "cooperative_deletion.delivery";
/// The peer route an ask is POSTed to.
pub const COOP_DELETION_PEER_PATH: &str = "/v1/federation/courtesy-delete";
/// The requester's route an answer is POSTed to.
pub const COOP_DELETION_REPLY_PEER_PATH: &str = "/v1/federation/courtesy-delete/reply";
/// How long an undelivered leg keeps retrying before it is `unreachable`.
pub const COOP_DELETION_GIVE_UP_SECS: u64 = 7 * 24 * 60 * 60;
/// The retry wait grows with the leg's age, between these bounds.
const MIN_BACKOFF_SECS: u64 = 60;
const MAX_BACKOFF_SECS: u64 = 6 * 60 * 60;
/// A reason code is a short token, never free text.
const MAX_REASON_CODE_LEN: usize = 48;

/// The sender's ledger, one row per ask and recipient: canon's fields only.
const NOTICES: SideTable<([u8; 16], [u8; 32]), CooperativeDeletionNotice, Named> =
    SideTable::new(&side_table::COOPERATIVE_DELETION_NOTICE);

/// The recipient's filed asks, by pact and nonce. The nonce is the replay
/// fence: a second ask under one nonce never replaces the first.
const INCOMING: SideTable<([u8; 32], [u8; 16]), IncomingCooperativeDeletion, Named> =
    SideTable::new(&side_table::COOPERATIVE_DELETION_INCOMING);

/// The pacts under which the owner kept what an ask covers: each filed ask
/// whose current answer is any choice but delete (BIZ-LEGAL-0004 B2).
/// Retrieval keeps those copies out of shared reads (Docs Q09).
pub(crate) fn courtesy_retained_pacts_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::BTreeSet<[u8; 32]>> {
    let mut pacts = std::collections::BTreeSet::new();
    for row in INCOMING.iter_from(store, txn, &[])? {
        let ((pact, _), filed) = row?;
        if filed
            .disposition
            .as_ref()
            .is_some_and(|answer| answer.kind != CooperativeDeletionDispositionKind::Delete)
        {
            pacts.insert(pact);
        }
    }
    Ok(pacts)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("courtesy delete: {reason}"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Parses `N` bytes of lowercase or uppercase hex.
pub fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The pseudonym the sender's ledger keeps for a recipient, in place of its
/// vault id.
#[must_use]
pub fn cooperative_deletion_recipient_id(pact_id: &[u8; 32], peer_vault_id: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(
        "oneiron/deletion/coop-recipient/v1",
        &[pact_id.as_slice(), peer_vault_id.as_slice()].concat(),
    )
}

/// The seven delivery states (BIZ-LEGAL-0004 A7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeletionDeliveryStatus {
    /// Staged; no try has started.
    Queued,
    /// A try started; retries keep this state.
    Sent,
    /// The peer's host answered 2xx: the ask is filed there.
    Delivered,
    /// The recipient's owner chose from the menu.
    Acknowledged,
    /// The recipient's owner declined.
    Declined,
    /// Retries ran out without an answer.
    Unreachable,
    /// The peer's host answered but did not file the ask; what it holds is unknown.
    Unknown,
}

impl CooperativeDeletionDeliveryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Declined => "declined",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// The state `next` leaves this one in, or `None` when the move is not
    /// one the ledger makes: an answer is final, a try starts only from
    /// `queued` or `sent`, and a try's result lands only on `sent`.
    const fn advance(self, next: Self) -> Option<Self> {
        match (self, next) {
            (Self::Acknowledged | Self::Declined, _) | (_, Self::Queued) => None,
            (Self::Queued | Self::Sent, Self::Sent)
            | (Self::Sent, Self::Delivered | Self::Unknown | Self::Unreachable)
            | (_, Self::Acknowledged | Self::Declined) => Some(next),
            _ => None,
        }
    }
}

/// The sender's record of one ask to one recipient. It keeps request id,
/// connection id, a pseudonymous recipient id, status and timestamps, and
/// never the erased content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeletionNotice {
    /// The signed ask's nonce, hex.
    pub request_id: String,
    /// The pact the ask is about, hex.
    pub connection_id: String,
    /// [`cooperative_deletion_recipient_id`], hex.
    pub recipient_id: String,
    pub status: CooperativeDeletionDeliveryStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

/// The recipient owner's menu (BIZ-LEGAL-0004 B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeletionDispositionKind {
    Delete,
    Redact,
    RestrictPendingReview,
    RetainUnderBasis,
    LegalHold,
    Decline,
}

impl CooperativeDeletionDispositionKind {
    /// What the requester learns of this choice.
    #[must_use]
    pub const fn reply_outcome(self) -> CooperativeDeletionReplyOutcome {
        match self {
            Self::Decline => CooperativeDeletionReplyOutcome::Declined,
            _ => CooperativeDeletionReplyOutcome::Acknowledged,
        }
    }
}

/// The owner's recorded choice on one filed ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeletionDisposition {
    pub kind: CooperativeDeletionDispositionKind,
    /// A concise reason code for any choice but delete; never free text.
    pub reason_code: Option<String>,
    /// When a choice other than delete comes up for review, unix seconds.
    pub review_at: Option<u64>,
    /// The records the owner deleted under a delete choice, hex.
    pub deleted: Vec<String>,
    pub recorded_at: u64,
}

/// One filed ask, for the recipient owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingCooperativeDeletion {
    /// The ask's nonce, hex.
    pub request_id: String,
    /// The pact, hex.
    pub connection_id: String,
    pub requester_vault_id: String,
    /// The worlds named, hex; none asks about everything the pact delivered.
    pub worlds: Vec<String>,
    pub epoch_cutoff: u64,
    /// The requester's clock when it signed.
    pub requested_at: u64,
    pub received_at: u64,
    /// The signed ask exactly as received.
    pub request: Vec<u8>,
    pub disposition: Option<CooperativeDeletionDisposition>,
    /// Delivery of the owner's answer back to the requester, once one is queued.
    pub reply_status: Option<CooperativeDeletionDeliveryStatus>,
    pub reply_started_at: Option<u64>,
}

/// What the owner chose for one filed ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionAnswer {
    pub kind: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete. Each goes through
    /// the ordinary delete rail, one by one.
    pub delete: Vec<EntityId>,
}

/// Where a peer-facing POST landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeDeletionIngress {
    /// Recorded; nothing was deleted.
    Filed,
    /// The same bytes were already recorded.
    AlreadyFiled,
    /// No pact with this peer, or the bytes do not verify against the key it pinned.
    Unauthenticated,
    /// The nonce already names a different ask or answer.
    Conflict,
}

/// One leg's try result, as the host's transport saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooperativeDeletionTry {
    /// The peer answered 2xx.
    Delivered,
    /// The peer answered and refused the bytes (a 4xx other than 408 or 429).
    Refused(u16),
    /// No answer, a timeout or a server error: try again later.
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Leg {
    Request,
    Reply,
}

/// The queued try: the signed bytes and the checked destination, frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPayload {
    leg: Leg,
    pact: String,
    nonce: String,
    /// The recipient pseudonym, for an ask.
    recipient: Option<String>,
    destination: String,
    bytes: Vec<u8>,
}

impl DeliveryPayload {
    fn ids(&self) -> Result<([u8; 32], [u8; 16])> {
        Ok((
            parse_hex(&self.pact).ok_or_else(|| invalid("payload pact"))?,
            parse_hex(&self.nonce).ok_or_else(|| invalid("payload nonce"))?,
        ))
    }
}

/// One claimed try for the host to POST.
#[derive(Debug, Clone)]
pub struct CooperativeDeletionDelivery {
    pub attempt: AttemptRecord,
    /// The full peer URL.
    pub destination: String,
    /// The signed bytes, unchanged on every try.
    pub bytes: Vec<u8>,
    payload: DeliveryPayload,
}

impl Vault {
    /// Queues `signed` for `destination` and records it `queued`, in one
    /// transaction. The ask must be this vault's, about a pact it ended.
    pub fn queue_cooperative_deletion_request_as(
        &self,
        owner: &AuthenticatedOwner,
        signed: &SignedCooperativeDeletionRequest,
        destination: &str,
        now: u64,
    ) -> Result<CooperativeDeletionNotice> {
        self.recheck_owner(owner)?;
        let body = &signed.body;
        let fold = self.authority_fold()?;
        if fold.vault_id != Some(body.requester_vault_id) {
            return Err(invalid("the ask is not this vault's"));
        }
        let pact = fold
            .federation_pacts
            .get(&body.pact_id)
            .filter(|pact| {
                matches!(
                    pact.status,
                    FederationPactStatus::Disconnected | FederationPactStatus::Dissolved
                )
            })
            .ok_or(crate::error::RecordError::CooperativeDeletionRequiresTerminalPact)?;
        if pact.peer_vault_id != body.peer_vault_id
            || body.epoch_cutoff > pact.terminal_epoch.unwrap_or(pact.pact_epoch)
        {
            return Err(invalid("the ask does not match its pact"));
        }
        let bytes = encode_signed_cooperative_deletion_request(signed)?;
        let recipient = cooperative_deletion_recipient_id(&body.pact_id, &body.peer_vault_id);
        let notice = CooperativeDeletionNotice {
            request_id: hex(&body.nonce),
            connection_id: hex(&body.pact_id),
            recipient_id: hex(&recipient),
            status: CooperativeDeletionDeliveryStatus::Queued,
            created_at: now,
            updated_at: now,
        };
        let payload = DeliveryPayload {
            leg: Leg::Request,
            pact: notice.connection_id.clone(),
            nonce: notice.request_id.clone(),
            recipient: Some(notice.recipient_id.clone()),
            destination: destination.to_owned(),
            bytes,
        };
        let key = (body.nonce, recipient);
        self.with_write_txn_grouped(|txn| {
            if NOTICES.contains(&self.store, txn, &key)? {
                return Err(invalid("an ask under this nonce is already queued"));
            }
            stage(self, txn, &payload, now)?;
            NOTICES.put(&self.store, txn, &key, &notice)?;
            Ok(notice.clone())
        })
    }

    /// Queues the owner's signed answer to a filed ask for `destination`.
    /// One answer goes back per ask; a later choice stays on this side.
    pub fn queue_cooperative_deletion_reply_as(
        &self,
        owner: &AuthenticatedOwner,
        signed: &SignedCooperativeDeletionReply,
        destination: &str,
        now: u64,
    ) -> Result<IncomingCooperativeDeletion> {
        self.recheck_owner(owner)?;
        let body = &signed.body;
        let bytes = encode_signed_cooperative_deletion_reply(signed)?;
        let key = (body.pact_id, body.nonce);
        self.with_write_txn_grouped(|txn| {
            let mut filed = INCOMING
                .get(&self.store, txn, &key)?
                .ok_or_else(|| invalid("no such ask"))?;
            let answered = filed
                .disposition
                .as_ref()
                .ok_or_else(|| invalid("the ask has no answer yet"))?;
            if answered.kind.reply_outcome() != body.outcome {
                return Err(invalid("the answer does not match the recorded choice"));
            }
            if filed.reply_status.is_some() {
                return Ok(filed);
            }
            let payload = DeliveryPayload {
                leg: Leg::Reply,
                pact: filed.connection_id.clone(),
                nonce: filed.request_id.clone(),
                recipient: None,
                destination: destination.to_owned(),
                bytes,
            };
            stage(self, txn, &payload, now)?;
            filed.reply_status = Some(CooperativeDeletionDeliveryStatus::Queued);
            filed.reply_started_at = Some(now);
            INCOMING.put(&self.store, txn, &key, &filed)?;
            Ok(filed)
        })
    }

    /// Every ask this vault sent, oldest first.
    pub fn cooperative_deletion_notices(&self) -> Result<Vec<CooperativeDeletionNotice>> {
        let rtxn = self.store.env.read_txn()?;
        let mut notices: Vec<_> = NOTICES
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, notice)| notice)
            .collect();
        notices.sort_by_key(|notice| notice.created_at);
        Ok(notices)
    }

    /// Every ask filed here, oldest first.
    pub fn incoming_cooperative_deletions(&self) -> Result<Vec<IncomingCooperativeDeletion>> {
        let rtxn = self.store.env.read_txn()?;
        let mut filed: Vec<_> = INCOMING
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, filed)| filed)
            .collect();
        filed.sort_by_key(|filed| filed.received_at);
        Ok(filed)
    }

    /// Files a peer's signed ask for the owner's review, after verifying it
    /// against the key this vault pinned for that peer. Nothing is deleted
    /// here, whatever the ask says.
    pub fn receive_cooperative_deletion_request(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<CooperativeDeletionIngress> {
        let Ok(pact_id) = peek_cooperative_deletion_pact(bytes) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        let fold = self.authority_fold()?;
        let Some(pact) = fold.federation_pacts.get(&pact_id) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        let Ok(body) = decode_and_verify_cooperative_deletion_request(bytes, &pact.peer_owner_key)
        else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        if body.pact_id != pact_id
            || body.requester_vault_id != pact.peer_vault_id
            || fold.vault_id != Some(body.peer_vault_id)
        {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        }
        let key = (pact_id, body.nonce);
        self.with_write_txn_grouped(|txn| match INCOMING.get(&self.store, txn, &key)? {
            Some(filed) if filed.request == bytes => Ok(CooperativeDeletionIngress::AlreadyFiled),
            Some(_) => Ok(CooperativeDeletionIngress::Conflict),
            None => {
                let filed = IncomingCooperativeDeletion {
                    request_id: hex(&body.nonce),
                    connection_id: hex(&pact_id),
                    requester_vault_id: hex(&body.requester_vault_id),
                    worlds: body.worlds.iter().map(EntityId::to_hex).collect(),
                    epoch_cutoff: body.epoch_cutoff,
                    requested_at: body.ts,
                    received_at: now,
                    request: bytes.to_vec(),
                    disposition: None,
                    reply_status: None,
                    reply_started_at: None,
                };
                INCOMING.put(&self.store, txn, &key, &filed)?;
                Ok(CooperativeDeletionIngress::Filed)
            }
        })
    }

    /// Lands a former peer's answer on this vault's record of the ask, after
    /// verifying it against the key this vault pinned for that peer.
    pub fn receive_cooperative_deletion_reply(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<CooperativeDeletionIngress> {
        let Ok(pact_id) = peek_cooperative_deletion_pact(bytes) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        let fold = self.authority_fold()?;
        let Some(pact) = fold.federation_pacts.get(&pact_id) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        let Ok(reply) = decode_and_verify_cooperative_deletion_reply(bytes, &pact.peer_owner_key)
        else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        if reply.pact_id != pact_id
            || reply.responder_vault_id != pact.peer_vault_id
            || fold.vault_id != Some(reply.requester_vault_id)
        {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        }
        let status = match reply.outcome {
            CooperativeDeletionReplyOutcome::Acknowledged => {
                CooperativeDeletionDeliveryStatus::Acknowledged
            }
            CooperativeDeletionReplyOutcome::Declined => {
                CooperativeDeletionDeliveryStatus::Declined
            }
        };
        let key = (
            reply.nonce,
            cooperative_deletion_recipient_id(&pact_id, &pact.peer_vault_id),
        );
        self.with_write_txn_grouped(|txn| {
            let Some(mut notice) = NOTICES.get(&self.store, txn, &key)? else {
                return Ok(CooperativeDeletionIngress::Unauthenticated);
            };
            if notice.status == status {
                return Ok(CooperativeDeletionIngress::AlreadyFiled);
            }
            let Some(next) = notice.status.advance(status) else {
                return Ok(CooperativeDeletionIngress::Conflict);
            };
            notice.status = next;
            notice.updated_at = now;
            NOTICES.put(&self.store, txn, &key, &notice)?;
            Ok(CooperativeDeletionIngress::Filed)
        })
    }

    /// Records the owner's choice on a filed ask. A delete choice hard-deletes
    /// the records the owner named through the ordinary delete rail first;
    /// every other choice is recorded with its reason code and review date,
    /// and nothing else happens to the data.
    pub fn answer_cooperative_deletion_as(
        &self,
        owner: &AuthenticatedOwner,
        pact_id: &[u8; 32],
        nonce: &[u8; 16],
        answer: &CooperativeDeletionAnswer,
        now: u64,
    ) -> Result<IncomingCooperativeDeletion> {
        self.recheck_owner(owner)?;
        let key = (*pact_id, *nonce);
        {
            let rtxn = self.store.env.read_txn()?;
            if !INCOMING.contains(&self.store, &rtxn, &key)? {
                return Err(invalid("no such ask"));
            }
        }
        let delete = answer.kind == CooperativeDeletionDispositionKind::Delete;
        if delete {
            if answer.reason_code.is_some() || answer.review_at.is_some() {
                return Err(invalid(
                    "a delete choice carries no reason code or review date",
                ));
            }
        } else {
            let code = answer
                .reason_code
                .as_deref()
                .ok_or_else(|| invalid("this choice needs a reason code"))?;
            if code.is_empty()
                || code.len() > MAX_REASON_CODE_LEN
                || !code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(invalid("a reason code is a short snake_case token"));
            }
            if answer.review_at.is_none_or(|at| at <= now) {
                return Err(invalid("this choice needs a future review date"));
            }
            if !answer.delete.is_empty() {
                return Err(invalid("only a delete choice deletes records"));
            }
        }
        let mut deleted = Vec::new();
        for id in &answer.delete {
            if self
                .delete_entity_with_reason(id, DeleteReason::UserHardDelete)?
                .existed
            {
                deleted.push(id.to_hex());
            }
        }
        self.with_write_txn_grouped(|txn| {
            let mut filed = INCOMING
                .get(&self.store, txn, &key)?
                .ok_or_else(|| invalid("no such ask"))?;
            filed.disposition = Some(CooperativeDeletionDisposition {
                kind: answer.kind,
                reason_code: answer.reason_code.clone(),
                review_at: answer.review_at,
                deleted: deleted.clone(),
                recorded_at: now,
            });
            INCOMING.put(&self.store, txn, &key, &filed)?;
            Ok(filed)
        })
    }

    /// Claims the next try and marks its leg `sent`. A try whose ledger row
    /// is gone or already past sending (an answered ask, or a job replayed
    /// from a restored image) is failed here and never reaches the host.
    pub fn claim_cooperative_deletion_delivery(
        &self,
        lease_owner: &str,
        now: u64,
    ) -> Result<Option<CooperativeDeletionDelivery>> {
        let queue = AttemptQueue::new(self);
        loop {
            let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
                COOP_DELETION_DELIVERY_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.into(),
                    now,
                },
            )?
            else {
                return Ok(None);
            };
            let payload = serde_json::from_slice::<DeliveryPayload>(&attempt.payload).ok();
            let live = match &payload {
                Some(payload) => self.with_write_txn_grouped(|txn| {
                    move_leg(
                        self,
                        txn,
                        payload,
                        CooperativeDeletionDeliveryStatus::Sent,
                        now,
                    )
                })?,
                None => false,
            };
            match payload {
                Some(payload) if live => {
                    return Ok(Some(CooperativeDeletionDelivery {
                        destination: payload.destination.clone(),
                        bytes: payload.bytes.clone(),
                        attempt,
                        payload,
                    }));
                }
                _ => {
                    queue.fail(FailAttempt {
                        id: attempt.id,
                        lease_owner: lease_owner.into(),
                        attempt_count: attempt.attempt_count,
                        reason: "ledger_settled".into(),
                        now,
                    })?;
                }
            }
        }
    }

    /// Settles one claimed try: 2xx is `delivered`; a refusal is `unknown`;
    /// a failure retries with a wait that grows with the leg's age, until
    /// [`COOP_DELETION_GIVE_UP_SECS`] makes it `unreachable`. The queue row
    /// and the ledger move in one transaction, fenced by the claim's lease.
    pub fn settle_cooperative_deletion_delivery(
        &self,
        delivery: &CooperativeDeletionDelivery,
        result: CooperativeDeletionTry,
        now: u64,
    ) -> Result<CooperativeDeletionDeliveryStatus> {
        let attempt = &delivery.attempt;
        let lease_owner = attempt
            .lease_owner
            .clone()
            .ok_or_else(|| invalid("delivery lease owner"))?;
        let payload = &delivery.payload;
        self.with_write_txn_grouped(|txn| {
            let queue = AttemptQueue::new(self);
            let started = leg_started_at(self, txn, payload)?.unwrap_or(now);
            let age = now.saturating_sub(started);
            let next = match &result {
                CooperativeDeletionTry::Delivered => {
                    queue.complete_in_txn(
                        txn,
                        CompleteAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            now,
                        },
                    )?;
                    CooperativeDeletionDeliveryStatus::Delivered
                }
                CooperativeDeletionTry::Refused(status) => {
                    queue.fail_in_txn(
                        txn,
                        FailAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            reason: format!("peer_refused_{status}"),
                            now,
                        },
                    )?;
                    CooperativeDeletionDeliveryStatus::Unknown
                }
                CooperativeDeletionTry::Failed(error) if age >= COOP_DELETION_GIVE_UP_SECS => {
                    queue.fail_in_txn(
                        txn,
                        FailAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            reason: format!("unreachable: {error}"),
                            now,
                        },
                    )?;
                    CooperativeDeletionDeliveryStatus::Unreachable
                }
                CooperativeDeletionTry::Failed(error) => {
                    queue.retry_in_txn(
                        txn,
                        RetryAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            backoff_until: now.saturating_add(
                                (age / 2).clamp(MIN_BACKOFF_SECS, MAX_BACKOFF_SECS),
                            ),
                            last_error: Some(error.clone()),
                            now,
                        },
                    )?;
                    return Ok(CooperativeDeletionDeliveryStatus::Sent);
                }
            };
            move_leg(self, txn, payload, next, now)?;
            Ok(next)
        })
    }
}

/// Stages one leg's queue row in the caller's transaction.
fn stage(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    payload: &DeliveryPayload,
    now: u64,
) -> Result<()> {
    let bytes = serde_json::to_vec(payload).map_err(|_| invalid("payload encoding"))?;
    let leg = match payload.leg {
        Leg::Request => "request",
        Leg::Reply => "reply",
    };
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        txn,
        EnqueueAttempt {
            kind: COOP_DELETION_DELIVERY_ATTEMPT_KIND.into(),
            payload: bytes,
            dedupe_key: Some(format!(
                "coop-delete:{leg}:{}:{}",
                payload.pact, payload.nonce
            )),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

/// When a leg was first queued: its ask's ledger row, or its answer's start.
fn leg_started_at(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    payload: &DeliveryPayload,
) -> Result<Option<u64>> {
    let (pact, nonce) = payload.ids()?;
    Ok(match payload.leg {
        Leg::Request => {
            let recipient = payload
                .recipient
                .as_deref()
                .and_then(parse_hex)
                .ok_or_else(|| invalid("payload recipient"))?;
            NOTICES
                .get(&vault.store, txn, &(nonce, recipient))?
                .map(|notice| notice.created_at)
        }
        Leg::Reply => INCOMING
            .get(&vault.store, txn, &(pact, nonce))?
            .and_then(|filed| filed.reply_started_at),
    })
}

/// Moves a leg's ledger state to `next`; false when the row is gone or the
/// move is not one the ledger makes.
fn move_leg(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    payload: &DeliveryPayload,
    next: CooperativeDeletionDeliveryStatus,
    now: u64,
) -> Result<bool> {
    let (pact, nonce) = payload.ids()?;
    match payload.leg {
        Leg::Request => {
            let recipient = payload
                .recipient
                .as_deref()
                .and_then(parse_hex)
                .ok_or_else(|| invalid("payload recipient"))?;
            let key = (nonce, recipient);
            let Some(mut notice) = NOTICES.get(&vault.store, txn, &key)? else {
                return Ok(false);
            };
            let Some(status) = notice.status.advance(next) else {
                return Ok(false);
            };
            notice.status = status;
            notice.updated_at = now;
            NOTICES.put(&vault.store, txn, &key, &notice)?;
        }
        Leg::Reply => {
            let key = (pact, nonce);
            let Some(mut filed) = INCOMING.get(&vault.store, txn, &key)? else {
                return Ok(false);
            };
            let Some(status) = filed.reply_status.and_then(|status| status.advance(next)) else {
                return Ok(false);
            };
            filed.reply_status = Some(status);
            INCOMING.put(&vault.store, txn, &key, &filed)?;
        }
    }
    Ok(true)
}

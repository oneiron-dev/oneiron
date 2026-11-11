//! The asking side's send (INQUIRE-1 PR 4; Engine ruling INQUIRE-SHAPE
//! Q2 = A, Q3 = A). The company vault sends one inquiry over the member's
//! route through an [`InquiryTransport`], writes the `inquiry` receipt, and
//! holds an answer's statements with the task. No route, no seat, an
//! expired slip, a member host that does not answer or refuses, and a reply
//! that does not answer this inquiry all give `unavailable`.
//!
//! A pending inquiry is re-sent by the agent with the same id; the member's
//! vault returns its current answer. No housekeeping pass re-sends it.

use super::record::{
    Inquiry, InquiryAnswer, InquiryAsker, InquiryOutcome, InquiryStatement, InquiryTask, refuse,
};
use super::route::{InquiryRoute, inquiry_route_in_txn};
use crate::Vault;
use crate::authority::AuthorityVaultId;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;

/// Carries one inquiry to a member host and brings back its answer. The
/// host's adapter attaches the slip and proves on each call that this host
/// holds the key the slip is bound to; a test carries the inquiry in
/// process.
pub trait InquiryTransport: Send + Sync {
    /// Sends `inquiry` (its wire bytes) to `member_host` for the vault
    /// `member_vault_id` under `slip_token`, and returns the answer's wire
    /// bytes.
    ///
    /// # Errors
    ///
    /// [`InquiryTransportError`]: the host did not answer, or refused.
    fn exchange(
        &self,
        member_host: &str,
        member_vault_id: &AuthorityVaultId,
        slip_token: &str,
        inquiry: &[u8],
    ) -> std::result::Result<Vec<u8>, InquiryTransportError>;
}

/// Why no answer came back. Each gives `unavailable`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InquiryTransportError {
    /// The member host did not answer: stopped or unreachable.
    Unreachable(String),
    /// The member host refused the inquiry: its edge, slip or pact no
    /// longer admits it.
    Refused(String),
}

/// One send of an inquiry, as the asking agent's verb gives it.
#[derive(Clone, Debug)]
pub struct InquirySendRequest {
    /// The shared vault the member holds a seat in.
    pub shared_vault_id: u64,
    /// The member asked about: the member's PERSON in this vault.
    pub member: EntityId,
    /// The asking actor.
    pub asker: EntityId,
    /// The asking actor's role, as the member's log shows it.
    pub asker_role: String,
    /// The asking actor's open TASK the answer serves.
    pub task: EntityId,
    /// One line: what the task needs the answer for.
    pub purpose: String,
    pub question: String,
    /// The second the asker stops waiting.
    pub expires_at: u64,
    /// The id of an earlier send to re-send; `None` sends a new inquiry.
    pub inquiry_id: Option<EntityId>,
}

/// What one send came to.
#[derive(Clone, Debug)]
pub struct InquirySent {
    /// The inquiry as it was sent; its id re-sends it.
    pub inquiry: Inquiry,
    pub outcome: InquiryOutcome,
    /// The member's statements when the outcome is `answered`.
    pub statements: Vec<InquiryStatement>,
    pub valid_until: Option<u64>,
    /// The send's `inquiry` receipt.
    pub receipt_id: String,
    /// Whether this vault holds the statements with the task now.
    pub held: bool,
}

impl Vault {
    /// Sends one inquiry about `request.member` over the member's route
    /// through `transport`, writes its `inquiry` receipt (never answer
    /// text), and holds an answer's statements with the task until the task
    /// ends or `valid_until` comes. The keep is the vault's `inquiry_keep`.
    /// `copy` has no landing yet (INQUIRE-1 PR 6), so an answer to a `copy`
    /// inquiry is held with the task as well.
    ///
    /// # Errors
    ///
    /// The task is not an open TASK of this vault; the inquiry breaks a
    /// field rule; this vault is not rooted; storage errors. A missing
    /// route or an unanswered send is an outcome, not an error.
    pub fn send_inquiry(
        &self,
        request: &InquirySendRequest,
        transport: &dyn InquiryTransport,
    ) -> Result<InquirySent> {
        if !super::holder::inquiry_task_is_open(self, request.task)? {
            return Err(refuse(
                "the inquiry's task is not an open TASK of this vault",
            ));
        }
        let keep = self.inquiry_keep()?.keep;
        let (inquiry, route) = {
            let txn = self.store.env.read_txn()?;
            let Some(vault_id) = self.authority_fold_readonly_in_txn(&txn)?.vault_id else {
                return Err(refuse(
                    "this vault is not rooted: it has no vault id to ask from",
                ));
            };
            let inquiry = Inquiry {
                id: request.inquiry_id.unwrap_or_else(EntityId::now),
                from: InquiryAsker {
                    vault: bytes_to_hex_lower(&vault_id),
                    actor: request.asker,
                    role: request.asker_role.clone(),
                },
                task: InquiryTask {
                    id: request.task,
                    purpose: request.purpose.clone(),
                },
                question: request.question.clone(),
                keep,
                expires_at: request.expires_at,
            };
            inquiry.validate()?;
            let route =
                if self.holds_inquiry_seat_in_txn(&txn, request.shared_vault_id, request.member)? {
                    inquiry_route_in_txn(
                        &self.store,
                        &txn,
                        request.shared_vault_id,
                        request.member,
                    )?
                } else {
                    None
                };
            (inquiry, route)
        };
        let answer = match &route {
            Some(route) => self.exchange_inquiry(&inquiry, route, transport)?,
            None => InquiryAnswer::unavailable(&inquiry),
        };
        let receipt = self.with_write_txn(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            super::receipt::write_inquiry_receipt_in_txn(
                &self.store,
                txn,
                &inquiry,
                &request.member,
                answer.outcome(),
                now,
            )
        })?;
        let held = match answer.valid_until() {
            Some(valid_until) if answer.outcome() == InquiryOutcome::Answered => self
                .hold_inquiry_answer(
                    request.asker,
                    request.task,
                    inquiry.id,
                    answer.statements(),
                    valid_until,
                )?,
            _ => false,
        };
        Ok(InquirySent {
            outcome: answer.outcome(),
            statements: answer.statements().to_vec(),
            valid_until: answer.valid_until(),
            receipt_id: receipt.receipt_id,
            held,
            inquiry,
        })
    }

    /// The member's answer to `inquiry` over `route`, or `unavailable`.
    fn exchange_inquiry(
        &self,
        inquiry: &Inquiry,
        route: &InquiryRoute,
        transport: &dyn InquiryTransport,
    ) -> Result<InquiryAnswer> {
        if route.slip_expires_at <= self.now_recorded_at() {
            return Ok(InquiryAnswer::unavailable(inquiry));
        }
        let wire = inquiry.encode_wire()?;
        let Ok(reply) = transport.exchange(
            &route.member_host,
            &route.member_vault_id,
            route.slip_token(),
            &wire,
        ) else {
            return Ok(InquiryAnswer::unavailable(inquiry));
        };
        Ok(match InquiryAnswer::decode_wire(&reply) {
            Ok(answer)
                if answer.answers(inquiry) && answer.outcome() != InquiryOutcome::Unavailable =>
            {
                answer
            }
            _ => InquiryAnswer::unavailable(inquiry),
        })
    }
}

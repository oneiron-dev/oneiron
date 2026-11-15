//! The member's [Now] (L7-03; federation.md #inquiry, line 95: "A need drawn
//! from a stamped claim goes to the member before its first use: “Tell the
//! company ‘Out Thursday’? [Now] [Only if asked] [No]”"; lead rulings
//! L7-03-LANDING = A and L7-03-SCOPE = A). The member tells the company of
//! one inquiry edge a statement unasked, in the member's own words.
//!
//! * On the member's vault, [Now] is one outbound send on the internal
//!   channel `inquiry_push`, scheduled through the schedule door's one
//!   enqueue. So the owner's undo-send window holds it like any other send
//!   (DEC-0006 #undo-send: one window per channel under one setting), and
//!   `vault.outbound.undo_send` takes it back while the window runs. The
//!   attempt queue gives it restart safety and retries. No hold table and
//!   no retract of its own exist.
//! * The member's route to the company ([`InquiryPushRoute`]) names the
//!   company host and the guest slip the company's vault minted for this
//!   host on its reciprocal grant. The edge's revoke ends it.
//! * The push row keeps the words, the claim they were drawn from (member
//!   local: it never crosses) and the send's connector TASK. [Now] files
//!   nothing in the opened scope (L7-03-SCOPE = A): it tells once.
//! * [`InquiryPushSink`] carries a released send to the company host
//!   through an [`InquiryPushTransport`]: the push id, the edge, the words
//!   and their source, and the time. No member record id crosses.
//! * On the company's vault, [`Vault::land_pushed_inquiry_statement`] admits
//!   the push on the company's own reciprocal grant, which carries the class
//!   `inquiry_push`, and lands the words at once as a copy, whatever
//!   `inquiry_keep` says (canon: "that statement is at once a company
//!   record"). The same push lands once. It writes one `inquiry` receipt
//!   with no question or task.
//!
//! The prompt that offers [Now], and the member's saved choice for it,
//! belong to the companion's stamped-need prompt and are not built here.
//! The verbs are `vault.inquiry.push_route.open` and `vault.inquiry.push`;
//! the member host's connector-send executor carries the send, and the
//! company host's route `INQUIRY_PUSH_PEER_PATH` lands it (oneiron-server).

use serde::{Deserialize, Serialize};

use super::edge::{InquiryEdge, inquiry_edge_grant_in_txn, refuse_undrawable_source_in_txn};
use super::landing::inquiry_landing;
use super::receipt::{inquiry_push_receipt_id, write_inquiry_push_receipt_in_txn};
use super::record::{InquiryStatement, StatementSource, refuse};
use super::route::inquiry_routes_to_member_in_txn;
use super::send::InquiryTransportError;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::authority::{AuthorityVaultId, CapabilitySlip, HostSlipIssuer, VerifiedSlip};
use crate::consent::{AuthenticatedOwner, EffectDigest};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::federation::{
    FederationGrantScope, INQUIRY_PUSH_VERB_CLASS, ScopeAxis, decode_federation_grant_body,
    pact_admits_grant,
};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EdgeActorClass, OutboundDraftInput, Vault};

/// The internal outbound channel a told statement goes out on.
pub const INQUIRY_PUSH_CHANNEL: &str = "inquiry_push";

/// The company host's route a told statement is sent to: the member host
/// POSTs the push's wire bytes there under the company's guest slip, with
/// its own signature on each call.
pub const INQUIRY_PUSH_PEER_PATH: &str = "/v1/federation/inquiry/push";

/// The most bytes a told statement's words take.
pub const MAX_INQUIRY_PUSH_STATEMENT_BYTES: usize = 4096;

/// The most bytes a push's wire body takes: the words, each byte at most six
/// JSON bytes, plus the fixed fields.
pub const MAX_INQUIRY_PUSH_WIRE_BYTES: usize = 32 * 1024;

const _: () = assert!(MAX_INQUIRY_PUSH_STATEMENT_BYTES * 6 + 1024 <= MAX_INQUIRY_PUSH_WIRE_BYTES);

/// The content ref a push's send carries: this prefix and the push id, hex.
const PUSH_CONTENT_REF_PREFIX: &str = "inquiry_push:";

/// The edge's grant → the member's route to its company.
const ROUTES: SideTable<EntityId, InquiryPushRoute, Named> =
    SideTable::new(&side_table::INQUIRY_PUSH_ROUTE);
/// The push → the told statement.
const PUSHES: SideTable<EntityId, InquiryPush, Named> = SideTable::new(&side_table::INQUIRY_PUSH);
/// The claim a push was drawn from and the push → a presence marker.
const PUSHES_BY_SOURCE: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::INQUIRY_PUSH_BY_SOURCE);
/// The member's vault and the push → the CLAIM the company landed it as.
const LANDED: SideTable<(AuthorityVaultId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::INQUIRY_PUSH_LANDED);

/// What the member's Owner gives to open the route to an edge's company.
#[derive(Clone, Debug)]
pub struct InquiryPushRouteRequest {
    /// The member's inquiry edge: its grant on this vault.
    pub edge_grant: EntityId,
    /// The company host's origin, `https://host[:port]`.
    pub company_host: String,
    /// The guest slip the company's vault minted for this host on its
    /// reciprocal grant.
    pub slip: CapabilitySlip,
}

/// The member's route to the company of one inquiry edge, as the member's
/// vault stores it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryPushRoute {
    pub edge_grant: EntityId,
    pub company_vault_id: AuthorityVaultId,
    pub company_host: String,
    /// The company's reciprocal grant, hex, as the slip names it.
    pub reciprocal_grant: String,
    /// The slip's token. It is bound to this host's key: it acts only with
    /// this host's signature on each call.
    slip_token: String,
    pub slip_expires_at: u64,
    pub opened_at: u64,
}

impl InquiryPushRoute {
    pub(crate) fn slip_token(&self) -> &str {
        &self.slip_token
    }
}

impl std::fmt::Debug for InquiryPushRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InquiryPushRoute")
            .field("edge_grant", &self.edge_grant)
            .field("company_host", &self.company_host)
            .field("reciprocal_grant", &self.reciprocal_grant)
            .field("slip_expires_at", &self.slip_expires_at)
            .field("opened_at", &self.opened_at)
            .finish_non_exhaustive()
    }
}

/// The member's [Now]: the words to tell the company of one edge.
#[derive(Clone, Debug)]
pub struct InquiryPushRequest {
    /// The member's inquiry edge: its grant on this vault.
    pub edge_grant: EntityId,
    /// The statement, in the member's own words.
    pub statement: String,
    /// The claim the statement was drawn from; it stays in this vault.
    pub drawn_from: Option<EntityId>,
}

/// One told statement, as the member's vault keeps it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryPush {
    pub push: EntityId,
    /// The inquiry edge it was told over.
    pub edge: EntityId,
    pub statement: String,
    /// The claim it was drawn from: member local, never part of the send.
    pub drawn_from: Option<EntityId>,
    pub told_at: u64,
    /// The send's connector TASK, once the schedule door took it.
    pub task_ref: Option<EntityId>,
}

/// How a told statement stands, read from its send's connector TASK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InquiryPushState {
    /// Scheduled: waiting in the owner's undo-send window, or for the
    /// executor.
    Queued,
    /// The company host took it.
    Sent,
    /// The owner took it back inside the window; it never left the vault.
    Undone,
    /// The send failed for good: the company refused it, or the edge ended.
    Failed,
}

/// A told statement and how it stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryPushView {
    pub push: InquiryPush,
    pub state: InquiryPushState,
}

/// What [`Vault::push_inquiry_statement`] scheduled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryPushed {
    pub push: EntityId,
    /// The send's connector TASK: `vault.outbound.undo_send` names it.
    pub task_ref: EntityId,
}

/// What crosses to the company: the push id, the edge, the words and their
/// source, and the time. Never a member record id, hit, score or vector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryPushWire {
    /// The member vault's id for the push: a re-delivery names it again.
    pub push: EntityId,
    /// The member vault's inquiry edge grant, 32 hex, as the company's
    /// route to the member names it.
    pub edge_grant: String,
    pub statement: InquiryStatement,
    /// When the member told it, in the member vault's clock.
    pub told_at: u64,
}

impl InquiryPushWire {
    /// Checks the push: the member's word, within its cap, over a grant id.
    ///
    /// # Errors
    ///
    /// The first field that breaks its rule.
    pub fn validate(&self) -> Result<()> {
        if self.statement.source() != StatementSource::MemberWord {
            return Err(refuse("a told statement is the member's word"));
        }
        check_statement(self.statement.text())?;
        if EntityId::from_hex(&self.edge_grant).is_err() {
            return Err(refuse("a told statement names its edge grant as 32 hex"));
        }
        Ok(())
    }

    /// The push as it crosses: JSON.
    ///
    /// # Errors
    ///
    /// An invalid push; an encoding error.
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| refuse(&format!("encode: {error}")))
    }

    /// A push read from the wire, checked as [`Self::validate`] does.
    ///
    /// # Errors
    ///
    /// More than [`MAX_INQUIRY_PUSH_WIRE_BYTES`]; bytes that are not a push;
    /// an invalid push.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INQUIRY_PUSH_WIRE_BYTES {
            return Err(refuse("a told statement's body is too large"));
        }
        let wire: Self =
            serde_json::from_slice(bytes).map_err(|error| refuse(&format!("decode: {error}")))?;
        wire.validate()?;
        Ok(wire)
    }
}

/// What [`Vault::land_pushed_inquiry_statement`] landed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryPushLanded {
    /// The CLAIM the statement landed as.
    pub claim: EntityId,
    /// The push's one `inquiry` receipt.
    pub receipt_id: String,
    /// Whether this delivery landed it; `false` for a re-delivery.
    pub landed_now: bool,
}

/// Carries one told statement to a company host. The host's adapter
/// attaches the slip and proves on each call that this host holds the key
/// the slip is bound to; a test carries the push in process.
pub trait InquiryPushTransport: Send + Sync {
    /// Sends `wire` (the push's wire bytes) to `company_host` for the vault
    /// `company_vault_id` under `slip_token`.
    ///
    /// # Errors
    ///
    /// [`InquiryTransportError`]: the host did not answer, or refused.
    fn push(
        &self,
        company_host: &str,
        company_vault_id: &AuthorityVaultId,
        slip_token: &str,
        wire: &[u8],
    ) -> std::result::Result<(), InquiryTransportError>;
}

/// The executor's sink for the channel `inquiry_push`: it reads the push and
/// the member's route once the send is released, checks that the edge still
/// stands, and calls the transport. A company refusal or an ended edge is a
/// definite non-delivery; no answer is a delivery that may have happened.
/// The executor may send either again on its retry curve, since the company
/// lands each push once by its id, the send's idempotency key.
pub struct InquiryPushSink<'a, T: InquiryPushTransport + ?Sized> {
    vault: &'a Vault,
    transport: &'a T,
}

impl<'a, T: InquiryPushTransport + ?Sized> InquiryPushSink<'a, T> {
    /// The sink that sends `vault`'s released pushes over `transport`.
    #[must_use]
    pub fn new(vault: &'a Vault, transport: &'a T) -> Self {
        Self { vault, transport }
    }
}

impl<T: InquiryPushTransport + ?Sized> OutboundExecutionSink for InquiryPushSink<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != INQUIRY_PUSH_CHANNEL {
            return OutboundExecutionOutcome::failed(
                "the inquiry push sink sends inquiry_push only",
            );
        }
        let Some(push) = request
            .intent
            .content_ref
            .as_deref()
            .and_then(push_of_content_ref)
        else {
            return OutboundExecutionOutcome::failed("the send names no told statement");
        };
        let (route, wire) = match self.vault.inquiry_push_delivery(push) {
            Ok(delivery) => delivery,
            Err(error) => return OutboundExecutionOutcome::failed(error.to_string()),
        };
        match self.transport.push(
            &route.company_host,
            &route.company_vault_id,
            route.slip_token(),
            &wire,
        ) {
            Ok(()) => OutboundExecutionOutcome::delivered_to_channel(format!(
                "{PUSH_CONTENT_REF_PREFIX}{}",
                push.to_hex()
            )),
            Err(InquiryTransportError::Refused(why)) => OutboundExecutionOutcome::failed(why),
            Err(InquiryTransportError::Unreachable(why)) => {
                OutboundExecutionOutcome::failed(why).with_possible_delivery()
            }
        }
    }
}

fn check_statement(statement: &str) -> Result<()> {
    if statement.trim().is_empty() {
        return Err(refuse("a told statement has words"));
    }
    if statement.len() > MAX_INQUIRY_PUSH_STATEMENT_BYTES {
        return Err(refuse("a told statement is longer than its cap"));
    }
    Ok(())
}

fn push_content_ref(push: EntityId) -> String {
    format!("{PUSH_CONTENT_REF_PREFIX}{}", push.to_hex())
}

fn push_of_content_ref(content_ref: &str) -> Option<EntityId> {
    EntityId::from_hex(content_ref.strip_prefix(PUSH_CONTENT_REF_PREFIX)?).ok()
}

/// The live inquiry edge `grant` names whose Connect pact admits it now.
/// Refuses an edge that is gone, expired, withdrawn or without an Active
/// pact.
fn live_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
    now: u64,
) -> Result<InquiryEdge> {
    let Some((edge, decoded)) = inquiry_edge_grant_in_txn(vault, txn, grant)? else {
        return Err(refuse(
            "that grant is not a live inquiry edge of this vault",
        ));
    };
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if !decoded.is_live_at(now)
        || vault.guest_grant_withdrawn_in_txn(txn, grant)?
        || !pact_admits_grant(&fold, grant, &decoded)
    {
        return Err(refuse(
            "the inquiry edge has no Active Connect pact with its company",
        ));
    }
    Ok(edge)
}

impl Vault {
    /// Opens the member's route to the company of the inquiry edge
    /// `request.edge_grant`, approved by the member vault's `owner`: the edge
    /// is live with an Active pact, and the slip was issued by the edge's
    /// company, names a grant, is bound to `issuer`'s key and has not
    /// expired. A later open replaces the route, so a renewed slip takes the
    /// old one's place.
    ///
    /// # Errors
    ///
    /// The first of those rules that fails; an owner proof that does not
    /// stand; storage errors.
    pub fn open_inquiry_push_route(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        request: &InquiryPushRouteRequest,
    ) -> Result<InquiryPushRoute> {
        let company_host = request.company_host.trim();
        let origin = company_host
            .strip_prefix("https://")
            .or_else(|| company_host.strip_prefix("http://"));
        if origin.is_none_or(|rest| rest.is_empty() || rest.contains(char::is_whitespace)) {
            return Err(refuse(
                "a push route names the company host as an http(s) origin",
            ));
        }
        let claims = &request.slip.claims;
        if claims.binding_key != issuer.binding_key() {
            return Err(refuse("the slip is not bound to this host's key"));
        }
        let Some(reciprocal_grant) = claims.grant_ref.clone() else {
            return Err(refuse("the slip names no reciprocal grant"));
        };
        let slip_token = request.slip.to_token()?;
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let company = live_edge_in_txn(self, txn, &request.edge_grant, now)?.company_vault_id;
            if claims.vault_id != company {
                return Err(refuse("the slip was not issued by the edge's company"));
            }
            if claims.expires_at <= now {
                return Err(refuse("the slip has expired"));
            }
            let route = InquiryPushRoute {
                edge_grant: request.edge_grant,
                company_vault_id: company,
                company_host: company_host.to_owned(),
                reciprocal_grant,
                slip_token,
                slip_expires_at: claims.expires_at,
                opened_at: now,
            };
            ROUTES.put(&self.store, txn, &request.edge_grant, &route)?;
            Ok(route)
        })
    }

    /// The member's route to the company of the inquiry edge `edge_grant`,
    /// if one is open.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_push_route(&self, edge_grant: &EntityId) -> Result<Option<InquiryPushRoute>> {
        let txn = self.store.env.read_txn()?;
        ROUTES.get(&self.store, &txn, edge_grant)
    }

    /// The member's [Now], approved by the member vault's `owner`: the
    /// statement is told to the company of the inquiry edge
    /// `request.edge_grant` as one send on `inquiry_push`. Before any send,
    /// the edge is live with an Active pact, its push route is open with a
    /// slip that has not expired, the words are within their cap, and the
    /// claim they were drawn from is live, outside the opened scope and not
    /// a foreign copy. The push row is written first; the schedule door then
    /// takes the send, held by the owner's undo-send window when one is set.
    ///
    /// # Errors
    ///
    /// The first of those rules that fails; an owner proof that does not
    /// stand; the schedule door's refusal (the push row is then removed);
    /// storage errors.
    pub fn push_inquiry_statement(
        &self,
        owner: &AuthenticatedOwner,
        request: &InquiryPushRequest,
    ) -> Result<InquiryPushed> {
        let statement = request.statement.trim();
        check_statement(statement)?;
        let push = self.store.clock.entity_id()?;
        let (record, company) = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let edge = live_edge_in_txn(self, txn, &request.edge_grant, now)?;
            let Some(route) = ROUTES.get(&self.store, txn, &request.edge_grant)? else {
                return Err(refuse("no push route to the edge's company is open"));
            };
            if route.slip_expires_at <= now {
                return Err(refuse("the push route's slip has expired"));
            }
            if let Some(source) = request.drawn_from {
                refuse_undrawable_source_in_txn(self, txn, &source, edge.terms.opened_world)?;
            }
            let record = InquiryPush {
                push,
                edge: request.edge_grant,
                statement: statement.to_owned(),
                drawn_from: request.drawn_from,
                told_at: now,
                task_ref: None,
            };
            PUSHES.put(&self.store, txn, &push, &record)?;
            if let Some(source) = request.drawn_from {
                PUSHES_BY_SOURCE.put(&self.store, txn, &(source, push), &())?;
            }
            Ok((record, edge.company_vault_id))
        })?;
        let task_ref = match self.schedule_inquiry_push(owner, &record, &company) {
            Ok(task_ref) => task_ref,
            Err(error) => {
                self.with_write_txn(|txn| drop_inquiry_push_in_txn(&self.store, txn, &record))?;
                return Err(error);
            }
        };
        self.with_write_txn(|txn| {
            if let Some(mut stored) = PUSHES.get(&self.store, txn, &push)? {
                stored.task_ref = Some(task_ref);
                PUSHES.put(&self.store, txn, &push, &stored)?;
            }
            Ok(())
        })?;
        Ok(InquiryPushed { push, task_ref })
    }

    /// The told statement `push` and how it stands, if this vault told it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_push(&self, push: &EntityId) -> Result<Option<InquiryPushView>> {
        let Some(record) = ({
            let txn = self.store.env.read_txn()?;
            PUSHES.get(&self.store, &txn, push)?
        }) else {
            return Ok(None);
        };
        self.inquiry_push_view(record).map(Some)
    }

    /// Every statement this vault told unasked, newest first, and how each
    /// stands: the member's own record of what left over each edge.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_pushes(&self) -> Result<Vec<InquiryPushView>> {
        let records = {
            let txn = self.store.env.read_txn()?;
            PUSHES.scan(&self.store, &txn)?
        };
        let mut views = records
            .into_iter()
            .map(|(_, record)| self.inquiry_push_view(record))
            .collect::<Result<Vec<_>>>()?;
        views.sort_by_key(|view| std::cmp::Reverse((view.push.told_at, view.push.push)));
        Ok(views)
    }

    /// `record` and how it stands, read from its send's connector TASK.
    fn inquiry_push_view(&self, record: InquiryPush) -> Result<InquiryPushView> {
        let state = match record.task_ref {
            None => InquiryPushState::Queued,
            Some(task_ref) => match self.connector_send_task(&task_ref)? {
                None => InquiryPushState::Queued,
                Some(task) => push_state_of(&task),
            },
        };
        Ok(InquiryPushView {
            push: record,
            state,
        })
    }

    /// The route and wire bytes of the released push `push`, read when the
    /// executor runs it: the edge still stands with an Active pact, and its
    /// route is open with a slip that has not expired.
    fn inquiry_push_delivery(&self, push: EntityId) -> Result<(InquiryPushRoute, Vec<u8>)> {
        let txn = self.store.env.read_txn()?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &txn)?;
        let Some(record) = PUSHES.get(&self.store, &txn, &push)? else {
            return Err(refuse("the told statement is gone"));
        };
        live_edge_in_txn(self, &txn, &record.edge, now)?;
        let Some(route) = ROUTES.get(&self.store, &txn, &record.edge)? else {
            return Err(refuse("no push route to the edge's company is open"));
        };
        if route.slip_expires_at <= now {
            return Err(refuse("the push route's slip has expired"));
        }
        let wire = InquiryPushWire {
            push,
            edge_grant: record.edge.to_hex(),
            statement: InquiryStatement::new(record.statement, StatementSource::MemberWord)?,
            told_at: record.told_at,
        }
        .encode_wire()?;
        Ok((route, wire))
    }

    /// Lands the statement `wire` the member's vault told this vault unasked,
    /// on the company's side, under `proof` (the member host's own
    /// credential on this vault's reciprocal grant `grant`), in one writer
    /// (lead ruling L7-03-LANDING = A):
    ///
    /// * the credential names `grant`, unattenuated and live; `grant` is a
    ///   live Connect guest grant of this vault carrying the class
    ///   `inquiry_push`, which only an inquiry edge's reciprocal grant
    ///   carries, and its Connect pact admits it;
    /// * the company Owner opened a route to the member over the edge the
    ///   push names, so the member's seat names the PERSON it is about;
    /// * the words land at once as one CLAIM in the foreign WORLD of the
    ///   member's vault and opened world, attributed by a delivery record,
    ///   whatever `inquiry_keep` says, with one `inquiry` receipt.
    ///
    /// A re-delivery of the same push lands nothing more and answers the
    /// first landing.
    ///
    /// # Errors
    ///
    /// The first of those rules that fails; an invalid push; no Active pact
    /// that opens exactly one world here; storage errors.
    pub fn land_pushed_inquiry_statement(
        &self,
        grant: EntityId,
        proof: &VerifiedSlip,
        wire: &InquiryPushWire,
    ) -> Result<InquiryPushLanded> {
        wire.validate()?;
        self.with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let (member_vault, guest_actor) =
                admitted_push_grant_in_txn(self, txn, grant, proof, now)?;
            if let Some(claim) = LANDED.get(&self.store, txn, &(member_vault, wire.push))? {
                return Ok(InquiryPushLanded {
                    claim,
                    receipt_id: inquiry_push_receipt_id(wire.push),
                    landed_now: false,
                });
            }
            let edge_grant = EntityId::from_hex(&wire.edge_grant)
                .map_err(|_| refuse("a told statement names its edge grant as 32 hex"))?
                .to_hex();
            let routes =
                inquiry_routes_to_member_in_txn(&self.store, txn, &member_vault, &edge_grant)?;
            let Some(route) = routes.first() else {
                return Err(refuse(
                    "no route to the member over that edge is open on this vault",
                ));
            };
            if routes.iter().any(|other| other.member != route.member) {
                return Err(refuse("the edge's routes name more than one member here"));
            }
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            let Some(landing) = inquiry_landing(&fold, route)? else {
                return Err(refuse(
                    "no Active Connect pact with the member's vault opens one world here",
                ));
            };
            let claim = self.store.clock.entity_id()?;
            self.land_pushed_copy_in_txn(
                txn,
                &landing,
                claim,
                wire.push,
                route.member,
                &wire.statement,
                now,
            )?;
            LANDED.put(&self.store, txn, &(member_vault, wire.push), &claim)?;
            let receipt = write_inquiry_push_receipt_in_txn(
                &self.store,
                txn,
                wire.push,
                &route.member,
                &guest_actor,
                wire.statement.source(),
                now,
            )?;
            Ok(InquiryPushLanded {
                claim,
                receipt_id: receipt.receipt_id,
                landed_now: true,
            })
        })
    }
}

/// The push state a connector TASK's settlement shows.
fn push_state_of(task: &crate::outbound::ConnectorSendTask) -> InquiryPushState {
    use crate::outbound::ConnectorSendTaskOutcome as Outcome;
    if task.suppression.as_deref() == Some(UNDO_SEND_SUPPRESSION) {
        return InquiryPushState::Undone;
    }
    match task.outcome {
        None => InquiryPushState::Queued,
        Some(Outcome::Delivered) => InquiryPushState::Sent,
        Some(Outcome::Failed | Outcome::Ambiguous | Outcome::OwnerDeclinedResend) => {
            InquiryPushState::Failed
        }
    }
}

/// The suppression a connector TASK settles with when the owner undoes its
/// send inside the window (`outbound::connector_task`).
const UNDO_SEND_SUPPRESSION: &str = "undo_send";

/// The member host's credential on this vault's reciprocal grant `grant`, as
/// the company side admits a told statement: the member's vault id (the
/// grant's peer) and the grant's guest actor.
fn admitted_push_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    proof: &VerifiedSlip,
    now: u64,
) -> Result<(AuthorityVaultId, EntityId)> {
    let not_admitted = || refuse("the credential does not admit a told statement over this grant");
    let claims = proof.claims();
    if claims.grant_ref.as_deref() != Some(grant.to_hex().as_str())
        || proof.is_transferred()
        || !proof.is_unattenuated()
        || !claims.channels.is_empty()
        || !claims.records.is_empty()
        || !vault.capability_slip_is_live_in_txn(txn, proof)?
    {
        return Err(not_admitted());
    }
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &grant)?
    else {
        return Err(not_admitted());
    };
    let decoded = decode_federation_grant_body(&body)?;
    let FederationGrantScope::Connect { peer_vault_id } = &decoded.scope else {
        return Err(not_admitted());
    };
    let member_vault = *peer_vault_id;
    let push_class = matches!(&decoded.authority_scope.verbs, ScopeAxis::Some(verbs)
        if verbs.contains(INQUIRY_PUSH_VERB_CLASS));
    if !push_class || !decoded.authority_scope.is_narrowing_of(proof.scope()) {
        return Err(not_admitted());
    }
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if !decoded.is_live_at(now)
        || vault.guest_grant_withdrawn_in_txn(txn, &grant)?
        || !pact_admits_grant(&fold, &grant, &decoded)
    {
        return Err(not_admitted());
    }
    Ok((member_vault, decoded.member_ref))
}

/// Removes `record`'s push row and its source marker: a push whose send the
/// schedule door refused never stands.
fn drop_inquiry_push_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &InquiryPush,
) -> Result<()> {
    PUSHES.delete(store, wtxn, &record.push)?;
    if let Some(source) = record.drawn_from {
        PUSHES_BY_SOURCE.delete(store, wtxn, &(source, record.push))?;
    }
    Ok(())
}

/// Ends the member's route of the inquiry edge `edge_grant`, in the edge's
/// revoke writer. Returns whether a route was open.
///
/// # Errors
///
/// Storage errors.
pub(super) fn end_inquiry_push_route_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    edge_grant: &EntityId,
) -> Result<bool> {
    ROUTES.delete(store, wtxn, edge_grant)
}

/// Drops the link of every push drawn from `claim`, when an erase removes
/// that claim: the push keeps its words, and no longer names the claim.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn drop_inquiry_push_links_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<()> {
    for (source, push) in PUSHES_BY_SOURCE.scan_keys(store, wtxn, claim.as_bytes())? {
        if let Some(mut record) = PUSHES.get(store, wtxn, &push)? {
            record.drawn_from = None;
            PUSHES.put(store, wtxn, &push, &record)?;
        }
        PUSHES_BY_SOURCE.delete(store, wtxn, &(source, push))?;
    }
    Ok(())
}

/// The company vault id `company`, as a send's target names it.
fn company_target(company: &AuthorityVaultId) -> String {
    bytes_to_hex_lower(company)
}

impl Vault {
    /// Schedules `record`'s send to `company` on `inquiry_push` through the
    /// schedule door, as the owner's own act, and returns its connector
    /// TASK. The owner's Human actor schedules it, so the enqueue holds it in
    /// the owner's undo-send window when one is set. The Gate asks for an
    /// approval of this one send (no standing grant covers an owner's push),
    /// and the owner's [Now] is that approval: an approve-once of the digest
    /// the Gate named, which the executor spends once the send is released.
    fn schedule_inquiry_push(
        &self,
        owner: &AuthenticatedOwner,
        record: &InquiryPush,
        company: &AuthorityVaultId,
    ) -> Result<EntityId> {
        let reference = push_content_ref(record.push);
        let receipt = self
            .memory(owner.actor(), EdgeActorClass::Human)
            .schedule_outbound(&OutboundDraftInput {
                verb: "send".to_owned(),
                channel: INQUIRY_PUSH_CHANNEL.to_owned(),
                target: company_target(company),
                on_behalf_of: None,
                content_ref: Some(reference.clone()),
                idempotency_key: Some(reference.clone()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: reference,
                job_ref: None,
                occurred_at: None,
                mention: None,
            })
            .map_err(|error| refuse(&format!("the schedule door refused the push: {error}")))?;
        if receipt.outcome != "held" {
            return Err(refuse(&format!(
                "the schedule door did not queue the push: {}",
                receipt.outcome
            )));
        }
        let attempt = receipt
            .intent_ref
            .strip_prefix("intent:")
            .and_then(crate::deletion::parse_hex::<16>)
            .and_then(|bytes| AttemptId::from_bytes(&bytes).ok())
            .ok_or_else(|| refuse("the schedule door named no attempt"))?;
        let task_ref = AttemptQueue::new(self)
            .get(attempt)?
            .and_then(|queued| queued.task_ref)
            .and_then(|hex| EntityId::from_hex(&hex).ok())
            .ok_or_else(|| refuse("the push's attempt names no connector TASK"))?;
        if let Some(digest) = receipt.approval_digest.as_deref() {
            let digest = crate::deletion::parse_hex::<32>(digest)
                .ok_or_else(|| refuse("the Gate named no approval digest"))?;
            self.approve_once(owner, EffectDigest::from_bytes(digest))?;
        }
        Ok(task_ref)
    }
}

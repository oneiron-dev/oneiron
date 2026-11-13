//! The inquiry verbs (INQUIRE-1 PR 5; federation.md #inquiry; Engine ruling
//! INQUIRE-SHAPE Q2, Q4, Q7 = A): the typed inputs and answers of every
//! `vault.inquire` / `vault.inquiry.*` row, and the fn each row calls.
//!
//! - The asking side: `vault.inquire` (the company's agent sends one
//!   inquiry over a member's route; act `read`), and the company Owner's
//!   `vault.inquiry.route.open` and `vault.inquiry.reciprocal_grant.mint`.
//! - The member side: `vault.inquiry.answer` (the member's word leaves the
//!   vault; act `outbound_send`), `vault.inquiry.list` ("Asked about you"),
//!   `vault.inquiry.scope.open` / `.close` / `.list`, and
//!   `vault.inquiry.edge.mint` / `.revoke`.
//!
//! The engine doors in `crate::inquiry` judge every act; these fns only
//! parse the wire and project the answer. A row that signs with the host's
//! own key (`vault.inquire`, the route open, the edge revoke) is refused on
//! an embedded handle, which holds none.

use serde::{Deserialize, Serialize};

use super::EmptyRequest;
use crate::authority::{AuthorityVaultId, CapabilitySlip, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::federation::FederationDirectionScope;
use crate::inquiry::{
    InquiryAnswer, InquiryCheckInMode, InquiryDecider, InquiryEdge, InquiryEdgeReciprocalGrant,
    InquiryEdgeRequest, InquiryKeep, InquiryLogEntry, InquiryMemberAnswer, InquiryRoute,
    InquiryRouteRequest, InquiryScopeItem, InquirySendRequest, InquirySent, InquiryStatement,
    InquiryTierCeiling, InquiryTransport,
};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::receipt::{GuestRevokeResponse, project_guest_revoke};
use crate::{EdgeActorClass, EntityId, Vault};

/// `vault.inquire`'s input: one inquiry about `member`'s seat in the shared
/// vault `shared_vault_id`, for the caller's open TASK `task`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquireRequest {
    /// The shared vault the member holds a seat in.
    pub shared_vault_id: u64,
    /// The member asked about: the member's PERSON in that shared vault.
    pub member: EntityId,
    /// The question, one line.
    pub question: String,
    /// The caller's open TASK the answer serves.
    pub task: EntityId,
    /// One line: what the task needs the answer for.
    pub purpose: String,
    /// The second the caller stops waiting (Unix seconds).
    pub expires_at: u64,
    /// The id of an earlier send to re-send; absent sends a new inquiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inquiry_id: Option<EntityId>,
}

/// One statement of an answer: its text and the source that made it,
/// `member_word` or `companion_of_member` (provisional).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryStatementView {
    pub text: String,
    pub source: String,
}

/// `vault.inquire`'s answer: the outcome (`answered`, `no_answer`,
/// `pending` or `unavailable`), the member's statements when answered, the
/// send's `inquiry` receipt, and whether this vault holds the statements
/// with the task.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquireAnswer {
    /// The inquiry's id; a re-send names it.
    pub inquiry_id: EntityId,
    pub outcome: String,
    pub statements: Vec<InquiryStatementView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    /// The keep the inquiry was sent with, `task` or `copy`.
    pub keep: String,
    pub receipt_id: String,
    pub held: bool,
}

/// `vault.inquiry.route.open`'s input: the member's seat, the member's vault
/// (64 hex), the member host's origin and the slip the member's vault
/// minted for this host on its inquiry edge (`v2.slip.`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryRouteOpenRequest {
    pub shared_vault_id: u64,
    pub member: EntityId,
    pub member_vault: String,
    /// `https://host[:port]`; plain `http` only on loopback.
    pub member_host: String,
    pub slip: String,
}

/// `vault.inquiry.route.open`'s answer: the route as this vault stores it,
/// without the slip.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryRouteOpened {
    pub shared_vault_id: u64,
    pub member: EntityId,
    pub member_vault: String,
    pub member_host: String,
    /// The member vault's inquiry edge grant, hex, as the slip names it.
    pub edge_grant: String,
    pub slip_expires_at: u64,
    pub opened_at: u64,
}

/// `vault.inquiry.reciprocal_grant.mint`'s input: the member's vault (64
/// hex) and the member's name, as the grant's WORLD title reads it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryReciprocalGrantMintRequest {
    pub member_vault: String,
    pub member_name: String,
}

/// `vault.inquiry.reciprocal_grant.mint`'s answer: the company's propose-only
/// grant to the member's vault, and the pact direction the Connect offer
/// and accept bind it as.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryReciprocalGrantMinted {
    pub grant: EntityId,
    pub world: EntityId,
    pub guest_actor: EntityId,
    pub pact_direction: FederationDirectionScope,
}

/// `vault.inquiry.edge.mint`'s input: the company's vault (64 hex) and name,
/// and the edge's terms. An absent term takes the member default: tier
/// `unstamped`, mode `ask_when_unsure`, keep `task`, no expiry.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryEdgeMintRequest {
    pub company_vault: String,
    pub company_name: String,
    /// `unstamped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_ceiling: Option<String>,
    /// `always_ask`, `ask_when_unsure` or `never_ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_mode: Option<String>,
    /// `task` or `copy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_allowed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// One inquiry edge, as the member's vault stores it, with the pact
/// direction the Connect offer shares it as.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryEdgeView {
    pub grant: EntityId,
    pub company_vault: String,
    pub guest_actor: EntityId,
    pub opened_world: EntityId,
    pub tier_ceiling: String,
    pub check_in_mode: String,
    pub keep_allowed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub pact_direction: FederationDirectionScope,
}

/// The input of every row that names one inquiry edge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryEdgeRef {
    /// The edge's Connect guest grant.
    pub grant: EntityId,
}

/// `vault.inquiry.scope.open`'s input: one statement opened to the edge's
/// company, in the member's words, and the claim it was drawn from (kept
/// member-local; never part of an answer).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryScopeOpenRequest {
    pub grant: EntityId,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawn_from: Option<EntityId>,
}

/// `vault.inquiry.scope.close`'s input: the statement's CLAIM to retract.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryScopeCloseRequest {
    pub grant: EntityId,
    pub claim: EntityId,
}

/// One statement in an edge's opened scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryScopeItemView {
    pub claim: EntityId,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawn_from: Option<EntityId>,
}

/// `vault.inquiry.scope.close`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryScopeClosed {
    pub grant: EntityId,
    pub claim: EntityId,
}

/// `vault.inquiry.scope.list`'s answer: the edge's opened statements.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryScopeItems {
    pub items: Vec<InquiryScopeItemView>,
}

/// An inquiry's answer as it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryAnswerView {
    pub inquiry_id: EntityId,
    /// `answered`, `no_answer`, `pending` or `unavailable`.
    pub outcome: String,
    pub statements: Vec<InquiryStatementView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    pub keep: String,
}

/// One row of "Asked about you": who asked, for which task and why, the
/// question, and its answer as it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryLogRow {
    /// The inquiry edge it came over.
    pub edge: EntityId,
    pub inquiry_id: EntityId,
    /// The asking vault, 64 hex.
    pub asking_vault: String,
    pub asker: EntityId,
    pub asker_role: String,
    pub task: EntityId,
    pub purpose: String,
    pub question: String,
    pub keep: String,
    pub expires_at: u64,
    pub received_at: u64,
    pub answer: InquiryAnswerView,
    /// `standing_row`, `companion`, `member` or `let_go`; absent while
    /// pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<u64>,
}

/// `vault.inquiry.list`'s answer, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InquiryLog {
    pub entries: Vec<InquiryLogRow>,
}

/// `vault.inquiry.answer`'s input: the member's answer to one pending
/// inquiry over the edge `grant`. `words` answer it; absent `words`
/// declines, which answers `no_answer`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryAnswerRequest {
    pub grant: EntityId,
    pub inquiry_id: EntityId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub words: Option<String>,
}

fn bad_request(message: &str) -> MemoryError {
    MemoryError::bad_request(message.to_owned())
}

/// A vault id on the wire: 64 hex.
fn vault_id(field: &str, hex: &str) -> MemoryResult<AuthorityVaultId> {
    let refused = || bad_request(&format!("{field} is not 32 bytes of hex"));
    if hex.len() != 64 {
        return Err(refused());
    }
    let mut id = [0; 32];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(id)
}

fn statement_view(statement: &InquiryStatement) -> InquiryStatementView {
    InquiryStatementView {
        text: statement.text().to_owned(),
        source: statement.source().as_str().to_owned(),
    }
}

fn answer_view(answer: &InquiryAnswer) -> InquiryAnswerView {
    InquiryAnswerView {
        inquiry_id: answer.inquiry_id(),
        outcome: answer.outcome().as_str().to_owned(),
        statements: answer.statements().iter().map(statement_view).collect(),
        valid_until: answer.valid_until(),
        keep: answer.keep().as_str().to_owned(),
    }
}

fn sent_view(sent: &InquirySent) -> InquireAnswer {
    InquireAnswer {
        inquiry_id: sent.inquiry.id,
        outcome: sent.outcome.as_str().to_owned(),
        statements: sent.statements.iter().map(statement_view).collect(),
        valid_until: sent.valid_until,
        keep: sent.inquiry.keep.as_str().to_owned(),
        receipt_id: sent.receipt_id.clone(),
        held: sent.held,
    }
}

fn decider_token(decider: &InquiryDecider) -> &'static str {
    match decider {
        InquiryDecider::StandingRow { .. } => "standing_row",
        InquiryDecider::Companion => "companion",
        InquiryDecider::Member { .. } => "member",
        InquiryDecider::LetGo => "let_go",
    }
}

fn log_row(entry: &InquiryLogEntry) -> InquiryLogRow {
    let inquiry = &entry.inquiry;
    InquiryLogRow {
        edge: entry.edge,
        inquiry_id: inquiry.id,
        asking_vault: inquiry.from.vault.clone(),
        asker: inquiry.from.actor,
        asker_role: inquiry.from.role.clone(),
        task: inquiry.task.id,
        purpose: inquiry.task.purpose.clone(),
        question: inquiry.question.clone(),
        keep: inquiry.keep.as_str().to_owned(),
        expires_at: inquiry.expires_at,
        received_at: entry.received_at,
        answer: answer_view(&entry.answer),
        decided_by: entry
            .decided_by
            .as_ref()
            .map(|by| decider_token(by).to_owned()),
        decided_at: entry.decided_at,
    }
}

fn edge_view(edge: &InquiryEdge) -> MemoryResult<InquiryEdgeView> {
    Ok(InquiryEdgeView {
        grant: edge.grant,
        company_vault: bytes_to_hex_lower(&edge.company_vault_id),
        guest_actor: edge.guest_actor,
        opened_world: edge.terms.opened_world,
        tier_ceiling: edge.terms.tier_ceiling.as_str().to_owned(),
        check_in_mode: edge.terms.check_in_mode.as_str().to_owned(),
        keep_allowed: edge.terms.keep_allowed.as_str().to_owned(),
        expires_at: edge.expires_at,
        pact_direction: edge.pact_direction()?,
    })
}

fn scope_item_view(item: &InquiryScopeItem) -> InquiryScopeItemView {
    InquiryScopeItemView {
        claim: item.claim,
        statement: item.statement.clone(),
        drawn_from: item.drawn_from,
    }
}

fn route_view(route: &InquiryRoute) -> InquiryRouteOpened {
    InquiryRouteOpened {
        shared_vault_id: route.shared_vault_id,
        member: route.member,
        member_vault: bytes_to_hex_lower(&route.member_vault_id),
        member_host: route.member_host.clone(),
        edge_grant: route.edge_grant.clone(),
        slip_expires_at: route.slip_expires_at,
        opened_at: route.opened_at,
    }
}

/// The asking actor's role as the member's log shows it: its actor class
/// on the asking vault. (The agent definition's own role is FIX
/// INQUIRY-ASKER-ROLE-FROM-DEFINITION.)
fn asker_role(class: EdgeActorClass) -> &'static str {
    match class {
        EdgeActorClass::Agent => "agent",
        EdgeActorClass::Human => "person",
        EdgeActorClass::System => "system",
    }
}

/// The refusal of a row that signs with the host's own key on an embedded
/// handle, which holds none.
fn host_key_only(verb: &str, act: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} {act} with the host's own key; an embedded vault holds none"),
        &[super::host::SERVED_CLIENT_HINT],
    )
}

// ---- The asking side ----

/// `vault.inquire` on a server: [`Vault::send_inquiry`] as the calling
/// actor (`memory`), over the member's route through `transport`, which
/// signs each call with this host's key.
///
/// # Errors
///
/// The engine's refusals: the task is not an open TASK of this vault, a
/// field breaks the inquiry's rules, the vault is not rooted. No route, no
/// seat and no answer are the outcome `unavailable`, not errors.
pub fn inquire_through(
    memory: &Memory<'_>,
    transport: &dyn InquiryTransport,
    input: InquireRequest,
) -> MemoryResult<InquireAnswer> {
    let request = InquirySendRequest {
        shared_vault_id: input.shared_vault_id,
        member: input.member,
        asker: memory.actor(),
        asker_role: asker_role(memory.actor_class()).to_owned(),
        task: input.task,
        purpose: input.purpose,
        question: input.question,
        expires_at: input.expires_at,
        inquiry_id: input.inquiry_id,
    };
    let sent = memory.vault().send_inquiry(&request, transport)?;
    Ok(sent_view(&sent))
}

/// `vault.inquire` on an embedded handle: refused, because each inquiry is
/// signed with a host key no embedded vault holds.
pub fn inquire_embedded(
    _memory: &Memory<'_>,
    _input: InquireRequest,
) -> MemoryResult<InquireAnswer> {
    Err(host_key_only("vault.inquire", "signs each inquiry"))
}

/// `vault.inquiry.route.open` on a server: [`Vault::open_inquiry_route`]
/// under the company Owner's proof and the host's own `issuer`, which the
/// slip must be bound to.
///
/// # Errors
///
/// A member vault or slip that does not parse; the engine's refusals.
pub fn open_inquiry_route_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: InquiryRouteOpenRequest,
) -> MemoryResult<InquiryRouteOpened> {
    let member_vault_id = vault_id("member_vault", &input.member_vault)?;
    let slip = CapabilitySlip::from_token(input.slip.trim())
        .map_err(|_| bad_request("slip is not a v2.slip. credential"))?;
    let route = vault.open_inquiry_route(
        owner,
        issuer,
        &InquiryRouteRequest {
            shared_vault_id: input.shared_vault_id,
            member: input.member,
            member_vault_id,
            member_host: input.member_host,
            slip,
        },
    )?;
    Ok(route_view(&route))
}

/// `vault.inquiry.route.open` on an embedded handle: the Owner's call,
/// refused, because the route binds a slip to the host's own key.
pub fn open_inquiry_route_embedded(
    memory: &Memory<'_>,
    _input: InquiryRouteOpenRequest,
) -> MemoryResult<InquiryRouteOpened> {
    let _owner = memory.embedded_owner("vault.inquiry.route.open")?;
    Err(host_key_only(
        "vault.inquiry.route.open",
        "binds the member's slip",
    ))
}

/// `vault.inquiry.reciprocal_grant.mint`: the company Owner's propose-only
/// grant to the member's vault ([`Vault::mint_inquiry_edge_reciprocal_grant`]).
///
/// # Errors
///
/// A member vault that does not parse; the engine's refusals.
pub fn mint_inquiry_reciprocal_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryReciprocalGrantMintRequest,
) -> MemoryResult<InquiryReciprocalGrantMinted> {
    let member_vault_id = vault_id("member_vault", &input.member_vault)?;
    let grant: InquiryEdgeReciprocalGrant =
        vault.mint_inquiry_edge_reciprocal_grant(owner, member_vault_id, &input.member_name)?;
    Ok(InquiryReciprocalGrantMinted {
        grant: grant.grant,
        world: grant.world,
        guest_actor: grant.guest_actor,
        pact_direction: grant.pact_direction()?,
    })
}

/// `vault.inquiry.reciprocal_grant.mint` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`mint_inquiry_reciprocal_grant_as`].
pub fn mint_inquiry_reciprocal_grant_embedded(
    memory: &Memory<'_>,
    input: InquiryReciprocalGrantMintRequest,
) -> MemoryResult<InquiryReciprocalGrantMinted> {
    let owner = memory.embedded_owner("vault.inquiry.reciprocal_grant.mint")?;
    mint_inquiry_reciprocal_grant_as(memory.vault(), &owner, input)
}

// ---- The member side ----

fn parse_token<T>(
    field: &str,
    token: Option<&str>,
    parse: fn(&str) -> Option<T>,
) -> MemoryResult<Option<T>> {
    token
        .map(|token| {
            parse(token.trim()).ok_or_else(|| bad_request(&format!("{field} is not a known value")))
        })
        .transpose()
}

/// `vault.inquiry.edge.mint`: the member's inquiry edge to one company
/// ([`Vault::mint_inquiry_edge`]), on the member defaults where a term is
/// absent.
///
/// # Errors
///
/// A company vault or term that does not parse; the engine's refusals.
pub fn mint_inquiry_edge_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryEdgeMintRequest,
) -> MemoryResult<InquiryEdgeView> {
    let company_vault_id = vault_id("company_vault", &input.company_vault)?;
    let mut request = InquiryEdgeRequest::member_defaults(company_vault_id, &input.company_name);
    if let Some(tier) = parse_token(
        "tier_ceiling",
        input.tier_ceiling.as_deref(),
        InquiryTierCeiling::from_token,
    )? {
        request.tier_ceiling = tier;
    }
    if let Some(mode) = parse_token(
        "check_in_mode",
        input.check_in_mode.as_deref(),
        InquiryCheckInMode::from_token,
    )? {
        request.check_in_mode = mode;
    }
    if let Some(keep) = parse_token(
        "keep_allowed",
        input.keep_allowed.as_deref(),
        InquiryKeep::from_token,
    )? {
        request.keep_allowed = keep;
    }
    request.expires_at = input.expires_at;
    let edge = vault.mint_inquiry_edge(owner, &request)?;
    edge_view(&edge)
}

/// `vault.inquiry.edge.mint` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`mint_inquiry_edge_as`].
pub fn mint_inquiry_edge_embedded(
    memory: &Memory<'_>,
    input: InquiryEdgeMintRequest,
) -> MemoryResult<InquiryEdgeView> {
    let owner = memory.embedded_owner("vault.inquiry.edge.mint")?;
    mint_inquiry_edge_as(memory.vault(), &owner, input)
}

/// `vault.inquiry.edge.revoke` on a server: [`Vault::revoke_inquiry_edge`]
/// under the member's proof and the host's own `issuer`, which signs the
/// pact disconnect.
///
/// # Errors
///
/// The engine's refusals: a grant that is not an inquiry edge.
pub fn revoke_inquiry_edge_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: InquiryEdgeRef,
) -> MemoryResult<GuestRevokeResponse> {
    let outcome = vault.revoke_inquiry_edge(owner, issuer, input.grant)?;
    Ok(project_guest_revoke(outcome))
}

/// `vault.inquiry.edge.revoke` on an embedded handle: the member's call,
/// refused, because the pact disconnect is signed with the host's own key.
pub fn revoke_inquiry_edge_embedded(
    memory: &Memory<'_>,
    _input: InquiryEdgeRef,
) -> MemoryResult<GuestRevokeResponse> {
    let _owner = memory.embedded_owner("vault.inquiry.edge.revoke")?;
    Err(host_key_only(
        "vault.inquiry.edge.revoke",
        "signs the pact disconnect",
    ))
}

/// `vault.inquiry.scope.open`: one statement opened to the edge's company
/// ([`Vault::open_inquiry_scope_item`]).
///
/// # Errors
///
/// The engine's refusals.
pub fn open_inquiry_scope_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryScopeOpenRequest,
) -> MemoryResult<InquiryScopeItemView> {
    let item =
        vault.open_inquiry_scope_item(owner, input.grant, &input.statement, input.drawn_from)?;
    Ok(scope_item_view(&item))
}

/// `vault.inquiry.scope.open` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`open_inquiry_scope_as`].
pub fn open_inquiry_scope_embedded(
    memory: &Memory<'_>,
    input: InquiryScopeOpenRequest,
) -> MemoryResult<InquiryScopeItemView> {
    let owner = memory.embedded_owner("vault.inquiry.scope.open")?;
    open_inquiry_scope_as(memory.vault(), &owner, input)
}

/// `vault.inquiry.scope.close`: retracts one opened statement
/// ([`Vault::close_inquiry_scope_item`]).
///
/// # Errors
///
/// The engine's refusals.
pub fn close_inquiry_scope_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryScopeCloseRequest,
) -> MemoryResult<InquiryScopeClosed> {
    vault.close_inquiry_scope_item(owner, input.grant, input.claim)?;
    Ok(InquiryScopeClosed {
        grant: input.grant,
        claim: input.claim,
    })
}

/// `vault.inquiry.scope.close` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`close_inquiry_scope_as`].
pub fn close_inquiry_scope_embedded(
    memory: &Memory<'_>,
    input: InquiryScopeCloseRequest,
) -> MemoryResult<InquiryScopeClosed> {
    let owner = memory.embedded_owner("vault.inquiry.scope.close")?;
    close_inquiry_scope_as(memory.vault(), &owner, input)
}

/// `vault.inquiry.scope.list`: the edge's opened statements
/// ([`Vault::inquiry_scope_items`]).
///
/// # Errors
///
/// The engine's refusals.
pub fn inquiry_scope_items_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryEdgeRef,
) -> MemoryResult<InquiryScopeItems> {
    let items = vault.inquiry_scope_items(owner, input.grant)?;
    Ok(InquiryScopeItems {
        items: items.iter().map(scope_item_view).collect(),
    })
}

/// `vault.inquiry.scope.list` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`inquiry_scope_items_as`].
pub fn inquiry_scope_items_embedded(
    memory: &Memory<'_>,
    input: InquiryEdgeRef,
) -> MemoryResult<InquiryScopeItems> {
    let owner = memory.embedded_owner("vault.inquiry.scope.list")?;
    inquiry_scope_items_as(memory.vault(), &owner, input)
}

/// `vault.inquiry.list`: "Asked about you", newest first
/// ([`Vault::inquiry_log`]), for the vault's owner alone: `owner` is
/// revalidated before the read.
///
/// # Errors
///
/// An owner proof that no longer stands; storage errors.
pub fn inquiry_log_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: EmptyRequest,
) -> MemoryResult<InquiryLog> {
    owner.revalidate(vault)?;
    let entries = vault.inquiry_log()?;
    Ok(InquiryLog {
        entries: entries.iter().map(log_row).collect(),
    })
}

/// `vault.inquiry.list` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`inquiry_log_as`].
pub fn inquiry_log_embedded(memory: &Memory<'_>, input: EmptyRequest) -> MemoryResult<InquiryLog> {
    let owner = memory.embedded_owner("vault.inquiry.list")?;
    inquiry_log_as(memory.vault(), &owner, input)
}

/// `vault.inquiry.answer`: the member's answer to one pending inquiry
/// ([`Vault::answer_inquiry`]): words answer it and are filed in the
/// edge's opened scope as the member's; absent words decline it.
///
/// # Errors
///
/// Blank words; the engine's refusals (no pending inquiry, an answer after
/// it expired, an edge that is gone).
pub fn answer_inquiry_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: InquiryAnswerRequest,
) -> MemoryResult<InquiryAnswerView> {
    let answer = match input.words {
        Some(words) if words.trim().is_empty() => {
            return Err(bad_request(
                "words are blank: give words, or leave them out to decline",
            ));
        }
        Some(words) => InquiryMemberAnswer::Words(words),
        None => InquiryMemberAnswer::Decline,
    };
    let answered = vault.answer_inquiry(owner, input.grant, input.inquiry_id, &answer)?;
    Ok(answer_view(&answered))
}

/// `vault.inquiry.answer` on an embedded handle.
///
/// # Errors
///
/// No embedded owner; as [`answer_inquiry_as`].
pub fn answer_inquiry_embedded(
    memory: &Memory<'_>,
    input: InquiryAnswerRequest,
) -> MemoryResult<InquiryAnswerView> {
    let owner = memory.embedded_owner("vault.inquiry.answer")?;
    answer_inquiry_as(memory.vault(), &owner, input)
}

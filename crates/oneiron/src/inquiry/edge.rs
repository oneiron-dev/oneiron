//! The inquiry edge and its opened scope (federation.md #inquiry-scope,
//! #inquiry-first-build; Engine ruling INQUIRE-SHAPE Q1 = A).
//!
//! On the member's personal vault the edge is one Connect guest grant to the
//! company vault: verbs the class `inquire` alone, its one world the empty
//! WORLD "What <company> can ask about", and its `inquiry_terms`. The member
//! mints it and offers it on the existing Connect pact; the company Owner
//! accepts with the smallest grant that lets the pact become Active
//! ([`Vault::mint_inquiry_edge_reciprocal_grant`]). Neither grant confers
//! read: `inquire` is not `read`, and the company's grant is `propose` alone.
//!
//! The opened scope starts empty. The member opens a statement into it: a
//! new CLAIM in the opened WORLD, stated by the member, with a private link
//! to the claim it was drawn from that stays in the member's vault. A claim
//! in a foreign WORLD is never drawn from: it is not re-shareable. Closing a
//! statement retracts it.
//!
//! A member seat carries its edge from joining (federation.md
//! #inquiry-first-build: "the edge is created at joining"; Engine rulings
//! L7-04-COMPANY-HALF and L7-04-NO-PERSONAL-VAULT = A). The member's vault
//! mints the edge on the member defaults and offers its Connect
//! ([`Vault::prepare_inquiry_edge_for_join`]); the company's accept writes the
//! seat, the company's reciprocal grant over the WORLD the pact fixes, and
//! the Connect in one writer, approved by the seat
//! ([`Vault::accept_shared_invitation_with_inquiry_edge`], or
//! [`Vault::attach_inquiry_edge_to_seat`] for a seat accepted without one);
//! the member's vault applies the company's counter with
//! [`Vault::accept_connect_as`]. The company's grant ends with the seat.
//!
//! The member changes an edge's terms after the mint in place
//! ([`Vault::change_inquiry_edge_terms`]): the grant row is rewritten, never
//! re-minted, and a Share receipt records the change.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::authority::{AuthorityVaultId, ConnectOffer, ConnectOfferTerms, HostSlipIssuer};
use crate::batch::BatchOp;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, is_foreign_world_id_range};
use crate::error::{Error, Result};
use crate::federation::{
    ConnectGrantApproval, ConnectGrantRequest, ConnectMemberLeaveBinding, FederationDirectionScope,
    FederationGrant, INQUIRE_VERB_CLASS, Scope, ScopeAxis, ScopeId, Sensitivity,
    SensitivityCeiling, connect_direction_projection,
};
use crate::receipt::GuestRevokeOutcome;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT};
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::receipt::write_inquiry_terms_receipt_in_txn;
use super::record::InquiryKeep;
use super::terms::{InquiryCheckInMode, InquiryKeepModes, InquiryTerms, InquiryTierCeiling};

mod join;
mod leave;
mod lookup;
mod scope;

pub use join::{InquiryJoinOffer, InquiryJoinPrepared};
pub(super) use lookup::{inquiry_edge_grant_in_txn, inquiry_edge_in_txn};
pub use scope::InquiryScopeItem;
pub(crate) use scope::drop_inquiry_scope_links_in_txn;
pub(super) use scope::{NewScopeItem, opened_statements_in_txn};

use join::{
    inquiry_join_world, is_seat_inquiry_grant_in_txn, refuse_live_connect_in_txn,
    seat_carries_inquiry_edge_in_txn, unbound_inquiry_edge_in_txn,
};

/// The predicate of a statement the member opened: a statement about the
/// member, in the member's words.
pub const INQUIRY_STATEMENT_PREDICATE: &str = "profile.statement";

/// The verb class of the company's reciprocal grant.
const PROPOSE_VERB_CLASS: &str = "propose";

/// Opened statement → the claim it was drawn from.
const SCOPE_LINK: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::INQUIRY_SCOPE_LINK);
/// Drawn-from claim and opened statement → a presence marker.
const SCOPE_LINK_BY_SOURCE: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::INQUIRY_SCOPE_LINK_BY_SOURCE);

/// What the member asks for when minting an inquiry edge to one company.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryEdgeRequest {
    /// The company's vault, the edge's peer.
    pub company_vault_id: AuthorityVaultId,
    /// The company's name, as the opened scope's title reads it.
    pub company_name: String,
    /// The tier recall reads the opened scope at.
    pub tier_ceiling: InquiryTierCeiling,
    /// The mode the member's check-in ladder runs an inquiry in, for each
    /// keep.
    pub check_in_modes: InquiryKeepModes,
    /// The keep the member allows without being asked.
    pub keep_allowed: InquiryKeep,
    /// The second the edge stops; `None` until revoked.
    pub expires_at: Option<u64>,
}

impl InquiryEdgeRequest {
    /// An edge to `company_vault_id` on the member defaults
    /// (federation.md #inquiry-first-build): tier `unstamped`, modes `auto`
    /// for `task` and `manual` for `copy`, keep `task`, no expiry.
    #[must_use]
    pub fn member_defaults(company_vault_id: AuthorityVaultId, company_name: &str) -> Self {
        Self {
            company_vault_id,
            company_name: company_name.to_owned(),
            tier_ceiling: InquiryTierCeiling::default(),
            check_in_modes: InquiryKeepModes::default(),
            keep_allowed: InquiryKeep::default(),
            expires_at: None,
        }
    }
}

/// What the member changes in an inquiry edge's terms after the mint; a
/// part left `None` stays as it is. The opened WORLD and the tier stay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InquiryTermsChange {
    /// The mode of an inquiry with keep `task`.
    pub task: Option<InquiryCheckInMode>,
    /// The mode of an inquiry with keep `copy`.
    pub copy: Option<InquiryCheckInMode>,
    /// The keep the member allows without being asked.
    pub keep_allowed: Option<InquiryKeep>,
}

/// How a terms change moved an inquiry edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InquiryTermsChangeOutcome {
    /// The terms already read so: nothing was written.
    Unchanged,
    /// No keep's mode answers further without the member, and no wider
    /// keep is allowed ([`InquiryTerms::is_narrowing_of`]).
    Narrowed,
    /// Some keep's mode answers further, or a wider keep is allowed.
    Widened,
}

impl InquiryTermsChangeOutcome {
    /// The wire token, as the change's receipt and verb name it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Narrowed => "narrowed",
            Self::Widened => "widened",
        }
    }
}

/// A terms change: the edge as it now stands, and how it moved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryTermsChanged {
    pub edge: InquiryEdge,
    pub outcome: InquiryTermsChangeOutcome,
}

/// One inquiry edge as the member's vault stores it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryEdge {
    /// The edge's Connect guest grant.
    pub grant: EntityId,
    /// The company's vault.
    pub company_vault_id: AuthorityVaultId,
    /// The vault-resident guest actor the grant names for the company.
    pub guest_actor: EntityId,
    /// The grant's stored scope: `inquire` alone over the opened WORLD.
    pub authority_scope: Scope,
    /// The edge's terms.
    pub terms: InquiryTerms,
    /// The second the edge stops; `None` until revoked.
    pub expires_at: Option<u64>,
}

/// The company's reciprocal grant to the member's vault: the smallest grant
/// that lets the Connect pact become Active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryEdgeReciprocalGrant {
    /// The company's Connect guest grant to the member's vault.
    pub grant: EntityId,
    /// The empty WORLD "Inquiry edge: <member>", the grant's only world.
    pub world: EntityId,
    /// The vault-resident guest actor the grant names for the member's
    /// vault.
    pub guest_actor: EntityId,
    /// The grant's stored scope: `propose` alone over that WORLD.
    pub authority_scope: Scope,
}

impl InquiryEdge {
    /// The pact direction the edge's grant projects to: the member's vault
    /// shares it as its half of the Connect with the company.
    ///
    /// # Errors
    ///
    /// A stored scope that projects to no pact direction.
    pub fn pact_direction(&self) -> Result<FederationDirectionScope> {
        pact_direction_of(&self.authority_scope)
    }
}

impl InquiryEdgeReciprocalGrant {
    /// The pact direction the company's grant projects to: the company's
    /// vault shares it as its half of the Connect with the member's vault.
    ///
    /// # Errors
    ///
    /// A stored scope that projects to no pact direction.
    pub fn pact_direction(&self) -> Result<FederationDirectionScope> {
        pact_direction_of(&self.authority_scope)
    }
}

fn pact_direction_of(scope: &Scope) -> Result<FederationDirectionScope> {
    connect_direction_projection(scope)
        .ok_or_else(|| refused("an inquiry edge's scope projects to no pact direction"))
}

/// The scope of both grants of an inquiry edge: `verb` alone over `world`,
/// no facet, CLAIM records of the default project, at most public content.
/// The smallest live Connect scope; neither verb confers read, so the scope
/// clamps no inquiry: the terms' tier ceiling does.
fn inquiry_edge_scope(world: EntityId, verb: &str) -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(world)])),
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        audience: ScopeAxis::Some(BTreeSet::from([
            ScopeId(crate::claim::default_project_id()),
        ])),
        verbs: ScopeAxis::Some(BTreeSet::from([verb.to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
    }
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Writes `item` into `edge`'s opened scope in `txn` at `now`: a new CLAIM
/// about the member in the opened WORLD, stated by the member, and, when it
/// was drawn from another claim (live and outside the opened WORLD), the
/// member-local link to it. The caller checked who opens it and notifies
/// proactivity after its commit.
pub(super) fn open_inquiry_scope_item_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    item: &NewScopeItem<'_>,
    edge: &InquiryEdge,
    now: u64,
) -> Result<()> {
    let opened_world = edge.terms.opened_world;
    if let Some(source) = item.drawn_from {
        let source_body = vault
            .get_claim_in_txn(txn, &source)?
            .ok_or(Error::EntityNotFound)?;
        if source_body.lifecycle != ClaimLifecycleStatus::Active
            || source_body.world == Some(opened_world)
        {
            return Err(refused(
                "an opened statement is drawn from a live claim outside the opened scope",
            ));
        }
        // A copy another vault shared, or an inquiry answer landed as a
        // copy, is not re-shareable: it is no source for an answer to a third
        // vault (federation.md:36; FIX INQUIRY-SCOPE-DRAWN-FROM-FOREIGN).
        if source_body
            .world
            .is_some_and(crate::entity_id::is_foreign_world_id_range)
        {
            return Err(refused(
                "an opened statement is never drawn from a claim in a foreign WORLD",
            ));
        }
    }
    let mut body = ClaimBody::new(
        INQUIRY_STATEMENT_PREDICATE,
        ClaimSubject::Entity(item.member),
        Value::from(item.statement),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.world = Some(opened_world);
    body.scope_facet = vault.default_facet_in_txn(txn)?;
    body.valid_from = Some(now);
    vault.put_claim_in_txn(
        txn,
        &item.claim,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    if let Some(source) = item.drawn_from {
        SCOPE_LINK.put(&vault.store, txn, &item.claim, &source)?;
        SCOPE_LINK_BY_SOURCE.put(&vault.store, txn, &(source, item.claim), &())?;
    }
    Ok(())
}

/// Rewrites the inquiry edge `grant`'s row as `grant_body` in `txn`, its
/// id, entity type and time kept: the one row write of a terms change.
fn rewrite_inquiry_edge_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    grant: EntityId,
    grant_body: &FederationGrant,
) -> Result<()> {
    let header = vault
        .entity_header_in_txn(txn, &grant)?
        .ok_or(Error::EntityNotFound)?;
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id: grant,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            row_version: None,
            data: crate::federation::encode_federation_grant_body(grant_body)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

impl Vault {
    /// Mints the member's inquiry edge to one company, approved by `owner`,
    /// in one writer: the empty WORLD "What <company> can ask about", then
    /// the Connect guest grant with verbs `inquire` alone over that WORLD
    /// and the request's terms. Every Connect mint check holds (a live
    /// Owner, an unconflicted root, not this vault, the manifest's Connect
    /// guest ceiling, a future expiry); a refusal leaves neither the WORLD
    /// nor the grant. A live Connect with the company refuses, saying the
    /// member disconnects it first: an edge does not join it (Engine ruling
    /// INQUIRE-EDGE-JOIN = A). The edge is inert until the Connect pact
    /// with the company is Active.
    pub fn mint_inquiry_edge(
        &self,
        owner: &AuthenticatedOwner,
        request: &InquiryEdgeRequest,
    ) -> Result<InquiryEdge> {
        self.with_write_txn_grouped(|txn| self.mint_inquiry_edge_in_txn(txn, owner, request))
    }

    /// The writer of [`Self::mint_inquiry_edge`], in the caller's
    /// transaction.
    fn mint_inquiry_edge_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        request: &InquiryEdgeRequest,
    ) -> Result<InquiryEdge> {
        let company = request.company_name.trim();
        if company.is_empty() {
            return Err(refused("an inquiry edge names its company"));
        }
        let name = format!("What {company} can ask about");
        refuse_live_connect_in_txn(self, txn, &request.company_vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let opened_world = self.create_world_in_txn(txn, owner, &name, now)?;
        let terms = InquiryTerms {
            opened_world,
            tier_ceiling: request.tier_ceiling,
            check_in_modes: request.check_in_modes,
            keep_allowed: request.keep_allowed,
        };
        let minted = self.mint_connect_grant_in_txn(
            txn,
            ConnectGrantApproval::Owner(owner),
            request.company_vault_id,
            ConnectGrantRequest {
                scope: inquiry_edge_scope(opened_world, INQUIRE_VERB_CLASS),
                inquiry_terms: Some(terms),
            },
            request.expires_at,
            None,
        )?;
        Ok(InquiryEdge {
            grant: minted.grant,
            company_vault_id: request.company_vault_id,
            guest_actor: minted.guest_actor,
            authority_scope: minted.resolved_scope,
            terms,
            expires_at: minted.expires_at,
        })
    }

    /// Prepares the member's inquiry edge for joining one company's shared
    /// vault, approved by `owner`, in one writer (federation.md
    /// #inquiry-first-build: "the edge is created at joining"; Engine ruling
    /// L7-04-COMPANY-HALF = A): the edge on the member defaults, minted as
    /// [`Self::mint_inquiry_edge`] mints it, or the unbound edge an earlier
    /// prepare left to that company; then this host's signed half of the
    /// Connect that binds it to the company's reciprocal grant, whose WORLD
    /// the pact's id fixes. The company takes the offer with the seat
    /// ([`Self::accept_shared_invitation_with_inquiry_edge`]) or later
    /// ([`Self::attach_inquiry_edge_to_seat`]); this vault then applies the
    /// company's counter with [`Self::accept_connect_as`] on the edge's
    /// grant. A live Connect with the company refuses, as the mint does
    /// (INQUIRE-EDGE-JOIN = A).
    ///
    /// # Errors
    ///
    /// A blank member or company name; a proof that is not this vault's live
    /// Owner; an issuer that is not this vault's host; a live Connect with
    /// the company; any refusal of the edge's mint; storage errors.
    pub fn prepare_inquiry_edge_for_join(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        company_vault_id: AuthorityVaultId,
        company_name: &str,
        member_name: &str,
    ) -> Result<InquiryJoinPrepared> {
        let member = member_name.trim();
        if member.is_empty() {
            return Err(refused(
                "an inquiry edge offered at joining names its member",
            ));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            refuse_live_connect_in_txn(self, txn, &company_vault_id)?;
            let edge = match unbound_inquiry_edge_in_txn(self, txn, &company_vault_id)? {
                Some(edge) => edge,
                None => self.mint_inquiry_edge_in_txn(
                    txn,
                    owner,
                    &InquiryEdgeRequest::member_defaults(company_vault_id, company_name),
                )?,
            };
            let pact_id = crate::authority::fresh_pact_id();
            let company_world = inquiry_join_world(&company_vault_id, &pact_id)?;
            let terms = ConnectOfferTerms {
                grant_ref: edge.grant,
                peer_vault_id: company_vault_id,
                outbound: edge.pact_direction()?,
                inbound: pact_direction_of(&inquiry_edge_scope(company_world, PROPOSE_VERB_CLASS))?,
            };
            let connect = self.propose_connect_in_txn(txn, issuer, terms, pact_id)?;
            Ok(InquiryJoinPrepared {
                edge,
                offer: InquiryJoinOffer {
                    member_name: member.to_owned(),
                    connect,
                },
            })
        })
    }

    /// The company's half of a member seat's inquiry edge, in the caller's
    /// writer, approved by `member`'s live seat in `shared_vault_id` (Engine
    /// ruling L7-04-COMPANY-HALF = A): the WORLD the offer's pact fixes,
    /// named "Inquiry edge: <member>"; the company's Connect guest grant to
    /// the member's vault with verbs `propose` alone over it, released when
    /// the member leaves; then the Connect logged from the member host's
    /// offer and signed by this vault's host `issuer`. Answers this host's
    /// counter, which goes back to the member's vault in the door's answer
    /// and never into a receipt or a log: it carries the pact's scope opening
    /// key. An exact repeat of a joined offer writes nothing and answers the
    /// same counter.
    pub(crate) fn join_inquiry_edge_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        shared_vault_id: u64,
        member: EntityId,
        join: &InquiryJoinOffer,
    ) -> Result<ConnectOffer> {
        if !self.holds_inquiry_seat_in_txn(txn, shared_vault_id, member)? {
            return Err(refused(
                "an inquiry edge joins only its member's own seat in this shared vault",
            ));
        }
        // The offer names its member, its exact repeat included (review
        // round 2 of #9195): a repeat answers only an offer the first call
        // would have taken.
        if join.member_name.trim().is_empty() {
            return Err(refused(
                "an inquiry edge offered at joining names its member",
            ));
        }
        let connect = &join.connect;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let local = fold
            .vault_id
            .ok_or_else(|| refused("this vault has no authority root yet"))?;
        let seat = ConnectMemberLeaveBinding {
            shared_vault_id,
            person_ref: member,
        };
        if let Some(pact) = fold.federation_pacts.get(&connect.pact_id) {
            let grant = pact.grant_ref;
            if !is_seat_inquiry_grant_in_txn(self, txn, &local, &grant, &connect.pact_id, seat)? {
                return Err(refused(
                    "that Connect offer's pact is not this seat's inquiry edge",
                ));
            }
            return Ok(self.accept_connect_in_txn(txn, issuer, grant, connect)?.1);
        }
        // One edge per seat (ARCH-0043 #inquiry-edge: "Every member seat
        // carries an inquiry edge"; FIX INQUIRY-EDGE-ONE-PER-SEAT). The exact
        // repeat was answered above, so a live inquiry edge of the seat here
        // belongs to another pact: a second edge, refused before any WORLD,
        // grant or pact is written.
        if seat_carries_inquiry_edge_in_txn(self, txn, &fold, &local, seat)? {
            return Err(refused("this member seat already carries an inquiry edge"));
        }
        // The WORLD is named for the seat's PERSON as this vault holds it,
        // never for the name the member's offer gives, which could be another
        // member's; a PERSON with no stored name reads as its id's prefix. Its
        // first 48 characters keep the WORLD's name inside its 256 bytes.
        let member_name: String = crate::reaction::person_name_in(self, txn, member)?
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| member.to_hex()[..8].to_owned())
            .trim()
            .chars()
            .take(48)
            .collect();
        let world = inquiry_join_world(&local, &connect.pact_id)?;
        // A member who leaves and joins again gets a new WORLD, so its name
        // carries the pact's own part.
        let name = format!("Inquiry edge: {member_name} ({})", &world.to_hex()[..8]);
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        // The seat checked above approves the WORLD; the grant's mint below
        // re-checks it in this writer, and a refusal rolls the WORLD back.
        self.put_world_in_txn(txn, world, &name, now, |_, _| Ok(()))?;
        let minted = self.mint_connect_grant_in_txn(
            txn,
            ConnectGrantApproval::InquirySeat {
                shared_vault_id,
                member,
            },
            connect.from_vault,
            ConnectGrantRequest {
                scope: inquiry_edge_scope(world, PROPOSE_VERB_CLASS),
                inquiry_terms: None,
            },
            None,
            None,
        )?;
        Ok(self
            .accept_connect_in_txn(txn, issuer, minted.grant, connect)?
            .1)
    }

    /// Attaches a member's inquiry edge to their seat, accepted earlier
    /// without one (Engine ruling L7-04-NO-PERSONAL-VAULT = A): on `member`'s
    /// own person-tier proof, for their own live seat in `shared_vault_id`
    /// (delegates and guests aside), the company's half of the edge is
    /// written as the accept writes it, in one writer and signed by this
    /// vault's host `issuer`. No Owner act: the seat approves its own edge
    /// (L7-04-COMPANY-HALF = A). An exact repeat answers the same counter and
    /// writes nothing. Until an edge is attached, an inquiry to the seat has
    /// no route and answers `unavailable`.
    ///
    /// # Errors
    ///
    /// A proof of no live person; no seat of theirs here; an offer that is
    /// not for this vault or that its pact's terms refuse; a live Connect
    /// with the member's vault; storage errors.
    pub fn attach_inquiry_edge_to_seat(
        &self,
        member: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        shared_vault_id: u64,
        join: &InquiryJoinOffer,
    ) -> Result<ConnectOffer> {
        self.with_write_txn_grouped(|txn| {
            let actor = member.revalidate_person_in_txn(self, txn)?;
            self.join_inquiry_edge_in_txn(txn, issuer, shared_vault_id, actor, join)
        })
    }

    /// The company's side of an inquiry edge, approved by the company's
    /// `owner`, in one writer: the empty WORLD "Inquiry edge: <member>",
    /// then a Connect guest grant to the member's vault with verbs
    /// `propose` alone over that WORLD, no facet, CLAIM records of the
    /// default project, at most public content (Engine ruling INQUIRE-SHAPE
    /// Q1 = A). It shares nothing: `propose` confers no read, and the WORLD
    /// holds no record. The existing Connect offer and accept then bind it.
    pub fn mint_inquiry_edge_reciprocal_grant(
        &self,
        owner: &AuthenticatedOwner,
        member_vault_id: AuthorityVaultId,
        member_name: &str,
    ) -> Result<InquiryEdgeReciprocalGrant> {
        let member = member_name.trim();
        if member.is_empty() {
            return Err(refused(
                "an inquiry edge's reciprocal grant names its member",
            ));
        }
        let name = format!("Inquiry edge: {member}");
        self.with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let world = self.create_world_in_txn(txn, owner, &name, now)?;
            let minted = self.mint_connect_grant_in_txn(
                txn,
                ConnectGrantApproval::Owner(owner),
                member_vault_id,
                ConnectGrantRequest {
                    scope: inquiry_edge_scope(world, PROPOSE_VERB_CLASS),
                    inquiry_terms: None,
                },
                None,
                None,
            )?;
            Ok(InquiryEdgeReciprocalGrant {
                grant: minted.grant,
                world,
                guest_actor: minted.guest_actor,
                authority_scope: minted.resolved_scope,
            })
        })
    }

    /// Changes an inquiry edge's terms after the mint, as the member's own
    /// act, in one writer (Engine ruling INQUIRE-STANDING = A; FIX
    /// INQUIRY-STANDING-PER-KEEP): the grant row's `inquiry_terms` are
    /// rewritten in place, its id, time and every other part kept, so the
    /// edge is not re-minted and its pact and slips stand; a Share receipt
    /// records the change. The next inquiry reads the new terms.
    ///
    /// `member` is this vault's live owner either way. A narrowing applies
    /// on that person's own proof, as a person's own refusal does, a person
    /// credential included. A widening takes the owner-tier proof the mint
    /// takes, so a person credential never widens. Terms that already read
    /// so write nothing.
    ///
    /// # Errors
    ///
    /// A proof of anyone who does not own this vault; a widening without
    /// the owner-tier proof; a grant that is not a live inquiry edge here;
    /// storage errors.
    pub fn change_inquiry_edge_terms(
        &self,
        member: &AuthenticatedOwner,
        grant: EntityId,
        change: InquiryTermsChange,
    ) -> Result<InquiryTermsChanged> {
        self.with_write_txn_grouped(|txn| {
            let actor = member.revalidate_person_in_txn(self, txn)?;
            if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &actor)? {
                return Err(refused(
                    "only the member who owns this vault changes an inquiry edge's terms",
                ));
            }
            let Some((edge, mut grant_body)) = inquiry_edge_grant_in_txn(self, txn, &grant)? else {
                return Err(refused(
                    "that grant is not a live inquiry edge of this vault",
                ));
            };
            let previous = edge.terms;
            let terms = InquiryTerms {
                check_in_modes: InquiryKeepModes {
                    task: change.task.unwrap_or(previous.check_in_modes.task),
                    copy: change.copy.unwrap_or(previous.check_in_modes.copy),
                },
                keep_allowed: change.keep_allowed.unwrap_or(previous.keep_allowed),
                ..previous
            };
            let outcome = if terms == previous {
                InquiryTermsChangeOutcome::Unchanged
            } else if terms.is_narrowing_of(&previous) {
                InquiryTermsChangeOutcome::Narrowed
            } else {
                InquiryTermsChangeOutcome::Widened
            };
            if outcome == InquiryTermsChangeOutcome::Unchanged {
                return Ok(InquiryTermsChanged { edge, outcome });
            }
            if outcome == InquiryTermsChangeOutcome::Widened {
                member.revalidate_in_txn(self, txn)?;
            }
            grant_body.inquiry_terms = Some(terms);
            rewrite_inquiry_edge_row_in_txn(self, txn, grant, &grant_body)?;
            let edge = InquiryEdge { terms, ..edge };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            write_inquiry_terms_receipt_in_txn(
                &self.store,
                txn,
                &edge,
                &previous,
                &actor,
                outcome,
                now,
            )?;
            Ok(InquiryTermsChanged { edge, outcome })
        })
    }

    /// The inquiry edge `grant` names, when it is a live inquiry edge here.
    pub fn inquiry_edge(&self, grant: &EntityId) -> Result<Option<InquiryEdge>> {
        let txn = self.store.env.read_txn()?;
        inquiry_edge_in_txn(self, &txn, grant)
    }

    /// Revokes an inquiry edge, approved by `owner`: the Connect guest
    /// revoke, in one writer (the pact's disconnect, the slips' revokes,
    /// the grant's withdrawal and delete). The opened WORLD and its
    /// statements stay the member's. A grant that is live and no inquiry
    /// edge refuses; a repeat answers the first revoke.
    pub fn revoke_inquiry_edge(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant: EntityId,
    ) -> Result<GuestRevokeOutcome> {
        let outcome = self.with_write_txn_grouped(|txn| {
            if matches!(
                live_entity_row_in_txn(&self.store, txn, &grant)?,
                LiveEntityRow::Live { .. }
            ) && inquiry_edge_in_txn(self, txn, &grant)?.is_none()
            {
                return Err(refused("that grant is not an inquiry edge"));
            }
            self.revoke_guest_access_in_txn(txn, owner, issuer, grant)
        })?;
        if !outcome.revoked_slips.is_empty() {
            self.store.notify_credential_revocations();
        }
        Ok(outcome)
    }
}

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
//! to the claim it was drawn from that stays in the member's vault. Closing
//! a statement retracts it.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::authority::{AuthorityVaultId, HostSlipIssuer};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    ConnectGrantRequest, FederationDirectionScope, FederationGrant, FederationGrantScope,
    INQUIRE_VERB_CLASS, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    connect_direction_projection, decode_federation_grant_body, require_one_connect_per_peer,
};
use crate::receipt::GuestRevokeOutcome;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::record::InquiryKeep;
use super::terms::{InquiryCheckInMode, InquiryTerms, InquiryTierCeiling};

/// The predicate of a statement the member opened: a statement about the
/// member, in the member's words.
pub const INQUIRY_STATEMENT_PREDICATE: &str = "profile.statement";

/// The verb class of the company's reciprocal grant.
const PROPOSE_VERB_CLASS: &str = "propose";

/// How many opened statements one page of the WORLD index reads.
const SCOPE_PAGE: usize = 256;

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
    /// The mode the member's check-in ladder runs an inquiry in.
    pub check_in_mode: InquiryCheckInMode,
    /// The keep the member allows without being asked.
    pub keep_allowed: InquiryKeep,
    /// The second the edge stops; `None` until revoked.
    pub expires_at: Option<u64>,
}

impl InquiryEdgeRequest {
    /// An edge to `company_vault_id` on the member defaults
    /// (federation.md #inquiry-first-build): tier `unstamped`, mode
    /// `ask_when_unsure`, keep `task`, no expiry.
    #[must_use]
    pub fn member_defaults(company_vault_id: AuthorityVaultId, company_name: &str) -> Self {
        Self {
            company_vault_id,
            company_name: company_name.to_owned(),
            tier_ceiling: InquiryTierCeiling::default(),
            check_in_mode: InquiryCheckInMode::default(),
            keep_allowed: InquiryKeep::default(),
            expires_at: None,
        }
    }
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

/// One statement in an edge's opened scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryScopeItem {
    /// The statement's CLAIM in the opened WORLD.
    pub claim: EntityId,
    /// The statement, in the member's words.
    pub statement: String,
    /// The claim it was drawn from, read from the member-local link; never
    /// part of an answer.
    pub drawn_from: Option<EntityId>,
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

/// The inquiry edge `grant` names, with the grant it decodes from, when it
/// is a live inquiry edge here. "Live" is the grant's row: its expiry, its
/// withdrawal and its pact are the caller's to check.
pub(super) fn inquiry_edge_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<Option<(InquiryEdge, FederationGrant)>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant)?
    else {
        return Ok(None);
    };
    let decoded = decode_federation_grant_body(&body)?;
    let (FederationGrantScope::Connect { peer_vault_id }, Some(terms)) =
        (&decoded.scope, decoded.inquiry_terms)
    else {
        return Ok(None);
    };
    let edge = InquiryEdge {
        grant: *grant,
        company_vault_id: *peer_vault_id,
        guest_actor: decoded.member_ref,
        authority_scope: decoded.authority_scope.clone(),
        terms,
        expires_at: decoded.expires_at,
    };
    Ok(Some((edge, decoded)))
}

/// The inquiry edge `grant` names, when it is a live inquiry edge here.
pub(super) fn inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<Option<InquiryEdge>> {
    Ok(inquiry_edge_grant_in_txn(vault, txn, grant)?.map(|(edge, _)| edge))
}

fn require_inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<InquiryEdge> {
    inquiry_edge_in_txn(vault, txn, grant)?
        .ok_or_else(|| refused("that grant is not a live inquiry edge of this vault"))
}

/// One statement to open in an edge's scope: its new CLAIM's id, the member
/// it is about, its words (trimmed, not empty) and the claim it was drawn
/// from.
pub(super) struct NewScopeItem<'a> {
    pub(super) claim: EntityId,
    pub(super) member: EntityId,
    pub(super) statement: &'a str,
    pub(super) drawn_from: Option<EntityId>,
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

/// One live statement of an opened scope, with the body it was read from.
pub(super) struct OpenedStatement {
    pub(super) claim: EntityId,
    pub(super) text: String,
    pub(super) body: ClaimBody,
}

/// The live statements of the opened WORLD `world`, in id order: the Active
/// claims of the statement predicate in that WORLD whose value is text.
/// Nothing outside the WORLD is read.
pub(super) fn opened_statements_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<OpenedStatement>> {
    let mut statements = Vec::new();
    let mut after = None;
    loop {
        let page = crate::store::claim_projection::claim_ids_for_world_page_in_txn(
            &vault.store,
            txn,
            world,
            after,
            SCOPE_PAGE,
        )?;
        let Some(last) = page.last().copied() else {
            return Ok(statements);
        };
        for claim in page {
            let Some(body) = vault.get_claim_in_txn(txn, &claim)? else {
                continue;
            };
            let Some(text) = body.value.as_str().map(str::to_owned) else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active
                || body.predicate != INQUIRY_STATEMENT_PREDICATE
                || body.world != Some(world)
            {
                continue;
            }
            statements.push(OpenedStatement { claim, text, body });
        }
        after = Some(last);
    }
}

/// Drops the link `statement` was opened with, when it has one: when the
/// member closes the statement. A link another opened statement holds to
/// `statement` stays; it goes only with an erase.
fn drop_inquiry_scope_link_of_statement_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    statement: &EntityId,
) -> Result<()> {
    if let Some(source) = SCOPE_LINK.get(store, wtxn, statement)? {
        SCOPE_LINK.delete(store, wtxn, statement)?;
        SCOPE_LINK_BY_SOURCE.delete(store, wtxn, &(source, *statement))?;
    }
    Ok(())
}

/// Drops every scope link `claim` stands in, as the opened statement or as
/// the claim one was drawn from: when an erase removes either claim.
pub(crate) fn drop_inquiry_scope_links_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<()> {
    drop_inquiry_scope_link_of_statement_in_txn(store, wtxn, claim)?;
    for (source, opened) in SCOPE_LINK_BY_SOURCE.scan_keys(store, wtxn, claim.as_bytes())? {
        SCOPE_LINK.delete(store, wtxn, &opened)?;
        SCOPE_LINK_BY_SOURCE.delete(store, wtxn, &(source, opened))?;
    }
    Ok(())
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
        let company = request.company_name.trim();
        if company.is_empty() {
            return Err(refused("an inquiry edge names its company"));
        }
        let name = format!("What {company} can ask about");
        self.with_write_txn_grouped(|txn| {
            // An edge cannot join a live Connect with the company: the grant
            // row is never widened in place and a re-scope only narrows
            // (Engine ruling INQUIRE-EDGE-JOIN = A).
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            if require_one_connect_per_peer(&fold, &request.company_vault_id, None).is_err() {
                return Err(refused(
                    "this vault already has a live Connect with that company, and an inquiry \
                     edge cannot join it yet: disconnect that Connect first, then mint the edge",
                ));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let opened_world = self.create_world_in_txn(txn, owner, &name, now)?;
            let terms = InquiryTerms {
                opened_world,
                tier_ceiling: request.tier_ceiling,
                check_in_mode: request.check_in_mode,
                keep_allowed: request.keep_allowed,
            };
            let minted = self.mint_connect_grant_in_txn(
                txn,
                owner,
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
                owner,
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

    /// Opens one statement to the company, approved by `owner`, in one
    /// writer: a new CLAIM about the member in the edge's opened WORLD,
    /// stated by the member, and, when it was drawn from another claim
    /// (`drawn_from`, live and outside the opened WORLD), the member-local
    /// link to it. The link never enters the statement's body.
    pub fn open_inquiry_scope_item(
        &self,
        owner: &AuthenticatedOwner,
        grant: EntityId,
        statement: &str,
        drawn_from: Option<EntityId>,
    ) -> Result<InquiryScopeItem> {
        let statement = statement.trim();
        if statement.is_empty() {
            return Err(refused("an opened statement has words"));
        }
        let claim = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            let member = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let edge = require_inquiry_edge_in_txn(self, txn, &grant)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            open_inquiry_scope_item_in_txn(
                self,
                txn,
                &NewScopeItem {
                    claim,
                    member,
                    statement,
                    drawn_from,
                },
                &edge,
                now,
            )
        })?;
        self.store.notify_proactivity_changes();
        Ok(InquiryScopeItem {
            claim,
            statement: statement.to_owned(),
            drawn_from,
        })
    }

    /// Closes one opened statement, approved by `owner`, in one writer: the
    /// statement's CLAIM is retracted and its own member-local link dropped;
    /// a statement of another edge drawn from it keeps its link. Only a
    /// statement of this edge's opened WORLD closes here; a closed one
    /// closes again as a no-op.
    pub fn close_inquiry_scope_item(
        &self,
        owner: &AuthenticatedOwner,
        grant: EntityId,
        claim: EntityId,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let edge = require_inquiry_edge_in_txn(self, txn, &grant)?;
            let body = self
                .get_claim_in_txn(txn, &claim)?
                .ok_or(Error::EntityNotFound)?;
            if body.world != Some(edge.terms.opened_world)
                || body.predicate != INQUIRY_STATEMENT_PREDICATE
            {
                return Err(refused(
                    "that claim is not a statement of this edge's opened scope",
                ));
            }
            if body.lifecycle == ClaimLifecycleStatus::Active {
                let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                self.retract_claim_in_txn(txn, &claim, now)?;
            }
            drop_inquiry_scope_link_of_statement_in_txn(&self.store, txn, &claim)
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// "What <company> can ask about": the live statements of the edge's
    /// opened scope, in id order, for `owner` alone. Empty until the member
    /// opens one.
    pub fn inquiry_scope_items(
        &self,
        owner: &AuthenticatedOwner,
        grant: EntityId,
    ) -> Result<Vec<InquiryScopeItem>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let edge = require_inquiry_edge_in_txn(self, &txn, &grant)?;
        opened_statements_in_txn(self, &txn, edge.terms.opened_world)?
            .into_iter()
            .map(|opened| {
                Ok(InquiryScopeItem {
                    claim: opened.claim,
                    statement: opened.text,
                    drawn_from: SCOPE_LINK.get(&self.store, &txn, &opened.claim)?,
                })
            })
            .collect()
    }
}

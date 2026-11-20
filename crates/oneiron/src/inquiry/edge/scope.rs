//! The opened scope: the statements the member opens to the company, and
//! the member-local links to the claims they were drawn from.

use crate::Vault;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::lookup::require_inquiry_edge_in_txn;
use super::{
    INQUIRY_STATEMENT_PREDICATE, SCOPE_LINK, SCOPE_LINK_BY_SOURCE, open_inquiry_scope_item_in_txn,
    refused,
};

/// How many opened statements one page of the WORLD index reads.
const SCOPE_PAGE: usize = 256;

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

/// One statement to open in an edge's scope: its new CLAIM's id, the member
/// it is about, its words (trimmed, not empty) and the claim it was drawn
/// from.
pub(in crate::inquiry) struct NewScopeItem<'a> {
    pub(in crate::inquiry) claim: EntityId,
    pub(in crate::inquiry) member: EntityId,
    pub(in crate::inquiry) statement: &'a str,
    pub(in crate::inquiry) drawn_from: Option<EntityId>,
}

/// One live statement of an opened scope, with the body it was read from.
pub(in crate::inquiry) struct OpenedStatement {
    pub(in crate::inquiry) claim: EntityId,
    pub(in crate::inquiry) text: String,
    pub(in crate::inquiry) body: ClaimBody,
}

/// The live statements of the opened WORLD `world`, in id order: the Active
/// claims of the statement predicate in that WORLD whose value is text.
/// Nothing outside the WORLD is read.
pub(in crate::inquiry) fn opened_statements_in_txn(
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

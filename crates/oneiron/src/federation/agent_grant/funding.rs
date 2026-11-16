//! The owner's explicitly selected funding Grant (FIX 7766, Engine 19:59 =
//! A; L02 20:15 proof contract): the proof a launch's root writer builds
//! before it freezes a [`crate::agent_dispatch::GrantSpendBinding`].
//!
//! A selection is a Grant id the authenticated owner named; it is never
//! picked from the first, a union or the current Grants of an agent, and
//! never inferred from an actor, a PERSON, a project, a plan or a slip. In
//! the root's own writer the proof revalidates the owner, reads the exact
//! live FEDERATION_GRANT row, judges its standing for its own agent (live
//! granting owner, expiry, conferring scope and verb classes, pact) and
//! takes the owner's counted mint the row stands on, whose every term the
//! row states, wallet included (pass 28 R3: the fold's grant line, one
//! comparison). The proof holds only inside that transaction: it is
//! never stored or serialized; the root stores the binding it yields, and
//! each new admission reads that binding again.

use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::{AgentVerbClasses, FederationGrantKind, FederationGrantRole, WalletRef};

/// Why a selected Grant cannot fund a launch.
const FUNDING_REFUSED: &str = "the selected funding grant cannot fund this launch";

/// The verb a Grant's standing for its own agent is judged under: `read`,
/// which every conferring Grant admits by its verbs or a class it names.
const FUNDING_STANDING_VERB: &str = "read";

/// An owner's agent Grant the authenticated owner selected as a launch's
/// funding, proved in the caller's write transaction (FIX 7766). Built only
/// by [`Vault::selected_owner_agent_funding_grant_in_txn`], on the writer
/// that then writes its binding; current only within that writer, never
/// cloned, stored or serialized.
#[derive(Debug)]
pub(crate) struct SelectedOwnerAgentFundingGrant {
    grant_ref: EntityId,
    principal: EntityId,
    mint_act: AuthorityEntryHash,
    wallet_ref: WalletRef,
}

impl SelectedOwnerAgentFundingGrant {
    /// The selected Grant's FEDERATION_GRANT row.
    pub(crate) const fn grant_ref(&self) -> EntityId {
        self.grant_ref
    }

    /// The agent the Grant names: the principal whose work it funds.
    pub(crate) const fn principal(&self) -> EntityId {
        self.principal
    }

    /// The authority entry of the owner's counted signed mint of the Grant.
    pub(crate) const fn mint_act(&self) -> &AuthorityEntryHash {
        &self.mint_act
    }

    /// The wallet the live row and the counted signed mint both name.
    pub(crate) const fn wallet_ref(&self) -> &WalletRef {
        &self.wallet_ref
    }
}

fn refused(why: &str) -> Error {
    Error::InvalidConfig(format!("{FUNDING_REFUSED}: {why}"))
}

impl Vault {
    /// The Grant `selected` as `owner` names it a launch's funding, proved in
    /// `txn`, the root's own writer (FIX 7766), never a read snapshot whose
    /// proof a later writer could replay: `owner` revalidated as the
    /// vault's live owner here; `selected` the exact live FEDERATION_GRANT of
    /// an owner's Access agent Grant (a Delegate, never Guest or GitPush),
    /// not known withdrawn, that names a wallet and stands now for its own
    /// agent, the principal (`Grant.member_ref`) as every owner-agent door
    /// judges it: a live granting owner, unexpired, conferring under its
    /// scope and verb classes, its pact standing kept; and standing on the
    /// owner's counted signed mint of it, which states the live row term for
    /// term and which no counted revoke or withdrawal ended (the agent Grant
    /// list, [`Vault::agent_grants_in_txn`]).
    ///
    /// # Errors
    /// An owner refusal; `InvalidConfig` when any of that fails. The launch
    /// never falls back to another Grant, an unbound root or a default
    /// wallet.
    pub(crate) fn selected_owner_agent_funding_grant_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        selected: EntityId,
    ) -> Result<SelectedOwnerAgentFundingGrant> {
        owner.revalidate_in_txn(self, txn)?;
        let standing = self
            .agent_grants_in_txn(txn)?
            .into_iter()
            .find(|standing| standing.id == selected)
            .ok_or_else(|| {
                refused("it names no live owner's agent grant standing on his counted mint")
            })?;
        let grant = &standing.grant;
        if !grant.owner_agent
            || grant.role != FederationGrantRole::Delegate
            || grant.kind != FederationGrantKind::Access
        {
            return Err(refused("it is not an owner's Access agent grant"));
        }
        let Some(wallet_ref) = grant.wallet_ref.clone() else {
            return Err(refused("the grant names no wallet"));
        };
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let classes = AgentVerbClasses::for_grants_in_txn(&self.store, txn, [grant])?;
        if !standing.stands_in_txn(
            self,
            txn,
            grant.member_ref,
            FUNDING_STANDING_VERB,
            now,
            &owners,
            &classes,
        ) {
            return Err(refused("the grant does not stand for its agent now"));
        }
        Ok(SelectedOwnerAgentFundingGrant {
            grant_ref: standing.id,
            principal: grant.member_ref,
            mint_act: standing.act,
            wallet_ref,
        })
    }
}

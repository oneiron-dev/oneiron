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
//! finds the one counted signed mint whose every field equals that row,
//! wallet included. The proof holds only inside that transaction: it is
//! never stored or serialized; the root stores the binding it yields, and
//! each new admission reads that binding again.

use std::collections::BTreeMap;

use crate::Vault;
use crate::authority::{
    AgentGrantActRecord, AgentGrantChange, AuthorityEntryHash, AuthorityOp, authority_entry_hash,
    decode_authority_log_entry_body,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

use super::super::{AgentVerbClasses, FederationGrantKind, FederationGrantRole, WalletRef};
use super::AgentGrantStanding;

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
    /// scope and verb classes, its pact standing kept; and one counted signed
    /// mint of it whose every field equals the live row, with no counted
    /// revoke or withdrawal of it.
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
            .ok_or_else(|| refused("it names no live owner's agent grant"))?;
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
        let mint_act = counted_matching_mint_in_txn(self, txn, &standing)?
            .ok_or_else(|| refused("no counted signed mint matches its live row"))?;
        Ok(SelectedOwnerAgentFundingGrant {
            grant_ref: standing.id,
            principal: grant.member_ref,
            mint_act,
            wallet_ref,
        })
    }
}

/// The counted signed mint of `standing`'s Grant whose every field equals
/// its live row ([`mint_matches_row`]), by its own authority entry hash.
/// `None` when no counted mint matches. A counted owner revoke, slip-grant
/// revoke or membership withdrawal of the Grant, or two matching counted
/// mints, refuses. The acts read are this vault's resident log rows and the
/// bodies an adopted checkpoint image carries whole for rows it does not
/// store: a paired or restored vault may hold the Grant's mint only there,
/// and the fold counts it. A resident row wins over the image's copy of it.
fn counted_matching_mint_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    standing: &AgentGrantStanding,
) -> Result<Option<AuthorityEntryHash>> {
    let names = |op: &AuthorityOp| match op {
        AuthorityOp::AgentGrantAct(record) => record.grant == standing.id,
        AuthorityOp::SlipGrantRevoke { grant_ref, .. } => *grant_ref == standing.id,
        AuthorityOp::MembershipExecution(record) => {
            record.withdrawn_grants.binary_search(&standing.id).is_ok()
        }
        _ => false,
    };
    let mut acts = BTreeMap::new();
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let id = id?;
        let Some(row) = vault.store.port_entity_record(txn, &id)? else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_AUTHORITY_LOG || row.body.is_empty() {
            continue;
        }
        let Ok(entry) = decode_authority_log_entry_body(&row.body) else {
            continue;
        };
        if names(&entry.op) {
            acts.insert(authority_entry_hash(&entry)?, entry);
        }
    }
    if let Some(evidence) = crate::authority::adopted_evidence_in_txn(&vault.store, txn)? {
        for (hash, entry) in evidence.bodies() {
            if names(&entry.op) {
                acts.entry(*hash).or_insert_with(|| entry.clone());
            }
        }
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut found: Option<AuthorityEntryHash> = None;
    for (hash, entry) in &acts {
        if !fold.valid_entries.contains(hash) {
            continue;
        }
        let AuthorityOp::AgentGrantAct(record) = &entry.op else {
            return Err(refused("a counted act withdrew it"));
        };
        match &record.change {
            AgentGrantChange::Revoke { .. } => return Err(refused("the owner revoked it")),
            AgentGrantChange::Mint { .. } => {
                if mint_matches_row(record, standing) && found.replace(*hash).is_some() {
                    return Err(refused("more than one counted signed mint names it"));
                }
            }
        }
    }
    Ok(found)
}

/// Whether the signed mint `record` is the account of `standing`'s live row:
/// signed by the owner the row names, with every field of the mint equal to
/// the row's (the signed scope against the row's authority scope), the
/// wallet present. The pattern names every field, so a field added to the
/// mint fails to compile here until it is compared.
fn mint_matches_row(record: &AgentGrantActRecord, standing: &AgentGrantStanding) -> bool {
    let AgentGrantChange::Mint {
        member,
        scope,
        expires_at,
        repo_bounds,
        grant_kind,
        git_push_bounds,
        verb_classes,
        wallet_ref,
    } = &record.change
    else {
        return false;
    };
    let grant = &standing.grant;
    record.act.owner == standing.delegated_by
        && *member == grant.member_ref
        && *scope == grant.authority_scope
        && *expires_at == grant.expires_at
        && *repo_bounds == grant.repo_bounds
        && *grant_kind == grant.kind
        && *git_push_bounds == grant.git_push_bounds
        && *verb_classes == grant.verb_classes
        && wallet_ref.is_some()
        && *wallet_ref == grant.wallet_ref
}

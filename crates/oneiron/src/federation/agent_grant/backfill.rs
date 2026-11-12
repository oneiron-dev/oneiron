//! The serve-start backfill of default agent Grants (FIX
//! AGENT-GRANTLESS-VISIBLE item 1; Engine RULING GRANTLESS-SHAPE, 12 Nov
//! 03:02).
//!
//! An agent paired before the owner's Grants existed, or on a link that
//! carried no owner proof, holds a live slip and no Grant. No Grant has ever
//! named it, so its slip reads as its Scope allows
//! (`authority::agent_grant_bound`), and no Grant row shows it to the owner.
//! On a self-hosted vault the serve start mints each such agent, once, its
//! default read Grant, as pairing mints it today (PAIR-GRANT-DESIGN Q3/Q4).
//! After that the holder has been named by a Grant, so every revoke narrows.
//!
//! - Never granted (Q2 = A): no owner-agent Grant row names the holder now,
//!   and no counted mint has ever named it. A holder whose Grants the owner
//!   revoked gets none back (AGENT-REVOKE-WIDENS stays closed).
//! - One Grant per distinct Scope (Q3 = A): a holder with live slips of
//!   different Scopes gets one default Grant for each, and equal Scopes share
//!   one. A read lies inside one Grant and inside its slip's own Scope, so no
//!   slip reads more than before.
//! - Eligible (Q4 = A): the live agent slips that admit a read
//!   ([`Vault::live_agent_slips_in_txn`]).
//! - Once (Q5 = A): the mints and the completion marker commit in one
//!   writer, the marker also when no holder was eligible. A refused owner
//!   proof or signer leaves neither, and the caller logs it and serves on. A
//!   slip paired later without the owner's proof waits for the owner's own
//!   act.
//! - Self-host only (Q6 = A): any other posture returns
//!   [`DefaultAgentGrantBackfill::NotSelfHosted`] and writes nothing. On a
//!   hosted vault the operator acts as nobody (cross-arch-0024:136).
//! - Provenance (Q7 = A): each mint is the owner's signed act on
//!   [`ActSurface::ThisInstall`]; there is no other receipt.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::{HostingPrivacyPosture, Vault};

use super::super::Scope;
use super::default_agent_grant_scope;

/// Set once the backfill has run on this vault (module docs).
const BACKFILL_COMPLETE: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_AGENT_DEFAULT_GRANT_BACKFILL);
/// The marker's one value.
const BACKFILL_COMPLETE_VALUE: u8 = 1;

/// What one call of [`Vault::backfill_default_agent_grants`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultAgentGrantBackfill {
    /// The vault is not self-hosted: nothing ran, and nothing was written.
    NotSelfHosted,
    /// An earlier call completed the backfill: nothing ran.
    AlreadyComplete,
    /// This call ran and set the completion marker.
    Completed {
        /// The default Grants it minted, in holder order; empty when no
        /// holder was eligible.
        grants: Vec<EntityId>,
    },
}

impl Vault {
    /// Mints, as `owner`'s signed act on this install, the default read
    /// Grant of each named agent that holds a live slip that reads and that
    /// no Grant has ever named; runs once per self-hosted vault (module
    /// docs).
    ///
    /// # Errors
    /// An owner refusal; a store, fold or clock failure;
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the owner's act. The writer then commits nothing: no
    /// Grant and no completion marker, so a later start tries again.
    pub fn backfill_default_agent_grants(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<DefaultAgentGrantBackfill> {
        if self.privacy_posture() != HostingPrivacyPosture::SelfHostLocal {
            return Ok(DefaultAgentGrantBackfill::NotSelfHosted);
        }
        if BACKFILL_COMPLETE.contains(&self.store, &self.store.env.read_txn()?, &())? {
            return Ok(DefaultAgentGrantBackfill::AlreadyComplete);
        }
        self.with_write_txn_grouped(|txn| {
            if BACKFILL_COMPLETE.contains(&self.store, txn, &())? {
                return Ok(DefaultAgentGrantBackfill::AlreadyComplete);
            }
            // Judged before any holder, so a refused proof sets no marker
            // when no holder is eligible either.
            owner.revalidate_in_txn(self, txn)?;
            let named_now: BTreeSet<EntityId> = self
                .agent_grants_reporting_in_txn(txn)?
                .0
                .iter()
                .map(|standing| standing.grant.member_ref)
                .collect();
            let mut scopes_by_holder: BTreeMap<EntityId, Vec<Scope>> = BTreeMap::new();
            for slip in self.live_agent_slips_in_txn(txn)? {
                let scope = default_agent_grant_scope(&slip.scope);
                let scopes = scopes_by_holder.entry(slip.holder).or_default();
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
            let mut grants = Vec::new();
            for (holder, scopes) in scopes_by_holder {
                if named_now.contains(&holder) || self.agent_grant_ever_named_in_txn(txn, holder)? {
                    continue;
                }
                for scope in scopes {
                    let minted = self.mint_agent_grant_in_txn(
                        txn,
                        owner,
                        ActSurface::ThisInstall,
                        holder,
                        scope,
                        None,
                        None,
                        BTreeSet::new(),
                        None,
                    )?;
                    grants.push(minted.standing.id);
                }
            }
            BACKFILL_COMPLETE.put(&self.store, txn, &(), &vec![BACKFILL_COMPLETE_VALUE])?;
            Ok(DefaultAgentGrantBackfill::Completed { grants })
        })
    }
}

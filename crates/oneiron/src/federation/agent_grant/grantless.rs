//! The named agents no Grant has named yet, and the owner's conversion of
//! one (FIX AGENT-GRANTLESS-VISIBLE, PR B; Engine RULING GRANTLESS-SHAPE
//! Q8/Q9 = A, 12 Nov 03:02).
//!
//! A named agent paired before the owner's Grants existed, or on a link with
//! no owner proof, holds a live slip, and its slip reads as its Scope allows
//! (`authority::agent_grant_bound`). A self-hosted vault's serve start mints
//! its default read Grant once ([`super::backfill`]). A managed vault, and a
//! slip paired without the owner's proof after that start, wait for the
//! owner:
//!
//! - Q8: the owner's registry lists each live slip whose holder no Grant row
//!   names now and no counted mint has ever named
//!   (`ConsentRegistry::grantless_agents`). Such a slip has no Grant id and
//!   no revoke. It leaves the list once a counted mint names its holder,
//!   also when the owner revokes that Grant later.
//! - Q9: `vault.agents.grants.from_slip { slip_ref }` converts one under the
//!   owner's proof, in one writer. It rechecks the slip (live, class
//!   `agent`, a live named agent's PERSON, a read verb) and that no Grant has
//!   ever named its holder. Then it mints the holder's default read Grants
//!   as the backfill does: the named slip's Scope first, then one for each
//!   other distinct Scope of the holder's live slips. Once a Grant names the
//!   holder, each of its slips reads only inside a live Grant, so no slip of
//!   the holder reads less than before. A slip that no longer qualifies
//!   answers unchanged with its reason, so a repeat never mints twice.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::authority::{ActSurface, AgentSlipStanding, LiveAgentSlip};
use crate::consent::{AuthenticatedOwner, GrantlessAgentConvertAction, GrantlessAgentRow};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

use super::{AgentGrantMintOutcome, default_agent_grant_scope};

/// The command a grantless registry row's conversion pins.
const AGENT_GRANT_FROM_SLIP_COMMAND: &str = "vault.agents.grants.from_slip";

/// Why `vault.agents.grants.from_slip` minted nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentGrantFromSlipUnchangedReason {
    /// The slip is revoked or expired, or no longer stands on its ancestry,
    /// Grant, invitation or delegation.
    SlipNotLive,
    /// The slip names no class `agent` or no read verb, or its holder is no
    /// live named agent.
    NotEligible,
    /// A Grant row names the slip's holder, or a counted mint once did: the
    /// owner's Grants govern its reach.
    AlreadyGranted,
}

/// What one conversion did.
#[derive(Debug, Clone)]
pub(crate) enum GrantlessAgentConversion {
    /// The holder's default read Grants, in mint order.
    Minted(Vec<AgentGrantMintOutcome>),
    /// Nothing was minted.
    Unchanged(AgentGrantFromSlipUnchangedReason),
}

/// The registry row of `slip` (module docs, Q8).
fn grantless_agent_row(slip: LiveAgentSlip) -> GrantlessAgentRow {
    let slip_ref = bytes_to_hex_lower(&slip.slip_id);
    GrantlessAgentRow {
        holder: slip.holder,
        slip_ref: slip_ref.clone(),
        issued_at: slip.issued_at,
        expires_at: slip.expires_at,
        scope: slip.scope,
        records: slip.records,
        channels: slip.channels,
        comm: slip.comm,
        convert_action: GrantlessAgentConvertAction {
            command: AGENT_GRANT_FROM_SLIP_COMMAND.to_owned(),
            slip_ref,
        },
    }
}

impl Vault {
    /// Whether a Grant row names `holder` in `txn` now, or a counted mint
    /// has ever named it.
    fn agent_grant_names_holder_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
    ) -> Result<bool> {
        Ok(self
            .agent_grants_reporting_in_txn(txn)?
            .0
            .iter()
            .any(|standing| standing.grant.member_ref == holder)
            || self.agent_grant_ever_named_in_txn(txn, holder)?)
    }

    /// The live agent slips of `txn` ([`Self::live_agent_slips_in_txn`])
    /// whose holder no Grant row names now and no counted mint has ever
    /// named, in slip id order.
    ///
    /// # Errors
    /// A store, fold or clock failure.
    pub(crate) fn grantless_agent_slips_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<LiveAgentSlip>> {
        let named_now: BTreeSet<EntityId> = self
            .agent_grants_reporting_in_txn(txn)?
            .0
            .iter()
            .map(|standing| standing.grant.member_ref)
            .collect();
        let mut ever_named: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut grantless = Vec::new();
        for slip in self.live_agent_slips_in_txn(txn)? {
            if named_now.contains(&slip.holder) {
                continue;
            }
            let named = match ever_named.get(&slip.holder) {
                Some(named) => *named,
                None => {
                    let named = self.agent_grant_ever_named_in_txn(txn, slip.holder)?;
                    ever_named.insert(slip.holder, named);
                    named
                }
            };
            if !named {
                grantless.push(slip);
            }
        }
        Ok(grantless)
    }

    /// The registry's grantless agent rows in `txn`, newest issued first,
    /// ties by slip id (module docs, Q8).
    ///
    /// # Errors
    /// A store, fold or clock failure.
    pub(crate) fn grantless_agent_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<GrantlessAgentRow>> {
        let mut rows: Vec<GrantlessAgentRow> = self
            .grantless_agent_slips_in_txn(txn)?
            .into_iter()
            .map(grantless_agent_row)
            .collect();
        rows.sort_by(|left, right| {
            right
                .issued_at
                .cmp(&left.issued_at)
                .then_with(|| left.slip_ref.cmp(&right.slip_ref))
        });
        Ok(rows)
    }

    /// The owner converts the slip `slip_id` into its holder's default read
    /// Grants, as his signed acts recording `surface` (module docs, Q9).
    ///
    /// # Errors
    /// An owner refusal; `EntityNotFound` when the authority fold counts no
    /// slip mint with this id; a store, fold or clock failure;
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the owner's act. The writer then commits nothing.
    pub(crate) fn mint_default_agent_grants_from_slip(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        slip_id: [u8; 32],
    ) -> Result<GrantlessAgentConversion> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let slip = match self.agent_slip_standing_in_txn(txn, &slip_id)? {
                AgentSlipStanding::Unknown => return Err(Error::EntityNotFound),
                AgentSlipStanding::NotEligible => {
                    return Ok(GrantlessAgentConversion::Unchanged(
                        AgentGrantFromSlipUnchangedReason::NotEligible,
                    ));
                }
                AgentSlipStanding::NotLive => {
                    return Ok(GrantlessAgentConversion::Unchanged(
                        AgentGrantFromSlipUnchangedReason::SlipNotLive,
                    ));
                }
                AgentSlipStanding::Live(slip) => slip,
            };
            if self.agent_grant_names_holder_in_txn(txn, slip.holder)? {
                return Ok(GrantlessAgentConversion::Unchanged(
                    AgentGrantFromSlipUnchangedReason::AlreadyGranted,
                ));
            }
            let mut scopes = vec![default_agent_grant_scope(&slip.scope)];
            for other in self.live_agent_slips_in_txn(txn)? {
                if other.holder != slip.holder {
                    continue;
                }
                let scope = default_agent_grant_scope(&other.scope);
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
            let mut minted = Vec::with_capacity(scopes.len());
            for scope in scopes {
                minted.push(self.mint_agent_grant_in_txn(
                    txn,
                    owner,
                    surface,
                    slip.holder,
                    scope,
                    None,
                    None,
                    BTreeSet::new(),
                    None,
                    None,
                )?);
            }
            Ok(GrantlessAgentConversion::Minted(minted))
        })
    }
}

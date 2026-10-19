//! The owner's grant of an explicit verb list to a named agent (FIX 5628):
//! `vault.agents.grants.mint` and `.revoke`, owner proof only.
//!
//! A grant is a Delegate/Delegate FEDERATION_GRANT the owner mints from no
//! parent grant, marked `owner_agent` in its body. Its member is a live agent
//! principal of this vault (a live agent definition, or a base agent such as
//! the Coach's MACHINE principal), never a person or a physical machine; its
//! authority is the six-axis scope the owner gave, stored exactly (a nonempty
//! explicit verb list, no default cap, no allowlist); it names the owner as
//! its delegator; and it stands until he revokes it, or until the expiry he
//! set, with no maximum (ARCH-0040, OF-453 L8: approved grants are durable
//! and revocable). A second mint for the same agent adds a second grant.
//!
//! Mint and revoke land the owner's signed act ([`AgentGrantAct`]) and the
//! grant row's Put or Delete in one write transaction. The vault's existing
//! grant readers (the Coach's digest settings rule, the world and act
//! grant readers, member projections) read the row as they read every
//! Delegate grant. The shared-vault delegate door (`vault.members.delegate`)
//! is untouched: its parent gate, default cap and 90-day cap stay its own.
//!
//! The owner reviews each grant in `vault.consent.registry`, with its own
//! one-tap revoke ([`AGENT_GRANT_REVOKE_COMMAND`]).

use crate::authority::{ActSurface, AgentGrantAct, AgentGrantActRef};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{TimeRange, Vault};

use super::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope, Scope,
    ScopeAxis, decode_federation_grant_body, encode_federation_grant_body,
    own_device_residence_scope,
};

/// The one-tap revoke command every agent grant carries.
pub(crate) const AGENT_GRANT_REVOKE_COMMAND: &str = "vault.agents.grants.revoke";

const NO_VERB_LIST: &str =
    "an agent grant names its verbs: authority_scope.verbs must be a nonempty explicit set";
const NOT_AN_AGENT: &str = "an agent grant names a live agent principal of this vault: an agent definition or a base agent";
const ALREADY_EXPIRED: &str = "an agent grant's expires_at must be later than now";

/// One owner's agent grant as its live row holds it.
#[derive(Debug, Clone)]
pub(crate) struct AgentGrantStanding {
    pub(crate) id: EntityId,
    pub(crate) grant: FederationGrant,
    /// The owner who granted it (the row's `delegated_by`).
    pub(crate) delegated_by: EntityId,
    /// Recording time of the mint (Unix seconds).
    pub(crate) created_at: u64,
}

impl AgentGrantStanding {
    /// Whether it still stands at `now`: no expiry, or one not reached.
    pub(crate) fn stands_at(&self, now: u64) -> bool {
        self.grant
            .expires_at
            .is_none_or(|expires_at| now < expires_at)
    }
}

/// What a mint wrote: the grant and the signed record of the owner's act.
#[derive(Debug, Clone)]
pub(crate) struct AgentGrantMintOutcome {
    pub(crate) standing: AgentGrantStanding,
    pub(crate) act: AgentGrantActRef,
}

/// What a revoke did. A repeat changed nothing and signed no act.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentGrantRevokeOutcome {
    /// The agent the revoked grant named; `None` for a repeat.
    pub(crate) agent: Option<EntityId>,
    /// The signed record of this revoke; `None` for a repeat.
    pub(crate) act: Option<AgentGrantActRef>,
}

impl Vault {
    /// The owner grants `agent` the explicit `authority_scope`, until
    /// `expires_at` or, when `None`, until he revokes it. `owner` is
    /// revalidated as the vault's live owner in the writer, which signs his
    /// act (`surface` says where he said so, for its audit only) before it
    /// puts the grant. On a shared vault the grant is under the vault's
    /// recorded scope; on a personal vault under the home's residence scope.
    ///
    /// # Errors
    /// An owner refusal; `InvalidConfig` for an empty or unlisted verb set,
    /// a member that is no live agent principal or an expiry already passed;
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the owner's act.
    pub(crate) fn mint_agent_grant(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        agent: EntityId,
        authority_scope: Scope,
        expires_at: Option<u64>,
    ) -> Result<AgentGrantMintOutcome> {
        self.with_write_txn_grouped(|txn| {
            let delegated_by = owner.revalidate_in_txn(self, txn)?;
            if !matches!(&authority_scope.verbs, ScopeAxis::Some(verbs) if !verbs.is_empty()) {
                return Err(Error::InvalidConfig(NO_VERB_LIST.into()));
            }
            if !self.is_agent_principal_in_txn(txn, agent)? {
                return Err(Error::InvalidConfig(NOT_AN_AGENT.into()));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if expires_at.is_some_and(|expires_at| expires_at <= now) {
                return Err(Error::InvalidConfig(ALREADY_EXPIRED.into()));
            }
            let scope = self
                .shared_vault_creation_in_txn(txn)?
                .map_or_else(own_device_residence_scope, |shared| {
                    FederationGrantScope::vault(shared.vault_id)
                });
            let grant = FederationGrant {
                authority_scope,
                scope,
                member_ref: agent,
                role: FederationGrantRole::Delegate,
                preset: FederationGrantPreset::Delegate,
                expires_at,
                delegated_by: Some(delegated_by),
                guest: None,
                owner_agent: true,
            };
            // Encoding validates: nothing is signed for a grant that cannot stand.
            let data = encode_federation_grant_body(&grant)?;
            let id = EntityId::now();
            let act = self.append_agent_grant_act_in_txn(
                txn,
                owner,
                surface,
                AgentGrantAct::Mint {
                    grant: id,
                    member: agent,
                    scope: grant.authority_scope.clone(),
                    expires_at,
                },
            )?;
            self.apply_agent_grant_op_in_txn(
                txn,
                BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
            )?;
            Ok(AgentGrantMintOutcome {
                standing: AgentGrantStanding {
                    id,
                    grant,
                    delegated_by,
                    created_at: now,
                },
                act,
            })
        })
    }

    /// The owner revokes the agent grant `grant_ref`: his signed act, then
    /// the row's delete, in one writer, so every grant reader stops counting
    /// it. A grant already deleted answers unchanged and signs nothing.
    ///
    /// # Errors
    /// An owner refusal; `EntityNotFound` for an id that names no
    /// FEDERATION_GRANT, or a live grant this door did not mint (an owner,
    /// own-device, guest or shared-vault member or delegate grant);
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the owner's act.
    pub(crate) fn revoke_agent_grant(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        grant_ref: EntityId,
    ) -> Result<AgentGrantRevokeOutcome> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let body = match live_entity_row_in_txn(&self.store, txn, &grant_ref)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    body,
                } => body,
                LiveEntityRow::DeletedShell
                    if self
                        .store
                        .port_entity_record(txn, &grant_ref)?
                        .is_some_and(|row| row.entity_type == ENTITY_TYPE_FEDERATION_GRANT) =>
                {
                    return Ok(AgentGrantRevokeOutcome {
                        agent: None,
                        act: None,
                    });
                }
                _ => return Err(Error::EntityNotFound),
            };
            let grant = decode_federation_grant_body(&body)
                .ok()
                .filter(|grant| grant.owner_agent)
                .ok_or(Error::EntityNotFound)?;
            let act = self.append_agent_grant_act_in_txn(
                txn,
                owner,
                surface,
                AgentGrantAct::Revoke { grant: grant_ref },
            )?;
            self.apply_agent_grant_op_in_txn(txn, BatchOp::Delete { id: grant_ref })?;
            Ok(AgentGrantRevokeOutcome {
                agent: Some(grant.member_ref),
                act: Some(act),
            })
        })
    }

    /// Every live agent grant of this vault, in id order. A row that does
    /// not decode is no agent grant here.
    pub(crate) fn agent_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<AgentGrantStanding>> {
        let mut grants = Vec::new();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = id?;
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            let Ok(grant) = decode_federation_grant_body(&body) else {
                continue;
            };
            if !grant.owner_agent {
                continue;
            }
            let Some(delegated_by) = grant.delegated_by else {
                continue;
            };
            let created_at = self
                .store
                .port_entity_record(txn, &id)?
                .map_or(0, |row| row.learned_at);
            grants.push(AgentGrantStanding {
                id,
                grant,
                delegated_by,
                created_at,
            });
        }
        Ok(grants)
    }

    /// The agent grants as `vault.consent.registry` reviews them: standing
    /// ones, or every live one with `include_revoked` (an expired grant
    /// shows as revoked).
    pub(crate) fn agent_grant_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        include_revoked: bool,
    ) -> Result<Vec<crate::consent::ConsentRegistryRow>> {
        let now = self.instant_in_txn(txn)?.secs();
        Ok(self
            .agent_grants_in_txn(txn)?
            .iter()
            .filter(|standing| include_revoked || standing.stands_at(now))
            .map(|standing| crate::consent::ConsentRegistryRow::from_agent_grant(standing, now))
            .collect())
    }

    /// Whether `agent` is a live agent principal of this vault: a live agent
    /// definition, or one of the two seeded base-agent MACHINE principals
    /// (the Dreamer's and the Coach's). Any other machine is a device.
    fn is_agent_principal_in_txn(&self, txn: &heed::RoTxn<'_>, agent: EntityId) -> Result<bool> {
        Ok(match live_entity_row_in_txn(&self.store, txn, &agent)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                ..
            } => true,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_MACHINE,
                ..
            } => crate::dreamer_runner::authority::is_base_agent_actor(&agent)?,
            _ => false,
        })
    }

    /// Applies one grant row op in the caller's writer, as the Delegate mint
    /// persists its grant.
    fn apply_agent_grant_op_in_txn(&self, txn: &mut heed::RwTxn<'_>, op: BatchOp) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![op],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}

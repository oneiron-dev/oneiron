//! FIX 988 (ARCH-0072 door 3, OF-399): typed scope-exceed evidence.
//!
//! A connector call held because it exceeds its own live scoped grant, on
//! the endpoint, payload-class or tool-data-class axis, leaves one signal
//! per logical call (principal, attempt, sequence), whatever retries or ask
//! repairs follow. A signal is evidence, never authority: it widens nothing.
//! The owner's ruling on the held call's ask folds into the consent ramp as a
//! Door witness, once. When that ramp's offer is earned and ED-05 does not
//! hold it, the engine drafts a proposed delta slate naming the signal as its
//! cause; only the owner's acceptance of that proposal mints a wider grant.
//!
//! A wrong principal, server or tool, an invalid grant, an unknown class, key
//! drift and transport failures are not evidence and leave no signal. The
//! ramp scope keys on the key, its authority generation, the tool, the axis
//! and the actor, so history from another grant, issuer or row never
//! transfers.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::record::{ConnectorKeyStatus, invalid_body};
use super::txn::read_connector_key_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::consent_graduation::RampScope;
use crate::error::{Error, Result};
use crate::identity_topology::ProposalOutcome;
use crate::outbound_consent::tool_call::ToolGrantDataClass;
use crate::outbound_consent::{DataClass, ScopedMcpCallContext, ScopedMcpEscalationReason};
use crate::outbound_grant::{StandingOutboundGrant, standing_outbound_grant_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// One logical call's scope signal. Key: the signal id.
const SCOPE_SIGNALS: SideTable<EntityId, ConnectorSlateScopeSignal, Named> =
    SideTable::new(&side_table::CONNECTOR_SLATE_SCOPE_SIGNAL);
/// A signal's id: its call's principal, attempt and sequence.
const SCOPE_SIGNAL_DOMAIN: &[u8] = b"oneiron:connector-scope-signal:v1";
/// The authority generation a signal was observed under.
const AUTHORITY_GENERATION_DOMAIN: &[u8] = b"oneiron:connector-scope-generation:v1";
/// The ramp target a signal's rulings fold into.
const SCOPE_RAMP_TARGET_DOMAIN: &[u8] = b"oneiron:connector-scope-ramp:v1";

/// The ramp op kind a connector scope revision rides (CALL
/// SLATE-988-evidence-scope): one kind, whose target is the key, generation,
/// tool and axis.
pub const CONNECTOR_SCOPE_RAMP_OP_KIND: &str = "connector_scope_widen";

/// The grant axis one call exceeded and what the call asked for on it: never
/// the payload, a header's value or a credential.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorScopeExceed {
    /// The endpoint the call resolved is not on the grant's allowlist.
    Endpoint { requested: String },
    /// The payload's class is above the grant's ceiling.
    PayloadClass {
        requested: DataClass,
        ceiling: DataClass,
    },
    /// The call carries a data class the grant does not let through:
    /// `arguments` or `x_mcp_header`.
    ToolDataClass { requested: String },
}

impl ConnectorScopeExceed {
    /// The exceeded axis's stable name.
    #[must_use]
    pub const fn axis(&self) -> &'static str {
        match self {
            Self::Endpoint { .. } => "endpoint",
            Self::PayloadClass { .. } => "payload_class",
            Self::ToolDataClass { .. } => "tool_data_class",
        }
    }

    /// What the call asked for on that axis.
    #[must_use]
    pub fn requested(&self) -> &str {
        match self {
            Self::Endpoint { requested } | Self::ToolDataClass { requested } => requested,
            Self::PayloadClass { requested, .. } => requested.as_str(),
        }
    }
}

/// The owner's ruling on a signal's held call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorScopeOutcome {
    ApprovedUntouched,
    ApprovedAmended,
    Rejected,
}

impl ConnectorScopeOutcome {
    const fn proposal(self) -> ProposalOutcome {
        match self {
            Self::ApprovedUntouched => ProposalOutcome::ApprovedUntouched,
            Self::ApprovedAmended => ProposalOutcome::ApprovedAmended,
            Self::Rejected => ProposalOutcome::Rejected,
        }
    }
}

/// The owner's ruling on a signal, as recorded once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorScopeRuling {
    pub outcome: ConnectorScopeOutcome,
    /// The approve-once digest of the held call's ask he ruled on.
    pub linked_ruling: String,
    /// The owner proof's decision id.
    pub owner_decision: String,
    pub at: u64,
}

/// One logical connector call's typed scope exceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateScopeSignal {
    pub signal_id: EntityId,
    /// The held row the call keeps.
    pub call_ref: EntityId,
    /// The gate decision that held it, when it named one.
    pub decision_ref: Option<String>,
    /// Every approve-once digest the call's holds named: the asks a ruling
    /// may link to.
    pub asks: BTreeSet<String>,
    /// The catalog connector the call named.
    pub connector: String,
    pub server: String,
    pub tool: String,
    /// The governing key and the live grant the call ran under.
    pub key_ref: EntityId,
    pub grant_id: EntityId,
    /// The principal whose call it was.
    pub actor: String,
    /// The key, grant and credential binding generations the call ran under.
    pub authority_generation: [u8; 32],
    pub exceed: ConnectorScopeExceed,
    pub observed_at: u64,
    /// The owner's ruling, recorded once.
    pub ruling: Option<ConnectorScopeRuling>,
    /// The proposed delta slate this signal's earned offer drafted or reuses.
    pub proposed_slate_ref: Option<EntityId>,
}

/// What an owner's ruling on a signal came to: the signal, its ramp's
/// counters, and the proposal an earned offer drafted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorScopeOutcomeRecorded {
    pub signal: ConnectorSlateScopeSignal,
    pub untouched_streak: u32,
    pub amended: u32,
    pub rejected: u32,
    /// The proposed delta slate, unstamped; `None` until the offer is earned.
    pub proposed_slate_ref: Option<EntityId>,
}

/// One held call's step, as its scope evidence names it.
pub(crate) struct ScopeExceedCall<'a> {
    /// The catalog connector the call named.
    pub(crate) connector: &'a str,
    pub(crate) principal_ref: &'a str,
    pub(crate) attempt: &'a [u8],
    pub(crate) call_seq: u64,
    /// The call's axes as prepared.
    pub(crate) call: &'a ScopedMcpCallContext,
}

/// A held call's typed exceed, before its row is kept.
#[derive(Debug, Clone)]
pub(crate) struct ConnectorScopeEvidence {
    signal_id: EntityId,
    connector: String,
    server: String,
    tool: String,
    key_ref: EntityId,
    grant_id: EntityId,
    actor: String,
    exceed: ConnectorScopeExceed,
}

/// The evidence a call held under its own live grant leaves (CALL
/// SLATE-988-evidence-scope): the endpoint, ceiling and tool-data-class
/// exceeds only, on a grant that is this principal's on exactly this server
/// and tool. `None` for every other hold.
pub(crate) fn connector_scope_evidence(
    reason: ScopedMcpEscalationReason,
    grant: &StandingOutboundGrant,
    grant_id: EntityId,
    key_id: EntityId,
    held: ScopeExceedCall<'_>,
) -> Option<ConnectorScopeEvidence> {
    if grant.principal_ref != held.principal_ref {
        return None;
    }
    let scope = grant.scope.scoped_mcp_grant()?;
    if scope.server != held.call.server || scope.tool != held.call.tool {
        return None;
    }
    let exceed = match reason {
        ScopedMcpEscalationReason::EndpointNotAllowed => {
            let endpoint = held.call.resolved_endpoint.as_str();
            let named = !endpoint.trim().is_empty() && endpoint == endpoint.trim();
            if !named
                || scope
                    .endpoint_allowlist
                    .iter()
                    .any(|known| known == endpoint)
            {
                return None;
            }
            ConnectorScopeExceed::Endpoint {
                requested: endpoint.to_owned(),
            }
        }
        ScopedMcpEscalationReason::DataClassCeilingExceeded => {
            let requested = held.call.payload_data_class;
            if !requested.is_grantable() || requested <= scope.data_class_ceiling {
                return None;
            }
            ConnectorScopeExceed::PayloadClass {
                requested,
                ceiling: scope.data_class_ceiling,
            }
        }
        ScopedMcpEscalationReason::ToolDataClassNotGranted => {
            let requested = if scope
                .tool_data_classes
                .contains(&ToolGrantDataClass::Arguments)
            {
                ToolGrantDataClass::XMcpHeader
            } else {
                ToolGrantDataClass::Arguments
            };
            ConnectorScopeExceed::ToolDataClass {
                requested: requested.as_str().to_owned(),
            }
        }
        _ => return None,
    };
    let signal_id = EntityId::derive(
        SCOPE_SIGNAL_DOMAIN,
        &[
            held.principal_ref.as_bytes(),
            held.attempt,
            &held.call_seq.to_le_bytes(),
        ],
    )
    .ok()?;
    Some(ConnectorScopeEvidence {
        signal_id,
        connector: held.connector.to_owned(),
        server: held.call.server.clone(),
        tool: held.call.tool.clone(),
        key_ref: key_id,
        grant_id,
        actor: held.principal_ref.to_owned(),
        exceed,
    })
}

/// Keeps `evidence` as its logical call's signal, beside held row
/// `call_ref` and the ask it named: once per logical call, so a retry or an
/// ask repair adds only its ask. Best effort: a signal that cannot be kept
/// never fails the call it describes.
pub(crate) fn keep_connector_scope_signal(
    vault: &Vault,
    evidence: ConnectorScopeEvidence,
    call_ref: EntityId,
    decision_ref: Option<&str>,
    ask: Option<&str>,
) {
    let kept = vault.with_write_txn_grouped(|txn| {
        let mut signal = match SCOPE_SIGNALS.get(&vault.store, txn, &evidence.signal_id)? {
            Some(signal) => signal,
            None => ConnectorSlateScopeSignal {
                signal_id: evidence.signal_id,
                call_ref,
                decision_ref: decision_ref.map(str::to_owned),
                asks: BTreeSet::new(),
                authority_generation: authority_generation_in_txn(
                    &vault.store,
                    txn,
                    &evidence.key_ref,
                    evidence.grant_id,
                    &evidence.tool,
                )?,
                connector: evidence.connector,
                server: evidence.server,
                tool: evidence.tool,
                key_ref: evidence.key_ref,
                grant_id: evidence.grant_id,
                actor: evidence.actor,
                exceed: evidence.exceed,
                observed_at: vault.store.clock.now_recorded_at(),
                ruling: None,
                proposed_slate_ref: None,
            },
        };
        if let Some(ask) = ask {
            signal.asks.insert(ask.to_owned());
        }
        SCOPE_SIGNALS.put(&vault.store, txn, &signal.signal_id, &signal)
    });
    if let Err(error) = kept {
        tracing::warn!(
            call_ref = %call_ref.to_hex(),
            %error,
            "connector scope signal not kept"
        );
    }
}

pub(super) fn read_signal_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ConnectorSlateScopeSignal>> {
    SCOPE_SIGNALS.get(store, txn, id)
}

pub(super) fn scan_signals_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<ConnectorSlateScopeSignal>> {
    Ok(SCOPE_SIGNALS
        .scan(store, txn)?
        .into_iter()
        .map(|(_, signal)| signal)
        .collect())
}

/// The generation one call's authority was admitted under: its governing
/// key, its live grant, and the generation of each credential binding its
/// row depends on.
fn authority_generation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_ref: &EntityId,
    grant_id: EntityId,
    tool: &str,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHORITY_GENERATION_DOMAIN);
    hasher.update(key_ref.as_bytes());
    hasher.update(grant_id.as_bytes());
    if let Some(key) = read_connector_key_in_txn(store, txn, key_ref)? {
        for generation in
            super::credential_binding::binding_generations_in_txn(store, txn, key_ref, &key, tool)?
        {
            hasher.update(&generation.to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Whether `signal`'s authority stands as it was observed: its key Active,
/// its grant this actor's live grant on the same server and tool, and the
/// same generation. A proposal from another generation mints nothing.
pub(super) fn signal_is_current_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    signal: &ConnectorSlateScopeSignal,
) -> Result<bool> {
    let Some(key) = read_connector_key_in_txn(store, txn, &signal.key_ref)? else {
        return Ok(false);
    };
    if key.status != ConnectorKeyStatus::Active {
        return Ok(false);
    }
    let Some(grant) = standing_outbound_grant_in_txn(store, txn, &signal.grant_id)? else {
        return Ok(false);
    };
    let floor = crate::gate::resolve_policy_manifest(store, txn)?.read_frontier_hash()?;
    if grant.principal_ref != signal.actor
        || !grant.is_active_under_policy(&floor)
        || grant
            .scope
            .scoped_mcp_grant()
            .is_none_or(|scope| scope.server != signal.server || scope.tool != signal.tool)
    {
        return Ok(false);
    }
    let generation =
        authority_generation_in_txn(store, txn, &signal.key_ref, signal.grant_id, &signal.tool)?;
    Ok(generation == signal.authority_generation)
}

/// The ramp scope a signal's rulings fold into: its key, authority
/// generation, tool and exceeded axis, for its actor.
pub(super) fn signal_ramp_scope(signal: &ConnectorSlateScopeSignal) -> Result<RampScope> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCOPE_RAMP_TARGET_DOMAIN);
    hasher.update(&signal.authority_generation);
    for part in [
        signal.tool.as_str(),
        signal.exceed.axis(),
        signal.exceed.requested(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize().to_hex();
    RampScope::new(
        CONNECTOR_SCOPE_RAMP_OP_KIND,
        format!(
            "connector:{}:{}",
            signal.key_ref.to_hex(),
            &digest.as_str()[..32]
        ),
        signal.actor.clone(),
    )
}

impl Vault {
    /// The owner's ruling on the held call a scope signal names (FIX 988):
    /// approved untouched, approved amended or rejected, linked to the exact
    /// ask he ruled on. It is recorded once and folds into the signal's ramp
    /// as a Door witness in the same writer. Once that ramp's offer is earned
    /// and ED-05 does not hold it, the writer drafts the proposed delta
    /// slate, or reuses its scope's standing one: nothing is stamped,
    /// granted or widened. A send, a minted grant or a notification answer
    /// is never a ruling here.
    pub fn record_connector_scope_outcome(
        &self,
        owner: &AuthenticatedOwner,
        signal_id: EntityId,
        linked_ruling: &str,
        outcome: ConnectorScopeOutcome,
    ) -> Result<ConnectorScopeOutcomeRecorded> {
        let at = self.store.clock.now_recorded_at();
        let (signal, scope) = self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut signal = SCOPE_SIGNALS
                .get(&self.store, txn, &signal_id)?
                .ok_or(Error::EntityNotFound)?;
            if signal.ruling.is_some() {
                return Err(invalid_body(
                    "the scope signal's ruling is already recorded",
                ));
            }
            if !signal.asks.contains(linked_ruling) {
                return Err(invalid_body(
                    "the ruling names no ask the signal's call held",
                ));
            }
            let scope = signal_ramp_scope(&signal)?;
            crate::consent_graduation::record_door_ramp_outcome_in_txn(
                self,
                txn,
                &scope,
                outcome.proposal(),
                at,
            )?;
            signal.ruling = Some(ConnectorScopeRuling {
                outcome,
                linked_ruling: linked_ruling.to_owned(),
                owner_decision: owner.decision_id().to_hex(),
                at,
            });
            if super::slate_revision::scope_offer_standing_in_txn(self, txn, &signal, &scope, at)? {
                signal.proposed_slate_ref =
                    super::slate_revision::scope_proposal_in_txn(self, txn, &signal, &scope)?;
            }
            SCOPE_SIGNALS.put(&self.store, txn, &signal_id, &signal)?;
            Ok((signal, scope))
        })?;
        let stats = self.scope_stats(&scope)?;
        Ok(ConnectorScopeOutcomeRecorded {
            proposed_slate_ref: signal.proposed_slate_ref,
            untouched_streak: stats.as_ref().map_or(0, |stats| stats.untouched_streak),
            amended: stats.as_ref().map_or(0, |stats| stats.amended),
            rejected: stats.as_ref().map_or(0, |stats| stats.rejected),
            signal,
        })
    }
}

//! FIX 988: proposed delta slates and the owner's acceptance of them
//! (ARCH-0072 "a proposed delta slate that lands only on a person's stamp").
//!
//! A revision's cause is engine-built from checked evidence: a scope signal
//! whose ramp offer was earned, a credential binding's issuer change, or the
//! declaration's own drift. A forced revision carries the prior slate's
//! declaration and every row with its settings, and re-asks only the rows
//! its cause names. It is stored unstamped and bound to nothing, so it
//! changes no live slate and no key while it waits; earning, listing or
//! viewing it grants nothing. The owner's stamp at the reviewed revision,
//! with the evidence rechecked in the same writer, is what lands it: a
//! scope revision then mints its widened grant through the connector
//! consent door, and an issuer revision accepts the new issuer at the
//! binding's expected generation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::lifecycle::{
    ConnectorConsentTarget, ConnectorToolConsent, ConnectorToolConsentRow, ConnectorToolGrant,
    derived_key_catalog_in_txn,
};
use super::record::{ConnectorKeyStatus, invalid_body, normalize_connector_key};
use super::slate::{
    ConnectorGrantSlate, SlateOwnerOverride, new_slate, put_slate_in_txn, read_slate_in_store_txn,
};
use super::slate_scope_signal::{
    ConnectorScopeExceed, ConnectorSlateScopeSignal, read_signal_in_txn, scan_signals_in_txn,
    signal_is_current_in_txn, signal_ramp_scope,
};
use super::txn::read_connector_key_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::consent_graduation::RampScope;
use crate::edit_distance::graduation::{
    OfferAnswer, SnoozeState, answer_graduation_offer_as_owner, asks_are_suppressed_in_txn,
    snooze_state, unpin_scope_as_owner,
};
use crate::error::{Error, Result};
use crate::outbound_consent::tool_call::ToolGrantDataClass;
use crate::outbound_grant::standing_outbound_grant_in_txn;
use crate::store::Store;
use crate::{EntityId, Vault};

/// Why a slate revises its prior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateRevisionCause {
    /// The connector's declaration drifted (a delta draft).
    ManifestDrift,
    /// The owner's rulings on repeated scope exceeds earned an offer to
    /// widen one row's grant.
    ScopeExceed {
        signal_ref: EntityId,
        key_ref: EntityId,
        actor: String,
        generation: [u8; 32],
        tool: String,
        exceed: ConnectorScopeExceed,
    },
    /// A credential binding answers for a new issuer: every row that
    /// depended on the old one goes back to the owner.
    CredentialIssuerChanged {
        binding_ref: EntityId,
        expected_generation: u64,
        old_issuer: String,
        new_issuer: String,
        proposed_credential_ref: String,
        dependent_rows: BTreeSet<String>,
    },
}

/// One proposed revision waiting on the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorSlateRevisionOffer {
    /// The proposed delta slate, unstamped; `None` while an issuer change is
    /// detected but its slate is not drafted.
    pub proposal_ref: Option<EntityId>,
    /// The revision the owner's stamp names.
    pub proposal_revision: Option<u64>,
    /// The slate it revises.
    pub prior_ref: Option<EntityId>,
    pub connector: String,
    /// The rows it re-asks.
    pub reask: BTreeSet<String>,
    pub cause: SlateRevisionCause,
}

/// The owner's answer that holds a scope revision's offer back (ED-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRevisionDeferral {
    /// Ask again after the next backoff step.
    NotNow,
    /// Stop offering until he unpins it.
    ManualPinned,
    /// Offer again once earned.
    Unpin,
}

/// An accepted revision: the stamped slate, its cause, and any grant its
/// acceptance minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorSlateRevisionAccepted {
    pub slate_id: EntityId,
    pub revision: u64,
    pub cause: SlateRevisionCause,
    pub grants: Vec<ConnectorToolGrant>,
}

/// A proposed revision of slate `prior_id`: the same declaration and every
/// row carried with its settings, `reask` back to the owner, and the cause
/// that forced it. `None` when the prior is gone or holds none of `reask`.
pub(super) fn draft_forced_revision_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    prior_id: EntityId,
    reask: BTreeSet<String>,
    cause: SlateRevisionCause,
) -> Result<Option<EntityId>> {
    let Some(prior) = read_slate_in_store_txn(store, txn, prior_id)? else {
        return Ok(None);
    };
    let reask: BTreeSet<String> = reask
        .into_iter()
        .filter(|row| prior.rows().iter().any(|known| &known.draft.tool == row))
        .collect();
    if reask.is_empty() {
        return Ok(None);
    }
    let slate = new_slate(
        prior.slate_manifest(),
        prior.rows().to_vec(),
        Some(&prior),
        Some(prior_id),
        reask,
    )?
    .with_cause(cause);
    let id = EntityId::now();
    put_slate_in_txn(store, txn, id, &slate)?;
    Ok(Some(id))
}

/// Whether `signal`'s offer stands now: its authority current, its ramp
/// past the threshold row, and ED-05 not holding it.
pub(super) fn scope_offer_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    signal: &ConnectorSlateScopeSignal,
    scope: &RampScope,
    now: u64,
) -> Result<bool> {
    Ok(signal_is_current_in_txn(&vault.store, txn, signal)?
        && crate::consent_graduation::offer_is_standing_in_txn(vault, txn, scope)?
        && !asks_are_suppressed_in_txn(&vault.store, txn, scope, now)?)
}

/// The proposal an earned scope offer lands as (CALL SLATE-988-signal-reuse):
/// the standing unstamped one another signal of the same scope drafted, else
/// a new forced revision of the slate the signal's key meets.
pub(super) fn scope_proposal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    signal: &ConnectorSlateScopeSignal,
    scope: &RampScope,
) -> Result<Option<EntityId>> {
    for other in scan_signals_in_txn(&vault.store, txn)? {
        let Some(proposal) = other.proposed_slate_ref else {
            continue;
        };
        if signal_ramp_scope(&other)? == *scope
            && read_slate_in_store_txn(&vault.store, txn, proposal)?
                .is_some_and(|slate| slate.owner_actor().is_none())
        {
            return Ok(Some(proposal));
        }
    }
    let Some(key) = super::txn::read_connector_key_in_txn(&vault.store, txn, &signal.key_ref)?
    else {
        return Ok(None);
    };
    let Some((prior_id, _)) =
        super::slate_setting::governing_slate_in_txn(&vault.store, txn, &key)?
    else {
        return Ok(None);
    };
    let cause = SlateRevisionCause::ScopeExceed {
        signal_ref: signal.signal_id,
        key_ref: signal.key_ref,
        actor: signal.actor.clone(),
        generation: signal.authority_generation,
        tool: signal.tool.clone(),
        exceed: signal.exceed.clone(),
    };
    draft_forced_revision_in_txn(
        &vault.store,
        txn,
        prior_id,
        BTreeSet::from([signal.tool.clone()]),
        cause,
    )
}

fn offer_of(
    proposal_ref: EntityId,
    proposal: &ConnectorGrantSlate,
    connector: String,
    cause: SlateRevisionCause,
) -> ConnectorSlateRevisionOffer {
    ConnectorSlateRevisionOffer {
        proposal_ref: Some(proposal_ref),
        proposal_revision: Some(proposal.revision()),
        prior_ref: proposal.prior(),
        connector,
        reask: proposal.reask().clone(),
        cause,
    }
}

/// A scope revision's acceptance, in the stamping writer: the offer must
/// still stand on the authority it was earned under, and the widened grant
/// adds the requested endpoint to the actor's grant for the row through the consent door.
fn accept_scope_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    slate_id: EntityId,
    signal_ref: EntityId,
    now: u64,
) -> Result<Vec<ConnectorToolGrant>> {
    let signal = read_signal_in_txn(&vault.store, txn, &signal_ref)?
        .filter(|signal| signal.proposed_slate_ref == Some(slate_id))
        .ok_or_else(|| invalid_body("the revision's scope signal is gone"))?;
    let scope = signal_ramp_scope(&signal)?;
    if !scope_offer_standing_in_txn(vault, txn, &signal, &scope, now)? {
        return Err(invalid_body("the scope revision's offer no longer stands"));
    }
    let grant = standing_outbound_grant_in_txn(&vault.store, txn, &signal.grant_id)?
        .ok_or_else(|| invalid_body("the revision's grant is gone"))?;
    let current = grant
        .scope
        .scoped_mcp_grant()
        .ok_or_else(|| invalid_body("the revision's grant is not scoped"))?;
    let mut ceiling = current.data_class_ceiling;
    let mut headers = current
        .tool_data_classes
        .contains(&ToolGrantDataClass::XMcpHeader);
    let mut endpoint = current
        .endpoint_allowlist
        .first()
        .cloned()
        .ok_or_else(|| invalid_body("the revision's grant names no endpoint"))?;
    match &signal.exceed {
        ConnectorScopeExceed::Endpoint { requested } => endpoint = requested.clone(),
        ConnectorScopeExceed::PayloadClass { requested, .. } => ceiling = ceiling.max(*requested),
        ConnectorScopeExceed::ToolDataClass { requested } => {
            headers |= requested == ToolGrantDataClass::XMcpHeader.as_str();
        }
    }
    let consent = ConnectorToolConsent {
        connector: signal.connector.clone(),
        target: ConnectorConsentTarget::Actor(EntityId::from_hex(&signal.actor)?),
        endpoint,
        rows: vec![ConnectorToolConsentRow {
            tool: signal.tool.clone(),
            data_class_ceiling: ceiling,
            headers,
        }],
    };
    vault.consent_connector_tools_in_txn(txn, owner, &consent, crate::unix_seconds_now())
}

impl Vault {
    /// Every proposed revision waiting on the owner, optionally for one
    /// catalog connector: each earned, unsuppressed scope offer whose
    /// authority still stands, and each issuer change not yet accepted.
    /// Listing activates nothing.
    pub fn connector_slate_revision_offers(
        &self,
        connector: Option<&str>,
    ) -> Result<Vec<ConnectorSlateRevisionOffer>> {
        let now = self.store.clock.now_recorded_at();
        let wanted = connector.map(normalize_connector_key);
        let names = |name: &str| {
            wanted
                .as_ref()
                .is_none_or(|wanted| *wanted == normalize_connector_key(name))
        };
        let txn = self.store.env.read_txn()?;
        let mut offers = Vec::new();
        let mut listed = BTreeSet::new();
        for signal in scan_signals_in_txn(&self.store, &txn)? {
            let Some(proposal_ref) = signal.proposed_slate_ref else {
                continue;
            };
            if !names(&signal.connector) || listed.contains(&proposal_ref) {
                continue;
            }
            let Some(proposal) = read_slate_in_store_txn(&self.store, &txn, proposal_ref)? else {
                continue;
            };
            let Some(cause) = proposal.cause().cloned() else {
                continue;
            };
            let scope = signal_ramp_scope(&signal)?;
            if proposal.owner_actor().is_some()
                || !scope_offer_standing_in_txn(self, &txn, &signal, &scope, now)?
            {
                continue;
            }
            listed.insert(proposal_ref);
            offers.push(offer_of(proposal_ref, &proposal, signal.connector, cause));
        }
        for (connector, proposal_ref, cause) in
            super::credential_binding::open_issuer_revisions_in_txn(&self.store, &txn)?
        {
            if !names(&connector) {
                continue;
            }
            let proposal = match proposal_ref {
                Some(id) => {
                    read_slate_in_store_txn(&self.store, &txn, id)?.map(|slate| (id, slate))
                }
                None => None,
            };
            offers.push(match proposal {
                Some((id, slate)) => offer_of(id, &slate, connector, cause),
                None => ConnectorSlateRevisionOffer {
                    proposal_ref: None,
                    proposal_revision: None,
                    prior_ref: None,
                    connector,
                    reask: BTreeSet::new(),
                    cause,
                },
            });
        }
        Ok(offers)
    }

    /// The owner holds a scope revision's offer back, or lets it surface
    /// again, through ED-05's own answers on the signal's ramp scope: no new
    /// backoff, and never its go-auto, which would mint a different grant.
    pub fn defer_connector_slate_revision(
        &self,
        owner: &AuthenticatedOwner,
        signal_id: EntityId,
        deferral: ConnectorRevisionDeferral,
    ) -> Result<SnoozeState> {
        let scope = {
            let txn = self.store.env.read_txn()?;
            let signal =
                read_signal_in_txn(&self.store, &txn, &signal_id)?.ok_or(Error::EntityNotFound)?;
            signal_ramp_scope(&signal)?
        };
        match deferral {
            ConnectorRevisionDeferral::NotNow => {
                answer_graduation_offer_as_owner(self, owner, &scope, OfferAnswer::NotNow)
                    .map(drop)?;
            }
            ConnectorRevisionDeferral::ManualPinned => {
                answer_graduation_offer_as_owner(self, owner, &scope, OfferAnswer::ManualPinned)
                    .map(drop)?;
            }
            ConnectorRevisionDeferral::Unpin => unpin_scope_as_owner(self, owner, &scope)?,
        }
        snooze_state(self, &scope)
    }

    /// The owner's one stamp of a proposed revision at `expected_revision`
    /// (ARCH-0072 settlement). Its evidence is rechecked in the stamping
    /// writer: a scope revision's offer must still stand on the authority it
    /// was earned under, and mints the widened grant; an issuer revision
    /// must match its binding's expected generation, and accepts the new
    /// issuer so the rows it held run again. A drift delta lands through its
    /// connector's own revision instead.
    pub fn accept_connector_slate_revision(
        &self,
        owner: &AuthenticatedOwner,
        slate_id: EntityId,
        expected_revision: u64,
    ) -> Result<ConnectorSlateRevisionAccepted> {
        self.accept_connector_slate_revision_with_overrides(
            owner,
            slate_id,
            expected_revision,
            &BTreeMap::new(),
        )
    }

    /// The owner's one stamp of a proposed revision at `expected_revision`
    /// (ARCH-0072 settlement), ruling rows by key through `overrides`: a tool
    /// name, or the elicitation row. A row left out keeps its drafted setting.
    /// Its evidence is rechecked in the stamping writer: a scope revision's
    /// offer must still stand on the authority it was earned under, and mints
    /// the widened grant; an issuer revision must match its binding's expected
    /// generation, and accepts the new issuer so the rows it held run again.
    /// A drift delta lands through its connector's own revision instead.
    pub fn accept_connector_slate_revision_with_overrides(
        &self,
        owner: &AuthenticatedOwner,
        slate_id: EntityId,
        expected_revision: u64,
        overrides: &BTreeMap<String, SlateOwnerOverride>,
    ) -> Result<ConnectorSlateRevisionAccepted> {
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let proposal = read_slate_in_store_txn(&self.store, txn, slate_id)?
                .ok_or(Error::EntityNotFound)?;
            if proposal.owner_actor().is_some() {
                return Err(invalid_body("the revision is already accepted"));
            }
            let cause = proposal
                .cause()
                .cloned()
                .ok_or_else(|| invalid_body("the slate is not a proposed revision"))?;
            let stamped =
                self.stamp_slate_in_txn(txn, owner, slate_id, expected_revision, overrides, None)?;
            let mut issuer_catalog_key: Option<EntityId> = None;
            let grants = match &cause {
                SlateRevisionCause::ScopeExceed { signal_ref, .. } => {
                    accept_scope_in_txn(self, txn, owner, slate_id, *signal_ref, now)?
                }
                SlateRevisionCause::CredentialIssuerChanged {
                    binding_ref,
                    expected_generation,
                    ..
                } => {
                    let catalog_key = super::credential_binding::accept_issuer_in_txn(
                        &self.store,
                        txn,
                        slate_id,
                        *binding_ref,
                        *expected_generation,
                    )?;
                    issuer_catalog_key = Some(catalog_key);
                    Vec::new()
                }
                SlateRevisionCause::ManifestDrift => {
                    return Err(invalid_body(
                        "a drift delta lands through its connector's revision",
                    ));
                }
            };
            // FIX 9304: the cause arm above runs first, byte-identical to today,
            // so the mint reads the pre-adopt live grant; the owner's row rulings
            // land last and win ties (a just-minted widening on a now-`never_allow`
            // row retires through the adopt's derived-key sync: his explicit hand
            // beats the earned widening in one act). The proposal never governs
            // (calls meet `key.slate_ref`, the prior), so proposal-only overrides
            // would be recorded-but-inert: the same map also stamps the prior, whose
            // live holder narrows only a prior stamp clears. Empty overrides skip
            // this whole step, and the accept behaves exactly as today.
            if !overrides.is_empty() {
                // A forced revision always carries its prior; `None` skips,
                // defensive.
                if let Some(prior_id) = proposal.prior() {
                    let prior = read_slate_in_store_txn(&self.store, txn, prior_id)?
                        .ok_or_else(|| invalid_body("connector slate missing"))?;
                    self.stamp_slate_in_txn(
                        txn,
                        owner,
                        prior_id,
                        prior.revision(),
                        overrides,
                        None,
                    )?;
                    let target: Option<EntityId> = match &cause {
                        SlateRevisionCause::CredentialIssuerChanged { .. } => issuer_catalog_key,
                        SlateRevisionCause::ScopeExceed { signal_ref, .. } => {
                            if let Some(signal) = read_signal_in_txn(&self.store, txn, signal_ref)?
                            {
                                if let Some(record) =
                                    read_connector_key_in_txn(&self.store, txn, &signal.key_ref)?
                                {
                                    if record.catalog.is_some() {
                                        Some(signal.key_ref)
                                    } else {
                                        derived_key_catalog_in_txn(&self.store, txn, &record)?
                                            .map(|(id, _, _)| id)
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        SlateRevisionCause::ManifestDrift => None,
                    };
                    if let Some(key_id) = target {
                        if let Some(key) = read_connector_key_in_txn(&self.store, txn, &key_id)? {
                            let admitted = key.catalog.is_some()
                                && matches!(
                                    key.status,
                                    ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
                                )
                                && key.qualification_receipt.is_some();
                            // Pending keys: the stamp suffices, qualify reads it;
                            // mirrors `/slate/accept`'s `if admitted` gate.
                            if admitted {
                                self.adopt_connector_slate_stamp_in_txn(txn, &key_id, now)?;
                            }
                        }
                    }
                }
            }
            Ok(ConnectorSlateRevisionAccepted {
                slate_id,
                revision: stamped.revision(),
                cause,
                grants,
            })
        })
    }
}

//! FIX 988: the owner's doors onto proposed connector slate revisions
//! (ARCH-0072 door 3, and the issuer-change re-ask on a credential binding).
//!
//! `vault.connectors.slates.scope_outcome` records his ruling on a held
//! call's typed scope exceed into its ramp; `revision_offers` lists the
//! revisions waiting on him; `defer_revision` holds a scope offer back
//! through ED-05's own answers; `accept_revision` is his one stamp of a
//! revision, rechecked against its evidence; `reask_issuer` is his
//! authenticated observation of the issuer a credential slot answers for.
//! None widens anything by itself: only `accept_revision` lands a revision.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::connector_key::{
    ConnectorBindingDependent, ConnectorCredentialBinding, ConnectorIssuerObservation,
    ConnectorIssuerTransitionState, ConnectorRevisionDeferral, ConnectorScopeExceed,
    ConnectorScopeOutcome, ConnectorScopeOutcomeRecorded, ConnectorSlateRevisionAccepted,
    ConnectorSlateRevisionOffer, ConnectorSlateScopeSignal, SlateDisposition, SlateOwnerOverride,
    SlateRevisionCause,
};
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::graduation::SnoozeState;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};

fn id(value: &str, field: &'static str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value).map_err(|_| MemoryError::bad_request(field))
}

/// Why a slate revises its prior, as the owner reviews it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectorSlateRevisionCauseView {
    /// The connector's declaration drifted.
    ManifestDrift,
    /// His rulings on repeated scope exceeds earned an offer to widen one
    /// row's grant.
    ScopeExceed {
        signal_ref: String,
        key_ref: String,
        actor: String,
        /// The authority generation the offer was earned under, 64 hex.
        generation: String,
        tool: String,
        exceed: ConnectorScopeExceed,
    },
    /// A credential binding answers for a new issuer: every row that
    /// depended on the old one is re-asked.
    CredentialIssuerChanged {
        binding_ref: String,
        expected_generation: u64,
        old_issuer: String,
        new_issuer: String,
        proposed_credential_ref: String,
        dependent_rows: Vec<String>,
    },
}

impl ConnectorSlateRevisionCauseView {
    /// The engine's cause, as he reviews it.
    #[must_use]
    pub fn of(cause: &SlateRevisionCause) -> Self {
        match cause {
            SlateRevisionCause::ManifestDrift => Self::ManifestDrift,
            SlateRevisionCause::ScopeExceed {
                signal_ref,
                key_ref,
                actor,
                generation,
                tool,
                exceed,
            } => Self::ScopeExceed {
                signal_ref: signal_ref.to_hex(),
                key_ref: key_ref.to_hex(),
                actor: actor.clone(),
                generation: generation
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                tool: tool.clone(),
                exceed: exceed.clone(),
            },
            SlateRevisionCause::CredentialIssuerChanged {
                binding_ref,
                expected_generation,
                old_issuer,
                new_issuer,
                proposed_credential_ref,
                dependent_rows,
            } => Self::CredentialIssuerChanged {
                binding_ref: binding_ref.to_hex(),
                expected_generation: *expected_generation,
                old_issuer: old_issuer.clone(),
                new_issuer: new_issuer.clone(),
                proposed_credential_ref: proposed_credential_ref.clone(),
                dependent_rows: dependent_rows.iter().cloned().collect(),
            },
        }
    }
}

/// One logical call's typed scope exceed, as the owner reviews it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorScopeSignalView {
    pub signal_ref: String,
    /// The held call it describes.
    pub call_ref: String,
    pub connector: String,
    pub tool: String,
    pub key_ref: String,
    pub grant_id: String,
    pub actor: String,
    pub exceed: ConnectorScopeExceed,
    pub observed_at: u64,
    /// His ruling, once recorded.
    pub ruling: Option<ConnectorScopeOutcome>,
    /// The proposed delta slate its earned offer drafted.
    pub proposal_ref: Option<String>,
}

impl ConnectorScopeSignalView {
    fn of(signal: &ConnectorSlateScopeSignal) -> Self {
        Self {
            signal_ref: signal.signal_id.to_hex(),
            call_ref: signal.call_ref.to_hex(),
            connector: signal.connector.clone(),
            tool: signal.tool.clone(),
            key_ref: signal.key_ref.to_hex(),
            grant_id: signal.grant_id.to_hex(),
            actor: signal.actor.clone(),
            exceed: signal.exceed.clone(),
            observed_at: signal.observed_at,
            ruling: signal.ruling.as_ref().map(|ruling| ruling.outcome),
            proposal_ref: signal.proposed_slate_ref.map(|id| id.to_hex()),
        }
    }
}

/// `vault.connectors.slates.scope_outcome`: the owner's ruling on the held
/// call a scope signal names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorScopeOutcomeRequest {
    /// The scope signal, 32 hex.
    pub signal_ref: String,
    /// The approve-once digest of the held call's ask he ruled on.
    pub linked_ruling: String,
    pub outcome: ConnectorScopeOutcome,
}

/// What his ruling came to: the signal, its ramp's counters and any
/// proposal the earned offer drafted. Nothing is stamped or granted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorScopeOutcomeView {
    pub signal: ConnectorScopeSignalView,
    pub untouched_streak: u32,
    pub amended: u32,
    pub rejected: u32,
    /// The proposed delta slate, unstamped; absent until the offer is earned.
    pub proposal_ref: Option<String>,
}

impl ConnectorScopeOutcomeView {
    fn of(recorded: &ConnectorScopeOutcomeRecorded) -> Self {
        Self {
            signal: ConnectorScopeSignalView::of(&recorded.signal),
            untouched_streak: recorded.untouched_streak,
            amended: recorded.amended,
            rejected: recorded.rejected,
            proposal_ref: recorded.proposed_slate_ref.map(|id| id.to_hex()),
        }
    }
}

/// `vault.connectors.slates.scope_outcome` as `owner`.
///
/// # Errors
/// A malformed ref, an unknown signal, a ruling already recorded or one
/// that names no ask of its call, and the owner check's refusal.
pub fn record_connector_scope_outcome(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorScopeOutcomeRequest,
) -> MemoryResult<ConnectorScopeOutcomeView> {
    let signal_id = id(&input.signal_ref, "signal_ref must be 32 hex")?;
    let recorded = vault.record_connector_scope_outcome(
        owner,
        signal_id,
        &input.linked_ruling,
        input.outcome,
    )?;
    Ok(ConnectorScopeOutcomeView::of(&recorded))
}

/// `vault.connectors.slates.revision_offers`: the revisions waiting on the
/// owner, optionally for one catalog connector.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRevisionOffersRequest {
    #[serde(default)]
    pub connector: Option<String>,
}

/// One revision waiting on the owner.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorSlateRevisionOfferView {
    /// The proposed delta slate, unstamped; absent while an issuer change is
    /// detected but its slate is not drafted.
    pub proposal_ref: Option<String>,
    /// The revision his stamp names.
    pub proposal_revision: Option<u64>,
    /// The slate it revises.
    pub prior_ref: Option<String>,
    pub connector: String,
    /// The rows it re-asks.
    pub reask: Vec<String>,
    pub cause: ConnectorSlateRevisionCauseView,
}

impl ConnectorSlateRevisionOfferView {
    fn of(offer: &ConnectorSlateRevisionOffer) -> Self {
        Self {
            proposal_ref: offer.proposal_ref.map(|id| id.to_hex()),
            proposal_revision: offer.proposal_revision,
            prior_ref: offer.prior_ref.map(|id| id.to_hex()),
            connector: offer.connector.clone(),
            reask: offer.reask.iter().cloned().collect(),
            cause: ConnectorSlateRevisionCauseView::of(&offer.cause),
        }
    }
}

/// The revisions waiting on the owner.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorSlateRevisionOffersView {
    pub offers: Vec<ConnectorSlateRevisionOfferView>,
}

/// `vault.connectors.slates.revision_offers` as `owner`. Listing activates
/// nothing.
///
/// # Errors
/// The owner check's refusal and storage failures.
pub fn connector_slate_revision_offers(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorSlateRevisionOffersRequest,
) -> MemoryResult<ConnectorSlateRevisionOffersView> {
    owner.revalidate(vault)?;
    let offers = vault.connector_slate_revision_offers(input.connector.as_deref())?;
    Ok(ConnectorSlateRevisionOffersView {
        offers: offers
            .iter()
            .map(ConnectorSlateRevisionOfferView::of)
            .collect(),
    })
}

/// `vault.connectors.slates.defer_revision`: the owner holds a scope
/// revision's offer back, or lets it surface again.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRevisionDeferRequest {
    /// The scope signal whose offer it is, 32 hex.
    pub signal_ref: String,
    pub deferral: ConnectorRevisionDeferral,
}

/// Whether, and until when, the offer is held back.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectorRevisionSnoozeView {
    /// Nothing holds it: an earned offer surfaces.
    Surfacing,
    /// Held until `next_eligible_at`, after `count` "not now" answers.
    Snoozed { count: u8, next_eligible_at: u64 },
    /// Held until he unpins it.
    ManualPinned,
}

impl ConnectorRevisionSnoozeView {
    fn of(state: SnoozeState) -> Self {
        match state {
            SnoozeState::None => Self::Surfacing,
            SnoozeState::Snoozed {
                count,
                next_eligible_at,
            } => Self::Snoozed {
                count,
                next_eligible_at,
            },
            SnoozeState::ManualPinned => Self::ManualPinned,
        }
    }
}

/// `vault.connectors.slates.defer_revision` as `owner`.
///
/// # Errors
/// A malformed ref, an unknown signal, no offer standing to decline, and
/// the owner check's refusal.
pub fn defer_connector_slate_revision(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorSlateRevisionDeferRequest,
) -> MemoryResult<ConnectorRevisionSnoozeView> {
    let signal_id = id(&input.signal_ref, "signal_ref must be 32 hex")?;
    let state = vault.defer_connector_slate_revision(owner, signal_id, input.deferral)?;
    Ok(ConnectorRevisionSnoozeView::of(state))
}

/// `vault.connectors.slates.accept_revision`: the owner's one stamp of a
/// proposed revision at the revision he reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRevisionAcceptRequest {
    /// The proposed delta slate, 32 hex.
    pub slate_ref: String,
    pub expected_revision: u64,
    /// The owner's setting per row: `always_allow`, `auto`, `always_ask` or
    /// `never_allow`. A row left out keeps its drafted setting. Rows go by
    /// tool name; `@elicitation` names the elicitation row.
    #[serde(default)]
    pub overrides: BTreeMap<String, SlateDisposition>,
}

/// One grant an accepted scope revision minted, with its per-grant key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorRevisionGrantView {
    pub tool: String,
    pub grant_id: String,
    pub key_id: String,
    pub key_connector: String,
}

/// The accepted revision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorSlateRevisionAcceptedView {
    pub slate_ref: String,
    pub revision: u64,
    pub cause: ConnectorSlateRevisionCauseView,
    /// The widened grant a scope revision minted; none for an issuer one.
    pub grants: Vec<ConnectorRevisionGrantView>,
}

impl ConnectorSlateRevisionAcceptedView {
    fn of(accepted: &ConnectorSlateRevisionAccepted) -> Self {
        Self {
            slate_ref: accepted.slate_id.to_hex(),
            revision: accepted.revision,
            cause: ConnectorSlateRevisionCauseView::of(&accepted.cause),
            grants: accepted
                .grants
                .iter()
                .map(|grant| ConnectorRevisionGrantView {
                    tool: grant.tool.clone(),
                    grant_id: grant.grant_id.clone(),
                    key_id: grant.key_id.clone(),
                    key_connector: grant.key_connector.clone(),
                })
                .collect(),
        }
    }
}

/// `vault.connectors.slates.accept_revision` as `owner`.
///
/// # Errors
/// A malformed ref, a slate that is no proposed revision or is already
/// accepted, a moved revision or binding generation, an offer that no
/// longer stands, and the stamp's and consent door's own refusals.
pub fn accept_connector_slate_revision(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorSlateRevisionAcceptRequest,
) -> MemoryResult<ConnectorSlateRevisionAcceptedView> {
    let slate_id = id(&input.slate_ref, "slate_ref must be 32 hex")?;
    let overrides: BTreeMap<String, SlateOwnerOverride> = input
        .overrides
        .into_iter()
        .map(|(tool, disposition)| (tool, SlateOwnerOverride { disposition }))
        .collect();
    let accepted = vault.accept_connector_slate_revision_with_overrides(
        owner,
        slate_id,
        input.expected_revision,
        &overrides,
    )?;
    Ok(ConnectorSlateRevisionAcceptedView::of(&accepted))
}

/// One key, or one row of it, that depends on a credential slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBindingDependentView {
    /// The catalog key or a per-grant key derived from it, 32 hex.
    pub key_ref: String,
    /// The row (a tool, or `@elicitation`); absent: every row the key calls.
    #[serde(default)]
    pub tool: Option<String>,
}

/// `vault.connectors.slates.reask_issuer`: the owner's observation of the
/// issuer one catalog connector's credential slot answers for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIssuerReaskRequest {
    /// The catalog connector's name.
    pub connector: String,
    /// The credential slot: `route`, or a custody record's name.
    pub slot: String,
    /// The issuer the slot's credential answers for now.
    pub issuer: String,
    /// The custody pointer or fingerprint presented now, never a value.
    pub credential_ref: String,
    /// The binding generation he read: 0 for the first observation.
    pub expected_generation: u64,
    /// The keys and rows that depend on the slot; empty keeps the binding's.
    #[serde(default)]
    pub dependents: Vec<ConnectorBindingDependentView>,
    /// What was observed, in words: never a credential.
    pub witness: String,
}

/// One credential slot's binding, as the owner reviews it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorCredentialBindingView {
    pub binding_ref: String,
    pub connector: String,
    pub slot: String,
    /// The accepted issuer.
    pub issuer: String,
    pub credential_ref: String,
    pub generation: u64,
    pub dependents: Vec<ConnectorBindingDependentView>,
    /// The latest issuer change's new issuer, and where it stands:
    /// `detected`, `drafted` or `accepted`.
    pub changed_to: Option<String>,
    pub change_state: Option<String>,
    /// The forced re-ask waiting on his stamp.
    pub proposal_ref: Option<String>,
}

impl ConnectorCredentialBindingView {
    fn of(binding: &ConnectorCredentialBinding) -> Self {
        let transition = binding.transition.as_ref();
        let (change_state, proposal_ref) = match transition.map(|change| &change.state) {
            None => (None, None),
            Some(ConnectorIssuerTransitionState::Detected) => (Some("detected"), None),
            Some(ConnectorIssuerTransitionState::Drafted { slate_ref }) => {
                (Some("drafted"), Some(slate_ref.to_hex()))
            }
            Some(ConnectorIssuerTransitionState::Accepted { .. }) => (Some("accepted"), None),
        };
        Self {
            binding_ref: binding.binding_ref.to_hex(),
            connector: binding.connector.clone(),
            slot: binding.slot.clone(),
            issuer: binding.issuer.clone(),
            credential_ref: binding.credential_ref.clone(),
            generation: binding.generation,
            dependents: binding
                .dependents
                .iter()
                .map(|dependent| ConnectorBindingDependentView {
                    key_ref: dependent.key_ref.to_hex(),
                    tool: dependent.tool.clone(),
                })
                .collect(),
            changed_to: transition.map(|change| change.new_issuer.clone()),
            change_state: change_state.map(str::to_owned),
            proposal_ref,
        }
    }
}

/// `vault.connectors.slates.reask_issuer` as `owner`, with the rows it
/// read: the catalog key and each dependent key.
///
/// # Errors
/// Malformed refs, an unknown catalog connector, a dependent that is not
/// its own, a moved binding generation, and the owner check's refusal.
pub fn reask_connector_issuer_as(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorIssuerReaskRequest,
) -> MemoryResult<(ConnectorCredentialBindingView, Vec<EntityId>)> {
    let dependents = input
        .dependents
        .iter()
        .map(|dependent| {
            Ok(ConnectorBindingDependent {
                key_ref: id(&dependent.key_ref, "dependent key_ref must be 32 hex")?,
                tool: dependent.tool.clone(),
            })
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    let binding = vault.observe_connector_credential_issuer(
        owner,
        &ConnectorIssuerObservation {
            connector: input.connector,
            slot: input.slot,
            issuer: input.issuer,
            credential_ref: input.credential_ref,
            expected_generation: input.expected_generation,
            dependents,
            witness: input.witness,
        },
    )?;
    let rows: BTreeSet<EntityId> = std::iter::once(binding.catalog_key)
        .chain(binding.dependents.iter().map(|dependent| dependent.key_ref))
        .collect();
    Ok((
        ConnectorCredentialBindingView::of(&binding),
        rows.into_iter().collect(),
    ))
}

/// `vault.connectors.slates.reask_issuer` on an embedded handle, as its
/// owner.
///
/// # Errors
/// As [`reask_connector_issuer_as`].
pub fn reask_connector_issuer(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorIssuerReaskRequest,
) -> MemoryResult<ConnectorCredentialBindingView> {
    reask_connector_issuer_as(vault, owner, input).map(|(view, _)| view)
}

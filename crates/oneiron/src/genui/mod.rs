//! OF-336 generated-UI component contract.
//!
//! This module owns the engine-resident payload shape and view-time deep-link
//! resolution, which reads the vault; grant storage and outbound execution
//! remain in later gates.

mod consent_cards;
mod consent_eval;
mod failure_card;
mod failure_card_validation;
mod protocol;
mod receipt_view;

pub use self::consent_cards::{
    BundleApprovalScope, BundleApproveCard, BundleSendItem, ConsentAskCard, ConsentScopeEscalator,
};
pub use self::consent_eval::{
    CONSENT_ACTION_APPROVE_ONCE, CONSENT_ACTION_DECLINE, CONSENT_ACTION_ESCALATE_PREFIX,
    CONSENT_BUNDLE_ACTION_DECLINE, CONSENT_BUNDLE_ACTION_ID_PREFIX, ConsentActionDecision,
    ConsentActionEvaluation, ConsentActionKind, ConsentActionRequest, ConsentActorIdentity,
    ConsentConfirmOutcome, ConsentSurface, GrantMintIntent, GrantMintIntentScope,
    calendar_grant_mint_intent, consent_action_id_offers_duration,
};
use self::failure_card::parse_card_ref;
pub use self::failure_card::{
    FailureDiagnosisState, HealerQaEntryRef, HealerQaFeed, SURFACED_FAILURE_CARD_SCHEMA_VERSION,
    SurfacedFailureCard, SurfacedFailureCardInput, surfaced_failure_card,
};
pub use self::protocol::{
    OF336_CARD_CATALOG_VERSION, OF336_MCP_UI_MIME, OF336_PROTOCOL_VERSION, Of336ActionDescriptor,
    Of336Component, Of336ComponentKind, Of336RenderedComponent, Of336SurfaceAdapter,
};
pub use self::receipt_view::{
    ReceiptDeepLink, ReceiptDeepLinkKind, ReceiptViewComponent, ViewTimeResolution,
    resolve_commitment_receipt_link,
};

#[cfg(test)]
mod tests;

// The flat genui.rs module used to provide its private crate/std import
// header to the sibling test module through `use super::*` (genui-internal
// items reach the tests through the `pub use` seam above). After the
// directory split the seam re-imports the header names the tests name bare
// so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::booking::DisclosureRung;
#[cfg(test)]
use crate::claim::ClaimLifecycleStatus;
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::failure_ladder::{FailureClass, HealerRepairRoute, failure_card_ref, failure_case_ref};
#[cfg(test)]
use crate::receipt::{ReceiptKind, ReceiptRecord};
#[cfg(test)]
use crate::run_tree::RunTree;
#[cfg(test)]
use crate::{Error, Result};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::BTreeMap;

//! Moved from `crates/oneiron/src/office_body/consent.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use loro::ExportMode;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_consent_state::consent::effect::EffectFacts;
use oneiron_consent_state::consent::grant::StandingConsentGrant;
use oneiron_contracts::entity_id::EntityId;
use oneiron_docedit::live::ApproveScope;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::ConsentDecision;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::typed_body::body_actor::BodyActor;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettleVerdict {
    Accept,
    Reject,
}

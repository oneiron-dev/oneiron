//! Moved from `crates/oneiron/src/blob_artifact/esign/ceremony.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SigningPage {
    pub item_count: usize,
    pub title: String,
    pub recipient: String,
    pub fields: Vec<EsignField>,
    pub presentations: Vec<super::render::FieldPresentation>,
    pub values: BTreeMap<String, SignatureRow>,
}

/// Receipt observations of the sealed bytes, in document item order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SigningSealedItem {
    pub sha256: String,
    pub active_content: oneiron_store::blob_artifact::esign::sealer::SealActiveContentFacts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum SigningOutcome {
    Page(SigningPage),
    NotYourTurn,
    Terminal {
        status: DocumentStatus,
        item_count: usize,
        /// None when no sealing receipt is available to read.
        sealed_items: Option<Vec<SigningSealedItem>>,
    },
    AwaitingSeal,
    /// D6: the signing dial does not open this automated sign act, so the
    /// call is held for its role chain's answer, never dropped.
    HeldForOwner {
        held_at: u64,
    },
    ConsentRequired,
}

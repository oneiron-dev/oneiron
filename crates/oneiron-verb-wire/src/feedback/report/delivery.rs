//! Moved from `crates/oneiron/src/feedback/report/delivery.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::report::delivery::owner::ReportDeliveryRun;
pub use crate::feedback::report::delivery::owner::ReportDeliveryRunRequest;
pub use crate::feedback::report::delivery::owner::ReportDeliveryStatusRequest;
pub use crate::feedback::report::delivery::owner::ReportPublisherBinding;
pub use crate::feedback::report::delivery::owner::ReportPublisherBindingRequest;
pub use crate::feedback::report::delivery::retry::ReportDeliveryRetryRequest;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The one delivery lane built here: content-free signatures.
pub const REPORT_SIGNATURE_LANE: &str = "signature";

/// Where a publisher's signatures go: a feedback channel and its exact
/// endpoint, as the owner bound them from this host's feedback destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportPublisherEndpoint {
    /// The outbound feedback channel.
    pub channel: String,
    /// The exact endpoint on it.
    pub endpoint: String,
}

/// Why an issue's signature has not left yet. Every hold is retried on the
/// next run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "hold", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportDeliveryHold {
    /// The historical artifact, version or model is not exactly resolvable;
    /// `reason` names the first missing piece.
    MetadataUnresolved { reason: String },
    /// No owner binding names an endpoint for the issue's publisher.
    EndpointUnbound,
    /// The bound destination takes no issue signatures.
    DestinationUnsupported { channel: String },
    /// The lane's destination (`bound`) is not what the binding or this
    /// host's feedback destination now names (`current`). Never redirected:
    /// the owner binds again.
    ChangedBinding {
        bound: ReportPublisherEndpoint,
        current: Option<ReportPublisherEndpoint>,
    },
    /// "Help improve Oneiron" (`participation`) or the publisher dial is
    /// off: the signature is kept, and nothing is sent.
    Withheld {
        participation: bool,
        publisher_dial: bool,
    },
}

/// What the lane's last send did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportDeliveryOutcome {
    /// The publisher's endpoint acknowledged it, with a persisted delivery
    /// receipt.
    Delivered,
    /// It may have landed. The outbound ledger reconciles it; it is never
    /// posted again.
    Uncertain,
    /// It did not leave on this send; `dispatch` is the pipeline's outcome.
    /// The next run sends the same logical send, and the ledger answers
    /// whatever it recorded.
    NotDelivered { dispatch: String },
}

impl ReportDeliveryOutcome {
    /// Whether the lane is done: a delivery, or a send that may have landed.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Delivered | Self::Uncertain)
    }
}

/// The frozen signature: the stored ED-08 row and its exact wire bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportFrozenSignature {
    /// The stored ED-08 signature.
    pub signature: EntityId,
    /// The exact body, canonical `oneiron.issue_signature.v1` JSON.
    pub body: String,
    /// Lowercase hex BLAKE3 of `body`.
    pub digest: String,
}

/// The frozen send: one destination and one logical send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportFrozenSend {
    /// Where it goes, frozen from the binding when this send is chosen.
    pub destination: ReportPublisherEndpoint,
    /// The logical send: receipt, intent, ledger and idempotency identity.
    pub send_ref: String,
}
pub mod owner;
pub mod retry;

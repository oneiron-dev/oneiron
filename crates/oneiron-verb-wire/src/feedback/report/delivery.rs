//! Moved from `crates/oneiron/src/feedback/report/delivery.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::report::delivery::owner::ReportDeliveryRun;
pub use crate::feedback::report::delivery::owner::ReportDeliveryRunRequest;
pub use crate::feedback::report::delivery::owner::ReportDeliveryStatus;
pub use crate::feedback::report::delivery::owner::ReportDeliveryStatusRequest;
pub use crate::feedback::report::delivery::owner::ReportPublisherBinding;
pub use crate::feedback::report::delivery::owner::ReportPublisherBindingRequest;
pub use crate::feedback::report::delivery::retry::ReportDeliveryRetryRequest;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The one delivery lane built here: content-free signatures.
pub const REPORT_SIGNATURE_LANE: &str = "signature";

/// One delivery lane of one issue: `(issue_ref, publisher_ref, lane)`. The
/// signature lane freezes one destination and one digest; a later approved
/// text send keeps a lane of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryKey {
    /// The ISSUE, 32 hex.
    pub issue_ref: String,
    /// The publisher the issue is routed to.
    pub publisher_ref: String,
    /// The lane: `signature`.
    pub lane: String,
}

impl ReportDeliveryKey {
    fn signature(issue_ref: &str, publisher_ref: &str) -> Self {
        Self {
            issue_ref: issue_ref.to_owned(),
            publisher_ref: publisher_ref.to_owned(),
            lane: REPORT_SIGNATURE_LANE.to_owned(),
        }
    }

    fn row(&self) -> Result<(EntityId, [u8; 32])> {
        Ok((
            EntityId::from_hex(&self.issue_ref)?,
            self.hash(b"oneiron.report.delivery.row.v1\0"),
        ))
    }

    /// The lane's initial logical send. Ordinary runs reuse the frozen send;
    /// only an explicit owner retry after proved non-delivery replaces it.
    fn send_ref(&self) -> String {
        let hash = blake3::Hash::from(self.hash(b"oneiron.report.delivery.send.v1\0"));
        format!("report-signature:{}", hash.to_hex())
    }

    fn hash(&self, domain: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        for part in [&self.issue_ref, &self.publisher_ref, &self.lane] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

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

/// One delivery lane's custody: the key, what is frozen, the hold, and the
/// last send's receipt and outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRecord {
    /// The lane.
    pub key: ReportDeliveryKey,
    /// The frozen signature, once its metadata resolved.
    pub signature: Option<ReportFrozenSignature>,
    /// The frozen send, once one was offered.
    pub send: Option<ReportFrozenSend>,
    /// What holds it, if anything.
    pub hold: Option<ReportDeliveryHold>,
    /// The last send's ordinary outbound receipt.
    pub receipt: Option<String>,
    /// The last send's outcome.
    pub outcome: Option<ReportDeliveryOutcome>,
    /// The last send's dispatch error, until a send records an outcome.
    pub last_error: Option<String>,
    /// When a run last touched it, in seconds.
    pub updated_at: u64,
}

impl ReportDeliveryRecord {
    fn new(key: ReportDeliveryKey, now: u64) -> Self {
        Self {
            key,
            signature: None,
            send: None,
            hold: None,
            receipt: None,
            outcome: None,
            last_error: None,
            updated_at: now,
        }
    }
}
pub mod owner;
pub mod retry;

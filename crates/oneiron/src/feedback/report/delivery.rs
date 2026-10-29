//! Publisher delivery of content-free issue signatures (OF-420, FIX 739),
//! keyed by `issue_ref`. A run walks every report arrival. A report routed to
//! a publisher gets one ED-08 [`IssueSignature`], built through its only
//! constructor from the historical metadata its subject's pack receipt names
//! and frozen once as wire bytes with their digest. Its send freezes the
//! destination the owner bound and leaves through the ordinary recorded
//! outbound spine under one logical send. Whatever cannot leave yet is a
//! visible hold on the issue's custody row: unresolved metadata, an unbound,
//! unsupported or changed endpoint, or a participation switch that is off. A
//! recorded delivery, or a send that may have landed, is never posted again.
//! Text never rides this lane: a disclosed report keeps its manual, approved
//! send.

mod counterparty;
mod metadata;
mod owner;
mod packet_signature;
mod participation;
mod wire;

use serde::{Deserialize, Serialize};

pub use self::metadata::ReportPublisherMetadata;
pub use self::owner::{
    ReportDeliveryRun, ReportDeliveryRunRequest, ReportDeliveryStatus, ReportDeliveryStatusRequest,
    ReportPublisherBinding, ReportPublisherBindingRequest,
};
pub(crate) use self::wire::received_issue_signature;
use self::wire::{SignatureSink, signature_request, wire_body};
use super::{ReportDisclosure, ReportIssue, ReportRoute, ReportRoutedPayload, ReportStatus};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::edit_distance::publisher::{
    IssueSignature, PublisherActor, PublisherError, SignatureDeliveryOutcome,
    emit_issue_signature_in_txn, issue_signature, record_signature_delivery,
    record_signature_delivery_in_txn, record_signature_hold_in_txn,
};
use crate::outbound::{
    OutboundDispatchOutcome, OutboundExecutionOutcome, OutboundExecutionRequest, connector_actor_id,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The Coach facet that delivers issue signatures, nightly and on the
/// owner's run-now.
pub const COACH_FEEDBACK_DELIVERY_FACET: &str = "coach.feedback_delivery";
/// The one delivery lane built here: content-free signatures.
pub const REPORT_SIGNATURE_LANE: &str = "signature";
/// The outbound verb a signature leaves on, beside a bundle's `send`.
pub const REPORT_SIGNATURE_VERB: &str = "signature";
/// The schema token every signature body carries.
pub const REPORT_SIGNATURE_SCHEMA: &str = "oneiron.issue_signature.v1";

/// The connector class the signature sender's actor id derives from.
const SENDER: &str = "feedback_signature";
/// A GitHub issue destination takes no signatures: each would open a public
/// issue, and nothing there deduplicates a retried POST.
const UNSUPPORTED_CHANNELS: [&str; 1] = ["feedback_github"];
/// Arrivals read per page; a page is only a traversal unit.
const INBOX_PAGE: usize = 256;

/// Custody of one issue's delivery lane. Key: issue id16, then the BLAKE3 of
/// the lane key.
const DELIVERIES: SideTable<(EntityId, [u8; 32]), ReportDeliveryRecord, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_DELIVERY);
/// The owner's publisher bindings. Key: publisher reference.
const ENDPOINTS: SideTable<String, ReportPublisherEndpoint, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_PUBLISHER_ENDPOINT);

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

    /// The lane's one logical send, derived from the key alone: every run
    /// sends under the same ledger identity, and the wire sees only a hash.
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
    /// Where it goes, frozen from the binding at the first send.
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

/// What one run did over the whole inbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportDeliveryPass {
    /// Reports read.
    pub seen: usize,
    /// Reports not routed to a publisher: local, duplicate, rejected or
    /// denied.
    pub not_routed: usize,
    /// Signatures delivered, now or before.
    pub delivered: usize,
    /// Signatures that may have landed.
    pub uncertain: usize,
    /// Lanes held.
    pub held: usize,
    /// Lanes sent but not delivered.
    pub not_delivered: usize,
    /// Reports whose lane failed to read or write; each is counted and the
    /// run goes on.
    pub errors: usize,
}

impl ReportDeliveryPass {
    fn count(&mut self, record: &ReportDeliveryRecord) {
        match (&record.hold, &record.outcome) {
            (Some(_), _) => self.held += 1,
            (None, Some(ReportDeliveryOutcome::Delivered)) => self.delivered += 1,
            (None, Some(ReportDeliveryOutcome::Uncertain)) => self.uncertain += 1,
            _ => self.not_delivered += 1,
        }
    }
}

/// What the host carrier is handed once the pipeline admits a signature.
pub struct ReportSignatureTransportRequest<'a> {
    /// The ordinary outbound execution request, unmodified.
    pub execution: &'a OutboundExecutionRequest<'a>,
    /// The frozen body.
    pub body: &'a [u8],
    /// Lowercase hex BLAKE3 of `body`.
    pub digest: &'a str,
}

/// The host's carrier for issue signatures.
pub trait ReportSignatureTransport {
    /// The feedback destination this host carries to, if it has one. A
    /// binding sends only while it names exactly this destination.
    fn destination(&self) -> Option<ReportPublisherEndpoint>;

    /// Delivers one signature and reports an ordinary execution outcome. A
    /// send that may have landed says so with
    /// [`OutboundExecutionOutcome::with_possible_delivery`].
    fn send_issue_signature(
        &mut self,
        request: &ReportSignatureTransportRequest<'_>,
    ) -> OutboundExecutionOutcome;
}

impl Vault {
    /// The Coach's delivery run: walks every report arrival to the end and
    /// offers each publisher-routed report's signature. There is no cursor,
    /// so a held issue is revisited on every run, after any disclosure,
    /// binding or dial change; one issue's hold or error never stops the
    /// others. The participation grant is kept in step first.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's, and storage errors outside a lane.
    pub fn run_coach_feedback_delivery<T: ReportSignatureTransport + ?Sized>(
        &self,
        admitted: &DreamerAdmittedAttempt,
        transport: &mut T,
        now: u64,
    ) -> Result<ReportDeliveryPass> {
        self.require_coach_attempt(admitted, COACH_FEEDBACK_DELIVERY_FACET)?;
        self.keep_signature_participation(transport.destination().as_ref(), now)?;
        let mut pass = ReportDeliveryPass::default();
        let mut after = None;
        loop {
            let page = self.report_inbox(after, INBOX_PAGE)?;
            for issue in &page {
                after = Some((issue.received_at, EntityId::from_hex(&issue.issue_ref)?));
                pass.seen += 1;
                match self.send_report_signature(&issue.issue_ref, transport, now) {
                    Ok(Some(record)) => pass.count(&record),
                    Ok(None) => pass.not_routed += 1,
                    Err(error) => {
                        pass.errors += 1;
                        tracing::warn!(%error, "an issue signature lane was not processed");
                    }
                }
            }
            if page.len() < INBOX_PAGE {
                return Ok(pass);
            }
        }
    }

    /// Offers one issue's content-free signature to its publisher's bound
    /// endpoint and records the lane. `Ok(None)` when the issue is not
    /// routed to a publisher. A finished lane answers its record and sends
    /// nothing. The gate admits the send on the participation grant that
    /// [`Self::run_coach_feedback_delivery`] keeps; without it the send is
    /// held like any other.
    ///
    /// # Errors
    ///
    /// Storage errors. A dispatch error is kept on the lane instead.
    pub fn send_report_signature<T: ReportSignatureTransport + ?Sized>(
        &self,
        issue_ref: &str,
        transport: &mut T,
        now: u64,
    ) -> Result<Option<ReportDeliveryRecord>> {
        let id = EntityId::from_hex(issue_ref)?;
        // The content-free projection: this lane carries no text (FIX 8747).
        let Some(payload) = self.report_signature_payload(&id)? else {
            return Ok(None);
        };
        let ReportRoute::Publisher { publisher_ref } = &payload.route else {
            return Ok(None);
        };
        let Some(issue) = self.report_issue(&id)? else {
            return Ok(None);
        };
        let key = ReportDeliveryKey::signature(&payload.signature.issue_ref, publisher_ref);
        let row = key.row()?;
        let txn = self.store.env.read_txn()?;
        let stored = DELIVERIES.get(&self.store, &txn, &row)?;
        drop(txn);
        let mut record = stored.unwrap_or_else(|| ReportDeliveryRecord::new(key, now));
        if record
            .outcome
            .as_ref()
            .is_some_and(ReportDeliveryOutcome::is_final)
        {
            // A finished lane whose write-back never ran settles here; a
            // settled one reads and writes nothing (FIX 7690).
            if let Some((signature, send_ref, outcome)) = signature_delivery(&record) {
                record_signature_delivery(self, signature, send_ref, outcome, |artifact| {
                    self.report_publisher_actor(publisher_ref, artifact)
                })
                .map_err(engine_error)?;
            }
            return Ok(Some(record));
        }
        record.updated_at = now;
        let mut built = None;
        record.hold =
            self.signature_hold(&mut record, &mut built, &issue, &payload, &*transport)?;
        // The frozen bytes and send are written before they can leave:
        // admission reads them under the outbound writer. A signature built
        // now is stored in that same write, so a crash leaves both or
        // neither, and the next run never stores a second (FIX 7689). The
        // lane's hold lands on that signature in the same write: Withheld
        // while the switches hold it, Pending once released (FIX 7690).
        let withheld = matches!(record.hold, Some(ReportDeliveryHold::Withheld { .. }));
        self.with_write_txn_grouped(|txn| {
            if let Some(built) = built {
                let signature = emit_issue_signature_in_txn(
                    self,
                    txn,
                    &built.signature,
                    &record.key.send_ref(),
                )
                .map_err(engine_error)?;
                record.signature = Some(ReportFrozenSignature {
                    signature,
                    body: built.body,
                    digest: built.digest,
                });
            }
            if let Some(frozen) = &record.signature {
                record_signature_hold_in_txn(self, txn, frozen.signature, withheld)?;
            }
            DELIVERIES.put(&self.store, txn, &row, &record)
        })?;
        if record.hold.is_none() {
            self.dispatch_report_signature(&mut record, transport, now)?;
            let publisher = self.delivered_publisher(&record, publisher_ref)?;
            // The send's outcome lands on its ED-08 signature in the lane's
            // own write (FIX 7690), naming the publisher ACTOR (FIX 7829).
            self.with_write_txn_grouped(|txn| {
                DELIVERIES.put(&self.store, txn, &row, &record)?;
                if let Some((signature, send_ref, outcome)) = signature_delivery(&record) {
                    record_signature_delivery_in_txn(
                        self,
                        txn,
                        signature,
                        send_ref,
                        outcome,
                        publisher.as_ref(),
                    )
                    .map_err(engine_error)?;
                }
                Ok(())
            })?;
        }
        Ok(Some(record))
    }

    /// Freezes what can be frozen, then answers the first thing that holds
    /// the lane: unresolved metadata, then the endpoint, then the switches.
    /// A lane with no signature yet has one built into `built`, for the
    /// lane's write to store.
    fn signature_hold<T: ReportSignatureTransport + ?Sized>(
        &self,
        record: &mut ReportDeliveryRecord,
        built: &mut Option<BuiltSignature>,
        issue: &ReportIssue,
        payload: &ReportRoutedPayload,
        transport: &T,
    ) -> Result<Option<ReportDeliveryHold>> {
        if record.signature.is_none() {
            match self.build_report_signature(issue, payload)? {
                Ok(signature) => *built = Some(signature),
                Err(reason) => {
                    return Ok(Some(ReportDeliveryHold::MetadataUnresolved {
                        reason: reason.to_owned(),
                    }));
                }
            }
        }
        let txn = self.store.env.read_txn()?;
        let bound = ENDPOINTS.get(&self.store, &txn, &record.key.publisher_ref)?;
        drop(txn);
        let Some(bound) = bound else {
            return Ok(Some(ReportDeliveryHold::EndpointUnbound));
        };
        if UNSUPPORTED_CHANNELS.contains(&bound.channel.as_str()) {
            return Ok(Some(ReportDeliveryHold::DestinationUnsupported {
                channel: bound.channel,
            }));
        }
        if let Some(send) = &record.send
            && send.destination != bound
        {
            return Ok(Some(ReportDeliveryHold::ChangedBinding {
                bound: send.destination.clone(),
                current: Some(bound),
            }));
        }
        let current = transport.destination();
        if current.as_ref() != Some(&bound) {
            return Ok(Some(ReportDeliveryHold::ChangedBinding { bound, current }));
        }
        let (participation, publisher_dial) = self.signature_switches()?;
        if !(participation && publisher_dial) {
            return Ok(Some(ReportDeliveryHold::Withheld {
                participation,
                publisher_dial,
            }));
        }
        if record.send.is_none() {
            record.send = Some(ReportFrozenSend {
                send_ref: record.key.send_ref(),
                destination: bound,
            });
        }
        Ok(None)
    }

    /// Builds the ED-08 signature through its constructor and freezes its
    /// wire bytes; the lane's write stores it. `Ok(Err(reason))` while
    /// metadata is unresolved.
    fn build_report_signature(
        &self,
        issue: &ReportIssue,
        payload: &ReportRoutedPayload,
    ) -> Result<std::result::Result<BuiltSignature, &'static str>> {
        let metadata = match self.resolve_report_publisher_metadata(issue)? {
            Ok(metadata) => metadata,
            Err(reason) => return Ok(Err(reason)),
        };
        let content_hash = blake3::Hash::from(payload.signature.subject_hash).to_hex();
        let stacks = {
            let txn = self.store.env.read_txn()?;
            self.signature_stacks_in_txn(&txn, &metadata.model_id)?
        };
        let Ok(signature) = IssueSignature::new(
            payload.signature.category,
            metadata.artifact,
            metadata.version,
            &stacks,
            &metadata.model_id,
            &metadata.counts,
            content_hash.as_str(),
        ) else {
            return Ok(Err("signature_refused"));
        };
        let body = wire_body(&signature)?;
        let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
        Ok(Ok(BuiltSignature {
            signature,
            body,
            digest,
        }))
    }

    /// Sends the frozen signature through the ordinary recorded outbound
    /// spine and keeps its receipt and outcome, or its dispatch error.
    fn dispatch_report_signature<T: ReportSignatureTransport + ?Sized>(
        &self,
        record: &mut ReportDeliveryRecord,
        transport: &mut T,
        now: u64,
    ) -> Result<()> {
        let (Some(signature), Some(send)) = (record.signature.clone(), record.send.clone()) else {
            return Err(Error::InvariantViolation("issue signature send not frozen"));
        };
        let request = signature_request(
            connector_actor_id(SENDER)?,
            &record.key,
            &signature,
            &send,
            now,
        );
        let mut sink = SignatureSink {
            transport,
            signature: &signature,
            destination: &send.destination,
        };
        match self.dispatch_outbound_intent_recorded(request, &mut sink) {
            Ok(result) => {
                record.last_error = None;
                record.receipt = Some(result.receipt.receipt_id);
                record.outcome = Some(match result.outcome {
                    OutboundDispatchOutcome::DeliveredToChannel => ReportDeliveryOutcome::Delivered,
                    OutboundDispatchOutcome::Ambiguous => ReportDeliveryOutcome::Uncertain,
                    other => ReportDeliveryOutcome::NotDelivered {
                        dispatch: other.as_str().to_owned(),
                    },
                });
            }
            Err(error) => record.last_error = Some(error.to_string()),
        }
        Ok(())
    }

    /// The publisher ACTOR a delivered lane's comm receipt names (FIX 7829),
    /// read before the lane's write takes its writer. `None` for any other
    /// outcome and for an artifact with no publisher actor, such as the
    /// owner's own pack: that delivery names no counterparty.
    fn delivered_publisher(
        &self,
        record: &ReportDeliveryRecord,
        publisher_ref: &str,
    ) -> Result<Option<PublisherActor>> {
        if !matches!(record.outcome, Some(ReportDeliveryOutcome::Delivered)) {
            return Ok(None);
        }
        let Some(frozen) = &record.signature else {
            return Ok(None);
        };
        match issue_signature(self, frozen.signature).map_err(engine_error)? {
            Some(signature) => self.report_publisher_actor(publisher_ref, signature.artifact()),
            None => Ok(None),
        }
    }
}

/// The ED-08 signature, logical send and outcome a lane's last send writes
/// back (FIX 7690); `None` before a send recorded an outcome.
fn signature_delivery(
    record: &ReportDeliveryRecord,
) -> Option<(EntityId, &str, SignatureDeliveryOutcome)> {
    let (Some(signature), Some(send), Some(outcome)) =
        (&record.signature, &record.send, &record.outcome)
    else {
        return None;
    };
    let outcome = match outcome {
        ReportDeliveryOutcome::Delivered => SignatureDeliveryOutcome::Delivered,
        ReportDeliveryOutcome::Uncertain => SignatureDeliveryOutcome::Uncertain,
        // A deferred send was accepted as a remote task: its delivery is not
        // known yet (FIX 7960), which is not a send that did not leave.
        ReportDeliveryOutcome::NotDelivered { dispatch }
            if dispatch == OutboundDispatchOutcome::Deferred.as_str() =>
        {
            SignatureDeliveryOutcome::Uncertain
        }
        ReportDeliveryOutcome::NotDelivered { .. } => SignatureDeliveryOutcome::NotDelivered,
    };
    Some((signature.signature, send.send_ref.as_str(), outcome))
}

/// The publisher a report's signature goes to: none for a local,
/// duplicate, rejected or denied report, as its routed payload rules.
fn publisher_of(issue: &ReportIssue) -> Option<&str> {
    let ReportRoute::Publisher { publisher_ref } = &issue.route else {
        return None;
    };
    (!matches!(
        issue.review.status,
        ReportStatus::Duplicate | ReportStatus::Rejected
    ) && issue.disclosure != ReportDisclosure::Denied)
        .then_some(publisher_ref.as_str())
}

/// A signature built this run and not stored yet: the write that records
/// its lane stores it (FIX 7689).
struct BuiltSignature {
    signature: IssueSignature,
    body: String,
    digest: String,
}

fn engine_error(error: PublisherError) -> Error {
    match error {
        PublisherError::Engine(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}

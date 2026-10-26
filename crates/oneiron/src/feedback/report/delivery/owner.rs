//! The owner's publisher delivery doors: run the delivery now, read one
//! issue's delivery, and bind or unbind a publisher's endpoint. Each
//! revalidates the owner's proof in the transaction it reads or writes in;
//! none supplies a plan, a lease, a Coach stamp or a send.

use serde::{Deserialize, Serialize};

use super::super::{store, validate_ref};
use super::{
    COACH_FEEDBACK_DELIVERY_FACET, DELIVERIES, ENDPOINTS, ReportDeliveryKey, ReportDeliveryRecord,
    ReportPublisherEndpoint, publisher_of,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::outbound::{OutboundDispatchError, outbound_dispatch_attempt_id};
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
use crate::side_table::SideKey;
use crate::{EntityId, Error, Result, Vault};

/// The owner's run-now ask. It carries no plan, lease or stamp: the
/// production delivery runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRunRequest {}

/// The delivery run a run-now ask queued, or the queued one it joined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRun {
    /// 32 hex: the run's attempt.
    pub attempt: EntityId,
}

/// Which issue's delivery to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryStatusRequest {
    /// 32 hex: the ISSUE.
    pub issue_ref: String,
}

/// One issue's delivery, as the owner reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryStatus {
    /// The ISSUE.
    pub issue_ref: String,
    /// Whether it is routed to a publisher at all: a local, duplicate,
    /// rejected or denied report sends nothing.
    pub routed: bool,
    /// The signature lane: its key, hold, frozen signature and send,
    /// receipt and outcome. `None` until a run reaches it.
    pub delivery: Option<ReportDeliveryRecord>,
    /// The owner's binding for the issue's publisher, if any.
    pub binding: Option<ReportPublisherEndpoint>,
}

/// The owner's change of one publisher's binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportPublisherBindingRequest {
    /// The publisher, as reports are routed to it.
    pub publisher_ref: String,
    /// `true` binds it to this host's feedback destination; `false` unbinds.
    pub bound: bool,
}

/// One publisher's binding after a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportPublisherBinding {
    /// The publisher.
    pub publisher_ref: String,
    /// Where its signatures go; `None` while unbound.
    pub endpoint: Option<ReportPublisherEndpoint>,
}

impl Vault {
    /// Queues the Coach's delivery run on the host queue now, joining one
    /// already queued.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn queue_feedback_report_delivery(
        &self,
        owner: &AuthenticatedOwner,
        _input: ReportDeliveryRunRequest,
    ) -> Result<ReportDeliveryRun> {
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let outcome = DreamerRunnerStore::new(self).enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_FEEDBACK_DELIVERY_FACET.into(),
                    input: rmpv::Value::Nil,
                    parent_attempt: None,
                },
                Some(COACH_FEEDBACK_DELIVERY_FACET.into()),
                None,
                now,
            )?;
            let status = match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status,
            };
            Ok(ReportDeliveryRun {
                attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
            })
        })
    }

    /// One issue's delivery; `None` when the vault holds no such issue.
    ///
    /// # Errors
    ///
    /// A malformed reference, a proof that no longer holds, and storage
    /// errors.
    pub fn report_delivery_status(
        &self,
        owner: &AuthenticatedOwner,
        input: &ReportDeliveryStatusRequest,
    ) -> Result<Option<ReportDeliveryStatus>> {
        let id = EntityId::from_hex(&input.issue_ref)?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let Some(issue) = store::read(self, &txn, &id)? else {
            return Ok(None);
        };
        let (delivery, binding) = match publisher_of(&issue) {
            Some(publisher_ref) => {
                let key = ReportDeliveryKey::signature(&issue.issue_ref, publisher_ref);
                (
                    DELIVERIES.get(&self.store, &txn, &key.row()?)?,
                    ENDPOINTS.get(&self.store, &txn, &key.publisher_ref)?,
                )
            }
            None => (None, None),
        };
        Ok(Some(ReportDeliveryStatus {
            routed: publisher_of(&issue).is_some(),
            issue_ref: issue.issue_ref,
            delivery,
            binding,
        }))
    }

    /// Binds `publisher_ref` to `endpoint`, the host's feedback destination,
    /// or unbinds it with `None`. A lane that froze another destination and
    /// was never offered takes the new binding in the same write (FIX
    /// 7688); one offered once holds as changed and is never redirected.
    ///
    /// # Errors
    ///
    /// An invalid reference or endpoint, a proof that no longer holds, and
    /// storage errors.
    pub fn set_report_publisher_endpoint(
        &self,
        owner: &AuthenticatedOwner,
        publisher_ref: &str,
        endpoint: Option<ReportPublisherEndpoint>,
    ) -> Result<ReportPublisherBinding> {
        validate_ref(publisher_ref)?;
        if endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.channel.is_empty() || endpoint.endpoint.is_empty())
        {
            return Err(Error::InvalidConfig(
                "a publisher binding names a channel and an exact endpoint".into(),
            ));
        }
        let key = publisher_ref.to_owned();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            match &endpoint {
                Some(endpoint) => {
                    ENDPOINTS.put(&self.store, txn, &key, endpoint)?;
                    refreeze_unsent_in_txn(self, txn, &key, endpoint)?;
                }
                None => {
                    ENDPOINTS.delete(&self.store, txn, &key)?;
                }
            }
            Ok(())
        })?;
        Ok(ReportPublisherBinding {
            publisher_ref: key,
            endpoint,
        })
    }
}

/// Re-freezes to `endpoint` each lane of `publisher_ref` that froze another
/// destination and never entered dispatch: no receipt, no outcome, and no
/// intent under its send in the outbound ledger (FIX 7688). Its hold clears,
/// and the next run reads it again. A lane that entered dispatch keeps its
/// destination, even when a crash kept its receipt from its row.
fn refreeze_unsent_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    publisher_ref: &str,
    endpoint: &ReportPublisherEndpoint,
) -> Result<()> {
    let now = vault.now_recorded_at();
    let mut moved = Vec::new();
    for row in DELIVERIES.iter_raw_from(&vault.store, &*txn, &[])? {
        let (key, value) = row?;
        // A row that does not decode is no lane to move; the bind stands.
        let (Some(row), Ok(mut record)) = (
            <(EntityId, [u8; 32]) as SideKey>::decode_key(&key),
            DELIVERIES.decode_value(&value),
        ) else {
            continue;
        };
        if record.key.publisher_ref != publisher_ref
            || record.receipt.is_some()
            || record.outcome.is_some()
        {
            continue;
        }
        let Some(send) = record.send.as_mut() else {
            continue;
        };
        if send.destination == *endpoint || entered_dispatch_in_txn(vault, txn, &send.send_ref)? {
            continue;
        }
        send.destination = endpoint.clone();
        record.hold = None;
        record.updated_at = now;
        moved.push((row, record));
    }
    for (row, record) in moved {
        DELIVERIES.put(&vault.store, txn, &row, &record)?;
    }
    Ok(())
}

/// Whether the outbound ledger holds an intent under `send_ref`: the send
/// entered dispatch, and may have left, whatever its lane recorded after.
fn entered_dispatch_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, send_ref: &str) -> Result<bool> {
    let attempt = outbound_dispatch_attempt_id(send_ref).map_err(|error| match error {
        OutboundDispatchError::Engine(error) => error,
        _ => Error::InvariantViolation("outbound dispatch attempt id"),
    })?;
    let intent =
        read_intent_for_attempt_in_txn(vault, txn, attempt, 0).map_err(|error| match error {
            IntentLedgerError::Engine(error) => error,
            _ => Error::CorruptedIndex("outbound intent ledger row"),
        })?;
    Ok(intent.is_some())
}

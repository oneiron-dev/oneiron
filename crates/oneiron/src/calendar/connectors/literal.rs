//! Exact row-owned calendar preconditions, retained independently of the readable projection.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::door::CalendarConnectorOperation;
use super::remote::RemoteWriteReceipt;
use crate::secret_custody::{
    open_connector_resume_in_txn, read_back_connector_resume_for_activation,
    retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::store::{CustodyBinding, CustodyForkRequirement as Requirement, CustodyPlan, Store};
use crate::vault::Vault;
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

#[doc(hidden)]
use oneiron_records::calendar::connectors::literal::{CODEC, GENERATION, reference};
#[doc(hidden)]
pub(super) use oneiron_records::calendar::connectors::literal::{LiteralKind, encode, invalid};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LiteralCarrier {
    pub(super) instance: [u8; 16],
    pub(super) seat: [u8; 32],
    boxed: Vec<u16>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LiteralValues {
    pub(super) href: Option<String>,
    pub(super) etag: Option<String>,
    pub(super) receipt: Option<RemoteWriteReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    codec: u8,
    kind: LiteralKind,
    instance: [u8; 16],
    reference: [u8; 16],
    key: [u8; 32],
    seat: [u8; 32],
    row: [u8; 32],
    uid: String,
    values: LiteralValues,
}

/// The digest of `value`'s literal encoding. A seat's literal scope and an outbox
/// row's or a remote cursor's digest are sealed in the custody envelope, and opening
/// it refuses one whose digests differ from the row's now, so each keeps its bytes
/// (K, PLAN-UC-04 stage 6.1).
pub(super) fn digest<T: Serialize>(value: &T) -> crate::Result<[u8; 32]> {
    Ok(LegacyDigest::new(purposes::calendar::CONNECTOR_LITERAL)
        .raw(&encode(value)?)
        .finish())
}

/// The digest of `value`'s literal encoding.
#[cfg(oneiron_test_support)]
pub(crate) fn literal_digest_for_test<T: Serialize>(value: &T) -> crate::Result<[u8; 32]> {
    digest(value)
}

impl LiteralCarrier {
    pub(super) fn seal(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        operation: &CalendarConnectorOperation,
        kind: LiteralKind,
        instance: [u8; 16],
        key: [u8; 32],
        row: [u8; 32],
        uid: &str,
        values: LiteralValues,
    ) -> crate::Result<Self> {
        let reference = reference(kind, &instance);
        let seat = operation.literal_scope()?;
        let payload = Zeroizing::new(encode(&Envelope {
            codec: CODEC,
            kind,
            instance,
            reference: *reference.as_bytes(),
            key,
            seat,
            row,
            uid: uid.into(),
            values,
        })?);
        let ciphertext =
            seal_connector_resume_in_txn(&vault.store, txn, &reference, GENERATION, &payload)?;
        // These words encode AEAD ciphertext, never clear provider text.
        let boxed = ciphertext
            .into_iter()
            .map(|byte| 256 + u16::from(byte))
            .collect();
        Ok(Self {
            instance,
            seat,
            boxed,
        })
    }

    pub(super) fn open(
        &self,
        vault: &Vault,
        operation: &CalendarConnectorOperation,
        kind: LiteralKind,
        key: [u8; 32],
        row: [u8; 32],
    ) -> crate::Result<(String, LiteralValues)> {
        operation.revalidate(vault)?;
        if self.seat != operation.literal_scope()? {
            return Err(invalid());
        }
        let ciphertext = self.ciphertext()?;
        let reference = reference(kind, &self.instance);
        let payload = {
            let snapshot = vault.store.custody_snapshot()?;
            operation.revalidate_in_txn(vault, &snapshot)?;
            open_connector_resume_in_txn(
                &vault.store,
                &snapshot,
                &reference,
                GENERATION,
                &ciphertext,
            )?
        };
        let envelope = self.envelope(&payload, kind, key, row)?;
        Ok((envelope.uid, envelope.values))
    }

    fn ciphertext(&self) -> crate::Result<Vec<u8>> {
        self.boxed
            .iter()
            .map(|word| {
                word.checked_sub(256)
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(invalid)
            })
            .collect()
    }

    fn envelope(
        &self,
        payload: &[u8],
        kind: LiteralKind,
        key: [u8; 32],
        row: [u8; 32],
    ) -> crate::Result<Envelope> {
        let reference = reference(kind, &self.instance);
        let envelope: Envelope = serde_json::from_slice(payload).map_err(|_| invalid())?;
        if envelope.codec != CODEC
            || envelope.kind != kind
            || envelope.instance != self.instance
            || envelope.reference != *reference.as_bytes()
            || envelope.key != key
            || envelope.row != row
            || envelope.seat != self.seat
        {
            return Err(invalid());
        }
        Ok(envelope)
    }

    pub(super) fn plan(
        &self,
        plan: &mut CustodyPlan,
        kind: LiteralKind,
    ) -> crate::Result<Option<Requirement>> {
        Store::plan_connector_resume(plan, &reference(kind, &self.instance), GENERATION)
    }

    pub(super) fn read_back(
        &self,
        binding: &CustodyBinding,
        kind: LiteralKind,
        key: [u8; 32],
        row: [u8; 32],
    ) -> crate::Result<()> {
        read_back_connector_resume_for_activation(
            binding,
            &reference(kind, &self.instance),
            GENERATION,
            &self.ciphertext()?,
            |payload| self.envelope(payload, kind, key, row).map(|_| ()),
        )
    }

    pub(super) fn retire(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        kind: LiteralKind,
    ) -> crate::Result<()> {
        retire_connector_resume_in_txn(&vault.store, txn, &reference(kind, &self.instance))
    }
}

pub(super) fn projection<T: Clone + Serialize>(value: &Option<T>) -> crate::Result<Option<T>> {
    let encoded = Zeroizing::new(encode(value)?);
    Ok(
        (!crate::batch::secret_scan::payload_carries_secret(&encoded))
            .then(|| value.clone())
            .flatten(),
    )
}

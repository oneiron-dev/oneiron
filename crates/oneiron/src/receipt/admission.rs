//! Durable admission observations of named typed calls (ARCH-0044 C5).
//!
//! An intent is the existing wire invocation id, not a second way to execute
//! a verb. Only the transport holds a tracker; callers can read their own
//! receipts but cannot manufacture a permit or settle one.
use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding_in_txn};
use crate::runtime_hooks::InvocationId;
use crate::side_table::{self, Named, SideTable};
use crate::work_line::LineObserver;
use crate::{EdgeActorClass, EntityId, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStatusRequest {
    /// The call's x-oneiron-invocation, 32 hex digits.
    pub intent_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceiptsRequest {
    /// The exact set of authored invocation ids to reconcile, in reply order.
    pub intent_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmissionStatus {
    /// Waiting for the existing fair line's permit, not for a health verdict.
    Queued,
    /// Running, or held by the verb's own typed ask. A health check never holds it.
    Held {
        reason: Option<String>,
    },
    Completed {
        result_digest: String,
    },
    Refused {
        code: String,
        reason: String,
    },
    /// The host stopped without observing settlement. Effects may have landed;
    /// this is not permission to replay the intent.
    Interrupted {
        reason: String,
    },
}

impl AdmissionStatus {
    fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Refused { .. } | Self::Interrupted { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub receipt_ref: String,
    pub intent_key: String,
    pub verb: String,
    pub request_digest: String,
    pub accepted_at: u64,
    pub updated_at: u64,
    pub state: AdmissionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAdmission {
    receipt: AdmissionReceipt,
    fingerprint: String,
    active: bool,
}

const ADMISSIONS: SideTable<[u8; 32], StoredAdmission, Named> =
    SideTable::new(&side_table::ADMISSION_INTENT);

fn intent(text: &str) -> MemoryResult<InvocationId> {
    InvocationId::parse_hex(text)
        .ok_or_else(|| MemoryError::bad_request("intent_key must be a 32-hex invocation id"))
}

fn key(actor: EntityId, class: EdgeActorClass, intent: InvocationId) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("oneiron admission intent v1");
    hash.update(actor.as_bytes());
    hash.update(class.gate_actor_class().as_bytes());
    hash.update(&intent.0);
    *hash.finalize().as_bytes()
}

/// A host's observation capability for one call. It conveys no write or
/// execution authority: the original typed door still admits every effect.
#[derive(Clone)]
pub struct AdmissionTracker {
    vault: Arc<Vault>,
    key: [u8; 32],
}

impl AdmissionTracker {
    /// Keeps the intent before the host starts its typed call. Actor binding,
    /// retry identity and the active/terminal fence are checked in the same
    /// write transaction as the receipt. Only an answered hook ask may resume.
    pub fn start(
        vault: Arc<Vault>,
        actor: EntityId,
        class: EdgeActorClass,
        invocation: InvocationId,
        verb: &str,
        request_digest: String,
        fingerprint: String,
    ) -> MemoryResult<Self> {
        let key = key(actor, class, invocation);
        vault.try_with_write_txn_grouped(|txn| -> MemoryResult<()> {
            verify_actor_binding_in_txn(&vault, txn, actor, class)?;
            if let Some(mut stored) = ADMISSIONS.get(&vault.store, txn, &key)? {
                if stored.fingerprint != fingerprint {
                    return Err(MemoryError::new(
                        crate::memory::MEMORY_CODE_INVALID_STATE,
                        "admission intent names a different call",
                        &[],
                    ));
                }
                if stored.active || stored.receipt.state.terminal() {
                    return Err(MemoryError::new(
                        crate::memory::MEMORY_CODE_INVALID_STATE,
                        "admission intent is already running or settled; read its status",
                        &[],
                    ));
                }
                stored.active = true;
                stored.receipt.state = AdmissionStatus::Held { reason: None };
                stored.receipt.updated_at = vault.store.clock.now_recorded_at();
                ADMISSIONS.put(vault.as_ref(), txn, &key, &stored)?;
                return Ok(());
            }
            let at = vault.store.clock.now_recorded_at();
            let receipt = AdmissionReceipt {
                receipt_ref: format!("admission:{}", crate::entity_id::bytes_to_hex_lower(&key)),
                intent_key: invocation.to_hex(),
                verb: verb.to_owned(),
                request_digest,
                accepted_at: at,
                updated_at: at,
                state: AdmissionStatus::Held { reason: None },
            };
            ADMISSIONS.put(
                vault.as_ref(),
                txn,
                &key,
                &StoredAdmission {
                    receipt,
                    fingerprint,
                    active: true,
                },
            )?;
            Ok(())
        })?;
        Ok(Self { vault, key })
    }

    fn update(&self, state: AdmissionStatus, active: bool) -> crate::Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            let Some(mut stored) = ADMISSIONS.get(&self.vault.store, txn, &self.key)? else {
                return Err(crate::Error::CorruptedIndex("admission intent missing"));
            };
            if stored.receipt.state.terminal() {
                return Ok(());
            }
            stored.receipt.state = state.clone();
            stored.receipt.updated_at = self.vault.store.clock.now_recorded_at();
            stored.active = active;
            ADMISSIONS.put(self.vault.as_ref(), txn, &self.key, &stored)
        })
    }

    /// Settles once after the original typed door answers; a pending ask
    /// remains held and can resume under its original invocation.
    pub fn finish(&self, result: Result<&serde_json::Value, (&str, &str)>) -> MemoryResult<()> {
        let state = match result {
            Ok(value) => AdmissionStatus::Completed {
                result_digest: super::call_json_digest(value),
            },
            Err((crate::memory::MEMORY_CODE_PENDING_ASK, reason)) => AdmissionStatus::Held {
                reason: Some(reason.to_owned()),
            },
            Err((code, reason)) => AdmissionStatus::Refused {
                code: code.to_owned(),
                reason: reason.to_owned(),
            },
        };
        self.update(state, false).map_err(MemoryError::from)
    }

    pub fn interrupt(&self) -> crate::Result<()> {
        self.update(AdmissionStatus::Interrupted {
            reason: "call stopped before settlement was observed; inspect effects before a new intent".to_owned(),
        }, false)
    }
}

impl LineObserver for AdmissionTracker {
    fn queued(&self) {
        if let Err(error) = self.update(AdmissionStatus::Queued, true) {
            tracing::error!(%error, "admission queued receipt failed");
        }
    }

    fn held(&self) {
        if let Err(error) = self.update(AdmissionStatus::Held { reason: None }, true) {
            tracing::error!(%error, "admission held receipt failed");
        }
    }
}

impl Vault {
    /// A new serving host cannot inherit in-memory permits. Keep a visible
    /// unknown-outcome receipt for unfinished work, never silently replay it.
    /// Held hook continuations have their own durable resume path and stay.
    pub fn recover_admission_intents(&self) -> crate::Result<()> {
        self.with_write_txn_grouped(|txn| {
            for (key, mut stored) in ADMISSIONS.scan(&self.store, txn)? {
                if stored.active && !stored.receipt.state.terminal() {
                    stored.active = false;
                    stored.receipt.updated_at = self.store.clock.now_recorded_at();
                    stored.receipt.state = AdmissionStatus::Interrupted {
                        reason: "host restarted before settlement was observed; inspect effects before a new intent".to_owned(),
                    };
                    ADMISSIONS.put(self, txn, &key, &stored)?;
                }
            }
            Ok(())
        })
    }
}

impl Memory<'_> {
    /// Reads only this caller's intent, using the same actor-binding check
    /// as call receipts. An unknown or other actor's key returns None.
    pub fn admission_status(
        &self,
        request: &AdmissionStatusRequest,
    ) -> MemoryResult<Option<AdmissionReceipt>> {
        let invocation = intent(&request.intent_key)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        Ok(ADMISSIONS
            .get(
                &vault.store,
                &txn,
                &key(self.actor(), self.actor_class(), invocation),
            )?
            .map(|stored| stored.receipt))
    }

    /// Reconciles an exact authored set in one read snapshot. Each accepted
    /// intent appears once; absent keys are not invented as successes.
    pub fn admission_receipts(
        &self,
        request: &AdmissionReceiptsRequest,
    ) -> MemoryResult<Vec<AdmissionReceipt>> {
        crate::memory::caps::check_limit(request.intent_keys.len())?;
        let invocations = request
            .intent_keys
            .iter()
            .map(|text| intent(text))
            .collect::<MemoryResult<Vec<_>>>()?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let mut seen = BTreeSet::new();
        let mut receipts = Vec::new();
        for invocation in invocations {
            if seen.insert(invocation)
                && let Some(stored) = ADMISSIONS.get(
                    &vault.store,
                    &txn,
                    &key(self.actor(), self.actor_class(), invocation),
                )?
            {
                receipts.push(stored.receipt);
            }
        }
        Ok(receipts)
    }
}

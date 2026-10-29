//! A vault's untouched seeded policy manifest taking the one this build
//! ships, and the re-gate of every consent that waited on the old one.
//!
//! The seeded marker holds only while no local write re-authored the default
//! manifest, so an owner's own policy is never touched. A new manifest moves
//! the policy frontier, and every pending consent bound to the old frontier
//! would refuse its grant or approval as stale. The re-gate takes each one's
//! verdict again under the new policy and parks it there: re-bound when the
//! verdict is the one it waited under, re-staged as a new pending decision
//! when it changed. Nothing is applied; the grant or the owner's approval
//! still decides, with a fresh verdict. A row whose claim does not read, or
//! whose fresh verdict denies the claim, stays stale on the old frontier.
use super::confirm::{
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED,
};
use crate::batch::{
    BatchOp, ClaimMaterialization, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
};
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::PendingGateConsentRecord;
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// What a re-gate did to the consents bound to the old frontier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ConsentRegate {
    /// Re-parked under the verdict they waited under.
    pub(crate) rebound: usize,
    /// Re-parked under a fresh verdict that differs.
    pub(crate) restaged: usize,
    /// Left on the old frontier: the claim did not read, or the fresh
    /// verdict denies it.
    pub(crate) stale: usize,
}

/// A read the re-gate cannot judge is `None`; a storage failure is not.
pub(crate) fn readable<T>(read: Result<Option<T>>) -> Result<Option<T>> {
    match read {
        Ok(value) => Ok(value),
        Err(error) if fatal(&error) => Err(error),
        Err(_) => Ok(None),
    }
}

fn fatal(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull
    )
}

/// Re-gates every pending consent bound to `old_frontier` under the policy
/// now in force in `txn`.
pub(crate) fn regate_pending_consents_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    old_frontier: &[u8; 32],
    now: u64,
) -> Result<ConsentRegate> {
    let mut regate = ConsentRegate::default();
    for pending in vault.store.pending_gate_consents_in_txn(txn, usize::MAX)? {
        if pending.read_frontier_hash != *old_frontier {
            continue;
        }
        let id = EntityId::from_bytes(pending.claim_id)?;
        let verdict = if vault.has_deferred_claim_in_txn(txn, &id)? {
            vault.restage_deferred_claim_in_txn(txn, &pending, now)?
        } else {
            restage_claim(vault, txn, &id, &pending, now)?
        };
        match verdict {
            Some(true) => regate.rebound += 1,
            Some(false) => regate.restaged += 1,
            None => regate.stale += 1,
        }
    }
    Ok(regate)
}

/// The claim door's verdict on a waiting claim, taken again and recorded as
/// a fresh decision, and its consent bound to it. A verdict that would now
/// land the claim keeps it waiting under the reasons it had; one that denies
/// it leaves the row stale, so no ceremony is ever bound to a denial.
fn restage_claim(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    pending: &PendingGateConsentRecord,
    now: u64,
) -> Result<Option<bool>> {
    let Some(body) = readable(vault.get_claim_in_txn(txn, id))? else {
        return Ok(None);
    };
    // A claim written through the raw door, or last changed by an unbound
    // status write, has no authored envelope: the door judges it as that
    // local write, as it did when the write was made.
    let Some(envelope) =
        readable(ClaimMaterialization::authored_envelope(vault, txn, id, &body).map(Some))?
    else {
        return Ok(None);
    };
    let policy = super::resolve_policy_manifest(&vault.store, txn)?;
    let mut recorded = None;
    let verdict = super::check_claim_policy_for_write_with_record(
        &vault.store,
        txn,
        id,
        super::ClaimGateWrite {
            body: &body,
            envelope: envelope.as_ref(),
            auto_checker: None,
            defer_metrics_until_commit: true,
            transition: None,
            owner_authored: None,
        },
        &policy,
        super::GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: false,
            include_source_in_gate_input: false,
        },
        &mut recorded,
    );
    match verdict {
        Ok(()) | Err(Error::Gate(_)) => {}
        Err(error) if fatal(&error) => return Err(error),
        Err(_) => return Ok(None),
    }
    let Some(fresh) = recorded.map(super::RecordedClaimGateDecision::into_record) else {
        return Ok(None);
    };
    if fresh.outcome == "deny" {
        return Ok(None);
    }
    let attached = fresh
        .receipt_reasons
        .iter()
        .any(|reason| reason == GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED);
    let reasons = if attached {
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    } else if fresh.outcome == "pending" {
        fresh.reason_codes.clone()
    } else {
        pending.reason_codes.clone()
    };
    let parked_under = vault.store.gate_decision_in_txn(txn, pending.decision_id)?;
    let same = (attached || fresh.outcome == "pending")
        && parked_under.is_some_and(|parked| parked.outcome == fresh.outcome)
        && reasons == pending.reason_codes;
    vault.store.put_pending_gate_consent_in_txn(
        txn,
        &PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: pending.claim_id,
            decision_id: fresh.decision_id,
            // A re-staged row is a new pending decision, so a ceremony it
            // newly needs gets its whole window.
            created_at: if same { pending.created_at } else { now },
            diff_handle: fresh.diff_handle,
            read_frontier_hash: fresh.read_frontier_hash,
            reason_codes: reasons,
            dreamer_run_id: pending.dreamer_run_id.clone(),
            predicate: Some(body.predicate.clone()),
        },
    )?;
    Ok(Some(same))
}

/// Installs `body` as the vault's seeded default at `id` through the
/// manifest write every install takes, and keeps it marked seeded so the
/// next shipped change can replace it too.
fn install_seeded_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    body: Vec<u8>,
) -> Result<()> {
    let hash = blake3::hash(&body);
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_POLICY_MANIFEST,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    super::manifest_authenticity::mark_seeded(&vault.store, txn, &id, hash.as_bytes())
}

/// The default manifest's id, header and body when it is still the seeded
/// one, untouched since the seed.
fn untouched_seeded(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<(EntityId, EntityMetadataHeader, Vec<u8>)>> {
    let id = super::default_policy_manifest_id()?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("policy manifest header"))?;
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST
        || !super::manifest_authenticity::manifest_is_seeded_default(&vault.store, txn, &id, &body)?
    {
        return Ok(None);
    }
    Ok(Some((id, header, body)))
}

impl Vault {
    /// Replaces an untouched seeded default whose bytes differ from the
    /// shipped manifest, and re-gates every consent that waited on it, in
    /// one transaction. `None` when there is nothing to upgrade.
    pub(crate) fn upgrade_seeded_policy_manifest(&self) -> Result<Option<ConsentRegate>> {
        let shipped = super::default_policy_manifest()?;
        self.with_write_txn_grouped(|txn| {
            let Some((id, header, body)) = untouched_seeded(self, txn)? else {
                return Ok(None);
            };
            if body == shipped {
                return Ok(None);
            }
            let old_frontier =
                super::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
            install_seeded_in_txn(self, txn, id, &header, shipped.clone())?;
            let policy = super::resolve_policy_manifest(&self.store, txn)?;
            if policy.is_fail_closed() || policy.diagnostics().loaded_manifest_forces_fail_closed()
            {
                return Err(Error::InvariantViolation(
                    "the shipped policy manifest does not resolve open",
                ));
            }
            let now = self.store.clock.now_recorded_at();
            regate_pending_consents_in_txn(self, txn, &old_frontier, now).map(Some)
        })
    }

    /// Puts `body` in place of the seeded default as an earlier build would
    /// have seeded it, marked seeded and untouched.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_seeded_policy_manifest_for_test(&self, body: Vec<u8>) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let id = super::default_policy_manifest_id()?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            install_seeded_in_txn(self, txn, id, &header, body)
        })
    }

    /// The shipped manifest as builds before canon's critical classes were
    /// seeded shipped it: without the `health.`, `safety.`, `legal.`,
    /// `boundary.` and `decision.settled` rules.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn policy_manifest_before_critical_classes_for_test() -> Result<Vec<u8>> {
        use rmpv::Value;
        let shipped = super::default_policy_manifest()?;
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut shipped.as_slice())
            .map_err(|_| Error::InvariantViolation("decode default policy manifest"))?
        else {
            return Err(Error::InvariantViolation(
                "default policy manifest is not a map",
            ));
        };
        for (key, value) in &mut entries {
            if key.as_str() == Some(super::constants::POLICY_RULES_KEY)
                && let Value::Array(rules) = value
            {
                rules.retain(|rule| {
                    let prefix = match rule {
                        Value::Map(fields) => fields
                            .iter()
                            .find(|(name, _)| {
                                name.as_str() == Some(super::constants::RULE_PREFIX_KEY)
                            })
                            .and_then(|(_, prefix)| prefix.as_str()),
                        _ => None,
                    };
                    !matches!(
                        prefix,
                        Some("health." | "safety." | "legal." | "boundary." | "decision.settled")
                    )
                });
            }
        }
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &Value::Map(entries))
            .map_err(|_| Error::InvariantViolation("encode default policy manifest"))?;
        Ok(data)
    }
}

//! Opt-in gate-decision age sweep over the actual ORCB custody unit.
//!
//! ONE-1640 uses one exterior key per claim, not a shared time-bucket key.
//! A claim ID is therefore the indivisible encrypted partition. An unlinked
//! decision has no exterior key and belongs to the separate unlinked partition.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;

use super::orcb;
use super::types::GateDecisionRecord;

/// One exterior-key partition: the claim-free partition, or one claim's. Spelled `0`, or `1`
/// then the claim id, after its table's prefix.
struct Partition(Option<[u8; 16]>);

impl SideKey for Partition {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self.0 {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id);
            }
            None => out.push(0),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (&0, []) => Some(Self(None)),
            (&1, id) => Some(Self(Some(id.try_into().ok()?))),
            _ => None,
        }
    }
}

/// A legal hold; the value is the single byte 1.
const HOLD: SideTable<Partition, [u8; 1], Raw> =
    SideTable::new(&side_table::GATE_DECISION_PARTITION_HOLD);
/// The latest retain-until stamp of a held partition.
const RETAIN_UNTIL: SideTable<Partition, u64, Raw> =
    SideTable::new(&side_table::GATE_DECISION_PARTITION_RETAIN_UNTIL);
/// A committed key-retirement intent: the claim partition's key generation.
pub(super) const RETIRE_PENDING: SideTable<[u8; 16], u64, Raw> =
    SideTable::new(&side_table::GATE_DECISION_PARTITION_RETIRE_PENDING);

impl Store {
    pub(crate) fn gate_partition_held_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: Option<&[u8; 16]>,
    ) -> Result<bool> {
        match HOLD.get(self, txn, &Partition(claim.copied()))? {
            None => Ok(false),
            Some([1]) => Ok(true),
            Some(_) => Err(Error::CorruptedIndex("gate decision partition hold")),
        }
    }

    pub(in crate::store) fn gate_partition_retire_pending_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: &[u8; 16],
    ) -> Result<Option<u64>> {
        RETIRE_PENDING.get(self, txn, claim)
    }

    pub(crate) fn reject_held_gate_partition_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: &[u8; 16],
    ) -> Result<()> {
        if self.gate_partition_held_in_txn(txn, Some(claim))? {
            return Err(Error::InvalidConfig(
                "gate decision partition is under legal hold".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_RETIRE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(in crate::store) fn arm_before_retire_lock(callback: impl FnOnce() + 'static) {
    BEFORE_RETIRE_LOCK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

impl Vault {
    /// Owner-authored retention horizon, kept in the trusted POLICY_MANIFEST
    /// instead of an alternate vault_meta scalar. `None` explicitly disables
    /// age pruning. The shipped manifest defaults to `None`.
    pub fn set_gate_decision_retention_secs(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        seconds: Option<u64>,
    ) -> Result<()> {
        if seconds == Some(0) {
            return Err(Error::InvalidConfig(
                "gate decision retention must be positive".into(),
            ));
        }
        self.update_gate_decision_retention_manifest(owner, Some(seconds), None)
    }

    /// Owner-authored maximum number of decisions removed by one sweep pass.
    pub fn set_gate_decision_sweep_budget(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        rows: usize,
    ) -> Result<()> {
        if rows == 0 {
            return Err(Error::InvalidConfig(
                "gate decision sweep budget must be positive".into(),
            ));
        }
        self.update_gate_decision_retention_manifest(owner, None, Some(rows))
    }

    fn update_gate_decision_retention_manifest(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        horizon: Option<Option<u64>>,
        budget: Option<usize>,
    ) -> Result<()> {
        use crate::batch::ENTITY_METADATA_HEADER_LEN;
        let mut txn = self.store.env.write_txn()?;
        // Read the effective trusted row in the SAME transaction that writes
        // the owner replacement; no policy override gets lost between reads.
        let (current, id) = crate::gate::retention_edit_target(&self.store, &txn)?;
        let raw = self
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("default policy manifest"))?;
        let manifest_body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("retention policy manifest"))?;
        // A narrow edit MUST NOT authenticate any unrelated peer-authored
        // permissions carried at this ID. Prove the exact amended body is
        // trusted and not quarantined under this same LMDB writer snapshot.
        if !crate::gate::manifest_authenticity::manifest_is_trusted(
            &self.store,
            &txn,
            &id,
            manifest_body,
        )? || crate::gate::manifest_authenticity::manifest_is_quarantined(
            &self.store,
            &txn,
            &id,
            manifest_body,
        )? {
            return Err(Error::InvalidConfig(
                "retention edit target is not trusted".into(),
            ));
        }
        let mut body: rmpv::Value = rmpv::decode::read_value(&mut &manifest_body[..])
            .map_err(|_| Error::CorruptedIndex("default policy manifest"))?;
        let rmpv::Value::Map(ref mut fields) = body else {
            return Err(Error::CorruptedIndex("default policy manifest"));
        };
        let (_, retention) = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("gate_decision_retention"))
            .ok_or(Error::CorruptedIndex("retention manifest row"))?;
        let rmpv::Value::Map(rows) = retention else {
            return Err(Error::CorruptedIndex("retention manifest row"));
        };
        if let Some(horizon) = horizon {
            let (_, value) = rows
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("horizon_secs"))
                .ok_or(Error::CorruptedIndex("retention horizon row"))?;
            *value = horizon.map_or(rmpv::Value::Nil, rmpv::Value::from);
        }
        if let Some(budget) = budget {
            let (_, value) = rows
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("max_sweep_rows"))
                .ok_or(Error::CorruptedIndex("retention budget row"))?;
            *value = rmpv::Value::from(u64::try_from(budget).map_err(|_| {
                Error::InvalidConfig("gate decision sweep budget too large".into())
            })?);
        }
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &body)
            .map_err(|_| Error::InvariantViolation("gate decision retention manifest encode"))?;
        let now = self.store.clock.now_recorded_at();
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        let expected = crate::gate::GateDecisionRetentionPolicy {
            horizon_secs: horizon.unwrap_or(current.horizon_secs),
            max_sweep_rows: budget.unwrap_or(current.max_sweep_rows),
            ..current
        };
        if crate::gate::resolve_gate_decision_retention(&self.store, &txn)? != Some(expected) {
            return Err(Error::InvalidConfig(
                "retention edit changed manifest precedence".into(),
            ));
        }
        txn.commit()?;
        Ok(())
    }

    /// Effective trusted-policy horizon. No horizon means NO age pruning.
    pub fn gate_decision_retention_secs(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            crate::gate::resolve_gate_decision_retention(&self.store, &txn)?
                .and_then(|policy| policy.horizon_secs),
        )
    }

    /// Hold the entire exterior-key partition, not an individual decision.
    /// `None` names the plaintext, claim-free partition. A hold must be
    /// released explicitly; the age sweep never clears it.
    pub fn set_gate_decision_partition_hold(
        &self,
        claim_partition: Option<[u8; 16]>,
        held: bool,
    ) -> Result<()> {
        let partition = Partition(claim_partition);
        self.with_write_txn(|txn| {
            if held {
                if let Some(claim) = claim_partition.as_ref()
                    && let Some(generation) = self
                        .store
                        .gate_partition_retire_pending_in_txn(txn, claim)?
                    && orcb::generation_retired(
                        &self.store.core.gate_custody_root,
                        claim,
                        generation,
                    )?
                {
                    return Err(Error::InvalidConfig(
                        "gate decision partition key already retired".into(),
                    ));
                }
                HOLD.put(&self.store, txn, &partition, &[1])?;
            } else {
                HOLD.delete(&self.store, txn, &partition)?;
            }
            Ok(())
        })
    }

    /// The most recent retain-until stamp for a held partition, if present.
    pub fn gate_decision_partition_retain_until(
        &self,
        claim_partition: Option<[u8; 16]>,
    ) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        RETAIN_UNTIL.get(&self.store, &txn, &Partition(claim_partition))
    }

    /// Complete durable key retirements staged by an erase or a sweep,
    /// including ones an interrupted process left behind. An intent names the
    /// newest generation to destroy; every older live generation goes with
    /// it. Never deletes a live row: the intent is committed with the
    /// redaction or removal of every row those generations decrypt.
    pub(crate) fn finish_gate_decision_retirements(&self) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let pending = RETIRE_PENDING.scan(&self.store, &txn)?;
        drop(txn);
        for (claim, _) in pending {
            #[cfg(test)]
            BEFORE_RETIRE_LOCK.with(|slot| {
                if let Some(callback) = slot.borrow_mut().take() {
                    callback();
                }
            });
            // Wait for ALL live reader snapshots before touching exterior
            // custody, then take the LMDB writer for hold/intent ordering.
            // The lock comes FIRST: never wait on readers while holding the
            // LMDB writer slot they may need to finish a read.
            let _custody =
                self.store.core.gate_retirement_lock.write().map_err(|_| {
                    Error::InvariantViolation("gate decision custody lock poisoned")
                })?;
            let mut txn = self.store.env.write_txn()?;
            // Re-read under the writer: another finisher may have consumed
            // the intent, or a later erase may have raised it.
            let Some(through) = self
                .store
                .gate_partition_retire_pending_in_txn(&txn, &claim)?
            else {
                continue;
            };
            if self.store.gate_partition_held_in_txn(&txn, Some(&claim))? {
                continue;
            }
            // Only ciphertext under a retiring generation needs its key.
            // Erased rows stay as plaintext skeletons that keep the claim id.
            for row in super::ledger::LEDGER.iter_raw_from(&self.store, &txn, &[])? {
                let (_, raw) = row?;
                if orcb::raw_claim_generation(&raw)
                    .is_some_and(|(owner, generation)| owner == claim && generation <= through)
                {
                    return Err(Error::CorruptedIndex(
                        "retiring gate decision partition has live rows",
                    ));
                }
            }
            let root = &self.store.core.gate_custody_root;
            for generation in orcb::key_generation(root, &claim)?..=through {
                orcb::retire_claim_key(root, &claim, generation)?;
            }
            RETIRE_PENDING.delete(&self.store, &mut txn, &claim)?;
            txn.commit()?;
        }
        Ok(())
    }

    /// Post-commit door for an act that staged a key retirement. The intent
    /// is durable, so a failure here is retried by the next retention pass
    /// and never reported as a failure of the act that already committed.
    pub(crate) fn finish_gate_decision_retirements_after_commit(&self) {
        if let Err(error) = self.finish_gate_decision_retirements() {
            tracing::warn!(
                error = %error,
                "gate decision key retirement deferred to the next retention pass"
            );
        }
    }

    /// One owner maintenance pass over gate-decision retention, for a host
    /// to run on a schedule: finish every staged key retirement, then age
    /// out rows past the owner's horizon until a pass removes nothing. A
    /// vault with no retention manifest or no horizon prunes nothing.
    /// Returns the number of decision rows removed.
    pub fn maintain_gate_decision_retention(&self) -> Result<u64> {
        self.finish_gate_decision_retirements()?;
        if self.gate_decision_retention_secs()?.is_none() {
            return Ok(0);
        }
        let mut removed = 0_u64;
        loop {
            let pass = self.sweep_gate_decision_retention()?;
            if pass == 0 {
                return Ok(removed);
            }
            removed = removed.saturating_add(pass);
        }
    }

    /// Live state that re-reads a claim-bound receipt as its current
    /// authority. A missing proof is a refusal, so pruning it would revoke
    /// the authority; keep it while the referencing state exists.
    fn live_claim_proof_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<bool> {
        Ok(
            crate::memory::skill_author_proof_is_live_in_txn(self, txn, record)?
                || crate::dreamer_runner::maintenance::representation::representation_approval_is_live_in_txn(
                    self, txn, record,
                )?,
        )
    }

    /// Remove decisions strictly older than the owner-selected horizon.
    /// Sidecars and primaries leave together. A key is destroyed only when
    /// *every* decision it decrypts is gone; a held partition is untouched.
    /// Removes at most the manifest's `max_sweep_rows` per call; repeat until zero.
    /// Returns the number of decision rows removed.
    pub fn sweep_gate_decision_retention(&self) -> Result<u64> {
        self.finish_gate_decision_retirements()?;
        let now = self.store.clock.now_recorded_at();
        let mut txn = self.store.env.write_txn()?;
        // Read the owner setting UNDER the same writer lock as pruning: an
        // owner who disables or lengthens retention before this pass wins.
        let policy = crate::gate::resolve_gate_decision_retention(&self.store, &txn)?.ok_or(
            Error::InvalidConfig("gate decision retention manifest missing".into()),
        )?;
        let Some(seconds) = policy.horizon_secs else {
            return Ok(0);
        };
        let retain_until = now.saturating_add(seconds);
        // An admission that still names its original allowing receipt is an
        // operational dependency, including revoked shares and publishes with
        // removed pointers, and so are durable mint taps and conflict rulings
        // that replay from their decision. Scan source-of-truth rows, not an
        // unproven index.
        let mut operational_refs =
            crate::share::share_gate_decision_refs_in_txn(&self.store, &txn)?;
        operational_refs.extend(crate::artifact_hosting::artifact_publish_gate_refs_in_txn(
            self, &txn,
        )?);
        operational_refs.extend(crate::workspace_roster::project_mint_gate_refs_in_txn(
            self, &txn,
        )?);
        operational_refs.extend(crate::memory::claim_conflict_ruling_gate_refs_in_txn(
            &self.store,
            &txn,
        )?);
        // Decode BEFORE mutating. A corrupt ciphertext/key aborts the entire
        // sweep instead of quietly miscounting the rows that share that key.
        let mut eligible: Vec<GateDecisionRecord> = Vec::new();
        let mut live_claims = BTreeSet::new();
        let mut removed_claims = BTreeSet::new();
        let mut held_partitions = BTreeSet::new();
        self.store.for_each_gate_decision_in_txn(&txn, |record| {
            let claim = record.claim_id;
            if self
                .store
                .gate_partition_held_in_txn(&txn, claim.as_ref())?
            {
                held_partitions.insert(claim);
                if let Some(claim) = claim {
                    live_claims.insert(claim);
                }
            } else if policy
                .horizon_for(self.store.gate_retention_context_in_txn(&txn, &record)?)
                .is_some_and(|horizon| record.created_at < now.saturating_sub(horizon))
                && eligible.len() < policy.max_sweep_rows
            {
                if operational_refs.contains(&record.decision_id)
                    || self.live_claim_proof_in_txn(&txn, &record)?
                {
                    if let Some(claim) = claim {
                        live_claims.insert(claim);
                    }
                    return Ok(());
                }
                // An unanswered consent must retain its exact source receipt;
                // closure loads it by decision ID in this same key partition.
                let required_by_pending = if let Some(claim) = claim {
                    self.store
                        .pending_gate_consent_in_txn(&txn, &EntityId::from_bytes(claim)?)?
                        .is_some_and(|pending| pending.decision_id == record.decision_id)
                } else {
                    false
                };
                if required_by_pending {
                    if let Some(claim) = claim {
                        live_claims.insert(claim);
                    }
                } else {
                    if let Some(claim) = claim {
                        removed_claims.insert(claim);
                    }
                    eligible.push(record);
                }
            } else if let Some(claim) = claim {
                // A skipped old row is still live until a later bounded pass.
                live_claims.insert(claim);
            }
            Ok(())
        })?;
        for claim in held_partitions {
            let partition = Partition(claim);
            let previous = RETAIN_UNTIL
                .get(&self.store, &txn, &partition)?
                .unwrap_or(0);
            RETAIN_UNTIL.put(
                &self.store,
                &mut txn,
                &partition,
                &previous.max(retain_until),
            )?;
        }
        let removed = eligible.len() as u64;
        for record in &eligible {
            self.store
                .delete_gate_decision_record_in_txn(&mut txn, record)?;
        }
        // Commit the intent WITH row removal, then touch exterior keys.
        // A crash before commit leaves readable rows; a crash after commit
        // leaves a resumable pending marker and no rows that need the key.
        for claim in removed_claims.difference(&live_claims) {
            let generation = orcb::key_generation(&self.store.core.gate_custody_root, claim)?;
            RETIRE_PENDING.put(&self.store, &mut txn, claim, &generation)?;
        }
        txn.commit()?;
        self.finish_gate_decision_retirements()?;
        Ok(removed)
    }
}

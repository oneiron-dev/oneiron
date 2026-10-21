//! Opt-in gate-decision age sweep over the actual ORCB custody unit, and the
//! claim client's retirement policy over typed custody (`key_custody`).
//!
//! ONE-1640 uses one exterior key per claim, not a shared time-bucket key.
//! A claim ID is therefore the indivisible encrypted partition. An unlinked
//! decision has no exterior key and belongs to the separate unlinked partition.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::deletion::LegalHoldTarget;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::key_custody::{
    CustodyKind, RetireCause, RetirementIntent, retirement_in_txn, retirement_prefix,
    retirements_in_rows, retirements_in_txn, stage_retirement_in_txn,
};
use crate::store::{Store, legal_hold};

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

/// The latest retain-until stamp of a held partition.
const RETAIN_UNTIL: SideTable<Partition, u64, Raw> =
    SideTable::new(&side_table::GATE_DECISION_PARTITION_RETAIN_UNTIL);

/// The claim a `ClaimDecision` subject keys.
fn intent_claim(intent: &RetirementIntent) -> Result<[u8; 16]> {
    intent
        .subject
        .item()
        .try_into()
        .map_err(|_| orcb::corrupt())
}

impl Store {
    /// Whether a legal hold stands on the partition: the one hold store's
    /// answer (OF-470), never a second marker.
    pub(crate) fn gate_partition_held_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: Option<&[u8; 16]>,
    ) -> Result<bool> {
        legal_hold::partition_held_in_txn(self, txn, claim)
    }

    /// Every staged key-retirement intent and whether it is an erase's, so a
    /// caller-owned write transaction can tell whether it staged one and must
    /// finish it. An erase can mark an intent without changing its
    /// generation.
    pub(crate) fn gate_retirements_staged_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<([u8; 16], u64, bool)>> {
        retirements_in_txn(self, txn, CustodyKind::ClaimDecision)?
            .iter()
            .map(|intent| {
                Ok((
                    intent_claim(intent)?,
                    intent.through,
                    intent.cause == RetireCause::Erase,
                ))
            })
            .collect()
    }

    /// A claim whose erase committed takes no hold until its key is
    /// destroyed: a hold cannot bring back what an erase decided.
    pub(crate) fn refuse_hold_on_erased_partition_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: &[u8; 16],
    ) -> Result<()> {
        // Unbound: no key, so no retirement, was ever staged here.
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let Some(intent) = retirement_in_txn(self, txn, &orcb::claim_subject(custody, claim)?)?
        else {
            return Ok(());
        };
        if intent.cause == RetireCause::Erase {
            return Err(Error::InvalidConfig(
                "gate decision partition was erased".into(),
            ));
        }
        if custody.retired(&intent.subject.at(intent.through))? {
            return Err(Error::InvalidConfig(
                "gate decision partition key already retired".into(),
            ));
        }
        Ok(())
    }
}

/// The `vault_meta` prefixes of the rows [`checkpoint_retirements`] reads.
pub(super) fn retirement_prefixes() -> [&'static [u8]; 3] {
    let [holds, host_holds] = legal_hold::target_prefixes();
    [retirement_prefix(), holds, host_holds]
}

/// Each claim, body instance and known-value history key-retirement intent
/// among a checkpoint's `vault_meta` rows, with whether the finisher would
/// carry it out now: an erase's always, a sweep's unless its partition is
/// held. A restore treats a carried-out one as done, so it never brings back
/// a key a vault has committed to destroy.
pub(super) fn checkpoint_retirements(
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<(RetirementIntent, bool)>> {
    let mut retirements = Vec::new();
    for intent in retirements_in_rows(rows)? {
        // A body instance, a holder's known-value history (KS-3), a world
        // pad (KS-5) and a credential's value or carrier key (KS-6) retire
        // for an erase only, which no hold defers (KS-2A): the restore
        // treats it as done.
        if matches!(
            intent.subject.kind(),
            CustodyKind::BodyInstance | CustodyKind::KnownValueEntry | CustodyKind::WorldPad
        ) || crate::store::credential_kind(intent.subject.kind())
        {
            retirements.push((intent, true));
            continue;
        }
        if intent.subject.kind() != CustodyKind::ClaimDecision {
            continue;
        }
        let held = legal_hold::rows_hold_claim(rows, &intent_claim(&intent)?);
        let carried = intent.cause == RetireCause::Erase || !held;
        retirements.push((intent, carried));
    }
    Ok(retirements)
}

/// The claim client's predicate for the custody finisher: a sweep's intent
/// waits while its partition is held, an erase's never; and no ciphertext
/// under a retiring generation may still be live. Erased rows stay as
/// plaintext skeletons that keep the claim id.
fn claim_retirement_ready(
    store: &Store,
    txn: &RoTxn<'_>,
    intent: &RetirementIntent,
) -> Result<bool> {
    let claim = intent_claim(intent)?;
    if intent.cause != RetireCause::Erase && store.gate_partition_held_in_txn(txn, Some(&claim))? {
        return Ok(false);
    }
    for row in super::ledger::LEDGER.iter_raw_from(store, txn, &[])? {
        let (_, raw) = row?;
        if orcb::raw_claim_generation(&raw)
            .is_some_and(|(owner, generation)| owner == claim && generation <= intent.through)
        {
            return Err(Error::CorruptedIndex(
                "retiring gate decision partition has live rows",
            ));
        }
    }
    Ok(true)
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?
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
        // A floor this commit moved is judged again at once (FIX 5505).
        self.apply_pending_rebinds_after_commit();
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
    /// released explicitly; the age sweep never clears it. A claim whose
    /// erase committed refuses a hold until its key is destroyed. A
    /// host-facing door: the partition's own row in the one legal-hold store
    /// (OF-470), logged; releasing it lifts that hold alone, never another
    /// hold naming the same claim.
    pub fn set_gate_decision_partition_hold(
        &self,
        claim_partition: Option<[u8; 16]>,
        held: bool,
    ) -> Result<()> {
        let claim = claim_partition.map(EntityId::from_bytes).transpose()?;
        self.with_write_txn_grouped(|txn| {
            if held && let Some(claim) = claim_partition.as_ref() {
                self.store
                    .refuse_hold_on_erased_partition_in_txn(txn, claim)?;
            }
            let now = self.store.clock.now_recorded_at();
            let target = LegalHoldTarget::GatePartition(claim);
            legal_hold::set_partition_hold_in_txn(&self.store, txn, target, held, now)
        })?;
        // A released partition hold may free a deferred delete (FIX 1488).
        if !held {
            self.note_backup_hold_recheck();
        }
        Ok(())
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
    /// redaction or removal of every row those generations decrypt. A hold
    /// defers a sweep's retirement until release, never an erase's.
    pub(crate) fn finish_gate_decision_retirements(&self) -> Result<()> {
        self.store
            .finish_custody_retirements(CustodyKind::ClaimDecision, |txn, intent| {
                claim_retirement_ready(&self.store, txn, intent)
            })
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
        // KS-2A: an erase's body instance retirements, once nothing names
        // their instances.
        #[cfg(unix)]
        self.finish_body_custody_retirements_after_commit();
        self.finish_known_history_retirements_after_commit();
        self.finish_world_pad_retirements_after_commit();
    }

    /// Post-commit door for an erase that staged a world's pad retirements
    /// (KS-5, FIX 346). The intents are durable, so a failure here is retried
    /// by the next housekeeping pass and never reported as a failure of the
    /// erase that already committed.
    pub(crate) fn finish_world_pad_retirements_after_commit(&self) {
        if let Err(error) = self.store.finish_world_pad_retirements() {
            tracing::warn!(
                error = %error,
                "world key pad retirement deferred to the next housekeeping pass"
            );
        }
    }

    /// Post-commit door for an erase that staged a holder's known-value
    /// history retirement (KS-3). The intent is durable, so a failure here
    /// is retried by the next housekeeping pass and never reported as a
    /// failure of the erase that already committed.
    pub(crate) fn finish_known_history_retirements_after_commit(&self) {
        if let Err(error) = self.store.finish_known_history_retirements() {
            tracing::warn!(
                error = %error,
                "known-value history retirement deferred to the next housekeeping pass"
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
        // Held partitions with rows past the horizon: the sweep's refusal.
        let mut refused_partitions = BTreeSet::new();
        self.store.for_each_gate_decision_in_txn(&txn, |record| {
            let claim = record.claim_id;
            if self
                .store
                .gate_partition_held_in_txn(&txn, claim.as_ref())?
            {
                if policy
                    .horizon_for(self.store.gate_retention_context_in_txn(&txn, &record)?)
                    .is_some_and(|horizon| record.created_at < now.saturating_sub(horizon))
                {
                    refused_partitions.insert(claim);
                }
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
        for claim in refused_partitions {
            let claim = claim.map(EntityId::from_bytes).transpose()?;
            let target = LegalHoldTarget::GatePartition(claim);
            legal_hold::log_timer_refusal_in_txn(&self.store, &mut txn, target, now)?;
        }
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
        // Unbound: no claim key was ever published, so none retires.
        if let Some(custody) = self.store.core.key_custody.local() {
            for claim in removed_claims.difference(&live_claims) {
                // An erase that committed after this pass's finisher may name
                // a newer generation or an erase; staging never lowers either.
                let subject = orcb::claim_subject(custody, claim)?;
                let intent = RetirementIntent {
                    through: custody.first_unretired(&subject)?,
                    subject,
                    cause: RetireCause::Retention,
                };
                stage_retirement_in_txn(&self.store, &mut txn, &intent)?;
            }
        }
        txn.commit()?;
        self.finish_gate_decision_retirements()?;
        Ok(removed)
    }
}

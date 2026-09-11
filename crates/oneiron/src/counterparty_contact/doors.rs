//! Counterparty contact Vault doors: create, opt-out, revoke, reads, and claim apply.

use super::codec::{
    decode_counterparty_contact_body, encode_counterparty_contact_body,
    is_counterparty_contact_claim_predicate,
};
use super::lifecycle::{
    comm_fold_error, counterparty_contact_record_from_claims_in_txn,
    rematerialize_contact_cache_in_txn, rematerialize_party_contact_cache_in_txn,
    supersede_family_owned_claim_in_txn,
};
use super::storage::{
    counterparty_contact_channel_class, counterparty_contact_index_key,
    counterparty_contact_index_key_for_record, decode_counterparty_contact_index_value,
    encode_counterparty_contact_index_value, put_counterparty_contact_party_channel_index,
    read_counterparty_contact_in_txn,
};
use super::types::{CounterpartyContactRecord, CounterpartyOptOutReason};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

impl Vault {
    /// Creates a per-(identity, counterparty) contact record.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_COUNTERPARTY_CONTACT` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-7 body and enforces a single consent row per target.
    pub fn create_counterparty_contact(
        &self,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<()> {
        // Validate the record before anything is written, exactly as the
        // encode-first shape did.
        encode_counterparty_contact_body(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || self.counterparty_contact_assignment_conflict_in_txn(&wtxn, id, record)?
        {
            return Err(Error::Record(RecordError::CounterpartyContactAlreadyExists));
        }
        // Claims first, cache second, one transaction (ONE-1752): the heads are
        // the truth and the row is derived from them. The claim_of edges point
        // at a row this same transaction is about to write.
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn,
            id,
            record,
            record.updated_at,
        )?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, record.updated_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Records a legal/platform opt-out event on a counterparty contact.
    ///
    /// Contact-level and party-level truth move TOGETHER: the same transaction
    /// supersedes this contact's `counterparty_contact.*` heads and one
    /// party-scoped `comm.opt_out` head with no channel class — the party said
    /// it to the owner, not to one mailbox — and then re-derives the cache.
    pub fn opt_out_counterparty_contact(
        &self,
        id: &EntityId,
        reason: CounterpartyOptOutReason,
        recorded_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.counterparty_contact_for_update_in_txn(&wtxn, id)?;
        let opted_out = current.opted_out(reason, recorded_at)?;
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn,
            id,
            &opted_out,
            recorded_at,
        )?;
        crate::comm::supersede_party_opt_out_head_in_txn(
            self,
            &mut wtxn,
            &opted_out.counterparty,
            reason,
            recorded_at,
        )
        .map_err(comm_fold_error)?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, recorded_at)?;
        // The head just written carries NO channel class, so it covers every
        // contact this party has — and every one of their cache rows has to say
        // so in this same transaction. Re-deriving only `id` would leave a
        // sibling contact on another channel identity reading not-opted-out,
        // and the gate, which folds type-132 rows rather than `comm.opt_out`
        // heads, would allow a send the party's own opt-out forbids.
        rematerialize_party_contact_cache_in_txn(
            self,
            &mut wtxn,
            &opted_out.counterparty,
            None,
            recorded_at,
        )?;
        let record = read_counterparty_contact_in_txn(&self.store, &wtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Revokes owner visibility/reachability for a counterparty contact.
    pub fn revoke_counterparty_contact(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.counterparty_contact_for_update_in_txn(&wtxn, id)?;
        let revoked = current.revoked(revoked_at)?;
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn, id, &revoked, revoked_at,
        )?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, revoked_at)?;
        let record = read_counterparty_contact_in_txn(&self.store, &wtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// The current record a contact writer is about to move forward.
    ///
    /// The snapshot is rebuilt from this contact's OWN `counterparty_contact.*`
    /// heads, never from the type-132 row, even though the writer holds the row
    /// already: the row is a cache the party's `comm.opt_out` heads have been
    /// folded into, and superseding contact heads from it would write that
    /// party-scoped suppression back out as contact-family truth — cache →
    /// claims, the one direction ONE-1752 forbids. A revoke that followed an
    /// inbound STOP would otherwise mint a `counterparty_contact.opt_out` head
    /// the contact family never asserted, and the family-owned CLEAR would then
    /// have a channel-scoped STOP to undo that no CLEAR is scoped to reach.
    ///
    /// The row is still READ first, so a missing subject and a wrong entity
    /// type fail exactly as they did when the body came from it.
    fn counterparty_contact_for_update_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CounterpartyContactRecord> {
        let raw = self
            .store
            .entities
            .get(wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        counterparty_contact_record_from_claims_in_txn(self, wtxn, id)
    }

    /// Moves this contact's `counterparty_contact.*` heads to `record`.
    ///
    /// One head per predicate. A head whose value is already exactly what the
    /// record projects is LEFT ALONE — a supersession that changes nothing is
    /// churn, not history — and every other predicate gets a new head that
    /// supersedes the old one inside this transaction, so the family never has
    /// two live heads for one predicate.
    fn supersede_counterparty_contact_claim_heads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        contact_id: &EntityId,
        record: &CounterpartyContactRecord,
        now: u64,
    ) -> Result<()> {
        let mut live: Vec<(EntityId, ClaimBody)> = Vec::new();
        for claim_id in self.claims_for_subject_in_txn(&*wtxn, contact_id)? {
            let Some(body) = self.get_claim_in_txn(&*wtxn, &claim_id)? else {
                continue;
            };
            if is_counterparty_contact_claim_predicate(&body.predicate)
                && body.lifecycle == ClaimLifecycleStatus::Active
                && !body.stale
            {
                live.push((claim_id, body));
            }
        }

        for body in record.claim_bodies(*contact_id) {
            let existing = live
                .iter()
                .find(|(_, live_body)| live_body.predicate == body.predicate);
            if existing.is_some_and(|(_, live_body)| live_body.value == body.value) {
                continue;
            }
            let new_id = EntityId::now();
            self.put_counterparty_contact_claim_in_txn(wtxn, &new_id, &body, now)?;
            if let Some((old_id, _)) = existing {
                supersede_family_owned_claim_in_txn(self, wtxn, &new_id, old_id, now)?;
            }
        }
        Ok(())
    }

    /// Crate-visible test door onto the family head writer above.
    ///
    /// The contact family has no public CLEAR verb yet, and a test that moved
    /// the heads itself would be asserting against its own copy of the door's
    /// rules rather than the door. This changes nothing about the door: it is
    /// the same call the shipping writers make, reachable from the sibling
    /// module that pins the opt-out coexistence ladder.
    #[cfg(test)]
    pub(crate) fn supersede_counterparty_contact_claim_heads_for_test(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        contact_id: &EntityId,
        record: &CounterpartyContactRecord,
        now: u64,
    ) -> Result<()> {
        self.supersede_counterparty_contact_claim_heads_in_txn(wtxn, contact_id, record, now)
    }

    /// The family-owned door for one `counterparty_contact.*` head.
    ///
    /// It writes through the same `apply_ops` chokepoint (and the same
    /// structural validation) as every other claim, on the ENGINE-OWNED
    /// setting: this family door already decided the write when it validated
    /// the record, exactly like `put_reserved_claim_in_txn`'s callers, so the
    /// public criticality ladder must not re-ask the question and turn a
    /// recorded contact fact into an owner review.
    ///
    /// It deliberately does NOT pre-check that the subject row exists: on
    /// create, the type-132 row is written by this SAME transaction's
    /// rematerialization, immediately after the heads it is derived from.
    fn put_counterparty_contact_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        now: u64,
    ) -> Result<()> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvalidClaimBody(
                "counterparty_contact claim subject must be an entity",
            ));
        };
        let data = crate::claim::encode_claim_body(body)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![
                BatchOp::Put {
                    id: *id,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: *id,
                    kind: crate::edge::EdgeKind::ClaimOf,
                    tgt: subject,
                    weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                    vad: crate::affect::Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// Reads and decodes a CounterpartyContact record.
    pub fn get_counterparty_contact(
        &self,
        id: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Finds one contact record by `(identity_ref, counterparty)`.
    pub fn find_counterparty_contact(
        &self,
        identity_ref: &EntityId,
        counterparty: &str,
    ) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let index_key = counterparty_contact_index_key(identity_ref, counterparty)?;
        if let Some(raw_id) = self.store.vault_meta.get(&rtxn, &index_key)? {
            let id = decode_counterparty_contact_index_value(&raw_id)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity row",
                ));
            };
            let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex(
                "counterparty contact lookup index entity header",
            ))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity type",
                ));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if !record.matches_counterparty(identity_ref, counterparty) {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index assignment",
                ));
            }
            return Ok(Some((id, record)));
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.matches_counterparty(identity_ref, counterparty) {
                return Ok(Some((id, record)));
            }
        }
        Ok(None)
    }

    /// Lists contact records visible for a channel identity.
    pub fn counterparty_contacts_for_identity(
        &self,
        identity_ref: &EntityId,
    ) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.identity_ref.as_bytes() == identity_ref.as_bytes() {
                records.push((id, record));
            }
        }
        Ok(records)
    }

    fn counterparty_contact_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<bool> {
        let index_key = counterparty_contact_index_key_for_record(record)?;
        if let Some(raw_id) = self.store.vault_meta.get(txn, &index_key)? {
            let existing_id = decode_counterparty_contact_index_value(&raw_id)?;
            if existing_id != *id {
                return Ok(true);
            }
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let existing_id = entity_id_from_type_index_key(&key)?;
            if existing_id == *id {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, existing_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let stored = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored.matches_counterparty(&record.identity_ref, &record.counterparty) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn apply_counterparty_contact_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let record = decode_counterparty_contact_body(&data)?;
        let new_index_key = counterparty_contact_index_key_for_record(&record)?;
        if let Some(raw_id) = self.store.vault_meta.get(&*wtxn, &new_index_key)? {
            let existing_id = decode_counterparty_contact_index_value(&raw_id)?;
            if existing_id != *id {
                return Err(Error::Record(RecordError::CounterpartyContactAlreadyExists));
            }
        }

        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let old_record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(counterparty_contact_index_key_for_record(&old_record)?)
        } else {
            None
        };

        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_COUNTERPARTY_CONTACT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        let index_value = encode_counterparty_contact_index_value(id);
        self.store
            .vault_meta
            .put(wtxn, &new_index_key, &index_value)?;

        // Identity-independent leg. A record whose identity has no resolvable
        // channel class is simply not indexed — the send-time full scan is what
        // covers it, so this is an accelerator, never a gate.
        if let Some(channel_class) =
            counterparty_contact_channel_class(&self.store, &*wtxn, &record)?
        {
            put_counterparty_contact_party_channel_index(
                &self.store,
                wtxn,
                &record.counterparty,
                &channel_class,
                *id,
            )?;
        }
        Ok(())
    }
}

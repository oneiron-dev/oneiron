//! Counterparty contact Vault doors: create, opt-out, revoke, reads, and claim apply.

use super::codec::{
    decode_counterparty_contact_body, encode_counterparty_contact_body,
    is_counterparty_contact_claim_predicate, normalize_counterparty,
};
use super::lifecycle::{
    comm_fold_error, counterparty_contact_in_claims_in_txn, live_counterparty_contact_heads_in_txn,
    rematerialize_contact_cache_in_txn, rematerialize_party_contact_cache_in_txn,
    supersede_family_owned_claim_in_txn,
};
use super::storage::{
    CONTACT_INDEX, contact_deleted_in_txn, contact_ids_with_live_head_in_txn,
    counterparty_contact_channel_class, counterparty_contact_index_key_for_record,
    put_counterparty_contact_party_channel_index, read_counterparty_contact_in_txn,
};
use super::types::{
    CounterpartyContactRecord, CounterpartyOptOutReason,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY, PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
use crate::temporal::TimeRange;

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
        if self.store.port_entity_record(&wtxn, id)?.is_some()
            || live_counterparty_contact_heads_in_txn(self, &wtxn, id)?.is_some()
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
    /// Existence is the family's own (OF-272): a contact whose row a cache
    /// drop removed is still a contact its writers can move, and a missing or
    /// deleted one fails `EntityNotFound`. A row of another type still fails
    /// on its type.
    fn counterparty_contact_for_update_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CounterpartyContactRecord> {
        self.reject_non_contact_row_in_txn(wtxn, id)?;
        live_counterparty_contact_heads_in_txn(self, wtxn, id)?.ok_or(Error::EntityNotFound)
    }

    /// A row at `id` of any other entity type is not a contact. A deleted id
    /// is answered by the claims reader's deletion check, whatever its shell.
    fn reject_non_contact_row_in_txn(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<()> {
        if contact_deleted_in_txn(&self.store, rtxn, id)? {
            return Ok(());
        }
        if let Some(raw) = self.store.port_entity_record(rtxn, id)?
            && raw.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT
        {
            return Err(Error::InvalidEntityType(raw.entity_type));
        }
        Ok(())
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

        for body in record.claim_bodies(*contact_id)? {
            let existing = live
                .iter()
                .find(|(_, live_body)| live_body.predicate == body.predicate);
            if existing.is_some_and(|(_, live_body)| live_body.value == body.value) {
                continue;
            }
            let new_id = self.store.clock.entity_id()?;
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

    /// Reads one contact, from its claims (OF-272).
    ///
    /// The record is the contact's own `counterparty_contact.*` heads with the
    /// party's standing `comm.opt_out` heads folded in — what the type-132 row
    /// holds when it is there, and the same answer when a cache drop removed
    /// it. `None` when `id` names no contact, or a deleted one.
    pub fn get_counterparty_contact(
        &self,
        id: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_counterparty_contact_in_txn(&rtxn, id)
    }

    /// [`Self::get_counterparty_contact`] in the caller's snapshot.
    pub(crate) fn get_counterparty_contact_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        self.reject_non_contact_row_in_txn(rtxn, id)?;
        counterparty_contact_in_claims_in_txn(self, rtxn, id)
    }

    /// Finds one contact record by `(identity_ref, counterparty)`, from claims.
    pub fn find_counterparty_contact(
        &self,
        identity_ref: &EntityId,
        counterparty: &str,
    ) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        self.find_counterparty_contact_in_txn(&rtxn, identity_ref, counterparty)
    }

    /// The contact is found through its live `counterparty_contact.counterparty`
    /// posting and matched on its identity head (OF-272): neither
    /// `CONTACT_INDEX` nor the type-132 rows are asked, so a cache drop cannot
    /// hide a contact the gate still sees.
    pub(crate) fn find_counterparty_contact_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        identity_ref: &EntityId,
        counterparty: &str,
    ) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
        let counterparty = normalize_counterparty(counterparty.to_owned())?;
        for id in contact_ids_with_live_head_in_txn(
            &self.store,
            rtxn,
            PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
            &counterparty,
        )? {
            if let Some(record) = counterparty_contact_in_claims_in_txn(self, rtxn, &id)?
                && record.matches_counterparty(identity_ref, &counterparty)
            {
                return Ok(Some((id, record)));
            }
        }
        Ok(None)
    }

    /// Lists contact records visible for a channel identity, from the
    /// identity's `counterparty_contact.identity_ref` postings (OF-272).
    pub fn counterparty_contacts_for_identity(
        &self,
        identity_ref: &EntityId,
    ) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for id in contact_ids_with_live_head_in_txn(
            &self.store,
            &rtxn,
            PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
            &identity_ref.to_hex(),
        )? {
            if let Some(record) = counterparty_contact_in_claims_in_txn(self, &rtxn, &id)? {
                records.push((id, record));
            }
        }
        Ok(records)
    }

    /// The contacts whose live `counterparty_contact.identity_ref` head names
    /// `identity_ref`, in the caller's snapshot: the discovery
    /// [`Self::counterparty_contacts_for_identity`] runs, claims-first
    /// (OF-272). A deleted contact is none of them.
    pub(crate) fn counterparty_contact_ids_for_identity_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        identity_ref: &EntityId,
    ) -> Result<Vec<EntityId>> {
        contact_ids_with_live_head_in_txn(
            &self.store,
            rtxn,
            PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
            &identity_ref.to_hex(),
        )
    }

    /// Whether another live contact already holds `record`'s
    /// `(identity, counterparty)` pair, by the contacts' claims (OF-272). The
    /// cache's own index uniqueness stays its writer's check.
    fn counterparty_contact_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<bool> {
        for existing_id in contact_ids_with_live_head_in_txn(
            &self.store,
            txn,
            PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
            &record.counterparty,
        )? {
            if existing_id == *id {
                continue;
            }
            if live_counterparty_contact_heads_in_txn(self, txn, &existing_id)?.is_some_and(
                |stored| stored.matches_counterparty(&record.identity_ref, &record.counterparty),
            ) {
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
        if let Some(existing_id) = CONTACT_INDEX.get(&self.store, &*wtxn, &new_index_key)?
            && existing_id != *id
            && self
                .store
                .port_entity_record(&*wtxn, &existing_id)?
                .is_some()
        {
            return Err(Error::Record(RecordError::CounterpartyContactAlreadyExists));
        }

        let old_index_key = if let Some(raw) = self
            .store
            .port_entity_record(&*wtxn, id)?
            .map(|row| row.encode())
        {
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
            CONTACT_INDEX.delete(&self.store, wtxn, old_index_key)?;
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
        CONTACT_INDEX.put(&self.store, wtxn, &new_index_key, id)?;

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

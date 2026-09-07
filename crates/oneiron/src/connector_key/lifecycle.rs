use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::secret_custody::resolve_secret_ref_in_txn;
use crate::temporal::TimeRange;

use super::charter::{charter_stamped_aggregate, compile_connector_charter};
use super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::meter::delete_charter_usage_rows_in_txn;
use super::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, ConnectorCallClass, ConnectorCatalogEntry,
    ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeySpec, ConnectorKeyStatus,
    EffectorBudget, PendingConnectorCharter, invalid_body, normalize_connector_key,
    validate_budget_row, validate_secret_ref, validate_suggested_budget_row,
};
use super::txn::{
    CONNECTOR_CATALOG_NAME_INDEX_PREFIX, ConnectorKeyGeneration, append_connector_key_op_record,
    connector_catalog_index_entity_id, connector_catalog_name_index_key,
    connector_key_index_entity_id, connector_key_index_key, connector_key_index_prefix,
    governing_connector_key, read_connector_key_generation_in_txn, read_connector_key_in_txn,
    reject_terminal_transition, revoke_connector_key_in_txn, rewrite_connector_key_in_txn,
    suspend_connector_key_in_txn, write_connector_key_generation_in_txn,
};

/// The HISTORY lens over one catalogued connector: what it is, plus the
/// VALUE-LESS metadata of the key that governs it. `secret_ref` is a custody
/// record NAME (ONE-1919), never a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDescription {
    /// The governing CONNECTOR_KEY entity.
    pub key_ref: EntityId,
    pub entry: ConnectorCatalogEntry,
    /// The connector token the key governs.
    pub connector: String,
    /// Resolves for a REMOVED connector too, reporting `Revoked`.
    pub status: ConnectorKeyStatus,
    pub secret_ref: Option<String>,
    pub key_generation: u32,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    /// Entry-wide ARCH-0054 classification: `call_class.debits_sends()`.
    pub budgeted_as_sends: bool,
}

/// The EXECUTION lens over one catalogued connector. Produced only while the
/// governing key is Active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallRoute {
    pub key_ref: EntityId,
    pub connector: String,
    pub call_class: ConnectorCallClass,
    /// ENTRY-WIDE (ARCH-0054): there is no verb parameter, so a mixed-verb
    /// `CounterpartyComm` connector budgets every call as a send.
    pub budgeted_as_sends: bool,
    /// Descriptive verb list from the catalog entry.
    pub verbs: Vec<String>,
    /// Custody record NAME to authenticate with; never a value.
    pub secret_ref: Option<String>,
}

/// Normalizes every `channel_class` narrowing in place: row matching compares
/// against the already-normalized effect channel, so a non-canonical stored
/// narrowing would never match a dispatch.
fn normalize_budget_channel_classes(budgets: &mut [EffectorBudget]) {
    for budget in budgets {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
    }
}

// --- Vault registry API -----------------------------------------------------------

impl Vault {
    /// Registers a connector key. Rejects a second non-revoked key for the
    /// same `(connector, actor_entity_ref)` tuple, a non-Active status, and a
    /// pre-stamped charter (a charter must enter via the receipted
    /// propose/approve pair, never via register).
    pub fn register_connector_key(
        &self,
        id: &EntityId,
        record: ConnectorKeyRecord,
    ) -> Result<ConnectorKeyRecord> {
        let mut record = record;
        record.connector = normalize_connector_key(&record.connector);
        normalize_budget_channel_classes(&mut record.budgets);
        normalize_budget_channel_classes(&mut record.suggested_budgets);
        // A catalog entry is MINTED BY registration, never carried into it:
        // the composed door is the only writer of the permanent name index,
        // so a catalogued key can never exist without its reserved name.
        // Rejected pre-write, before any transaction opens.
        if record.catalog.is_some() {
            return Err(invalid_body("catalog requires composed registration"));
        }
        record.validate()?;

        let mut wtxn = self.store.env.write_txn()?;
        self.register_connector_key_in_txn(&mut wtxn, id, &record)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Registration IS "catalog entry + key mint" — one entity id, one
    /// transaction, one `gate.connector_key.register` receipt.
    ///
    /// The entry's own `registered_at` is advisory input and is OVERWRITTEN by
    /// the `registered_at` parameter, so a stale entry cannot date the catalog
    /// row. Both connector tokens and the catalog name normalize before the
    /// uniqueness checks, so `"my-connector"` and `"my_connector"` are the
    /// same registration. Every leg — entity body, connector index, permanent
    /// name index, generation-0 log row, receipt — commits together or not at
    /// all.
    pub fn register_connector(
        &self,
        entry: ConnectorCatalogEntry,
        key_spec: ConnectorKeySpec,
        registered_at: u64,
    ) -> Result<(EntityId, ConnectorKeyRecord)> {
        let mut entry = entry;
        entry.name = normalize_connector_key(&entry.name);
        entry.connector = normalize_connector_key(&entry.connector);
        entry.registered_at = registered_at;
        entry.validate()?;

        let mut record = ConnectorKeyRecord::active(
            normalize_connector_key(&key_spec.connector),
            key_spec.actor_entity_ref,
            key_spec.budgets,
            registered_at,
        );
        normalize_budget_channel_classes(&mut record.budgets);
        record.secret_ref = key_spec.secret_ref;
        record.catalog = Some(entry);
        // `validate` binds the entry to the key: a catalog naming a different
        // connector than the key governs is rejected here, pre-write.
        record.validate()?;

        let id = EntityId::now();
        let mut wtxn = self.store.env.write_txn()?;
        self.register_connector_key_in_txn(&mut wtxn, &id, &record)?;
        wtxn.commit()?;
        Ok((id, record))
    }

    /// The in-txn registration core shared by BOTH register doors, so the
    /// legacy and composed paths cannot drift on what registration MEANS:
    /// entity-id collision, `(connector, actor)` tuple uniqueness against
    /// non-revoked siblings, custody-reference resolution, catalog-name
    /// reservation, the entity body + connector index, the generation-0 log
    /// row, and the register receipt. The caller owns the transaction, which
    /// is what makes a composed registration atomic.
    fn register_connector_key_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &ConnectorKeyRecord,
    ) -> Result<()> {
        record.validate()?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if record.charter.is_some() || record.pending_charter.is_some() {
            return Err(invalid_body("registration must not carry a charter"));
        }
        // Rotation counts from the registration, so registration is the ONE
        // op that mints generation 0; a caller cannot register mid-history.
        if record.key_generation != 0 {
            return Err(invalid_body("registration mints generation 0"));
        }

        let data = encode_connector_key_body(record)?;
        if self.store.entities.get(&*wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ConnectorKeyAlreadyExists);
        }
        let prefix = connector_key_index_prefix(&record.connector)?;
        let mut sibling_ids = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&*wtxn, &prefix)? {
            let (key, _) = entry?;
            sibling_ids.push(connector_key_index_entity_id(&key, &record.connector)?);
        }
        for sibling_id in sibling_ids {
            let sibling = read_connector_key_in_txn(&self.store, &*wtxn, &sibling_id)?
                .ok_or(Error::CorruptedIndex("connector key index row"))?;
            if sibling.status != ConnectorKeyStatus::Revoked
                && sibling.actor_entity_ref == record.actor_entity_ref
            {
                return Err(Error::ConnectorKeyAlreadyExists);
            }
        }
        // The custody reference must NAME a live record before anything is
        // written: a dangling ref fails the whole registration closed rather
        // than minting a key that can never authenticate. This resolves a
        // name to an id — the value door is never opened here.
        if let Some(secret_ref) = record.secret_ref.as_deref()
            && resolve_secret_ref_in_txn(&self.store, &*wtxn, secret_ref)?.is_none()
        {
            return Err(invalid_body("secret_ref does not resolve"));
        }
        // The catalog name is reserved for the life of the VAULT, not of the
        // key: `remove_connector_key` leaves this row standing, so a taken
        // name stays taken even after removal.
        if let Some(catalog) = record.catalog.as_ref() {
            let name_key = connector_catalog_name_index_key(&catalog.name);
            if self.store.vault_meta.get(&*wtxn, &name_key)?.is_some() {
                return Err(Error::ConnectorKeyAlreadyExists);
            }
            self.store.vault_meta.put(wtxn, &name_key, id.as_bytes())?;
        }

        self.apply_connector_key_body(wtxn, id, record.registered_at, data)?;
        write_connector_key_generation_in_txn(
            &self.store,
            wtxn,
            id,
            &ConnectorKeyGeneration {
                generation: 0,
                secret_ref: record.secret_ref.clone(),
                rotated_at: record.registered_at,
            },
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.register",
            record,
            policy.read_frontier_hash()?,
            record.registered_at,
        )
    }

    /// Reads and decodes a connector-key record.
    pub fn get_connector_key(&self, id: &EntityId) -> Result<Option<ConnectorKeyRecord>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_in_txn(&self.store, &rtxn, id)
    }

    /// Resolves the key governing `(connector, actor_entity_ref)` (read-txn
    /// wrapper over the gate's resolution order).
    pub fn connector_key_for(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )
    }

    /// Mints an Active connector key whose budget table is necessarily empty.
    /// Optional budget rows can only enter through the owner mutation APIs.
    pub fn mint_unbudgeted_connector_key(
        &self,
        connector: &str,
        actor_entity_ref: Option<EntityId>,
        registered_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        self.register_connector_key(
            &EntityId::now(),
            ConnectorKeyRecord::active(connector, actor_entity_ref, Vec::new(), registered_at),
        )
    }

    /// Appends one owner-supplied budget row to an existing non-revoked key.
    pub fn add_connector_key_budget(
        &self,
        id: &EntityId,
        mut budget: EffectorBudget,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
        validate_budget_row(&budget)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot add budget row to revoked key"));
        }
        if record.budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        record.budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_add",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Stages one advisory budget row. Suggested rows never participate in
    /// charging, and may only carry Refuse semantics.
    pub fn suggest_connector_key_budget(
        &self,
        id: &EntityId,
        mut budget: EffectorBudget,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
        validate_suggested_budget_row(&budget)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot suggest budget row on revoked key"));
        }
        if record.suggested_budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many suggested budget rows"));
        }
        record.suggested_budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_suggest",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Accepts one staged row into the active budget table. Existing usage is
    /// not consulted or backfilled, so accounting begins at activation.
    pub fn accept_connector_key_budget_suggestion(
        &self,
        id: &EntityId,
        suggestion_index: usize,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot accept budget row on revoked key"));
        }
        if record.budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        if suggestion_index >= record.suggested_budgets.len() {
            return Err(invalid_body("suggested budget row not found"));
        }
        let budget = record.suggested_budgets.remove(suggestion_index);
        validate_suggested_budget_row(&budget)?;
        record.budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_accept",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Suspends an Active key (owner op).
    pub fn suspend_connector_key(
        &self,
        id: &EntityId,
        reason: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("illegal status transition"));
        }
        let suspended = suspend_connector_key_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &record,
            reason.to_owned(),
            at,
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.suspend",
            &suspended,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(suspended)
    }

    /// Resumes a Suspended key. Deliberately does NOT clear usage rows: the
    /// window state is truth — if the window has not rolled, the next send
    /// re-exhausts and re-suspends (correct hard-cap behavior).
    pub fn resume_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Suspended {
            return Err(invalid_body("illegal status transition"));
        }
        let resumed = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            suspended_reason: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &resumed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.resume",
            &resumed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(resumed)
    }

    /// Revokes a key (terminal) from any non-revoked state.
    pub fn revoke_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(reject_terminal_transition());
        }
        let revoked = revoke_connector_key_in_txn(&self.store, &mut wtxn, id, &record, at)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.revoke",
            &revoked,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Removes a connector from the engine catalog.
    ///
    /// Mechanically this is the SAME terminal revocation core, but it is a
    /// different OP: exactly ONE `gate.connector_key.remove` record is
    /// appended and `gate.connector_key.revoke` is never emitted, so the
    /// receipt trail distinguishes "the owner pulled this key" from "the
    /// operator retired this connector".
    ///
    /// The permanent catalog name-index row is deliberately NOT deleted:
    /// names are unique per vault ACROSS HISTORY. So after removal
    /// `search_connector_catalog` omits the connector (Active-only),
    /// `describe_connector` still resolves it as Revoked, `route_connector_call`
    /// returns `None`, and re-registering the same name fails
    /// [`Error::ConnectorKeyAlreadyExists`] rather than recycling the name
    /// onto a different connector.
    pub fn remove_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(reject_terminal_transition());
        }
        let removed = revoke_connector_key_in_txn(&self.store, &mut wtxn, id, &record, at)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.remove",
            &removed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(removed)
    }

    /// Re-points a key at a NEW custody record and bumps its rotation
    /// generation, receipted as `gate.connector_key.rotate`.
    ///
    /// VALUE-FREE by construction: `new_secret_ref` is a custody record NAME
    /// that must resolve to a live record BEFORE anything is written, and the
    /// secret value is never read, copied, or carried through here. Rotating
    /// the VALUE behind a custody record is SECRET-04's job; this rotates
    /// which record the connector key points AT.
    ///
    /// The generation log lazily backfills the record's CURRENT generation
    /// first, so a key whose body predates the log (a v1/v2 body, which
    /// decodes at generation 0) still leaves `0..=new` point-readable through
    /// [`Self::connector_key_generation`].
    pub fn rotate_connector_key(
        &self,
        id: &EntityId,
        new_secret_ref: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        validate_secret_ref(new_secret_ref)?;
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot rotate a revoked key"));
        }
        if resolve_secret_ref_in_txn(&self.store, &wtxn, new_secret_ref)?.is_none() {
            return Err(invalid_body("secret_ref does not resolve"));
        }
        let next_generation =
            record
                .key_generation
                .checked_add(1)
                .ok_or(Error::InvariantViolation(
                    "connector key generation overflow",
                ))?;
        if read_connector_key_generation_in_txn(&self.store, &wtxn, id, record.key_generation)?
            .is_none()
        {
            write_connector_key_generation_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &ConnectorKeyGeneration {
                    generation: record.key_generation,
                    secret_ref: record.secret_ref.clone(),
                    rotated_at: record.registered_at,
                },
            )?;
        }
        let rotated = ConnectorKeyRecord {
            secret_ref: Some(new_secret_ref.to_owned()),
            key_generation: next_generation,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &rotated)?;
        write_connector_key_generation_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &ConnectorKeyGeneration {
                generation: next_generation,
                secret_ref: rotated.secret_ref.clone(),
                rotated_at: at,
            },
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.rotate",
            &rotated,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(rotated)
    }

    /// Point-reads one entry of a key's rotation-generation log: which custody
    /// record the key pointed at while that generation was current.
    pub fn connector_key_generation(
        &self,
        id: &EntityId,
        generation: u32,
    ) -> Result<Option<ConnectorKeyGeneration>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_generation_in_txn(&self.store, &rtxn, id, generation)
    }

    /// Compiles and STAGES a charter proposal (GOV-10). Never changes
    /// enforcement — that is the human gate. Overwrites a previous pending
    /// proposal; the receipt trail records both.
    pub fn propose_connector_charter(
        &self,
        id: &EntityId,
        text: &str,
        proposed_at: u64,
    ) -> Result<PendingConnectorCharter> {
        let compiled = compile_connector_charter(text)?;
        let normalized = text.replace("\r\n", "\n");
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let pending = PendingConnectorCharter {
            text: normalized,
            text_hash: compiled.text_hash,
            compiled: compiled.compiled,
            compiled_hash: compiled.compiled_hash,
            proposed_at,
        };
        let proposed = ConnectorKeyRecord {
            pending_charter: Some(pending.clone()),
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &proposed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_propose",
            &proposed,
            policy.read_frontier_hash()?,
            proposed_at,
        )?;
        wtxn.commit()?;
        Ok(pending)
    }

    /// The human gate (GOV-10): applies the staged compile iff the caller
    /// re-presents its compiled hash out-of-band, and stamps the aggregate
    /// binding text + compiled policy. Clears every compiled-cap usage row
    /// (`0x8000 | *`) in the same txn — compiled-cap usage is keyed
    /// positionally, so a re-stamped charter must never inherit the old
    /// charter's usage at the same indices or leave orphaned rows.
    ///
    /// There is deliberately NO single-call compile-and-activate API; which
    /// callers may invoke `approve` is host-surface policy (the same trust
    /// boundary as every owner Vault op) — in-engine the gate is the
    /// propose/approve split plus the receipt trail.
    pub fn approve_connector_charter(
        &self,
        id: &EntityId,
        expected_compiled_hash: [u8; 32],
        stamped_by: &str,
        stamped_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        if stamped_by.trim().is_empty() {
            return Err(invalid_body("stamped_by must not be blank"));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let Some(pending) = record.pending_charter.clone() else {
            return Err(Error::ConnectorCharterMissing);
        };
        if pending.compiled_hash != expected_compiled_hash {
            return Err(Error::ConnectorCharterApprovalMismatch);
        }
        let stamped = ConnectorKeyRecord {
            charter: Some(ConnectorCharterBlock {
                stamped_aggregate: charter_stamped_aggregate(
                    &pending.text_hash,
                    &pending.compiled_hash,
                ),
                text: pending.text,
                text_hash: pending.text_hash,
                compiled: pending.compiled,
                compiled_hash: pending.compiled_hash,
                stamped_by: stamped_by.to_owned(),
                stamped_at,
            }),
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &stamped)?;
        delete_charter_usage_rows_in_txn(&self.store, &mut wtxn, id)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_approve",
            &stamped,
            policy.read_frontier_hash()?,
            stamped_at,
        )?;
        wtxn.commit()?;
        Ok(stamped)
    }

    /// Owner rejection of a staged charter compile (GOV-10): clears the
    /// pending proposal, receipted. Enforcement was never changed by it.
    pub fn discard_connector_charter(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        if record.pending_charter.is_none() {
            return Err(Error::ConnectorCharterMissing);
        }
        let discarded = ConnectorKeyRecord {
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &discarded)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_discard",
            &discarded,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(discarded)
    }

    /// Engine-catalog search — the DISCOVERY lens, Active keys only.
    ///
    /// The query is matched two ways at once: normalized against the catalog
    /// name (so a hyphenated query finds an underscored name, the same
    /// normalization every connector token gets) and case-insensitively as a
    /// substring of the summary. A blank query lists the whole live catalog.
    /// Results come back in name order — the index walk is the ordering.
    pub fn search_connector_catalog(&self, query: &str) -> Result<Vec<ConnectorCatalogEntry>> {
        let name_query = normalize_connector_key(query);
        let summary_query = query.trim().to_lowercase();
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, CONNECTOR_CATALOG_NAME_INDEX_PREFIX)?
        {
            let (_, raw_id) = entry?;
            ids.push(connector_catalog_index_entity_id(&raw_id)?);
        }
        let mut hits = Vec::new();
        for id in ids {
            let record = read_connector_key_in_txn(&self.store, &rtxn, &id)?
                .ok_or(Error::CorruptedIndex("connector catalog name index row"))?;
            // Removed connectors keep their index row and their entry; the
            // discovery lens is live-only, so the status filter is what
            // hides them here while `describe_connector` still resolves them.
            if record.status != ConnectorKeyStatus::Active {
                continue;
            }
            let Some(catalog) = record.catalog else {
                continue;
            };
            if catalog.name.contains(&name_query)
                || catalog.summary.to_lowercase().contains(&summary_query)
            {
                hits.push(catalog);
            }
        }
        Ok(hits)
    }

    /// Describes one catalogued connector — the HISTORY lens. Resolves a
    /// REMOVED connector too (reporting `Revoked`), because the name index is
    /// permanent. The key metadata it reports is value-less: `secret_ref`
    /// names a custody record, it is never a secret.
    pub fn describe_connector(&self, name: &str) -> Result<Option<ConnectorDescription>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_ref, record)) = self.catalog_record_in_txn(&rtxn, name)? else {
            return Ok(None);
        };
        let Some(entry) = record.catalog else {
            return Ok(None);
        };
        let budgeted_as_sends = entry.call_class.debits_sends();
        Ok(Some(ConnectorDescription {
            key_ref,
            entry,
            connector: record.connector,
            status: record.status,
            secret_ref: record.secret_ref,
            key_generation: record.key_generation,
            registered_at: record.registered_at,
            status_changed_at: record.status_changed_at,
            budgeted_as_sends,
        }))
    }

    /// Routes a call to one catalogued connector — the EXECUTION lens, so
    /// `Some` ONLY while the governing key is Active (a removed or suspended
    /// connector reports `None` and stops execution at the lookup).
    ///
    /// `budgeted_as_sends` is ENTRY-WIDE and there is deliberately no verb
    /// parameter: ARCH-0054's Send class is a property of what the connector
    /// IS, not of which verb a caller reaches for. An UNCLASSIFIED key
    /// (`catalog = None`) has no route at all, which leaves the executor on
    /// the canon default — scoped-MCP tool calls unbudgeted.
    ///
    /// This is metadata only. The live chokepoint keeps charging through
    /// `charge_effector_budgets` until the named wiring follow-on consults
    /// this route.
    pub fn route_connector_call(&self, name: &str) -> Result<Option<ConnectorCallRoute>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_ref, record)) = self.catalog_record_in_txn(&rtxn, name)? else {
            return Ok(None);
        };
        if record.status != ConnectorKeyStatus::Active {
            return Ok(None);
        }
        let Some(entry) = record.catalog else {
            return Ok(None);
        };
        Ok(Some(ConnectorCallRoute {
            key_ref,
            connector: record.connector,
            call_class: entry.call_class,
            budgeted_as_sends: entry.call_class.debits_sends(),
            verbs: entry.verbs,
            secret_ref: record.secret_ref,
        }))
    }

    /// Resolves a catalog name (normalized) to its key through the permanent
    /// name index, regardless of status.
    fn catalog_record_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        name: &str,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let name_key = connector_catalog_name_index_key(&normalize_connector_key(name));
        let Some(raw_id) = self.store.vault_meta.get(rtxn, &name_key)? else {
            return Ok(None);
        };
        let id = connector_catalog_index_entity_id(&raw_id)?;
        let record = read_connector_key_in_txn(&self.store, rtxn, &id)?
            .ok_or(Error::CorruptedIndex("connector catalog name index row"))?;
        Ok(Some((id, record)))
    }

    fn apply_connector_key_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_record = decode_connector_key_body(&data)?;
        let new_index_key = connector_key_index_key(&new_record.connector, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("connector key entity header"));
            };
            if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
                return Err(Error::CorruptedIndex("connector key entity type"));
            }
            let old_record = decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(connector_key_index_key(&old_record.connector, id)?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CONNECTOR_KEY,
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
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}

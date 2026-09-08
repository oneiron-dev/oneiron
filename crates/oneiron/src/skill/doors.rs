//! Typed Vault doors for SKILL records.

use rmpv::Value;

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::temporal::TimeRange;

use super::codec::{decode_skill_record, encode_skill_record};
use super::lifecycle::SkillLifecycle;
use super::record::SkillRecord;
use super::validate::validate_skill_update;

impl Vault {
    /// Typed SKILL put door. New records are born `candidate` — all three
    /// birth paths (Dreamer distill, conversation convert, hub import)
    /// enter the one lifecycle machine at the same state; the admission
    /// gate (ONE-1449) owns `candidate → active`. Existing records flow
    /// through the update gate at the batch chokepoint. The raw
    /// `put_entity` door stays state-agnostic on purpose: sync remat and
    /// legacy-body upgrades write already-lifecycled records.
    ///
    /// ONE-1449 armed that gate for the AUTOMATED road only:
    /// [`crate::skill_optimize::admit_optimized_skill_revision`] is the one
    /// door an optimizer-born candidate reaches `active` through, and the
    /// batch chokepoint refuses a bare flip of one. A user-authored candidate
    /// is admitted by its owner through [`Vault::update_skill_record`],
    /// exactly as before — the arming binds the loop, not the person.
    pub fn put_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.put_skill_record_in_txn(wtxn, id, record, occurred, learned_at)
        })
    }

    /// [`Vault::put_skill_record`] inside the caller's write transaction.
    ///
    /// Same door, same checks — only the transaction boundary moves out. Birth
    /// paths whose DEDUP decision must not race their create need the lookup
    /// and the write under one transaction (the conversation-convert door,
    /// ONE-1446), and a create that commits on its own would let two callers
    /// both read "no holder" and both mint.
    pub(crate) fn put_skill_record_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        if self.store.entities.get(&*wtxn, id.as_bytes())?.is_none() {
            if record.lifecycle_status != SkillLifecycle::Candidate {
                return Err(Error::InvalidSkillBody(
                    "new skills are born candidate; the admission gate activates them",
                ));
            }
            // Fork lineage is not forgeable at the local create door: a
            // named parent must be a real type-7 SKILL. The DerivedFrom
            // edge stays door-authored (it references the fork, so it
            // cannot precede this create in the txn) and is not required
            // here. The batch chokepoint re-runs both checks for local
            // raw creates; sync remat (`replicated`) is exempt.
            if let Some(parent) = record.forked_from {
                self.validate_local_fork_parent(wtxn, id, &parent)?;
            }
        }
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, false)
    }

    /// Read INSIDE the caller's transaction: the parent this create trusts must
    /// be the parent the create commits against.
    fn validate_local_fork_parent(
        &self,
        wtxn: &heed::RwTxn<'_>,
        fork_id: &EntityId,
        parent: &EntityId,
    ) -> Result<()> {
        if parent == fork_id {
            return Err(Error::InvalidSkillBody(
                "forkedFrom cannot name the fork itself",
            ));
        }
        let Some(raw) = self.store.entities.get(wtxn, parent.as_bytes())? else {
            return Err(Error::InvalidSkillBody(
                "forkedFrom parent must exist as a type-7 SKILL",
            ));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody(
                "forkedFrom parent must exist as a type-7 SKILL",
            ));
        }
        Ok(())
    }

    /// Forks a skill into a new entity — the ONE fork law, shared with the
    /// ordinary AGENT_DEF row fork (ONE-1444/ONE-1890, where `forked_from`
    /// names the parent ROW id): a local edit of an import is a fork, never
    /// an in-place overwrite. The fork is a NEW entity
    /// carrying `forked_from` lineage plus a `DerivedFrom` lineage edge to
    /// the parent (written in the same transaction); upstream auto-updates
    /// stop at the fork and arrive as merge PROPOSALs against the parent.
    ///
    /// The fork is stamped as an explicit local act
    /// (`source = UserStated`, `approval = Approved`) and is born
    /// `candidate` on its own version line: edited content re-enters
    /// through the admission gate like any other birth. `content_hash` is
    /// cleared — identity is recomputed from the edited tree, so an
    /// unedited fork never collides with its parent's canonical identity
    /// row.
    pub fn fork_skill_record(
        &self,
        parent_id: &EntityId,
        fork_id: &EntityId,
        fork_skill_id: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SkillRecord> {
        let parent = self
            .get_skill_record(parent_id)?
            .ok_or(Error::EntityNotFound)?;
        if fork_id == parent_id || self.get_raw(fork_id)?.is_some() {
            return Err(Error::InvalidSkillBody("fork target entity already exists"));
        }
        if fork_skill_id == parent.skill_id {
            return Err(Error::InvalidSkillBody(
                "fork must take its own skillId; the parent keeps the imported one",
            ));
        }
        let mut fork = SkillRecord::new(
            fork_skill_id,
            parent.desc.clone(),
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            parent.dependencies.clone(),
            Value::Map(vec![
                (Value::from("forkOf"), Value::from(parent.skill_id.as_str())),
                (Value::from("forkOfEntity"), Value::from(parent_id.to_hex())),
                (
                    Value::from("forkOfVersion"),
                    Value::from(parent.version.as_str()),
                ),
            ]),
        );
        fork.forked_from = Some(*parent_id);
        let data = encode_skill_record(&fork)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.apply_skill_record_body(&mut wtxn, fork_id, occurred, learned_at, data, false)?;
        self.batch_in()
            .edge(
                fork_id,
                EdgeKind::DerivedFrom,
                parent_id,
                EdgeKind::DerivedFrom.default_weight().unwrap_or(0.2),
            )
            .apply(&mut wtxn)?;
        wtxn.commit()?;
        Ok(fork)
    }

    /// Marks an old revision superseded by an admitted new revision of the
    /// SAME skill (ARCH-0053 §6): the old record flips
    /// `active → superseded` (frozen; never loads as canon again) and a
    /// `Supersedes` edge `new → old` records the succession, in one
    /// transaction. This door does NOT activate `new_id` — admission
    /// (`candidate → active`, ONE-1449) is the gate's act, not this one's.
    pub fn supersede_skill_record(
        &self,
        old_id: &EntityId,
        new_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if old_id == new_id {
            return Err(Error::InvalidSkillBody(
                "a skill revision cannot supersede itself",
            ));
        }
        let old = self
            .get_skill_record(old_id)?
            .ok_or(Error::EntityNotFound)?;
        let new = self
            .get_skill_record(new_id)?
            .ok_or(Error::EntityNotFound)?;
        if new.skill_id != old.skill_id {
            return Err(Error::InvalidSkillBody(
                "supersession links two revisions of one skill",
            ));
        }
        if new.version == old.version {
            return Err(Error::InvalidSkillBody(
                "superseding revision must carry a new version",
            ));
        }
        // Canon (ARCH-0053 §6): superseded means "new version ADMITTED".
        // A non-active successor would leave the skillId with no admitted
        // canon revision at all. Activation itself stays the admission
        // gate's act (ONE-1449): callers admit first, then supersede.
        if new.lifecycle_status != SkillLifecycle::Active {
            return Err(Error::InvalidSkillBody(
                "superseding revision must be admitted (active) before it supersedes",
            ));
        }
        // Explicit Active check, NOT `can_transition(Superseded)`: the table's
        // self-loop allowance would let an already-superseded revision pass and
        // mint a second (bogus) succession edge.
        if old.lifecycle_status != SkillLifecycle::Active {
            return Err(Error::InvalidSkillBody(
                "only an active skill revision can be superseded",
            ));
        }
        let mut frozen = old;
        frozen.lifecycle_status = SkillLifecycle::Superseded;
        let data = encode_skill_record(&frozen)?;
        self.batch()
            .put(old_id, ENTITY_TYPE_SKILL, occurred, learned_at, &data)
            .edge(
                new_id,
                EdgeKind::Supersedes,
                old_id,
                EdgeKind::Supersedes.default_weight().unwrap_or(0.3),
            )
            .commit()
    }

    /// Typed SKILL update door. Rejects transitions INTO `superseded`:
    /// supersession is [`Vault::supersede_skill_record`]'s act (admitted
    /// successor + succession edge) — a bare flip here would orphan a
    /// frozen revision with no successor. The substrate gate
    /// (`validate_skill_update`) deliberately still admits the transition:
    /// the supersede door's own batch write and sync replay flow through
    /// it.
    pub fn update_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_skill_record_in_txn(&wtxn, id)?;
        if record.lifecycle_status == SkillLifecycle::Superseded
            && existing.lifecycle_status != SkillLifecycle::Superseded
        {
            return Err(Error::InvalidSkillBody(
                "supersession is supersede_skill_record's act; a bare flip would orphan a frozen revision",
            ));
        }
        validate_skill_update(&existing, record)?;
        // ONE-1892's activation scan consult is deliberately NOT here: it runs
        // at the batch materialization chokepoint every SKILL body converges
        // on (`skill_scan::escalate_activation_approval_in_txn`), so
        // `put_entity` and a raw `batch().put` are governed by the same dial
        // this door is. A second consult on this path would only re-derive the
        // stamp the chokepoint is about to set.
        let data = encode_skill_record(record)?;
        self.apply_skill_record_body(&mut wtxn, id, occurred, learned_at, data, false)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Writes the demoted `confidence` CACHE from the reliability projector
    /// (ONE-1738), inside the caller's write transaction.
    ///
    /// Every other field is copied from the STORED record, so a cache refresh
    /// structurally cannot smuggle a content edit — and the write still runs
    /// the ordinary update gate, so the lifecycle machine and the fork law keep
    /// their say. `skill_content_changed` normalizes `confidence` away, which
    /// is what lets this land on an imported skill without a version bump.
    ///
    /// Crate-private on purpose: hosts move this value by projecting the claim
    /// ([`crate::skill_reliability::rebuild_skill_confidence_cache`]), never by
    /// asserting a number.
    ///
    /// A SUPERSEDED revision keeps the cache it was frozen with. The lifecycle
    /// machine below hard-rejects any update to a frozen revision, and this
    /// door shares its caller's write transaction — so a late outcome
    /// attributed to v1 after v2 was admitted would roll back the OUTCOME and
    /// the reliability CLAIM alongside the cache write, losing valid evidence
    /// to a materialization. Truth still lands; only the cache, which the
    /// frozen revision no longer serves anything from, is skipped.
    pub(crate) fn refresh_skill_confidence_cache_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        confidence: f32,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let stored = self.read_skill_record_in_txn(wtxn, id)?;
        if stored.lifecycle_status == SkillLifecycle::Superseded {
            return Ok(());
        }
        let mut refreshed = stored.clone();
        refreshed.confidence = confidence;
        validate_skill_update(&stored, &refreshed)?;
        let data = encode_skill_record(&refreshed)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, false)
    }

    pub(crate) fn apply_hub_sync_skill_record(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, true)
    }

    pub(crate) fn apply_hub_import_skill_record(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if record.source != ClaimSource::Imported {
            return Err(Error::InvalidSkillBody(
                "hub import package must carry imported source",
            ));
        }
        let data = encode_skill_record(record)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, false)
    }

    pub fn get_skill_record(&self, id: &EntityId) -> Result<Option<SkillRecord>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    pub(crate) fn read_skill_record_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<SkillRecord> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    /// Crate-private, and the ONE way an engine-authored state flip reaches a
    /// SKILL body inside a caller's transaction (ONE-1447's stale fold is the
    /// second such writer after the confidence cache): every caller has already
    /// run [`validate_skill_update`] against the STORED record, and the batch
    /// chokepoint runs it again.
    pub(crate) fn apply_skill_record_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        hub_sync_imported: bool,
    ) -> Result<()> {
        // ONE-1741: a content-hash change no longer relocates scan verdicts.
        // Verdicts anchor to the immortal content bytes, so the departing hash's
        // verdicts stay discoverable on their own anchor and this holder simply
        // stops carrying that hash (the content-hash index is maintained by the
        // batch put/delete paths).
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }
}

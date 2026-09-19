//! vault_meta scope/tier-A rows, Vault impl, and agent-visible assembly block.

use heed::RoTxn;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body,
    encode_claim_body, validate_claim_body_bytes,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::interlocutor::{InterlocutorSet, InterlocutorStamp};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;

use super::disclosure_tier;
use super::position::scope_admits_record;
use super::scope::{
    ScopeCeiling, decode_scope_ceiling_body, encode_scope_ceiling_body, meet_all,
    scope_ceiling_body_value,
};
use super::tier_classification::{
    DISCLOSURE_TIER_VALUE_TIER_A, DisclosureMode, DisclosureTier, PREDICATE_DISCLOSURE_SCOPE,
    PREDICATE_DISCLOSURE_TIER, is_disclosure_claim_predicate, read_stored_claim_body,
    validate_disclosure_claim_structure,
};

/// `vault_meta` row key prefix for per-contact scope rows (enforcement truth;
/// one O(1) read per non-owner interlocutor, the off-record-fence shape).
const DISCLOSURE_SCOPE_KEY_PREFIX: &[u8] = b"disclosure.scope.v2:";

/// `vault_meta` row key prefix for owner Tier-A mark rows.
const DISCLOSURE_TIER_A_KEY_PREFIX: &[u8] = b"disclosure.tier_a.v1:";

pub(super) fn disclosure_scope_meta_key(contact_id: &EntityId) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(DISCLOSURE_SCOPE_KEY_PREFIX.len() + contact_id.as_bytes().len());
    key.extend_from_slice(DISCLOSURE_SCOPE_KEY_PREFIX);
    key.extend_from_slice(contact_id.as_bytes());
    key
}

pub(super) fn disclosure_tier_a_meta_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DISCLOSURE_TIER_A_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(DISCLOSURE_TIER_A_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn disclosure_tier_a_marked_in(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &disclosure_tier_a_meta_key(id))?
        .is_some())
}

/// Deterministic claim-mirror id for a subject's disclosure claim: the CID-7
/// overwrite pattern — re-sets rewrite the SAME claim entity, so exactly one
/// owner-visible claim per (family, subject) exists and a rewrite supersedes
/// the prior value.
fn derive_disclosure_claim_id(prefix: &[u8], subject: &EntityId) -> Result<EntityId> {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
}

pub(super) fn disclosure_scope_claim_id(contact_id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.scope.claim.v2:", contact_id)
}

pub(super) fn disclosure_tier_claim_id(id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.tier.claim.v1:", id)
}

fn ceiling_updated_at() -> u64 {
    crate::unix_seconds_now()
}

impl Vault {
    /// Narrows a contact clearance and atomically updates its claim mirror.
    /// Missing or corrupt prior clearance is bottom. Widening requires
    /// `authorize_counterparty_disclosure_scope` and an exact signed intent.
    pub fn set_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        ceiling: &ScopeCeiling,
    ) -> Result<()> {
        self.write_counterparty_disclosure_scope(contact_id, ceiling, None)
    }

    /// Applies an exact owner-signed, one-shot clearance change. Unlike the
    /// unsigned setter, this door may widen the existing clearance.
    pub fn authorize_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        ceiling: &ScopeCeiling,
        authorization: &super::DisclosureScopeAuthorization,
    ) -> Result<()> {
        self.write_counterparty_disclosure_scope(contact_id, ceiling, Some(authorization))
    }

    fn write_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        ceiling: &ScopeCeiling,
        authorization: Option<&super::DisclosureScopeAuthorization>,
    ) -> Result<()> {
        ceiling.validate()?;
        let data = encode_scope_ceiling_body(ceiling)?;
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(authorization) = authorization {
            authorization.consume(self, &mut wtxn, contact_id, ceiling)?;
        } else {
            let previous = self
                .store
                .vault_meta
                .get(&wtxn, &disclosure_scope_meta_key(contact_id))?
                .and_then(|raw| decode_scope_ceiling_body(&raw).ok())
                .unwrap_or_else(ScopeCeiling::bottom);
            if ceiling.meet(&previous) != *ceiling {
                return Err(Error::Gate(
                    crate::error::GateError::DisclosureClampViolation(
                        "clearance widening requires owner-signed intent",
                    ),
                ));
            }
        }
        let raw = self
            .store
            .entities
            .get(&wtxn, contact_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        self.store
            .vault_meta
            .put(&mut wtxn, &disclosure_scope_meta_key(contact_id), &data)?;
        let claim_id = disclosure_scope_claim_id(contact_id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_SCOPE,
            ClaimSubject::Entity(*contact_id),
            scope_ceiling_body_value(ceiling),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, ceiling_updated_at())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Revokes a contact's disclosure clearance: deletes the enforcement row
    /// and supersedes the owner-visible `disclosure.scope` claim mirror. A
    /// missing row resolves to [`ScopeCeiling::bottom`] (fail-closed), so
    /// revocation-by-delete and storing bottom are equivalent at every
    /// enforcement point.
    pub fn clear_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        cleared_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self
            .store
            .entities
            .get(&wtxn, contact_id.as_bytes())?
            .is_none()
        {
            return Err(Error::EntityNotFound);
        }
        self.store
            .vault_meta
            .delete(&mut wtxn, &disclosure_scope_meta_key(contact_id))?;
        let claim_id = disclosure_scope_claim_id(contact_id)?;
        if let Some(raw) = self.store.entities.get(&wtxn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type == ENTITY_TYPE_CLAIM
                && let Some(payload) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                && let Ok(mut body) = decode_claim_body(payload, true)
                && body.predicate == PREDICATE_DISCLOSURE_SCOPE
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                body.lifecycle = ClaimLifecycleStatus::Superseded;
                body.valid_to = Some(cleared_at);
                self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &body, cleared_at)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the enforcement-truth clearance row for a contact. Missing row
    /// -> `Ok(None)`; resolution maps it to [`ScopeCeiling::bottom`].
    pub fn counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
    ) -> Result<Option<ScopeCeiling>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &disclosure_scope_meta_key(contact_id))?
        else {
            return Ok(None);
        };
        decode_scope_ceiling_body(&bytes).map(Some)
    }

    /// Owner-marks an entity Tier A (design §7 rule 5): meta row plus the
    /// owner-visible `disclosure.tier` claim, one wtxn.
    pub fn set_disclosure_tier_a(&self, id: &EntityId, marked_at: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_none() {
            return Err(Error::EntityNotFound);
        }
        self.store.vault_meta.put(
            &mut wtxn,
            &disclosure_tier_a_meta_key(id),
            &marked_at.to_le_bytes(),
        )?;
        let claim_id = disclosure_tier_claim_id(id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_TIER,
            ClaimSubject::Entity(*id),
            Value::from(DISCLOSURE_TIER_VALUE_TIER_A),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, marked_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Clears an owner Tier-A mark: deletes the meta row and supersedes the
    /// `disclosure.tier` claim.
    ///
    /// The stored body at the derived mirror id is only superseded when it
    /// actually IS this family's `disclosure.tier` mirror. A foreign claim
    /// squatting that id (the id is a public sha256 derivation, so any
    /// caller can compute it and write there through the normal gated
    /// `put_claim` door) is left untouched rather than re-written through
    /// the engine-internal door below.
    pub fn clear_disclosure_tier_a(
        &self,
        id: &EntityId,
        cleared_at: u64,
        authorization: &super::DisclosureScopeAuthorization,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        authorization.consume_transcript(
            self,
            &mut wtxn,
            authorization.clear_tier_a_transcript(id, cleared_at),
        )?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_none() {
            return Err(Error::EntityNotFound);
        }
        self.store
            .vault_meta
            .delete(&mut wtxn, &disclosure_tier_a_meta_key(id))?;
        let claim_id = disclosure_tier_claim_id(id)?;
        if let Some(raw) = self.store.entities.get(&wtxn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type == ENTITY_TYPE_CLAIM
                && let Some(payload) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                && let Ok(mut body) = decode_claim_body(payload, true)
                && body.predicate == PREDICATE_DISCLOSURE_TIER
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                body.lifecycle = ClaimLifecycleStatus::Superseded;
                body.valid_to = Some(cleared_at);
                self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &body, cleared_at)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Returns whether an owner Tier-A mark row exists for `id`.
    pub fn disclosure_tier_a_marked(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        disclosure_tier_a_marked_in(&self.store, &rtxn, id)
    }

    /// Writes one disclosure claim mirror through the `apply_ops` claim
    /// door.
    ///
    /// The put uses the ENGINE-INTERNAL claim door
    /// (`allow_reserved_predicate: true`, the door the provenance unit
    /// uses): these mirrors are deterministic engine records of an action
    /// the owner just took through a dedicated owner-session Vault method
    /// (I6 — no HTTP path, no message-content path), so the first-party
    /// consent gate's criticality floor does not re-ask the owner.
    ///
    /// PREDICATE CONTAINMENT (load-bearing): the door refuses any predicate
    /// outside [`crate::disclosure::DISCLOSURE_CLAIM_PREDICATES`] before it writes. That makes
    /// the safety argument for skipping the write gate STRUCTURAL rather
    /// than a call-site convention — no body reaching this door can carry a
    /// caller-chosen predicate through the gate-exempt path. The strict
    /// pre-validation (`allow_reserved = false`) additionally rejects any
    /// reserved `edge.*` predicate, and the body passes the full
    /// disclosure-family structural validation either way.
    pub(super) fn put_disclosure_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim_id: &EntityId,
        body: &ClaimBody,
        learned_at: u64,
    ) -> Result<()> {
        if !is_disclosure_claim_predicate(&body.predicate) {
            return Err(Error::InvalidClaimBody(
                "disclosure claim door refuses predicates outside the disclosure family",
            ));
        }
        validate_disclosure_claim_structure(body)?;
        let data = encode_claim_body(body)?;
        validate_claim_body_bytes(&data, false)?;
        let mut ops = vec![BatchOp::Put {
            id: *claim_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }];
        if let ClaimSubject::Entity(subject) = body.subject {
            ops.push(BatchOp::Edge {
                src: *claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }
}

/// The resolved disclosure state one context assembly is clamped against:
/// mode, interlocutor set, and the five-axis non-owner clearance meet. One value feeds builder, board, and response so the response can
/// never describe a different clamp than the one applied (design §11 rule 6).
#[derive(Debug, Clone)]
pub struct DisclosureContext {
    mode: DisclosureMode,
    interlocutors: InterlocutorSet,
    pub(super) scope: ScopeCeiling,
    pub(super) generation: Option<super::generation::GenerationStamp>,
}

impl DisclosureContext {
    /// Resolves the room's disclosable set: `public ∪ (∩ clearances of all
    /// non-owner present)` (ILDF2 room rule). P1: branches on
    /// `non_owner(roster).is_empty()` BEFORE any fold — an empty non-owner
    /// roster resolves to [`ScopeCeiling::top`], never ∅, never first().
    /// Fail-closed: an unknown party, a revoked or missing clearance, or a
    /// row that FAILS TO DECODE contributes [`ScopeCeiling::bottom`] as a
    /// roster MEMBER (V3 — never roster-absence), so the meet denies
    /// everything but public. Corruption never propagates as an error from
    /// this path (§14.5: the clamp only ever narrows); only storage I/O
    /// failures stay loud. The owner-facing read
    /// (`Vault::counterparty_disclosure_scope`) keeps erroring loudly so
    /// corruption stays visible on the consent surface.
    ///
    /// This resolves a snapshot. In-flight generation uses `DisclosureSession`
    /// so roster changes invalidate both context packs and transcript turns,
    /// and each output chunk crosses its generation's publication barrier.
    pub fn resolve(vault: &Vault, set: InterlocutorSet) -> Result<Self> {
        let mode = DisclosureMode::from_set(&set);
        // P1: the empty-family branch comes BEFORE any fold.
        let non_owner: Vec<_> = set.non_owner().collect();
        let scope = if non_owner.is_empty() {
            // P1: absence of non-owner members is TOP, not an unknown member.
            ScopeCeiling::top()
        } else {
            let txn = vault.store.env.read_txn()?;
            let mut ceilings = Vec::with_capacity(non_owner.len());
            for entry in non_owner {
                ceilings.push(Self::member_ceiling(&vault.store, &txn, entry)?);
            }
            meet_all(&ceilings)
        };
        Ok(Self {
            mode,
            interlocutors: set,
            scope,
            generation: None,
        })
    }

    /// One roster member's clearance contribution: the stored ceiling for a
    /// known contact, else [`ScopeCeiling::bottom`]. A present-but-unknown
    /// party is a bottom-clearance MEMBER (V3), never roster-absence.
    fn member_ceiling(
        store: &Store,
        txn: &RoTxn<'_>,
        entry: &crate::interlocutor::Interlocutor,
    ) -> Result<ScopeCeiling> {
        let Some(hex) = entry.contact_ref() else {
            return Ok(ScopeCeiling::bottom());
        };
        let Ok(contact_id) = EntityId::from_hex(hex) else {
            return Ok(ScopeCeiling::bottom());
        };
        let Some(raw) = store.entities.get(txn, contact_id.as_bytes())? else {
            return Ok(ScopeCeiling::bottom());
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(ScopeCeiling::bottom());
        };
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Ok(ScopeCeiling::bottom());
        }
        let Ok(record) = crate::counterparty_contact::decode_counterparty_contact_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        ) else {
            return Ok(ScopeCeiling::bottom());
        };
        if record.status != crate::counterparty_contact::CounterpartyContactStatus::Active {
            return Ok(ScopeCeiling::bottom());
        }
        Ok(store
            .vault_meta
            .get(txn, &disclosure_scope_meta_key(&contact_id))?
            .and_then(|bytes| decode_scope_ceiling_body(&bytes).ok())
            .unwrap_or_else(ScopeCeiling::bottom))
    }

    /// The private-room meet (TOP for an empty non-owner roster). Admission
    /// unions its downset with the independent public downset. An axis-wise
    /// join would erase private world/project/facet restrictions.
    #[must_use]
    pub fn disclosable_set(&self) -> &ScopeCeiling {
        &self.scope
    }

    #[must_use]
    pub fn mode(&self) -> DisclosureMode {
        self.mode
    }

    #[must_use]
    pub fn interlocutors(&self) -> &InterlocutorSet {
        &self.interlocutors
    }

    /// Rejects a generation snapshot invalidated by a roster update.
    pub(crate) fn ensure_current(&self) -> Result<()> {
        if let Some(generation) = &self.generation {
            generation.ensure_current()?;
        }
        Ok(())
    }

    pub(crate) fn admits(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        claim_body: Option<&ClaimBody>,
    ) -> Result<bool> {
        self.ensure_current()?;
        if self.mode == DisclosureMode::OwnerAlone {
            if let Some(generation) = &self.generation {
                generation.observe(*id)?;
            }
            return Ok(true);
        }
        let decoded;
        let body = if entity_type == ENTITY_TYPE_CLAIM {
            match claim_body {
                Some(body) => Some(body),
                None => {
                    decoded = read_stored_claim_body(store, rtxn, id)?;
                    decoded.as_ref()
                }
            }
        } else {
            None
        };
        if disclosure_tier(store, rtxn, id, entity_type, body)? == DisclosureTier::TierA {
            return Ok(false);
        }
        let admitted = scope_admits_record(
            store,
            rtxn,
            &self.live_ceiling(store, rtxn)?,
            id,
            entity_type,
            body,
        )?;
        if admitted && let Some(generation) = &self.generation {
            generation.observe(*id)?;
        }
        Ok(admitted)
    }

    pub(super) fn live_ceiling(&self, store: &Store, txn: &RoTxn<'_>) -> Result<ScopeCeiling> {
        let mut live_ceiling = self.scope.clone();
        for member in self.interlocutors.non_owner() {
            live_ceiling = live_ceiling.meet(&Self::member_ceiling(store, txn, member)?);
        }
        Ok(live_ceiling)
    }

    /// Builds the agent-visible assembly block for this clamp.
    #[must_use]
    pub fn assembly(&self, clamped_out: u64) -> DisclosureAssembly {
        DisclosureAssembly {
            mode: self.mode.as_str().to_owned(),
            notice: (self.mode == DisclosureMode::Supervised)
                .then(|| presence_discretion_notice(&self.interlocutors)),
            interlocutors: self.interlocutors.stamps(),
            clamped_out,
        }
    }

    /// The OF-369 receipt stamp for this clamp (design §10):
    /// `"mode=<mode>;interlocutors=<class>:<label>[,...]"`.
    ///
    /// AUDIT INTEGRITY: labels are caller-supplied display data, and J3
    /// pinned this stamp as the security-relevant record of the assembly.
    /// Every structural character (`%`, `=`, `;`, `,`, `:`) and every
    /// control byte in a label is percent-encoded before it enters the
    /// stamp, so no label can ambiguate the delimiter grammar or forge an
    /// entry; a parser recovers the exact label by percent-decoding. Mode
    /// and class strings are engine-fixed vocabulary and never escaped.
    #[must_use]
    pub fn receipt_stamp(&self) -> String {
        let interlocutors = self
            .interlocutors
            .entries()
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}",
                    entry.class().as_str(),
                    escape_receipt_stamp_label(entry.label())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("mode={};interlocutors={interlocutors}", self.mode.as_str())
    }
}

/// Percent-encodes the stamp's structural characters plus `%` itself and
/// control bytes, leaving every other byte verbatim. Total and reversible:
/// every label encodes safely, so stamping can never fail on a hostile
/// label — the label is display data and must not block resolution.
fn escape_receipt_stamp_label(label: &str) -> String {
    let mut escaped = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '%' | '=' | ';' | ',' | ':' => {
                escaped.push('%');
                escaped.push_str(&format!("{:02X}", ch as u32));
            }
            ch if ch.is_control() => {
                for byte in ch.to_string().as_bytes() {
                    escaped.push('%');
                    escaped.push_str(&format!("{byte:02X}"));
                }
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

/// Agent-visible disclosure block riding the context-pack response and the
/// MEMORIES board. `clamped_out` counts scored candidates dropped by the
/// clamp's CANDIDATE SWEEP this assembly (the walk/edge/final enforcement
/// points drop without counting — design §9); it is diagnostic and is NOT
/// persisted on receipts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisclosureAssembly {
    pub mode: String,
    /// The presence-discretion notice; `Some` iff Supervised.
    pub notice: Option<String>,
    pub interlocutors: Vec<InterlocutorStamp>,
    pub clamped_out: u64,
}

/// The pinned named-presence discretion notice (design §10). Enumerates
/// NON-OWNER entries only, in set order — the Owner entry never appears
/// under "Others present".
#[must_use]
pub fn presence_discretion_notice(set: &InterlocutorSet) -> String {
    let others = set
        .non_owner()
        .map(|entry| {
            let mut part = format!("{} ({}", entry.label(), entry.class().as_str());
            if let Some(relationship) = entry.relationship() {
                part.push_str(", ");
                part.push_str(relationship);
            }
            if let Some(first_touch) = entry.first_touch() {
                part.push_str(", first contact: ");
                part.push_str(first_touch.as_str());
            }
            part.push(')');
            part
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Others present: {others}. Don't volunteer personal or sensitive information; \
         if asked about private matters, defer to the owner."
    )
}

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
use crate::error::{Error, ErrorKind, Result};
use crate::interlocutor::{InterlocutorSet, InterlocutorStamp};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;

use super::disclosure_tier;
use super::scope_codec::{
    DisclosureScope, DisclosureScopeStatus, decode_disclosure_scope_body,
    disclosure_scope_body_value, encode_disclosure_scope_body,
};
use super::tier_classification::{
    DISCLOSURE_TIER_VALUE_TIER_A, DisclosureMode, DisclosureTier, PREDICATE_DISCLOSURE_SCOPE,
    PREDICATE_DISCLOSURE_TIER, is_disclosure_claim_predicate, read_stored_claim_body,
    validate_disclosure_claim_structure,
};

/// `vault_meta` row key prefix for per-contact scope rows (enforcement truth;
/// one O(1) read per non-owner interlocutor, the off-record-fence shape).
const DISCLOSURE_SCOPE_KEY_PREFIX: &[u8] = b"disclosure.scope.v1:";

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

pub(crate) fn disclosure_tier_a_marked_in(
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
    derive_disclosure_claim_id(b"disclosure.scope.claim.v1:", contact_id)
}

pub(super) fn disclosure_tier_claim_id(id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.tier.claim.v1:", id)
}

impl Vault {
    /// Sets (or replaces — dial-not-wall) the disclosure scope for a CID-7
    /// contact record: dual-writes the `vault_meta` enforcement row and the
    /// owner-visible `disclosure.scope` claim in one wtxn. Widening is one
    /// owner call, but only through this owner-session write path (I6 — no
    /// HTTP exposure in this chain).
    pub fn set_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        scope: &DisclosureScope,
    ) -> Result<()> {
        scope.validate()?;
        let data = encode_disclosure_scope_body(scope)?;
        let mut wtxn = self.store.env.write_txn()?;
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
            disclosure_scope_body_value(scope),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, scope.updated_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the enforcement-truth scope row for a contact. Missing row ->
    /// `Ok(None)`; a Revoked scope decodes fine — `DisclosureContext::resolve`
    /// maps it to deny-all.
    pub fn counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
    ) -> Result<Option<DisclosureScope>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &disclosure_scope_meta_key(contact_id))?
        else {
            return Ok(None);
        };
        decode_disclosure_scope_body(&bytes).map(Some)
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
    pub fn clear_disclosure_tier_a(&self, id: &EntityId, cleared_at: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
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
    /// outside [`DISCLOSURE_CLAIM_PREDICATES`] before it writes. That makes
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
/// mode, interlocutor set, and (owner-absent only) the DEC-0005-intersected
/// scope. One value feeds builder, board, and response so the response can
/// never describe a different clamp than the one applied (design §11 rule 6).
#[derive(Debug, Clone)]
pub struct DisclosureContext {
    mode: DisclosureMode,
    interlocutors: InterlocutorSet,
    pub(super) scope: Option<DisclosureScope>,
}

impl DisclosureContext {
    /// Derives the mode and, under `AbsenceClamp`, loads and intersects every
    /// non-owner interlocutor's scope. Fail-closed: an unknown party, a
    /// revoked scope, a missing row, or a row that FAILS TO DECODE
    /// contributes the EMPTY scope, so the intersection denies everything.
    /// Corruption never propagates as an error from this path (§14.5: the
    /// clamp only ever narrows — an abort here could surface partial state
    /// or be swallowed by a caller into a wider-than-intended pack); only
    /// storage I/O failures stay loud. The owner-facing read
    /// (`Vault::counterparty_disclosure_scope`) keeps erroring loudly so
    /// corruption stays visible on the consent surface.
    pub fn resolve(vault: &Vault, set: InterlocutorSet) -> Result<Self> {
        let mode = DisclosureMode::from_set(&set);
        let scope = if mode == DisclosureMode::AbsenceClamp && set.has_non_owner() {
            let now = crate::unix_seconds_now();
            let mut folded: Option<DisclosureScope> = None;
            for entry in set.non_owner() {
                let entry_scope = match entry.contact_ref() {
                    Some(hex) => {
                        let contact_id = EntityId::from_hex(hex)?;
                        match vault.counterparty_disclosure_scope(&contact_id) {
                            Ok(Some(scope)) if scope.status == DisclosureScopeStatus::Active => {
                                scope
                            }
                            Ok(_) => DisclosureScope::deny_all(now),
                            Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => {
                                DisclosureScope::deny_all(now)
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    None => DisclosureScope::deny_all(now),
                };
                folded = Some(match folded {
                    None => entry_scope,
                    Some(accumulated) => accumulated.intersect(&entry_scope),
                });
            }
            folded
        } else {
            None
        };
        Ok(Self {
            mode,
            interlocutors: set,
            scope,
        })
    }

    #[must_use]
    pub fn mode(&self) -> DisclosureMode {
        self.mode
    }

    #[must_use]
    pub fn interlocutors(&self) -> &InterlocutorSet {
        &self.interlocutors
    }

    /// The clamp's admission predicate: `OwnerAlone` admits everything;
    /// `Supervised` admits everything not Tier A; `AbsenceClamp` admits only
    /// non-Tier-A entities on the intersected allowlist, or claims ABOUT an
    /// allowlisted entity. Tier is checked FIRST so scope can never override
    /// tier (never-widen, I2).
    pub(crate) fn admits(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        claim_body: Option<&ClaimBody>,
    ) -> Result<bool> {
        if self.mode == DisclosureMode::OwnerAlone {
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
        if self.mode == DisclosureMode::Supervised {
            return Ok(true);
        }
        let Some(scope) = self.scope.as_ref() else {
            return Ok(false);
        };
        if scope.allows_entity(id) {
            return Ok(true);
        }
        if let Some(body) = body
            && let ClaimSubject::Entity(subject) = body.subject
        {
            return Ok(scope.allows_entity(&subject));
        }
        Ok(false)
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

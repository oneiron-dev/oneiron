//! Shared facade plumbing: [`Memory`] itself, actor/scope verification,
//! JSON<->MessagePack wire encoding, and ref/short-id utilities used across
//! the concern files. Split from the flat `facade.rs`.

use super::structural::*;
use super::*;

use rmpv::Value;

use crate::Vault;
use crate::batch::parse_short_id_value;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::companion::companion_value_to_json;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;

const SCOPE_SENSITIVITY_KEY: &str = "sensitivity";

const GATE_RECEIPT_SCAN_LIMIT: usize = 512;

/// Parses the pinned actor-key grammar `"<actor_class>:<entity_ref>"`
/// (design §4.3): `actor_class ∈ human|agent|system`, `entity_ref` a
/// short-id ref or 32-hex id. Malformed keys are typed errors, never a
/// defaulted class.
pub fn parse_actor_key(vault: &Vault, key: &str) -> FacadeResult<(EntityId, EdgeActorClass)> {
    let Some((class_str, entity_ref)) = key.split_once(':') else {
        return Err(FacadeError::bad_request_with(
            format!("actor key {key:?} is not of the form <actor_class>:<entity_ref>"),
            &["Use \"human:<ref>\", \"agent:<ref>\", or \"system:<ref>\"."],
        ));
    };
    let actor_class = match class_str {
        "human" => EdgeActorClass::Human,
        "agent" => EdgeActorClass::Agent,
        "system" => EdgeActorClass::System,
        other => {
            return Err(FacadeError::bad_request_with(
                format!("unknown actor class {other:?}"),
                &["Use one of: human, agent, system."],
            ));
        }
    };
    let actor = resolve_entity_ref(vault, entity_ref)?;
    verify_actor_binding(vault, actor, actor_class)?;
    Ok((actor, actor_class))
}

/// Resolves a facade entity ref — 32-hex id or `"<short_id>:<hash-hex>"`
/// short ref — to an [`EntityId`]. Short refs must resolve in the vault.
///
/// The short-ref grammar comes from [`crate::entity_id::parse_short_ref_syntax`],
/// which is syntax only: a prefix no registry declares still PARSES here and
/// fails below with "does not resolve". That split is what lets a retired
/// prefix resolve through its alias row while an invented one does not.
pub fn resolve_entity_ref(vault: &Vault, reference: &str) -> FacadeResult<EntityId> {
    let reference = reference.trim();
    if reference.len() == 32 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return EntityId::from_hex(reference)
            .map_err(|_| FacadeError::bad_request(format!("invalid entity id {reference:?}")));
    }
    if let Ok((short_id, content_hash)) = crate::entity_id::parse_short_ref_syntax(reference) {
        return match vault.hydrate_short_id(short_id, content_hash)? {
            Some(entry) => Ok(entry.id),
            None => Err(FacadeError::not_found(format!(
                "short ref {reference:?} does not resolve"
            ))),
        };
    }
    Err(FacadeError::bad_request_with(
        format!("entity ref {reference:?} is neither a 32-hex id nor a short ref"),
        &["Pass a 32-character hex entity id or a short ref like \"ms1:a3\"."],
    ))
}

/// Store-truth check behind every actor binding: the entity must exist
/// and its stored type must permit the asserted class.
///
/// DA-0 audit: every actor-gated non-claim mutation uses
/// [`Memory::with_verified_actor_write_txn`] so the store-truth actor
/// check and mutation share one LMDB write transaction. The enumerated verbs
/// are witness, claim_retract, put_structural, put_habit_checkin,
/// put_companion_record, put_blob_artifact, append_blob_version,
/// enqueue_consolidation, and schedule_outbound's schedule-time Gate decision
/// followed by its durable enqueue. The claim
/// doors (commit, claim_upsert, admit_imported_claim, seed_claims) are skipped:
/// `apply_claim_candidate` already revalidates their actor in the claim write
/// transaction. Reads and status/query verbs are ungated and non-mutating.
/// safe_delete is the ordered multi-transaction exception; its gate is
/// evaluated before TXN1, staged for recovery there, and appended on TXN3.
pub(crate) fn verify_actor_binding(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    let entity_type = vault.get_entity_type(&actor)?;
    verify_actor_entity_type(actor, actor_class, entity_type)
}

pub(super) fn verify_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    let entity_type = vault
        .get_raw_in(txn, &actor)?
        .map(|raw| {
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or_else(|| FacadeError::from(Error::CorruptedIndex("entity header")))
                .map(|header| header.entity_type)
        })
        .transpose()?;
    verify_actor_entity_type(actor, actor_class, entity_type)
}

/// Owner-verb teeth (ONE-1604-D2 / ESB-C).
///
/// [`verify_actor_binding`] proves the asserted actor EXISTS and that its
/// entity type admits the class. That is store truth, not authority: any
/// facade holder could name a pre-existing PERSON as `human` and exercise
/// owner verbs. This check demands the authority log agree — a folded ACTIVE
/// binding `{signing key in the live owner-capable roster, actor_ref == actor,
/// actor_class == "human" EXACTLY, live epoch}`.
///
/// Enforcement scales with declared authority: a vault with no folded genesis
/// has not declared an authority root, so it keeps the store-truth check only.
/// The moment a host establishes a root, owner verbs require the binding —
/// which is exactly the pressure that makes the atomic `[genesis, bind]`
/// ceremony the natural path. No dual-mode shim, no flag.
///
/// A missing `vault_id` is NOT one state. The fold also returns `None` when the
/// log carries several independently rooted vaults, and that collapse clears
/// `actor_bindings` wholesale — so treating every `None` as "unrooted" would
/// hand full owner rights to exactly the vault whose authority root is under
/// attack. Multi-root therefore fails CLOSED and unrooted keeps the spec'd
/// pass-through.
///
/// An UNCOMPUTABLE fold is a third state, and it is the one this gate must not
/// paper over. When an AUTHORITY_LOG row has lost its first-seen sidecar after
/// the one-shot migration ran, the readonly fold cannot decide whether a
/// delayable widen elapsed — and a `RotateKey` or `RecoveryReboot` left
/// un-applied keeps the key it RETIRES live and owner-bound. So the fold
/// refuses instead of guessing, and the refusal surfaces here as INVALID_STATE
/// (the vault's authority is broken, not the caller's request), suspending
/// every owner verb until the log is re-folded through the write path.
///
/// A PRE-MIGRATION log takes the same door for the same reason. There the
/// first-seen time is not lost but never recorded, and the only other candidate
/// — the header's `learned_at` — is peer-written: trusting it lets a legacy
/// `EnrollDevice(learned_at = 0)` present as long matured, so a child
/// `BindActor` on the freshly owner-capable key would fold ACTIVE with no veto
/// window. The fold assumes first-seen-now instead, which leaves the affected
/// widens pending, and refuses while any of them is load-bearing. Unlike the
/// lost-sidecar case this clears itself: one write-path fold records the
/// observation and the delay runs from there.
pub(super) fn verify_owner_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> FacadeResult<()> {
    let fold = vault.authority_fold_readonly_in_txn(txn).map_err(|err| {
        if crate::authority::is_corrupt_first_seen_sidecar(&err) {
            return FacadeError::new(
                FACADE_CODE_INVALID_STATE,
                format!("{err}; owner verbs are suspended"),
                &[
                    "Restore this vault's sync_state from backup, or re-import the authority log into a fresh vault so first-seen times are observed again.",
                    "A widen whose local first-seen time is lost cannot be judged elapsed or pending; no binding authorizes until it can.",
                ],
            );
        }
        if crate::authority::is_indeterminate_first_seen(&err) {
            return FacadeError::new(
                FACADE_CODE_INVALID_STATE,
                format!("{err}; owner verbs are suspended"),
                &[
                    "Run a write-path authority fold (any authority-log write, or `authority_fold`) so this vault records when it first observed the pending entries.",
                    "The delay then runs from that local observation; a widen's first-seen time is never taken from the peer-claimed learned_at metadata.",
                ],
            );
        }
        FacadeError::from(err)
    })?;
    if fold.vault_root_is_conflicted() {
        return Err(FacadeError::new(
            FACADE_CODE_INVALID_STATE,
            "authority log folds to conflicting vault roots; owner verbs are suspended".to_owned(),
            &[
                "Resolve the authority fork: keep the entries of the legitimate root and drop the foreign ones.",
                "A vault cannot have two authority roots; no binding authorizes until one wins.",
            ],
        ));
    }
    if fold.vault_id.is_none() {
        return Ok(());
    }
    if crate::authority::actor_binding_is_active(&fold, &actor, "human") {
        return Ok(());
    }
    Err(FacadeError::new(
        FACADE_CODE_FORBIDDEN,
        format!(
            "actor {} holds no active owner binding in the authority log",
            actor.to_hex()
        ),
        &[
            "Establish an owner binding with a BindActor entry signed by an owner device.",
            "Actor keys assert identity; the authority log decides whether it holds.",
        ],
    ))
}

/// The COMPLETE deletion-authority predicate, evaluatable inside any read or
/// write transaction: actor binding + human class + folded owner binding.
///
/// It exists as one function because it is evaluated TWICE per gated delete and
/// the two evaluations must be identical. `evaluate_deletion_gate` runs it in
/// its own read txn to mint the decision record; `delete_entity_with_reason_impl`
/// runs it AGAIN inside the destructive write txn. Anything checked only in the
/// first pass is checked in a snapshot that is already stale by the time the
/// purge commits — a revocation landing in that window would be invisible, which
/// is exactly the TOCTOU the second pass closes. Split the two lists and they
/// drift; keep them here and they cannot.
///
/// The sibling owner verbs already fold inside their write txns
/// (`claim_retract`, `put_structural`), so this makes deletion the third
/// consistent arm rather than introducing a new rule.
pub(crate) fn verify_deletion_authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    verify_actor_binding_in_txn(vault, txn, actor, actor_class)?;
    if actor_class != EdgeActorClass::Human {
        return Err(FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "actor class {} may not delete entities; deletion is an owner verb",
                actor_class.gate_actor_class(),
            ),
            &[
                "Bind a human-class owner actor key to delete.",
                "Agents withdraw their own claims via claim_retract.",
            ],
        ));
    }
    verify_owner_actor_binding_in_txn(vault, txn, actor)
}

fn verify_actor_entity_type(
    actor: EntityId,
    actor_class: EdgeActorClass,
    entity_type: Option<u8>,
) -> FacadeResult<()> {
    let Some(entity_type) = entity_type else {
        return Err(FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "bound actor {} does not exist in this vault",
                actor.to_hex()
            ),
            &[
                "Provision the actor entity before binding its key.",
                "Actor keys assert identity; the store decides whether it holds.",
            ],
        ));
    };
    crate::provenance::validate_actor_class(entity_type, actor_class).map_err(|_| {
        FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "bound actor {} is a {} entity and cannot act as class {}",
                actor.to_hex(),
                kind_string_for_type(entity_type),
                actor_class.gate_actor_class(),
            ),
            &["Bind an actor key whose entity type matches its asserted class."],
        )
    })
}

pub(super) fn json_to_rmpv(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::from(u)
            } else if let Some(i) = n.as_i64() {
                Value::from(i)
            } else {
                Value::from(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::from(s.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::from(k.as_str()), json_to_rmpv(v)))
                .collect(),
        ),
    }
}

pub(super) fn encode_rmpv(value: &Value) -> FacadeResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| FacadeError::bad_request("body is not MessagePack-encodable"))?;
    Ok(out)
}

pub(super) fn decode_body_json(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    Some(companion_value_to_json(&value))
}

pub(crate) fn facade_provenance(verb: &str) -> Value {
    Value::Map(vec![
        (Value::from("surface"), Value::from("facade")),
        (Value::from("verb"), Value::from(verb)),
    ])
}

pub(super) fn requested_approval(
    source: ClaimSource,
    scope: Option<&serde_json::Value>,
) -> ClaimApprovalStatus {
    let auto_source = matches!(source, ClaimSource::UserStated | ClaimSource::Observed);
    let has_sensitivity_key = scope
        .and_then(serde_json::Value::as_object)
        .is_some_and(|map| map.contains_key(SCOPE_SENSITIVITY_KEY));
    if auto_source && !has_sensitivity_key {
        ClaimApprovalStatus::Auto
    } else {
        ClaimApprovalStatus::Proposed
    }
}

pub(super) fn id_from_optional_hex(id: Option<&str>) -> FacadeResult<EntityId> {
    match id {
        Some(hex) => EntityId::from_hex(hex)
            .map_err(|_| FacadeError::bad_request(format!("invalid entity id {hex:?}"))),
        None => Ok(EntityId::now()),
    }
}

pub(super) fn subject_ref_string(subject: &ClaimSubject) -> String {
    match subject {
        ClaimSubject::Entity(id) => id.to_hex(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            format!(
                "edge:{}:{}:{}",
                source.to_hex(),
                *kind as u8,
                target.to_hex()
            )
        }
    }
}

/// The actor-bound memory SURFACE: every verb takes the actor context bound
/// at construction (W3 — construction is not authority; the gate decides).
///
/// A facade by pattern, and the module still describes it that way — but the
/// pattern is an implementation note and the surface is what a caller reaches
/// for, so the type is named for the thing rather than for the shape.
pub struct Memory<'v> {
    pub(super) vault: &'v Vault,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
}

impl Vault {
    /// Binds the memory facade to an actor. The actor entity must exist and
    /// match the class (PERSON for human/agent, MACHINE for system) by the
    /// time a gated write runs — the engine enforces this per write.
    #[must_use]
    pub fn memory_facade(&self, actor: EntityId, actor_class: EdgeActorClass) -> Memory<'_> {
        Memory {
            vault: self,
            actor,
            actor_class,
        }
    }
}

impl Memory<'_> {
    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    /// The bound actor entity id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    pub(crate) fn with_verified_actor_write_txn<T>(
        &self,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> FacadeResult<T>,
    ) -> FacadeResult<T> {
        self.vault.try_with_write_txn(|wtxn| {
            verify_actor_binding_in_txn(self.vault, &*wtxn, self.actor, self.actor_class)?;
            write(wtxn)
        })
    }

    pub(super) fn resolve_ref(&self, reference: &str) -> FacadeResult<EntityId> {
        resolve_entity_ref(self.vault, reference)
    }

    /// PRE-TRANSACTION variant of the hard-delete refusal, used ONLY where
    /// the engine owns the write transaction internally (companion create,
    /// ingest admission) and the marker check cannot ride it. Residual for
    /// those two verbs: a hard delete landing between this check and the
    /// engine's commit recreates at the purged id; closing it needs in-txn
    /// engine seams (`create_companion_record_in_txn`, ingest). Every other
    /// id-accepting verb checks the marker INSIDE its own write
    /// transaction (A1).
    pub(super) fn refuse_hard_deleted_id(&self, id: &EntityId) -> FacadeResult<()> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| FacadeError::from(Error::from(err)))?;
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(&rtxn, id)?
        {
            return Err(hard_deleted_refusal(id));
        }
        Ok(())
    }

    /// Resolves the caller-asserted actor against the STORE before any
    /// authority is granted (asserted class strings are never trusted):
    /// the actor entity must exist, and its stored type must match the
    /// asserted class (PERSON ⇒ human/agent, MACHINE ⇒ system — the same
    /// rule the gated write path enforces via
    /// `provenance::validate_actor_class`). Anything unresolvable fails
    /// closed with a typed denial.
    pub(super) fn verified_actor_class(&self) -> FacadeResult<EdgeActorClass> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.actor_class)
    }

    pub(super) fn short_ref_of(&self, id: &EntityId) -> FacadeResult<Option<String>> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| FacadeError::from(Error::from(err)))?;
        let Some(raw) = self
            .vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
        else {
            return Ok(None);
        };
        let (short_id, content_hash) = parse_short_id_value(&raw)?;
        Ok(Some(format!("{short_id}:{content_hash:02x}")))
    }

    pub(super) fn short_ref_or_hex(&self, id: &EntityId) -> FacadeResult<String> {
        Ok(self.short_ref_of(id)?.unwrap_or_else(|| id.to_hex()))
    }

    pub(super) fn latest_decision_ref_for(&self, id: &EntityId) -> FacadeResult<Option<String>> {
        let decisions = self.vault.gate_decisions(GATE_RECEIPT_SCAN_LIMIT)?;
        let latest = decisions
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(id.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex());
        Ok(latest.map(|record| format!("gate:{}", record.decision_id.to_hex())))
    }
}

/// Typed refusal for creation at an id carrying the durable `dt:`
/// hard-delete marker (hard-once-seen — the same presence-only marker the
/// sync replay path consults). Without this refusal a delete-authorized
/// caller could two-step retype an entity (hard delete, then recreate
/// under a different type), and a migration re-run could resurrect data
/// the user erased.
pub(super) fn hard_deleted_refusal(id: &EntityId) -> FacadeError {
    FacadeError::new(
        FACADE_CODE_FORBIDDEN,
        format!(
            "id {} was hard-deleted and cannot be recreated through the facade",
            id.to_hex()
        ),
        &[
            "Hard-deleted ids are permanent (hard-once-seen); use a fresh id.",
            "Recreation at a purged id would resurrect erased data or retype an actor.",
        ],
    )
}

pub(super) fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

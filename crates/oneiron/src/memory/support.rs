//! Shared facade plumbing: [`Memory`] itself, actor/scope verification,
//! JSON<->MessagePack wire encoding, and ref/short-id utilities used across
//! the concern files. Split from the flat `facade.rs`.

use super::structural::*;
use super::*;

use rmpv::Value;

use crate::Vault;

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;

const SCOPE_SENSITIVITY_KEY: &str = "sensitivity";

const GATE_RECEIPT_SCAN_LIMIT: usize = 512;

/// Parses the pinned actor-key grammar `"<actor_class>:<entity_ref>"`
/// (design §4.3): `actor_class ∈ human|agent|system`, `entity_ref` a
/// short-id ref or 32-hex id. Malformed keys are typed errors, never a
/// defaulted class.
pub fn parse_actor_key(vault: &Vault, key: &str) -> MemoryResult<(EntityId, EdgeActorClass)> {
    let Some((class_str, entity_ref)) = key.split_once(':') else {
        return Err(MemoryError::bad_request_with(
            format!("actor key {key:?} is not of the form <actor_class>:<entity_ref>"),
            &["Use \"human:<ref>\", \"agent:<ref>\", or \"system:<ref>\"."],
        ));
    };
    let actor_class = match class_str {
        "human" => EdgeActorClass::Human,
        "agent" => EdgeActorClass::Agent,
        "system" => EdgeActorClass::System,
        other => {
            return Err(MemoryError::bad_request_with(
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
pub fn resolve_entity_ref(vault: &Vault, reference: &str) -> MemoryResult<EntityId> {
    let reference = reference.trim();
    if reference.len() == 32 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return EntityId::from_hex(reference)
            .map_err(|_| MemoryError::bad_request(format!("invalid entity id {reference:?}")));
    }
    if let Ok((short_id, content_hash)) = crate::entity_id::parse_short_ref_syntax(reference) {
        return match vault.hydrate_short_id(short_id, content_hash)? {
            Some(entry) => Ok(entry.id),
            None => Err(MemoryError::not_found(format!(
                "short ref {reference:?} does not resolve"
            ))),
        };
    }
    Err(MemoryError::bad_request_with(
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
/// put_blob_artifact, append_blob_version,
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
) -> MemoryResult<()> {
    let entity_type = vault.get_entity_type(&actor)?;
    verify_actor_entity_type(actor, actor_class, entity_type)
}

pub(crate) fn verify_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> MemoryResult<()> {
    let entity_type = vault
        .get_raw_in(txn, &actor)?
        .map(|raw| {
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or_else(|| MemoryError::from(Error::CorruptedIndex("entity header")))
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
/// A vault with no folded genesis has declared no authority root, so no
/// binding there can hold. Its own live embedded owner passes: the host that
/// holds the vault in process can act as it anyway, and an embedded vault has
/// no root to bind it under. Every other PERSON is refused (H149): store
/// truth alone would let any PERSON named `human`, an agent's persona
/// included, act as the owner. A self-hosted host that roots the vault binds
/// its owner in the same transaction ([`Vault::ensure_host_root_slip`]).
///
/// A missing `vault_id` is NOT one state. The fold also returns `None` when the
/// log carries several independently rooted vaults, and that collapse clears
/// `actor_bindings` wholesale. Multi-root is refused as INVALID_STATE (the
/// vault's authority is broken), unrooted as OWNER_BINDING_REQUIRED (the
/// ceremony has not run).
///
/// An UNCOMPUTABLE fold is a third state, and it is the one this gate must not
/// paper over. When an AUTHORITY_LOG row has lost its first-seen sidecar after
/// the one-shot migration ran, the readonly fold cannot decide whether an
/// approval resting on a revoked roster has outlived its stale-roster window.
/// So the fold refuses instead of guessing, and the refusal surfaces here as
/// INVALID_STATE (the vault's authority is broken, not the caller's request),
/// suspending every owner verb until the log is re-folded through the write
/// path.
pub(crate) fn verify_owner_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> MemoryResult<()> {
    let fold = vault.authority_fold_readonly_in_txn(txn).map_err(|err| {
        if crate::authority::is_corrupt_first_seen_sidecar(&err) {
            return MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                format!("{err}; owner verbs are suspended"),
                &[
                    "Restore this vault's sync_state from backup, or re-import the authority log into a fresh vault so first-seen times are observed again.",
                    "An approval whose local first-seen time is lost cannot be judged stale or live; no binding authorizes until it can.",
                ],
            );
        }
        MemoryError::from(err)
    })?;
    if let Some(floor) = fold.authority_log_memory_floor() {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "authority log fold passes its memory floor of {floor} bytes; owner verbs are suspended"
            ),
            &[
                "The log's fold would hold more than the authority_log_fold_memory_floor policy row; no binding authorizes until the row is raised on a machine that holds the fold.",
            ],
        ));
    }
    if fold.vault_root_is_conflicted() {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "authority log folds to conflicting vault roots; owner verbs are suspended".to_owned(),
            &[
                "Resolve the authority fork: keep the entries of the legitimate root and drop the foreign ones.",
                "A vault cannot have two authority roots; no binding authorizes until one wins.",
            ],
        ));
    }
    if fold.vault_id.is_none() {
        if actor == crate::vault::embedded_owner_actor_id()?
            && crate::consent::person_is_live_in_txn(vault, txn, &actor)?
        {
            return Ok(());
        }
        return Err(MemoryError::new(
            MEMORY_CODE_OWNER_BINDING_REQUIRED,
            format!(
                "actor {} holds no owner binding: this vault has no authority root",
                actor.to_hex()
            ),
            &[
                "Root the vault under its host key: a self-hosted root binds the vault's owner.",
                "Actor keys assert identity; the authority log decides whether it holds.",
            ],
        ));
    }
    if crate::authority::actor_binding_is_active(&fold, &actor, "human") {
        return Ok(());
    }
    // Its OWN code, not the generic FORBIDDEN: `safe_delete` can be refused by
    // the Gate on the same verb and that denial is FORBIDDEN too, so the code
    // is what tells a caller which door it hit — and the remedy here (mint a
    // BindActor entry signed by an owner device) is nothing the gate family's
    // advice covers.
    Err(MemoryError::new(
        MEMORY_CODE_OWNER_BINDING_REQUIRED,
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
) -> MemoryResult<()> {
    verify_actor_binding_in_txn(vault, txn, actor, actor_class)?;
    if actor_class != EdgeActorClass::Human {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "actor class {} may not delete entities; deletion is an owner verb",
                actor_class.gate_actor_class(),
            ),
            &[
                "Bind a human-class owner actor key to delete.",
                "Agents withdraw their own claims via vault.claims.retract.",
            ],
        ));
    }
    verify_owner_actor_binding_in_txn(vault, txn, actor)
}

fn verify_actor_entity_type(
    actor: EntityId,
    actor_class: EdgeActorClass,
    entity_type: Option<u8>,
) -> MemoryResult<()> {
    let Some(entity_type) = entity_type else {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
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
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
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

pub(super) fn encode_rmpv(value: &Value) -> MemoryResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| MemoryError::bad_request("body is not MessagePack-encodable"))?;
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
    Some(crate::batch::export::served_stored_messagepack_json(
        bytes, value,
    ))
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

pub(super) fn id_from_optional_hex(
    vault: &crate::Vault,
    id: Option<&str>,
) -> MemoryResult<EntityId> {
    match id {
        Some(hex) => EntityId::from_hex(hex)
            .map_err(|_| MemoryError::bad_request(format!("invalid entity id {hex:?}"))),
        None => Ok(vault.store.clock.entity_id()?),
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
#[derive(Clone)]
pub struct Memory<'v> {
    pub(super) vault: &'v Vault,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    /// Sitting selected by the authenticated host, including its peer machine.
    pub(super) session_key: Option<crate::session_lifecycle::SessionKey>,
    /// Private signer stays with the machine host; only the transcript crosses
    /// this callback, and each commit re-signs after its final approval choice.
    pub(super) machine_signer: Option<([u8; 32], &'v MachineSignFn<'v>)>,
    /// The verified credential this actor presented, when a host bound one:
    /// every read verb then reads under the key that proof builds.
    pub(super) read_proof: Option<crate::authority::VerifiedSlip>,
    /// The room turn this handle runs inside, when a host bound one.
    pub(super) room_turn: Option<crate::claim::RoomTurnCeiling>,
    /// The write origin a host bound, when one did: claim doors stamp it in
    /// place of the caller's declared source.
    pub(super) host_origin: Option<HostWriteOrigin>,
    /// Where the caller sits; see [`Memory::at`].
    pub(super) locality: crate::claim::CallerLocality,
    /// Where a host collects the rows its reads pick (`listing_producers`).
    pub(super) producers: Option<&'v super::ProducerRows>,
    /// Where a host bound its writer's TASKs to be born (`with_birth_position`).
    pub(super) birth_position: crate::federation::record_scope::BirthPosition,
    /// The vault owner's authentication, when a host bound the owner's own
    /// direct request (`with_owner_authorship`).
    pub(super) owner_authorship: Option<crate::consent::AuthenticatedOwner>,
    /// The logical verb's id a host carried in (`with_invocation`): verb
    /// hooks run once per id, across wrappers (ARCH-0080 §3).
    pub(super) invocation: Option<crate::runtime_hooks::InvocationId>,
    /// The signed instrument the caller's request was admitted on, when a
    /// host bound one (`with_invocation_slip`): work this surface queues
    /// carries it, and it is verified again when that work runs.
    pub(super) invocation_slip: Option<crate::authority::InvocationSlipBinding>,
    /// A transport's caller reaches this surface, slip or none
    /// (`with_transport_invocation`). Only the host sets it, and nothing
    /// clears it: a surface without it is the in-process host's own.
    pub(super) transport_invocation: bool,
    /// The conversation whose request this surface's work answers, when a
    /// host bound one (`with_origin_conversation`, OF-221): context, not
    /// authority.
    pub(super) origin_conversation: Option<EntityId>,
    /// The running agent attempt a host bound as this surface's TASK creator
    /// (`with_task_host`, OF-532).
    pub(super) task_host: Option<crate::task_verb::HostBinding>,
    /// The off-record session the host's request named
    /// (`in_off_record_session`): context, not authority.
    pub(super) off_record_session: Option<String>,
    /// A host bound this surface for a caller its credential admitted
    /// (`for_credential`); only that host verifies the credential again.
    pub(super) credential: bool,
    /// The door's own admission of a hook's rewritten args
    /// (`with_rewrite_admit`).
    pub(super) rewrite_admit: Option<RewriteAdmit>,
}

/// A door's admission of a verb hook's rewritten args, run on the verb's name
/// and the new args after the row's own input check, as if the caller sent
/// them (ARCH-0080 §3). The reason refuses the rewrite.
pub type RewriteAdmit = std::sync::Arc<
    dyn Fn(&str, &serde_json::Value) -> std::result::Result<(), String> + Send + Sync,
>;

/// A host-owned write origin: the source, lineage and provenance a [`Memory`]
/// surface's claim doors stamp in place of the caller's declared source.
///
/// Only the engine builds one, from a write envelope it owns: the code-run
/// dispatcher, for a guest's verb call. A host passes it through to
/// [`Memory::with_host_origin`]; nothing the guest sends reaches its fields.
#[derive(Debug, Clone, PartialEq)]
pub struct HostWriteOrigin {
    envelope: crate::WriteEnvelope,
    /// The running agent attempt the dispatcher bound as the call's TASK
    /// creator (OF-532), read from its live lease, never from the guest.
    task_host: Option<crate::task_verb::HostBinding>,
}

impl HostWriteOrigin {
    pub(crate) const fn new(envelope: crate::WriteEnvelope) -> Self {
        Self {
            envelope,
            task_host: None,
        }
    }

    /// This origin with the run's TASK creator binding, if it has one.
    pub(crate) fn with_task_host(mut self, binding: Option<crate::task_verb::HostBinding>) -> Self {
        self.task_host = binding;
        self
    }

    /// The TASK creator the dispatcher bound, if any.
    #[must_use]
    pub const fn task_host(&self) -> Option<&crate::task_verb::HostBinding> {
        self.task_host.as_ref()
    }

    /// The source every claim written under this origin carries.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        self.envelope.source()
    }
}

type MachineSignFn<'a> = dyn Fn(&[u8]) -> crate::Result<[u8; 64]> + Send + Sync + 'a;

impl Vault {
    /// Binds this vault's [`Memory`] surface to an actor. The actor entity
    /// must exist and match the class (PERSON for human/agent, MACHINE for
    /// system) by the time a gated write runs — the engine enforces this per
    /// write.
    ///
    /// `actor_class` is not a convenience the caller may drop: it is half of
    /// what the store-truth check verifies, and the two are bound together
    /// here so no verb can be reached without both.
    #[must_use]
    pub fn memory(&self, actor: EntityId, actor_class: EdgeActorClass) -> Memory<'_> {
        Memory {
            vault: self,
            actor,
            actor_class,
            session_key: None,
            machine_signer: None,
            read_proof: None,
            room_turn: None,
            host_origin: None,
            locality: crate::claim::CallerLocality::OnDevice,
            producers: None,
            birth_position: Default::default(),
            owner_authorship: None,
            invocation: None,
            invocation_slip: None,
            transport_invocation: false,
            origin_conversation: None,
            task_host: None,
            off_record_session: None,
            credential: false,
            rewrite_admit: None,
        }
    }

    /// Binds a MACHINE's claim writes to its enrolled software signing key.
    /// Transport authentication alone cannot supply this proof. Other memory
    /// verbs remain subject to their own authorization and write doors.
    ///
    /// The surface's claim and key-value writes call `sign` inside the vault's
    /// write transaction, which may be one group commit shared with other
    /// writes. `sign` must only sign: it must not call into this vault or wait
    /// on anything a vault caller can hold while it writes, or the vault's
    /// writer deadlocks.
    #[must_use]
    pub fn memory_signed_machine<'a>(
        &'a self,
        machine: EntityId,
        public_key: [u8; 32],
        sign: &'a (dyn Fn(&[u8]) -> crate::Result<[u8; 64]> + Send + Sync),
    ) -> Memory<'a> {
        Memory {
            vault: self,
            actor: machine,
            actor_class: EdgeActorClass::System,
            session_key: None,
            machine_signer: Some((public_key, sign)),
            read_proof: None,
            room_turn: None,
            host_origin: None,
            locality: crate::claim::CallerLocality::OnDevice,
            producers: None,
            birth_position: Default::default(),
            owner_authorship: None,
            invocation: None,
            invocation_slip: None,
            transport_invocation: false,
            origin_conversation: None,
            task_host: None,
            off_record_session: None,
            credential: false,
            rewrite_admit: None,
        }
    }
}

impl<'v> Memory<'v> {
    /// Opens this actor's turn in `room` (ARCH-0067 §8). The engine reads the
    /// roster from the room's own record and each member's grants; the caller
    /// supplies only the room. Every read through the returned turn runs
    /// inside `room_scope(roster)` for the current roster and passes the
    /// all-of-audience rule and every member's own read. The turn only
    /// narrows: every check the actor's reads already make still runs.
    pub fn for_room_turn(&self, room: EntityId) -> MemoryResult<super::RoomTurnHandle<'v>> {
        self.verified_actor_class()?;
        self.require_room_in_facets(room)?;
        let ceiling = match self.room_turn_now()? {
            Some(now) if now.room == room => now,
            Some(_) => {
                return Err(MemoryError::bad_request_with(
                    "room differs from the bound room turn",
                    &[],
                ));
            }
            None => self.room_ceiling(room)?,
        };
        Ok(super::RoomTurnHandle {
            memory: Memory {
                vault: self.vault,
                actor: self.actor,
                actor_class: self.actor_class,
                session_key: self.session_key,
                machine_signer: self.machine_signer,
                read_proof: self.read_proof.clone(),
                room_turn: Some(ceiling),
                host_origin: self.host_origin.clone(),
                locality: self.locality,
                producers: self.producers,
                birth_position: self.birth_position,
                // A room turn writes into the room's talk, not as the owner
                // in person.
                owner_authorship: None,
                // The same logical verb, run inside the turn.
                invocation: self.invocation,
                invocation_slip: self.invocation_slip.clone(),
                transport_invocation: self.transport_invocation,
                origin_conversation: self.origin_conversation,
                task_host: self.task_host.clone(),
                off_record_session: self.off_record_session.clone(),
                credential: self.credential,
                rewrite_admit: self.rewrite_admit.clone(),
            },
        })
    }
}

impl Memory<'_> {
    /// Bind witnessed turns to the host's actor/machine sitting. This is
    /// context, not authority: ordinary actor and write checks still apply.
    #[must_use]
    pub fn with_session(mut self, key: crate::session_lifecycle::SessionKey) -> Self {
        self.session_key = Some(key);
        self
    }

    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    /// Binds this surface's reads to the verified credential the actor
    /// presented (ONE-1187-D6: a render read runs under the principal's
    /// already-held key). Every read verb then reads under the key that proof
    /// builds, never a broader one — not even the owner's. The proof's holder
    /// must be the bound actor; a read refuses otherwise.
    #[must_use]
    pub fn with_read_proof(mut self, proof: &crate::authority::VerifiedSlip) -> Self {
        self.read_proof = Some(proof.clone());
        self
    }

    /// Marks this surface's claim writes as made in person by the vault's
    /// authenticated owner: owner-authored writes carry their own
    /// confirmation, so a critical claim they land attaches no confirm.
    ///
    /// A host binds it only for a request the owner made directly, through a
    /// door that authenticated the owner (an unattenuated owner credential or
    /// the native owner door). An agent's, a room turn's or an import's write
    /// never carries it. Each claim write revalidates the proof as the vault's
    /// owner in its own transaction and refuses when it no longer holds; the
    /// proof's actor must be this surface's actor, as a human.
    #[must_use]
    pub fn with_owner_authorship(mut self, owner: &crate::consent::AuthenticatedOwner) -> Self {
        self.owner_authorship = Some(owner.clone());
        self
    }

    /// Binds the logical verb's id a transport carried in, so a verb hook
    /// fires once for it however many wrappers it crosses.
    #[must_use]
    pub fn with_invocation(mut self, invocation: crate::runtime_hooks::InvocationId) -> Self {
        self.invocation = Some(invocation);
        self
    }

    /// Binds the signed instrument the caller's request was admitted on.
    /// Work this surface queues carries it, and that work's standing is the
    /// slip's own when it runs: verified again then, a revoked slip stops it.
    #[must_use]
    pub fn with_invocation_slip(
        mut self,
        binding: &crate::authority::InvocationSlipBinding,
    ) -> Self {
        self.invocation_slip = Some(binding.clone());
        self
    }

    /// The signed instrument a host bound, if any.
    pub(crate) fn invocation_slip(&self) -> Option<&crate::authority::InvocationSlipBinding> {
        self.invocation_slip.as_ref()
    }

    /// Marks this surface as a transport caller's, with a slip or without
    /// one, on loopback as off the device. It only narrows: no call clears it.
    #[must_use]
    pub fn with_transport_invocation(mut self) -> Self {
        self.transport_invocation = true;
        self
    }

    /// Whether the in-process host itself holds this surface: no transport
    /// reached it and no credential is bound to it.
    pub(crate) fn native_invocation(&self) -> bool {
        !self.transport_invocation && self.invocation_slip.is_none() && self.read_proof.is_none()
    }

    /// Binds the conversation whose request started this surface's work
    /// (OF-221). A host binds it only from the authenticated request that
    /// actually started the work, never from caller text, a selected room or
    /// a transcript. A root TASK this surface creates keeps it, through
    /// approval and wave planning, and the agent that realizes it carries it
    /// as its dispatch origin; a child always takes its parent's instead. It
    /// grants nothing.
    #[must_use]
    pub fn with_origin_conversation(mut self, id: EntityId) -> Self {
        self.origin_conversation = Some(id);
        self
    }

    /// Binds the off-record session the host's request names (its
    /// `x-oneiron-session`) for this surface's principal, the request's own:
    /// context, not authority. Inside one the live registry holds anonymous
    /// and that principal is verified in (its room's roster, or the actor
    /// who entered it alone), a reference refusal or an unlinked prose link
    /// is refused or unlinked as anywhere else but writes no receipt
    /// (OF-063, Engine ruling 10-17, matching OF-538's call receipts). A
    /// caller whose principal provably differs writes its receipts as
    /// anywhere else; one with no principal keeps the unchecked rule.
    #[must_use]
    pub fn in_off_record_session(mut self, session_ref: &str) -> Self {
        self.off_record_session = Some(session_ref.trim().to_owned());
        self
    }

    /// Whether this surface's call sits in an anonymous off-record session
    /// its principal is verified in, which keeps no record: the one signal
    /// OF-538's call receipts read
    /// ([`Vault::off_record_session_is_anonymous_for`]), judged now, when a
    /// receipt would be written, not when the session was bound.
    ///
    /// The principal is the one the bound credential names (its holder,
    /// the same one the transports' call receipts compare), or none for the
    /// host root, which names no person; a surface no credential is bound
    /// to calls for its bound actor.
    pub(crate) fn keeps_no_record(&self) -> bool {
        self.off_record_session.as_deref().is_some_and(|session| {
            let principal = match &self.read_proof {
                Some(proof) => EntityId::from_hex(&proof.claims().holder_ref).ok(),
                None => Some(self.actor),
            };
            self.vault
                .off_record_session_is_anonymous_for(session, principal)
        })
    }

    /// The logical verb's id a host bound, if any.
    #[must_use]
    pub fn invocation(&self) -> Option<crate::runtime_hooks::InvocationId> {
        self.invocation
    }

    /// The origin conversation a host bound, if any.
    #[must_use]
    pub fn origin_conversation(&self) -> Option<EntityId> {
        self.origin_conversation
    }

    /// Marks this surface as a caller's whose credential this host admitted.
    /// It grants and narrows nothing: a verb hook's ask on its call saves no
    /// way to run the call without the caller, so only the caller's retry,
    /// which the host verifies again, resumes it (ARCH-0080 §3 Ask).
    #[must_use]
    pub fn for_credential(mut self) -> Self {
        self.credential = true;
        self
    }

    /// Binds the door's admission of a hook's rewritten args: a rewrite the
    /// door would refuse from the caller is refused from a hook too. A room
    /// turn opened on this surface keeps it.
    #[must_use]
    pub fn with_rewrite_admit(mut self, admit: RewriteAdmit) -> Self {
        self.rewrite_admit = Some(admit);
        self
    }

    /// The door's admission of rewritten args a host bound, if any.
    pub(crate) fn rewrite_admit(&self) -> Option<&RewriteAdmit> {
        self.rewrite_admit.as_ref()
    }

    /// Binds the running agent attempt whose TASK creates this surface makes
    /// (OF-532): a TASK it creates for an agent then runs inside that
    /// attempt's lease tree and project. A host builds the binding from the
    /// leased row it holds, never from caller text. It grants nothing: each
    /// create re-proves the lease, the actor and the spend scope in its own
    /// transaction, and a stale one refuses.
    #[must_use]
    pub fn with_task_host(mut self, binding: crate::task_verb::HostBinding) -> Self {
        self.task_host = Some(binding);
        self
    }

    /// The TASK creator a host bound, if any.
    pub(crate) fn task_host(&self) -> Option<&crate::task_verb::HostBinding> {
        self.task_host.as_ref()
    }

    /// The owner authorship of a claim write in `txn`, revalidated there.
    ///
    /// A surface bound to a host origin or a machine signer writes for
    /// someone else, so it authors nothing as the owner.
    pub(super) fn owner_authored_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Option<crate::consent::OwnerAuthoredWrite>> {
        let Some(owner) = &self.owner_authorship else {
            return Ok(None);
        };
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return Ok(None);
        }
        if owner.revalidate_in_txn(self.vault, txn)? != self.actor
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(crate::Error::Gate(
                crate::error::GateError::ConsentOwnerNotAuthenticated(
                    "owner proof does not name this surface's actor",
                ),
            ));
        }
        owner.owner_authored_write_in_txn(self.vault, txn).map(Some)
    }

    /// The owner proof a host bound ([`Self::with_owner_authorship`]), for a
    /// door that revalidates it itself; `None` on a surface that writes for
    /// someone else.
    pub(crate) fn owner_authorship(&self) -> Option<&crate::consent::AuthenticatedOwner> {
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return None;
        }
        self.owner_authorship.as_ref()
    }

    /// Binds this surface's claim writes to a host-owned origin: every claim
    /// door then stamps the origin's source, lineage and provenance, and the
    /// caller's declared source is not read. Approval still follows from that
    /// source and the gate decides.
    #[must_use]
    pub fn with_host_origin(mut self, origin: HostWriteOrigin) -> Self {
        if let Some(binding) = &origin.task_host {
            self.task_host = Some(binding.clone());
        }
        self.host_origin = Some(origin);
        self
    }

    /// Whether a host bound this surface to generated code's origin. Such a
    /// surface never speaks, answers or assigns in a person's name.
    pub(crate) fn writes_generated(&self) -> bool {
        self.host_origin
            .as_ref()
            .is_some_and(|origin| origin.source() == ClaimSource::Generated)
    }

    /// The source a claim door writes: the bound origin's, else the caller's.
    pub(super) fn claim_source(&self, declared: &str) -> MemoryResult<ClaimSource> {
        match &self.host_origin {
            Some(origin) => Ok(origin.source()),
            None => super::claims::parse_claim_source(declared),
        }
    }

    /// The envelope a claim door writes under: the bound origin's, else the
    /// facade's own provenance for `verb` over the caller's `source`.
    pub(super) fn claim_envelope(
        &self,
        source: ClaimSource,
        verb: &str,
        approval: ClaimApprovalStatus,
    ) -> crate::Result<crate::WriteEnvelope> {
        match self.host_envelope(approval)? {
            Some(envelope) => Ok(envelope),
            None => Ok(crate::WriteEnvelope::new(
                crate::WriteActor::new(self.actor, self.actor_class),
                source,
                crate::WriteProvenance::new(facade_provenance(verb))?,
                approval,
            )),
        }
    }

    /// The bound origin's envelope at `approval`, for a writer that stamps its
    /// own source and provenance when no origin is bound.
    pub(crate) fn host_envelope(
        &self,
        approval: ClaimApprovalStatus,
    ) -> crate::Result<Option<crate::WriteEnvelope>> {
        let Some(origin) = &self.host_origin else {
            return Ok(None);
        };
        if origin.envelope.actor() != crate::WriteActor::new(self.actor, self.actor_class) {
            return Err(Error::InvalidClaimBody(
                "host write origin does not match bound facade",
            ));
        }
        Ok(Some(origin.envelope.clone().with_approval(approval)))
    }

    /// The room turn this handle is bound to, if any.
    pub(crate) fn room_turn(&self) -> Option<&crate::claim::RoomTurnCeiling> {
        self.room_turn.as_ref()
    }

    /// The sitting and the room turn's room a host bound, when nothing else
    /// on this surface is something a resumed call could not rebuild: no
    /// credential or read proof, on this device, a room's own turn rather
    /// than a thread's, and no owner authorship, host origin, machine signer,
    /// producer list, birth position, TASK host, off-record session or door
    /// rewrite admission. A verb hook's ask saves
    /// them, so settlement runs the call again as this caller (ARCH-0080 §3
    /// Ask); `None` resumes only on the caller's retry.
    pub(crate) fn resume_bounds(
        &self,
    ) -> Option<(
        Option<crate::session_lifecycle::SessionKey>,
        Option<EntityId>,
    )> {
        let plain = !self.credential
            && self.read_proof.is_none()
            && self.locality == crate::claim::CallerLocality::OnDevice
            && self
                .room_turn
                .as_ref()
                .is_none_or(|turn| turn.branch.is_none())
            && self.owner_authorship.is_none()
            && self.host_origin.is_none()
            && self.machine_signer.is_none()
            && self.producers.is_none()
            && self.birth_position == crate::federation::record_scope::BirthPosition::default()
            && self.task_host.is_none()
            && self.off_record_session.is_none()
            && self.rewrite_admit.is_none();
        plain.then(|| {
            (
                self.session_key,
                self.room_turn.as_ref().map(|turn| turn.room),
            )
        })
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

    /// The owner check: a human actor whose owner binding verifies.
    pub fn verify_owner(&self) -> MemoryResult<()> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        self.verify_owner_in_txn(&txn)
    }

    pub(crate) fn verify_owner_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        super::credential_key::verify_vault_owner_in_txn(
            self.vault,
            txn,
            self.actor,
            self.actor_class,
        )
    }

    /// One actor-bound content writer. Its interface exposes read-only
    /// observation and typed content programs; ordinary content cannot take
    /// a raw mutable transaction from this entry.
    pub(crate) fn with_actor_content_write_txn<T>(
        &self,
        write: impl FnOnce(&mut crate::federation::ActorContentTxn<'_, '_, '_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.with_actor_content_write_txn_as(
            crate::WriteActor::new(self.actor, self.actor_class),
            write,
        )
    }

    /// Preserve the observed authority frontier when a typed Vault NOTE door
    /// is called with an already-bound WriteActor rather than the facade's
    /// ordinary actor pair.
    pub(crate) fn with_actor_content_write_txn_as<T>(
        &self,
        actor: crate::WriteActor,
        write: impl FnOnce(&mut crate::federation::ActorContentTxn<'_, '_, '_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        if actor.entity_ref() != self.actor || actor.actor_class() != self.actor_class {
            return Err(
                Error::InvalidClaimBody("content actor does not match bound facade").into(),
            );
        }
        self.vault.try_with_write_txn_grouped(|wtxn| {
            verify_actor_binding_in_txn(self.vault, wtxn, self.actor, self.actor_class)?;
            let mut content = crate::federation::ActorContentTxn::new(self.vault, wtxn, actor)?;
            let result = write(&mut content)?;
            content.finish()?;
            Ok(result)
        })
    }

    /// Legacy domain-specific actor writes that do not yet expose a resolved
    /// record position require a full content-write grant in a shared vault.
    /// A scoped writer uses `with_actor_content_write_txn` and its typed
    /// effects instead. No caller may use raw access to bypass membership.
    pub(crate) fn with_verified_actor_write_txn<T>(
        &self,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.with_verified_actor_write_txn_as(crate::store::Callback::Audited, write)
    }

    /// [`Self::with_verified_actor_write_txn`] through the door `callback`
    /// names: a write that runs host code in its transaction is
    /// [`crate::store::Callback::Opaque`].
    pub(crate) fn with_verified_actor_write_txn_as<T>(
        &self,
        callback: crate::store::Callback,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.vault.write_txn_door(callback, |wtxn| {
            self.verify_actor_write_in_txn(wtxn)?;
            write(wtxn)
        })
    }

    /// The actor checks [`Self::with_verified_actor_write_txn_as`] runs in its
    /// transaction, for a writer that must run its own check before them.
    pub(crate) fn verify_actor_write_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        verify_actor_binding_in_txn(self.vault, txn, self.actor, self.actor_class)?;
        if let Some(creation) = self.vault.shared_vault_creation_in_txn(txn)? {
            self.vault.authorize_shared_vault_write_in_txn(
                txn,
                creation.vault_id,
                &crate::WriteActor::new(self.actor, self.actor_class),
                &crate::federation::SharedVaultWrite::Content(crate::federation::Scope::top()),
            )?;
        }
        Ok(())
    }

    pub(super) fn resolve_ref(&self, reference: &str) -> MemoryResult<EntityId> {
        resolve_entity_ref(self.vault, reference)
    }

    /// PRE-TRANSACTION variant of the hard-delete refusal, used ONLY where
    /// the engine owns the write transaction internally (imported-claim
    /// ingest admission) and the marker check cannot ride it. Residual for
    /// that verb: a hard delete landing between this check and the engine's
    /// commit recreates at the purged id; closing it needs an in-txn ingest
    /// seam. Every other id-accepting verb checks the marker INSIDE its own
    /// write transaction (A1).
    pub(super) fn refuse_hard_deleted_id(&self, id: &EntityId) -> MemoryResult<()> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| MemoryError::from(Error::from(err)))?;
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
    pub(super) fn verified_actor_class(&self) -> MemoryResult<EdgeActorClass> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.actor_class)
    }

    pub(super) fn short_ref_of(&self, id: &EntityId) -> MemoryResult<Option<String>> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| MemoryError::from(Error::from(err)))?;
        self.short_ref_of_in_txn(&rtxn, id)
    }

    /// [`Self::short_ref_of`] inside a caller's read transaction.
    ///
    /// A short ref carries the claim's CONTENT HASH, so resolving one in a
    /// later snapshot than the values it labels can hand back a ref for a body
    /// that has since moved on. A caller whose values and refs must describe
    /// the same instant resolves both here, under one `rtxn`.
    pub(super) fn short_ref_of_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<Option<String>> {
        short_ref_in_txn(&self.vault.store, rtxn, id)
    }

    pub(super) fn short_ref_or_hex(&self, id: &EntityId) -> MemoryResult<String> {
        Ok(self.short_ref_of(id)?.unwrap_or_else(|| id.to_hex()))
    }

    pub(super) fn latest_decision_ref_for(&self, id: &EntityId) -> MemoryResult<Option<String>> {
        let latest = self
            .vault
            .store
            .latest_gate_decision_for_claim(id.as_bytes(), GATE_RECEIPT_SCAN_LIMIT)?;
        Ok(latest.map(|decision_id| format!("gate:{}", decision_id.to_hex())))
    }
}

/// Typed refusal for creation at an id carrying the durable `dt:`
/// hard-delete marker (hard-once-seen — the same presence-only marker the
/// sync replay path consults). Without this refusal a delete-authorized
/// caller could two-step retype an entity (hard delete, then recreate
/// under a different type), and a migration re-run could resurrect data
/// the user erased.
pub(crate) fn hard_deleted_refusal(id: &EntityId) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
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

/// The short ref `store` holds for `id`: the vault's own, or a room's view,
/// whose staged rows carry their own.
pub(super) fn short_ref_in_txn(
    store: &impl crate::store::ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<Option<String>> {
    Ok(
        crate::ports::ShortIdStoreRead::port_short_id_reference(store, rtxn, id)?
            .map(|(name, hash)| format!("{name}:{hash:02x}")),
    )
}

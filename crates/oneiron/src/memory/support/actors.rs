//! Actor verification: store-truth bindings, the folded owner binding and deletion authority.
//! `verify_actor_binding` and `Memory::verify_owner` are its call surface.
//! `memory::support` defines `Memory` and re-exports these checks at their old reach.

use super::*;

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
    // The shared view, not a copy of the fold: a host action's read key runs
    // this once per candidate row (FIX 2222).
    let fold = vault.authority_view_readonly_in_txn(txn).map_err(|err| {
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

impl Memory<'_> {
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

    /// Resolves the caller-asserted actor against the STORE before any
    /// authority is granted (asserted class strings are never trusted):
    /// the actor entity must exist, and its stored type must match the
    /// asserted class (PERSON ⇒ human/agent, MACHINE ⇒ system — the same
    /// rule the gated write path enforces via
    /// `provenance::validate_actor_class`). Anything unresolvable fails
    /// closed with a typed denial.
    pub(in crate::memory) fn verified_actor_class(&self) -> MemoryResult<EdgeActorClass> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.actor_class)
    }
}

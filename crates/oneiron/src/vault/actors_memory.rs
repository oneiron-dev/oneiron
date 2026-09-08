//! Vault actor binding, structural kinds and code-memory attachment.

use super::Vault;
use super::open::{embedded_owner_actor_id, encode_embedded_owner_actor_body};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::registry::{StructuralKindRegistration, TypeByteZone};
use crate::temporal::TimeRange;
use crate::unix_seconds_now;

/// A session-scoped actor binding created by [`Vault::as_actor`]
/// (ONE-1113 ruling, session ergonomics): the handle carries
/// `actor_entity_ref` + the caller-supplied D13 `actor_class` and injects
/// both on every provenance-path write, so a bound caller "writes normally"
/// after binding once. The MCP daemon injects the session actor on the
/// named-writes lane (ARCH-0028) through exactly this surface.
///
/// The binding is correlation-only ergonomics — NO sessions registry, NO
/// authorization, NO stored state. Every write delegates to
/// [`Vault::put_edge_provenance`] and runs its full fail-closed gate chain.
///
/// NAMING: engine-internal until ABI-pinned (the ruling pins semantics, not
/// names); expect the public surface name to be ratified at the FFI/NAPI
/// milestone.
#[derive(Clone, Copy)]
pub struct ActorBound<'a> {
    vault: &'a Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl ActorBound<'_> {
    /// The bound actor entity reference.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound caller-supplied D13 actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    /// Builds an `edge.provenance` value record pre-filled with the BOUND
    /// actor — the "write normally" entry point: fill `confidence` +
    /// `supersession_status`, set optional fields on the returned record,
    /// then pass it to [`ActorBound::put_edge_provenance`].
    #[must_use]
    pub fn provenance_body(
        &self,
        confidence: f32,
        supersession_status: SupersessionStatus,
    ) -> EdgeProvenanceClaimBody {
        EdgeProvenanceClaimBody::new(self.actor, confidence, supersession_status)
    }

    /// Writes an `edge.provenance` Claim for `subject` carrying the BOUND
    /// actor + class — delegates to [`Vault::put_edge_provenance`] with the
    /// bound `actor_class` injected, running the full gate chain (write-once
    /// id, subject-edge existence, D13 actor validation, D14 precedence,
    /// implicit supersession, winner restamp, PPR invalidation).
    ///
    /// Fail-closed binding check: a `body.actor_entity_ref` that names a
    /// DIFFERENT entity than the bound actor is rejected typed
    /// ([`Error::InvalidProvenanceBody`]) — the handle injects the actor, it
    /// never silently rewrites a conflicting one. Construct the record via
    /// [`ActorBound::provenance_body`] to avoid the mismatch entirely.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        learned_at: u64,
    ) -> Result<()> {
        if body.actor_entity_ref != self.actor {
            return Err(Error::InvalidProvenanceBody(
                "body actor_entity_ref conflicts with the session-bound actor",
            ));
        }
        self.vault
            .put_edge_provenance(claim_id, subject, body, self.actor_class, learned_at)
    }
}

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Binds an actor to a session-scoped write handle (ONE-1113 ruling,
    /// session ergonomics): bind the actor ONCE, then write provenanced
    /// edges normally — the handle injects `actor_entity_ref` +
    /// `actor_class` on every provenance-path write, so prod callers (e.g.
    /// the MCP daemon's named-writes lane, ARCH-0028) never type provenance
    /// by hand.
    ///
    /// The handle is pure ergonomics: NO sessions registry, NO
    /// authorization — "sessions are correlation-only, never authorization".
    /// Binding validates nothing by itself; every write through the handle
    /// runs the full [`Vault::put_edge_provenance`] gate chain (actor
    /// existence, D13 class validation, D14 precedence, …).
    ///
    /// NAMING: `as_actor` / [`ActorBound`] are INDICATIVE, engine-internal
    /// names (the ruling pins the semantics, not the ABI surface); the
    /// public ABI name is pinned at the FFI/NAPI milestone.
    #[must_use]
    pub fn as_actor(&self, actor: EntityId, actor_class: EdgeActorClass) -> ActorBound<'_> {
        ActorBound {
            vault: self,
            actor,
            actor_class,
        }
    }

    /// Ensures and returns the generic owner actor unauthenticated embedded SDK
    /// constructors bind (ONE-1441 WIRE-P1 embedded ownership bootstrap).
    ///
    /// Constructor bootstrap: embedded ownership IS the authority, so no
    /// verifier chain runs (OF-452 D10). The wire fixture also reaches this
    /// seam to bind an owner PERSON on a pre-server vault — the same
    /// construction-time binding, before any facade gate exists to consult.
    ///
    /// IDEMPOTENT and single-transaction. The id is derived from a pinned
    /// namespace, so it is the same in every vault and across every process;
    /// the check and the create share ONE write transaction, so two racing
    /// constructors cannot both observe "absent" and both write. An occupant
    /// that is present but is NOT a `PERSON` is a typed refusal, never an
    /// overwrite: the bootstrap creates the owner, it does not retype whatever
    /// it finds.
    ///
    /// The write goes through the ordinary `batch_in().put(...)` entity door
    /// this crate uses everywhere else — no bespoke storage path, no
    /// placeholder timestamps. `put_structural`'s verified-human-owner gate is
    /// deliberately NOT invoked: by D10 it does not run at construction time,
    /// and it could not, because the actor it would verify is the one being
    /// created.
    ///
    /// `#[doc(hidden)] pub` — housekeeping, and housekeeping is public, so the
    /// crate-boundary census does not draft it into the public catalog.
    /// Bindings call THIS; they never call `put_entity`, `batch().put`, or any
    /// other storage mutation directly.
    #[doc(hidden)]
    pub fn ensure_embedded_owner_actor(&self) -> crate::memory::MemoryResult<EntityId> {
        let owner = embedded_owner_actor_id()?;
        let now = unix_seconds_now();
        self.try_with_write_txn(|wtxn| {
            if self.local_hard_delete_marker_exists_in_txn(wtxn, &owner)? {
                return Err(crate::memory::hard_deleted_refusal(&owner));
            }
            match self.get_entity_type_in_txn(wtxn, &owner)? {
                Some(crate::registry::ENTITY_TYPE_PERSON) => return Ok(owner),
                // Present but not a PERSON: refuse, never retype. The typed
                // engine error carries the occupant's byte, and the central
                // `From<Error>` mapping renders it — no bespoke code is minted
                // for a case the vocabulary already spells.
                Some(existing) => {
                    return Err(crate::memory::MemoryError::from(
                        Error::EntityTypeImmutable {
                            id: owner,
                            existing,
                            attempted: crate::registry::ENTITY_TYPE_PERSON,
                        },
                    ));
                }
                None => {}
            }
            self.batch_in()
                .put(
                    &owner,
                    crate::registry::ENTITY_TYPE_PERSON,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode_embedded_owner_actor_body()?,
                )
                .apply(wtxn)?;
            Ok(owner)
        })
    }

    pub(crate) fn scoped_read_search_candidate_limit(
        &self,
        requested: usize,
        include_text: bool,
        include_vector: bool,
    ) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.store.env.read_txn()?;
        let mut limit = requested;
        let mut hybrid_union_limit = 0usize;
        if include_text {
            let indexed_docs = usize::try_from(crate::bm25::read_total_docs(&self.store, &rtxn)?)
                .map_err(|_| Error::IndexOverflow("bm25 total docs"))?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_docs);
            limit = limit.max(indexed_docs);
        }
        if include_vector {
            let indexed_vectors = crate::hnsw::hnsw_entity_count(&self.store, &rtxn)?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_vectors);
            limit = limit.max(indexed_vectors);
        }
        if include_text && include_vector {
            limit = limit.max(hybrid_union_limit);
        }
        Ok(limit)
    }

    /// Registers a vault-scoped pack StructuralKind slot.
    ///
    /// The claim is persisted in `vault_meta` under the dynamic kind-registry
    /// key family and becomes visible to subsequent write validation and
    /// short-id allocation for this vault. Under byte-space v3 the only
    /// production-registrable zone is compiled-product 100–125: reserved
    /// Semantic/CORE bytes, bytes outside `zone`, the engine-authored system
    /// zone, the PackByteMap half, and collisions with either static or
    /// already-registered runtime entries all reject.
    pub fn register_structural_kind(
        &self,
        type_byte: u8,
        short_id_prefix: impl Into<String>,
        zone: TypeByteZone,
        pack: impl Into<String>,
    ) -> Result<StructuralKindRegistration> {
        self.store
            .register_structural_kind(type_byte, short_id_prefix, zone, pack)
    }

    /// Returns the dynamic StructuralKind registration for `type_byte`, if
    /// this vault has one. Static registry entries are not mirrored here.
    #[must_use]
    pub fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        self.store.structural_kind_registration(type_byte)
    }

    /// Returns all vault-scoped dynamic StructuralKind registrations sorted
    /// by type byte. Static registry entries are intentionally excluded.
    #[must_use]
    pub fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        self.store.structural_kind_registrations()
    }

    /// Attaches durable L2 memory to a `CODE_SYMBOL` anchor.
    ///
    /// The ONLY ordinary attachment write: it appends or actor-scope-dedupes
    /// into the named slot and never replaces one. There is deliberately no
    /// `attach_to_path` twin — path resemblance can never move a note.
    pub fn attach_code_memory(
        &self,
        input: crate::code_memory::AttachCodeMemory,
    ) -> Result<crate::code_memory::SlotInsertOutcome> {
        self.with_write_txn(|wtxn| crate::code_memory::attach_code_memory(&self.store, wtxn, input))
    }

    /// Applies one EXPLICIT rename/copy anchor transfer.
    ///
    /// `Rename` re-points slots, attachment-index rows, and always-on
    /// registrations onto the target and retires the source; `Copy` clones
    /// them and leaves the source intact. Destination collisions always
    /// resolve through the canonical `merge_union` — there is no overwrite
    /// path — and the whole operation is one transaction.
    pub fn transfer_code_memory_anchor(
        &self,
        transfer: &crate::code_memory::AnchorTransfer,
    ) -> Result<crate::code_memory::AnchorTransferReceipt> {
        self.with_write_txn(|wtxn| {
            crate::code_memory::transfer_code_memory_anchor(&self.store, wtxn, transfer)
        })
    }

    /// Decoded transfer history touching `of` on either endpoint. Raw
    /// metadata keys never cross this boundary.
    pub fn code_memory_transfers(
        &self,
        of: EntityId,
    ) -> Result<Vec<crate::code_memory::AnchorTransferRecord>> {
        let rtxn = self.store.env.read_txn()?;
        crate::code_memory::read_transfer_records(&self.store, &rtxn, &of)
    }

    /// Decoded attachment-index rows for one symbol, keyed by symbol identity.
    ///
    /// There is NO path-keyed counterpart: a stale `path_at_revision` is a
    /// locator, and the public surface offers no way to resolve attachment
    /// identity from one.
    pub fn code_memory_attachments(
        &self,
        symbol_id: EntityId,
    ) -> Result<Vec<crate::code_memory::CodeMemoryAttachment>> {
        let rtxn = self.store.env.read_txn()?;
        crate::code_memory::read_attachments_for_symbol(&self.store, &rtxn, &symbol_id)
    }

    /// Decoded slot bodies for one symbol, with each value's actor, time, and
    /// provenance intact and `conflict_visible` exposed as DATA.
    pub fn code_memory_slots(
        &self,
        symbol_id: EntityId,
    ) -> Result<Vec<crate::code_memory::CodeMemorySlot>> {
        let rtxn = self.store.env.read_txn()?;
        crate::code_memory::read_slots_for_symbol(&self.store, &rtxn, &symbol_id)
    }

    /// Registered always-on interface/policy contracts for one symbol.
    pub fn code_memory_always_on_contracts(
        &self,
        symbol_id: EntityId,
    ) -> Result<Vec<crate::code_memory::AlwaysOnCodeMemoryContract>> {
        let rtxn = self.store.env.read_txn()?;
        crate::code_memory::read_always_on_for_symbol(&self.store, &rtxn, &symbol_id)
    }

    /// Registers one bounded always-on interface/policy contract.
    pub fn register_always_on_contract(
        &self,
        contract: crate::code_memory::AlwaysOnCodeMemoryContract,
    ) -> Result<()> {
        self.with_write_txn(|wtxn| {
            crate::code_memory::register_always_on_contract(&self.store, wtxn, contract)
        })
    }

    /// The ONLY `blocks` write door: `from` blocks `to`.
    ///
    /// Binds the actor entity to its asserted class, refuses a `System`
    /// actor and a permit-requiring [`crate::claim::ClaimSource`], proves
    /// acyclicity over `blocks` edges alone, then writes both index rows,
    /// invalidates PPR, and increments the graph version in one transaction.
    /// The generic [`Self::put_edge`] door rejects this kind outright.
    pub fn insert_blocks_edge(
        &self,
        from: EntityId,
        to: EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<()> {
        self.with_write_txn(|wtxn| {
            crate::code_memory::insert_blocks_edge(self, wtxn, from, to, context)
        })
    }

    /// The ONLY `blocks` retirement door. Same authority steps, both index
    /// rows deleted, same in-transaction side effects. Returns whether an
    /// edge existed. The generic [`Self::delete_edge`] door still rejects
    /// this kind.
    pub fn remove_blocks_edge(
        &self,
        from: EntityId,
        to: EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<bool> {
        self.with_write_txn(|wtxn| {
            crate::code_memory::remove_blocks_edge(self, wtxn, from, to, context)
        })
    }

    /// Outgoing readiness dependencies: blocker `of` → blocked neighbors.
    ///
    /// The only read surface for `blocks`, since PPR never traverses the kind
    /// (`lambda_for_kind` is `None`).
    pub fn blocks_dependencies(&self, of: EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_out,
            &of,
            EdgeKind::Blocks,
            None,
            "blocks dependencies",
        )
    }

    /// ScopedRead-clamped L2 pull: provenance-labelled DATA, never
    /// executable instructions and never pushed.
    pub fn pull_code_memory(
        &self,
        actor_key: crate::claim::ScopedReadActorKey,
        request: crate::code_memory::CodeMemoryPullRequest,
    ) -> Result<crate::code_memory::CodeMemoryPullResult> {
        let scoped_read = self.scoped_read(actor_key);
        crate::code_memory::pull_code_memory(self, &scoped_read, request)
    }
}

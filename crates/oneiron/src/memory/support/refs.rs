//! Ref and id utilities: actor keys, entity refs, short ids, hex ids and hard-delete refusals.
//! `parse_actor_key` and `resolve_entity_ref` are its call surface.
//! `memory::support` defines `Memory` and re-exports these at their old reach.

use super::*;

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

pub(in crate::memory) fn id_from_optional_hex(
    vault: &crate::Vault,
    id: Option<&str>,
) -> MemoryResult<EntityId> {
    match id {
        Some(hex) => EntityId::from_hex(hex)
            .map_err(|_| MemoryError::bad_request(format!("invalid entity id {hex:?}"))),
        None => Ok(vault.store.clock.entity_id()?),
    }
}

pub(in crate::memory) fn subject_ref_string(subject: &ClaimSubject) -> String {
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

impl Memory<'_> {
    pub(in crate::memory) fn resolve_ref(&self, reference: &str) -> MemoryResult<EntityId> {
        resolve_entity_ref(self.vault, reference)
    }

    /// PRE-TRANSACTION variant of the hard-delete refusal, used ONLY where
    /// the engine owns the write transaction internally (imported-claim
    /// ingest admission) and the marker check cannot ride it. Residual for
    /// that verb: a hard delete landing between this check and the engine's
    /// commit recreates at the purged id; closing it needs an in-txn ingest
    /// seam. Every other id-accepting verb checks the marker INSIDE its own
    /// write transaction (A1).
    pub(in crate::memory) fn refuse_hard_deleted_id(&self, id: &EntityId) -> MemoryResult<()> {
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

    pub(in crate::memory) fn short_ref_of(&self, id: &EntityId) -> MemoryResult<Option<String>> {
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
    pub(in crate::memory) fn short_ref_of_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<Option<String>> {
        short_ref_in_txn(&self.vault.store, rtxn, id)
    }

    pub(in crate::memory) fn short_ref_or_hex(&self, id: &EntityId) -> MemoryResult<String> {
        Ok(self.short_ref_of(id)?.unwrap_or_else(|| id.to_hex()))
    }

    pub(in crate::memory) fn latest_decision_ref_for(
        &self,
        id: &EntityId,
    ) -> MemoryResult<Option<String>> {
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

pub(in crate::memory) fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The short ref `store` holds for `id`: the vault's own, or a room's view,
/// whose staged rows carry their own.
pub(in crate::memory) fn short_ref_in_txn(
    store: &impl crate::store::ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<Option<String>> {
    Ok(
        crate::ports::ShortIdStoreRead::port_short_id_reference(store, rtxn, id)?
            .map(|(name, hash)| format!("{name}:{hash:02x}")),
    )
}

//! Relationship access checks share the row read transaction with grant resolution.
use super::ScopedRead;
use super::agent_grants::{AskedFilter, HeldGrants};
use crate::EntityId;
use crate::access_grant::AccessContext;
use crate::claim::{ClaimBody, decode_claim_body};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::federation::Scope;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TURN,
};
use crate::store::Store;
use std::cell::RefCell;

fn private_scope(scope: Option<&rmpv::Value>) -> bool {
    let Some(scope) = scope else { return false };
    let Some(fields) = scope.as_map() else {
        return true;
    };
    let mut private = None;
    for (key, value) in fields {
        if key.as_str() == Some("private") {
            if private.is_some() {
                return true;
            }
            private = Some(value.as_bool().unwrap_or(true));
        }
    }
    private.unwrap_or(false)
}

/// The relationship a claim is scoped to and whether it is private, as
/// relationship reads see them.
pub(crate) fn claim_access_axes(body: &ClaimBody) -> (Option<EntityId>, bool) {
    (body.rel, private_scope(body.scope.as_ref()))
}

/// The relationship authority the row checks of one read share in its one
/// snapshot: loaded at the first row that needs it, then reused, so a batch
/// read resolves the reader's grants and memberships once, not per row.
/// The second field names the one row whose legal non-use conjunct a named
/// read asks on its own ([`Self::asking_use_of`]). The third holds, for the
/// same serving txn, each reader's own live Grants once a row's own
/// admission refuses it, and what the read asked of its rows (FIX 7462).
#[derive(Default)]
pub(super) struct HeldAuthority<'v>(
    RefCell<Option<AccessContext<'v>>>,
    Option<EntityId>,
    HeldGrants,
);

impl HeldAuthority<'_> {
    /// The row checks of one serving txn whose filter the read resolved from
    /// `requested` over its key's own floor (`None`: the floor alone).
    pub(super) fn for_request(requested: Option<&super::RetrievalFilter>) -> Self {
        Self(
            RefCell::default(),
            None,
            HeldGrants::fresh(AskedFilter::Known(requested.cloned())),
        )
    }

    /// The row checks of a named read of `id` that asks `id`'s legal non-use
    /// conjunct on its own, after every other gate (FIX 5226): `id` is judged
    /// by every other gate as before, and every other row, each source `id`
    /// was written from included, keeps that conjunct. It shares this read's
    /// Grants.
    pub(super) fn asking_use_of(&self, id: EntityId) -> Self {
        Self(RefCell::default(), Some(id), self.2.clone())
    }

    /// A peer's row checks in this read's serving txn: its own relationship
    /// authority and legal non-use conjunct, under its own floor alone, and
    /// this read's Grants, where it reads its own actor's entry.
    pub(super) fn for_peer(&self) -> Self {
        Self(
            RefCell::default(),
            None,
            self.2.shared_asking(AskedFilter::Known(None)),
        )
    }

    /// Whether the read leaves `id`'s legal non-use conjunct to the named
    /// read that asks it on its own.
    pub(super) fn asks_use_of(&self, id: &EntityId) -> bool {
        self.1.as_ref() == Some(id)
    }

    /// The Grants this serving txn holds, by reader.
    pub(super) fn grants(&self) -> &HeldGrants {
        &self.2
    }
}

impl<'v> ScopedRead<'v> {
    /// Persist grant time before the read snapshot, never inside it. Inside
    /// a room turn, or with peer reads, each peer's access grants are judged
    /// at that time too, and the snapshot may hold a member who joined after
    /// the key was built.
    pub(crate) fn persist_grant_clock(&self) -> Result<()> {
        if self.actor_key.enforce_access_grants
            || self.actor_key.room_turn.is_some()
            || !self.peer_reads.is_empty()
        {
            self.vault.store.authorization_now()?;
        }
        Ok(())
    }

    pub(super) fn grant_read_txn(&self) -> Result<heed::RoTxn<'_>> {
        self.persist_grant_clock()?;
        Ok(self.vault.store.env.read_txn()?)
    }

    /// Whether this read's relationship gate binds in `txn`. A narrower
    /// credential of the owner's is exempt only while its holder still exists
    /// and is the vault's owner in this snapshot (Astra #1413-003, Sol
    /// R5-007).
    pub(super) fn relationship_gated_in(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        if !self.actor_key.enforce_access_grants {
            return Ok(false);
        }
        let Some(owner) = self.actor_key.owner_exemption else {
            return Ok(true);
        };
        crate::memory::owner_exemption_holds_in_txn(self.vault, txn, owner)
            .map(|owner| !owner)
            .map_err(|refusal| {
                crate::error::Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(
                    Box::new(refusal),
                ))
            })
    }

    pub(super) fn relationship_claim_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        if !self.relationship_gated_in(txn)? {
            return Ok(true);
        }
        let read = RelationshipRead::claim(body);
        if self.support_disclosure_admits_in(txn, id, &read)? {
            return Ok(true);
        }
        let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
        Ok(read.allowed_by(&context))
    }

    /// [`Self::relationship_claim_allowed_in`] for a claim that may never
    /// have landed, from the relationship axes and record Scope its Gate
    /// decision kept (FIX 7499). No stored row names it, so no support slip
    /// can name it either: only the reader's memberships and grants decide.
    pub(super) fn relationship_axes_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        space: Option<EntityId>,
        private: bool,
        record: &Scope,
    ) -> Result<bool> {
        if !self.relationship_gated_in(txn)? {
            return Ok(true);
        }
        let read = RelationshipRead::Gated {
            kind: ENTITY_TYPE_CLAIM,
            space,
            private,
            record: record.clone(),
        };
        let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
        Ok(read.allowed_by(&context))
    }

    /// The support-disclosure projection at the relationship gate (OF-606):
    /// a live support slip reads a relationship-gated row it names exactly
    /// in its records, inside its own read Scope, and never a private one.
    /// It replaces only the relationship grant: the audience, locality,
    /// private-thread, record and Scope conjuncts of the read still bind,
    /// there is no owner exemption, and the gate binds every other row.
    fn support_disclosure_admits_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        read: &RelationshipRead,
    ) -> Result<bool> {
        let Some(proof) = &self.actor_key.proof else {
            return Ok(false);
        };
        let claims = proof.claims();
        if claims.delegation.is_none() || !claims.records.contains(&id.to_hex()) {
            return Ok(false);
        }
        let RelationshipRead::Gated {
            private: false,
            record,
            ..
        } = read
        else {
            return Ok(false);
        };
        let in_scope = self
            .actor_key
            .authority_scope()
            .is_some_and(|authority| authority.admits("read", record, &Scope::top()));
        Ok(in_scope && self.vault.capability_slip_is_live_in_txn(txn, proof)?)
    }

    pub(super) fn relationship_raw_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        if !self.relationship_gated_in(txn)? {
            return Ok(true);
        }
        // The row's position is content, read where this read reads it: a
        // room's MESSAGE or SUMMARY at the position its write staged beside
        // it. The grants and memberships it is judged by stay base.
        let read = relationship_read_keyed(
            &self.store_read(),
            txn,
            id,
            raw,
            self.actor_key.unscoped_rows_open,
        )?;
        if let RelationshipRead::Decided(allowed) = read {
            return Ok(allowed);
        }
        if self.support_disclosure_admits_in(txn, id, &read)? {
            return Ok(true);
        }
        let mut held = authority.0.borrow_mut();
        let context = match held.take() {
            Some(context) => context,
            None => AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?,
        };
        let allowed = read.allowed_by(&context)
            || self.conversation_message_granted_in(txn, id, &read, &context);
        *held = Some(context);
        Ok(allowed)
    }

    /// Whether `context` holds a live read grant over the conversation the
    /// MESSAGE `id` is part of (FIX 10895): a MESSAGE that names no
    /// relationship and no private scope, which no membership or
    /// relationship grant admits, is read on a `ConversationMessages` grant
    /// over its conversation, found on this read's content as the
    /// transcript finds it (the MESSAGE PartOf a TURN, the TURN ChildOf the
    /// conversation). The grant stands in for the relationship check alone;
    /// every other check on the row still binds. Edges that do not read
    /// admit nothing.
    fn conversation_message_granted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        read: &RelationshipRead,
        context: &AccessContext<'_>,
    ) -> bool {
        let RelationshipRead::Gated {
            kind: ENTITY_TYPE_MESSAGE,
            space: None,
            private: false,
            record,
        } = read
        else {
            return false;
        };
        if !context.holds_conversation_grants() {
            return false;
        }
        self.edge_targets_in(txn, id, EdgeKind::PartOf, ENTITY_TYPE_TURN)
            .iter()
            .flat_map(|turn| {
                self.edge_targets_in(txn, turn, EdgeKind::ChildOf, ENTITY_TYPE_CONVERSATION)
            })
            .any(|conversation| {
                context.allows_conversation_message_at_snapshot(conversation, record)
            })
    }

    /// The targets of `id`'s outgoing `kind` edges whose rows are of
    /// `entity_type`, on this read's content; none when the edges do not
    /// read.
    fn edge_targets_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        kind: EdgeKind,
        entity_type: u8,
    ) -> Vec<EntityId> {
        let Ok(edges) = self.out_edges_in(txn, id, Some(kind)) else {
            return Vec::new();
        };
        edges
            .filter_map(|edge| edge.ok().map(|edge| edge.target))
            .filter(|target| {
                self.entity_record_in(txn, target)
                    .ok()
                    .flatten()
                    .is_some_and(|row| row.entity_type == entity_type)
            })
            .collect()
    }
}

/// What a relationship read decides one stored row on, before it knows who
/// reads it.
pub(crate) enum RelationshipRead {
    /// The row decides alone: a kind relationship reads do not gate
    /// (`true`), or one whose scope fields or record position do not resolve
    /// (`false`).
    Decided(bool),
    /// The reader's memberships and grants decide, from the row's kind, the
    /// relationship it is scoped to, whether it is private, and its record
    /// position.
    Gated {
        kind: u8,
        space: Option<EntityId>,
        private: bool,
        record: Scope,
    },
}

impl RelationshipRead {
    fn claim(body: &ClaimBody) -> Self {
        let (space, private) = claim_access_axes(body);
        Self::Gated {
            kind: ENTITY_TYPE_CLAIM,
            space,
            private,
            record: body.record_scope("read"),
        }
    }

    /// Whether the principal `context` was loaded for may read the row.
    pub(crate) fn allowed_by(&self, context: &AccessContext<'_>) -> bool {
        match self {
            Self::Decided(allowed) => *allowed,
            Self::Gated {
                kind,
                space,
                private,
                record,
            } => context.allows_at_snapshot(*kind, *space, *private, record),
        }
    }
}

/// What a relationship read decides the stored row `raw` of `id` on: a
/// CLAIM's scope from its body, a MESSAGE's or SUMMARY's from its typed
/// `rel` and `scope` fields and its record position.
pub(crate) fn relationship_read(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<RelationshipRead> {
    relationship_read_keyed(store, txn, id, raw, false)
}

/// [`relationship_read`] for a key that may open unscoped rows: with
/// `unscoped_rows_open` (a vault-internal reader,
/// `require_relationship_grants`), a MESSAGE or SUMMARY that names neither a
/// relationship nor a private scope is the vault's own and decides readable.
/// `store` is the content the row is read on, where its position is looked
/// up: base, or a room's union (WILL L11-01).
fn relationship_read_keyed<S>(
    store: &S,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    unscoped_rows_open: bool,
) -> Result<RelationshipRead>
where
    S: crate::store::ManifestDbs + crate::federation::record_scope::MachineHistoryScope,
{
    let header = crate::batch::EntityMetadataHeader::parse(raw).ok_or(
        crate::error::Error::CorruptedIndex("relationship record header"),
    )?;
    let kind = header.entity_type;
    let bytes = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    if kind == ENTITY_TYPE_CLAIM {
        if bytes.is_empty() {
            return Ok(RelationshipRead::Decided(false));
        }
        return Ok(RelationshipRead::claim(&decode_claim_body(bytes, true)?));
    }
    if !matches!(kind, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SUMMARY) {
        return Ok(RelationshipRead::Decided(true));
    }
    // Memory data scopes are typed fields, never inferred from content or names.
    let mut cursor = std::io::Cursor::new(bytes);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(RelationshipRead::Decided(false));
    };
    if cursor.position() != bytes.len() as u64 {
        return Ok(RelationshipRead::Decided(false));
    }
    let Some(fields) = body.as_map() else {
        return Ok(RelationshipRead::Decided(false));
    };
    // Witness MESSAGE scope fields live in the authenticated envelope's
    // metadata. Legacy top-level fields remain readable, but declaring the
    // same axis in both locations is ambiguous and fails closed below.
    let mut metadata = None;
    if kind == ENTITY_TYPE_MESSAGE {
        for (key, value) in fields {
            if key.as_str() == Some("metadata") {
                if metadata.is_some() {
                    return Ok(RelationshipRead::Decided(false));
                }
                metadata = Some(value);
            }
        }
    }
    let metadata_fields = match metadata {
        None | Some(rmpv::Value::Nil) => &[][..],
        Some(rmpv::Value::Map(fields)) => fields.as_slice(),
        Some(_) => return Ok(RelationshipRead::Decided(false)),
    };
    let mut space = None;
    let mut seen_rel = false;
    let mut seen_scope = false;
    let mut private = false;
    for (key, value) in fields.iter().chain(metadata_fields) {
        if key.as_str() == Some("rel") {
            if seen_rel {
                return Ok(RelationshipRead::Decided(false));
            }
            seen_rel = true;
            space = match value {
                rmpv::Value::Binary(bytes) => bytes
                    .as_slice()
                    .try_into()
                    .ok()
                    .and_then(|b| EntityId::from_bytes(b).ok()),
                rmpv::Value::String(s) => s.as_str().and_then(|s| EntityId::from_hex(s).ok()),
                _ => None,
            };
        }
        if key.as_str() == Some("scope") {
            if seen_scope {
                return Ok(RelationshipRead::Decided(false));
            }
            seen_scope = true;
            private |= private_scope(Some(value));
        }
    }
    if unscoped_rows_open && !seen_rel && !private {
        return Ok(RelationshipRead::Decided(true));
    }
    let Some(record) = crate::federation::record_scope::scope_for_blob(store, txn, *id, raw)?
    else {
        return Ok(RelationshipRead::Decided(false));
    };
    Ok(RelationshipRead::Gated {
        kind,
        space,
        private,
        record,
    })
}

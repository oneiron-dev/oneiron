//! Relationship access checks share the row read transaction with grant resolution.
use super::ScopedRead;
use crate::EntityId;
use crate::access_grant::AccessContext;
use crate::claim::{ClaimBody, decode_claim_body};
use crate::error::Result;
use crate::federation::Scope;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY};
use crate::store::Store;

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

impl ScopedRead<'_> {
    /// Persist grant time before the read snapshot, never inside it.
    pub(crate) fn persist_grant_clock(&self) -> Result<()> {
        if self.actor_key.enforce_access_grants {
            self.vault.store.authorization_now()?;
        }
        Ok(())
    }

    pub(super) fn grant_read_txn(&self) -> Result<heed::RoTxn<'_>> {
        self.persist_grant_clock()?;
        Ok(self.vault.store.env.read_txn()?)
    }

    pub(super) fn relationship_claim_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        body: &ClaimBody,
    ) -> Result<bool> {
        if !self.actor_key.enforce_access_grants {
            return Ok(true);
        }
        let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
        Ok(RelationshipRead::claim(body).allowed_by(&context))
    }

    pub(super) fn relationship_raw_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        if !self.actor_key.enforce_access_grants {
            return Ok(true);
        }
        let read = relationship_read(&self.vault.store, txn, id, raw)?;
        if let RelationshipRead::Decided(allowed) = read {
            return Ok(allowed);
        }
        let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
        Ok(read.allowed_by(&context))
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

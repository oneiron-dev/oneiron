//! Relationship access checks share the row read transaction with grant resolution.
use super::ScopedRead;
use crate::EntityId;
use crate::access_grant::AccessContext;
use crate::claim::{ClaimBody, decode_claim_body};
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY};

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
        Ok(context.allows_at_snapshot(
            ENTITY_TYPE_CLAIM,
            body.rel,
            private_scope(body.scope.as_ref()),
        ))
    }

    pub(super) fn relationship_raw_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        bytes: &[u8],
    ) -> Result<bool> {
        if !self.actor_key.enforce_access_grants {
            return Ok(true);
        }
        if kind == ENTITY_TYPE_CLAIM {
            if bytes.is_empty() {
                return Ok(false);
            }
            return self.relationship_claim_allowed_in(txn, &decode_claim_body(bytes, true)?);
        }
        if !matches!(kind, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SUMMARY) {
            return Ok(true);
        }
        // Memory data scopes are typed fields, never inferred from content or names.
        let mut cursor = std::io::Cursor::new(bytes);
        let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
            return Ok(false);
        };
        if cursor.position() != bytes.len() as u64 {
            return Ok(false);
        }
        let Some(fields) = body.as_map() else {
            return Ok(false);
        };
        // Witness MESSAGE scope fields live in the authenticated envelope's
        // metadata. Legacy top-level fields remain readable, but declaring the
        // same axis in both locations is ambiguous and fails closed below.
        let mut metadata = None;
        if kind == ENTITY_TYPE_MESSAGE {
            for (key, value) in fields {
                if key.as_str() == Some("metadata") {
                    if metadata.is_some() {
                        return Ok(false);
                    }
                    metadata = Some(value);
                }
            }
        }
        let metadata_fields = match metadata {
            None | Some(rmpv::Value::Nil) => &[][..],
            Some(rmpv::Value::Map(fields)) => fields.as_slice(),
            Some(_) => return Ok(false),
        };
        let mut space = None;
        let mut seen_rel = false;
        let mut seen_scope = false;
        let mut private = false;
        for (key, value) in fields.iter().chain(metadata_fields) {
            if key.as_str() == Some("rel") {
                if seen_rel {
                    return Ok(false);
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
                    return Ok(false);
                }
                seen_scope = true;
                private |= private_scope(Some(value));
            }
        }
        let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
        Ok(context.allows_at_snapshot(kind, space, private))
    }
}

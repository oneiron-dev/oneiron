//! Resolver-owned binding inside the entity body, not a separate source-id index.
//!
//! The body is a MessagePack map with one `source_binding` map containing exactly
//! the UTF-8 strings `provider`, `kind`, and `external_id`. The external id is the
//! ASCII-trimmed, otherwise opaque key used by the unchanged entity hash domain.
//! Other top-level fields belong to the caller and are ignored, never rewritten.
//! Removing or changing the binding makes subsequent resolution fail closed.
//! A binding is an explicit source association, not provider authentication.

use super::{Disposition, LinkedInEntityKind, LinkedInExternalKey, evidence_field};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::{Vault, unix_seconds_now};

fn binding_fields(key: &LinkedInExternalKey) -> [(&'static str, &str); 3] {
    [
        ("provider", "linkedin"),
        (
            "kind",
            match key.kind {
                LinkedInEntityKind::Company => "company",
                LinkedInEntityKind::Person => "person",
            },
        ),
        ("external_id", key.external_id.as_str()),
    ]
}

fn encode_bound_body(key: &LinkedInExternalKey) -> crate::Result<Vec<u8>> {
    let binding = rmpv::Value::Map(
        binding_fields(key)
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect(),
    );
    let body = rmpv::Value::Map(vec![("source_binding".into(), binding)]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)
        .map_err(|_| Error::InvariantViolation("LinkedIn source binding encode failed"))?;
    Ok(bytes)
}

fn matches_binding(bytes: &[u8], key: &LinkedInExternalKey) -> bool {
    let mut cursor = std::io::Cursor::new(bytes);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    if cursor.position() != bytes.len() as u64 {
        return false;
    }
    // A unique outer field and exactly three unique inner string fields prevent
    // duplicate-key, missing-field, and alternate-shape proofs from authorizing reuse.
    let Some(binding) = evidence_field(&body, "source_binding") else {
        return false;
    };
    binding.as_map().is_some_and(|fields| fields.len() == 3)
        && binding_fields(key).into_iter().all(|(name, expected)| {
            evidence_field(binding, name).and_then(rmpv::Value::as_str) == Some(expected)
        })
}

/// Check identity and write the fresh entity plus binding in the caller's txn.
/// No claims or edges are written here. An error aborts the resolver transaction.
pub(super) fn resolve_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    key: &LinkedInExternalKey,
) -> crate::Result<Disposition> {
    if let Some(raw) = vault.get_raw_in(wtxn, id)? {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != key.kind.entity_type() {
            return Err(Error::InvariantViolation(
                "LinkedIn derived entity type mismatch",
            ));
        }
        if !matches_binding(&raw[ENTITY_METADATA_HEADER_LEN..], key) {
            return Err(Error::InvariantViolation(
                "LinkedIn derived entity source binding mismatch",
            ));
        }
        return Ok(Disposition::Reused);
    }
    let body = encode_bound_body(key)?;
    let learned_at = unix_seconds_now();
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    // A single entity row contains both identity proof and user-data space.
    // It cannot leave an orphan binding after rollback or entity replacement.
    vault
        .batch_in()
        .put(id, key.kind.entity_type(), occurred, learned_at, &body)
        .apply(wtxn)?;
    Ok(Disposition::Created)
}

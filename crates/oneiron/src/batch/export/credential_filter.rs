//! Credential filtering at memory serve and export serialization boundaries.

use super::{ExportManifest, ExportSecretsNulledManifest, whole_vault_export_excludes_entity};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use serde_json::Value;

/// Replaces credential-like fields and values recursively before serving memory.
/// This never changes stored evidence.
pub fn redact_credentials(value: &mut Value) -> bool {
    crate::batch::secret_scan::sanitize_credentials(value, false)
}

/// Filter a legacy raw transport without changing safe payload bytes or types.
pub fn redacted_memory_payload(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
        if !redact_credentials(&mut value) {
            return Ok(bytes);
        }
        return serde_json::to_vec(&value)
            .map_err(|_| Error::InvariantViolation("redacted JSON encode failed"));
    }
    let mut cursor = std::io::Cursor::new(&bytes);
    if let Ok(mut value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        if !crate::batch::secret_scan::sanitize_messagepack_credentials(&mut value, false) {
            return Ok(bytes);
        }
        let mut output = Vec::new();
        rmpv::encode::write_value(&mut output, &value)
            .map_err(|_| Error::InvariantViolation("redacted MessagePack encode failed"))?;
        return Ok(output);
    }
    if crate::batch::secret_scan::scan_file_content("", &bytes).is_some() {
        Ok(b"[redacted]".to_vec())
    } else {
        Ok(bytes)
    }
}

/// Decodes a memory payload without giving opaque bytes a way around the filter.
/// A credential in a non-structured body replaces the entire body.
pub fn redacted_memory_body(bytes: &[u8]) -> Value {
    let mut cursor = std::io::Cursor::new(bytes);
    let mut value = if let Ok(mut value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        crate::batch::secret_scan::sanitize_messagepack_credentials(&mut value, false);
        crate::companion::companion_value_to_json(&value)
    } else if let Ok(value) = serde_json::from_slice(bytes) {
        value
    } else if crate::batch::secret_scan::scan_file_content("", bytes).is_some() {
        Value::String("[redacted]".into())
    } else {
        serde_json::json!({"bodyBytes": bytes})
    };
    redact_credentials(&mut value);
    value
}

impl Vault {
    /// Whole-vault JSON export with credential nulling enforced at serialization.
    pub fn export_vault_json(&self) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for row in self.store.entities.iter(&txn)? {
            let (key, _) = row?;
            let bytes: [u8; 16] = key
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvariantViolation("invalid export id"))?;
            ids.push(EntityId::from_bytes(bytes)?);
        }
        drop(txn);
        self.export_entity_bundle_json(&ids)
    }

    /// Serializes an entity bundle through the whole-vault export boundary.
    /// Off-record rows are excluded; custody containers are always nulled.
    /// The manifest is derived from the bytes, not a caller's declaration.
    pub fn export_entity_bundle_json(&self, ids: &[EntityId]) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        let mut nulled = false;
        for id in ids {
            if whole_vault_export_excludes_entity(self, id)? {
                continue;
            }
            let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::InvariantViolation("invalid export entity header"))?;
            let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
            let mut cursor = std::io::Cursor::new(bytes);
            let mut body = if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
                nulled = true;
                Value::Null
            } else if let Ok(mut value) = rmpv::decode::read_value(&mut cursor)
                && cursor.position() == bytes.len() as u64
            {
                nulled |=
                    crate::batch::secret_scan::sanitize_messagepack_credentials(&mut value, true);
                crate::companion::companion_value_to_json(&value)
            } else if let Ok(value) = serde_json::from_slice(bytes) {
                value
            } else if crate::batch::secret_scan::scan_file_content("", bytes).is_some() {
                nulled = true;
                Value::Null
            } else {
                serde_json::json!({"bodyBytes": bytes})
            };
            nulled |= crate::batch::secret_scan::sanitize_credentials(&mut body, true);
            if !crate::secret_rotation::exhaust_taint_refs_in_txn(&self.store, &txn, id)?.is_empty()
            {
                body = Value::Null;
                nulled = true;
            }
            records.push(serde_json::json!({
                "id": id.to_hex(), "entity_type": header.entity_type,
                "occurred_start": header.occurred_start, "occurred_end": header.occurred_end,
                "learned_at": header.learned_at, "body": body,
            }));
        }
        let manifest =
            ExportManifest::from_secrets_nulled(ExportSecretsNulledManifest::from_redacted(nulled));
        serde_json::to_vec(&serde_json::json!({"manifest": manifest, "entities": records}))
            .map_err(|_| Error::InvariantViolation("entity export JSON encode failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_serve_preserves_safe_fields_and_filters_nested_credentials() {
        let mut value = serde_json::json!({"safe":"hello", "nested":[
            {"password":"not-for-memory", "value":"ghp_0123456789abcdefghijklmnopqrstuvwxyz"}
        ]});
        assert!(redact_credentials(&mut value));
        assert_eq!(value["safe"], "hello");
        assert_eq!(value["nested"][0]["password"], "[redacted]");
        assert_eq!(value["nested"][0]["value"], "[redacted]");
        assert!(!redact_credentials(&mut value));
        let mut binary = serde_json::json!({"safe":"kept","nested":{"value":b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec()}});
        assert!(redact_credentials(&mut binary));
        assert_eq!(binary["nested"]["value"], "[redacted]");
        assert_eq!(binary["safe"], "kept");
    }

    #[test]
    fn raw_messagepack_redacts_binary_secrets_without_retyping_safe_fields() -> Result<()> {
        use rmpv::Value as M;
        let secret = b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec();
        let safe = M::Binary(vec![0, 255, 1]);
        let input = M::Map(vec![
            (M::from("safe"), safe.clone()),
            (
                M::from("nested"),
                M::Array(vec![M::Binary(secret.clone()), M::Ext(7, secret)]),
            ),
            (M::from("password"), M::Binary(b"legacy-password".to_vec())),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &input).unwrap();
        let projection = redacted_memory_body(&encoded);
        assert_eq!(projection["nested"][0], "[redacted]");
        let raw = redacted_memory_payload(encoded)?;
        let decoded = rmpv::decode::read_value(&mut raw.as_slice()).unwrap();
        assert_eq!(
            decoded,
            M::Map(vec![
                (M::from("safe"), safe),
                (
                    M::from("nested"),
                    M::Array(vec![M::from("[redacted]"), M::from("[redacted]")])
                ),
                (M::from("password"), M::from("[redacted]")),
            ])
        );
        assert_eq!(redacted_memory_payload(raw.clone())?, raw);
        Ok(())
    }

    #[test]
    fn export_legacy_payload_nulls_credentials_and_stamps_manifest() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let id = EntityId::now();
        let mut raw = vec![crate::registry::ENTITY_TYPE_PERSON];
        raw.extend_from_slice(&[0; 24]);
        rmpv::encode::write_value(
            &mut raw,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("safe"), rmpv::Value::from("kept")),
                (
                    rmpv::Value::from("encoded"),
                    rmpv::Value::Binary(b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec()),
                ),
                (
                    rmpv::Value::from("nested"),
                    rmpv::Value::Array(vec![rmpv::Value::Map(vec![(
                        rmpv::Value::from("password"),
                        rmpv::Value::from("legacy-fixture"),
                    )])]),
                ),
            ]),
        )
        .unwrap();
        let mut txn = vault.store.env.write_txn()?;
        vault.store.entities.put(&mut txn, id.as_bytes(), &raw)?;
        txn.commit()?;
        let bundle: Value = serde_json::from_slice(&vault.export_vault_json()?).unwrap();
        let entity = bundle["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id.to_hex())
            .unwrap();
        assert_eq!(entity["body"]["safe"], "kept");
        assert!(entity["body"]["nested"][0]["password"].is_null());
        assert!(entity["body"]["encoded"].is_null());
        assert_eq!(bundle["manifest"]["secrets_nulled"]["payloads"], true);
        Ok(())
    }
}

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

/// Replaces credential-like values and sensitive fields in decoded MessagePack
/// before any lossy projection; safe binary and extension values keep their
/// type. This never changes stored evidence.
pub fn redact_messagepack_credentials(value: &mut rmpv::Value) -> bool {
    crate::batch::secret_scan::sanitize_messagepack_credentials(value, false)
}

/// Filter a legacy raw transport without changing safe payload bytes or types.
pub fn redacted_memory_payload(bytes: Vec<u8>) -> Result<Vec<u8>> {
    // The original bytes go back only when no member of them is redacted: a
    // JSON map keeps only the last of two equal keys, so JSON is judged as a
    // tree that keeps every member, its keys included.
    if let Ok(mut value) = serde_json::from_slice::<rmpv::Value>(&bytes) {
        if !redact_messagepack_credentials(&mut value) {
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
    if crate::batch::secret_scan::scan_undecoded_body(&bytes).is_some() {
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
    } else if crate::batch::secret_scan::scan_undecoded_body(bytes).is_some() {
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
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            ids.push(row?.0);
        }
        drop(txn);
        self.export_entity_bundle_json(&ids)
    }

    /// Serializes an entity bundle through the whole-vault export boundary.
    /// Off-record rows and unpublished LFS chunks are excluded; custody
    /// containers are always nulled.
    /// The manifest is derived from the bytes, not a caller's declaration.
    pub fn export_entity_bundle_json(&self, ids: &[EntityId]) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        let mut nulled = false;
        for id in ids {
            if whole_vault_export_excludes_entity(self, id)? {
                continue;
            }
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, id)?
            else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::InvariantViolation("invalid export entity header"))?;
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &txn,
                id,
                header.entity_type,
            )? {
                continue;
            }
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
            } else if crate::batch::secret_scan::scan_undecoded_body(bytes).is_some() {
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
        // Binary items are read joined, as strings are: an array whose items
        // hold a secret leaves as one marker.
        assert_eq!(projection["nested"], "[redacted]");
        let raw = redacted_memory_payload(encoded)?;
        let decoded = rmpv::decode::read_value(&mut raw.as_slice()).unwrap();
        assert_eq!(
            decoded,
            M::Map(vec![
                (M::from("safe"), safe),
                (M::from("nested"), M::from("[redacted]")),
                (M::from("password"), M::from("[redacted]")),
            ])
        );
        assert_eq!(redacted_memory_payload(raw.clone())?, raw);
        Ok(())
    }

    #[test]
    fn raw_json_serving_reads_every_member_before_returning_the_original_bytes() -> Result<()> {
        let credential = "Xq7-not-for-memory-42";
        let repeated = format!(r#"{{"password":"{credential}","password":"[redacted]"}}"#);
        let served = redacted_memory_payload(repeated.into_bytes())?;
        assert!(!String::from_utf8_lossy(&served).contains(credential));
        // A token-shaped key, assembled at run time.
        let key = format!("gh{}_{}", 'p', "0123456789abcdefghijklmnopqrstuvwxyz");
        let keyed = format!(r#"{{"{key}":"note","safe":"kept"}}"#);
        let served = redacted_memory_payload(keyed.into_bytes())?;
        assert!(!String::from_utf8_lossy(&served).contains(&key));
        assert!(redacted_memory_body(&served)["safe"] == "kept");
        // A body with nothing to redact keeps its exact bytes.
        let safe = br#"{"a": 1,  "b": [true, null]}"#.to_vec();
        assert_eq!(redacted_memory_payload(safe.clone())?, safe);
        Ok(())
    }

    #[test]
    fn raw_serving_redacts_a_framed_receipt_whose_payload_holds_a_credential() -> Result<()> {
        let mut carrier = b"oneiron.refinement-receipt.v1\0".to_vec();
        carrier.extend_from_slice(&[7; 32]);
        carrier.extend_from_slice(
            br#"{"kind":"skill","receipt":{"question":"password=Xq7-not-for-memory-42"}}"#,
        );
        assert_eq!(
            redacted_memory_payload(carrier.clone())?,
            b"[redacted]".to_vec()
        );
        assert_eq!(
            redacted_memory_body(&carrier),
            Value::String("[redacted]".into())
        );
        Ok(())
    }

    #[test]
    fn a_body_nested_past_its_decoder_is_served_by_no_release_door() -> Result<()> {
        let member = r#"{"pass\u0077ord":"private fixture"}"#;
        let deep = format!("{}{member}{}", "[".repeat(129), "]".repeat(129)).into_bytes();
        assert_eq!(
            redacted_memory_payload(deep.clone())?,
            b"[redacted]".to_vec()
        );
        assert_eq!(
            redacted_memory_body(&deep),
            Value::String("[redacted]".into())
        );
        let asset = crate::registry::ENTITY_TYPE_ASSET;
        assert_eq!(
            crate::serialize::ExportBody::from_bytes(&deep, asset),
            crate::serialize::ExportBody::Nulled
        );
        // Brackets in text that is no JSON are text.
        let source = format!("[{}]", ["'['"; 127].join(","));
        assert_eq!(
            redacted_memory_payload(source.clone().into_bytes())?,
            source.as_bytes()
        );
        assert_eq!(
            crate::serialize::ExportBody::from_bytes(source.as_bytes(), asset),
            crate::serialize::ExportBody::Utf8(source)
        );
        Ok(())
    }

    #[test]
    fn a_credential_shaped_key_leaves_with_its_member_and_takes_no_real_key() -> Result<()> {
        // A token-shaped key, assembled at run time.
        let key = format!("gh{}_{}", 'p', "0123456789abcdefghijklmnopqrstuvwxyz");
        let json = format!(r#"{{"[redacted]":"kept","{key}":"discarded"}}"#);
        let served: Value = serde_json::from_slice(&redacted_memory_payload(json.into_bytes())?)
            .map_err(|_| Error::InvariantViolation("served JSON"))?;
        assert_eq!(served, serde_json::json!({"[redacted]": "kept"}));
        let map = rmpv::Value::Map(vec![
            (rmpv::Value::from("[redacted]"), rmpv::Value::from("kept")),
            (
                rmpv::Value::from(key.as_str()),
                rmpv::Value::from("discarded"),
            ),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &map).unwrap();
        let served = redacted_memory_payload(encoded)?;
        assert_eq!(
            rmpv::decode::read_value(&mut served.as_slice()).unwrap(),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("[redacted]"),
                rmpv::Value::from("kept")
            )])
        );
        Ok(())
    }

    /// A vault whose owner switched the write scan off, as an owner may: serve
    /// and export still redact in that mode.
    fn vault_with_scan_off() -> Result<(tempfile::TempDir, Vault)> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let id = crate::vault::embedded_owner_actor_id()?;
        let owner = vault.authenticate_owner(
            id,
            &id.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        vault.set_secret_scan_mode(&owner, crate::batch::secret_scan::SecretScanMode::Off, 10)?;
        Ok((dir, vault))
    }

    fn put_asset(vault: &Vault, body: &[u8]) -> Result<EntityId> {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_ASSET,
                crate::TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .commit()?;
        Ok(id)
    }

    /// The public BIP39 test vector, as a recovery phrase's words.
    const PHRASE: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn typed_export_reads_json_text_through_every_member() -> Result<()> {
        let (_dir, vault) = vault_with_scan_off()?;
        // A token-shaped value whose `p` is a JSON escape: no text rule reads it.
        let suffix = "0123456789abcdefghijklmnopqrstuvwxyz";
        let escaped = format!(r"gh\u0070_{suffix}");
        let scalar = format!(r#""{escaped}""#);
        let repeated = format!(r#"{{"note":"{escaped}","note":"kept"}}"#);
        for body in [scalar, repeated] {
            put_asset(&vault, body.as_bytes())?;
            let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
            let document = String::from_utf8_lossy(export.bytes()).into_owned();
            assert!(!document.contains(suffix), "{body}: {document}");
        }
        Ok(())
    }

    /// Whether an output still carries the fixture's word `sausage`, read as
    /// the release doors read text: strings, binary and extension bytes, and
    /// arrays of byte values.
    fn carries_sausage(bytes: &[u8]) -> bool {
        fn texts(value: &rmpv::Value, out: &mut String) {
            use rmpv::Value as M;
            match value {
                M::String(text) => out.push_str(&String::from_utf8_lossy(text.as_bytes())),
                M::Binary(bytes) | M::Ext(_, bytes) => {
                    out.push_str(&String::from_utf8_lossy(bytes));
                }
                M::Array(items) => match items
                    .iter()
                    .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect::<Option<Vec<u8>>>()
                {
                    Some(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
                    None => items.iter().for_each(|item| texts(item, out)),
                },
                M::Map(entries) => entries.iter().for_each(|(key, value)| {
                    texts(key, out);
                    texts(value, out);
                }),
                _ => {}
            }
            out.push('\n');
        }
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        if let Some(value) = crate::batch::secret_scan::decode_members(bytes) {
            texts(&value, &mut text);
        }
        text.contains("sausage")
    }

    #[test]
    fn a_phrase_one_byte_word_per_item_leaves_by_no_release_door() -> Result<()> {
        let (_dir, vault) = vault_with_scan_off()?;
        let words: Vec<&[u8]> = PHRASE.split(' ').map(str::as_bytes).collect();
        // One word per item: MessagePack binary, MessagePack byte values, the
        // two mixed, byte values each in an array of its own, and JSON byte
        // values bare and wrapped.
        let binary = |word: &[u8]| rmpv::Value::Binary(word.to_vec());
        let numbers =
            |word: &[u8]| rmpv::Value::Array(word.iter().map(|&b| rmpv::Value::from(b)).collect());
        let items = [
            words.iter().map(|word| binary(word)).collect::<Vec<_>>(),
            words.iter().map(|word| numbers(word)).collect(),
            words
                .iter()
                .enumerate()
                .map(|(at, word)| if at == 6 { numbers(word) } else { binary(word) })
                .collect(),
            words
                .iter()
                .map(|word| rmpv::Value::Array(vec![numbers(word)]))
                .collect(),
        ];
        let mut bodies = Vec::new();
        for value in items.map(rmpv::Value::Array) {
            let mut body = Vec::new();
            rmpv::encode::write_value(&mut body, &value).unwrap();
            bodies.push(body);
        }
        let wrapped: Vec<Vec<&[u8]>> = words.iter().map(|word| vec![*word]).collect();
        for value in [
            serde_json::json!({ "words": words }),
            serde_json::json!(wrapped),
        ] {
            // The context writers' walk reads the same values.
            let written = crate::serialize::null_credentials("", &value);
            assert!(
                !carries_sausage(written.to_string().as_bytes()),
                "{written}"
            );
            bodies.push(
                serde_json::to_vec(&value)
                    .map_err(|_| Error::InvariantViolation("fixture JSON"))?,
            );
        }
        for body in &bodies {
            assert!(carries_sausage(body));
            let id = put_asset(&vault, body)?;
            let stored = vault.get(&id)?.ok_or(Error::InvariantViolation("stored"))?;
            let served = redacted_memory_payload(stored)?;
            assert!(!carries_sausage(&served), "raw serving: {served:?}");
            let typed =
                crate::serialize::ExportBody::from_bytes(body, crate::registry::ENTITY_TYPE_ASSET);
            assert!(
                !typed.to_bytes().is_ok_and(|bytes| carries_sausage(&bytes)),
                "typed export: {typed:?}"
            );
            let bundle: Value = serde_json::from_slice(&vault.export_entity_bundle_json(&[id])?)
                .map_err(|_| Error::InvariantViolation("bundle JSON"))?;
            let emitted = bundle["entities"][0]["body"].to_string();
            assert!(
                !carries_sausage(emitted.as_bytes()),
                "bundle export: {emitted}"
            );
        }
        Ok(())
    }

    #[test]
    fn bundle_export_nulling_is_its_own_fixed_point() -> Result<()> {
        let (_dir, vault) = vault_with_scan_off()?;
        let words: Vec<&str> = PHRASE.split(' ').collect();
        // Between the two halves: an assignment, and another phrase one word
        // per line, which the whole run of 24 lines hides and which is read
        // alone.
        let other = format!("{}\nabout", ["abandon"; 11].join("\n"));
        for middle in ["password=fixture-value-1", other.as_str()] {
            let mut items = words.clone();
            items.insert(6, middle);
            let body = serde_json::to_vec(&serde_json::json!({ "words": items }))
                .map_err(|_| Error::InvariantViolation("fixture JSON"))?;
            let id = put_asset(&vault, &body)?;
            let bundle: Value = serde_json::from_slice(&vault.export_entity_bundle_json(&[id])?)
                .map_err(|_| Error::InvariantViolation("bundle JSON"))?;
            let mut emitted = bundle["entities"][0]["body"].clone();
            assert!(
                !emitted.to_string().contains("sausage"),
                "{middle}: {emitted}"
            );
            assert!(
                !crate::batch::secret_scan::sanitize_credentials(&mut emitted, true),
                "{middle}: a second pass changed {emitted}"
            );
            // The context writers' walk keeps the same fixed point.
            let written = crate::serialize::null_credentials("", &serde_json::json!(items));
            assert!(
                !written.to_string().contains("sausage"),
                "{middle}: {written}"
            );
            assert_eq!(crate::serialize::null_credentials("", &written), written);
        }
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

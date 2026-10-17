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

/// Whether the parts a reader serves from one claim (its predicate, value,
/// evidence and scope) read as a secret together, in their MessagePack form
/// and before any projection; a reader then serves none of them. A reader
/// serves the predicate as the text it is, so it is read as that text.
pub fn claim_reads_as_secret(body: &crate::claim::ClaimBody) -> bool {
    let predicate = rmpv::Value::from(body.predicate.as_str());
    let mut parts = vec![&body.value];
    parts.extend(body.evidence.as_ref());
    parts.extend(body.scope.as_ref());
    crate::batch::secret_scan::release_parts_read_whole(&[&predicate], &parts)
}

/// Whether the write door, scanning On, refuses these stored body bytes. A
/// door whose projection no read can follow exactly (context hydration, the
/// owner's run review) serves none of such a body, whatever the owner's
/// switch was when it was stored.
pub fn write_door_refuses_body(bytes: &[u8]) -> bool {
    crate::batch::secret_scan::scan_write_payload(bytes).is_err()
}

/// [`write_door_refuses_body`] over a claim as the write door reads a claim
/// candidate: its encoding.
pub fn write_door_refuses_claim(body: &crate::claim::ClaimBody) -> bool {
    match crate::claim::encode_claim_body(body) {
        Ok(bytes) => write_door_refuses_body(&bytes),
        Err(_) => true,
    }
}

/// Decoded MessagePack as a memory read serves it, as JSON. Its parts are
/// judged before the projection drops a float's width; then the projection
/// itself, still as MessagePack (a binary nulled, a non-text key dropped, a
/// repeated key folded, each number at its width), is read as the JSON it
/// becomes; then that JSON's text, for a credential the projection spells.
pub(crate) fn served_messagepack_json(value: rmpv::Value) -> Value {
    released_messagepack_json(value, None, false).0
}

/// [`served_messagepack_json`] over a body decoded from `stored`: its
/// encoding is read as it was stored, where a re-encoding would write each
/// number at its narrowest width.
pub(crate) fn served_stored_messagepack_json(stored: &[u8], value: rmpv::Value) -> Value {
    released_messagepack_json(value, Some(stored), false).0
}

/// [`served_messagepack_json`] with nulls in place of markers when `null`
/// (the export representation), and whether anything was removed.
fn released_messagepack_json(
    mut value: rmpv::Value,
    stored: Option<&[u8]>,
    null: bool,
) -> (Value, bool) {
    use crate::batch::secret_scan::{
        Encoding, sanitize_messagepack_credentials_in, sanitize_read_credentials,
    };
    let original = stored.map(|bytes| (value.clone(), bytes));
    let encoding = match &original {
        Some((original, bytes)) => Encoding::Stored { original, bytes },
        None => Encoding::Own,
    };
    let mut removed = sanitize_messagepack_credentials_in(&mut value, encoding, null);
    let mut projected = crate::serialize::msgpack_value_projection(&value);
    removed |= sanitize_messagepack_credentials_in(&mut projected, encoding, null);
    let mut json = crate::serialize::msgpack_value_to_json(&projected);
    removed |= sanitize_read_credentials(&mut json, null);
    (json, removed)
}

/// Filter a legacy raw transport without changing safe payload bytes or types.
pub fn redacted_memory_payload(bytes: Vec<u8>) -> Result<Vec<u8>> {
    use crate::batch::secret_scan::{Encoding, sanitize_messagepack_credentials_in};
    // The original bytes go back only when no member of them is redacted: a
    // JSON map keeps only the last of two equal keys, so JSON is judged as a
    // tree that keeps every member, its keys included.
    // Text that never was MessagePack has no encoding but its text to read.
    if let Ok(mut value) = serde_json::from_slice::<rmpv::Value>(&bytes) {
        if !sanitize_messagepack_credentials_in(&mut value, Encoding::Text, false) {
            return Ok(unchanged_or_marker(bytes, br#""[redacted]""#));
        }
        return serde_json::to_vec(&value)
            .map_err(|_| Error::InvariantViolation("redacted JSON encode failed"));
    }
    let mut cursor = std::io::Cursor::new(&bytes);
    if let Ok(mut value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        let original = value.clone();
        let stored = Encoding::Stored {
            original: &original,
            bytes: &bytes,
        };
        if !sanitize_messagepack_credentials_in(&mut value, stored, false) {
            // `[redacted]` as a MessagePack string.
            return Ok(unchanged_or_marker(bytes, b"\xaa[redacted]"));
        }
        // What is still as it was stored goes out in its stored bytes: the
        // encoding the whole read took.
        return crate::batch::secret_scan::encode_as_stored(&value, &original, &bytes).ok_or(
            Error::InvariantViolation("redacted MessagePack encode failed"),
        );
    }
    if crate::batch::secret_scan::scan_undecoded_body(&bytes).is_some() {
        Ok(b"[redacted]".to_vec())
    } else {
        Ok(bytes)
    }
}

/// Stored bytes go back as they are only when the write door's reading of
/// those very bytes refuses nothing: an encoding can differ from the decoded
/// value's own (a wider header, a length that reads as a line break).
fn unchanged_or_marker(bytes: Vec<u8>, marker: &[u8]) -> Vec<u8> {
    if crate::batch::secret_scan::write_door_refuses_raw(&bytes) {
        marker.to_vec()
    } else {
        bytes
    }
}

/// Decodes a memory payload without giving opaque bytes a way around the filter.
/// A credential in a non-structured body replaces the entire body. Each body
/// is read once, in the form it was stored.
pub fn redacted_memory_body(bytes: &[u8]) -> Value {
    let mut cursor = std::io::Cursor::new(bytes);
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        return served_stored_messagepack_json(bytes, value);
    }
    let mut value = if let Ok(value) = serde_json::from_slice(bytes) {
        value
    } else if crate::batch::secret_scan::scan_undecoded_body(bytes).is_some() {
        Value::String("[redacted]".into())
    } else {
        serde_json::json!({"bodyBytes": bytes})
    };
    crate::batch::secret_scan::sanitize_read_credentials(&mut value, false);
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
        let exported: std::collections::BTreeSet<EntityId> = ids.iter().copied().collect();
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
            // Words a deletion withdrew, or whose recorded sources no longer
            // stand, leave with the export too (I1).
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &txn,
                id,
                header.entity_type,
            )? || (raw.len() > ENTITY_METADATA_HEADER_LEN
                && !crate::ports::raw_readable_in_txn(&self.store, &txn, id, &raw)?)
            {
                continue;
            }
            let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
            // An epoch summary leaves only beside every record it was written
            // from, nested summaries included; otherwise it stays home.
            if crate::compaction::epoch_sources_admitted_in(&self.store, &txn, id, bytes, |source, _| {
                Ok(exported.contains(source) && !whole_vault_export_excludes_entity(self, source)?)
            })? == Some(false)
            {
                continue;
            }
            let mut cursor = std::io::Cursor::new(bytes);
            let mut body = if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
                nulled = true;
                Value::Null
            } else if let Ok(value) = rmpv::decode::read_value(&mut cursor)
                && cursor.position() == bytes.len() as u64
            {
                let (value, removed) = released_messagepack_json(value, Some(bytes), true);
                nulled |= removed;
                value
            } else if let Ok(mut value) = serde_json::from_slice(bytes) {
                nulled |= crate::batch::secret_scan::sanitize_read_credentials(&mut value, true);
                value
            } else if crate::batch::secret_scan::scan_undecoded_body(bytes).is_some() {
                nulled = true;
                Value::Null
            } else {
                let mut value = serde_json::json!({"bodyBytes": bytes});
                nulled |= crate::batch::secret_scan::sanitize_read_credentials(&mut value, true);
                value
            };
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
    /// the release doors read text: strings, binary and extension bytes,
    /// arrays of byte values, and the MessagePack a decoded output encodes to.
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
            let mut encoded = Vec::new();
            rmpv::encode::write_value(&mut encoded, &value).unwrap();
            text.push_str(&String::from_utf8_lossy(&encoded));
        }
        text.contains("sausage")
    }

    #[test]
    fn a_phrase_one_byte_word_per_item_leaves_by_no_release_door() -> Result<()> {
        let (_dir, vault) = vault_with_scan_off()?;
        let words: Vec<&[u8]> = PHRASE.split(' ').map(str::as_bytes).collect();
        // One word per item: MessagePack binary, MessagePack byte values, the
        // two mixed, byte values each in an array of its own, the phrase's
        // byte values after a line break, a word per 64-bit number, and JSON
        // byte values bare and wrapped.
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
            std::iter::once(rmpv::Value::from("\n"))
                .chain(PHRASE.bytes().map(rmpv::Value::from))
                .collect(),
            words
                .iter()
                .map(|word| rmpv::Value::from(u64::from_be_bytes(padded(word))))
                .collect(),
        ];
        let values = items.map(rmpv::Value::Array);
        let mut bodies = Vec::new();
        for value in &values {
            let mut body = Vec::new();
            rmpv::encode::write_value(&mut body, value).unwrap();
            // The write door refuses each in its raw bytes.
            assert!(
                crate::batch::secret_scan::scan_write_payload(&body).is_err(),
                "{value}"
            );
            // A reader that projects it to JSON redacts the projection.
            let mut projected = crate::serialize::msgpack_value_to_json(value);
            redact_credentials(&mut projected);
            assert!(
                !carries_sausage(projected.to_string().as_bytes()),
                "projected: {projected}"
            );
            bodies.push(body);
        }
        let wrapped: Vec<Vec<&[u8]>> = words.iter().map(|word| vec![*word]).collect();
        for value in [
            serde_json::json!({ "words": words }),
            serde_json::json!(wrapped),
        ] {
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
        // The context writers read what hydration hands them: of a body the
        // write door refuses, nothing, though a map gives it a field to
        // hydrate (Wonder R1). The key ends in a stop, so the words after it
        // still stand alone in the raw bytes. A body it accepts still
        // hydrates.
        for value in values {
            let mut body = Vec::new();
            let field = rmpv::Value::Map(vec![("notes:".into(), value)]);
            rmpv::encode::write_value(&mut body, &field).unwrap();
            assert!(
                crate::batch::secret_scan::scan_write_payload(&body).is_err(),
                "{field}"
            );
            put_asset(&vault, &body)?;
        }
        let mut kept = Vec::new();
        rmpv::encode::write_value(
            &mut kept,
            &rmpv::Value::Map(vec![("title".into(), "kept asset words".into())]),
        )
        .unwrap();
        put_asset(&vault, &kept)?;
        for format in [
            crate::context_pack::PackFormat::Json,
            crate::context_pack::PackFormat::Yaml,
            crate::context_pack::PackFormat::Toon,
            crate::context_pack::PackFormat::Markdown,
            crate::context_pack::PackFormat::Plaintext,
        ] {
            let pack = vault
                .context_pack()
                .search_temporal(1, 1, 64)
                .filter_types(&[crate::registry::ENTITY_TYPE_ASSET])
                .field_profile(crate::context_pack::FieldProfile::Full)
                .token_budget(0)
                .max_field_chars(0)
                .max_item_tokens(0)
                .format(format)
                .run_serialized()?;
            let text = String::from_utf8_lossy(&pack);
            assert!(text.contains("kept asset words"), "{format:?}: {text}");
            assert!(!carries_sausage(&pack), "{format:?}: {text}");
        }
        Ok(())
    }

    /// A word padded to the eight bytes of a 64-bit number.
    fn padded(word: &[u8]) -> [u8; 8] {
        let mut padded = [b' '; 8];
        padded[..word.len()].copy_from_slice(word);
        padded
    }

    #[test]
    fn raw_serving_reads_the_bytes_it_returns() -> Result<()> {
        // Each map's 16-bit length ends in a line break, which stands the
        // phrase (a word per number) on a line of its own in these bytes; the
        // value's own encoding has no such break, so `xyzzy` joins the words.
        let mut body = vec![0x94, 0xcf];
        body.extend(padded(b"xyzzy"));
        body.extend([0xde, 0x00, 0x0a]);
        for word in PHRASE.split(' ') {
            body.push(0xcf);
            body.extend(padded(word.as_bytes()));
        }
        body.extend([0xc0; 8]);
        body.extend([0xde, 0x00, 0x0a]);
        body.extend([0xc0; 20]);
        body.push(0xcf);
        body.extend(padded(b"xyzzy"));
        assert!(crate::batch::secret_scan::scan_write_payload(&body).is_err());
        let served = redacted_memory_payload(body)?;
        assert!(!carries_sausage(&served), "{served:?}");
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

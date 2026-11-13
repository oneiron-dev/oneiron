//! Core half of `batch::export::credential_filter`: its store-layer items live in `oneiron_store::batch::export::credential_filter` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::export::credential_filter::*;

use super::bundle_lineage::BundleLineage;
use super::{
    ExportManifest, ExportScope, ExportSecretsNulledManifest, carries_embedding_setup,
    whole_vault_export_excludes_entity_in_txn,
};
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
pub fn claim_reads_as_secret(body: &crate::write_envelope::claim_body::ClaimBody) -> bool {
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
pub fn write_door_refuses_claim(body: &crate::write_envelope::claim_body::ClaimBody) -> bool {
    match crate::write_envelope::claim_body::encode_claim_body(body) {
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

/// What the partial archive's typed Nulled rule releases of one stored body
/// to a reader whose grant admits no credential: the one rule of the scoped
/// export and the contact bundle ([`released_body`]).
pub(crate) enum ReleasedBody {
    /// The rule and the raw release check change nothing: the stored body
    /// goes as it is.
    Unchanged,
    /// The Nulled typed body, and its bytes, which the raw check leaves alone.
    Rewritten {
        body: crate::serialize::ExportBody,
        bytes: Vec<u8>,
    },
    /// Nothing of the body goes.
    Withheld,
}

/// One stored body under the partial archive's typed Nulled rule. If that
/// rule and the raw release check change nothing, the body is
/// [`ReleasedBody::Unchanged`]. Otherwise it is the Nulled typed body, only if
/// the raw check leaves that body's bytes alone. A changed ASSET or
/// proof-bound body is withheld, never rewritten. So is a changed body that is
/// Nulled, is a file reference, cannot encode, or no longer decodes as its
/// native CLAIM or SKILL record.
///
/// # Errors
/// A failed raw release check.
pub(crate) fn released_body(entity_type: u8, body: &[u8]) -> Result<ReleasedBody> {
    use crate::serialize::{ExportBody, ExportSecrets};

    let nulled = ExportBody::from_bytes(body, entity_type);
    let included = ExportBody::from_bytes_with(body, entity_type, ExportSecrets::Included);
    let raw_unchanged = redacted_memory_payload(body.to_vec())? == body;
    if nulled == included && raw_unchanged {
        return Ok(ReleasedBody::Unchanged);
    }
    if entity_type == crate::registry::ENTITY_TYPE_ASSET
        || proof_bound_body(entity_type, body)
        || matches!(nulled, ExportBody::Nulled | ExportBody::File(_))
    {
        return Ok(ReleasedBody::Withheld);
    }
    let Ok(rewritten) = nulled.to_bytes() else {
        return Ok(ReleasedBody::Withheld);
    };
    if redacted_memory_payload(rewritten.clone())? != rewritten {
        return Ok(ReleasedBody::Withheld);
    }
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && crate::write_envelope::claim_body::decode_claim_body(&rewritten, true).is_err()
    {
        return Ok(ReleasedBody::Withheld);
    }
    if entity_type == crate::registry::ENTITY_TYPE_SKILL
        && crate::skill::decode_skill_record(&rewritten).is_err()
    {
        return Ok(ReleasedBody::Withheld);
    }
    Ok(ReleasedBody::Rewritten {
        body: nulled,
        bytes: rewritten,
    })
}

/// Release one scoped record with [`released_body`]: an unchanged body keeps
/// the record byte-exact; a rewritten one goes as its bytes inside the
/// record's id and original metadata header; a withheld one leaves no record.
///
/// # Errors
/// A record shorter than its header, or a failed raw release check.
pub(crate) fn export_released_record(
    entity_type: u8,
    mut record: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    if record.len() < ENTITY_METADATA_HEADER_LEN {
        return Err(Error::CorruptedIndex("scoped export record header"));
    }
    let body = record.split_off(ENTITY_METADATA_HEADER_LEN);
    match released_body(entity_type, &body)? {
        ReleasedBody::Unchanged => record.extend_from_slice(&body),
        ReleasedBody::Rewritten { bytes, .. } => record.extend_from_slice(&bytes),
        ReleasedBody::Withheld => return Ok(None),
    }
    Ok(Some(record))
}

/// A contact bundle's body for a stored body that [`released_body`] changes,
/// and whether a credential was nulled from it; `None` when the rule changes
/// nothing, and the body keeps the bundle's JSON reading. A rewritten
/// MessagePack body goes as its Nulled typed tree's JSON, only if the JSON
/// read of that JSON nulls nothing more; a credential was nulled when that
/// JSON differs from the Included tree's, so a body whose only change is an
/// opaque binary, which JSON never carries, names none. Any other changed
/// body goes as null.
fn released_bundle_body(entity_type: u8, body: &[u8]) -> Result<Option<(Value, bool)>> {
    use crate::serialize::{ExportBody, ExportSecrets};

    let value = match released_body(entity_type, body)? {
        ReleasedBody::Unchanged => return Ok(None),
        ReleasedBody::Rewritten {
            body: ExportBody::MessagePack(value),
            ..
        } => value,
        ReleasedBody::Rewritten { .. } | ReleasedBody::Withheld => {
            return Ok(Some((Value::Null, true)));
        }
    };
    let Ok(json) = value.to_released_json() else {
        return Ok(Some((Value::Null, true)));
    };
    if crate::batch::secret_scan::sanitize_read_credentials(&mut json.clone(), true) {
        return Ok(Some((Value::Null, true)));
    }
    let included = match ExportBody::from_bytes_with(body, entity_type, ExportSecrets::Included) {
        ExportBody::MessagePack(value) => value.to_released_json().ok(),
        _ => None,
    };
    let nulled = included.as_ref() != Some(&json);
    Ok(Some((json, nulled)))
}

fn proof_bound_body(entity_type: u8, body: &[u8]) -> bool {
    use crate::registry::{
        ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_RECEIPT_RECORD,
        ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    };

    if matches!(
        entity_type,
        ENTITY_TYPE_AUTHORITY_LOG
            | ENTITY_TYPE_REDACTION_AUDIT
            | ENTITY_TYPE_SKILL_CONTENT_ANCHOR
            | ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
            | ENTITY_TYPE_RECEIPT_RECORD
            | ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR
    ) {
        return true;
    }
    if entity_type != ENTITY_TYPE_CLAIM {
        return false;
    }
    let Ok(claim) = crate::write_envelope::claim_body::decode_claim_body(body, true) else {
        return true;
    };
    crate::claim::history_store::machine_history_kind(&claim.predicate).is_some()
        || claim.evidence.as_ref().is_some_and(|evidence| {
            evidence.as_map().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|(key, _)| key.as_str() == Some("machine_signature"))
            })
        })
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
    /// Beside its entities it carries the vault's embedding setup (OF-370):
    /// `embedding_spaces`, each declared space's descriptor in id order, and
    /// `slot_bindings`, the three kind slots; no vector. It has no importer.
    pub fn export_vault_json(&self) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            ids.push(row?.0);
        }
        drop(txn);
        self.entity_bundle_json(&ids, ExportScope::WholeVault)
    }

    /// Serializes an entity bundle through the whole-vault export boundary.
    /// Off-record rows and unpublished LFS chunks are excluded; custody
    /// containers are always nulled. Every other body is read by the scoped
    /// export's typed Nulled rule ([`released_body`]): a body it changes goes
    /// as the JSON of its Nulled typed tree, or as null when the rule
    /// withholds it.
    /// The manifest is derived from the bytes, not a caller's declaration.
    pub fn export_entity_bundle_json(&self, ids: &[EntityId]) -> Result<Vec<u8>> {
        self.entity_bundle_json(ids, ExportScope::Records)
    }

    /// The bundle both doors write; `scope` decides whether it carries the
    /// embedding setup. The whole vault's copy is the owner's, in its export
    /// audit (FIX 6427). One that carries another member's personal mailbox
    /// leaves only once its audit row and each mailbox's person's notice are
    /// written, in one write (fix list row 15416); when that write does not
    /// commit, the copy is made again without those mailboxes, each named in
    /// it, and recorded as any other copy is, never withheld (L5-17). Once it
    /// commits, the copy leaves as it was recorded, under its one export id,
    /// even when a step after the commit fails.
    fn entity_bundle_json(&self, ids: &[EntityId], scope: ExportScope) -> Result<Vec<u8>> {
        let bundle = self.entity_bundle_pass(ids, scope, false)?;
        if scope != ExportScope::WholeVault {
            return Ok(bundle.json);
        }
        let Some(member_mail) = bundle.member_mail else {
            crate::memory::record_raw_json_export(self, &bundle.json, bundle.thread_roots);
            return Ok(bundle.json);
        };
        match crate::memory::record_member_mail_json_export(
            self,
            &bundle.json,
            bundle.thread_roots,
            &member_mail,
        ) {
            Ok(()) => Ok(bundle.json),
            // The write did not commit: no audit row and no notice of it
            // stands.
            Err(error) => {
                tracing::warn!(
                    %error,
                    "JSON export: members' mailboxes left out, their people not told"
                );
                let bundle = self.entity_bundle_pass(ids, scope, true)?;
                if bundle.member_mail.is_some() {
                    return Err(Error::InvariantViolation(
                        "an export whose mailboxes' people were not told carries a mailbox",
                    ));
                }
                // The copy made again is recorded as any other copy is, its
                // row counting no mailbox, and never withheld (L5-17).
                crate::memory::record_remade_json_export(self, &bundle.json, bundle.thread_roots);
                Ok(bundle.json)
            }
        }
    }

    /// One pass of the bundle over `ids` in a snapshot of its own. A
    /// whole-vault pass of a shared vault leaves out each row of a member's
    /// personal mailbox it does not carry, and each row whose words came from
    /// one ([`crate::mail_pack::MemberMailboxPlan`]), before the row is read
    /// whole, and names each such mailbox in `mailbox_notices`; with
    /// `untold`, it carries no member's mailbox.
    fn entity_bundle_pass(
        &self,
        ids: &[EntityId],
        scope: ExportScope,
        untold: bool,
    ) -> Result<BundlePass> {
        let txn = self.store.env.read_txn()?;
        let plan = if scope == ExportScope::WholeVault {
            let exporter = crate::vault::embedded_owner_actor_id()?;
            crate::mail_pack::MemberMailboxPlan::read_in(self, &txn, exporter, untold)?
        } else {
            None
        };
        let dbs = self.store.read();
        let mut judge = plan
            .as_ref()
            .map(|plan| plan.judge(self, &dbs, &txn))
            .transpose()?;
        let mut lineage = BundleLineage::read_in(&self.store, &txn, judge.is_some())?;
        let exported: std::collections::BTreeSet<EntityId> = ids.iter().copied().collect();
        let mut records = Vec::new();
        let mut nulled = false;
        let mut thread_roots = crate::workspace_roster::ExportThreadRoots::default();
        for id in ids {
            if whole_vault_export_excludes_entity_in_txn(&self.store, &txn, id)? {
                continue;
            }
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, id)?
            else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::InvariantViolation("invalid export entity header"))?;
            // Words a deletion withdrew, or whose recorded sources no longer
            // stand, leave with the export too (I1). The whole vault's
            // bundle keeps a record a cleanup archive filed away (FIX 21912).
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &txn,
                id,
                header.entity_type,
            )? || (raw.len() > ENTITY_METADATA_HEADER_LEN
                && !(if scope == ExportScope::WholeVault {
                    crate::ports::raw_exportable_in_txn(&self.store, &txn, id, &raw)?
                } else {
                    crate::ports::raw_readable_in_txn(&self.store, &txn, id, &raw)?
                }))
            {
                continue;
            }
            // A member's mailbox the copy does not carry, and what was
            // learned from it, stay home (fix list row 15416).
            let Some(sources) = lineage.admitted(judge.as_mut(), *id, header.entity_type, &raw)?
            else {
                continue;
            };
            // A file-plane ASSET leaves as its body, never the manifest its
            // row keeps (FIX 3677).
            let raw = self.materialized_row_in_txn(&txn, id, raw)?;
            let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
            // An epoch summary leaves only beside every record it was written
            // from, nested summaries included; otherwise it stays home.
            if crate::compaction::epoch_sources_admitted_in(
                &self.store,
                &txn,
                id,
                bytes,
                |source, _| {
                    Ok(exported.contains(source)
                        && !whole_vault_export_excludes_entity_in_txn(&self.store, &txn, source)?
                        && lineage.carried_by(judge.as_mut(), *source)?)
                },
            )? == Some(false)
            {
                continue;
            }
            // A contact bundle (Records scope) releases each body by the
            // scoped export's typed Nulled rule (ARCH-0038 CONS-06/09): a
            // body the rule changes goes as its Nulled typed tree's JSON or
            // as null, and one it leaves unchanged keeps the reading below.
            // The owner's whole-vault JSON keeps that reading alone.
            let released = match scope {
                ExportScope::Records
                    if header.entity_type != crate::registry::ENTITY_TYPE_SECRET_CUSTODY =>
                {
                    released_bundle_body(header.entity_type, bytes)?
                }
                _ => None,
            };
            let mut cursor = std::io::Cursor::new(bytes);
            let mut body = if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
                nulled = true;
                Value::Null
            } else if let Some((value, removed)) = released {
                nulled |= removed;
                value
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
            thread_roots.extend(crate::memory::turn_thread_root(header.entity_type, bytes));
            // The copy carries a member's mailbox only through a row it ships
            // (fix list row 15416).
            if let Some(judge) = judge.as_mut() {
                lineage.ships(judge, *id, sources);
            }
            records.push((
                *id,
                serde_json::json!({
                    "id": id.to_hex(), "entity_type": header.entity_type,
                    "occurred_start": header.occurred_start, "occurred_end": header.occurred_end,
                    "learned_at": header.learned_at, "body": body,
                }),
            ));
        }
        // A birth leaves naming only the rows this bundle carries (Q26 = B);
        // one key per export, so its handles link to no other copy.
        let ships: std::collections::BTreeSet<EntityId> =
            records.iter().map(|(id, _)| *id).collect();
        let key = crate::store::row_birth::WithheldKey::for_export();
        let mut entities = Vec::with_capacity(records.len());
        for (id, mut record) in records {
            if let Some(birth) =
                crate::store::birth_record::row_birth_in_txn(&self.store, &txn, &id)?
                && let Some(fields) = record.as_object_mut()
            {
                let birth = serde_json::to_value(birth.masked(|row| ships.contains(row), &key))
                    .map_err(|_| Error::InvariantViolation("export birth JSON encode failed"))?;
                fields.insert("birth".into(), birth);
            }
            entities.push(record);
        }
        // OF-370: the setup is read in this snapshot, each descriptor through
        // this bundle's nulling pass; one the pass would change is withheld.
        let setup = if carries_embedding_setup(scope) {
            let setup = super::embedding_setup_in_txn(&self.store, &txn)?.released(|value| {
                crate::batch::secret_scan::sanitize_read_credentials(&mut value.clone(), true)
            })?;
            nulled |= !setup.withheld.is_empty();
            Some(setup)
        } else {
            None
        };
        let manifest =
            ExportManifest::from_secrets_nulled(ExportSecretsNulledManifest::from_redacted(nulled));
        let mut bundle = match setup {
            Some(setup) => serde_json::json!({
                "manifest": manifest, "entities": entities,
                "embedding_spaces": setup.spaces, "slot_bindings": setup.slots,
                "embedding_setup_withheld": setup.withheld,
            }),
            None => serde_json::json!({"manifest": manifest, "entities": entities}),
        };
        // Each mailbox the pass left out is named beside the entities, to
        // the Owner who exported; what it carried waits for its people.
        let met = judge.map(crate::source_audience::ExportJudge::met);
        let mut member_mail = None;
        if let Some((plan, met)) = plan.zip(met) {
            let (notices, carried) = plan.outcome(&met);
            member_mail = carried;
            let notices = serde_json::to_value(notices)
                .map_err(|_| Error::InvariantViolation("export mailbox notices encode failed"))?;
            if let Some(fields) = bundle.as_object_mut() {
                fields.insert("mailbox_notices".into(), notices);
            }
        }
        let json = serde_json::to_vec(&bundle)
            .map_err(|_| Error::InvariantViolation("entity export JSON encode failed"))?;
        if scope == ExportScope::WholeVault {
            thread_roots.capture_in(&dbs, &txn);
        }
        Ok(BundlePass {
            json,
            thread_roots,
            member_mail,
        })
    }
}

/// One pass of an entity bundle: its bytes, the private threads it carries,
/// and the other members' personal mailboxes it carries, whose people are
/// told before it leaves (fix list row 15416).
struct BundlePass {
    json: Vec<u8>,
    thread_roots: crate::workspace_roster::ExportThreadRoots,
    member_mail: Option<crate::mail_pack::CarriedMemberMailboxes>,
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

    /// CONS-07 (owner ruling 2026-10-17, ARCH-0038 #export-credentials): the
    /// typed export still reads JSON text through every member, so a token
    /// hidden behind JSON escapes or duplicate keys never leaves a scoped or
    /// contact export; the Owner's whole-vault export keeps those bytes
    /// byte-equal to stored.
    #[test]
    fn typed_export_reads_json_text_through_every_member() -> Result<()> {
        let (_dir, vault) = vault_with_scan_off()?;
        // A token-shaped value whose `p` is a JSON escape: no text rule reads it.
        let suffix = "0123456789abcdefghijklmnopqrstuvwxyz";
        let escaped = format!(r"gh\u0070_{suffix}");
        let scalar = format!(r#""{escaped}""#);
        let repeated = format!(r#"{{"note":"{escaped}","note":"kept"}}"#);
        let bodies = [scalar, repeated];
        let mut ids = Vec::new();
        for body in &bodies {
            ids.push(put_asset(&vault, body.as_bytes())?);
        }
        // The Owner's whole-vault export keeps each body byte-equal to stored.
        let export = vault.export_whole_vault(true)?;
        export.manifest().validate()?;
        assert!(export.manifest().secrets_included);
        let document = vault.read_whole_vault_archive(export.bytes())?;
        for (id, body) in ids.iter().zip(bodies.iter()) {
            let row = document
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == id.to_hex())
                .expect("exported row");
            assert_eq!(
                row.body,
                crate::serialize::ExportBody::Utf8(body.clone()),
                "the owner's archive keeps {body} byte-equal"
            );
        }
        // A scoped export still nulls them: an ASSET the release filter would
        // change leaves whole or not at all.
        let top = crate::federation::Scope::top();
        let scoped = vault.export_records_in_scope(&top, &top, &top)?;
        for id in &ids {
            for record in scoped.iter().filter(|record| record.id == *id) {
                assert!(
                    !String::from_utf8_lossy(&record.bytes).contains(suffix),
                    "a scoped record carries no token"
                );
            }
        }
        let shipped: Vec<u8> = scoped
            .iter()
            .flat_map(|record| record.bytes.iter().copied())
            .collect();
        assert!(
            !String::from_utf8_lossy(&shipped).contains(suffix),
            "the scoped export carries no token"
        );
        // A contact's shareable bundle still nulls them.
        let bundle: Value = serde_json::from_slice(&vault.export_entity_bundle_json(&ids)?)
            .map_err(|_| Error::InvariantViolation("bundle JSON"))?;
        assert!(
            !bundle.to_string().contains(suffix),
            "contact bundle: {bundle}"
        );
        let entities = bundle["entities"].as_array().expect("bundle entities");
        assert_eq!(entities.len(), 2);
        assert!(
            entities[0]["body"].is_null(),
            "the scalar token is nulled: {}",
            entities[0]["body"]
        );
        assert_eq!(bundle["manifest"]["secrets_nulled"]["payloads"], true);
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

    /// The vault's custody rows, by id.
    fn custody_records(vault: &Vault) -> Result<Vec<EntityId>> {
        let rtxn = vault.store.env.read_txn()?;
        Ok(crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &vault.store,
            &rtxn,
            crate::registry::ENTITY_TYPE_SECRET_CUSTODY,
            None,
        )?
        .collect::<Result<Vec<_>>>()?)
    }

    /// LABEL-04 (ARCH-0069 #mask-on-write, #handles-in-fields): a split
    /// recovery phrase is masked on write — the write lands, never refused,
    /// and the hit is sealed into custody with a handle — while read, export
    /// and pack still withhold it (ARCH-0069 #readers-built).
    #[test]
    fn a_phrase_one_byte_word_per_item_leaves_by_no_release_door() -> Result<()> {
        // Mask on write applies: the default vault leaves the owner's scan switch on.
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
        let (_residue_dir, residue_vault) = vault_with_scan_off()?;
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
        let custody_before = custody_records(&vault)?.len();
        for body in &bodies {
            assert!(carries_sausage(body));
            // The write lands, never refused; the hit is sealed into custody,
            // and the file's mark covers each word: the stored bytes stay the
            // owner's (owner ruling G04 binary = C2), and a masked reader is
            // served no word.
            let id = put_asset(&vault, body).expect("LABEL-04: a split-phrase write lands");
            let stored = vault.get(&id)?.ok_or(Error::InvariantViolation("stored"))?;
            assert_eq!(&stored, body, "the stored file stays the owner's");
            let masked = vault
                .sighted_asset_bytes(stored.clone(), crate::secret_custody::SecretSight::Masked)?;
            assert!(!carries_sausage(&masked), "masked reader: {masked:?}");
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
            // Independent release coverage: the scan-off write still holds
            // the phrase, so masking at the write door cannot satisfy these.
            let residue = put_asset(&residue_vault, body)?;
            let stored = residue_vault
                .get(&residue)?
                .ok_or(Error::InvariantViolation("stored residue"))?;
            assert_eq!(
                &stored, body,
                "scan-off residue keeps the exact fixture bytes"
            );
            assert!(
                carries_sausage(&stored),
                "release fixture still holds the phrase"
            );
            let served = redacted_memory_payload(stored)?;
            assert!(
                !carries_sausage(&served),
                "residual raw serving: {served:?}"
            );
            let bundle: Value =
                serde_json::from_slice(&residue_vault.export_entity_bundle_json(&[residue])?)
                    .map_err(|_| Error::InvariantViolation("residual bundle JSON"))?;
            let entities = bundle["entities"]
                .as_array()
                .expect("residual bundle entities");
            assert_eq!(entities.len(), 1);
            assert_eq!(entities[0]["id"], residue.to_hex());
            let emitted = entities[0]["body"].to_string();
            assert!(
                !carries_sausage(emitted.as_bytes()),
                "residual bundle export: {emitted}"
            );
            assert!(
                !carries_sausage(bundle.to_string().as_bytes()),
                "residual bundle export: {bundle}"
            );
        }
        // The hits were sealed into custody, not dropped.
        assert!(
            custody_records(&vault)?.len() > custody_before,
            "split-phrase hits are sealed into custody"
        );
        // The context writers read what hydration hands them: of a masked
        // body, its handle, never the phrase. A map gives it a field to
        // hydrate (Wonder R1). The key ends in a stop, so the words after it
        // still stand alone in the raw bytes. A body it accepts still
        // hydrates.
        for value in values {
            let mut body = Vec::new();
            let field = rmpv::Value::Map(vec![("notes:".into(), value)]);
            rmpv::encode::write_value(&mut body, &field).unwrap();
            let residue = put_asset(&residue_vault, &body)?;
            let stored = residue_vault
                .get(&residue)?
                .ok_or(Error::InvariantViolation("stored mapped residue"))?;
            assert_eq!(
                stored, body,
                "scan-off mapped residue keeps the fixture bytes"
            );
            assert!(
                carries_sausage(&stored),
                "pack fixture still holds the phrase"
            );
            let id = put_asset(&vault, &body).expect("LABEL-04: a mapped split-phrase write lands");
            let stored = vault.get(&id)?.ok_or(Error::InvariantViolation("stored"))?;
            assert_eq!(stored, body, "the stored file stays the owner's");
            let masked =
                vault.sighted_asset_bytes(stored, crate::secret_custody::SecretSight::Masked)?;
            assert!(!carries_sausage(&masked), "masked reader: {masked:?}");
        }
        let mut kept = Vec::new();
        rmpv::encode::write_value(
            &mut kept,
            &rmpv::Value::Map(vec![("title".into(), "kept asset words".into())]),
        )
        .unwrap();
        for pack_vault in [&vault, &residue_vault] {
            put_asset(pack_vault, &kept)?;
            for format in [
                crate::context_pack::PackFormat::Json,
                crate::context_pack::PackFormat::Yaml,
                crate::context_pack::PackFormat::Toon,
                crate::context_pack::PackFormat::Markdown,
                crate::context_pack::PackFormat::Plaintext,
            ] {
                let pack = pack_vault
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

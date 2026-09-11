//! Owner-consented export, MemoryPack-lite and markdown renders, export-record persistence.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use super::codec::{
    decode_persona_snapshot_export_body, encode_persona_snapshot_export_body, hash_hex,
    invalid_snapshot,
};
use super::compile::{markdown_safe_line, verify_compile_against_stamp};
use super::types::{
    MEMORY_PACK_LITE_SCHEMA_VERSION, PersonaSnapshotArtifact, PersonaSnapshotCompile,
    PersonaSnapshotExportConsent, PersonaSnapshotExportRecord, PersonaSnapshotRow,
    PersonaSnapshotRowKind, PersonaSnapshotStrikeList, STRUCK_IDENTITY_LINE_PLACEHOLDER,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT;
use crate::temporal::TimeRange;

impl crate::Vault {
    /// Exports the OF-325 persona snapshot artifact (mode A): applies the
    /// preview strike-list over `compile`, renders BOTH artifacts from the
    /// one compile, persists the export record, and thereby emits the Share
    /// receipt carrying `persona_compile_stamp`.
    ///
    /// Consent is content-addressed: `consent.compile_stamp` must equal the
    /// compile's stamp identity, so consent granted over one preview can
    /// never issue a different compile.
    pub fn export_persona_snapshot(
        &self,
        compile: &PersonaSnapshotCompile,
        strikes: &PersonaSnapshotStrikeList,
        consent: &PersonaSnapshotExportConsent,
    ) -> Result<PersonaSnapshotArtifact> {
        if consent.granted_by.trim().is_empty() {
            return Err(invalid_snapshot(
                "export consent granted_by must be non-empty",
            ));
        }
        verify_compile_against_stamp(compile)?;
        let compile_stamp = compile.stamp.identity();
        if consent.compile_stamp != compile_stamp {
            return Err(Error::Gate(GateError::PersonaSnapshotConsentStale {
                consent_stamp: consent.compile_stamp.clone(),
                compile_stamp,
            }));
        }

        let known_row_ids: BTreeSet<&str> =
            compile.rows.iter().map(|row| row.row_id.as_str()).collect();
        for row_id in strikes.strike.iter().chain(strikes.unstrike.iter()) {
            if !known_row_ids.contains(row_id.as_str()) {
                return Err(invalid_snapshot("strike list references unknown row id"));
            }
        }
        if strikes
            .strike
            .iter()
            .any(|row_id| strikes.unstrike.contains(row_id))
        {
            return Err(invalid_snapshot("strike and unstrike must not overlap"));
        }

        let mut included = Vec::new();
        let mut struck_row_ids = Vec::new();
        for row in &compile.rows {
            let struck = (row.struck || strikes.strike.contains(&row.row_id))
                && !strikes.unstrike.contains(&row.row_id);
            if struck {
                struck_row_ids.push(row.row_id.clone());
            } else {
                included.push(row);
            }
        }
        let included_row_ids: Vec<String> = included.iter().map(|row| row.row_id.clone()).collect();

        let identity_included = included
            .iter()
            .any(|row| row.kind == PersonaSnapshotRowKind::Identity);
        let memory_pack_json = render_memory_pack_lite(compile, &included, identity_included);
        let markdown = render_markdown_card(compile, &included, identity_included);

        let mut artifact_bytes = Vec::new();
        artifact_bytes.extend_from_slice(memory_pack_json.as_bytes());
        artifact_bytes.push(0);
        artifact_bytes.extend_from_slice(markdown.as_bytes());
        let artifact_fingerprint = hash_hex(&artifact_bytes);

        // A struck identity row means the name/role never leaves the vault:
        // the export record is itself a queryable row, so it must not retain
        // the struck text either.
        let recorded_identity_line = if identity_included {
            compile.identity_line.clone()
        } else {
            STRUCK_IDENTITY_LINE_PLACEHOLDER.to_owned()
        };
        let record = PersonaSnapshotExportRecord {
            subject_ref: compile.subject_ref,
            audience_ref: compile.audience_ref.clone(),
            identity_line: recorded_identity_line,
            compiled_at_secs: compile.compiled_at_secs,
            stale_after_secs: compile.stale_after_secs,
            compiled_fingerprint: compile.stamp.compiled_fingerprint.clone(),
            takes_included: compile.takes_included,
            granted_by: consent.granted_by.trim().to_owned(),
            granted_at_secs: consent.granted_at_secs,
            exported_at_secs: crate::unix_seconds_now(),
            included_row_ids: included_row_ids.clone(),
            struck_row_ids: struck_row_ids.clone(),
            artifact_fingerprint,
        };
        let export_id = EntityId::now();
        self.put_persona_snapshot_export(&export_id, &record)?;

        Ok(PersonaSnapshotArtifact {
            export_id,
            subject_ref: compile.subject_ref,
            memory_pack_json,
            markdown,
            compiled_at_secs: compile.compiled_at_secs,
            stale_after_secs: compile.stale_after_secs,
            stamp: compile.stamp.clone(),
            included_row_ids,
            struck_row_ids,
        })
    }

    /// Stores an engine-authored PERSONA_SNAPSHOT_EXPORT record.
    ///
    /// Generic public puts of the kind remain rejected as a maintenance
    /// kind; this helper validates the pinned body schema before using the
    /// internal maintenance write path.
    pub fn put_persona_snapshot_export(
        &self,
        id: &EntityId,
        record: &PersonaSnapshotExportRecord,
    ) -> Result<()> {
        let data = encode_persona_snapshot_export_body(record)?;
        let learned_at = record.exported_at_secs;
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted.load(Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads and decodes a PERSONA_SNAPSHOT_EXPORT record.
    pub fn get_persona_snapshot_export(
        &self,
        id: &EntityId,
    ) -> Result<Option<PersonaSnapshotExportRecord>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_persona_snapshot_export_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }
}

fn render_memory_pack_lite(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let rows: Vec<serde_json::Value> = included
        .iter()
        .map(|row| {
            // Relationship rows stay COARSE in the exported artifact: name +
            // role text only, no third-party entity ids or vault-internal
            // provenance refs (those exceed the coarse default; claim rows
            // about others only appear at all via explicit un-strike).
            if row.kind == PersonaSnapshotRowKind::Relationship {
                return serde_json::json!({
                    "row_id": row.row_id,
                    "kind": row.kind.as_str(),
                    "text": row.text,
                });
            }
            let mut entry = serde_json::json!({
                "row_id": row.row_id,
                "kind": row.kind.as_str(),
                "text": row.text,
                "subject_ref": row.subject_ref.to_hex(),
                "provenance_refs": row.provenance_refs,
            });
            if let Some(salience) = row.salience {
                entry["salience"] = serde_json::json!(salience);
            }
            if let Some(attribution) = &row.attribution {
                entry["attribution"] = serde_json::json!(attribution);
            }
            entry
        })
        .collect();

    let pack = serde_json::json!({
        "schema": MEMORY_PACK_LITE_SCHEMA_VERSION,
        "kind": "persona_snapshot",
        "subject_ref": compile.subject_ref.to_hex(),
        "identity_line": identity_included
            .then(|| compile.identity_line.clone()),
        "audience_ref": compile.audience_ref,
        "takes_included": compile.takes_included,
        "compiled_at_secs": compile.compiled_at_secs,
        "stale_after_secs": compile.stale_after_secs,
        "persona_compile_stamp": compile.stamp.identity(),
        "rows": rows,
    });
    pack.to_string()
}

fn render_markdown_card(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let mut out = String::new();
    if identity_included {
        out.push_str(&format!(
            "# {}\n",
            markdown_safe_line(&compile.identity_line)
        ));
    } else {
        out.push_str("# Persona snapshot\n");
    }
    out.push('\n');
    out.push_str(&format!("- subject: {}\n", compile.subject_ref.to_hex()));
    if let Some(audience_ref) = &compile.audience_ref {
        out.push_str(&format!("- for: {audience_ref}\n"));
    }
    out.push_str(&format!(
        "- compiled_at_secs: {}\n",
        compile.compiled_at_secs
    ));
    out.push_str(&format!(
        "- stale_after_secs: {}\n",
        compile.stale_after_secs
    ));
    out.push_str(&format!(
        "- persona_compile_stamp: {}\n",
        compile.stamp.identity()
    ));

    let mut push_section = |title: &str, kind: PersonaSnapshotRowKind| {
        let rows: Vec<&&PersonaSnapshotRow> =
            included.iter().filter(|row| row.kind == kind).collect();
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("\n## {title}\n\n"));
        for row in rows {
            // Relationship rows stay COARSE in the exported artifact:
            // name + role text only, no vault-internal provenance refs.
            let provenance = if row.provenance_refs.is_empty()
                || row.kind == PersonaSnapshotRowKind::Relationship
            {
                String::new()
            } else {
                format!(" `[{}]`", row.provenance_refs.join(", "))
            };
            let text = markdown_safe_line(&row.text);
            match &row.attribution {
                Some(attribution) => {
                    out.push_str(&format!(
                        "- {} (take): {text}{provenance}\n",
                        markdown_safe_line(attribution)
                    ));
                }
                None => out.push_str(&format!("- {text}{provenance}\n")),
            }
        }
    };

    push_section("Key relationships", PersonaSnapshotRowKind::Relationship);
    push_section("Claims", PersonaSnapshotRowKind::SubjectClaim);
    push_section(
        "Third-party details",
        PersonaSnapshotRowKind::ThirdPartyClaim,
    );
    push_section("Agent takes", PersonaSnapshotRowKind::AgentTake);
    out
}

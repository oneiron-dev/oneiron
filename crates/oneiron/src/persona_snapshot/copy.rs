//! Owner edits to accepted mode-A copies, never to their source claims.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::codec::invalid_snapshot;
use super::compile::{compile_fingerprint, row_id};
use super::{
    PersonaSnapshotArtifact, PersonaSnapshotCompile, PersonaSnapshotCompileOptions,
    PersonaSnapshotExportConsent, PersonaSnapshotRowKind, PersonaSnapshotStrikeList,
};
use crate::claim::CallerLocality;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

const COPIES: SideTable<EntityId, AcceptedCopy, Named> =
    SideTable::new(&side_table::PERSONA_SNAPSHOT_COPY);

#[derive(Serialize, Deserialize)]
struct AcceptedCopy {
    compile: PersonaSnapshotCompile,
    strikes: PersonaSnapshotStrikeList,
    source_stamp: String,
}

/// Replaces only one accepted row's text. Its sources and attribution stay intact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotTextEdit {
    pub row_id: String,
    pub text: String,
}

/// Consent to issue exactly the previewed version, with explicit row exclusions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotCopyRequest {
    pub subject: EntityId,
    pub stamp: String,
    #[serde(default)]
    pub strike: BTreeSet<String>,
    #[serde(default)]
    pub unstrike: BTreeSet<String>,
}

/// An accepted copy's stamp fences its edits. Each edit issues a new immutable
/// export; an already handed copy and the neutral source claims remain unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotCopyEditRequest {
    pub export_id: EntityId,
    pub stamp: String,
    pub edits: Vec<PersonaSnapshotTextEdit>,
    #[serde(default)]
    pub strike: BTreeSet<String>,
    #[serde(default)]
    pub unstrike: BTreeSet<String>,
}

fn require_stamp(expected: &str, actual: &str) -> Result<()> {
    if expected != actual {
        return Err(Error::Gate(GateError::PersonaSnapshotConsentStale {
            consent_stamp: expected.to_owned(),
            compile_stamp: actual.to_owned(),
        }));
    }
    Ok(())
}

impl Vault {
    /// Compiling while holding the writer keeps preview freshness, owner
    /// revalidation and the export record in the same write transaction.
    pub fn export_persona_snapshot_copy_as(
        &self,
        owner: &AuthenticatedOwner,
        request: &PersonaSnapshotCopyRequest,
        locality: CallerLocality,
    ) -> Result<PersonaSnapshotArtifact> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let compile = self.compile_persona_snapshot(
            &request.subject,
            &PersonaSnapshotCompileOptions {
                locality,
                ..Default::default()
            },
        )?;
        require_stamp(&request.stamp, &compile.stamp.identity())?;
        let strikes = PersonaSnapshotStrikeList {
            strike: request.strike.clone(),
            unstrike: request.unstrike.clone(),
        };
        let consent = PersonaSnapshotExportConsent {
            granted_by: actor.to_hex(),
            compile_stamp: request.stamp.clone(),
            granted_at_secs: self.store.clock.now_recorded_at(),
        };
        let artifact = self.export_persona_snapshot_in_txn(
            &mut txn,
            &compile,
            &strikes,
            &consent,
            Some(owner),
        )?;
        self.save_persona_snapshot_copy_in_txn(
            &mut txn,
            artifact.export_id,
            &compile,
            &strikes,
            &request.stamp,
        )?;
        txn.commit()?;
        Ok(artifact)
    }

    /// Edits one accepted copy. A fresh compile only checks the source stamp
    /// and locality; it never silently refreshes or replaces the accepted text.
    pub fn edit_persona_snapshot_copy_as(
        &self,
        owner: &AuthenticatedOwner,
        request: &PersonaSnapshotCopyEditRequest,
        locality: CallerLocality,
    ) -> Result<PersonaSnapshotArtifact> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        match crate::vault::live_entity_row_in_txn(&self.store, &txn, &request.export_id)? {
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
                ..
            } => {}
            _ => return Err(Error::EntityNotFound),
        }
        let accepted = COPIES
            .get(&self.store, &txn, &request.export_id)?
            .ok_or(Error::EntityNotFound)?;
        let mut compile = accepted.compile;
        require_stamp(&request.stamp, &compile.stamp.identity())?;
        let current = self.compile_persona_snapshot(
            &compile.subject_ref,
            &PersonaSnapshotCompileOptions {
                locality,
                ..Default::default()
            },
        )?;
        require_stamp(&accepted.source_stamp, &current.stamp.identity())?;
        let known: BTreeSet<_> = compile.rows.iter().map(|row| row.row_id.clone()).collect();
        let mut edits = BTreeMap::new();
        for edit in &request.edits {
            if edit.text.trim().is_empty()
                || edits
                    .insert(edit.row_id.as_str(), edit.text.as_str())
                    .is_some()
            {
                return Err(invalid_snapshot(
                    "copy edits need non-empty text and distinct row ids",
                ));
            }
        }
        if edits.keys().any(|id| !known.contains(*id))
            || request
                .strike
                .iter()
                .chain(&request.unstrike)
                .any(|id| !known.contains(id))
        {
            return Err(invalid_snapshot(
                "copy edit or strike references unknown row id",
            ));
        }
        if !request.strike.is_disjoint(&request.unstrike) {
            return Err(invalid_snapshot("strike and unstrike must not overlap"));
        }
        // Persist the effective strike state in the new copy, then apply only
        // the new explicit decisions. A text replacement never un-strikes a row.
        for row in &mut compile.rows {
            row.struck = (row.struck || accepted.strikes.strike.contains(&row.row_id))
                && !accepted.strikes.unstrike.contains(&row.row_id);
        }
        let mut renamed = BTreeMap::new();
        for row in &mut compile.rows {
            let old_id = row.row_id.clone();
            if let Some(text) = edits.get(old_id.as_str()) {
                row.text = (*text).to_owned();
                if row.kind == PersonaSnapshotRowKind::Identity {
                    compile.identity_line = row.text.clone();
                }
                row.row_id = row_id(
                    row.kind,
                    &row.subject_ref,
                    &row.text,
                    row.attribution.as_deref(),
                    &row.provenance_refs,
                );
            }
            renamed.insert(old_id, row.row_id.clone());
        }
        compile.compiled_at_secs = self.store.clock.now_recorded_at();
        compile.stamp.compiled_at_secs = compile.compiled_at_secs;
        compile.stamp.compiled_fingerprint = compile_fingerprint(
            &compile.subject_ref,
            &compile.identity_line,
            compile.audience_ref.as_deref(),
            compile.takes_included,
            compile.stale_after_secs,
            &compile.rows,
        );
        let strikes = PersonaSnapshotStrikeList {
            strike: request
                .strike
                .iter()
                .map(|id| renamed[id].clone())
                .collect(),
            unstrike: request
                .unstrike
                .iter()
                .map(|id| renamed[id].clone())
                .collect(),
        };
        let consent = PersonaSnapshotExportConsent {
            granted_by: actor.to_hex(),
            compile_stamp: compile.stamp.identity(),
            granted_at_secs: self.store.clock.now_recorded_at(),
        };
        let artifact = self.export_persona_snapshot_in_txn(
            &mut txn,
            &compile,
            &strikes,
            &consent,
            Some(owner),
        )?;
        self.save_persona_snapshot_copy_in_txn(
            &mut txn,
            artifact.export_id,
            &compile,
            &strikes,
            &accepted.source_stamp,
        )?;
        txn.commit()?;
        Ok(artifact)
    }

    fn save_persona_snapshot_copy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        compile: &PersonaSnapshotCompile,
        strikes: &PersonaSnapshotStrikeList,
        source_stamp: &str,
    ) -> Result<()> {
        COPIES.put(
            &self.store,
            txn,
            &id,
            &AcceptedCopy {
                compile: compile.clone(),
                strikes: strikes.clone(),
                source_stamp: source_stamp.to_owned(),
            },
        )
    }
}

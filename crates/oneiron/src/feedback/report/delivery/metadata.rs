//! The historical ED-08 metadata a report's subject names (OF-420, FIX 739).
//! Only a subject that is an attempt pack receipt resolves: its one loaded
//! skill and the version that load stamped, the skill entity the issue's own
//! publisher shipped under that skill id, and the executor the pack
//! attribution pinned, mapped to the one registered model stack that serves
//! it. Anything else is a named reason, never a guess: no subject string is
//! parsed, the current model is never used, and no version is invented.

use std::collections::BTreeSet;

use super::super::routing::IMPORTS;
use super::super::{ReportIssue, ReportRoute};
use crate::attempt_queue::ManifestKind;
use crate::edit_distance::publisher::{CountKey, tally_judged_outcomes};
use crate::settings::default_model_stack_registry;
use crate::{EntityId, Result, Vault};

/// What an issue signature says about the work its report is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportPublisherMetadata {
    /// The shipped SKILL entity the attempt loaded.
    pub artifact: EntityId,
    /// The version the attempt's pack load stamped.
    pub version: u32,
    /// The registered model stack serving the attempt's executor.
    pub model_id: String,
    /// The closed judged-outcome tally over the attempt's own pack receipt.
    pub counts: [(CountKey, u32); 3],
}

impl Vault {
    /// Resolves an issue's signature metadata from its subject's attempt
    /// pack receipt. `Ok(Err(reason))` names the first piece that is not
    /// exactly resolvable: the reason a `metadata_unresolved` hold shows.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn resolve_report_publisher_metadata(
        &self,
        issue: &ReportIssue,
    ) -> Result<std::result::Result<ReportPublisherMetadata, &'static str>> {
        let ReportRoute::Publisher { publisher_ref } = &issue.route else {
            return Ok(Err("not_routed_to_publisher"));
        };
        let Some(receipt) = crate::receipt::attempt_pack_receipt(self, &issue.request.subject_ref)?
        else {
            return Ok(Err("subject_not_pack_receipt"));
        };
        let skills: Vec<_> = receipt
            .pack_manifest_entries()
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.kind == ManifestKind::Skill)
            .collect();
        let [skill] = skills.as_slice() else {
            return Ok(Err("skill_load_not_single"));
        };
        let Some(version) = exact_u32(&skill.version) else {
            return Ok(Err("version_not_u32"));
        };
        let Some(artifact) = self.report_artifact(publisher_ref, &skill.reference)? else {
            return Ok(Err("artifact_not_single"));
        };
        let Ok(attribution) = receipt.pack_attribution_fields() else {
            return Ok(Err("attribution_unreadable"));
        };
        let Some(model_id) = registered_stack(&attribution.executor) else {
            return Ok(Err("model_not_registered"));
        };
        Ok(Ok(ReportPublisherMetadata {
            artifact,
            version,
            model_id,
            counts: tally_judged_outcomes(std::slice::from_ref(&receipt)),
        }))
    }

    /// The one SKILL entity `publisher_ref` shipped under `skill_id`, from
    /// its canonical import receipts and installed packs; `None` when there
    /// is none, or more than one.
    fn report_artifact(&self, publisher_ref: &str, skill_id: &str) -> Result<Option<EntityId>> {
        let mut candidates = BTreeSet::new();
        let txn = self.store.env.read_txn()?;
        for row in IMPORTS.iter_from(&self.store, &txn, &[])? {
            let (_, receipt) = row?;
            if receipt.publisher.as_deref() == Some(publisher_ref) {
                candidates.extend(EntityId::from_hex(&receipt.entity).ok());
            }
        }
        drop(txn);
        for pack in self.installed_packs()? {
            if pack.publisher == publisher_ref {
                candidates.extend(
                    pack.skills
                        .iter()
                        .filter_map(|skill| EntityId::from_hex(skill).ok()),
                );
            }
        }
        let mut artifacts = BTreeSet::new();
        for id in candidates {
            if matches!(self.get_skill_record(&id), Ok(Some(record)) if record.skill_id == skill_id)
            {
                artifacts.insert(id);
            }
        }
        let mut artifacts = artifacts.into_iter();
        Ok(match (artifacts.next(), artifacts.next()) {
            (Some(artifact), None) => Some(artifact),
            _ => None,
        })
    }
}

/// The version text as a `u32`, only when it is exactly that number.
fn exact_u32(text: &str) -> Option<u32> {
    let value: u32 = text.parse().ok()?;
    (value.to_string() == text).then_some(value)
}

/// The one registered model stack whose models include `executor`, pinned
/// as `id@revision`.
fn registered_stack(executor: &str) -> Option<String> {
    let registry = default_model_stack_registry();
    let mut serving = registry.stacks.values().filter(|stack| {
        stack
            .models
            .iter()
            .any(|model| model.model.as_str() == executor)
    });
    let stack = serving.next()?;
    serving
        .next()
        .is_none()
        .then(|| stack.id.as_str().to_owned())
}

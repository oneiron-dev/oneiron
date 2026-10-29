//! The historical ED-08 metadata a report's subject names (OF-420, FIX 739).
//! Only a subject that is an attempt pack receipt resolves: its one loaded
//! skill and the version that load stamped, the skill entity the issue's own
//! publisher shipped under that skill id, and the executor the pack
//! attribution pinned, mapped to the one registered model stack that serves
//! it: a compiled default stack, else the one-model stack of the host
//! registry's row for exactly that model (FIX 7686). Anything else is a named
//! reason, never a guess: no subject string is parsed, the current model is
//! never used, and no version is invented.

use std::collections::BTreeSet;

use super::super::routing::IMPORTS;
use super::super::{ReportIssue, ReportRoute};
use crate::attempt_queue::ManifestKind;
use crate::edit_distance::publisher::{CountKey, tally_judged_outcomes};
use crate::settings::{
    ModelStack, ModelStackId, ModelStackModel, ModelStackRegistry, default_model_stack_registry,
};
use crate::{EntityId, ModelId, Result, Vault};

/// The role a host model's one-model stack names it under.
const HOST_STACK_ROLE: &str = "executor";
/// The generation of every host model's one-model stack.
const HOST_STACK_GENERATION: u32 = 1;

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
        let Some(model_id) = self.registered_stack(&attribution.executor)? else {
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
pub(super) fn exact_u32(text: &str) -> Option<u32> {
    let value: u32 = text.parse().ok()?;
    (value.to_string() == text).then_some(value)
}

/// The one compiled model stack whose models include `executor`, pinned
/// as `id@revision`.
pub(super) fn compiled_stack(executor: &str) -> Option<String> {
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

/// `model` as the id of its one-model stack: the model id itself, spelled in
/// a stack id's alphabet (`_` as `__`, `/` as `_.`, `@` as `_-`), so it reads
/// back to exactly that model and to nothing else.
pub(super) fn host_stack_id(model: &ModelId) -> String {
    let mut id = String::with_capacity(model.as_str().len() + 4);
    for character in model.as_str().chars() {
        match character {
            '_' => id.push_str("__"),
            '/' => id.push_str("_."),
            '@' => id.push_str("_-"),
            other => id.push(other),
        }
    }
    id
}

/// The model a stack id spells in [`host_stack_id`]'s form; `None` for any
/// other id.
fn host_stack_model(stack: &str) -> Option<ModelId> {
    let mut model = String::with_capacity(stack.len());
    let mut characters = stack.chars();
    while let Some(character) = characters.next() {
        if character != '_' {
            model.push(character);
            continue;
        }
        model.push(match characters.next()? {
            '_' => '_',
            '.' => '/',
            '-' => '@',
            _ => return None,
        });
    }
    let model = ModelId::new(model).ok()?;
    (host_stack_id(&model) == stack).then_some(model)
}

/// The compiled stacks, and `model`'s one-model stack beside them.
fn with_host_stack(model: ModelId) -> Option<ModelStackRegistry> {
    let mut registry = default_model_stack_registry();
    let id = ModelStackId::new(host_stack_id(&model)).ok()?;
    let name = model.as_str().to_owned();
    let stack = ModelStack::new(
        id.clone(),
        name,
        HOST_STACK_GENERATION,
        vec![ModelStackModel::new(HOST_STACK_ROLE, model)],
    )
    .ok()?;
    registry.stacks.entry(id).or_insert(stack);
    Some(registry)
}

/// The stacks a received signature's model id reads against: the compiled
/// ones, and the one-model stack its id spells, when it spells a model.
pub(super) fn received_stacks(model_id: &str) -> ModelStackRegistry {
    host_stack_model(model_id)
        .and_then(with_host_stack)
        .unwrap_or_else(default_model_stack_registry)
}

impl Vault {
    /// The model stack serving `executor`: the one compiled stack that
    /// includes it, else, when the host registry holds a row for exactly
    /// that model, its one-model stack (FIX 7686). `None` for an executor
    /// neither names.
    fn registered_stack(&self, executor: &str) -> Result<Option<String>> {
        if let Some(stack) = compiled_stack(executor) {
            return Ok(Some(stack));
        }
        let Ok(model) = ModelId::new(executor) else {
            return Ok(None);
        };
        Ok(self
            .model_registry_row(&model)?
            .map(|_| host_stack_id(&model)))
    }

    /// The stacks an issue signature's `model_id` is checked against, as
    /// `txn` reads the host registry: the compiled ones, and the one-model
    /// stack of the host model `model_id` spells while the registry holds a
    /// row for it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn signature_stacks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        model_id: &str,
    ) -> Result<ModelStackRegistry> {
        let Some(model) = host_stack_model(model_id) else {
            return Ok(default_model_stack_registry());
        };
        if self.model_registry_row_in_txn(txn, &model)?.is_none() {
            return Ok(default_model_stack_registry());
        }
        Ok(with_host_stack(model).unwrap_or_else(default_model_stack_registry))
    }
}

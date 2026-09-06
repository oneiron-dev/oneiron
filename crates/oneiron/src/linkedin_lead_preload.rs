//! Deterministic LinkedIn entity resolution and explicit runtime-path corpus preload.
//!
//! Corpus application is a single-owner operation. Entity check/create is atomic;
//! claim and edge existence checks precede separate writes under that ownership
//! constraint. Claims are admitted only after the resolver transaction commits.
//! Storage failures can leave partial progress; reruns reuse deterministic ids and
//! existing edges, including provenanced edges, without rewriting them. Changed
//! values for an existing source/predicate do not replace its deterministic claim.
//! There is no network access, default corpus path, persisted source-id index,
//! name matching, or contact-consent creation. Reports contain counts only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ingest::{
    ImportedEvidenceAdmission, ImportedEvidenceEntityResolution, NormalizedIngestClaim,
    admit_imported_evidence_claim,
};
use crate::temporal::TimeRange;
use crate::{Vault, WriteActor, unix_seconds_now};

pub const LINKEDIN_LEAD_CORPUS_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInLeadCorpus {
    pub schema_version: u16,
    pub companies: Vec<LinkedInCompanySeed>,
    pub contacts: Vec<LinkedInContactSeed>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInCompanySeed {
    pub external_id: String,
    pub display_name: String,
    pub profile_url: Option<String>,
    pub website_domain: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInContactSeed {
    pub external_id: String,
    pub display_name: String,
    pub company_external_id: String,
    pub title: Option<String>,
    pub profile_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkedInEntityKind {
    Company,
    Person,
}

impl LinkedInEntityKind {
    pub(crate) const fn entity_type(self) -> u8 {
        match self {
            Self::Company => crate::registry::ENTITY_TYPE_ORG,
            Self::Person => crate::registry::ENTITY_TYPE_PERSON,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinkedInExternalKey {
    pub(crate) kind: LinkedInEntityKind,
    pub(crate) external_id: String,
}

impl LinkedInExternalKey {
    pub(crate) fn company(external_id: &str) -> Result<Self, LinkedInResolutionError> {
        Self::new(LinkedInEntityKind::Company, external_id)
    }

    pub(crate) fn person(external_id: &str) -> Result<Self, LinkedInResolutionError> {
        Self::new(LinkedInEntityKind::Person, external_id)
    }

    fn new(kind: LinkedInEntityKind, external_id: &str) -> Result<Self, LinkedInResolutionError> {
        let external_id = external_id.trim_ascii();
        if external_id.is_empty() {
            return Err(LinkedInResolutionError::EmptySourceId);
        }
        if external_id.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(LinkedInResolutionError::MalformedExternalId);
        }
        Ok(Self {
            kind,
            external_id: external_id.to_owned(),
        })
    }

    /// Canonical provider-and-kind source identity; display fields never enter it.
    pub(crate) fn source_ref(&self) -> String {
        let kind = match self.kind {
            LinkedInEntityKind::Company => "company",
            LinkedInEntityKind::Person => "person",
        };
        format!("linkedin:{kind}:{}", self.external_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Created,
    Reused,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkedInResolutionError {
    #[error("malformed LinkedIn external id")]
    MalformedExternalId,
    #[error("empty LinkedIn source id")]
    EmptySourceId,
    #[error(transparent)]
    Vault(#[from] Error),
}

#[derive(Debug, thiserror::Error)]
pub enum LinkedInLeadPreloadError {
    #[error("unsupported LinkedIn lead corpus schema version {found}; supported {supported}")]
    SchemaVersionUnsupported { found: u16, supported: u16 },
    #[error("LinkedIn lead corpus contact {contact_index} references an unresolved company")]
    CrossRefUnresolved { contact_index: usize },
    #[error("malformed LinkedIn lead corpus {kind} row {index}: {reason}")]
    Malformed {
        kind: &'static str,
        index: usize,
        reason: &'static str,
    },
    #[error(transparent)]
    Resolution(#[from] LinkedInResolutionError),
    #[error(transparent)]
    Vault(#[from] Error),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkedInLeadPreloadReport {
    pub companies_created: usize,
    pub companies_reused: usize,
    pub contacts_created: usize,
    pub contacts_reused: usize,
    pub employed_by_created: usize,
    pub employed_by_reused: usize,
    pub claims_admitted: usize,
}

impl LinkedInLeadPreloadReport {
    pub fn created_entities(&self) -> usize {
        self.companies_created + self.contacts_created
    }

    pub fn created_edges(&self) -> usize {
        self.employed_by_created
    }

    pub fn companies_seen(&self) -> usize {
        self.companies_created + self.companies_reused
    }

    pub fn contacts_seen(&self) -> usize {
        self.contacts_created + self.contacts_reused
    }
}

fn derived_id(domain: &[u8], parts: &[&str]) -> crate::Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part.as_bytes());
    }
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes)
}

pub(crate) fn resolve_linkedin_entity(
    vault: &Vault,
    key: LinkedInExternalKey,
) -> Result<(EntityId, Disposition), LinkedInResolutionError> {
    // Revalidate even a crate-local caller's directly constructed key.
    let key = LinkedInExternalKey::new(key.kind, &key.external_id)?;
    let id = derived_id(b"oneiron.linkedin.entity.v1", &[&key.source_ref()])?;
    let disposition =
        vault.with_write_txn(|wtxn| match vault.get_entity_type_in_txn(wtxn, &id)? {
            Some(kind) if kind == key.kind.entity_type() => Ok(Disposition::Reused),
            Some(_) => Err(Error::InvariantViolation(
                "LinkedIn derived entity type mismatch",
            )),
            None => {
                let learned_at = unix_seconds_now();
                let occurred = TimeRange {
                    start: learned_at,
                    end: learned_at,
                };
                vault
                    .batch_in()
                    .put(&id, key.kind.entity_type(), occurred, learned_at, b"")
                    .apply(wtxn)?;
                Ok(Disposition::Created)
            }
        })?;
    Ok((id, disposition))
}

fn malformed(kind: &'static str, index: usize, reason: &'static str) -> LinkedInLeadPreloadError {
    LinkedInLeadPreloadError::Malformed {
        kind,
        index,
        reason,
    }
}

fn validate_corpus(corpus: &mut LinkedInLeadCorpus) -> Result<(), LinkedInLeadPreloadError> {
    if corpus.schema_version != LINKEDIN_LEAD_CORPUS_SCHEMA_VERSION {
        return Err(LinkedInLeadPreloadError::SchemaVersionUnsupported {
            found: corpus.schema_version,
            supported: LINKEDIN_LEAD_CORPUS_SCHEMA_VERSION,
        });
    }
    let mut companies = BTreeSet::new();
    for (index, row) in corpus.companies.iter_mut().enumerate() {
        row.external_id = LinkedInExternalKey::company(&row.external_id)
            .map_err(|_| malformed("company", index, "invalid external id"))?
            .external_id;
        if row.display_name.trim().is_empty() {
            return Err(malformed("company", index, "empty display name"));
        }
        if !companies.insert(row.external_id.clone()) {
            return Err(malformed("company", index, "duplicate external id"));
        }
    }
    let mut contacts = BTreeSet::new();
    for (index, row) in corpus.contacts.iter_mut().enumerate() {
        row.external_id = LinkedInExternalKey::person(&row.external_id)
            .map_err(|_| malformed("contact", index, "invalid external id"))?
            .external_id;
        row.company_external_id = LinkedInExternalKey::company(&row.company_external_id)
            .map_err(|_| malformed("contact", index, "invalid company external id"))?
            .external_id;
        if row.display_name.trim().is_empty() {
            return Err(malformed("contact", index, "empty display name"));
        }
        if !contacts.insert(row.external_id.clone()) {
            return Err(malformed("contact", index, "duplicate external id"));
        }
        if !companies.contains(&row.company_external_id) {
            return Err(LinkedInLeadPreloadError::CrossRefUnresolved {
                contact_index: index,
            });
        }
    }
    Ok(())
}

impl Vault {
    /// Reads, validates, and applies one explicit UTF-8 JSON runtime corpus path.
    /// The caller supplies a pre-existing actor and owns exclusive corpus application.
    /// Structural errors precede all writes; runtime failures may leave resumable progress.
    pub fn preload_linkedin_lead_corpus(
        &self,
        path: impl AsRef<Path>,
        actor: WriteActor,
    ) -> Result<LinkedInLeadPreloadReport, LinkedInLeadPreloadError> {
        let bytes = std::fs::read(path).map_err(Error::from)?;
        // Serde structs also accept positional sequences. Require JSON objects,
        // then decode the original bytes so duplicate fields still fail closed.
        let shape: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| malformed("document", 0, "invalid JSON document or schema"))?;
        if !shape.is_object()
            || ["companies", "contacts"].iter().any(|field| {
                !shape[*field]
                    .as_array()
                    .is_some_and(|rows| rows.iter().all(serde_json::Value::is_object))
            })
        {
            return Err(malformed(
                "document",
                0,
                "expected document and row objects",
            ));
        }
        drop(shape);
        let corpus = serde_json::from_slice(&bytes)
            .map_err(|_| malformed("document", 0, "invalid JSON document or schema"))?;
        apply_linkedin_lead_corpus(self, corpus, actor)
    }
}

fn admit_facts(
    vault: &Vault,
    key: &LinkedInExternalKey,
    subject: EntityId,
    actor: WriteActor,
    facts: &[(&str, Option<&str>)],
) -> Result<usize, LinkedInLeadPreloadError> {
    let source_ref = key.source_ref();
    let mut admitted = 0;
    for &(predicate, value) in facts {
        let Some(value) = value else { continue };
        let claim_id = derived_id(b"oneiron.linkedin.claim.v1", &[&source_ref, predicate])?;
        // The typed read also refuses a non-CLAIM squatting at this id.
        if vault.get_claim(&claim_id)?.is_some() {
            continue;
        }
        let learned_at = unix_seconds_now();
        let occurred = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        let claim = NormalizedIngestClaim {
            source_record_id: source_ref.clone(),
            predicate: predicate.to_owned(),
            value: serde_json::Value::String(value.to_owned()),
        };
        admit_imported_evidence_claim(
            vault,
            &claim,
            ImportedEvidenceAdmission::proposed(
                "linkedin-lead-corpus",
                claim_id,
                ImportedEvidenceEntityResolution::subject(subject),
                actor,
                occurred,
                learned_at,
            ),
        )?;
        admitted += 1;
    }
    Ok(admitted)
}

fn resolve_employment(
    vault: &Vault,
    person: EntityId,
    company: EntityId,
) -> Result<Disposition, LinkedInResolutionError> {
    let kind = EdgeKind::EmployedBy;
    if vault.edge_exists(&person, kind, &company)? {
        return Ok(Disposition::Reused);
    }
    let weight = kind.default_weight().ok_or(Error::InvariantViolation(
        "EmployedBy has no default weight",
    ))?;
    vault.put_edge(&person, kind, &company, weight)?;
    Ok(Disposition::Created)
}

pub(crate) fn apply_linkedin_lead_corpus(
    vault: &Vault,
    mut corpus: LinkedInLeadCorpus,
    actor: WriteActor,
) -> Result<LinkedInLeadPreloadReport, LinkedInLeadPreloadError> {
    validate_corpus(&mut corpus)?;
    // Check even empty/reused corpora; missing actors cannot bootstrap themselves.
    if vault.get_entity_type(&actor.entity_ref())?.is_none() {
        return Err(Error::EntityNotFound.into());
    }
    let mut report = LinkedInLeadPreloadReport::default();
    let mut companies = BTreeMap::new();
    for row in corpus.companies {
        let key = LinkedInExternalKey::company(&row.external_id)?;
        let (id, disposition) = resolve_linkedin_entity(vault, key.clone())?;
        match disposition {
            Disposition::Created => report.companies_created += 1,
            Disposition::Reused => report.companies_reused += 1,
        }
        companies.insert(row.external_id, id);
        report.claims_admitted += admit_facts(
            vault,
            &key,
            id,
            actor,
            &[
                ("linkedin.display_name", Some(row.display_name.as_str())),
                ("linkedin.profile_url", row.profile_url.as_deref()),
                ("linkedin.website_domain", row.website_domain.as_deref()),
            ],
        )?;
    }
    for row in corpus.contacts {
        let key = LinkedInExternalKey::person(&row.external_id)?;
        let (id, disposition) = resolve_linkedin_entity(vault, key.clone())?;
        match disposition {
            Disposition::Created => report.contacts_created += 1,
            Disposition::Reused => report.contacts_reused += 1,
        }
        report.claims_admitted += admit_facts(
            vault,
            &key,
            id,
            actor,
            &[
                ("linkedin.display_name", Some(row.display_name.as_str())),
                ("linkedin.title", row.title.as_deref()),
                ("linkedin.profile_url", row.profile_url.as_deref()),
            ],
        )?;
        let company = companies
            .get(&row.company_external_id)
            .ok_or(Error::InvariantViolation(
                "validated LinkedIn company missing",
            ))?;
        match resolve_employment(vault, id, *company)? {
            Disposition::Created => report.employed_by_created += 1,
            Disposition::Reused => report.employed_by_reused += 1,
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests;

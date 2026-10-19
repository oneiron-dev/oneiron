//! Typed PERSON setup and look-before-mint over the declared identity index.
//! Hints never identify a person. Only stored confidence evidence is scored,
//! by the ingest waterfall, and a lookup never restores, links or mints.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{EntityRefReceipt, Memory, MemoryError, MemoryResult, StructuralPutInput};
use crate::consent::AuthenticatedOwner;
use crate::ingest::{EntityResolutionCandidate, EntityResolutionWaterfallDecision};
use crate::provenance::made_by::MadeBy;
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::{EntityId, Error, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityKind {
    Person,
    Org,
    Place,
}

impl IdentityKind {
    fn type_byte(self) -> u8 {
        match self {
            Self::Person => ENTITY_TYPE_PERSON,
            Self::Org => ENTITY_TYPE_ORG,
            Self::Place => ENTITY_TYPE_PLACE,
        }
    }
}

/// The fields declared by `identity_fields_for_kind`, not an identity id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityHints {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub phonetic: Vec<String>,
    #[serde(default)]
    pub contact_handle: Vec<String>,
}

impl IdentityHints {
    fn terms(&self, kind: IdentityKind) -> MemoryResult<BTreeSet<String>> {
        if kind != IdentityKind::Person && !self.contact_handle.is_empty() {
            return Err(MemoryError::bad_request(
                "contact_handle is declared only for PERSON",
            ));
        }
        let terms: BTreeSet<_> = self
            .name
            .iter()
            .chain(&self.aliases)
            .chain(&self.phonetic)
            .chain(&self.contact_handle)
            .map(|term| term.trim().to_lowercase())
            .filter(|term| !term.is_empty())
            .collect();
        if terms.is_empty() {
            return Err(MemoryError::bad_request(
                "at least one declared identity hint is required",
            ));
        }
        Ok(terms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonCreateRequest {
    pub identity: IdentityHints,
    /// Existing contact, organisation, message or other evidence records.
    /// A name alone is not identity evidence.
    pub identity_evidence_refs: Vec<String>,
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonCreated {
    pub person: EntityRefReceipt,
    pub identity: IdentityHints,
    pub identity_evidence_refs: Vec<String>,
    pub owner_ref: String,
    pub recorded_at: u64,
    /// The index was read in the creation transaction. These people were
    /// not selected or merged; the owner explicitly created a distinct record.
    pub prior_candidate_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityLookupRequest {
    pub kind: IdentityKind,
    pub identity: IdentityHints,
    /// Already-produced provider.enrichment claims about index candidates.
    /// Omit these to read candidates without proposing any match.
    #[serde(default)]
    pub mention_evidence: Vec<EntityResolutionCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityConfidenceEvidence {
    pub claim_ref: String,
    pub effective_confidence: f32,
    pub source: Option<String>,
    pub evidence: Option<serde_json::Value>,
    pub made_by: Option<MadeBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityLookupCandidate {
    pub entity_ref: String,
    pub matched_hints: Vec<String>,
    pub identity_evidence_refs: Vec<String>,
    pub identity_owner_ref: Option<String>,
    pub identity_recorded_at: Option<u64>,
    pub made_by: Option<MadeBy>,
    pub mention_evidence: Vec<IdentityConfidenceEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityLookup {
    pub kind: IdentityKind,
    pub candidates: Vec<IdentityLookupCandidate>,
    /// Scoring only: even a selected subject is not linked or restored by
    /// this query. No evidence means no selected subject.
    pub waterfall: EntityResolutionWaterfallDecision,
}

pub(crate) fn require_identity_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    refs: &[EntityId],
) -> crate::Result<()> {
    for id in refs {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
            return Err(Error::EntityNotFound);
        }
    }
    Ok(())
}

fn lookup_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: IdentityKind,
    terms: &BTreeSet<String>,
) -> crate::Result<BTreeMap<EntityId, BTreeSet<String>>> {
    let mut found: BTreeMap<EntityId, BTreeSet<String>> = BTreeMap::new();
    for term in terms {
        for id in vault.lookup_identity_key_in_txn(txn, kind.type_byte(), term)? {
            for head in vault.resolve_entity_in_txn(txn, &id)? {
                if vault.get_entity_type_in_txn(txn, &head)? == Some(kind.type_byte()) {
                    found.entry(head).or_default().insert(term.clone());
                }
            }
        }
    }
    Ok(found)
}

fn stored_body(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<serde_json::Value> {
    let raw = vault.get_raw_in(txn, id)?.ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("identity candidate header"))?;
    crate::ingest::identity_hint_body(
        header.entity_type,
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .ok_or_else(|| MemoryError::bad_request("identity candidate body is not a typed map"))
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect()
}

impl Memory<'_> {
    pub fn people_create_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &PersonCreateRequest,
    ) -> MemoryResult<PersonCreated> {
        let terms = input.identity.terms(IdentityKind::Person)?;
        if input
            .identity
            .name
            .as_deref()
            .is_none_or(|name| name.trim().is_empty())
        {
            return Err(MemoryError::bad_request("PERSON creation requires name"));
        }
        if input.identity_evidence_refs.is_empty() {
            return Err(MemoryError::bad_request(
                "PERSON creation requires identity evidence refs",
            ));
        }
        let evidence = self.identity_evidence_refs(&input.identity_evidence_refs)?;
        let owner_id = owner.revalidate(self.vault())?;
        let recorded_at = self.vault().now_recorded_at();
        let mut body = serde_json::to_value(&input.identity)
            .map_err(|_| MemoryError::bad_request("identity hints cannot be encoded"))?;
        body["identity_evidence_refs"] =
            serde_json::json!(evidence.iter().map(EntityId::to_hex).collect::<Vec<_>>());
        body["identity_owner_ref"] = serde_json::json!(owner_id.to_hex());
        body["identity_recorded_at"] = serde_json::json!(recorded_at);
        let prior = std::cell::RefCell::new(Vec::new());
        let person = self.put_structural_guarded(
            &StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body,
                text_fields: None,
                edges: None,
                occurred_at: input.occurred_at,
                learned_at: input.learned_at,
            },
            |txn| {
                owner.revalidate_in_txn(self.vault(), txn)?;
                require_identity_evidence_in_txn(self.vault(), txn, &evidence)?;
                *prior.borrow_mut() =
                    lookup_in_txn(self.vault(), txn, IdentityKind::Person, &terms)?
                        .keys()
                        .map(EntityId::to_hex)
                        .collect();
                Ok(())
            },
        )?;
        self.produced_from(evidence.iter().copied().chain([owner_id]));
        self.produced_from(
            prior
                .borrow()
                .iter()
                .filter_map(|reference| EntityId::from_hex(reference).ok()),
        );
        Ok(PersonCreated {
            person,
            identity: input.identity.clone(),
            identity_evidence_refs: evidence.iter().map(EntityId::to_hex).collect(),
            owner_ref: owner_id.to_hex(),
            recorded_at,
            prior_candidate_refs: prior.into_inner(),
        })
    }

    pub(crate) fn identity_evidence_refs(&self, refs: &[String]) -> MemoryResult<Vec<EntityId>> {
        refs.iter()
            .map(|reference| {
                self.get_entity(reference)?
                    .value
                    .ok_or_else(|| MemoryError::not_found("identity evidence must be readable"))?;
                self.resolve_ref(reference)
            })
            .collect()
    }

    pub fn entities_look_before_mint_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &IdentityLookupRequest,
    ) -> MemoryResult<IdentityLookup> {
        let terms = input.identity.terms(input.kind)?;
        self.with_verified_actor_write_txn(|txn| {
            owner.revalidate_in_txn(self.vault(), txn)?;
            let found = lookup_in_txn(self.vault(), txn, input.kind, &terms)?;
            if input
                .mention_evidence
                .iter()
                .any(|item| !found.contains_key(&item.subject))
            {
                return Err(MemoryError::bad_request(
                    "mention evidence is outside the declared identity lookup",
                ));
            }
            let waterfall = crate::ingest::score_entity_resolution_waterfall_in_txn(
                self.vault(),
                txn,
                &input.mention_evidence,
                found.len() > 1,
            )?;
            let mut candidates = Vec::with_capacity(found.len());
            for (id, hints) in found {
                let body = stored_body(self.vault(), txn, &id)?;
                let identity_evidence_refs = strings(body.get("identity_evidence_refs"));
                let identity_owner_ref = body
                    .get("identity_owner_ref")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                let mut mention_evidence = Vec::new();
                for scored in waterfall
                    .ranked
                    .iter()
                    .filter(|item| item.candidate.subject == id)
                {
                    let claim_ref = scored.candidate.confidence_claim_ref;
                    let claim = self
                        .vault()
                        .get_claim_in_txn(txn, &claim_ref)?
                        .ok_or(Error::EntityNotFound)?;
                    self.produced_from([claim_ref]);
                    mention_evidence.push(IdentityConfidenceEvidence {
                        claim_ref: claim_ref.to_hex(),
                        effective_confidence: scored.effective_confidence,
                        source: claim.source.map(|source| source.as_str().to_owned()),
                        evidence: claim
                            .evidence
                            .as_ref()
                            .map(crate::serialize::msgpack_value_to_json),
                        made_by: crate::provenance::birth::row_birth_in_txn(
                            &self.vault().store,
                            txn,
                            &claim_ref,
                        )?
                        .map(|birth| birth.made_by),
                    });
                }
                self.produced_from(
                    std::iter::once(id).chain(
                        identity_evidence_refs
                            .iter()
                            .chain(identity_owner_ref.iter())
                            .filter_map(|reference| EntityId::from_hex(reference).ok()),
                    ),
                );
                candidates.push(IdentityLookupCandidate {
                    entity_ref: id.to_hex(),
                    matched_hints: hints.into_iter().collect(),
                    identity_evidence_refs,
                    identity_owner_ref,
                    identity_recorded_at: body
                        .get("identity_recorded_at")
                        .and_then(serde_json::Value::as_u64),
                    made_by: crate::provenance::birth::row_birth_in_txn(
                        &self.vault().store,
                        txn,
                        &id,
                    )?
                    .map(|birth| birth.made_by),
                    mention_evidence,
                });
            }
            Ok(IdentityLookup {
                kind: input.kind,
                candidates,
                waterfall,
            })
        })
    }
}

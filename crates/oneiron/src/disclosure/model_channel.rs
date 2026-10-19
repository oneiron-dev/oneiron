//! The model connection is a disclosure audience, not a read grant.
//! These registry dials change serialization only, after the caller's own read.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject, ScopedReadActorKey, claim_surfaceable};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
use crate::ports::{EntityStoreRead, ShortIdStoreRead};
use crate::side_table::{self, Named, SideTable};

const CEILINGS: SideTable<String, DisclosureBand, Named> =
    SideTable::new(&side_table::DISCLOSURE_MODEL_CEILING);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDataClass {
    Names,
    Dates,
    Contact,
    Ids,
    Health,
}

impl DisclosureDataClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Names => "names",
            Self::Dates => "dates",
            Self::Contact => "contact",
            Self::Ids => "ids",
            Self::Health => "health",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureBand {
    Public,
    Private,
    Sensitive,
    Restricted,
}

impl DisclosureBand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Sensitive => "sensitive",
            Self::Restricted => "restricted",
        }
    }

    fn sensitivity(self) -> Sensitivity {
        match self {
            Self::Public => Sensitivity::Public,
            Self::Private => Sensitivity::Private,
            Self::Sensitive => Sensitivity::Sensitive,
            Self::Restricted => Sensitivity::Restricted,
        }
    }

    pub(crate) fn of_claim(body: &ClaimBody) -> Self {
        match crate::claim::claim_sensitivity_band(body) {
            Some(0) => Self::Public,
            Some(1) => Self::Private,
            Some(2) => Self::Sensitive,
            _ => Self::Restricted,
        }
    }
}

/// One registry dial. Omit class to address the whole connection.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingRequest {
    /// The credential-bound connection, e.g. agent:<principal hex>.
    pub connection: String,
    #[serde(default)]
    pub class: Option<DisclosureDataClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingSet {
    pub connection: String,
    #[serde(default)]
    pub class: Option<DisclosureDataClass>,
    pub ceiling: DisclosureBand,
}

/// None means no dial: class falls back to connection, then actor inference.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingView {
    pub connection: String,
    pub class: Option<DisclosureDataClass>,
    pub ceiling: Option<DisclosureBand>,
}

fn key(connection: &str, class: Option<DisclosureDataClass>) -> Result<String> {
    let valid = connection.split_once(':').is_some_and(|(kind, id)| {
        matches!(kind, "agent" | "owner") && EntityId::from_hex(id).is_ok()
    });
    if !valid {
        return Err(Error::InvalidClaimBody(
            "connection is agent:<hex> or owner:<hex>",
        ));
    }
    Ok(dial_key(connection, class))
}

fn dial_key(connection: &str, class: Option<DisclosureDataClass>) -> String {
    format!(
        "{connection}/{}",
        class.map_or("*", DisclosureDataClass::as_str)
    )
}

impl Vault {
    pub fn model_disclosure_ceiling(
        &self,
        owner: &AuthenticatedOwner,
        input: DisclosureCeilingRequest,
    ) -> Result<DisclosureCeilingView> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let ceiling = CEILINGS.get(&self.store, &txn, &key(&input.connection, input.class)?)?;
        Ok(DisclosureCeilingView {
            connection: input.connection,
            class: input.class,
            ceiling,
        })
    }

    pub fn set_model_disclosure_ceiling(
        &self,
        owner: &AuthenticatedOwner,
        input: DisclosureCeilingSet,
    ) -> Result<DisclosureCeilingView> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let key = key(&input.connection, input.class)?;
            CEILINGS.put(&self.store, txn, &key, &input.ceiling)?;
            Ok(DisclosureCeilingView {
                connection: input.connection,
                class: input.class,
                ceiling: Some(input.ceiling),
            })
        })
    }

    pub fn clear_model_disclosure_ceiling(
        &self,
        owner: &AuthenticatedOwner,
        input: DisclosureCeilingRequest,
    ) -> Result<DisclosureCeilingView> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            CEILINGS.delete(&self.store, txn, &key(&input.connection, input.class)?)?;
            Ok(DisclosureCeilingView {
                connection: input.connection,
                class: input.class,
                ceiling: None,
            })
        })
    }
}

pub(crate) fn claim_data_class(body: &ClaimBody) -> Option<DisclosureDataClass> {
    if body.predicate.starts_with("health.") {
        return Some(DisclosureDataClass::Health);
    }
    match body.predicate.rsplit('.').next()? {
        "name" | "display_name" | "full_name" | "given_name" | "family_name" => {
            Some(DisclosureDataClass::Names)
        }
        "birthdate" | "date_of_birth" | "birthday" | "dob" => Some(DisclosureDataClass::Dates),
        "email" | "phone" | "address" | "contact" => Some(DisclosureDataClass::Contact),
        "id" | "identifier" => Some(DisclosureDataClass::Ids),
        _ => None,
    }
}

/// A person's current names-class claim, independent of who wrote that claim.
/// Authority is checked by the caller, never inferred from the writer's class.
pub(crate) fn person_name_claim_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Option<(EntityId, ClaimBody)>> {
    let mut names = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &person)? {
        if let Some(body) = vault.get_claim_in_txn(txn, &id)?
            && body.subject == ClaimSubject::Entity(person)
            && claim_data_class(&body) == Some(DisclosureDataClass::Names)
            && claim_surfaceable(&body)
            && crate::claim::has_live_support_in_txn(&vault.store, txn, &body)?
        {
            names.push((id, body));
        }
    }
    names.sort_by_key(|(id, _)| *id);
    Ok(names.pop())
}

fn connection(reader: &ScopedReadActorKey) -> String {
    format!(
        "{}:{}",
        if reader.reads_as_vault_owner() {
            "owner"
        } else {
            "agent"
        },
        reader.actor_ref()
    )
}

fn admits(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    class: DisclosureDataClass,
    band: DisclosureBand,
) -> Result<bool> {
    let connection = connection(reader);
    let ceiling = CEILINGS
        .get(&vault.store, txn, &dial_key(&connection, Some(class)))?
        .or(CEILINGS.get(&vault.store, txn, &dial_key(&connection, None))?)
        .unwrap_or(if reader.reads_as_vault_owner() {
            DisclosureBand::Restricted
        } else {
            DisclosureBand::Public
        });
    let channel = Scope {
        sensitivity: SensitivityCeiling::AtMost(ceiling.sensitivity()),
        ..Scope::top()
    };
    let record = Scope {
        sensitivity: SensitivityCeiling::AtMost(band.sensitivity()),
        ..Scope::top()
    };
    Ok(channel.admits("read", &record, &Scope::top()))
}

pub(crate) fn model_names_admitted_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    band: DisclosureBand,
) -> Result<bool> {
    admits(vault, txn, reader, DisclosureDataClass::Names, band)
}

/// The bare PERSON handle for a claim above this model channel's ceiling.
/// This is not a grant: the caller must already have admitted the claim.
pub(crate) fn claim_handle_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    body: &ClaimBody,
) -> Result<Option<String>> {
    let (ClaimSubject::Entity(person), Some(class)) = (&body.subject, claim_data_class(body))
    else {
        return Ok(None);
    };
    if vault
        .store
        .port_entity_record(txn, person)?
        .map(|row| row.entity_type)
        != Some(crate::registry::ENTITY_TYPE_PERSON)
        || admits(vault, txn, reader, class, DisclosureBand::of_claim(body))?
    {
        return Ok(None);
    }
    let handle = vault
        .store
        .port_short_id_reference(txn, person)?
        .map(|(handle, _)| handle)
        .ok_or(Error::EntityNotFound)?;
    Ok(Some(handle))
}

/// Applies the model-channel projection after scoped admission, before any
/// format, board or HTTP projection can copy a value out of the pack.
pub(crate) fn project_model_pack_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    pack: &mut crate::context_pack::ContextPack,
) -> Result<()> {
    if let Some(summary) = pack.l2_base.as_mut() {
        let mut rows: Vec<serde_json::Value> = serde_json::from_str(&summary.body)
            .map_err(|_| Error::InvariantViolation("model disclosure L2 JSON"))?;
        let mut changed = false;
        for row in &mut rows {
            let id = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| EntityId::from_hex(id).ok())
                .ok_or(Error::EntityNotFound)?;
            if let Some(body) = vault.get_claim_in_txn(txn, &id)?
                && let Some(handle) = claim_handle_in(vault, txn, reader, &body)?
            {
                row["val"] = serde_json::Value::String(handle);
                changed = true;
            }
        }
        if changed {
            let body = serde_json::to_string(&rows)
                .map_err(|_| Error::InvariantViolation("model disclosure L2 render"))?;
            summary.content_hash = *blake3::hash(body.as_bytes()).as_bytes();
            summary.body = std::sync::Arc::from(body);
        }
    }
    for entity in pack.results.iter_mut().chain(&mut pack.neighbors) {
        let Some(fields) = entity.fields.as_mut() else {
            continue;
        };
        if entity.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            if let Some(body) = vault.get_claim_in_txn(txn, &entity.id)?
                && let Some(handle) = claim_handle_in(vault, txn, reader, &body)?
            {
                fields.retain(|key, _| {
                    matches!(key.as_str(), "pred" | "conf" | "src" | "from" | "to")
                });
                fields.insert("val".to_owned(), serde_json::Value::String(handle));
                entity.vector = None;
            }
        } else if entity.entity_type == crate::registry::ENTITY_TYPE_PERSON {
            let band = person_name_claim_in(vault, txn, entity.id)?
                .map_or(DisclosureBand::Sensitive, |(_, body)| {
                    DisclosureBand::of_claim(&body)
                });
            if !admits(vault, txn, reader, DisclosureDataClass::Names, band)? {
                for field in ["name", "display_name", "full_name"] {
                    if fields.contains_key(field) {
                        fields.insert(
                            field.to_owned(),
                            serde_json::Value::String(entity.short_id.clone()),
                        );
                    }
                }
                entity.vector = None;
            }
        }
    }
    Ok(())
}

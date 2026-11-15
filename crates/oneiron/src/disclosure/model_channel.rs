//! The model connection is a disclosure audience, not a read grant.
//! These registry dials change serialization only, after the caller's own read.
//! Each dial is a row of the setting `disclosure.model_ceiling`
//! (`super::setting_keys::MODEL_CEILING`), its item the connection and class.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject, ScopedReadActorKey, claim_surfaceable};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::setting::SettingValue;
use oneiron_authority::federation::{Scope, Sensitivity, SensitivityCeiling};

#[doc(hidden)]
pub use oneiron_verb_wire::disclosure::model_channel::DisclosureDataClass;

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

impl SettingValue for DisclosureBand {}

/// Whether `item` names one dial: `agent:<hex>` or `owner:<hex>`, then `/`
/// and a data class or `*` for the whole connection.
pub(super) fn is_dial_item(item: &str) -> bool {
    let Some((connection, class)) = item.rsplit_once('/') else {
        return false;
    };
    let connection_ok = connection.split_once(':').is_some_and(|(kind, id)| {
        matches!(kind, "agent" | "owner") && EntityId::from_hex(id).is_ok()
    });
    let class_ok = class == "*"
        || [
            DisclosureDataClass::Names,
            DisclosureDataClass::Dates,
            DisclosureDataClass::Contact,
            DisclosureDataClass::Ids,
            DisclosureDataClass::Health,
        ]
        .iter()
        .any(|known| known.as_str() == class);
    connection_ok && class_ok
}

fn dial_key(connection: &str, class: Option<DisclosureDataClass>) -> String {
    format!(
        "{connection}/{}",
        class.map_or("*", DisclosureDataClass::as_str)
    )
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
    let dial = |class| {
        super::setting_keys::MODEL_CEILING
            .read_in_txn(vault, txn, &[], Some(&dial_key(&connection, class)))
            .map(|resolved| resolved.value)
    };
    let ceiling = match dial(Some(class))? {
        Some(ceiling) => Some(ceiling),
        None => dial(None)?,
    }
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

/// The bare handle of a classed claim's subject, for a claim above this
/// model channel's ceiling: its short handle, else its id. A claim of a
/// data class about any record is projected, not only one about a PERSON
/// (FIX 9785); a claim of no class stays as its scoped read admitted it.
/// This is not a grant: the caller must already have admitted the claim.
pub(crate) fn claim_handle_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    body: &ClaimBody,
) -> Result<Option<String>> {
    let (ClaimSubject::Entity(subject), Some(class)) = (&body.subject, claim_data_class(body))
    else {
        return Ok(None);
    };
    if admits(vault, txn, reader, class, DisclosureBand::of_claim(body))? {
        return Ok(None);
    }
    let handle = vault
        .store
        .port_short_id_reference(txn, subject)?
        .map_or_else(|| subject.to_hex(), |(handle, _)| handle);
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
        if rows.len() != summary.evidence_ids().len() {
            return Err(Error::InvariantViolation(
                "model disclosure L2 evidence rows",
            ));
        }
        let mut changed = false;
        // A row's `id` is its display handle (a short id where one is
        // stored), never a storage key: each row is read by the typed
        // evidence id the producer paired with it, in the same order
        // (FIX 21913).
        for (row, id) in rows.iter_mut().zip(summary.evidence_ids()) {
            if let Some(body) = vault.get_claim_in_txn(txn, id)?
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

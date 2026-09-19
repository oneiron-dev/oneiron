//! Calendar EVENT origin union: atomic recorded provenance and source invalidation.
use super::claims::{CalendarOrigin, PREDICATE_CALENDAR_ORIGIN, is_calendar_claim_predicate};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, claim_surfaceable,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::memory::MemoryResult;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use rmpv::Value;

/// Origin-specific EVENT fields. An absent origin is a write refusal, never a default.
#[derive(Debug, Clone, Default)]
pub struct CalendarEventInput {
    pub origin: Option<CalendarOrigin>,
    pub name: String,
    pub evidence_turn_ids: Vec<EntityId>,
    pub source_frontiers: Vec<String>,
    pub rrule: Option<String>,
    pub calendar_name: Option<String>,
    pub import_source: Option<String>,
    pub external_id: Option<String>,
}
fn invalid(message: &'static str) -> Error {
    Error::InvalidClaimBody(message)
}

impl CalendarEventInput {
    pub fn validate(&self) -> Result<CalendarOrigin> {
        let origin = self
            .origin
            .ok_or(invalid("calendar EVENT requires origin"))?;
        if self.name.trim().is_empty() {
            return Err(invalid("calendar EVENT name is empty"));
        }
        match origin {
            CalendarOrigin::Dreamer => {
                if self.evidence_turn_ids.is_empty()
                    || self.source_frontiers.is_empty()
                    || self.source_frontiers.iter().any(|s| s.trim().is_empty())
                    || self.rrule.is_some()
                    || self.calendar_name.is_some()
                {
                    return Err(invalid(
                        "dreamer EVENT requires evidence and forbids recurrence/calendarName",
                    ));
                }
            }
            CalendarOrigin::Native => {
                if !self.evidence_turn_ids.is_empty() || !self.source_frontiers.is_empty() {
                    return Err(invalid("native EVENT forbids extraction evidence"));
                }
            }
            CalendarOrigin::Imported => {
                if self
                    .import_source
                    .as_deref()
                    .is_none_or(|s| s.trim().is_empty())
                    || self
                        .external_id
                        .as_deref()
                        .is_none_or(|s| s.trim().is_empty())
                    || !self.evidence_turn_ids.is_empty()
                {
                    return Err(invalid(
                        "imported EVENT requires source/externalId and forbids evidenceTurnIds",
                    ));
                }
            }
        }
        Ok(origin)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let origin = self.validate()?;
        let mut fields = vec![
            (Value::from("name"), Value::from(self.name.as_str())),
            (Value::from("origin"), Value::from(origin.as_str())),
        ];
        if !self.evidence_turn_ids.is_empty() {
            fields.push((
                Value::from("evidenceTurnIds"),
                Value::Array(
                    self.evidence_turn_ids
                        .iter()
                        .map(|id| Value::from(id.to_hex()))
                        .collect(),
                ),
            ));
        }
        if !self.source_frontiers.is_empty() {
            fields.push((
                Value::from("sourceFrontiers"),
                Value::Array(
                    self.source_frontiers
                        .iter()
                        .map(|s| Value::from(s.as_str()))
                        .collect(),
                ),
            ));
        }
        for (key, value) in [
            ("rrule", &self.rrule),
            ("calendarName", &self.calendar_name),
            ("importSource", &self.import_source),
            ("externalId", &self.external_id),
        ] {
            if let Some(value) = value {
                fields.push((Value::from(key), Value::from(value.as_str())));
            }
        }
        encode(&Value::Map(fields))
    }
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid("calendar body encode"))?;
    Ok(bytes)
}

/// Reads the live origin claim in this transaction. No origin defaults on the write side.
pub(crate) fn live_origin(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<Option<CalendarOrigin>> {
    let prefix = crate::vault::edge_kind_prefix(&event, EdgeKind::ClaimOf);
    let mut chosen = None;
    for entry in store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        let id = EntityId::from_bytes(
            key.get(17..33)
                .ok_or(invalid("calendar claim edge"))?
                .try_into()
                .map_err(|_| invalid("calendar claim edge"))?,
        )?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let Some(bytes) = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .filter(|b| !b.is_empty())
        else {
            continue;
        };
        let body = crate::claim::decode_claim_body(bytes, true)?;
        if body.predicate == PREDICATE_CALENDAR_ORIGIN && claim_surfaceable(&body) {
            let origin = body
                .value
                .as_str()
                .and_then(CalendarOrigin::parse)
                .ok_or(invalid("calendar origin value"))?;
            if chosen.is_none_or(|(old, _)| id < old) {
                chosen = Some((id, origin));
            }
        }
    }
    Ok(chosen.map(|(_, origin)| origin))
}

impl Vault {
    /// Writes the EVENT and projector-recorded origin together. The first
    /// structural staging row is invisible until origin admission also commits.
    pub fn create_calendar_event(
        &self,
        input: &CalendarEventInput,
        occurred: TimeRange,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let origin = input.validate()?;
        if occurred.start > occurred.end {
            return Err(invalid("calendar time is reversed").into());
        }
        let body = input.encode()?;
        let event = EntityId::now();
        let at = crate::unix_seconds_now();
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                for evidence in &input.evidence_turn_ids {
                    if self.get_entity_type_in_txn(txn, evidence)? != Some(ENTITY_TYPE_TURN) {
                        return Err(invalid("calendar evidence must be a live TURN").into());
                    }
                }
                let stub = encode(&Value::Map(vec![(
                    Value::from("name"),
                    Value::from(input.name.as_str()),
                )]))?;
                self.batch_in()
                    .put(&event, ENTITY_TYPE_EVENT, occurred, at, &stub)
                    .apply(txn)?;
                let mut claim = ClaimBody::new(
                    PREDICATE_CALENDAR_ORIGIN,
                    ClaimSubject::Entity(event),
                    Value::from(origin.as_str()),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                );
                // Recorded projector fact, not a user-authored assertion about origin.
                claim.evidence = Some(Value::Map(vec![
                    (Value::from("kind"), Value::from("calendar_projector")),
                    (Value::from("write_class"), Value::from("recorded")),
                    (
                        Value::from("actor"),
                        Value::from(actor.entity_ref().to_hex()),
                    ),
                ]));
                self.put_reserved_claim_in_txn(txn, &EntityId::now(), &claim, occurred, at)?;
                self.batch_in()
                    .put(&event, ENTITY_TYPE_EVENT, occurred, at, &body)
                    .apply(txn)?;
                for evidence in &input.evidence_turn_ids {
                    self.batch_in()
                        .edge(&event, EdgeKind::DerivedFrom, evidence, 1.0)
                        .apply(txn)?;
                }
                if live_origin(&self.store, txn, event)? != Some(origin) {
                    return Err(invalid("calendar EVENT requires live calendar.origin").into());
                }
                Ok(event)
            })
    }
    pub fn create_native_calendar_event(
        &self,
        input: &CalendarEventInput,
        occurred: TimeRange,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let mut input = input.clone();
        input.origin = Some(CalendarOrigin::Native);
        self.create_calendar_event(&input, occurred, actor)
    }
    pub fn create_dreamer_calendar_event(
        &self,
        input: &CalendarEventInput,
        occurred: TimeRange,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let mut input = input.clone();
        input.origin = Some(CalendarOrigin::Dreamer);
        self.create_calendar_event(&input, occurred, actor)
    }
    /// Read-only legacy default. Missing records are not legacy records.
    pub fn calendar_event_origin(&self, event: EntityId) -> Result<CalendarOrigin> {
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &event)? != Some(ENTITY_TYPE_EVENT) {
            return Err(Error::EntityNotFound);
        }
        Ok(live_origin(&self.store, &txn, event)?.unwrap_or(CalendarOrigin::Dreamer))
    }
}

/// Local generic EVENT overwrites cannot bypass live provenance. Legacy rows
/// remain readable; their next calendar write must establish an origin first.
pub(crate) fn validate_event_write(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    let mut reader = data;
    let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut reader) else {
        return Ok(());
    };
    let get = |name: &str| {
        fields
            .iter()
            .find_map(|(k, v)| (k.as_str() == Some(name)).then_some(v))
    };
    let body_origin = get("origin")
        .map(|v| {
            v.as_str()
                .and_then(CalendarOrigin::parse)
                .ok_or(invalid("unknown calendar origin"))
        })
        .transpose()?;
    if let Some(origin) = body_origin {
        if (origin == CalendarOrigin::Native
            && (get("evidenceTurnIds").is_some() || get("sourceFrontiers").is_some()))
            || (origin == CalendarOrigin::Imported && get("evidenceTurnIds").is_some())
        {
            return Err(invalid("calendar origin forbids evidence fields"));
        }
        let ids = match get("evidenceTurnIds") {
            None => Vec::new(),
            Some(Value::Array(ids)) => ids
                .iter()
                .map(|v| EntityId::from_hex(v.as_str().ok_or(invalid("evidence id"))?))
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid("evidenceTurnIds must be an array")),
        };
        let frontiers = match get("sourceFrontiers") {
            None => Vec::new(),
            Some(Value::Array(v)) => v
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(invalid("frontier must be text"))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid("sourceFrontiers must be an array")),
        };
        let optional = |key: &str| -> Result<Option<String>> {
            get(key)
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(invalid("calendar field must be text"))
                })
                .transpose()
        };
        CalendarEventInput {
            origin: Some(origin),
            name: optional("name")?.unwrap_or_default(),
            evidence_turn_ids: ids,
            source_frontiers: frontiers,
            rrule: optional("rrule")?,
            calendar_name: optional("calendarName")?,
            import_source: optional("importSource")?,
            external_id: optional("externalId")?,
        }
        .validate()?;
        if !replicated && live_origin(store, txn, event)? != Some(origin) {
            return Err(invalid(
                "calendar EVENT requires matching live calendar.origin",
            ));
        }
    } else if !replicated {
        let prefix = crate::vault::edge_kind_prefix(&event, EdgeKind::ClaimOf);
        for entry in store.edges_in.prefix_iter(txn, &prefix)? {
            let (key, _) = entry?;
            let Some(raw) = store.entities.get(txn, &key[17..])? else {
                continue;
            };
            let Some(bytes) = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .filter(|b| !b.is_empty())
            else {
                continue;
            };
            let claim = crate::claim::decode_claim_body(bytes, true)?;
            if is_calendar_claim_predicate(&claim.predicate)
                && claim_surfaceable(&claim)
                && live_origin(store, txn, event)?.is_none()
            {
                return Err(invalid("calendar EVENT requires live calendar.origin"));
            }
        }
    }
    Ok(())
}
fn invalid_key(event: EntityId) -> Vec<u8> {
    [b"calendar_invalid:v1:".as_slice(), event.as_bytes()].concat()
}
pub(crate) fn invalidate_dependents(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let prefix = crate::vault::edge_kind_prefix(source, EdgeKind::DerivedFrom);
    let mut dependents = Vec::new();
    for entry in vault.store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        let event = EntityId::from_bytes(
            key.get(17..33)
                .ok_or(invalid("calendar dependency edge"))?
                .try_into()
                .map_err(|_| invalid("calendar dependency edge"))?,
        )?;
        let Some(raw) = vault.store.entities.get(txn, event.as_bytes())? else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw).is_some_and(|h| h.entity_type == ENTITY_TYPE_EVENT)
            && live_origin(&vault.store, txn, event)?.unwrap_or(CalendarOrigin::Dreamer)
                == CalendarOrigin::Dreamer
        {
            dependents.push(event);
        }
    }
    for event in dependents {
        vault
            .store
            .vault_meta
            .put(txn, &invalid_key(event), source.as_bytes())?;
    }
    Ok(())
}
pub(in crate::calendar) fn invalidated(vault: &Vault, event: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&txn, &invalid_key(event))?
        .is_some())
}

#[cfg(test)]
mod tests;

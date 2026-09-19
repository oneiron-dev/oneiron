//! Calendar EVENT origin union: atomic recorded provenance and source invalidation.
use super::claims::{CalendarOrigin, PREDICATE_CALENDAR_ORIGIN, is_calendar_claim_predicate};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, claim_surfaceable,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::memory::MemoryResult;
use crate::ports::EdgeStoreRead;
use crate::ports::{EntityStore, EntityStoreRead};
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
    pub(in crate::calendar) fn encode(&self) -> Result<Vec<u8>> {
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
    let mut chosen = None;
    for entry in store.port_edges(
        txn,
        &event,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let id = entry?.target;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
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
            if chosen.is_some_and(|(_, existing)| existing != origin) {
                return Err(invalid("conflicting live calendar origins"));
            }
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
        input.validate()?;
        if occurred.start > occurred.end {
            return Err(invalid("calendar time is reversed").into());
        }
        let event = self.store.clock.entity_id()?;
        let at = self.store.clock.now_recorded_at();
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                self.stage_calendar_event(txn, input, occurred, actor, event, at)?;
                Ok(event)
            })
    }
    /// Trusted projectors use this inside their existing admission transaction.
    pub(in crate::calendar) fn stage_calendar_event(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &CalendarEventInput,
        occurred: TimeRange,
        actor: WriteActor,
        event: EntityId,
        at: u64,
    ) -> Result<()> {
        let origin = input.validate()?;
        let body = input.encode()?;
        let actor_kind = self
            .get_entity_type_in_txn(txn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        crate::provenance::validate_actor_class(actor_kind, actor.actor_class())?;
        for evidence in &input.evidence_turn_ids {
            if self.get_entity_type_in_txn(txn, evidence)? != Some(ENTITY_TYPE_TURN) {
                return Err(invalid("calendar evidence must be a live TURN"));
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
        self.put_reserved_claim_in_txn(txn, &self.store.clock.entity_id()?, &claim, occurred, at)?;
        self.batch_in()
            .put(&event, ENTITY_TYPE_EVENT, occurred, at, &body)
            .apply(txn)?;
        for evidence in &input.evidence_turn_ids {
            self.batch_in()
                .edge(&event, EdgeKind::DerivedFrom, evidence, 1.0)
                .apply(txn)?;
        }
        if live_origin(&self.store, txn, event)? != Some(origin) {
            return Err(invalid("calendar EVENT requires live calendar.origin"));
        }
        Ok(())
    }
    /// Apply imported name/time drift without changing the EVENT's origin union.
    /// Native and extracted fields survive; imported provenance follows the source.
    pub(in crate::calendar) fn update_calendar_import_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        event: EntityId,
        input: &CalendarEventInput,
        occurred: TimeRange,
        at: u64,
    ) -> Result<()> {
        let origin = live_origin(&self.store, txn, event)?
            .ok_or(invalid("calendar EVENT requires live calendar.origin"))?;
        let row = self
            .port_entity_get(txn, &event)?
            .ok_or(Error::EntityNotFound)?;
        let mut value = rmpv::decode::read_value(&mut std::io::Cursor::new(row.body))
            .map_err(|_| invalid("calendar EVENT body"))?;
        let Value::Map(fields) = &mut value else {
            return Err(invalid("calendar EVENT body"));
        };
        let mut replace = |key: &str, value: Value| {
            fields.retain(|(name, _)| name.as_str() != Some(key));
            fields.push((Value::from(key), value));
        };
        replace("name", Value::from(input.name.as_str()));
        replace("origin", Value::from(origin.as_str()));
        if origin == CalendarOrigin::Imported {
            input.validate()?;
            replace(
                "importSource",
                Value::from(input.import_source.as_deref().unwrap_or_default()),
            );
            replace(
                "externalId",
                Value::from(input.external_id.as_deref().unwrap_or_default()),
            );
        }
        self.batch_in()
            .put(&event, ENTITY_TYPE_EVENT, occurred, at, &encode(&value)?)
            .apply(txn)
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
        if !replay_origin_bound(&self.store, &txn, event)? {
            return Err(invalid("calendar origin claim has not been reconciled"));
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
    let existing_origin = live_origin(store, txn, event)?;
    let mut reader = data;
    let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut reader) else {
        // EVENT is also a generic opaque entity. Once it is a calendar EVENT,
        // however, neither a local write nor replay may erase its schema.
        return if existing_origin.is_some() {
            Err(invalid("calendar EVENT body must be a MessagePack map"))
        } else {
            Ok(())
        };
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
    let has_calendar_fields = [
        "evidenceTurnIds",
        "sourceFrontiers",
        "rrule",
        "calendarName",
        "importSource",
        "externalId",
    ]
    .iter()
    .any(|field| get(field).is_some());
    if (existing_origin.is_some() || body_origin.is_some() || has_calendar_fields)
        && !reader.is_empty()
    {
        return Err(invalid("calendar EVENT body has trailing bytes"));
    }
    if existing_origin.is_some() && body_origin.is_none() {
        return Err(invalid(
            "calendar EVENT requires matching live calendar.origin",
        ));
    }
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
        if existing_origin.is_some_and(|live| live != origin)
            || (!replicated && existing_origin.is_none())
        {
            return Err(invalid(
                "calendar EVENT requires matching live calendar.origin",
            ));
        }
    } else if has_calendar_fields {
        return Err(invalid("calendar EVENT fields require origin"));
    } else if !replicated {
        for entry in store.port_edges(
            txn,
            &event,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )? {
            let peer = entry?.target;
            let Some(raw) = store
                .port_entity_record(txn, &peer)?
                .map(|row| row.encode())
            else {
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
/// A typed body may arrive before its claim, but cannot be read as a legacy
/// Dreamer or invalidated as derived state while that binding is incomplete.
pub(crate) fn replay_origin_bound(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<bool> {
    let Some(row) = store.port_entity_record(txn, &event)? else {
        return Ok(true);
    };
    if row.entity_type != ENTITY_TYPE_EVENT {
        return Ok(true);
    }
    let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut row.body.as_slice()) else {
        return Ok(true);
    };
    let Some((_, value)) = fields.iter().find(|(k, _)| k.as_str() == Some("origin")) else {
        return Ok(true);
    };
    let origin = value
        .as_str()
        .and_then(CalendarOrigin::parse)
        .ok_or(invalid("unknown calendar origin"))?;
    Ok(live_origin(store, txn, event)? == Some(origin))
}

/// Native calendar entries are authored state, not derived artifacts. Provenance
/// links do not let a source deletion remove them from reads or search.
pub(crate) fn survives_source_deletion(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<bool> {
    Ok(!replay_origin_bound(store, txn, event)?
        || live_origin(store, txn, event)? == Some(CalendarOrigin::Native))
}

fn invalid_key(event: EntityId) -> Vec<u8> {
    [b"calendar_invalid:v1:".as_slice(), event.as_bytes()].concat()
}
pub(crate) fn invalidate_dependents(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let mut dependents = Vec::new();
    for entry in vault.store.port_edges(
        txn,
        source,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::DerivedFrom),
        None,
    )? {
        let event = entry?.target;
        let Some(raw) = vault
            .store
            .port_entity_record(txn, &event)?
            .map(|row| row.encode())
        else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw).is_some_and(|h| h.entity_type == ENTITY_TYPE_EVENT)
            && replay_origin_bound(&vault.store, txn, event)?
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
    Ok(!replay_origin_bound(&vault.store, &txn, event)?
        || vault
            .store
            .vault_meta
            .get(&txn, &invalid_key(event))?
            .is_some())
}

#[cfg(test)]
mod tests;

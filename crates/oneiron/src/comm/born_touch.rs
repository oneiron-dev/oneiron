//! Projection of the original, explicitly born touch after its native batch write.

use super::claims::{CommClaim, CommClaimValue, CommError, CommResult};
use super::generic_put_routing::CommSourceEvent;
use super::head_admission::{HeadAdmission, ProjectedHeadAdmission};
use super::projector::RecordedEventProjection;
use super::records::{
    CommEventKind, CommRecord, decode_comm_record, next_event_sequence_in_txn,
    put_comm_record_in_txn,
};
use crate::ports::EntityStoreRead;
use crate::provenance::birth::RowBirth;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMM_RECORD};
use crate::{EntityId, Error, Result, Vault};
use std::collections::BTreeSet;

struct BornTouch {
    id: EntityId,
    data: Vec<u8>,
    birth: RowBirth,
    event: CommSourceEvent,
}

enum DeferredTouch {
    Born(BornTouch),
    Routed(CommSourceEvent),
}

/// Original-order touches after native writes, separate from input preflight.
#[derive(Default)]
pub(crate) struct DeferredBornTouches {
    touches: Vec<DeferredTouch>,
}

impl DeferredBornTouches {
    pub(super) fn push(
        &mut self,
        id: EntityId,
        data: &[u8],
        birth: &RowBirth,
        event: CommSourceEvent,
    ) {
        self.touches.push(DeferredTouch::Born(BornTouch {
            id,
            data: data.to_vec(),
            birth: birth.base_form().into_owned(),
            event,
        }));
    }

    pub(super) fn push_routed(&mut self, event: CommSourceEvent) {
        self.touches.push(DeferredTouch::Routed(event));
    }

    /// Without a born touch, all events keep their original pre-apply phase.
    /// With one, only touch assertions join its post-native schedule.
    pub(super) fn split_prefix_events(self) -> (Vec<CommSourceEvent>, Self) {
        let has_born = self
            .touches
            .iter()
            .any(|touch| matches!(touch, DeferredTouch::Born(_)));
        let mut events = Vec::new();
        let mut deferred = Self::default();
        for touch in self.touches {
            match touch {
                DeferredTouch::Routed(event)
                    if !has_born || event.kind != CommEventKind::TouchAsserted =>
                {
                    events.push(event);
                }
                touch => deferred.touches.push(touch),
            }
        }
        (events, deferred)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.touches.is_empty()
    }

    /// The caller has already applied and admitted the original puts and births.
    pub(crate) fn record_with_admission_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        admission: Option<&mut dyn ProjectedHeadAdmission>,
    ) -> Result<BTreeSet<EntityId>> {
        let mut admission = match admission {
            Some(bound) => HeadAdmission::bound(bound),
            None => HeadAdmission::default(),
        };
        let mut projection = RecordedEventProjection::default();
        let mut later_born_heads: BTreeSet<_> = self
            .touches
            .iter()
            .filter_map(|touch| match touch {
                DeferredTouch::Born(touch) => Some(touch.id),
                DeferredTouch::Routed(_) => None,
            })
            .collect();
        for touch in self.touches {
            let touch = match touch {
                DeferredTouch::Born(touch) => touch,
                DeferredTouch::Routed(event) => {
                    event.record_in_txn(
                        vault,
                        txn,
                        &mut projection,
                        &mut admission,
                        Some(&later_born_heads),
                    )?;
                    continue;
                }
            };
            later_born_heads.remove(&touch.id);
            // A mask or another native operation may have changed the input.
            // Such a write keeps its ordinary raw result, not a fabricated event.
            let Some(row) = vault.store.port_entity_record(txn, &touch.id)? else {
                continue;
            };
            if row.entity_type != ENTITY_TYPE_CLAIM || row.body != touch.data[..] {
                continue;
            }
            let birth = crate::store::birth_record::row_birth_in_txn(&vault.store, txn, &touch.id)?;
            if birth.as_ref() != Some(&touch.birth)
                || !vault
                    .claims_for_subject_in_txn(txn, &touch.event.party_ref)?
                    .contains(&touch.id)
            {
                continue;
            }
            let body = crate::claim::decode_claim_body(&row.body, false)?;
            let claim = CommClaim::from_claim_body(&body)?;
            let (id, source_position) =
                touch_event_binding(touch.id, &row.encode(), &touch.birth, &body, &claim.value)
                    .map_err(super::generic_put_routing::source_event_error)?;
            let mut event = touch.event;
            event.channel_class = event
                .channel_class
                .as_deref()
                .map(crate::counterparty_contact::normalize_channel_class);
            let resident = match vault.store.port_entity_record(txn, &id)? {
                Some(row) => {
                    if row.entity_type != ENTITY_TYPE_COMM_RECORD {
                        return Err(Error::InvalidClaimBody("comm touch source id collision"));
                    }
                    Some(
                        decode_comm_record(&row.body)
                            .map_err(super::generic_put_routing::source_event_error)?,
                    )
                }
                None => None,
            };
            match resident {
                Some(CommRecord::Event {
                    kind: CommEventKind::TouchAsserted,
                    party_ref,
                    channel_class,
                    thread_ref: None,
                    occurred_at,
                    original_head: Some(original_head),
                    source_position: resident_source,
                    ..
                }) if party_ref == event.party_ref
                    && channel_class == event.channel_class
                    && occurred_at == event.occurred_at
                    && original_head == touch.id
                    && resident_source.as_ref() == Some(&source_position) => {}
                Some(_) => return Err(Error::InvalidClaimBody("comm touch source id collision")),
                None => {
                    let record = CommRecord::Event {
                        sequence: next_event_sequence_in_txn(vault, txn)
                            .map_err(super::generic_put_routing::source_event_error)?,
                        kind: CommEventKind::TouchAsserted,
                        party_ref: event.party_ref,
                        channel_class: event.channel_class,
                        thread_ref: None,
                        occurred_at: event.occurred_at,
                        projected: false,
                        original_head: Some(touch.id),
                        source_position: Some(source_position),
                    };
                    put_comm_record_in_txn(vault, txn, id, &record)
                        .map_err(super::generic_put_routing::source_event_error)?;
                }
            }
            projection
                .project_in_txn(
                    vault,
                    txn,
                    id,
                    CommEventKind::TouchAsserted,
                    &mut admission,
                    Some(&later_born_heads),
                )
                .map_err(super::generic_put_routing::source_event_error)?;
        }
        Ok(projection.into_written())
    }
}

/// A stored source names an existing native head; it never recreates that head.
/// Missing row/birth can arrive on sync later. A closed head stays closed.
pub(super) fn adopt_born_touch_head_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source_event_id: EntityId,
    id: EntityId,
    value: &CommClaimValue,
    source_position: &crate::write_envelope::communication_record::ScopedTouchSource,
) -> CommResult<Option<EntityId>> {
    let row = vault
        .store
        .port_entity_record(txn, &id)?
        .ok_or(CommError::Engine(Error::EntityNotFound))?;
    if crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.live_type()
        != Some(ENTITY_TYPE_CLAIM)
    {
        return Err(CommError::Engine(Error::EntityNotFound));
    }
    let birth = crate::store::birth_record::row_birth_in_txn(&vault.store, txn, &id)?
        .ok_or(CommError::Engine(Error::EntityNotFound))?;
    let body = crate::claim::decode_claim_body(&row.body, false)?;
    let claim = CommClaim::from_claim_body(&body)?;
    let (
        CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            occurred_at,
        },
        CommClaimValue::LastTouch {
            party_ref: actual_party,
            channel_class: actual_channel,
            occurred_at: actual_at,
        },
    ) = (value, &claim.value)
    else {
        return Err(CommError::InvalidRecord);
    };
    if party_ref != actual_party
        || occurred_at != actual_at
        || crate::counterparty_contact::normalize_channel_class(channel_class)
            != crate::counterparty_contact::normalize_channel_class(actual_channel)
    {
        return Err(CommError::InvalidRecord);
    }
    if !claim.is_standing() {
        return Ok(None);
    }
    // A pending source must not adopt a later scope/envelope/header revision
    // merely because that revision still states the same touch value.
    let (bound_id, bound_source) =
        touch_event_binding(id, &row.encode(), &birth, &body, &claim.value)?;
    if bound_id != source_event_id || &bound_source != source_position {
        return Err(CommError::InvalidRecord);
    }
    if !vault
        .claims_for_subject_in_txn(txn, party_ref)?
        .contains(&id)
        || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)?
    {
        return Err(CommError::InvalidRecord);
    }
    // This is the original Put the batch already admitted, not a new write.
    // The projector admits every subsequent supersession of another head.
    Ok(Some(id))
}

fn touch_event_binding(
    id: EntityId,
    row: &[u8],
    birth: &RowBirth,
    body: &crate::claim::ClaimBody,
    value: &CommClaimValue,
) -> CommResult<(
    EntityId,
    crate::write_envelope::communication_record::ScopedTouchSource,
)> {
    let CommClaimValue::LastTouch {
        party_ref,
        channel_class,
        occurred_at,
    } = value
    else {
        return Err(CommError::InvalidRecord);
    };
    let source = super::scoped_touch::capture_scoped_touch_source(body, row, birth)?;
    let event = super::scoped_touch::scoped_touch_event_id(
        id,
        &source,
        *party_ref,
        channel_class,
        *occurred_at,
    )?;
    Ok((event, source))
}

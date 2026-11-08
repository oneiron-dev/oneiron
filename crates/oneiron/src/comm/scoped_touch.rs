//! Identity and native position of a scoped, explicitly born touch source.

use super::claims::{CommClaim, CommClaimValue};
use super::records::{CommEventKind, CommRecord, decode_comm_record};
use crate::claim::{ClaimBody, record_scope_at};
use crate::entity_id::derived_domains::COMM_BORN_TOUCH_EVENT;
use crate::federation::Scope;
use crate::ports::{EdgeStoreRead, EntityStoreRead};
use crate::provenance::birth::RowBirth;
use crate::store::ManifestDbs;
use crate::write_envelope::communication_record::ScopedTouchSource;
use crate::{EntityId, Error, Result};

pub(crate) struct ScopedTouchRecord {
    source: ScopedTouchSource,
    original_head: EntityId,
    party_ref: EntityId,
    channel_class: String,
    occurred_at: u64,
}

impl ScopedTouchRecord {
    pub(crate) fn decode(id: EntityId, data: &[u8]) -> Result<Option<Self>> {
        let Ok(record) = decode_comm_record(data) else {
            return Ok(None);
        };
        let CommRecord::Event {
            kind: CommEventKind::TouchAsserted,
            original_head: Some(original_head),
            source_position: Some(source),
            party_ref,
            channel_class: Some(channel_class),
            occurred_at,
            ..
        } = record
        else {
            return Ok(None);
        };
        if scoped_touch_event_id(
            original_head,
            &source,
            party_ref,
            &channel_class,
            occurred_at,
        )? != id
        {
            return Err(Error::InvalidClaimBody(
                "scoped comm source binding mismatch",
            ));
        }
        Ok(Some(Self {
            source,
            original_head,
            party_ref,
            channel_class,
            occurred_at,
        }))
    }

    pub(crate) fn original_head(&self) -> EntityId {
        self.original_head
    }

    pub(crate) fn facet(&self) -> EntityId {
        self.source.facet
    }

    pub(crate) fn world(&self) -> EntityId {
        self.source.world
    }

    pub(crate) fn position(&self) -> Scope {
        scoped_touch_position(&self.source)
    }

    /// Required at the source's native birth, not again after closing a loser.
    pub(crate) fn origin_matches_in_txn(
        &self,
        store: &impl ManifestDbs,
        txn: &heed::RoTxn<'_>,
    ) -> Result<bool> {
        let Some(row) = store.port_entity_record(txn, &self.original_head)? else {
            return Ok(false);
        };
        if crate::vault::live_entity_row_in_txn(store, txn, &self.original_head)?.live_type()
            != Some(crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Ok(false);
        }
        let Some(birth) =
            crate::store::birth_record::row_birth_in_txn(store, txn, &self.original_head)?
        else {
            return Ok(false);
        };
        let body = crate::claim::decode_claim_body(&row.body, false)?;
        let claim = CommClaim::from_claim_body(&body)?;
        let standing = claim.is_standing();
        let CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            occurred_at,
        } = claim.value
        else {
            return Ok(false);
        };
        if !standing
            || party_ref != self.party_ref
            || occurred_at != self.occurred_at
            || crate::counterparty_contact::normalize_channel_class(&channel_class)
                != crate::counterparty_contact::normalize_channel_class(&self.channel_class)
            || store
                .port_edge_get(
                    txn,
                    &self.original_head,
                    crate::edge::EdgeKind::ClaimOf,
                    &self.party_ref,
                )?
                .is_none()
        {
            return Ok(false);
        }
        Ok(capture_scoped_touch_source(&body, &row.encode(), &birth)? == self.source)
    }
}

pub(super) fn capture_scoped_touch_source(
    body: &ClaimBody,
    row: &[u8],
    birth: &RowBirth,
) -> Result<ScopedTouchSource> {
    let world = body.world.unwrap_or_else(crate::claim::base_world_id);
    let claim = CommClaim::from_claim_body(body)?;
    let canonical = claim.value.claim_body()?;
    if !matches!(&claim.value, CommClaimValue::LastTouch { .. })
        || !same_touch_context_except_world(body, &canonical)
    {
        return Err(Error::InvalidClaimBody(
            "unsupported scoped comm source context",
        ));
    }
    let sensitivity = crate::claim::claim_sensitivity_band(body)
        .ok_or(Error::InvalidClaimBody("scoped comm source sensitivity"))?;
    let birth = rmp_serde::to_vec_named(birth.base_form().as_ref())
        .map_err(|_| Error::InvariantViolation("comm touch birth encoding failed"))?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron.comm.scoped_touch_origin.v1\0");
    digest.update(&(row.len() as u64).to_le_bytes());
    digest.update(row);
    digest.update(&birth);
    Ok(ScopedTouchSource {
        world,
        facet: body.scope_facet,
        project: body.scope_project,
        sensitivity,
        origin_digest: *digest.finalize().as_bytes(),
    })
}

pub(super) fn scoped_touch_event_id(
    original_head: EntityId,
    source: &ScopedTouchSource,
    party_ref: EntityId,
    channel_class: &str,
    occurred_at: u64,
) -> Result<EntityId> {
    let channel = crate::counterparty_contact::normalize_channel_class(channel_class);
    EntityId::derive(
        COMM_BORN_TOUCH_EVENT,
        &[
            original_head.as_bytes(),
            &source.origin_digest,
            source.world.as_bytes(),
            source.facet.as_bytes(),
            source.project.as_bytes(),
            &[source.sensitivity],
            party_ref.as_bytes(),
            channel.as_bytes(),
            &occurred_at.to_le_bytes(),
        ],
    )
}

pub(super) fn scoped_touch_position(source: &ScopedTouchSource) -> Scope {
    record_scope_at(
        source.world,
        source.facet,
        source.project,
        Some(source.sensitivity),
        "read",
    )
}

pub(super) fn same_touch_context_except_world(left: &ClaimBody, right: &ClaimBody) -> bool {
    left.rel == right.rel
        && left.scope_facet == right.scope_facet
        && left.scope_project == right.scope_project
        && left.scope == right.scope
        && crate::claim::claim_sensitivity_band(left) == crate::claim::claim_sensitivity_band(right)
        && left.session_tag == right.session_tag
}

pub(super) fn same_touch_context(left: &ClaimBody, right: &ClaimBody) -> bool {
    left.world.unwrap_or_else(crate::claim::base_world_id)
        == right.world.unwrap_or_else(crate::claim::base_world_id)
        && same_touch_context_except_world(left, right)
}

pub(super) fn touch_slot_body(
    value: &CommClaimValue,
    source: Option<&ScopedTouchSource>,
) -> super::claims::CommResult<ClaimBody> {
    let mut body = value.claim_body()?;
    if let Some(source) = source {
        if source.facet != body.scope_facet
            || source.project != body.scope_project
            || Some(source.sensitivity) != crate::claim::claim_sensitivity_band(&body)
        {
            return Err(super::claims::CommError::InvalidRecord);
        }
        body.world = Some(source.world);
    }
    Ok(body)
}

pub(super) fn matching_touch_heads_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    party_ref: EntityId,
    channel: &str,
    expected: &ClaimBody,
) -> super::claims::CommResult<Vec<(EntityId, CommClaim)>> {
    let heads = super::projection_writes::matching_claims_in_txn(
        vault,
        txn,
        party_ref,
        super::claims::PREDICATE_COMM_LAST_TOUCH,
        Some(channel),
        None,
        true,
    )?;
    let mut matches = Vec::new();
    for (id, claim) in heads {
        if let Some(body) = vault.get_claim_in_txn(txn, &id)?
            && same_touch_context(&body, expected)
        {
            matches.push((id, claim));
        }
    }
    Ok(matches)
}

//! The same native read-position predicate for inline source families.

use super::access_gate::RelationshipRead;
use super::{ScopedRead, ScopedReadActorKey};
use crate::EntityId;
use crate::access_grant::AccessContext;
use crate::error::{Error, Result};
use crate::skill_attribution::{AttributionJudgmentReadPosition, SkillEditProposalReadPosition};
use crate::skill_optimize::{JudgeLabelReadPosition, SkillVerdictReadPosition};
use crate::store::GateReadAnchors;
use crate::write_envelope::claim_body::RelationshipScope;
use oneiron_authority::federation::Scope;

/// A borrowed producer position. The canonical row and the live reader are
/// checked separately; these fields confer no authority.
pub(super) struct NativeReadPosition<'a> {
    scope: &'a Scope,
    kind_band: u8,
    relationship: &'a RelationshipScope,
    private: bool,
    body_worlds: &'a [EntityId],
    body_facets: &'a [EntityId],
    anchors: &'a GateReadAnchors,
}

impl NativeReadPosition<'_> {
    pub(super) fn is_complete(&self) -> bool {
        self.anchors.is_complete()
            && !self.anchors.worlds().is_empty()
            && !self.body_worlds.is_empty()
            && self.scope.bands.contains(&self.kind_band)
    }
}

impl<'a> From<&'a JudgeLabelReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a JudgeLabelReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl<'a> From<&'a SkillVerdictReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a SkillVerdictReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl<'a> From<&'a AttributionJudgmentReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a AttributionJudgmentReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl<'a> From<&'a SkillEditProposalReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a SkillEditProposalReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl<'a> From<&'a crate::skill_reliability::RuleOutcomeReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a crate::skill_reliability::RuleOutcomeReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl<'a> From<&'a crate::skill_reliability::OutcomeReadPosition> for NativeReadPosition<'a> {
    fn from(position: &'a crate::skill_reliability::OutcomeReadPosition) -> Self {
        Self {
            scope: &position.scope,
            kind_band: position.kind_band,
            relationship: &position.relationship,
            private: position.private,
            body_worlds: &position.body_worlds,
            body_facets: &position.body_facets,
            anchors: &position.anchors,
        }
    }
}

impl ScopedRead<'_> {
    pub(super) fn native_position_lane_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        row_id: EntityId,
        position: &NativeReadPosition<'_>,
    ) -> Result<bool> {
        match self.owner_live_in(txn) {
            Ok(()) => {}
            Err(Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(_))) => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        if !self.proof_live_in(txn)? || !self.credential_allows_row_in(txn, &row_id) {
            return Ok(false);
        }
        if let Some(proof) = self.actor_key.proof.as_ref()
            && !self
                .vault
                .guest_row_admitted_in_txn(txn, proof.claims(), || {
                    Ok(Some((*position.scope).clone()))
                })
        {
            return Ok(false);
        }
        if crate::store::legal_hold::use_limit_in_txn(&self.vault.store, txn, &row_id)?.is_some() {
            return Ok(false);
        }
        let policy = self.policy_manifest_in(txn)?;
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            None,
        )?;
        if filter.deny_all
            || self
                .vault
                .store
                .validate_entity_type(position.kind_band)
                .is_err()
            || !filter.read_scope().bands.contains(&position.kind_band)
            || !position
                .scope
                .sensitivity
                .is_narrowing_of(filter.read_scope().sensitivity)
            || !crate::gate::scoped_read_record_allowed(&policy, &self.actor_key, position.scope)
            || !self
                .actor_key
                .facets_allow_placed_in(self.vault, txn, position.body_facets)?
        {
            return Ok(false);
        }
        if self.relationship_gated_in(txn)? {
            let context = AccessContext::load(self.vault, txn, self.actor_key.principal_ref)?;
            let read = RelationshipRead::Gated {
                kind: position.kind_band,
                space: (*position.relationship).clone(),
                private: position.private,
                record: (*position.scope).clone(),
            };
            if !read.allowed_by(&context) {
                return Ok(false);
            }
        }
        let room = match &self.actor_key.room_turn {
            Some(turn) => match self.room_ceiling_in(txn, turn)? {
                Some(room) => Some(room),
                None => return Ok(false),
            },
            None => None,
        };
        let withheld = crate::settings::device_local_worlds_for(
            self.vault,
            txn,
            self.actor_key.destination(),
        )?;
        let ceiling = self.actor_key.world_ceiling();
        let declared = super::actor_key::world_only(position.scope.worlds.clone());
        for world in position.body_worlds.iter().chain(position.anchors.worlds()) {
            let record = super::actor_key::record_world_scope(Some(*world));
            if !record.is_narrowing_of(&declared)
                || !record.is_narrowing_of(&ceiling)
                || withheld.contains(world)
                || room
                    .as_ref()
                    .is_some_and(|room| !room.admits_world(&record))
            {
                return Ok(false);
            }
        }
        let viewers: Vec<_> = self.actor_key.authenticated_person().into_iter().collect();
        if !self.native_position_audience_in(
            txn,
            position.anchors,
            &viewers,
            self.room_peer,
            None,
        )? {
            return Ok(false);
        }
        let personal = room
            .as_ref()
            .filter(|room| room.personal)
            .map(|room| room.caller);
        if let Some(room) = &room {
            let disclosed = room.terms.with(|terms| {
                !terms.p7
                    || terms.clearance.is_none()
                    || position.scope.sensitivity
                        == oneiron_authority::federation::SensitivityCeiling::AtMost(
                            oneiron_authority::federation::Sensitivity::Public,
                        )
                    || terms.room_scope().admits(
                        "read",
                        position.scope,
                        &oneiron_authority::federation::Scope::top(),
                    )
            });
            if !disclosed
                || !self.native_position_audience_in(
                    txn,
                    position.anchors,
                    &room.roster,
                    room.personal,
                    personal,
                )?
                || !self.native_position_peers_admit_in(
                    txn,
                    &room.peers,
                    row_id,
                    position,
                    room.personal,
                )?
            {
                return Ok(false);
            }
        }
        if let Some(audience) = &self.audience
            && !self.native_position_audience_in(
                txn,
                position.anchors,
                audience,
                personal.is_some(),
                personal,
            )?
        {
            return Ok(false);
        }
        let unbound_agent = self.actor_key.room_turn.is_none()
            && [crate::EdgeActorClass::Agent, crate::EdgeActorClass::System]
                .into_iter()
                .any(|class| self.actor_key.actor_class() == Some(class.gate_actor_class()));
        if unbound_agent {
            let Some(reader) = EntityId::from_hex(self.actor_key.actor_ref()).ok() else {
                return Ok(false);
            };
            let Some(occurred) = position.anchors.occurred() else {
                return Ok(false);
            };
            if !crate::conversation::anchors_own_windows_admit_in(
                self.vault,
                txn,
                position.anchors.rooms(),
                reader,
                occurred.start,
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn native_position_audience_in(
        &self,
        txn: &heed::RoTxn<'_>,
        anchors: &GateReadAnchors,
        audience: &[EntityId],
        current: bool,
        personal: Option<EntityId>,
    ) -> Result<bool> {
        self.audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .anchors_readable_in(
                self.vault,
                &self.store_read(),
                txn,
                anchors,
                audience,
                current,
                personal,
            )
    }

    fn native_position_peers_admit_in(
        &self,
        txn: &heed::RoTxn<'_>,
        peers: &[ScopedReadActorKey],
        row_id: EntityId,
        position: &NativeReadPosition<'_>,
        room_peer: bool,
    ) -> Result<bool> {
        for key in peers {
            let mut peer = self.vault.scoped_read(key.clone());
            peer.room_peer = room_peer;
            peer.judged_at = self.judged_at;
            if !peer.native_position_lane_admitted_in(txn, row_id, position)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

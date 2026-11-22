//! FIX AGENT-GRAPHFS-GRANT-WORLDS: a credential the owner's agent Grants
//! bind reads a row only where one of those Grants, alone, admits the row's
//! whole position (Engine RULING GRANT-COMBINE Q1 = A, 11 Nov 04:30; Grants
//! are never unioned). The key's own Scope is met with their envelope, so
//! every other check already binds; this adds the one conjunct the envelope
//! cannot answer, and the one the NOTE shortcuts skip: a base NOTE is read
//! "always" at the world-membership check (`note_world`), so only a Grant
//! that holds base reads it, as FIX 7462 judges a row under a Grant. The
//! holder's Grants are also read again in each serving txn, so a lane held
//! past a revoke narrows with it (REVIEW-7051 P1).

use super::access_gate::HeldAuthority;
use super::{ScopedRead, ScopedReadActorKey};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimRecordScope, decode_claim_body};
use crate::error::{Error, Result};
use crate::federation::facet_read::facets_admit_in;
use crate::federation::record_scope::{default_stamp, note_world, scope_for_blob};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron_authority::federation::Scope;

impl ScopedRead<'_> {
    /// Whether the row `raw` of `id` lies inside one of this key's agent
    /// Grant alternatives alone: its record position, held at one world the
    /// key's ceiling and that alternative both hold, admitted by that
    /// alternative, and its facets inside that alternative's. A key no agent
    /// Grant binds admits every row here; one bound by no standing Grant,
    /// none.
    ///
    /// A key that names its holder ([`ScopedReadActorKey::agent_grant_holder`])
    /// also needs one of the Grants that stand for that holder in `rtxn`,
    /// each alone and met with the key's own Scope, read once per serving txn
    /// in `authority`: a Grant revoked or lapsed since the key was built, or
    /// since its lane was saved, narrows the lane still held (REVIEW-7051
    /// P1). A Grant minted since narrows it too, as a fresh key would be.
    ///
    /// # Errors
    /// A store or decode failure reading the row's position or facets, or a
    /// store, fold or clock failure reading the holder's Grants.
    pub(super) fn one_grant_alternative_admits_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority,
    ) -> Result<bool> {
        let standing = self
            .actor_key
            .agent_grant_holder()
            .map(|holder| {
                authority.grants().bounds_of(holder, || {
                    self.vault.agent_grant_read_bounds_in_txn(rtxn, holder)
                })
            })
            .transpose()?;
        let standing = standing.as_deref().and_then(|bounds| bounds.as_deref());
        let kept = self.actor_key.grant_alternatives();
        if kept.is_none() && standing.is_none() {
            return Ok(true);
        }
        let Some((entity_type, record)) = self.row_position_in(rtxn, id, raw)? else {
            return Ok(false);
        };
        if let Some(kept) = kept
            && !self.one_of_admits_in(rtxn, id, raw, entity_type, &record, kept)?
        {
            return Ok(false);
        }
        let Some(standing) = standing else {
            return Ok(true);
        };
        let own = self
            .actor_key
            .authority_scope()
            .cloned()
            .unwrap_or_else(Scope::top);
        let live: Vec<Scope> = standing
            .iter()
            .map(|bound| ScopedReadActorKey::read_authority(&own.meet(bound)))
            .collect();
        self.one_of_admits_in(rtxn, id, raw, entity_type, &record, &live)
    }

    /// [`Self::one_grant_alternative_admits_in`] for a position judged with
    /// no live row behind it (FIX AGENT-GRANT-ENVELOPE-ONLY-PATHS; RULING
    /// GRANT-COMBINE Q1 = A): whether `holds` accepts one of this key's kept
    /// agent Grant alternatives alone and, when the key names its holder, one
    /// of the holder's Grants that stand for `read` in `rtxn`, alone and met
    /// with the key's own Scope. A key no agent Grant binds holds every
    /// position here; one bound by no standing Grant, none. The key's world
    /// ceiling is the caller's to check.
    ///
    /// The holder's Grants are read through `authority`, once per serving txn
    /// where the caller holds one for the whole read (the change feed, short
    /// references, loop decisions); the world listing and a timeline's
    /// deleted shells pass a fresh one, so they read them per call. A kept
    /// alternative that refuses ends the check before any Grant is read.
    ///
    /// # Errors
    /// `holds`'s, or a store, fold or clock failure reading the holder's
    /// Grants.
    fn one_grant_alternative_holds_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        authority: &HeldAuthority,
        mut holds: impl FnMut(&Scope) -> Result<bool>,
    ) -> Result<bool> {
        let kept = self.actor_key.grant_alternatives();
        if let Some(kept) = kept {
            let mut one = false;
            for alternative in kept {
                if holds(alternative)? {
                    one = true;
                    break;
                }
            }
            if !one {
                return Ok(false);
            }
        }
        let standing = self
            .actor_key
            .agent_grant_holder()
            .map(|holder| {
                authority.grants().bounds_of(holder, || {
                    self.vault.agent_grant_read_bounds_in_txn(rtxn, holder)
                })
            })
            .transpose()?;
        let Some(standing) = standing.as_deref().and_then(|bounds| bounds.as_deref()) else {
            return Ok(true);
        };
        let own = self
            .actor_key
            .authority_scope()
            .cloned()
            .unwrap_or_else(Scope::top);
        for bound in standing {
            if holds(&ScopedReadActorKey::read_authority(&own.meet(bound)))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether one Grant alone holds `world` (`None` is base reality), as
    /// [`Self::one_grant_alternative_holds_in`] judges it: the graph_fs walk
    /// lists, and walks into, only a world one Grant alone reads (ARCH-0051
    /// "a walk lists only what the grant allows"), so a lane held past a
    /// revoke stops listing that Grant's worlds.
    ///
    /// # Errors
    /// A store, fold or clock failure reading the holder's Grants.
    pub(crate) fn one_grant_alternative_walks_world_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
    ) -> Result<bool> {
        let position = super::actor_key::record_world_scope(world);
        self.one_grant_alternative_holds_in(
            rtxn,
            &HeldAuthority::for_request(None),
            |alternative| Ok(holds_world(&position, alternative)),
        )
    }

    /// Whether one Grant alone holds the deleted shell `raw` of `id` at the
    /// world-only `position` it still proves, and its facets, as the row gate
    /// judges a live row's ([`Self::one_of_admits_in`]).
    ///
    /// # Errors
    /// A store failure reading the shell's facets, or the holder's Grants.
    pub(super) fn one_grant_alternative_holds_shell_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        authority: &HeldAuthority,
        id: &EntityId,
        raw: &[u8],
        position: &Scope,
    ) -> Result<bool> {
        let entity_type = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity header"))?
            .entity_type;
        self.one_grant_alternative_holds_in(rtxn, authority, |alternative| {
            Ok(holds_world(position, alternative)
                && alternative.bands.contains(&entity_type)
                && self.alternative_facets_admit_in(rtxn, id, Some(raw), alternative)?)
        })
    }

    /// Whether `alternative`'s facets admit the row `id` whose stored row is
    /// `raw`, as the key's own facet check judges it ([`facets_admit_in`]);
    /// with no stored row, only an alternative that holds every facet does.
    fn alternative_facets_admit_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: Option<&[u8]>,
        alternative: &Scope,
    ) -> Result<bool> {
        let Some(raw) = raw else {
            return Ok(matches!(
                alternative.facets,
                oneiron_authority::federation::ScopeAxis::All
            ));
        };
        match self.session_view {
            Some(view) => facets_admit_in(self.vault, view, rtxn, *id, raw, &alternative.facets),
            None => facets_admit_in(
                self.vault,
                &self.vault.store,
                rtxn,
                *id,
                raw,
                &alternative.facets,
            ),
        }
    }

    /// Whether one Grant alone admits a read of the record position `record`
    /// under `policy`, as a proof of that Grant would at the record door: a
    /// deleted TASK's kept stamp, a kept loop decision's position with no
    /// claim, or every position at once for deletion metadata. The record
    /// door judges no facet, so where the caller's own check judged the
    /// facets of a `row` (its id and stored row, if any), that Grant's facets
    /// must admit it too, as the row gate holds them.
    ///
    /// # Errors
    /// A store failure reading the row's facets, or a store, fold or clock
    /// failure reading the holder's Grants.
    pub(super) fn one_grant_alternative_admits_record_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        authority: &HeldAuthority,
        policy: &crate::gate::PolicyManifestResolution,
        record: &Scope,
        row: Option<(&EntityId, Option<&[u8]>)>,
    ) -> Result<bool> {
        self.one_grant_alternative_holds_in(rtxn, authority, |alternative| {
            Ok(crate::gate::scoped_read_record_allowed_with_scope(
                policy,
                &self.actor_key,
                record,
                Some(alternative),
            ) && row.map_or(Ok(true), |(id, raw)| {
                self.alternative_facets_admit_in(rtxn, id, raw, alternative)
            })?)
        })
    }

    /// [`Self::one_grant_alternative_admits_record_in`] at the claim door: a
    /// kept loop decision's claim `view`, judged as its base check judges it.
    ///
    /// # Errors
    /// A store, fold or clock failure reading the holder's Grants.
    pub(super) fn one_grant_alternative_admits_claim_view_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        authority: &HeldAuthority,
        policy: &crate::gate::PolicyManifestResolution,
        view: &crate::gate::ClaimReadView<'_>,
        row: Option<(&EntityId, Option<&[u8]>)>,
    ) -> Result<bool> {
        self.one_grant_alternative_holds_in(rtxn, authority, |alternative| {
            Ok(crate::gate::scoped_read_claim_view_allowed(
                policy,
                &self.actor_key,
                view,
                Some(alternative),
            ) && row.map_or(Ok(true), |(id, raw)| {
                self.alternative_facets_admit_in(rtxn, id, raw, alternative)
            })?)
        })
    }

    /// Whether one of `alternatives` alone admits the row `raw` of `id`,
    /// whose type is `entity_type` and record position `record`: held at one
    /// world the key's ceiling and that alternative both hold, admitted by
    /// that alternative, and its facets inside that alternative's.
    fn one_of_admits_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        entity_type: u8,
        record: &Scope,
        alternatives: &[Scope],
    ) -> Result<bool> {
        let ceiling = self.actor_key.world_ceiling();
        for alternative in alternatives {
            let held = note_world::held_at(
                &self.store_read(),
                rtxn,
                *id,
                entity_type,
                record,
                &[&ceiling.worlds, &alternative.worlds],
            );
            if !alternative.admits("read", &held, &Scope::top()) {
                continue;
            }
            let facets = match self.session_view {
                Some(view) => {
                    facets_admit_in(self.vault, view, rtxn, *id, raw, &alternative.facets)?
                }
                None => facets_admit_in(
                    self.vault,
                    &self.vault.store,
                    rtxn,
                    *id,
                    raw,
                    &alternative.facets,
                )?,
            };
            if facets {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The record position of the row `raw` of `id`, with its type: a
    /// CLAIM's own record Scope, any other row's where `scope_for_blob`
    /// places it on this read's store, and a NOTE born with no FacetOf edge
    /// at the ordinary base position (as `Vault::content_scope_in_txn`
    /// places one). `None`: sealed custody, a CLAIM that does not decode, or
    /// another row with no position.
    fn row_position_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<Option<(u8, Scope)>> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
            return Ok(None);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            return Ok(decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
                .ok()
                .map(|body| (header.entity_type, body.record_scope("read"))));
        }
        let stamped = match self.session_view {
            Some(view) => scope_for_blob(view, rtxn, *id, raw)?,
            None => scope_for_blob(&self.vault.store, rtxn, *id, raw)?,
        };
        Ok(match stamped {
            Some(record) => Some((header.entity_type, record)),
            None if header.entity_type == ENTITY_TYPE_NOTE => Some((
                header.entity_type,
                default_stamp(header.entity_type, crate::claim::substrate_facet_id(*id)?),
            )),
            None => None,
        })
    }
}

/// Whether `alternative`'s worlds hold the world-only `position`.
fn holds_world(position: &Scope, alternative: &Scope) -> bool {
    position.is_narrowing_of(&super::actor_key::world_only(alternative.worlds.clone()))
}

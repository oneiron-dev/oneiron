//! The gate a deleted record's shell takes on a memory timeline, as its
//! anchor and as one of its records: B, the key's own floor reads the
//! shell's type and holds its place, else A, one of the reader's own live
//! Grants alone does (Engine ANSWER GRANT-AGENT-DELETED-SHELLS = A). Either
//! way the shell shows its deletion metadata only, never a body.

use super::ScopedRead;
use super::access_gate::HeldAuthority;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::federation::record_scope::{default_stamp, scope_for_blob};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::{EntityId, Error, Result};
use oneiron_authority::federation::{Scope, ScopeAxis};

impl ScopedRead<'_> {
    /// A deleted shell's authority: B, the key's own `filter` reads its type
    /// and it holds the shell's place, else A, one of the reader's own live
    /// Grants alone does (Engine ANSWER GRANT-AGENT-DELETED-SHELLS = A).
    pub(super) fn shell_authority_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
        raw: &[u8],
        held: &HeldAuthority,
    ) -> Result<bool> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if !filter.deny_all
            && filter.read_scope().bands.contains(&header.entity_type)
            && self.deleted_shell_position_allowed_in(txn, policy, id, raw, held, None)?
        {
            return Ok(true);
        }
        Ok(self.own_shell_readable_by_grant_in(
            txn,
            policy,
            filter,
            header.entity_type,
            held,
            |grant| self.deleted_shell_position_allowed_in(txn, policy, id, raw, held, Some(grant)),
        ))
    }

    /// The type-only fallback above serves a deleted shell's metadata, but a
    /// TASK may have been born in any world or facet (ARCH-0067 §5). Its
    /// shell reads at the position a kept stamp proves; one whose stamp went
    /// with its body reads as if it sat anywhere, so only a reader whose
    /// ceiling holds every world and facet sees it. Under `grant` (A), that
    /// Grant alone must hold the shell's place too.
    fn deleted_shell_position_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        held: &HeldAuthority,
        grant: Option<&Scope>,
    ) -> Result<bool> {
        // A read limited to facets names only a shell that still proves a
        // place inside them. The credential's records and channel caveats
        // bound a shell as they bound its live row (FIX 8666).
        if !self.credential_allows_id(id) || !self.facets_allow_held_in(txn, id, raw, held)? {
            return Ok(false);
        }
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_TASK {
            // Any other shell sits in the world its row still proves; one
            // that proves none reads as if anywhere, so only a read whose
            // asked and credential worlds hold every world sees it (FIX 8666).
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let world = match self.session_view {
                Some(view) => crate::federation::record_scope::record_world_in(
                    view,
                    txn,
                    *id,
                    header.entity_type,
                    body,
                )?,
                None => crate::federation::record_scope::record_world_in(
                    &self.vault.store,
                    txn,
                    *id,
                    header.entity_type,
                    body,
                )?,
            };
            let position = world.map_or_else(Scope::top, super::actor_key::record_world_scope);
            // One agent Grant alone must hold it too (FIX
            // AGENT-GRANT-ENVELOPE-ONLY-PATHS).
            return Ok(position.is_narrowing_of(&self.actor_key.world_ceiling())
                && grant.map_or(Ok(true), |grant| {
                    self.own_grant_holds_shell_in(txn, id, raw, &position, world.is_some(), grant)
                })?
                && self.one_grant_alternative_holds_shell_in(
                    txn,
                    &HeldAuthority::for_request(None),
                    id,
                    raw,
                    &position,
                )?);
        }
        let kept = match self.session_view {
            Some(view) => scope_for_blob(view, txn, *id, raw)?,
            None => scope_for_blob(&self.vault.store, txn, *id, raw)?,
        };
        let proved = kept.is_some();
        let position = kept.unwrap_or_else(|| Scope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            verbs: ScopeAxis::Some(["read".to_owned()].into()),
            ..default_stamp(header.entity_type, *id)
        });
        let record = grant.or(self.actor_key.authority_scope());
        Ok(crate::gate::scoped_read_record_allowed_with_scope(
            policy,
            &self.actor_key,
            &position,
            record,
        ) && grant.map_or(Ok(true), |grant| {
            self.own_grant_holds_shell_in(txn, id, raw, &position, proved, grant)
        })? && self.one_grant_alternative_admits_record_in(
            txn,
            &HeldAuthority::for_request(None),
            policy,
            &position,
            Some((id, Some(raw))),
        )?)
    }
}

//! Project placement of NOTE, MESSAGE and TURN rows: the one reader of a row's
//! project and the NOTE settle door. A row's project is the audience axis of
//! its birth stamp in `SCOPE_RECORD`; a session-placed write settles it at
//! birth, as the witness doors settle TURN and MESSAGE rows.

use super::*;

/// A stored row's PROJECT: a CLAIM's own body stamp; for any other row its
/// record position, where both TURN write doors stamp a leader-chat turn's
/// project, the same stamp the scoped read doors select. The vault default
/// where the row carries no position; `None` where the position's audience
/// is not exactly one project, or where a stamp row stands but does not bind
/// (`stamp_bound_on` false), which is no usable placement.
pub(crate) fn stored_project(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    body: &[u8],
) -> Result<Option<EntityId>> {
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(Some(
            crate::claim::decode_claim_body(body, true)?.scope_project,
        ));
    }
    let Some(position) = disclosure_scope_for_stored_row(store, txn, id, kind, body)? else {
        // `stored_scope` answers `None` both where no stamp row stands and
        // where one stands but does not bind: only the first reads as the
        // vault default.
        let stamped = SCOPE_RECORD.get(store, txn, &id)?.is_some();
        return Ok((!stamped).then(crate::claim::default_project_id));
    };
    Ok(match position.audience {
        crate::federation::ScopeAxis::Some(ids) if ids.len() == 1 => {
            ids.into_iter().next().map(|id| id.0)
        }
        _ => None,
    })
}

/// Whether the session's projects admit this row: a CLAIM by its body, a NOTE,
/// MESSAGE or TURN by its placement in the lane's own store, and every other
/// row always. `stored_project` reads no stamp as the default project and an
/// unusable stamp as no placement. With `room_speech` (a room history lane,
/// PLACEMENT-B-ROOM-ROWS = B), every MESSAGE and TURN: the room admits those.
pub(crate) fn session_projects_admit_row(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    projects: &crate::session_project::SessionProjects,
    room_speech: bool,
) -> Result<bool> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    match header.entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => Ok(crate::claim::decode_claim_body(body, true)
            .is_ok_and(|body| projects.admits(body.scope_project))),
        crate::registry::ENTITY_TYPE_MESSAGE | crate::registry::ENTITY_TYPE_TURN if room_speech => {
            Ok(true)
        }
        crate::registry::ENTITY_TYPE_NOTE
        | crate::registry::ENTITY_TYPE_MESSAGE
        | crate::registry::ENTITY_TYPE_TURN => {
            match stored_project(store, txn, id, header.entity_type, body) {
                Ok(project) => Ok(project.is_some_and(|project| projects.admits(project))),
                Err(error) => {
                    tracing::warn!(
                        error_kind = ?error.kind(),
                        "a session read refused a row whose placement it could not read: unreadable \
                         placement is quiet, never a wider read (SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT)"
                    );
                    Ok(false)
                }
            }
        }
        _ => Ok(true),
    }
}

/// Settle a session-placed NOTE onto its project
/// (SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT), after the NOTE's birth batch
/// lands. Only the birth writer calls this door, in the birth transaction;
/// opaque replicated rows cannot call it and remain unstamped.
///
/// The birth position is immutable (see `stamp_put`): this door only moves
/// the record's own default birth stamp to the session's project, or confirms
/// the project stamp it already carries. Any other prior position is refused.
/// Like `stamp_witness_project` it settles only the audience; the birth facet
/// stays the NOTE's own `FacetOf` target, and a NOTE with none is refused.
pub(crate) fn stamp_note_project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    project: EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("note project scope header"))?;
    let kind = header.entity_type;
    if kind != crate::registry::ENTITY_TYPE_NOTE {
        return Err(Error::InvalidEntityType(kind));
    }
    // A NOTE's stamp binds to its `FacetOf` birth facet (`stamp_bound_on`'s
    // NOTE arm reads it through `carries_birth_stamp`): with no birth facet
    // there is no position to settle.
    let Some(facet) = birth_facet(store, txn, id)? else {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    };
    let prior = SCOPE_RECORD.get(store, txn, &id)?;
    let position = match &prior {
        Some(stamp)
            if stamp.version == 2
                && stamp.kind == kind
                && stamp.birth_facet == *facet.as_bytes() =>
        {
            stamp.scope.clone()
        }
        Some(_) => {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        None => default_stamp(kind, facet),
    };
    let default_audience = singleton(ScopeId(crate::claim::default_project_id()));
    if position.audience != default_audience && position.audience != singleton(ScopeId(project)) {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    let mut scope = position.clone();
    scope.audience = singleton(ScopeId(project));
    if prior.as_ref().is_some_and(|stamp| stamp.scope == scope) {
        return Ok(());
    }
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *facet.as_bytes(),
            scope,
        },
    )?;
    Ok(())
}

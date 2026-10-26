//! The birth-position stamp doors: put, stage, settle and restamp a record's position.

use super::*;

pub(crate) fn stamp_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    bump_scope_revision(store, txn)?;
    let prior = SCOPE_RECORD.get(store, txn, &id)?;
    let Some((scope, facet)) = derived_position(store, txn, id, kind, data)? else {
        if prior.is_some() {
            return Err(Error::InvalidClaimBody("birth facet restamp refused"));
        }
        // A birth without its same-transaction FacetOf is not stamped.
        return Ok(());
    };
    if let Some(prior) = prior {
        // Content is mutable. The type, facet and authority position are NOT.
        // A changed facet/sensitivity/world/audience is a fork with a new id.
        let kept = prior.birth_facet == *facet.as_bytes()
            && (prior.scope == scope
                || settled_at_birth(kind, &prior.scope, &scope)
                || note_world::live_world_kept(kind, &prior.scope, &scope));
        if prior.version != 2 || prior.kind != kind || !(kept || writer_settled(&prior, &scope)) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        return Ok(());
    }
    if replicated && kind != crate::registry::ENTITY_TYPE_CLAIM {
        // A peer cannot mint a birth position for an opaque row merely by
        // picking its ID and bytes. Only an existing stamped row inherits.
        return Ok(());
    }
    let stamp = Stamp {
        version: 2,
        kind,
        birth_facet: *facet.as_bytes(),
        scope,
    };
    SCOPE_RECORD.put(store, txn, &id, &stamp)?;
    Ok(())
}

/// Stages the position of `id`, a row a room's write stages in `view`, beside
/// it in the room's overlay (WILL L11-01): the derivation `stamp_put` makes
/// on base, kept as the room's content metadata, which a narrowed read places
/// the row by. A row base holds keeps its base birth, which a room never
/// restamps; a row the room placed keeps that position; one whose position
/// cannot be derived yet (a NOTE before its `FacetOf`, a body that names no
/// position) stays unplaced, and a narrowed read never finds it. Base and its
/// scope revision see nothing, and a promote replays none of it.
pub(crate) fn stage_session_position(
    view: &crate::store::SessionStoreView<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    if crate::ports::EntityStoreRead::port_entity_present(view.read().base(), &*txn, &id)?
        || SCOPE_RECORD.get(view, txn, &id)?.is_some()
    {
        return Ok(());
    }
    let (scope, facet) = match derived_position(view, txn, id, kind, data) {
        Ok(Some(position)) => position,
        Ok(None) | Err(Error::InvalidClaimBody(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let stamp = Stamp {
        version: 2,
        kind,
        birth_facet: *facet.as_bytes(),
        scope,
    };
    SCOPE_RECORD.put(view, txn, &id, &stamp)
}

/// Whether every row `view`'s room stages a body, words, a vector or an
/// out-edge for is one the room placed itself (WILL L11-01): a room birth
/// carrying the position its write staged beside it
/// ([`stage_session_position`]). A room that restages or hides a base row,
/// or adds an edge from one, or holds a row whose position it could not
/// derive, has not placed all its rows: a read that must place each row it
/// serves (a credential for only some worlds) reads base alone there, so no
/// base row is placed for it by what the room wrote.
pub(crate) fn room_rows_placed(view: &crate::store::SessionStoreView<'_>) -> bool {
    // Each of these keys starts with the row's id; an out-edge's with its
    // source's.
    let placed = |key: &[u8]| {
        key.get(..16)
            .and_then(|id| <[u8; 16]>::try_from(id).ok())
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            .is_some_and(|id| view.vault_meta.stages_row(&SCOPE_RECORD.key_bytes(&id)))
    };
    let rows = [
        &view.entities,
        &view.text_forward,
        &view.vectors,
        &view.edges_out,
    ];
    rows.into_iter().all(|keyspace| {
        keyspace.staged_rows().is_none_or(|staged| {
            !staged.clear_base && staged.rows.iter().all(|(key, _)| placed(key))
        })
    })
}

/// Settles an epoch SUMMARY's birth position in its mint transaction: born
/// in `world` under `facet`, where its run's records are born, never the
/// generic SUMMARY position. Only the default stamp `stamp_put` just wrote
/// may be settled; its structural anchor and every other axis stay.
pub(crate) fn settle_epoch_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    world: EntityId,
    facet: EntityId,
) -> Result<()> {
    let kind = crate::registry::ENTITY_TYPE_SUMMARY;
    let anchor = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, anchor);
    let prior = SCOPE_RECORD
        .get(store, txn, &id)?
        .ok_or(Error::InvalidClaimBody("unstamped epoch summary"))?;
    if prior.version != 2
        || prior.kind != kind
        || prior.birth_facet != *anchor.as_bytes()
        || prior.scope != birth
    {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    let mut scope = birth;
    scope.worlds = singleton(ScopeId(world));
    scope.facets = singleton(ScopeId(facet));
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *anchor.as_bytes(),
            scope,
        },
    )?;
    Ok(())
}

/// Settles a confirmed provisional entity's birth position in its birth
/// transaction (FIX 10168): born under `facet`, the facet of the turn its
/// name was read from (ARCH-0022), never its own substrate facet. Only the
/// default stamp `stamp_put` just wrote for a PERSON, ORG or PLACE may be
/// settled; its structural anchor and every other axis stay, a settled
/// birth is never moved again, and a later content put keeps the settled
/// facet (`settled_at_birth`).
pub(crate) fn settle_source_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    facet: EntityId,
) -> Result<()> {
    let named = matches!(
        kind,
        crate::registry::ENTITY_TYPE_PERSON
            | crate::registry::ENTITY_TYPE_ORG
            | crate::registry::ENTITY_TYPE_PLACE
    );
    let anchor = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, anchor);
    let prior = SCOPE_RECORD
        .get(store, txn, &id)?
        .ok_or(Error::InvalidClaimBody("unstamped source birth"))?;
    if !named
        || prior.version != 2
        || prior.kind != kind
        || prior.birth_facet != *anchor.as_bytes()
        || prior.scope != birth
    {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    let mut scope = birth;
    scope.facets = singleton(ScopeId(facet));
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *anchor.as_bytes(),
            scope,
        },
    )?;
    Ok(())
}

/// Raises a stamped record's sensitivity to at least `band`, in the
/// transaction that stored it (OF-560: a file the write door kept with keys
/// in it is Restricted). Every other axis stays. An unstamped record stays
/// unstamped, and a stamp already as strict stays as it is.
pub(crate) fn restrict_stamp_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    band: Sensitivity,
) -> Result<()> {
    let Some(mut stamp) = SCOPE_RECORD.get(store, txn, &id)? else {
        return Ok(());
    };
    if matches!(stamp.scope.sensitivity, SensitivityCeiling::AtMost(at) if at >= band) {
        return Ok(());
    }
    stamp.scope.sensitivity = SensitivityCeiling::AtMost(band);
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(store, txn, &id, &stamp)
}

/// Settle a locally minted TASK at its writer's world and facet, in the
/// transaction that put its first body. The writer's facet is provenance:
/// the mask that spoke stamps the record (ARCH-0022 "Every record carries a
/// facet").
///
/// The birth position is immutable (see `stamp_put`): like
/// `stamp_leader_project`, this door only moves the record's own default
/// birth stamp, or confirms the position it already carries. Any other prior
/// position is refused. Opaque replicated rows cannot call it and remain
/// unstamped.
pub(crate) fn stamp_task_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    position: BirthPosition,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("task birth scope header"))?;
    let kind = header.entity_type;
    if kind != crate::registry::ENTITY_TYPE_TASK {
        return Err(Error::InvalidEntityType(kind));
    }
    let substrate = crate::claim::substrate_facet_id(id)?;
    let facet = position.facet.unwrap_or(substrate);
    let mut scope = default_stamp(kind, facet);
    if let Some(world) = position.world {
        scope.worlds = singleton(ScopeId(world));
    }
    if let Some(prior) = SCOPE_RECORD.get(store, txn, &id)? {
        let settled = prior.birth_facet == *facet.as_bytes() && prior.scope == scope;
        let birth = prior.birth_facet == *substrate.as_bytes()
            && prior.scope == default_stamp(kind, substrate);
        if prior.version != 2 || prior.kind != kind || !(settled || birth) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        if settled {
            return Ok(());
        }
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

/// An authority fact about one TASK is born at that TASK's settled position,
/// so a reader outside the TASK's world reads none of the facts about it. A
/// TASK at its default birth, or with no stamp, leaves the fact at its own.
pub(crate) fn stamp_task_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    fact: EntityId,
    task: EntityId,
) -> Result<()> {
    let Some(stamp) = SCOPE_RECORD.get(store, txn, &task)? else {
        return Ok(());
    };
    if stamp.version != 2 || stamp.kind != crate::registry::ENTITY_TYPE_TASK {
        return Ok(());
    }
    let world = match &stamp.scope.worlds {
        ScopeAxis::Some(worlds) if worlds.len() == 1 => worlds.first().map(|world| world.0),
        _ => None,
    };
    let substrate = crate::claim::substrate_facet_id(task)?;
    let position = BirthPosition {
        world: world.filter(|world| *world != crate::claim::base_world_id()),
        facet: EntityId::from_bytes(stamp.birth_facet)
            .ok()
            .filter(|facet| *facet != substrate),
    };
    if position == BirthPosition::default() {
        return Ok(());
    }
    stamp_task_birth(store, txn, fact, position)
}

/// Restamp a locally authenticated leader-chat TURN/MESSAGE at the ordinary
/// record-position scope door, after the typed write's full batch succeeds.
/// Opaque replicated rows cannot call this door and remain unstamped.
///
/// The birth position is immutable (see `stamp_put`): this door only moves
/// the record's own default birth stamp to the leader's project, or confirms
/// the leader stamp it already carries. Any other prior position is refused.
pub(crate) fn stamp_leader_project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    project: EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("leader chat scope header"))?;
    let kind = header.entity_type;
    if !matches!(
        kind,
        crate::registry::ENTITY_TYPE_TURN | crate::registry::ENTITY_TYPE_MESSAGE
    ) {
        return Err(Error::InvalidEntityType(kind));
    }
    let facet = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, facet);
    let mut scope = birth.clone();
    scope.audience = singleton(ScopeId(project));
    if let Some(prior) = SCOPE_RECORD.get(store, txn, &id)? {
        if prior.version != 2
            || prior.kind != kind
            || prior.birth_facet != *facet.as_bytes()
            || (prior.scope != birth && prior.scope != scope)
        {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        if prior.scope == scope {
            return Ok(());
        }
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

/// Births an imported claim into its topic's standing import audience (OF-492).
/// `scope` is the claim's opaque scope as promotion is about to sign it, and
/// `import_review` the history import its cited words came from. When the
/// owner answered the topic's ask, read in `txn`, the project selector moves to
/// the audience they chose: only me is the default (private) project and a
/// project is that project. The source's own sharing keeps the evidence's
/// stamp, since a history import carries no source audience. A claim from a
/// batch that raised the ask, a topic with no settled rule, or a chosen project
/// no longer visible keeps `scope` as it was. Never called on an existing row.
pub(crate) fn stamp_import_audience_birth(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: rmpv::Value,
    import_review: &str,
) -> Result<rmpv::Value> {
    let Some((topic, _)) = crate::ingest::import_audience_topic(Some(&scope))? else {
        return Ok(scope);
    };
    let Some((audience, raising)) = vault.import_audience_rule_in_txn(txn, &topic)? else {
        return Ok(scope);
    };
    if raising.iter().any(|review| review == import_review) {
        return Ok(scope);
    }
    let project = match audience {
        crate::ingest::ImportAudience::Source => return Ok(scope),
        crate::ingest::ImportAudience::OnlyMe => crate::claim::default_project_id(),
        crate::ingest::ImportAudience::Project { project } => {
            match vault.project_in_txn(txn, project)? {
                Some(record) if record.role != crate::workspace_roster::ProjectRole::Corpus => {
                    project
                }
                _ => return Ok(scope),
            }
        }
    };
    let mut entries = match scope {
        rmpv::Value::Map(entries) => entries,
        other => return Ok(other),
    };
    entries.retain(|(key, _)| key.as_str() != Some("scopeProjectId"));
    entries.push((
        rmpv::Value::from("scopeProjectId"),
        rmpv::Value::Binary(project.as_bytes().to_vec()),
    ));
    Ok(rmpv::Value::Map(entries))
}

/// Settles a BLOB_ARTIFACT's audience to `project` in the transaction that
/// binds it to that project: a signing document drafted for a project, and
/// the sealed copies and signature images it makes (OF-415). Like
/// [`stamp_leader_project`], it only moves the record's own default birth
/// stamp, or confirms the project stamp it already carries; any other prior
/// position is refused.
pub(crate) fn stamp_blob_project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    project: EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("blob scope header"))?;
    let kind = header.entity_type;
    if kind != crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
        return Err(Error::InvalidEntityType(kind));
    }
    let facet = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, facet);
    let mut scope = birth.clone();
    scope.audience = singleton(ScopeId(project));
    if let Some(prior) = SCOPE_RECORD.get(store, txn, &id)? {
        if prior.version != 2
            || prior.kind != kind
            || prior.birth_facet != *facet.as_bytes()
            || (prior.scope != birth && prior.scope != scope)
        {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        if prior.scope == scope {
            return Ok(());
        }
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

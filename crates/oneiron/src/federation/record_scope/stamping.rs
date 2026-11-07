//! The birth-position stamp doors: put, stage, settle and restamp a record's position.

use super::*;

pub(crate) fn stamp_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    put: RowPut,
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
    // A local re-put of a row stored with no position is no birth either, so
    // a local put of a replicated row keeps it unstamped (FIX 11925).
    if put != RowPut::Birth && kind != crate::registry::ENTITY_TYPE_CLAIM {
        // A peer cannot mint a birth position for an opaque row merely by
        // picking its ID and bytes. Only an existing stamped row inherits.
        // A replicated NOTIFICATION stays unstamped through its recipient's
        // local marks too (FIX 6552).
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

/// Whether `id` is stored here with a birth position.
pub(crate) fn has_stored_position(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<bool> {
    Ok(SCOPE_RECORD.get(store, txn, &id)?.is_some())
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

/// Takes the position [`stage_session_position`] staged beside `id`, a row
/// `view`'s room deletes (FIX 11932), as base's delete retires its stamp. A
/// position the room did not stage is not the room's to take; base and its
/// scope revision see nothing.
pub(crate) fn unstage_session_position(
    view: &crate::store::SessionStoreView<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    if view.vault_meta.stages_row(&SCOPE_RECORD.key_bytes(&id)) {
        SCOPE_RECORD.delete(view, txn, &id)?;
    }
    Ok(())
}

/// Whether the body `data` of `kind` for `id` keeps the birth position
/// `stamp` holds, with `id`'s birth facet read on `store` (Sol R22). A
/// CLAIM body names its whole record scope and its facet. A FACET or
/// RELATIONSHIP body names its sensitivity. Any other body names no
/// position: the stamp holds it. A promoted edit and a room read
/// ([`room_row_placed`]) share this one comparison. A body that moves the
/// position is refused as `InvalidClaimBody`.
pub(super) fn body_keeps_stamp(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    stamp: &Stamp,
) -> Result<()> {
    if !stamp_bound_on(store, txn, id, kind, stamp)? {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        let mut proposed = body.record_scope("read");
        proposed.verbs = ScopeAxis::Bottom;
        if proposed != stamp.scope || stamp.birth_facet != *body.scope_facet.as_bytes() {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
    }
    if matches!(
        kind,
        crate::registry::ENTITY_TYPE_FACET | crate::registry::ENTITY_TYPE_RELATIONSHIP
    ) {
        let proposed = match rmpv::decode::read_value(&mut &data[..]) {
            Ok(rmpv::Value::Map(entries)) => {
                let bands: Vec<_> = entries
                    .iter()
                    .filter(|(key, _)| key.as_str() == Some("sensitivity"))
                    .collect();
                match bands.as_slice() {
                    [] => Sensitivity::Sensitive,
                    [(_, value)] => match value.as_str() {
                        Some("public") => Sensitivity::Public,
                        Some("private") => Sensitivity::Private,
                        Some("sensitive") => Sensitivity::Sensitive,
                        Some("restricted") => Sensitivity::Restricted,
                        _ => return Err(Error::InvalidClaimBody("invalid facet sensitivity")),
                    },
                    _ => return Err(Error::InvalidClaimBody("duplicate facet sensitivity")),
                }
            }
            _ => Sensitivity::Sensitive,
        };
        if stamp.scope.sensitivity != SensitivityCeiling::AtMost(proposed) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
    }
    Ok(())
}

/// Whether the row `view`'s room serves for `id`, of `kind` with body
/// `data`, stands at a position a read limited to some worlds may place it
/// by (FIX 5161, Sol R22). Each row is placed alone: a row that fails
/// withholds itself, never the whole room, and never falls back to base's
/// body under the same id.
///
/// - A base row the room does not restage stands at base's position. A
///   NOTE or ASSET also keeps base's birth facet: a `FacetOf` the room adds
///   does not move it.
/// - A base row the room restages keeps base's own stamp, read on base,
///   and the room's body must keep it ([`body_keeps_stamp`]).
/// - A base NOTE, restaged or not, keeps base's worlds: an `InWorld` edge
///   the room adds or drops would widen or move where it reads, so the NOTE
///   stands nowhere for this read (review P1 #5926).
/// - A room birth keeps the position its write staged beside it
///   ([`stage_session_position`]). With no staged position it stands
///   nowhere: no position is inferred.
/// - A position the room stages for a base row stands in for base's, so
///   that row stands nowhere.
///
/// A row the room hides is no row of the union, so it never reaches here.
/// Storage errors stay errors.
pub(crate) fn room_row_placed(
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<bool> {
    let base = view.read().base();
    let room_stamp = view.vault_meta.stages_row(&SCOPE_RECORD.key_bytes(&id));
    // A row the room does not stage is base's own row.
    if !view.entities.stages_row(id.as_bytes()) {
        return Ok(!room_stamp
            && (!carries_birth_stamp(kind)
                || birth_facet(view, txn, id)? == birth_facet(base, txn, id)?)
            && keeps_base_worlds(view, txn, id, kind));
    }
    // A restaged base row keeps base's stamp, read on base; a room birth
    // keeps the stamp its write staged. Exactly one of them stands.
    let base_row = crate::ports::EntityStoreRead::port_entity_present(base, txn, &id)?;
    if base_row && !keeps_base_worlds(view, txn, id, kind) {
        return Ok(false);
    }
    let stamp = match (base_row, room_stamp) {
        (true, false) => SCOPE_RECORD.get(base, txn, &id)?,
        (false, true) => SCOPE_RECORD.get(view, txn, &id)?,
        _ => None,
    };
    let Some(stamp) = stamp else {
        return Ok(false);
    };
    match body_keeps_stamp(view, txn, id, kind, data, &stamp) {
        Ok(()) => Ok(true),
        Err(Error::InvalidClaimBody(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether the base row `id` of `kind` sits in the same worlds in `view`'s
/// room as on base: always for a row that is not a NOTE, whose world is
/// stamped; for a NOTE, whose world its live `InWorld` edges name, only when
/// the room's edges name the same worlds (review P1 #5926).
fn keeps_base_worlds(
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> bool {
    kind != crate::registry::ENTITY_TYPE_NOTE
        || super::note_world::note_worlds_in(view, txn, id)
            == super::note_world::note_worlds_in(view.read().base(), txn, id)
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
/// default stamp `stamp_put` just wrote for a kind with a declared identity
/// key (a PERSON, ORG or PLACE today; FIX 11382) may be settled; its
/// structural anchor and every other axis stay, a settled birth is never
/// moved again, and a later content put keeps the settled facet
/// (`settled_at_birth`).
pub(crate) fn settle_source_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    facet: EntityId,
) -> Result<()> {
    let named = !crate::store::identity_hints::identity_fields_for_kind(kind).is_empty();
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
    // Blind-review P1 (FIX 7774): a new leader-chat TURN may be born under
    // the mask/default facet, so the birth facet here is the row's own, not
    // its substrate; this door settles only the audience. A row already
    // settled onto another project is refused; the unsettled and idempotent
    // same-project cases proceed.
    let prior = SCOPE_RECORD.get(store, txn, &id)?;
    let (facet, position) = match &prior {
        Some(stamp) if stamp.version == 2 && stamp.kind == kind => (
            EntityId::from_bytes(stamp.birth_facet)
                .map_err(|_| Error::CorruptedIndex("leader chat birth facet"))?,
            stamp.scope.clone(),
        ),
        Some(_) => {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        None => {
            let facet = crate::claim::substrate_facet_id(id)?;
            (facet, default_stamp(kind, facet))
        }
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

/// Settles only the fresh artifact named by an actual queue-check completion.
/// Its input placement and taint were captured before the command ran. The
/// structural birth anchor stays the artifact's own; its effective placement
/// stays the input's, with the output kind and no capability verbs.
pub(crate) fn stamp_queue_check_exhaust_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    token: &crate::merge_queue::QueueCheckFieldToken<'_>,
) -> Result<()> {
    let id = token.artifact_id();
    let kind = crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
    let facet = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, facet);
    let prior = SCOPE_RECORD.get(store, txn, &id)?;
    let scope = token.input_scope().map(|source| {
        let mut scope = source.clone();
        scope.bands = singleton(kind);
        scope.verbs = ScopeAxis::Bottom;
        if let SensitivityCeiling::AtMost(band) = scope.sensitivity
            && band < Sensitivity::Sensitive
        {
            scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Sensitive);
        }
        scope
    });
    let Some(prior) = prior else {
        return if scope.is_none() {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody("unstamped queue-check exhaust"))
        };
    };
    if prior.version != 2
        || prior.kind != kind
        || prior.birth_facet != *facet.as_bytes()
        || (prior.scope != birth && scope.as_ref() != Some(&prior.scope))
    {
        return Err(Error::InvalidClaimBody(
            "queue-check exhaust restamp refused",
        ));
    }
    let Some(scope) = scope else {
        SCOPE_RECORD.delete(store, txn, &id)?;
        return bump_scope_revision(store, txn);
    };
    if prior.scope == scope {
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
    )
}

//! A revision document's actors (FIX 6072, part 3 of 3): each raw entity row
//! a revision recorded, its NOTE core's author split out by the core's own
//! projection (`crate::note::checkpoint::split_core_row`) and put back by
//! its join, through the shared Loro projection
//! (`crate::store::checkpoint_payload::loro`). The allowlist (Engine R4) is
//! the fixed four-key NOTE core and the strict two-field MODEL body, which
//! names no one. Any other kind, an unregistered one, a NOTE pointer or a
//! spelling the core does not give back, two kinds in one history, a commit
//! message and an operation outside the document's record and text fields
//! keep the whole document under the vault-wide seal, its reason named.
//!
//! No public revision ref changes (lead pick (b)). A ref hashed over its
//! retained frontier stays, as the split keeps every operation. A ref hashed
//! over the raw row its frontier selects stays only while no actor's erase
//! changes that row. A row an erase changes keeps its frontier ref only
//! while its short-reference hash byte stays too, as a saved `short:hh@rev`
//! checks that byte. Any other document stays under the vault-wide seal. The
//! capture reads every binding of the entity from its own view: its state,
//! its retained frontiers, their reverse rows and the revisions its staged
//! inputs wait on. A restore checks those bindings once every row of the
//! getter is in ([`finish_restore_in_txn`]), and rewrites none.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use loro::{
    ContainerID, ContainerType, EncodedBlobMode, Frontiers, JsonMapOp, JsonOp, JsonOpContent,
    JsonTextOp, LoroDoc, LoroValue, VersionVector,
};

use super::super::super::{RevisionRef, pending_index, phonetic};
use super::super::{DOC, FRONTIER, IDENTITY, RevisionState, STATE, doc_raw, reference, text_fields};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, short_id_content_hash};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::note::checkpoint::{join_core_row, split_core_row};
use crate::note::decode_note_body_in_txn;
use crate::provenance::decode_model_entity_body;
use crate::registry::{ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTE, entity_type_registry_entry};
use crate::side_table::{SideCodec, SideKey, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::loro::{
    self as shared, LoroActorCodec, OpenedRow, SHALLOW, Split, SplitRow, SplitValue,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, RoundTripPolicy, RowLocator, RowPart,
    TypedRow, Unresolved,
};

/// The round trip a revision document takes (Engine R1): the same history,
/// in a container Loro may encode anew. Every ref the ledger keeps hashes a
/// frontier or a raw row, never these bytes, so a restore has no digest of
/// them to derive again.
const REVISION_ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// The map whose `raw` key holds each revision's raw entity row.
const RECORD: &str = "record";
const RAW: &str = "raw";
/// The map naming each text field; each field's text is the root text
/// container `field:<name>`.
const TEXT_FIELDS: &str = "text_fields";
const FIELD: &str = "field:";

/// An operation outside the revision document's schema.
const OUTSIDE_SCHEMA: &str = "a revision document operation outside its schema";
/// A commit message: the ledger writes none.
const COMMIT_MESSAGE: &str = "a revision document commit message";
/// A raw row whose entity header does not read.
const RAW_UNREAD: &str = "a revision raw row whose header does not read";
/// A raw row of a kind no revision codec reads (Engine R4).
const UNSUPPORTED_KIND: &str = "a revision of a kind no revision codec reads";
/// A MODEL row that is not the strict two-field body.
const MODEL_UNREAD: &str = "a MODEL revision that is not the strict two-field body";
/// A history whose raw rows are of two kinds.
const MIXED_KINDS: &str = "a revision document whose rows are of two kinds";
/// A binding whose origin does not prove: no state naming the document, a
/// frontier that does not resolve or whose ref hashes neither it nor its
/// row, or a ref no retained frontier binds.
const BINDING_UNPROVED: &str = "a revision binding whose origin does not prove";
/// A raw-derived ref an actor's erase would change (lead pick (b)).
const RAW_REF_CHANGES: &str = "a raw-derived revision ref an actor's erase would change";
/// A revision whose short-reference hash byte an actor's erase would change.
const SHORT_REF_CHANGES: &str = "a revision short-reference hash an actor's erase would change";

/// A projection's outcome: the value, or why its row stays under the
/// vault-wide seal.
type Admission<T> = std::result::Result<T, Unresolved>;

/// A revision document's actor carriers: the author of each NOTE core its
/// record wrote.
struct RevisionActors<'a> {
    /// The document row whose actor parts a fill reads.
    at: &'a RowLocator,
}

impl LoroActorCodec for RevisionActors<'_> {
    const FAMILY: &'static str = "entity_revision";

    fn split_message(&self, _: &str) -> Split<String> {
        Err(COMMIT_MESSAGE)
    }

    fn fill_message(&self, _: &str, _: &str, _: EntityId) -> Result<String> {
        Err(rows::bad_part())
    }

    fn split_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        value: &LoroValue,
    ) -> Split<LoroValue> {
        match value {
            LoroValue::Bool(true) if is_root(container, TEXT_FIELDS, ContainerType::Map) => {
                Ok(SplitValue::kept(value.clone()))
            }
            LoroValue::Binary(raw) if is_root(container, RECORD, ContainerType::Map) => {
                if key != RAW {
                    return Err(OUTSIDE_SCHEMA);
                }
                let split = split_raw(raw)?;
                Ok(SplitValue {
                    no_one: LoroValue::from(split.no_one),
                    actors: split.actors,
                })
            }
            _ => Err(OUTSIDE_SCHEMA),
        }
    }

    fn fill_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        no_one: &LoroValue,
        path: &str,
        actor: EntityId,
    ) -> Result<LoroValue> {
        let LoroValue::Binary(raw) = no_one else {
            return Err(rows::bad_part());
        };
        if !is_root(container, RECORD, ContainerType::Map) || key != RAW {
            return Err(rows::bad_part());
        }
        // The opened author as the one part the NOTE core's own join reads.
        let part = ActorPart {
            actor_entity: actor,
            content_locator: self.at.clone(),
            field: path.to_owned(),
            bytes: actor.as_bytes().to_vec(),
        };
        Ok(LoroValue::from(join_core_row(raw, &[&part])?))
    }

    fn keep_op(&self, op: &JsonOp) -> std::result::Result<(), &'static str> {
        match &op.content {
            JsonOpContent::Text(JsonTextOp::Insert { .. } | JsonTextOp::Delete { .. })
                if text_field(&op.container).is_some() =>
            {
                Ok(())
            }
            JsonOpContent::Map(JsonMapOp::Delete { .. })
                if is_root(&op.container, TEXT_FIELDS, ContainerType::Map) =>
            {
                Ok(())
            }
            _ => Err(OUTSIDE_SCHEMA),
        }
    }
}

/// Splits one raw row a revision recorded: a NOTE core's author out
/// (`split_core_row`); a strict MODEL body, and an empty shell of either
/// kind, as they stand, as they name no one. Any other kind refuses.
fn split_raw(raw: &[u8]) -> Split<Vec<u8>> {
    let header = EntityMetadataHeader::parse(raw).ok_or(RAW_UNREAD)?;
    let shell = raw.len() == ENTITY_METADATA_HEADER_LEN;
    match header.entity_type {
        ENTITY_TYPE_NOTE if !shell => split_core_row(raw),
        ENTITY_TYPE_MODEL if !shell => {
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            decode_model_entity_body(body).map_err(|_| MODEL_UNREAD)?;
            Ok(SplitValue::kept(raw.to_vec()))
        }
        ENTITY_TYPE_NOTE | ENTITY_TYPE_MODEL => Ok(SplitValue::kept(raw.to_vec())),
        _ => Err(UNSUPPORTED_KIND),
    }
}

/// Whether `container` is the root container `name` of kind `kind`.
fn is_root(container: &ContainerID, name: &str, kind: ContainerType) -> bool {
    match container {
        ContainerID::Root {
            name: root,
            container_type,
        } => root.as_str() == name && *container_type == kind,
        ContainerID::Normal { .. } => false,
    }
}

/// The text field a root text container `field:<name>` holds.
fn text_field(container: &ContainerID) -> Option<&str> {
    match container {
        ContainerID::Root {
            name,
            container_type: ContainerType::Text,
        } => name.as_str().strip_prefix(FIELD),
        _ => None,
    }
}

/// The short-reference hash byte of a raw row's body, as a pin to its
/// revision carries it (`short:hh@rev`).
fn short_hash(raw: &[u8]) -> u8 {
    short_id_content_hash(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default())
}

/// `bytes` as the document it holds: a full snapshot that imports with
/// nothing pending. A shallow one holds no history before its cut, so no
/// projection shows its actors (Engine R3).
fn full_doc(bytes: &[u8]) -> Admission<LoroDoc> {
    let meta = LoroDoc::decode_import_blob_meta(bytes, true);
    match meta.map_err(|_| Unresolved::Undecodable)?.mode {
        EncodedBlobMode::Snapshot => {}
        EncodedBlobMode::ShallowSnapshot => return Err(Unresolved::ActorSplit(SHALLOW)),
        _ => return Err(Unresolved::Undecodable),
    }
    let doc = LoroDoc::new();
    let status = doc.import(bytes).map_err(|_| Unresolved::Undecodable)?;
    if status.pending.is_some() {
        return Err(Unresolved::Undecodable);
    }
    if doc.is_shallow() {
        return Err(Unresolved::ActorSplit(SHALLOW));
    }
    Ok(doc)
}

/// What a revision document's history records: its one entity kind, and
/// each raw row it wrote, in history order.
struct History {
    kind: u8,
    raws: Vec<Vec<u8>>,
}

/// A history read so far.
#[derive(Default)]
struct Reading {
    kind: Option<u8>,
    raws: Vec<Vec<u8>>,
    /// The text fields the recorded rows' bodies hold.
    fields: BTreeSet<String>,
    /// The text fields the document's map and containers name.
    named: BTreeSet<String>,
}

impl Reading {
    /// One operation: a raw row into the record, a text field named or
    /// unnamed, or its text edited. Any other refuses.
    fn op(&mut self, op: &JsonOp) -> Admission<()> {
        let schema = Unresolved::ActorSplit(OUTSIDE_SCHEMA);
        match &op.content {
            JsonOpContent::Map(JsonMapOp::Insert { key, value }) => {
                if is_root(&op.container, RECORD, ContainerType::Map) && key.as_str() == RAW {
                    return self.raw(value);
                }
                if !is_root(&op.container, TEXT_FIELDS, ContainerType::Map)
                    || *value != LoroValue::Bool(true)
                {
                    return Err(schema);
                }
                self.named.insert(key.clone());
                Ok(())
            }
            JsonOpContent::Map(JsonMapOp::Delete { .. })
                if is_root(&op.container, TEXT_FIELDS, ContainerType::Map) =>
            {
                Ok(())
            }
            JsonOpContent::Text(JsonTextOp::Insert { .. } | JsonTextOp::Delete { .. }) => {
                let name = text_field(&op.container).ok_or(schema)?;
                self.named.insert(name.to_owned());
                Ok(())
            }
            _ => Err(schema),
        }
    }

    /// One raw row a revision recorded: its header reads, its kind is
    /// registered and the allowlist reads it, and it is the history's one
    /// kind.
    fn raw(&mut self, value: &LoroValue) -> Admission<()> {
        let LoroValue::Binary(raw) = value else {
            return Err(Unresolved::ActorSplit(OUTSIDE_SCHEMA));
        };
        let header = EntityMetadataHeader::parse(raw).ok_or(Unresolved::Undecodable)?;
        let kind = header.entity_type;
        if entity_type_registry_entry(kind).is_none() {
            return Err(Unresolved::UnknownKind);
        }
        split_raw(raw).map_err(Unresolved::ActorSplit)?;
        if *self.kind.get_or_insert(kind) != kind {
            return Err(Unresolved::ActorSplit(MIXED_KINDS));
        }
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let fields = text_fields(body).into_iter().map(|(name, _)| name);
        self.fields.extend(fields);
        self.raws.push(raw.to_vec());
        Ok(())
    }

    /// The history read: one kind, and no text field its rows do not hold.
    fn finish(self) -> Admission<History> {
        let kind = self.kind.ok_or(Unresolved::Undecodable)?;
        if !self.named.is_subset(&self.fields) {
            return Err(Unresolved::ActorSplit(OUTSIDE_SCHEMA));
        }
        Ok(History {
            kind,
            raws: self.raws,
        })
    }
}

/// Reads every operation of `doc`'s history, not only the values that stand
/// now. A commit message refuses: the ledger commits with none.
fn read_history(doc: &LoroDoc) -> Admission<History> {
    let start = VersionVector::default();
    let all = doc.export_json_updates_without_peer_compression(&start, &doc.oplog_vv());
    let mut reading = Reading::default();
    for change in &all.changes {
        if change.msg.is_some() {
            return Err(Unresolved::ActorSplit(COMMIT_MESSAGE));
        }
        for op in &change.ops {
            reading.op(op)?;
        }
    }
    reading.finish()
}

/// What a retained ref hashes (`fork_revision`).
enum Origin {
    /// Its encoded frontier.
    Frontier,
    /// The raw row its frontier selects.
    Raw,
}

/// How `revision` binds its retained frontier `encoded` in `doc`, as
/// `fork_revision` reads it, with the raw row that frontier selects: hashed
/// over the frontier, or over that row. `None` when it binds neither.
fn binding_origin(
    id: &EntityId,
    doc: &LoroDoc,
    revision: RevisionRef,
    encoded: &[u8],
) -> Option<(Origin, Vec<u8>)> {
    let frontier = Frontiers::decode(encoded).ok()?;
    let raw = doc_raw(&doc.fork_at(&frontier).ok()?).ok()?;
    if reference(id, encoded) == revision {
        Some((Origin::Frontier, raw))
    } else if reference(id, &raw) == revision {
        Some((Origin::Raw, raw))
    } else {
        None
    }
}

/// Refuses a retained binding an actor's erase could change (lead pick
/// (b)): a raw ref over a row the split changes, or a frontier ref whose
/// row's short-reference hash byte the split changes. A NOTE core has one
/// hole, so the row as stored and its no-one form are its only openings,
/// and both are compared.
fn keeps_binding(
    id: &EntityId,
    doc: &LoroDoc,
    revision: RevisionRef,
    encoded: &[u8],
) -> Admission<()> {
    let unproved = Unresolved::ActorSplit(BINDING_UNPROVED);
    let found = binding_origin(id, doc, revision, encoded);
    let (origin, raw) = found.ok_or(unproved)?;
    let split = split_raw(&raw).map_err(Unresolved::ActorSplit)?;
    if split.actors.is_empty() {
        return Ok(());
    }
    match origin {
        Origin::Raw => Err(Unresolved::ActorSplit(RAW_REF_CHANGES)),
        Origin::Frontier if short_hash(&raw) == short_hash(&split.no_one) => Ok(()),
        Origin::Frontier => Err(Unresolved::ActorSplit(SHORT_REF_CHANGES)),
    }
}

/// The bindings the capture view holds for each entity whose revision
/// document it captures: what that document's projection must leave as it
/// is.
pub(super) struct Bindings {
    entities: BTreeMap<EntityId, Bound>,
}

/// One entity's bindings in the capture view.
#[derive(Default)]
struct Bound {
    /// Its live and indexed refs, when its state names its document.
    state: Option<[RevisionRef; 2]>,
    /// Each retained ref, with its encoded frontier.
    frontiers: Vec<(RevisionRef, Vec<u8>)>,
    /// Each ref a reverse row names it under.
    identities: Vec<RevisionRef>,
}

impl Bindings {
    /// The bindings of each entity `docs` holds a revision document of.
    pub(super) fn index(
        docs: &[TypedRow<EntityId, Vec<u8>>],
        states: &[TypedRow<EntityId, RevisionState>],
        frontiers: &[TypedRow<(EntityId, [u8; 16]), Vec<u8>>],
        identities: &[TypedRow<[u8; 16], EntityId>],
    ) -> Self {
        let mut entities = BTreeMap::new();
        for row in docs {
            entities.insert(row.key, Bound::default());
        }
        for row in states {
            if let Some(bound) = entities.get_mut(&row.key) {
                let state = &row.value;
                bound.state = state.has_doc.then_some([state.live, state.indexed]);
            }
        }
        for row in frontiers {
            if let Some(bound) = entities.get_mut(&row.key.0) {
                let revision = RevisionRef(row.key.1);
                bound.frontiers.push((revision, row.bytes.clone()));
            }
        }
        for row in identities {
            if let Some(bound) = entities.get_mut(&row.value) {
                bound.identities.push(RevisionRef(row.key));
            }
        }
        Self { entities }
    }

    /// Refuses `id`'s document `doc` unless each binding the view holds for
    /// it stays as it is under every opening of the document's actors, and
    /// each ref its state, its reverse rows and its `staged` inputs name is
    /// one of its retained frontiers.
    fn keeps(&self, id: &EntityId, doc: &LoroDoc, staged: &[RevisionRef]) -> Admission<()> {
        let unproved = Unresolved::ActorSplit(BINDING_UNPROVED);
        let bound = self.entities.get(id).ok_or(unproved)?;
        let state = bound.state.ok_or(unproved)?;
        let mut retained = BTreeSet::new();
        for (revision, encoded) in &bound.frontiers {
            keeps_binding(id, doc, *revision, encoded)?;
            retained.insert(*revision);
        }
        let mut named = state.iter().chain(&bound.identities).chain(staged);
        if named.all(|revision| retained.contains(revision)) {
            Ok(())
        } else {
            Err(unproved)
        }
    }
}

/// One revision document of the capture view, under its entity: split when
/// its history is one the allowlist reads and no binding the view holds for
/// it would change, exact when it names no one, and otherwise under the
/// vault-wide seal, its reason named.
pub(super) fn capture(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    out: &mut Captured,
    bindings: &Bindings,
    row: TypedRow<EntityId, Vec<u8>>,
) -> Result<()> {
    let owner = OwnerRef::entity(&row.key);
    match project(dbs, txn, bindings, &row)? {
        Ok(split) if split.atoms.is_empty() => out.exact(owner, row.at, row.bytes),
        Ok(split) => shared::place(out, owner, row.at, split),
        Err(reason) => out.unclassified(row.at, Some(owner), reason),
    }
    Ok(())
}

/// `row`'s split, or why it stays under the vault-wide seal.
fn project(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    bindings: &Bindings,
    row: &TypedRow<EntityId, Vec<u8>>,
) -> Result<Admission<SplitRow>> {
    let (doc, history, split) = match shape(&row.at, &row.bytes) {
        Ok(shape) => shape,
        Err(reason) => return Ok(Err(reason)),
    };
    if let Err(reason) = note_kinds_held(dbs, txn, &history)? {
        return Ok(Err(reason));
    }
    let staged = staged_revisions(dbs, txn, &row.key)?;
    Ok(bindings.keeps(&row.key, &doc, &staged).map(|()| split))
}

/// A revision document's split, with the document and its history: a full
/// history the allowlist reads, whose all-open join gives it back.
fn shape(at: &RowLocator, bytes: &[u8]) -> Admission<(LoroDoc, History, SplitRow)> {
    let doc = full_doc(bytes)?;
    let history = read_history(&doc)?;
    let codec = RevisionActors { at };
    let mut split = shared::split_loro(&[bytes], &codec, REVISION_ROUND_TRIP)?;
    let row = split.pop().ok_or(Unresolved::Undecodable)?;
    Ok((doc, history, row))
}

/// Refuses a NOTE history one of whose cores names a kind the capture
/// view's registry does not hold: the core's split reads only a kind's wire
/// spelling, and a PACK kind is the registry's.
fn note_kinds_held(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    history: &History,
) -> Result<Admission<()>> {
    if history.kind != ENTITY_TYPE_NOTE {
        return Ok(Ok(()));
    }
    for raw in &history.raws {
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if body.is_empty() {
            continue;
        }
        match decode_note_body_in_txn(dbs, txn, body) {
            Ok(_) => {}
            Err(Error::Record(_)) => return Ok(Err(Unresolved::UnknownKind)),
            Err(Error::CorruptedIndex(_)) => return Ok(Err(Unresolved::Undecodable)),
            Err(error) => return Err(error),
        }
    }
    Ok(Ok(()))
}

/// The revisions `id`'s staged index inputs and phonetic codes wait on.
fn staged_revisions(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<RevisionRef>> {
    let inputs = pending_index::checkpoint::staged_revision(dbs, txn, id)?;
    let codes = phonetic::checkpoint::staged_revision(dbs, txn, id)?;
    Ok(inputs.into_iter().chain(codes).collect())
}

/// Refuses `value` at `at` unless it is a revision document row: its key an
/// entity, its bytes a full history the allowlist reads.
pub(super) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(DOC, at, value)?;
    match full_doc(value).and_then(|doc| read_history(&doc)) {
        Ok(_) => Ok(()),
        Err(_) => Err(rows::bad_part()),
    }
}

/// A revision document rebuilt from its content and the actors that opened:
/// each author that did not open stays erased.
pub(super) fn join(
    _: &RoTxn<'_>,
    at: &RowLocator,
    content: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if !at.in_table(DOC.decl()) {
        return Err(rows::bad_part());
    }
    let atoms = shared::opened_atoms(parts)?;
    let codec = RevisionActors { at };
    let mut joined = shared::join_loro(&[OpenedRow { content, atoms }], &codec)?.rows;
    let bytes = joined.pop().ok_or_else(rows::bad_part)?;
    Ok(Some(bytes))
}

/// What a restore stages for one revision document, read before any of its
/// rows is written: its entity, and the ref of each reverse row.
pub(super) struct Staged {
    entity: EntityId,
    reverse: Vec<RevisionRef>,
}

/// Reads the bindings `opened` stages before any of its rows is written:
/// `None` when it holds no revision document. Refuses a reverse row naming
/// another entity or staged twice, and a ref another entity's reverse row
/// already holds.
pub(super) fn preflight(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    opened: &OpenedOwnerRows,
) -> Result<Option<Staged>> {
    let Some(entity) = staged_document(opened)? else {
        return Ok(None);
    };
    let mut reverse = BTreeSet::new();
    for part in &opened.rows {
        let RowPart::Exact { at, value } = part else {
            continue;
        };
        if !at.in_table(IDENTITY.decl()) {
            continue;
        }
        let revision = table_key(IDENTITY, at)?;
        let held = IDENTITY.get(dbs, txn, &revision)?;
        let named = IDENTITY.decode_value(value)?;
        if named != entity
            || held.is_some_and(|other| other != entity)
            || !reverse.insert(RevisionRef(revision))
        {
            return Err(rows::bad_part());
        }
    }
    let reverse = reverse.into_iter().collect();
    Ok(Some(Staged { entity, reverse }))
}

/// The entity whose revision document `opened` holds, when it holds one: its
/// owner's own, and only one.
fn staged_document(opened: &OpenedOwnerRows) -> Result<Option<EntityId>> {
    let mut entity = None;
    for part in &opened.rows {
        let at = part.at();
        if at.in_table(DOC.decl()) && entity.replace(table_key(DOC, at)?).is_some() {
            return Err(rows::bad_part());
        }
    }
    let owner = OwnerRef {
        subtype: opened.subtype,
        owner32: opened.owner32,
    };
    match entity {
        Some(id) if OwnerRef::entity(&id) != owner => Err(rows::bad_part()),
        found => Ok(found),
    }
}

/// The key `at` names in `table`.
fn table_key<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    at: &RowLocator,
) -> Result<K> {
    let key = at.key.strip_prefix(table.decl().prefix);
    key.and_then(K::decode_key).ok_or_else(rows::bad_part)
}

/// Checks, in the restore's own transaction, the bindings of the revision
/// document `staged` names, once every row of this getter is in and before
/// the restore returns: each retained ref still hashes its frontier, or the
/// raw row that frontier selects in the restored document, and has its
/// reverse row; the state, the reverse rows staged and the revisions the
/// staged inputs wait on name only retained refs. Nothing is derived anew
/// or rewritten (lead pick (b)); a binding that does not hold refuses the
/// restore, and its transaction goes with it.
pub(super) fn finish_restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    staged: &Staged,
) -> Result<()> {
    let id = &staged.entity;
    let bytes = DOC.get(dbs, txn, id)?.ok_or_else(rows::bad_part)?;
    let doc = full_doc(&bytes).map_err(|_| rows::bad_part())?;
    let state = STATE.get(dbs, txn, id)?.filter(|state| state.has_doc);
    let state = state.ok_or_else(rows::bad_part)?;
    let mut retained = BTreeSet::new();
    for ((_, revision), encoded) in FRONTIER.scan_from(dbs, txn, id.as_bytes())? {
        let reverse = IDENTITY.get(dbs, txn, &revision)?;
        let revision = RevisionRef(revision);
        let bound = binding_origin(id, &doc, revision, &encoded).is_some();
        if !bound || reverse != Some(*id) {
            return Err(rows::bad_part());
        }
        retained.insert(revision);
    }
    let inputs = staged_revisions(dbs, txn, id)?;
    let refs = [state.live, state.indexed].into_iter();
    let mut named = refs.chain(staged.reverse.iter().copied()).chain(inputs);
    if named.all(|revision| retained.contains(&revision)) {
        Ok(())
    } else {
        Err(rows::bad_part())
    }
}

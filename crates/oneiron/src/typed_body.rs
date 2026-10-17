//! Typed bodies on the entity-document plane: one Loro document per entity
//! whose shape its owning module defines (an office body, a deck).
//!
//! Unlike a text document, a typed body leaves the entity's record alone: the
//! record keeps no text field and no document pointer, so the entity's own
//! record writes go on as before. A body names its shape by a schema tag, and
//! every read and write names the tag it expects.
//!
//! Every commit runs under a fresh peer bound to its actor and carries its
//! MadeBy in the commit message, so the operation log is the receipt ledger
//! and a merged fork's operations bring their receipts with them. A fork is
//! written only by its opener and lands only through a merge by someone else
//! against the head that someone reviewed. Erasing the entity erases its body
//! and every fork of it ([`erase_in_txn`]).

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::{MadeBy, MadeByClass};
use crate::provenance::text_commit::{RowProvenance, TextCommitReceipt};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, Frontiers, LoroDoc};
use serde::{Deserialize, Serialize};
use std::ops::ControlFlow;

const HEADS: SideTable<EntityId, TypedBodyHead, Named> =
    SideTable::new(&side_table::TYPED_BODY_HEAD);
const DOCS: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::TYPED_BODY_DOC);
const FORKS: SideTable<(EntityId, EntityId), TypedBodyFork, Named> =
    SideTable::new(&side_table::TYPED_BODY_FORK);
const FORK_DOCS: SideTable<(EntityId, EntityId), Vec<u8>, Raw> =
    SideTable::new(&side_table::TYPED_BODY_FORK_DOC);

const STAMP: &str = "oneiron.typed_body.v1";
const RECEIPT_PREFIX: &str = "|made_by=";

/// One entity's typed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBodyHead {
    pub entity: EntityId,
    /// The owning module's shape tag, e.g. `office.docx.v1`.
    pub schema: String,
    /// The body as born: an owner's base for what changed since.
    pub birth: Vec<u8>,
    pub frontier: Vec<u8>,
    /// Commits on the body, a merged fork's included.
    pub commits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TypedForkState {
    Open,
    Merged {
        by: EntityId,
        at: u64,
        head: Vec<u8>,
    },
    Discarded {
        by: EntityId,
        at: u64,
    },
}

/// Work on a body away from its head: opened at a head frontier, written only
/// by its opener, landed by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBodyFork {
    pub entity: EntityId,
    pub fork: EntityId,
    pub opener: EntityId,
    pub base: Vec<u8>,
    pub commits: u64,
    pub opened_at: u64,
    pub state: TypedForkState,
}

/// Who writes one commit, and the body shape the writer expects.
#[derive(Debug, Clone, Copy)]
pub struct TypedBodyWriter<'a> {
    /// The body's shape tag ([`TypedBodyHead::schema`]).
    pub schema: &'a str,
    pub actor: WriteActor,
    /// The commit's receipt. Its process names `actor`; its `at` is the commit time.
    pub made_by: &'a MadeBy,
}

/// One commit: the frontier it left and its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedBodyCommit {
    pub frontier: Vec<u8>,
    pub receipt: TextCommitReceipt,
}

/// Births `entity`'s typed body: `init` writes its first state, committed as
/// the writer's. The record is not touched. One entity has one body.
pub(crate) fn birth_typed_body_in_txn<T>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    writer: TypedBodyWriter<'_>,
    init: impl FnOnce(&LoroDoc) -> Result<T>,
) -> Result<(T, TypedBodyCommit)> {
    let schema = writer.schema;
    if schema.is_empty() || schema.len() > 64 || !schema.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid(
            "a typed body schema is 1 to 64 visible ASCII bytes",
        ));
    }
    require_live(&vault.store, txn, entity)?;
    if HEADS.contains(&vault.store, txn, entity)? {
        return Err(invalid("the entity already has a typed body"));
    }
    let doc = LoroDoc::new();
    doc.set_record_timestamp(true);
    let (value, receipt) = commit_as(vault, txn, &doc, *entity, writer, "birth", init)?;
    let frontier = doc.oplog_frontiers().encode();
    DOCS.put(&vault.store, txn, entity, &snapshot(&doc)?)?;
    let head = TypedBodyHead {
        entity: *entity,
        schema: schema.to_owned(),
        birth: frontier.clone(),
        frontier: frontier.clone(),
        commits: 1,
    };
    HEADS.put(&vault.store, txn, entity, &head)?;
    Ok((value, TypedBodyCommit { frontier, receipt }))
}

/// The writer's operations on the live body. Operations read against an older
/// `base` frontier apply there and merge into the head, as a CRDT peer's
/// would. The caller may read the body back in the same transaction and fail
/// it to refuse a shape it does not accept.
pub(crate) fn edit_typed_body_in_txn<T>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    base: Option<&[u8]>,
    writer: TypedBodyWriter<'_>,
    edit: impl FnOnce(&LoroDoc) -> Result<T>,
) -> Result<(T, TypedBodyCommit)> {
    let mut head = head_in_txn(&vault.store, txn, entity, writer.schema)?;
    let live = load(DOCS.get(&vault.store, txn, entity)?, Some(&head.frontier))?;
    let (value, receipt) = match base {
        None => commit_as(vault, txn, &live, *entity, writer, "edit", edit)?,
        Some(base) => {
            let target = fork_at(&live, base)?;
            let before = target.oplog_vv();
            let out = commit_as(vault, txn, &target, *entity, writer, "edit", edit)?;
            let updates = target
                .export(ExportMode::updates(&before))
                .map_err(|_| invalid("typed body update export"))?;
            import(&live, &updates)?;
            out
        }
    };
    head.frontier = live.oplog_frontiers().encode();
    head.commits += 1;
    DOCS.put(&vault.store, txn, entity, &snapshot(&live)?)?;
    HEADS.put(&vault.store, txn, entity, &head)?;
    Ok((
        value,
        TypedBodyCommit {
            frontier: head.frontier,
            receipt,
        },
    ))
}

/// `entity`'s body under `schema`: its head, or a detached copy at an earlier
/// frontier `at` of its history. `None` when the entity has no typed body.
pub(crate) fn typed_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    schema: &str,
    at: Option<&[u8]>,
) -> Result<Option<(TypedBodyHead, LoroDoc)>> {
    require_live(store, txn, entity)?;
    let Some(head) = HEADS.get(store, txn, entity)? else {
        return Ok(None);
    };
    if head.schema != schema {
        return Err(invalid("the typed body has another schema"));
    }
    let doc = load(DOCS.get(store, txn, entity)?, Some(&head.frontier))?;
    let doc = match at {
        None => doc,
        Some(frontier) => fork_at(&doc, frontier)?,
    };
    Ok(Some((head, doc)))
}

/// Opens a fork of the live body at its head for `actor`'s work.
pub(crate) fn open_typed_body_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    schema: &str,
    actor: WriteActor,
) -> Result<TypedBodyFork> {
    validate_actor(vault, txn, actor)?;
    let head = head_in_txn(&vault.store, txn, entity, schema)?;
    let live = load(DOCS.get(&vault.store, txn, entity)?, Some(&head.frontier))?;
    let fork = TypedBodyFork {
        entity: *entity,
        fork: vault.new_entity_id()?,
        opener: actor.entity_ref(),
        base: head.frontier,
        commits: 0,
        opened_at: vault.now_recorded_at(),
        state: TypedForkState::Open,
    };
    let key = (*entity, fork.fork);
    FORK_DOCS.put(&vault.store, txn, &key, &snapshot(&live)?)?;
    FORKS.put(&vault.store, txn, &key, &fork)?;
    Ok(fork)
}

/// The opener's operations on its open fork.
pub(crate) fn edit_typed_body_fork_in_txn<T>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    writer: TypedBodyWriter<'_>,
    edit: impl FnOnce(&LoroDoc) -> Result<T>,
) -> Result<(T, TypedBodyCommit)> {
    head_in_txn(&vault.store, txn, entity, writer.schema)?;
    let key = (*entity, *fork);
    let mut record = FORKS
        .get(&vault.store, txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open || record.opener != writer.actor.entity_ref() {
        return Err(invalid("only the opener writes to its open fork"));
    }
    let doc = load(FORK_DOCS.get(&vault.store, txn, &key)?, None)?;
    let (value, receipt) = commit_as(vault, txn, &doc, *entity, writer, "fork", edit)?;
    FORK_DOCS.put(&vault.store, txn, &key, &snapshot(&doc)?)?;
    record.commits += 1;
    FORKS.put(&vault.store, txn, &key, &record)?;
    Ok((
        value,
        TypedBodyCommit {
            frontier: doc.oplog_frontiers().encode(),
            receipt,
        },
    ))
}

/// A fork's record, and its body while it is open (a reviewer diffs it
/// against the head). `None` when `entity` has no such fork.
pub(crate) fn typed_body_fork_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
) -> Result<Option<(TypedBodyFork, Option<LoroDoc>)>> {
    require_live(store, txn, entity)?;
    let key = (*entity, *fork);
    let Some(record) = FORKS.get(store, txn, &key)? else {
        return Ok(None);
    };
    let doc = match record.state {
        TypedForkState::Open => Some(load(FORK_DOCS.get(store, txn, &key)?, None)?),
        _ => None,
    };
    Ok(Some((record, doc)))
}

/// Lands an open fork. The merger names the head it reviewed: a moved head, or
/// the opener as merger, refuses. The fork's own operations are imported, not
/// rewritten, so its receipts land with them. Returns the new head; the caller
/// may read the body back in the same transaction and fail it to refuse.
pub(crate) fn merge_typed_body_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    expected_head: &[u8],
    actor: WriteActor,
) -> Result<TypedBodyHead> {
    let key = (*entity, *fork);
    let mut record = FORKS
        .get(&vault.store, txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    // "The opener's lineage and its forks never settle their own proposal."
    if record.opener == actor.entity_ref() {
        return Err(invalid("a fork's opener cannot merge it"));
    }
    validate_actor(vault, txn, actor)?;
    require_live(&vault.store, txn, entity)?;
    let mut head = HEADS
        .get(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    if head.frontier != expected_head {
        return Err(invalid(
            "the body moved since the review; read the fork again",
        ));
    }
    let live = load(DOCS.get(&vault.store, txn, entity)?, Some(&head.frontier))?;
    let proposal = load(FORK_DOCS.get(&vault.store, txn, &key)?, None)?;
    let updates = proposal
        .export(ExportMode::updates(&live.oplog_vv()))
        .map_err(|_| invalid("typed body fork export"))?;
    import(&live, &updates)?;
    head.frontier = live.oplog_frontiers().encode();
    head.commits += record.commits;
    DOCS.put(&vault.store, txn, entity, &snapshot(&live)?)?;
    HEADS.put(&vault.store, txn, entity, &head)?;
    record.state = TypedForkState::Merged {
        by: actor.entity_ref(),
        at: vault.now_recorded_at(),
        head: head.frontier.clone(),
    };
    FORKS.put(&vault.store, txn, &key, &record)?;
    FORK_DOCS.delete(&vault.store, txn, &key)?;
    Ok(head)
}

/// Abandons an open fork's unlanded work.
pub(crate) fn discard_typed_body_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    actor: WriteActor,
) -> Result<TypedBodyFork> {
    let key = (*entity, *fork);
    let mut record = FORKS
        .get(&vault.store, txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    record.state = TypedForkState::Discarded {
        by: actor.entity_ref(),
        at: vault.now_recorded_at(),
    };
    FORKS.put(&vault.store, txn, &key, &record)?;
    FORK_DOCS.delete(&vault.store, txn, &key)?;
    Ok(record)
}

/// Removes `entity`'s typed body and every fork of it. Registered with the
/// per-entity erasers in `deletion/derived_rows.rs`.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    HEADS.delete(store, txn, entity)?;
    DOCS.delete(store, txn, entity)?;
    FORKS.delete_from(store, txn, entity.as_bytes())?;
    FORK_DOCS.delete_from(store, txn, entity.as_bytes())?;
    Ok(())
}

impl Vault {
    /// `entity`'s typed body head, when it has one.
    pub fn typed_body_head(&self, entity: &EntityId) -> Result<Option<TypedBodyHead>> {
        let txn = self.store.env.read_txn()?;
        require_live(&self.store, &txn, entity)?;
        HEADS.get(&self.store, &txn, entity)
    }

    /// `entity`'s body under `schema` at its head, or a detached copy at an
    /// earlier frontier `at`.
    pub fn typed_body(
        &self,
        entity: &EntityId,
        schema: &str,
        at: Option<&[u8]>,
    ) -> Result<Option<LoroDoc>> {
        let txn = self.store.env.read_txn()?;
        Ok(typed_body_in_txn(&self.store, &txn, entity, schema, at)?.map(|(_, doc)| doc))
    }

    /// One fork's record.
    pub fn typed_body_fork(
        &self,
        entity: &EntityId,
        fork: &EntityId,
    ) -> Result<Option<TypedBodyFork>> {
        let txn = self.store.env.read_txn()?;
        Ok(typed_body_fork_in_txn(&self.store, &txn, entity, fork)?.map(|(record, _)| record))
    }

    /// Every commit's receipt on the head's history, oldest first. A commit
    /// whose receipt is missing, malformed or not honored for its peer is
    /// `None`, so a fold of the list fails closed.
    pub fn typed_body_receipts(&self, entity: &EntityId) -> Result<Vec<Option<TextCommitReceipt>>> {
        let doc = {
            let txn = self.store.env.read_txn()?;
            require_live(&self.store, &txn, entity)?;
            let head = HEADS
                .get(&self.store, &txn, entity)?
                .ok_or(Error::EntityNotFound)?;
            load(DOCS.get(&self.store, &txn, entity)?, Some(&head.frontier))?
        };
        let mut metas = Vec::new();
        doc.travel_change_ancestors(&doc.oplog_frontiers().to_vec(), &mut |meta| {
            metas.push(meta);
            ControlFlow::Continue(())
        })
        .map_err(|_| Error::CorruptedIndex("typed body change history"))?;
        // Loro walks ancestors newest first.
        metas.reverse();
        let mut receipts = Vec::with_capacity(metas.len());
        for meta in metas {
            let Some((actor, made_by)) = parse_message(meta.message.as_deref()) else {
                receipts.push(None);
                continue;
            };
            let honored = u64::try_from(meta.timestamp).ok() == Some(made_by.at)
                && made_by_names(actor, &made_by)
                && crate::edit_distance::peer_actor_stamp_is_honored(
                    self,
                    meta.id.peer,
                    made_by.at,
                    &actor,
                )?;
            let end = i32::try_from(meta.len)
                .ok()
                .and_then(|len| meta.id.counter.checked_add(len));
            receipts.push(match end {
                Some(end) if honored => Some(TextCommitReceipt {
                    document: *entity,
                    peer: meta.id.peer,
                    start: meta.id.counter,
                    end,
                    made_by,
                }),
                _ => None,
            });
        }
        Ok(receipts)
    }

    /// The body's provenance folded from every receipt; `None` when any
    /// commit lacks one.
    pub fn typed_body_provenance(&self, entity: &EntityId) -> Result<Option<RowProvenance>> {
        Ok(RowProvenance::fold(
            *entity,
            self.typed_body_receipts(entity)?,
        ))
    }

    /// Births `entity`'s typed body in a transaction of its own; a caller
    /// with rows of its own to write in the same transaction uses
    /// `birth_typed_body_in_txn`.
    pub fn birth_typed_body<T>(
        &self,
        entity: &EntityId,
        writer: TypedBodyWriter<'_>,
        init: impl FnOnce(&LoroDoc) -> Result<T>,
    ) -> Result<(T, TypedBodyCommit)> {
        self.with_write_txn_grouped(|txn| birth_typed_body_in_txn(self, txn, entity, writer, init))
    }

    /// The writer's operations on the live body, read against `base` when
    /// given (`edit_typed_body_in_txn`).
    pub fn edit_typed_body<T>(
        &self,
        entity: &EntityId,
        base: Option<&[u8]>,
        writer: TypedBodyWriter<'_>,
        edit: impl FnOnce(&LoroDoc) -> Result<T>,
    ) -> Result<(T, TypedBodyCommit)> {
        self.with_write_txn_grouped(|txn| {
            edit_typed_body_in_txn(self, txn, entity, base, writer, edit)
        })
    }

    /// Opens a fork of the live body at its head for `actor`'s work.
    pub fn open_typed_body_fork(
        &self,
        entity: &EntityId,
        schema: &str,
        actor: WriteActor,
    ) -> Result<TypedBodyFork> {
        self.with_write_txn_grouped(|txn| {
            open_typed_body_fork_in_txn(self, txn, entity, schema, actor)
        })
    }

    /// The opener's operations on its open fork.
    pub fn edit_typed_body_fork<T>(
        &self,
        entity: &EntityId,
        fork: &EntityId,
        writer: TypedBodyWriter<'_>,
        edit: impl FnOnce(&LoroDoc) -> Result<T>,
    ) -> Result<(T, TypedBodyCommit)> {
        self.with_write_txn_grouped(|txn| {
            edit_typed_body_fork_in_txn(self, txn, entity, fork, writer, edit)
        })
    }

    /// Lands an open fork against the head its merger reviewed
    /// (`merge_typed_body_fork_in_txn`).
    pub fn merge_typed_body_fork(
        &self,
        entity: &EntityId,
        fork: &EntityId,
        expected_head: &[u8],
        actor: WriteActor,
    ) -> Result<TypedBodyHead> {
        self.with_write_txn_grouped(|txn| {
            merge_typed_body_fork_in_txn(self, txn, entity, fork, expected_head, actor)
        })
    }

    /// Abandons an open fork's unlanded work.
    pub fn discard_typed_body_fork(
        &self,
        entity: &EntityId,
        fork: &EntityId,
        actor: WriteActor,
    ) -> Result<TypedBodyFork> {
        self.with_write_txn_grouped(|txn| {
            discard_typed_body_fork_in_txn(self, txn, entity, fork, actor)
        })
    }
}

/// Runs one call's operations under a fresh peer bound to the writer's actor
/// and commits them with the writer's receipt in the message.
fn commit_as<T>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    doc: &LoroDoc,
    entity: EntityId,
    writer: TypedBodyWriter<'_>,
    verb: &str,
    edit: impl FnOnce(&LoroDoc) -> Result<T>,
) -> Result<(T, TextCommitReceipt)> {
    let TypedBodyWriter { actor, made_by, .. } = writer;
    if !made_by_names(actor, made_by) {
        return Err(invalid(
            "the MadeBy envelope does not name this actor's process",
        ));
    }
    validate_actor(vault, txn, actor)?;
    let at = i64::try_from(made_by.at).map_err(|_| invalid("typed body commit time"))?;
    let encoded = serde_json::to_string(made_by)
        .map_err(|_| Error::InvariantViolation("typed body receipt encoding"))?;
    // A fresh peer per call: the receipt covers exactly this call's
    // operations, and no two calls coalesce into one change.
    doc.set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| invalid("typed body peer"))?;
    let peer = doc.peer_id();
    let before = doc.state_frontiers();
    let value = edit(doc)?;
    let message = format!(
        "{STAMP} {verb} actor={}.{} {RECEIPT_PREFIX}{encoded}",
        actor.entity_ref().to_hex(),
        crate::edit_distance::actor_class_token(actor.actor_class()),
    );
    doc.commit_with(CommitOptions::new().commit_msg(&message).timestamp(at));
    let end = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
    if end <= 0 {
        return Err(invalid("the call changed nothing"));
    }
    admit_body(vault, txn, doc, &before)?;
    bind_peer(vault, txn, peer, actor, made_by.at)?;
    Ok((
        value,
        TextCommitReceipt {
            document: entity,
            peer,
            start: 0,
            end,
            made_by: made_by.clone(),
        },
    ))
}

/// The body as one call left it, read whole by the write door under the
/// owner's switch before it is serialized (OF-067). A typed body's history is
/// its receipt ledger, so no handle can replace what an operation wrote: a
/// hit refuses the call, unless the body read the same way before it.
fn admit_body(vault: &Vault, txn: &RoTxn<'_>, doc: &LoroDoc, before: &Frontiers) -> Result<()> {
    let read = |doc: &LoroDoc| {
        serde_json::to_vec(&doc.get_deep_value())
            .map_err(|_| Error::InvariantViolation("typed body state did not encode"))
    };
    crate::batch::secret_scan::scan_document_in_txn(&vault.store, txn, &read(doc)?, || {
        if before.is_empty() {
            return Ok(None);
        }
        let prior = doc
            .fork_at(before)
            .map_err(|_| invalid("unknown typed body frontier"))?;
        read(&prior).map(Some)
    })
}

/// Whether `made_by` is a receipt `actor` may give: its process names the
/// actor, and only a person states.
fn made_by_names(actor: WriteActor, made_by: &MadeBy) -> bool {
    made_by.process.actor == actor.entity_ref()
        && made_by.process.is_valid()
        && made_by.inputs.len() <= 1024
        && (actor.actor_class() == EdgeActorClass::Human
            || made_by.process.class != MadeByClass::Stated)
}

fn parse_message(message: Option<&str>) -> Option<(WriteActor, MadeBy)> {
    let rest = message?.strip_prefix(STAMP)?.strip_prefix(' ')?;
    let (stamp, encoded) = rest.split_once(RECEIPT_PREFIX)?;
    let mut tokens = stamp.split_whitespace();
    let _verb = tokens.next()?;
    let (id, class) = tokens.next()?.strip_prefix("actor=")?.split_once('.')?;
    let actor = WriteActor::new(
        EntityId::from_hex(id).ok()?,
        crate::edit_distance::actor_class_from_token(class)?,
    );
    Some((actor, serde_json::from_str(encoded).ok()?))
}

/// Writes the `actor.peer_binding` claim that lets a reader honor `peer`'s
/// commits as `actor`'s from `at`. Each authored call takes a fresh peer, so
/// same-second changes by different actors never share a binding.
pub(crate) fn bind_peer(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    peer: u64,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        PREDICATE_ACTOR_PEER_BINDING,
    };
    let mut body = ClaimBody::new(
        PREDICATE_ACTOR_PEER_BINDING,
        ClaimSubject::Entity(actor.entity_ref()),
        rmpv::Value::Map(vec![
            (rmpv::Value::from("peer"), rmpv::Value::from(peer)),
            (
                rmpv::Value::from("class"),
                rmpv::Value::from(crate::edit_distance::actor_class_token(actor.actor_class())),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        txn,
        &EntityId::now(),
        &body,
        crate::temporal::TimeRange { start: at, end: at },
        at,
    )
}

fn validate_actor(vault: &Vault, txn: &RoTxn<'_>, actor: WriteActor) -> Result<()> {
    require_live(&vault.store, txn, &actor.entity_ref())?;
    crate::memory::verify_actor_binding_in_txn(vault, txn, actor.entity_ref(), actor.actor_class())
        .map_err(|_| invalid("typed body actor class does not match store truth"))?;
    if vault.entity_lifecycle_state_in_txn(txn, &actor.entity_ref())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(invalid("typed body actor is not active"));
    }
    Ok(())
}

/// A live, unwithdrawn row that is not secret custody.
fn require_live(store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<()> {
    match live_entity_row_in_txn(store, txn, entity)? {
        LiveEntityRow::Live { entity_type, .. }
            if entity_type != crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                && !crate::ports::withdrawn_in_txn(store, txn, entity)? =>
        {
            Ok(())
        }
        _ => Err(Error::EntityNotFound),
    }
}

fn head_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    schema: &str,
) -> Result<TypedBodyHead> {
    require_live(store, txn, entity)?;
    let head = HEADS
        .get(store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    if head.schema != schema {
        return Err(invalid("the typed body has another schema"));
    }
    Ok(head)
}

fn load(bytes: Option<Vec<u8>>, frontier: Option<&[u8]>) -> Result<LoroDoc> {
    let bytes = bytes.ok_or(Error::CorruptedIndex("typed body document missing"))?;
    let doc =
        LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("typed body document"))?;
    if frontier.is_some_and(|frontier| doc.oplog_frontiers().encode() != frontier) {
        return Err(Error::CorruptedIndex("typed body frontier"));
    }
    doc.set_record_timestamp(true);
    Ok(doc)
}

fn snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|_| invalid("typed body snapshot"))
}

fn import(doc: &LoroDoc, updates: &[u8]) -> Result<()> {
    let status = doc
        .import(updates)
        .map_err(|_| invalid("typed body update import"))?;
    if status.pending.is_some() {
        return Err(Error::CorruptedIndex("typed body update dependencies"));
    }
    Ok(())
}

fn fork_at(doc: &LoroDoc, frontier: &[u8]) -> Result<LoroDoc> {
    let frontier =
        Frontiers::decode(frontier).map_err(|_| invalid("invalid typed body frontier"))?;
    doc.fork_at(&frontier)
        .map_err(|_| invalid("unknown typed body frontier"))
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(reason))
}

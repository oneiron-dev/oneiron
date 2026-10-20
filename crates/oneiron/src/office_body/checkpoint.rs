//! The checkpoint getter of office bodies (KS7-2): each artifact's office
//! head, deck fork records, export records, proposals and fork memberships
//! under the artifact's own entity tree. The DOCX, XLSX and PPTX documents
//! are typed bodies, which the typed-body getter holds; nothing here takes a
//! second snapshot of them.
//!
//! Every actor a row names is split out: a deck fork's opener and settler,
//! an export's actor with the author it showed, and a proposal's opener, each
//! member's opener and each answer's caller and person. A restore mirrors
//! the erase (FIX 3520): an open fork whose opener did not open goes; an
//! export whose actor did not open names no one and shows no author; a
//! waiting member whose opener did not open leaves its proposal, with its
//! membership row, and a proposal left with no member goes, one left with
//! none waiting closing at the restore's time. The deck oracle's receipts
//! are keyed by export profile, not by an artifact, so they are not
//! compartmented. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::consent::{
    AnsweringAuthority, MEMBERSHIP, MemberAnswer, MemberVerdict, OfficeBodyProposal, PROPOSALS,
    close_if_done,
};
use super::pptx::ORACLE;
use super::{
    EXPORTS, FORKS, ForkState, OfficeBodyExportRecord, OfficeBodyFork, SOURCES, version_key,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, RowPart,
    TypedRow, Unresolved,
};
use crate::typed_body::BodyActor;

/// The field a deck fork's or a proposal's opener fills.
const OPENER: &str = "opener";

/// The field the actor who merged or discarded a deck fork fills.
const SETTLER: &str = "settler";

/// The field an export's actor fills.
const ACTOR: &str = "actor";

/// The field the author an export showed fills, as its text.
const AUTHOR: &str = "author";

/// A proposal member's fields: this, the member fork's id, then its role.
const MEMBER: &str = "member ";

/// The roles of a member's answer: who called the settlement, and the
/// person whose word answered.
const CALLER: &str = "caller";
const PERSON: &str = "person";

/// Moves `slot`'s actor out as `field`, leaving no one.
fn take(slot: &mut BodyActor, field: String, actors: &mut Vec<(String, EntityId)>) {
    if let BodyActor::Actor(id) = std::mem::replace(slot, BodyActor::Erased) {
        actors.push((field, id));
    }
}

/// Puts an opened actor back where the split left no one.
fn fill(slot: &mut BodyActor, actor: EntityId) -> Result<()> {
    if *slot != BodyActor::Erased {
        return Err(rows::bad_part());
    }
    *slot = BodyActor::Actor(actor);
    Ok(())
}

fn take_fork_actors(fork: &mut OfficeBodyFork) -> Vec<(String, EntityId)> {
    let mut actors = Vec::new();
    take(&mut fork.opener, OPENER.to_owned(), &mut actors);
    if let ForkState::Merged { by, .. } | ForkState::Discarded { by, .. } = &mut fork.state {
        take(by, SETTLER.to_owned(), &mut actors);
    }
    actors
}

fn put_fork_actor(fork: &mut OfficeBodyFork, field: &str, actor: EntityId) -> Result<()> {
    match (field, &mut fork.state) {
        (OPENER, _) => fill(&mut fork.opener, actor),
        (SETTLER, ForkState::Merged { by, .. } | ForkState::Discarded { by, .. }) => {
            fill(by, actor)
        }
        _ => Err(rows::bad_part()),
    }
}

fn take_proposal_actors(record: &mut OfficeBodyProposal) -> Vec<(String, EntityId)> {
    let mut actors = Vec::new();
    take(&mut record.header.opener, OPENER.to_owned(), &mut actors);
    for member in &mut record.members {
        let fork = member.fork.to_hex();
        take(
            &mut member.opener,
            format!("{MEMBER}{fork} {OPENER}"),
            &mut actors,
        );
        if let Some(answer) = &mut member.answer {
            take(
                &mut answer.caller,
                format!("{MEMBER}{fork} {CALLER}"),
                &mut actors,
            );
            if let AnsweringAuthority::Word { person } = &mut answer.by {
                take(person, format!("{MEMBER}{fork} {PERSON}"), &mut actors);
            }
        }
    }
    actors
}

fn put_proposal_actor(record: &mut OfficeBodyProposal, field: &str, actor: EntityId) -> Result<()> {
    if field == OPENER {
        return fill(&mut record.header.opener, actor);
    }
    let (fork, role) = field
        .strip_prefix(MEMBER)
        .and_then(|rest| rest.split_once(' '))
        .ok_or_else(rows::bad_part)?;
    let member = record
        .members
        .iter_mut()
        .find(|member| member.fork.to_hex() == fork)
        .ok_or_else(rows::bad_part)?;
    let slot = match (role, &mut member.answer) {
        (OPENER, _) => &mut member.opener,
        (CALLER, Some(answer)) => &mut answer.caller,
        (
            PERSON,
            Some(MemberAnswer {
                by: AnsweringAuthority::Word { person },
                ..
            }),
        ) => person,
        _ => return Err(rows::bad_part()),
    };
    fill(slot, actor)
}

/// Splits an export's actor and the author it showed out of `row`: the
/// content keeps the erase's form, no one and no author, and both are actor
/// parts of the export's actor.
fn split_export(
    out: &mut Captured,
    owner: OwnerRef,
    row: TypedRow<Vec<u8>, OfficeBodyExportRecord>,
) -> Result<()> {
    if !rows::spells_back(EXPORTS, &row) {
        let reason = Unresolved::ActorSplit(rows::NOT_SPELLED_BACK);
        out.unclassified(row.at, Some(owner), reason);
        return Ok(());
    }
    let TypedRow {
        at,
        mut value,
        bytes,
        ..
    } = row;
    let BodyActor::Actor(actor) = std::mem::replace(&mut value.actor, BodyActor::Erased) else {
        out.exact(owner, at, bytes);
        return Ok(());
    };
    let author = std::mem::take(&mut value.author);
    let content = EXPORTS.encode_value(&value)?;
    let held = out.owner(owner);
    for (field, part) in [
        (ACTOR, actor.as_bytes().to_vec()),
        (AUTHOR, author.into_bytes()),
    ] {
        held.actor_parts.push(ActorPart {
            actor_entity: actor,
            content_locator: at.clone(),
            field: field.to_owned(),
            bytes: part,
        });
    }
    held.rows.push(RowPart::NoActor { at, value: content });
    Ok(())
}

/// Every office row in `txn`, by artifact.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, SOURCES, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, FORKS, &mut out)? {
        let (artifact, fork) = row.key;
        if row.value.artifact != artifact || row.value.id != fork {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        let owner = OwnerRef::entity(&artifact);
        rows::split_actors(&mut out, owner, FORKS, row, take_fork_actors)?;
    }
    for row in rows::typed_rows(dbs, txn, EXPORTS, &mut out)? {
        if row.key != version_key(&row.value.artifact, row.value.version) {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        let owner = OwnerRef::entity(&row.value.artifact);
        split_export(&mut out, owner, row)?;
    }
    // A waiting member's membership row goes with it when its opener is
    // erased.
    let mut waiting = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, PROPOSALS, &mut out)? {
        let (artifact, proposal) = row.key;
        let header = &row.value.header;
        if header.artifact != artifact || header.proposal != proposal {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        for member in &row.value.members {
            if let (MemberVerdict::Waiting, BodyActor::Actor(opener)) =
                (member.verdict, member.opener)
            {
                waiting.insert((artifact, member.fork), opener);
            }
        }
        let owner = OwnerRef::entity(&artifact);
        rows::split_actors(&mut out, owner, PROPOSALS, row, take_proposal_actors)?;
    }
    for row in rows::typed_rows(dbs, txn, MEMBERSHIP, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0);
        if let Some(opener) = waiting.get(&row.key) {
            out.depends(owner, &row.at, OwnerRef::entity(opener));
        }
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, ORACLE, &mut out)? {
        out.unclassified(row.at, None, Unresolved::NoOwner);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [
        SOURCES.decl(),
        FORKS.decl(),
        EXPORTS.decl(),
        PROPOSALS.decl(),
        MEMBERSHIP.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
}

/// The bundle framing of `rows`' office parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(SOURCES.decl()) {
        rows::check_row(SOURCES, at, value)
    } else if at.in_table(FORKS.decl()) {
        rows::check_row(FORKS, at, value)
    } else if at.in_table(EXPORTS.decl()) {
        rows::check_row(EXPORTS, at, value)
    } else if at.in_table(PROPOSALS.decl()) {
        rows::check_row(PROPOSALS, at, value)
    } else if at.in_table(MEMBERSHIP.decl()) {
        rows::check_row(MEMBERSHIP, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// An export with its actor and author back when its actor opened (both or
/// neither: one actor holds them), else the erase's form.
fn join_export(value: &[u8], parts: &[&ActorPart]) -> Result<Vec<u8>> {
    let mut record = EXPORTS.decode_value(value)?;
    if !matches!(parts.len(), 0 | 2) {
        return Err(rows::bad_part());
    }
    for part in parts {
        match part.field.as_str() {
            ACTOR if record.actor == BodyActor::Erased => {
                let id: [u8; 16] = part
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| rows::bad_part())?;
                if EntityId::from_bytes(id)? != part.actor_entity {
                    return Err(rows::bad_part());
                }
                record.actor = BodyActor::Actor(part.actor_entity);
            }
            AUTHOR if record.author.is_empty() => {
                record.author =
                    String::from_utf8(part.bytes.clone()).map_err(|_| rows::bad_part())?;
            }
            _ => return Err(rows::bad_part()),
        }
    }
    EXPORTS.encode_value(&record)
}

/// A proposal with its opened actors back. Each waiting member whose opener
/// did not open leaves it, as the erase takes it out; `None` once no member
/// is left, and a proposal left with none waiting closes now.
fn join_proposal(
    dbs: &impl ManifestDbs,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let mut record = rows::join_actors(PROPOSALS, value, parts, put_proposal_actor)?;
    let members = record.members.len();
    record.members.retain(|member| {
        member.verdict != MemberVerdict::Waiting || member.opener != BodyActor::Erased
    });
    if record.members.is_empty() {
        return Ok(None);
    }
    if record.members.len() != members {
        close_if_done(&mut record, dbs.clock().now_recorded_at(), None);
    }
    PROPOSALS.encode_value(&record).map(Some)
}

/// A no-one-form row with its opened actors back, as the erase leaves it
/// for each actor that did not open.
fn join(
    dbs: &impl ManifestDbs,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(FORKS.decl()) {
        let fork = rows::join_actors(FORKS, value, parts, put_fork_actor)?;
        if fork.opener == BodyActor::Erased && fork.state == ForkState::Open {
            return Ok(None);
        }
        return FORKS.encode_value(&fork).map(Some);
    }
    if at.in_table(EXPORTS.decl()) {
        return join_export(value, parts).map(Some);
    }
    if at.in_table(PROPOSALS.decl()) {
        return join_proposal(dbs, value, parts);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s office rows back: exact rows as they are, each fork,
/// export and proposal with the actors that opened, and each membership row
/// whose waiting member's opener opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, |_, at, value, parts| {
        join(dbs, at, value, parts)
    })
}

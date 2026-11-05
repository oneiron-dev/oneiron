//! An erased actor out of the office rows that name it (FIX 3520): the
//! export records, the deck forks' records, the proposals and the deck
//! oracle's receipts. The typed-body forks under them go in the typed body's
//! own scrub.

use super::consent::{AnsweringAuthority, MEMBERSHIP, MemberVerdict, PROPOSALS, close_if_done};
use super::holder_ask::LIVE_EDIT_GROUPS;
use super::pptx::ORACLE;
use super::{EXPORT_AUTHORS, EXPORTS, FORKS, ForkState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::typed_body::names_no_actor;

impl ForkState {
    /// Makes the one who settled the fork no one when it is `actor`; whether
    /// it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Open => false,
            Self::Merged { by, .. } | Self::Discarded { by, .. } => by.forget(actor),
        }
    }
}

/// Erasing `actor` from the export records (FIX 3520): an export it made
/// keeps its version, frontier and time and names no one, and the author it
/// showed goes with it. One-way, in the erase's own transaction. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an export row that cannot be read.
pub(crate) fn erase_export_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut exports = Vec::new();
    for (key, mut record) in EXPORTS.scan(&vault.store, wtxn)? {
        if record.actor.forget(*actor) {
            record.author.clear();
            exports.push((key, record));
        }
    }
    for (key, record) in exports {
        EXPORTS.put(&vault.store, wtxn, &key, &record)?;
    }
    Ok(())
}

/// Erasing `actor` from a DOCX revision group's author binding (FIX 595):
/// the token stays so the bytes still resolve, but the actor becomes `None`
/// and the outgoing copy shows `erased`.
///
/// # Errors
///
/// Storage errors, or an author row that cannot be read.
pub(crate) fn erase_export_author_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut authors = Vec::new();
    for (key, mut record) in EXPORT_AUTHORS.scan(&vault.store, wtxn)? {
        if record.actor == Some(*actor) {
            record.actor = None;
            authors.push((key, record));
        }
    }
    for (key, record) in authors {
        EXPORT_AUTHORS.put(&vault.store, wtxn, &key, &record)?;
    }
    Ok(())
}

/// Erasing `actor` from the deck forks' records (FIX 3520): an open fork it
/// opened is work a merge could still land, so its record goes, as its
/// typed-body fork does; a merged or discarded fork keeps its record and
/// names no one. One-way, in the erase's own transaction. An id whose entity
/// is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn erase_fork_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut forks = Vec::new();
    for (key, mut fork) in FORKS.scan(&vault.store, wtxn)? {
        let opened = fork.opener.forget(*actor);
        let settled = fork.state.forget(*actor);
        if opened || settled {
            forks.push((key, fork, opened));
        }
    }
    for (key, fork, opened) in forks {
        if opened && fork.state == ForkState::Open {
            FORKS.delete(&vault.store, wtxn, &key)?;
        } else {
            FORKS.put(&vault.store, wtxn, &key, &fork)?;
        }
    }
    Ok(())
}

/// Erasing `actor` from the office proposals (FIX 3520): a waiting member it
/// opened leaves its proposal, as its fork goes, and a proposal left with no
/// member goes; one left with no member waiting closes. Everywhere else it is
/// named (the proposal's opener, a member's opener, an answer's person or
/// caller), the row keeps its verdict and time and names no one. One-way, in
/// the erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a proposal row that cannot be read.
pub(crate) fn erase_proposal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut proposals = Vec::new();
    for (key, mut record) in PROPOSALS.scan(&vault.store, wtxn)? {
        let mut named = record.header.opener.forget(*actor);
        let mut left = Vec::new();
        record.members.retain_mut(|member| {
            if member.verdict == MemberVerdict::Waiting && member.opener.is(*actor) {
                left.push((member.artifact, member.fork));
                return false;
            }
            named |= member.opener.forget(*actor);
            if let Some(answer) = &mut member.answer {
                named |= answer.caller.forget(*actor);
                if let AnsweringAuthority::Word { person } = &mut answer.by {
                    named |= person.forget(*actor);
                }
            }
            true
        });
        if named || !left.is_empty() {
            proposals.push((key, record, left));
        }
    }
    let at = vault.now_recorded_at();
    for (key, mut record, left) in proposals {
        for (artifact, fork) in left {
            MEMBERSHIP.delete(&vault.store, wtxn, &(artifact, fork))?;
        }
        if record.members.is_empty() {
            PROPOSALS.delete(&vault.store, wtxn, &key)?;
        } else {
            close_if_done(&mut record, at, None);
            PROPOSALS.put(&vault.store, wtxn, &key, &record)?;
        }
    }
    Ok(())
}

/// Erasing `actor` from the deck oracle's receipts (FIX 4511): a receipt it
/// recorded keeps its outcome, projector and time and names no one, so the
/// export gate it opened stays as it is. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an oracle row that cannot be read.
pub(crate) fn erase_oracle_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut records = Vec::new();
    for (profile, mut record) in ORACLE.scan(&vault.store, wtxn)? {
        if record.recorded_by.forget(*actor) {
            records.push((profile, record));
        }
    }
    for (profile, record) in records {
        ORACLE.put(&vault.store, wtxn, &profile, &record)?;
    }
    Ok(())
}

/// Erasing `actor` from live-edit holder-ask routes (FIX 596): an erased
/// editor's route goes, and an erased owner leaves the electorate; a route
/// with no owner left goes too. Artifact and revision stay on surviving
/// routes, so the next admission builds a truthful fresh route if needed.
pub(crate) fn erase_live_edit_ask_group_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut deleted = Vec::new();
    let mut updated = Vec::new();
    for (group, mut route) in LIVE_EDIT_GROUPS.scan(&vault.store, wtxn)? {
        if route.editor == *actor {
            deleted.push(group);
            continue;
        }
        let owners = route.owners.len();
        route.owners.retain(|owner| owner != actor);
        if route.owners.len() == owners {
            continue;
        }
        if route.owners.is_empty() {
            deleted.push(group);
        } else {
            updated.push((group, route));
        }
    }
    for group in deleted {
        LIVE_EDIT_GROUPS.delete(&vault.store, wtxn, &group)?;
    }
    for (group, route) in updated {
        LIVE_EDIT_GROUPS.put(&vault.store, wtxn, &group, &route)?;
    }
    super::consent::revoke_office_edit_grants_naming_in_txn(&vault.store, wtxn, actor)?;
    Ok(())
}

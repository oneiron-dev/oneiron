//! The source-audience conjunct every audience read meets: a row reads to
//! its viewers only while each of them reads under the policy it was born
//! under, and under the policies of what its words came from.
//!
//! What a row's words came from, as this walk reads it:
//! - a MESSAGE's TURN (`PartOf`);
//! - every record a row is `DerivedFrom` (an attachment's text, an EVENT a
//!   message proposed, an epoch summary);
//! - the records and MESSAGEs a summary, a merge header or a copied reply
//!   carries words from ([`crate::scope_summary::word_sources_in`]), and a
//!   scope summary's covers;
//! - a CLAIM's entity subject.
//!
//! Each of those must read: a summary of a private thread is as private as
//! the thread. A CLAIM is the one union: its supporting sources (`Supports`
//! into it) are the evidence it was learned from, and a claim learned from
//! a personal mailbox alone reads only to that mailbox's readers, while one
//! any reader could also have learned from a source they read stays theirs
//! too. A claim with no support restricts nothing by this rule.
//!
//! A row nothing binds and whose words came from nothing bound reads as
//! before. A policy that does not resolve denies, and a read that
//! authenticates no one reads no bound row, as a private thread is read
//! (FIX 2951). A cycle adds no restriction of its own.
//!
//! A row a source landed carries its source in its own bytes: a mail
//! CONVERSATION's or TURN's `import_source` (one of the pack's own source
//! names), a MESSAGE through its TURN. Bindings and policies are this
//! vault's own rows and do not travel with a replica, so such a row read
//! where its binding is absent reads to no one; and a bound row, or a row
//! whose words came from one, does not leave this vault by window
//! replication ([`withheld_from_replication_in`]).

use std::collections::{BTreeMap, BTreeSet};

use crate::EdgeKind;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN,
};
use crate::{EntityId, Vault};

/// The TURN and CONVERSATION body key naming an imported transcript's
/// source.
const IMPORT_SOURCE_KEY: &str = "import_source";
/// The import sources a source audience lands: the Mail & Calendar pack's
/// own, exactly (`mail_pack::landing::import_source`). A caller that births
/// a conversation stamped with one of these names only hides its own rows.
const SOURCE_IMPORTS: [&str; 6] = [
    "mail.google_workspace",
    "mail.google",
    "mail.microsoft365",
    "mail.imap",
    "calendar.caldav",
    "calendar.ics",
];

/// The string value of `key` in a MessagePack map body.
fn body_string<'b>(body: &'b [u8], key: &str) -> Option<&'b str> {
    let mut cursor = body;
    let Ok(rmpv::ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return None;
    };
    entries
        .into_iter()
        .find_map(|(name, value)| match (name, value) {
            (rmpv::ValueRef::String(name), rmpv::ValueRef::String(value))
                if name.as_str() == Some(key) =>
            {
                value.into_str()
            }
            _ => None,
        })
}

/// Whether a TURN or CONVERSATION row `raw` is a source's import.
fn container_marked(raw: &[u8]) -> bool {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return false;
    };
    if !matches!(
        header.entity_type,
        ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION
    ) {
        return false;
    }
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    body_string(body, IMPORT_SOURCE_KEY).is_some_and(|source| SOURCE_IMPORTS.contains(&source))
}

/// Whether the row `id` (bytes `raw`) is one a source audience landed: a
/// source-imported TURN or CONVERSATION by its own stamp, a MESSAGE by its
/// TURN's (`PartOf`), since a MESSAGE's type is its caller's word.
fn source_marked_in(
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    match header.entity_type {
        ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION => Ok(container_marked(raw)),
        ENTITY_TYPE_MESSAGE => {
            for turn in
                crate::conversation_dag::counted_edge_ids(dbs, txn, &id, EdgeKind::PartOf, false)?
            {
                if let Some(bytes) =
                    crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &turn)?
                    && container_marked(&bytes)
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// What the words of the row `id` (bytes `bytes`) came from, as the walk
/// reads it: the rows each of which must read, and a CLAIM's supports, one
/// of which must.
fn word_sources(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    bytes: &[u8],
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let header = EntityMetadataHeader::parse(bytes)
        .ok_or(Error::CorruptedIndex("source audience row header"))?;
    let body = bytes.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let mut every = Vec::new();
    if header.entity_type == ENTITY_TYPE_MESSAGE {
        every.extend(crate::conversation_dag::counted_edge_ids(
            dbs,
            txn,
            &id,
            EdgeKind::PartOf,
            false,
        )?);
    }
    every.extend(crate::conversation_dag::counted_edge_ids(
        dbs,
        txn,
        &id,
        EdgeKind::DerivedFrom,
        false,
    )?);
    // A summary whose sources no longer resolve, or do not read, is refused
    // by the derived-source conjunct; here it names nothing more.
    if let Ok(crate::scope_summary::WordSources::From(sources)) =
        crate::scope_summary::word_sources_in(vault, txn, &id, bytes)
    {
        every.extend(sources);
    }
    if let Ok(Some(covers)) =
        crate::scope_summary::body_covers_in_txn(vault, txn, &id, header.entity_type, body)
    {
        every.extend(covers);
    }
    let mut supports = Vec::new();
    if header.entity_type == ENTITY_TYPE_CLAIM {
        if let Ok(claim) = crate::claim::decode_claim_body(body, true)
            && let crate::claim::ClaimSubject::Entity(subject) = claim.subject
        {
            every.push(subject);
        }
        supports =
            crate::conversation_dag::counted_edge_ids(dbs, txn, &id, EdgeKind::Supports, true)?;
    }
    Ok((every, supports))
}

/// Whether the row `id` stays out of window replication: it is bound to a
/// source audience, a source landed it, or its words came from such a row
/// (any support of a CLAIM counts, so a claim also supported elsewhere stays
/// too). Bindings and policies do not travel with a replica, so a bound row
/// stays on the vault that landed it and is read there through the scoped
/// reads. Where the vault holds no policy only a row a source landed is
/// withheld, by its own stamp.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn withheld_from_replication_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let dbs = vault.store.read();
    if !super::any_policy_in(vault, txn)? {
        return match crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, id)? {
            Some(raw) => source_marked_in(&dbs, txn, *id, &raw),
            None => Ok(false),
        };
    }
    // A worklist, not recursion: an ancestry chain of any length is read
    // without growing the stack.
    let mut seen = BTreeSet::from([*id]);
    let mut pending = vec![*id];
    while let Some(row) = pending.pop() {
        if super::binding_in(vault, txn, &row)?.is_some() {
            return Ok(true);
        }
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, &row)? else {
            continue;
        };
        if source_marked_in(&dbs, txn, row, &bytes)? {
            return Ok(true);
        }
        let (every, supports) = word_sources(vault, &dbs, txn, row, &bytes)?;
        for source in every.into_iter().chain(supports) {
            if seen.insert(source) {
                pending.push(source);
            }
        }
    }
    Ok(false)
}

/// Whether every one of `viewers` reads the revision `raw` of `id` under
/// the source audience: its own binding, and those of everything its words
/// came from. `dbs` is the view the read walks (a session's composed view
/// included); bindings and policies read base. A vault that holds no policy
/// answers at once.
pub(crate) fn readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
) -> Result<bool> {
    if !super::any_policy_in(vault, txn)? {
        // No policy here, as on a replica the audience never reached: a row
        // a source landed still reads to no one.
        return Ok(!source_marked_in(dbs, txn, id, raw)?);
    }
    let mut judge = Judge {
        vault,
        dbs,
        txn,
        viewers,
        policies: BTreeMap::new(),
        rows: BTreeMap::new(),
    };
    judge.row_readable(id, Some(raw))
}

/// One read's verdicts, memoised by row and by policy.
struct Judge<'a, 's, 't> {
    vault: &'a Vault,
    dbs: &'a crate::store::StoreRead<'s>,
    txn: &'a heed::RoTxn<'t>,
    viewers: &'a [EntityId],
    policies: BTreeMap<EntityId, bool>,
    rows: BTreeMap<EntityId, bool>,
}

impl Judge<'_, '_, '_> {
    fn row_readable(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<bool> {
        if let Some(known) = self.rows.get(&id) {
            return Ok(*known);
        }
        // In progress: a cycle back to this row adds no restriction.
        self.rows.insert(id, true);
        let verdict = self.judge_row(id, raw)?;
        self.rows.insert(id, verdict);
        Ok(verdict)
    }

    fn judge_row(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<bool> {
        let binding = super::binding_in(self.vault, self.txn, &id)?;
        if let Some(policy) = binding
            && !self.policy_readable(policy)?
        {
            return Ok(false);
        }
        let bytes = match raw {
            Some(raw) => raw.to_vec(),
            None => {
                match crate::ports::EntityStoreRead::port_entity_raw(self.dbs, self.txn, &id)? {
                    Some(bytes) => bytes,
                    // A row gone from this view carries no words to judge; its
                    // own binding, read above, still stands.
                    None => return Ok(true),
                }
            }
        };
        // A row a source landed whose binding is absent here reads to no one.
        if binding.is_none() && source_marked_in(self.dbs, self.txn, id, &bytes)? {
            return Ok(false);
        }
        let (every, supports) = word_sources(self.vault, self.dbs, self.txn, id, &bytes)?;
        for source in every {
            if source != id && !self.row_readable(source, None)? {
                return Ok(false);
            }
        }
        if supports.is_empty() {
            return Ok(true);
        }
        for source in supports {
            if source == id || self.row_readable(source, None)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn policy_readable(&mut self, policy: EntityId) -> Result<bool> {
        if let Some(known) = self.policies.get(&policy) {
            return Ok(*known);
        }
        let verdict = match super::readers_in(self.vault, self.txn, &policy)? {
            None => false,
            Some(None) => true,
            Some(Some(readers)) => {
                let mut every = !self.viewers.is_empty();
                for viewer in self.viewers {
                    if !every {
                        break;
                    }
                    every = super::names_reader_in(self.vault, self.txn, &readers, *viewer)?;
                }
                every
            }
        };
        self.policies.insert(policy, verdict);
        Ok(verdict)
    }
}

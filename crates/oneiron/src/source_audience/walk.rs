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

use std::collections::BTreeMap;

use crate::EdgeKind;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE};
use crate::{EntityId, Vault};

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
        return Ok(true);
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
        if let Some(policy) = super::binding_in(self.vault, self.txn, &id)?
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
        let header = EntityMetadataHeader::parse(&bytes)
            .ok_or(Error::CorruptedIndex("source audience row header"))?;
        let body = bytes.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let mut every = Vec::new();
        if header.entity_type == ENTITY_TYPE_MESSAGE {
            every.extend(crate::conversation_dag::counted_edge_ids(
                self.dbs,
                self.txn,
                &id,
                EdgeKind::PartOf,
                false,
            )?);
        }
        every.extend(crate::conversation_dag::counted_edge_ids(
            self.dbs,
            self.txn,
            &id,
            EdgeKind::DerivedFrom,
            false,
        )?);
        // A summary whose sources no longer resolve, or do not read, is
        // refused by the derived-source conjunct; here it names nothing more.
        if let Ok(crate::scope_summary::WordSources::From(sources)) =
            crate::scope_summary::word_sources_in(self.vault, self.txn, &id, &bytes)
        {
            every.extend(sources);
        }
        if let Ok(Some(covers)) = crate::scope_summary::body_covers_in_txn(
            self.vault,
            self.txn,
            &id,
            header.entity_type,
            body,
        ) {
            every.extend(covers);
        }
        let mut supports = Vec::new();
        if header.entity_type == ENTITY_TYPE_CLAIM {
            if let Ok(claim) = crate::claim::decode_claim_body(body, true)
                && let crate::claim::ClaimSubject::Entity(subject) = claim.subject
            {
                every.push(subject);
            }
            supports = crate::conversation_dag::counted_edge_ids(
                self.dbs,
                self.txn,
                &id,
                EdgeKind::Supports,
                true,
            )?;
        }
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

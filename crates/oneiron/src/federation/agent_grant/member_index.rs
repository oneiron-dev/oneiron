//! Every agent a signed owner-agent Grant mint has ever named (Engine RULING
//! PAIR-GRANT-DESIGN Q2 = A, 11 Nov 06:51): a credential's read bound asks it
//! once no live Grant row names the credential's holder, so revoking an
//! agent's last Grant narrows it to nothing rather than back to its slip
//! (FIX AGENT-REVOKE-WIDENS).
//!
//! A revoke deletes the Grant's row, and its bodyless shell no longer names
//! the member; the signed mint in the authority log still does. So the index
//! keeps a posting (member, grant, the mint's entry hash), written in the
//! writer that stages each authority-log row and never removed: ever means
//! ever. The local append, a signed-history import and a sync ingest all
//! stage their rows through the batch put, so the hook sees every mint row
//! this vault holds. A vault-checkpoint restore copies rows past that hook,
//! so the restore rebuilds the index from the log, as open does for a vault
//! older than it.
//!
//! The mint hash is part of the key, not the value: a second signed mint for
//! the same (member, grant) that the fold refuses adds its own posting and
//! never hides the counted one (REVIEW-3 P2).
//!
//! A mint that an adopted authority checkpoint carries with no resident row
//! never passes the staging hook, and an adoption can land after open. The
//! reader therefore also reads the adopted evidence's carried mints, as the
//! funding check reads them beside the resident rows (REVIEW-3 P1).
//!
//! The index alone admits nothing and narrows nothing: a reader counts a
//! posting only while the authority fold counts its mint, so a row no
//! counted act stands behind never takes an agent's reach.

use crate::Vault;
use crate::authority::{
    AgentGrantChange, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, authority_entry_hash,
    decode_authority_log_entry_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Raw, SideTable};

use super::super::FederationGrantKind;

/// (member, grant, the entry hash of a signed mint naming them) -> ().
const MEMBER_INDEX: SideTable<(EntityId, EntityId, AuthorityEntryHash), (), Raw> =
    SideTable::new(&side_table::FEDERATION_AGENT_GRANT_MEMBER);
/// Schema-version byte gating the index's rebuild from the authority log.
const SCHEMA_VERSION: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_AGENT_GRANT_MEMBER_SCHEMA_VERSION);
const MEMBER_INDEX_SCHEMA_VERSION: u8 = 1;

/// The member and Grant the owner-agent Grant mint `entry` names; `None` for
/// any other entry: a revoke, a GitPush mint, any other op.
fn owner_agent_mint(entry: &AuthorityLogEntry) -> Option<(EntityId, EntityId)> {
    let AuthorityOp::AgentGrantAct(record) = &entry.op else {
        return None;
    };
    match &record.change {
        AgentGrantChange::Mint {
            member,
            grant_kind: FederationGrantKind::Access,
            ..
        } => Some((*member, record.grant)),
        AgentGrantChange::Mint { .. } | AgentGrantChange::Revoke { .. } => None,
    }
}

/// Indexes the member the owner-agent Grant mint `entry` names, in the writer
/// that stages its authority-log row; any other entry writes nothing.
///
/// # Errors
/// A store failure.
pub(crate) fn index_agent_grant_member_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entry: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) -> Result<()> {
    if let Some((member, grant)) = owner_agent_mint(entry) {
        MEMBER_INDEX.put(store, wtxn, &(member, grant, *hash), &())?;
    }
    Ok(())
}

/// Rebuilds the index from every resident authority-log row, at open when
/// its schema version is missing or older (a vault from before the index),
/// and always with `force` (after a restore copied rows past the staging
/// hook). Postings are only added; one whose mint the fold does not count
/// is ignored by the reader.
///
/// # Errors
/// A store or decode failure, or a schema version newer than this build's.
pub(crate) fn backfill_agent_grant_member_index(vault: &Vault, force: bool) -> Result<()> {
    let store = &vault.store;
    if !force {
        let rtxn = store.env.read_txn()?;
        let stored_version = match SCHEMA_VERSION.get(store, &rtxn, &())? {
            Some(raw) if raw.len() == 1 => raw[0],
            Some(_) => return Err(Error::InvalidKey),
            None => 0,
        };
        drop(rtxn);
        if stored_version > MEMBER_INDEX_SCHEMA_VERSION {
            return Err(Error::InvalidKey);
        }
        if stored_version == MEMBER_INDEX_SCHEMA_VERSION {
            return Ok(());
        }
    }
    // Collect first, then write: the type-index cursor is dropped before any
    // vault_meta write, as the skill content-hash index's backfill does.
    let mut wtxn = store.env.write_txn()?;
    let mut postings = Vec::<(EntityId, EntityId, AuthorityEntryHash)>::new();
    for id in store.port_entity_ids_by_type(&wtxn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        let id = id?;
        let Some(row) = store.port_entity_record(&wtxn, &id)? else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_AUTHORITY_LOG || row.body.is_empty() {
            continue;
        }
        let Ok(entry) = decode_authority_log_entry_body(&row.body) else {
            continue;
        };
        if let Some((member, grant)) = owner_agent_mint(&entry) {
            postings.push((member, grant, authority_entry_hash(&entry)?));
        }
    }
    for posting in &postings {
        MEMBER_INDEX.put(store, &mut wtxn, posting, &())?;
    }
    SCHEMA_VERSION.put(store, &mut wtxn, &(), &vec![MEMBER_INDEX_SCHEMA_VERSION])?;
    wtxn.commit()?;
    Ok(())
}

impl Vault {
    /// Whether a signed owner-agent Grant mint that the authority fold of
    /// `txn` counts has ever named `member`, whether or not its Grant still
    /// stands: a resident mint through the index, or a mint the adopted
    /// authority checkpoint carries (module docs).
    ///
    /// # Errors
    /// A store or fold failure.
    pub(crate) fn agent_grant_ever_named_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
    ) -> Result<bool> {
        let mut mints = Vec::new();
        for posting in MEMBER_INDEX.iter_from(&self.store, txn, member.as_bytes())? {
            let ((posted_member, _grant, hash), ()) = posting?;
            if posted_member == member {
                mints.push(hash);
            }
        }
        if let Some(evidence) = crate::authority::adopted_evidence_in_txn(&self.store, txn)? {
            mints.extend(
                evidence
                    .bodies()
                    .iter()
                    .filter(|(_, entry)| {
                        owner_agent_mint(entry).is_some_and(|(named, _grant)| named == member)
                    })
                    .map(|(hash, _)| *hash),
            );
        }
        if mints.is_empty() {
            return Ok(false);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(mints.iter().any(|hash| fold.valid_entries.contains(hash)))
    }
}

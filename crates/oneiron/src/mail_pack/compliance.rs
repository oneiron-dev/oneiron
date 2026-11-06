//! Org compliance search over mail (owner MAIL-SHARE = A, 2026-11-03): an
//! org admin setting, off by default, every use logged. While it is off no
//! one reads across mailboxes, the vault's Owner included. The vault's Owner
//! or an Admin turns it on or off; each change, and each search made under
//! it, is kept in the compliance log before the search answers anything. A
//! search the log cannot record answers nothing.

use serde::{Deserialize, Serialize};

use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The setting; absent reads off.
const SETTING: SideTable<(), MailComplianceSettingRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_COMPLIANCE_SETTING);
/// The compliance log, by sequence.
const LOG: SideTable<u64, MailComplianceEventRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_COMPLIANCE_EVENT);

/// The longest purpose a change or a search records.
const MAX_PURPOSE_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailComplianceSettingRow {
    enabled: bool,
    set_by: Option<EntityId>,
    set_at: u64,
}

/// What one compliance log entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailComplianceEventKind {
    Enabled,
    Disabled,
    /// One search across mailboxes, made while the setting was on.
    Search,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailComplianceEventRow {
    kind: MailComplianceEventKind,
    by: Option<EntityId>,
    at: u64,
    purpose: String,
    /// A search's BLAKE3 of its query, 64-hex: the log keeps that the
    /// search ran and what it matched, not the words searched.
    query_digest: Option<String>,
    result_count: Option<u64>,
}

/// The setting as anyone in the vault reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSettingView {
    pub enabled: bool,
    /// Who last changed it, 32-hex; absent if it was never set, or once that
    /// actor was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_at: Option<u64>,
}

/// `vault.mail.compliance.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSetRequest {
    pub enabled: bool,
    /// Why, in the setter's words; kept in the compliance log.
    pub purpose: String,
}

/// One compliance log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceEventView {
    pub sequence: u64,
    pub kind: MailComplianceEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_ref: Option<String>,
    pub at: u64,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_count: Option<u64>,
}

fn valid_purpose(purpose: &str) -> MemoryResult<()> {
    if purpose.trim().is_empty()
        || purpose.len() > MAX_PURPOSE_BYTES
        || purpose.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err(MemoryError::bad_request(
            "a compliance purpose is a short, nonempty statement",
        ));
    }
    Ok(())
}

/// Whether `actor` is the vault's Owner or an Admin, a pen through its
/// PERSON, or the embedded owner of a vault with no authority root.
pub(crate) fn manages_in(vault: &Vault, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<bool> {
    Ok(
        crate::workspace_roster::vault_standing_in(vault, txn, actor)?.is_some()
            || crate::source_audience::embedded_owner_person_in(vault, txn, actor)?.is_some(),
    )
}

/// Whether compliance search is on in `txn`; absent reads off.
pub(crate) fn compliance_search_enabled_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(SETTING
        .get(&vault.store, txn, &())?
        .is_some_and(|row| row.enabled))
}

fn append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &MailComplianceEventRow,
) -> Result<u64> {
    let next = match LOG.iter_rev_from(&vault.store, txn, &[])?.next() {
        Some(last) => last?.0 + 1,
        None => 1,
    };
    LOG.put(&vault.store, txn, &next, row)?;
    Ok(next)
}

/// Records one compliance search in `txn`, before the search answers: who
/// searched, why, the BLAKE3 of the query and how many rows it matched.
/// Refused while the setting is off. Answers the log sequence.
pub(crate) fn record_compliance_search_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    by: EntityId,
    purpose: &str,
    query: &str,
    result_count: u64,
) -> Result<u64> {
    if !compliance_search_enabled_in(vault, txn)? {
        return Err(crate::Error::InvalidConfig(
            "org compliance search is off".into(),
        ));
    }
    append_in_txn(
        vault,
        txn,
        &MailComplianceEventRow {
            kind: MailComplianceEventKind::Search,
            by: Some(by),
            at: crate::unix_seconds_now(),
            purpose: purpose.to_owned(),
            query_digest: Some(blake3::hash(query.as_bytes()).to_hex().to_string()),
            result_count: Some(result_count),
        },
    )
}

impl Memory<'_> {
    /// The org compliance search setting, as anyone in the vault reads it:
    /// whether someone may search across mailboxes right now.
    pub fn mail_compliance_setting(&self) -> MemoryResult<MailComplianceSettingView> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let row = SETTING.get(&vault.store, &txn, &())?;
        Ok(MailComplianceSettingView {
            enabled: row.as_ref().is_some_and(|row| row.enabled),
            set_by_ref: row
                .as_ref()
                .and_then(|row| row.set_by)
                .map(|id| id.to_hex()),
            set_at: row.map(|row| row.set_at),
        })
    }

    /// Turns org compliance search on or off, by the vault's Owner or an
    /// Admin, with the purpose kept in the compliance log. A request that
    /// changes nothing records nothing.
    pub fn mail_compliance_set(
        &self,
        input: &MailComplianceSetRequest,
    ) -> MemoryResult<MailComplianceSettingView> {
        valid_purpose(&input.purpose)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            super::pack::require_pack_active_in(vault, txn)?;
            if !manages_in(vault, txn, actor)? {
                return Err(MemoryError::bad_request(
                    "org compliance search is set by the vault's Owner or an Admin",
                ));
            }
            if compliance_search_enabled_in(vault, txn)? != input.enabled {
                let at = crate::unix_seconds_now();
                SETTING.put(
                    &vault.store,
                    txn,
                    &(),
                    &MailComplianceSettingRow {
                        enabled: input.enabled,
                        set_by: Some(actor),
                        set_at: at,
                    },
                )?;
                append_in_txn(
                    vault,
                    txn,
                    &MailComplianceEventRow {
                        kind: if input.enabled {
                            MailComplianceEventKind::Enabled
                        } else {
                            MailComplianceEventKind::Disabled
                        },
                        by: Some(actor),
                        at,
                        purpose: input.purpose.clone(),
                        query_digest: None,
                        result_count: None,
                    },
                )?;
            }
            Ok(())
        })?;
        self.mail_compliance_setting()
    }

    /// The compliance log, oldest first: every change to the setting and
    /// every search made under it. The vault's Owner and its Admins read it.
    pub fn mail_compliance_log(&self) -> MemoryResult<Vec<MailComplianceEventView>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        if !manages_in(vault, &txn, self.actor())? {
            return Err(MemoryError::not_found("no compliance log for this reader"));
        }
        LOG.iter_from(&vault.store, &txn, &[])?
            .map(|row| {
                let (sequence, row) = row?;
                Ok(MailComplianceEventView {
                    sequence,
                    kind: row.kind,
                    by_ref: row.by.map(|id| id.to_hex()),
                    at: row.at,
                    purpose: row.purpose,
                    query_digest: row.query_digest,
                    result_count: row.result_count,
                })
            })
            .collect()
    }
}

/// An actor's erase takes its id out of the setting and the log (FIX 3520);
/// the entries themselves stay, so the log still shows each change and use.
pub(crate) fn erase_compliance_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if let Some(mut row) = SETTING.get(&vault.store, wtxn, &())?
        && row.set_by == Some(*actor)
    {
        row.set_by = None;
        SETTING.put(&vault.store, wtxn, &(), &row)?;
    }
    let entries = LOG.scan(&vault.store, wtxn)?;
    for (sequence, mut row) in entries {
        if row.by == Some(*actor) {
            row.by = None;
            LOG.put(&vault.store, wtxn, &sequence, &row)?;
        }
    }
    Ok(())
}

/// `vault.mail.compliance.search`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSearchRequest {
    /// The words searched; the log keeps their BLAKE3, not the words.
    pub query: String,
    /// Why, in the searcher's words; kept in the compliance log.
    pub purpose: String,
    /// How many messages at most; 50 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One message a compliance search found, across mailboxes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceHit {
    pub source_ref: String,
    pub thread_ref: String,
    pub message_ref: String,
    pub score: f32,
    /// The message's words as the vault holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// What a compliance search answered, after its log entry was kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSearchReply {
    /// The compliance log entry this search wrote before answering.
    pub log_sequence: u64,
    pub hits: Vec<MailComplianceHit>,
}

impl Memory<'_> {
    /// Org compliance search across every mailbox (owner MAIL-SHARE = A):
    /// while the setting is on, the vault's Owner or an Admin searches the
    /// mail the vault holds, whoever's mailbox it is. The search is logged
    /// (who, when, why, the query's BLAKE3 and how many messages it found)
    /// before anything is answered; a search the log cannot record answers
    /// nothing. This is the one read across mailboxes; it grants no lasting
    /// read of any of them.
    pub fn mail_compliance_search(
        &self,
        input: &MailComplianceSearchRequest,
    ) -> MemoryResult<MailComplianceSearchReply> {
        valid_purpose(&input.purpose)?;
        if input.query.trim().is_empty() {
            return Err(MemoryError::bad_request(
                "a compliance search names its words",
            ));
        }
        let limit = input.limit.unwrap_or(50).max(1) as usize;
        let vault = self.vault();
        let actor = self.actor();
        let hits = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            super::pack::require_pack_active_in(vault, &txn)?;
            if !manages_in(vault, &txn, actor)? || !compliance_search_enabled_in(vault, &txn)? {
                return Err(MemoryError::bad_request(
                    "org compliance search is off, or the caller is not the vault's Owner or an Admin",
                ));
            }
            vault.ensure_text_index_trusted()?;
            let sources = super::inbox::sources_by_audience_in(vault, &txn)?;
            let config = crate::config::Bm25RankProfile::default()
                .to_bm25_config()
                .map_err(crate::Error::from)?;
            let mut mail_bound = |id: &EntityId| -> Result<bool> {
                Ok(crate::source_audience::binding_in(vault, &txn, id)?.is_some())
            };
            let scored = crate::bm25::search_text_scoped_with_recency(
                &vault.store,
                &txn,
                &vault.analyzer,
                &config,
                &input.query,
                limit,
                crate::bm25::Bm25SearchOptions {
                    recency: None,
                    exact_posting_matches_scope: &mut mail_bound,
                    private_note_ids: None,
                },
            )?;
            let mut hits = Vec::new();
            for scored in scored {
                let id = scored.id;
                if crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &id)?
                    .deleted
                    || vault.get_entity_type_in_txn(&txn, &id)?
                        != Some(crate::registry::ENTITY_TYPE_MESSAGE)
                {
                    continue;
                }
                let Some(thread) = crate::source_audience::binding_in(vault, &txn, &id)? else {
                    continue;
                };
                let Some((source_policy, _)) =
                    crate::source_audience::thread_shares_in(vault, &txn, &thread)?
                else {
                    continue;
                };
                let Some((source, _)) = sources.get(&source_policy) else {
                    continue;
                };
                let turn = crate::conversation_dag::counted_edge_ids(
                    &vault.store,
                    &txn,
                    &id,
                    crate::EdgeKind::PartOf,
                    false,
                )?
                .into_iter()
                .next();
                let conversation = match turn {
                    Some(turn) => crate::conversation_dag::counted_edge_ids(
                        &vault.store,
                        &txn,
                        &turn,
                        crate::EdgeKind::ChildOf,
                        false,
                    )?
                    .into_iter()
                    .next(),
                    None => None,
                };
                let text = match turn {
                    Some(turn) => crate::tagging::message_text_in_txn(vault, &txn, &turn, &id)?,
                    None => None,
                };
                hits.push(MailComplianceHit {
                    source_ref: source.to_hex(),
                    thread_ref: conversation.map(|id| id.to_hex()).unwrap_or_default(),
                    message_ref: id.to_hex(),
                    score: scored.score,
                    text,
                });
            }
            hits
        };
        let count = hits.len() as u64;
        let log_sequence = vault.with_write_txn_grouped(|txn| {
            if !manages_in(vault, txn, actor)? {
                return Err(crate::Error::InvalidConfig(
                    "the searcher is no longer the vault's Owner or an Admin".into(),
                ));
            }
            record_compliance_search_in_txn(vault, txn, actor, &input.purpose, &input.query, count)
        })?;
        Ok(MailComplianceSearchReply { log_sequence, hits })
    }
}

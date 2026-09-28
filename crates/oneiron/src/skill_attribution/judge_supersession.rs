//! Judge-revision provenance for routed receipts, and non-destructive displacement.

use super::{attribution_judgments, projector::attribution_judgments_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// The judge revision that routed one judgment, stamped once. Key: evidence sequence.
const JUDGE_REVISION: SideTable<u64, JudgeProvenance, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_JUDGE_REVISION);

/// A routed judgment whose judge was displaced: the replacement revision. Key: evidence sequence.
const DISPLACED_JUDGE: SideTable<u64, DisplacedMarker, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_DISPLACED_JUDGE);

/// The fence on a displaced judge revision: its replacement revision. Key: the displaced
/// revision's text.
const REVISION_FENCE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_DISPLACED_REVISION);

/// [`JUDGE_REVISION`]'s row: the revision as UTF-8. A row that is not UTF-8 is corrupt
/// provenance, as it always read.
struct JudgeProvenance(String);

impl RawValue for JudgeProvenance {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        String::from_utf8(bytes.to_vec())
            .map(Self)
            .map_err(|_| Error::CorruptedIndex("displaced judge provenance").into())
    }
}

/// [`DISPLACED_JUDGE`]'s row: the replacement revision as UTF-8.
struct DisplacedMarker(String);

impl RawValue for DisplacedMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        String::from_utf8(bytes.to_vec())
            .map(Self)
            .map_err(|_| Error::CorruptedIndex("displaced judge marker").into())
    }
}

pub(crate) fn ensure_current_attribution_judge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision: &str,
) -> Result<()> {
    if REVISION_FENCE.contains(&vault.store, txn, &revision.to_owned())? {
        return Err(Error::InvalidClaimBody(
            "attribution judge revision was displaced",
        ));
    }
    Ok(())
}

pub(super) fn stamp_judge_revision(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sequence: u64,
    revision: &str,
) -> Result<()> {
    if revision.is_empty() || revision.len() > 256 || revision.chars().any(char::is_control) {
        return Err(Error::InvalidClaimBody(
            "invalid attribution judge revision",
        ));
    }
    if let Some(held) = JUDGE_REVISION.get(&vault.store, txn, &sequence)? {
        if held.0 != revision {
            return Err(Error::InvalidClaimBody(
                "attribution judgment cannot be rescored by a new judge",
            ));
        }
        return Ok(());
    }
    JUDGE_REVISION.put(
        &vault.store,
        txn,
        &sequence,
        &JudgeProvenance(revision.to_owned()),
    )
}

pub(crate) fn judgment_displaced(vault: &Vault, sequence: u64) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    judgment_displaced_in_txn(vault, &txn, sequence)
}

pub(crate) fn judgment_displaced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sequence: u64,
) -> Result<bool> {
    DISPLACED_JUDGE.contains(&vault.store, txn, &sequence)
}

/// One old judge's retained receipt. The original judgment and attempt receipt
/// remain readable; the replacement identity is a marker, never a rescore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplacedJudgeReceipt {
    pub judgment_sequence: u64,
    pub receipt_ref: String,
    pub displaced_revision: String,
    pub replacement_revision: String,
}

/// Reads marked receipts without deleting or reinterpreting their verdicts.
pub fn displaced_judge_receipts(vault: &Vault) -> Result<Vec<DisplacedJudgeReceipt>> {
    let judgments = attribution_judgments(vault)?;
    let txn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for judgment in judgments {
        let Some(DisplacedMarker(replacement_revision)) =
            DISPLACED_JUDGE.get(&vault.store, &txn, &judgment.sequence)?
        else {
            continue;
        };
        let JudgeProvenance(displaced_revision) = JUDGE_REVISION
            .get(&vault.store, &txn, &judgment.sequence)?
            .ok_or(Error::CorruptedIndex("displaced judge provenance"))?;
        for receipt_ref in &judgment.evidence_receipts {
            rows.push(DisplacedJudgeReceipt {
                judgment_sequence: judgment.sequence,
                receipt_ref: receipt_ref.clone(),
                displaced_revision: displaced_revision.clone(),
                replacement_revision: replacement_revision.clone(),
            });
        }
    }
    Ok(rows)
}

/// Marks exactly the verdicts by the displaced judge revision. The original
/// receipt/judgment/outcome rows stay intact; active posterior projections
/// omit only their superseded weight. Repeating the swap is idempotent.
pub fn supersede_displaced_judge_receipts(
    vault: &Vault,
    displaced: &str,
    replacement: &str,
    at: u64,
) -> Result<Vec<DisplacedJudgeReceipt>> {
    if displaced == replacement
        || displaced.is_empty()
        || replacement.is_empty()
        || displaced.len() > 256
        || replacement.len() > 256
        || displaced.chars().any(char::is_control)
        || replacement.chars().any(char::is_control)
    {
        return Err(Error::InvalidClaimBody("invalid judge replacement"));
    }
    let mut affected: Vec<(EntityId, Option<String>)> = Vec::new();
    #[cfg(test)]
    PRE_WRITER_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
    vault.with_write_txn(|txn| {
        // Scan on the same writer snapshot that installs the fence. A J1
        // verdict committed before this lock is present here; one committed
        // afterward is refused by the revision fence in its own writer.
        let judgments = attribution_judgments_in_txn(vault, txn)?;
        let fence = displaced.to_owned();
        if let Some(held) = REVISION_FENCE.get(&vault.store, txn, &fence)? {
            if held != replacement {
                return Err(Error::InvalidClaimBody(
                    "attribution judge already displaced by another revision",
                ));
            }
        } else {
            REVISION_FENCE.put(&vault.store, txn, &fence, &replacement.to_owned())?;
        }
        for judgment in &judgments {
            let origin = JUDGE_REVISION.get(&vault.store, txn, &judgment.sequence)?;
            if origin.as_ref().map(|origin| origin.0.as_str()) != Some(displaced) {
                continue;
            }
            if let Some(held) = DISPLACED_JUDGE.get(&vault.store, txn, &judgment.sequence)? {
                if held.0 != replacement {
                    return Err(Error::InvalidClaimBody("judge verdict already displaced"));
                }
            } else {
                DISPLACED_JUDGE.put(
                    &vault.store,
                    txn,
                    &judgment.sequence,
                    &DisplacedMarker(replacement.to_owned()),
                )?;
            }
            // Also re-project on a repeated call: a crash after committing the
            // marker but before projecting must not strand a stale active claim.
            if judgment.verdict == super::AttributionVerdict::SkillDefect {
                let Some(receipt_ref) = judgment.evidence_receipts.first() else {
                    continue;
                };
                let executor =
                    crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, receipt_ref)?
                        .and_then(|receipt| {
                            receipt
                                .fields
                                .get("model")
                                .filter(|id| !id.is_empty())
                                .cloned()
                        });
                crate::skill_reliability::mark_displaced_outcome_in_txn(
                    vault,
                    txn,
                    &judgment.subject,
                    executor.as_deref(),
                    receipt_ref,
                    displaced,
                    replacement,
                )?;
                let pair = (judgment.subject, executor);
                if !affected.contains(&pair) {
                    affected.push(pair);
                }
            }
        }
        Ok(())
    })?;
    for (skill, executor) in affected {
        match executor {
            Some(model) => {
                crate::skill_reliability::project_skill_reliability_for_executor(
                    vault, &skill, &model, at,
                )?;
            }
            None => {
                crate::skill_reliability::project_skill_reliability_for(vault, &skill, at)?;
            }
        }
    }
    Ok(displaced_judge_receipts(vault)?
        .into_iter()
        .filter(|row| {
            row.displaced_revision == displaced && row.replacement_revision == replacement
        })
        .collect())
}

#[cfg(test)]
thread_local! {
    static PRE_WRITER_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_pre_writer_hook(hook: Box<dyn FnOnce()>) {
    PRE_WRITER_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

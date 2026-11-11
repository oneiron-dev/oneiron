//! A hook's regen history (ARCH-0080 §8, FIX 4691): one receipt for every
//! regen decision and every enactment of one, kept per hook (its pack and
//! name) so the history reads across the rebind an adoption makes. A
//! receipt names bodies by hash and keeps a decision's golden manifest; it
//! never holds a body's text.

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::PackHookBinding;
// No bare `Result` import: schemars' JsonSchema derive writes an unqualified
// `Result<_, S::Error>` for a defaulted field, which the crate alias breaks.
use crate::{EntityId, Error, Vault};

use super::{
    HookContractStamp, HookGoldenDiff, HookGoldenManifest, HookRegenFailure, HookRegenOutcome,
};

/// Every regen receipt of one hook, in order. Key: hash32 (the hook's pack
/// and name, [`hook_key`]) + u64be (its sequence within the hook).
const RECEIPTS: SideTable<([u8; 32], u64), HookRegenReceipt, Named> =
    SideTable::new(&side_table::HOOKS_REGEN_RECEIPT);

/// The receipts one history read returns at most.
pub const MAX_HOOK_REGEN_HISTORY: usize = 256;

/// Whether a masked copy of a `HOOKS_REGEN_RECEIPT` row still decodes as its
/// typed value, for the historical lift sweep (FIX 2680).
pub(crate) fn hooks_regen_receipt_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<HookRegenReceipt, Named>(bytes)
}

/// Who ran or enacted a regen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum HookRegenActor {
    /// The engine's own pass after a verb-table or sandbox-contract change.
    Engine,
    /// The vault's owner, on any hook of the vault's own packs.
    Owner {
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        actor: EntityId,
    },
    /// A resident agent, on a hook it authored.
    Agent {
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        agent: EntityId,
    },
}

/// What a regen decided, as its receipt keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookRegenDecision {
    AutoAdopt,
    NeedsHumanStamp,
    RolledBack,
}

/// One step in a hook's regen history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HookRegenEvent {
    /// A regen ran and decided: the candidate it holds, the contract it ran
    /// against, and the golden manifest and diff it stood on. A failed regen
    /// keeps its failure and no candidate.
    Decided {
        decision: HookRegenDecision,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_hash: Option<String>,
        target: HookContractStamp,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        diff: Option<HookGoldenDiff>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        golden: Option<HookGoldenManifest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<HookRegenFailure>,
    },
    /// A pending candidate was installed as the hook's body. `stamped` says
    /// the owner's stamp enacted it; an identical fingerprint needs none.
    Adopted {
        candidate_hash: String,
        target: HookContractStamp,
        stamped: bool,
        /// The binding the new body bound under, when it is a new id.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::serialize::entity_ref::optional"
        )]
        #[schemars(with = "Option<String>")]
        rebound: Option<EntityId>,
    },
    /// A waiting decision was set aside unenacted; the hook stays on its
    /// body, and the contract it targeted is declined.
    Cancelled {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_hash: Option<String>,
        declined: HookContractStamp,
    },
    /// An adoption was reverted by hand: the body it replaced is the hook's
    /// body again, and the contract in force is declined.
    Reverted {
        /// The adopted body taken out.
        from_hash: String,
        /// The body put back.
        to_hash: String,
        declined: HookContractStamp,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::serialize::entity_ref::optional"
        )]
        #[schemars(with = "Option<String>")]
        rebound: Option<EntityId>,
    },
}

impl HookRegenEvent {
    /// The receipt event of a regen decision.
    pub(super) fn decided(outcome: &HookRegenOutcome) -> Self {
        match outcome {
            HookRegenOutcome::AutoAdopt {
                target,
                diff,
                golden,
                ..
            }
            | HookRegenOutcome::NeedsHumanStamp {
                target,
                diff,
                golden,
                ..
            } => Self::Decided {
                decision: if matches!(outcome, HookRegenOutcome::AutoAdopt { .. }) {
                    HookRegenDecision::AutoAdopt
                } else {
                    HookRegenDecision::NeedsHumanStamp
                },
                candidate_hash: outcome.candidate_hash(),
                target: target.clone(),
                diff: Some(diff.clone()),
                golden: Some(golden.clone()),
                failure: None,
            },
            HookRegenOutcome::RolledBack { failure, target } => Self::Decided {
                decision: HookRegenDecision::RolledBack,
                candidate_hash: None,
                target: target.clone(),
                diff: None,
                golden: None,
                failure: Some(failure.clone()),
            },
        }
    }
}

/// One regen receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenReceipt {
    /// Its place in the hook's history, from 0.
    pub sequence: u64,
    /// The binding the event acted on.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    /// When it was recorded, in the vault clock's seconds.
    pub recorded_at: u64,
    pub actor: HookRegenActor,
    /// The hook's last good body once the event stood, as BLAKE3 hex.
    pub body_hash: String,
    pub event: HookRegenEvent,
}

/// A hook's history key: BLAKE3 of its pack and name, which a rebind keeps.
fn hook_key(pack: &str, hook: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pack.as_bytes());
    hasher.update(&[0]);
    hasher.update(hook.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Appends one receipt to `row`'s hook history in the acting writer.
pub(super) fn append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    row: &PackHookBinding,
    body_hash: &str,
    actor: &HookRegenActor,
    event: HookRegenEvent,
) -> crate::Result<()> {
    let key = hook_key(&row.pack, &row.hook);
    let sequence = {
        let mut newest = RECEIPTS.iter_rev_from(&vault.store, txn, &key)?;
        match newest.next().transpose()? {
            Some(((_, sequence), _)) => sequence.checked_add(1).ok_or(Error::CorruptedIndex(
                "a hook regen history is out of sequence numbers",
            ))?,
            None => 0,
        }
    };
    RECEIPTS.put(
        vault,
        txn,
        &(key, sequence),
        &HookRegenReceipt {
            sequence,
            binding,
            recorded_at: vault.store.clock.now_recorded_at(),
            actor: actor.clone(),
            body_hash: body_hash.to_owned(),
            event,
        },
    )
}

impl Vault {
    /// `binding`'s hook regen history, newest first, at most `limit`
    /// receipts (capped at [`MAX_HOOK_REGEN_HISTORY`]); `before` pages back
    /// from a receipt's sequence. It reads across the hook's rebinds.
    ///
    /// # Errors
    ///
    /// An unknown binding, and storage errors.
    pub fn hook_regen_history(
        &self,
        binding: EntityId,
        before: Option<u64>,
        limit: usize,
    ) -> crate::Result<Vec<HookRegenReceipt>> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        let key = hook_key(&row.pack, &row.hook);
        let limit = limit.min(MAX_HOOK_REGEN_HISTORY);
        let rtxn = self.store.env.read_txn()?;
        let mut receipts = Vec::new();
        for item in RECEIPTS.iter_rev_from(&self.store, &rtxn, &key)? {
            if receipts.len() >= limit {
                break;
            }
            let ((_, sequence), receipt) = item?;
            if before.is_some_and(|before| sequence >= before) {
                continue;
            }
            receipts.push(receipt);
        }
        Ok(receipts)
    }
}

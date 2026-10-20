//! FIX 6424 part 2a (Engine 10-20 21:0x ruling 8, CALLS `FIX 6424 pinned
//! Pending proof retention`): the owner's one-send press a Linear dispatch's
//! or a campaign leg's first admission spent, kept beside its ledger row.
//!
//! The row's own `admitted_approval` field keeps native mail's, e-sign's and
//! a failure-signal batch's proof, validated by recomposing its digest from
//! the frozen payload for the row's server and tool. A campaign leg rides
//! any channel (email among them) on its program's raw body, so that check
//! cannot name it, and a Linear dispatch freezes no pinned send ref; this
//! table keeps their press apart, filed under the family its pinned target
//! names, and leaves that field, its codec and its validation untouched.
//!
//! The press is written in the admission writer that spends it and inserts
//! the Pending row. A retry of that row reads it under the same retry
//! context; the Gate reuses it only while the retry's own pinned digest is
//! the kept one. A row that does not read leaves the retry on its existing
//! path, as before this table.

use super::types::{AdmittedApproval, IntentId, IntentLedgerError};
use crate::Vault;
use crate::gate::ExternalEffectGateInput;
use crate::side_table::{self, Raw, SideTable};

/// The kept press's row layout version.
const PINNED_APPROVAL_VERSION: u8 = 1;

/// Intent id → version, family tag, then the spent press's 32-byte digest.
const PINNED_APPROVAL: SideTable<IntentId, [u8; 34], Raw> =
    SideTable::new(&side_table::OUTBOUND_PINNED_APPROVAL);

/// The family a kept press is filed under, named by the pinned target of the
/// effect whose admission spent it, never by the row's connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PinnedApprovalFamily {
    /// A Linear issue mutation through the outbound dispatch door.
    LinearDispatch,
    /// A campaign enrollment's outbound leg.
    CampaignLeg,
}

impl PinnedApprovalFamily {
    const fn tag(self) -> u8 {
        match self {
            Self::LinearDispatch => 1,
            Self::CampaignLeg => 2,
        }
    }
}

/// One spent press of a pinned family, as its admission selected it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PinnedApproval {
    family: PinnedApprovalFamily,
    proof: AdmittedApproval,
}

impl PinnedApproval {
    pub(crate) const fn new(family: PinnedApprovalFamily, proof: AdmittedApproval) -> Self {
        Self { family, proof }
    }
}

/// Keeps `approval` beside its Pending row, in the admission writer that
/// spends it. `None` keeps nothing.
///
/// # Errors
/// A storage failure of that writer.
pub(crate) fn keep_pinned_approval_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    approval: Option<PinnedApproval>,
) -> Result<(), IntentLedgerError> {
    let Some(approval) = approval else {
        return Ok(());
    };
    let mut value = [0_u8; 34];
    value[0] = PINNED_APPROVAL_VERSION;
    value[1] = approval.family.tag();
    value[2..].copy_from_slice(approval.proof.effect_digest().as_bytes());
    PINNED_APPROVAL.put(&vault.store, wtxn, &approval.proof.intent_id(), &value)?;
    Ok(())
}

/// The press `intent_id`'s first admission spent, kept for a retry whose
/// live `effect` pins the same family. `None` for none kept, another family,
/// or a row that does not read: that retry stays on its existing path.
pub(crate) fn pinned_retry_approval(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent_id: IntentId,
    effect: &ExternalEffectGateInput,
) -> Option<AdmittedApproval> {
    let family = effect
        .provenance
        .approval_target
        .as_ref()?
        .pinned_family()?;
    let value = PINNED_APPROVAL
        .get(&vault.store, txn, &intent_id)
        .ok()
        .flatten()?;
    if value[0] != PINNED_APPROVAL_VERSION || value[1] != family.tag() {
        return None;
    }
    let digest: [u8; 32] = value[2..].try_into().ok()?;
    Some(AdmittedApproval::from_gate(
        intent_id,
        crate::consent::EffectDigest::from_bytes(digest),
    ))
}

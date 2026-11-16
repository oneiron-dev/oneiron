//! Value-free owner decisions on code-run secret lift proposals.
//! Dismissing a proposal never clears its occurrence's secret or taint marks.

use heed::RoTxn;

use super::super::replay::ResultOccurrence;
use super::records::{CodeRunSecretLiftProposal, RAW_OUTPUT_SECRETS, lift_proposal};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{Error, Result, Vault};

mod room;
pub use room::CodeRunRoomSecretLiftRequest;

const DISMISSED: SideTable<String, CodeRunSecretLiftDismissal, Named> =
    SideTable::new(&side_table::CODE_RUN_SECRET_LIFT_DISMISSED);
const CONTENT_KIND: &str = "code_run_secret_lift";
const DISMISSED_REASON: &str = "gate.code_run.secret_lift_dismissed";

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::storage::secret_lift::{
    CodeRunSecretLiftDismiss, CodeRunSecretLiftDismissal, CodeRunSecretLiftProposalView,
    CodeRunSecretLiftRequest, CodeRunSecretLiftStatus,
};

impl From<CodeRunSecretLiftProposal> for CodeRunSecretLiftProposalView {
    fn from(proposal: CodeRunSecretLiftProposal) -> Self {
        Self {
            handle: proposal.handle,
            occurrence: proposal.occurrence.id().to_hex(),
            detector_reason: proposal.detector_reason,
            suggested_secret_name: proposal.suggested_secret_name,
        }
    }
}

impl Vault {
    /// The native list in the caller's snapshot. Dismissal hides only the
    /// proposal; every body reader keeps consulting the original marks.
    pub(super) fn code_run_secret_lift_proposals_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<CodeRunSecretLiftProposal>> {
        let mut proposals = Vec::new();
        for (key, reason) in RAW_OUTPUT_SECRETS.scan(&self.store, txn)? {
            if !DISMISSED.contains(&self.store, txn, &key)? {
                proposals.push(lift_proposal(&key, reason)?);
            }
        }
        Ok(proposals)
    }

    /// The owner's list and optional proposal-only dismissal, under a live
    /// owner proof rechecked in the same transaction as the decision. A
    /// repeated dismissal returns its original receipt. Neither dismissal
    /// nor listing changes any secret, taint, body, export or read gate.
    ///
    /// # Errors
    /// Storage errors, an invalid occurrence id, an absent proposal, or an
    /// owner proof that no longer holds.
    pub fn code_run_secret_lifts_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &CodeRunSecretLiftRequest,
    ) -> Result<CodeRunSecretLiftStatus> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let dismissed = if let Some(request) = &request.dismiss {
            let key = format!("{}/{}", request.handle, request.occurrence);
            let (handle, occurrence) = ResultOccurrence::parse_mark_key(&key)?;
            let key = occurrence.mark_key(handle);
            if !RAW_OUTPUT_SECRETS.contains(&self.store, &txn, &key)? {
                return Err(Error::EntityNotFound);
            }
            let dismissal = match DISMISSED.get(&self.store, &txn, &key)? {
                Some(dismissal) => dismissal,
                None => {
                    let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
                    let at = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
                    let dismissal = CodeRunSecretLiftDismissal {
                        handle: handle.to_owned(),
                        occurrence: occurrence.id().to_hex(),
                        dismissed_by: actor.to_hex(),
                        dismissed_at: at,
                        receipt: format!("gate:{}", decision_id.to_hex()),
                    };
                    let record = GateDecisionRecord {
                        version: GATE_DECISION_LEDGER_VERSION,
                        decision_id,
                        created_at: at,
                        outcome: "approved".into(),
                        reason_codes: vec![DISMISSED_REASON.into()],
                        receipt_reasons: Vec::new(),
                        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                            CONTENT_KIND,
                            vec![format!(
                                "proposal:{}",
                                blake3::hash(key.as_bytes()).to_hex()
                            )],
                        ),
                        actor_class: "human".into(),
                        actor_ref: Some(actor.to_hex()),
                        content_kind: CONTENT_KIND.into(),
                        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                        claim_id: None,
                        grant_ref: None,
                        diff_handle: blake3::hash(key.as_bytes()).as_bytes().to_vec(),
                        read_frontier_hash: [0; 32],
                        context: Default::default(),
                        redacted_at: None,
                    };
                    self.store.append_gate_decision_in_txn(&mut txn, &record)?;
                    DISMISSED.put(&self.store, &mut txn, &key, &dismissal)?;
                    dismissal
                }
            };
            Some(dismissal)
        } else {
            None
        };
        let proposals = self
            .code_run_secret_lift_proposals_in_txn(&txn)?
            .into_iter()
            .map(CodeRunSecretLiftProposalView::from)
            .collect();
        txn.commit()?;
        Ok(CodeRunSecretLiftStatus {
            proposals,
            dismissed,
        })
    }
}

/// Drops one retired occurrence's marks and its proposal-only decision.
/// The caller has already proved this exact occurrence is being retired.
pub(crate) fn drop_code_run_result_marks_in_txn(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    key: &String,
) -> Result<()> {
    super::records::RAW_OUTPUT_TAINTS.delete(dbs, txn, key)?;
    RAW_OUTPUT_SECRETS.delete(dbs, txn, key)?;
    DISMISSED.delete(dbs, txn, key)?;
    Ok(())
}

/// Erases the marks of the held occurrences the row being erased owns,
/// read before its descriptors go. The optional MESSAGE source provenance is
/// not an occurrence marker. Other owners' and occurrences' marks stay intact.
pub(crate) fn erase_retained_result_marks_in_txn(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    bodies: &[crate::provenance::body::OwnedBody],
) -> Result<()> {
    for body in bodies {
        let Some(held) = body.state.held() else {
            continue;
        };
        let handle =
            super::super::replay::CodeRunRawOutput::of_ref(crate::compaction::output::OutputRef {
                hash: held.blake3,
                byte_len: held.bytes,
            })
            .handle;
        let key = format!(
            "{}{}",
            ResultOccurrence::marks_prefix(&handle),
            body.occurrence.to_hex()
        );
        drop_code_run_result_marks_in_txn(dbs, txn, &key)?;
    }
    Ok(())
}

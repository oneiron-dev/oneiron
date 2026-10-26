//! The ask a consult interruption's frozen consent case raises (FIX 10692):
//! the human verdict its Finish lands on.
//! Entry: `Memory::raise_case_ask_in`.
//!
//! The case's ask goes to every vault owner but the case's opener, on the
//! consult's own question and context refs, governed by the consult, and is
//! kept under the case ref, the group the consult's Finish reads. Only the
//! engine names that group; no caller supplies it. Its intent names the id
//! this node derives for the case, so only the admitting node settles it, as
//! every ask is settled by the node that admitted it. The ask carries refs
//! and no text, so a session that keeps no record raises it too, as it keeps
//! the case (Engine 10-26, FIX 10694).
//!
//! It is raised in a savepoint of the interruption's writer, and again on a
//! later consent-required interruption: an ask that does not land is logged
//! and leaves the interruption as it is and its Finish unverified, as
//! before, and one that landed stands as it is. With no owner but the
//! opener, nothing is raised.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::{
    ConsultPayload, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
};

use super::super::ask_record;
use super::finish::frozen_case_in;

/// What every case ask's intent key starts with:
/// `consult_case/<case ref hex>/<anchor hex>`, the anchor the id this node
/// derives for `consult_case/<case ref hex>`.
const INTENT_PREFIX: &str = "consult_case/";

/// The case intent of `case_ref`, which a case ask's anchor is derived for.
fn case_intent(case_ref: EntityId) -> String {
    format!("{INTENT_PREFIX}{}", case_ref.to_hex())
}

/// The case intent and anchor `intent_key` names when it is the intent of
/// the case ask kept under `id`; `None` for every other ask.
pub(in crate::task_verb) fn case_ask_anchor(
    intent_key: &str,
    id: EntityId,
) -> Option<(String, EntityId)> {
    let (case_hex, anchor_hex) = intent_key.strip_prefix(INTENT_PREFIX)?.split_once('/')?;
    let case_ref = EntityId::from_hex(case_hex).ok()?;
    let anchor = EntityId::from_hex(anchor_hex).ok()?;
    let intent = case_intent(case_ref);
    (case_ref == id && format!("{intent}/{}", anchor.to_hex()) == intent_key)
        .then_some((intent, anchor))
}

impl Memory<'_> {
    /// The credential chains this handle's caller presented, read in `txn`
    /// (FIX 10693): the lineage a case freezes for its opener, whose words
    /// and forks settle nothing for it. A handle that presented none has
    /// none; chains that do not read are logged, and the case freezes none,
    /// as before.
    pub(super) fn opener_lineage_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Vec<[u8; 32]> {
        let Some(credential) = self.presented_credential() else {
            return Vec::new();
        };
        self.vault()
            .slip_lineage_in_txn(txn, credential)
            .unwrap_or_else(|_| {
                tracing::warn!(
                    task = %task_ref.to_hex(),
                    "a consult case opener's credential lineage did not read; the case freezes none"
                );
                Vec::new()
            })
    }

    /// Raises the ask of `task_ref`'s frozen consent case in a savepoint of
    /// `wtxn`, the interruption's writer (module docs). `consult` is the
    /// consult's payload and `deadline_at` its deadline, which the ask
    /// takes when it is still ahead. Never fails the interruption.
    pub(super) fn raise_case_ask_in(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        consult: Option<&ConsultPayload>,
        deadline_at: Option<u64>,
    ) {
        let Some(consult) = consult else {
            return;
        };
        if let Err(error) = self.case_ask_in(wtxn, task_ref, consult, deadline_at) {
            tracing::warn!(
                task = %task_ref.to_hex(),
                code = %error.code,
                "a consult consent case's ask was not raised; its Finish stays unverified"
            );
        }
    }

    fn case_ask_in(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        consult: &ConsultPayload,
        deadline_at: Option<u64>,
    ) -> MemoryResult<()> {
        let Some(case) = frozen_case_in(self.vault(), &*wtxn, task_ref)? else {
            return Ok(());
        };
        // One raised earlier stands as it is.
        if ask_record::read_group(self.vault(), &*wtxn, case.case_ref)?.is_some() {
            return Ok(());
        }
        let mut savepoint = self
            .vault()
            .store
            .env
            .nested_write_txn(wtxn)
            .map_err(crate::Error::from)?;
        let owners: BTreeSet<EntityId> =
            crate::policy_model::owners_in_txn(self.vault(), &savepoint)?
                .into_iter()
                .filter(|owner| Some(*owner) != case.opener)
                .collect();
        if owners.is_empty() {
            return Ok(());
        }
        let now = self.vault().store.clock.now_recorded_at();
        let anchor = ask_record::group_id(
            self.vault(),
            &mut savepoint,
            self.actor(),
            &case_intent(case.case_ref),
        )?;
        let mut what = TaskAskQuestion::new(consult.question_ref);
        what.context_refs.clone_from(&consult.context_refs);
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(owners)),
            what,
            deadline_at.filter(|deadline| *deadline > now),
            TaskAskDefault::Hold,
        );
        spec.intent_key = format!("{}/{}", case_intent(case.case_ref), anchor.to_hex());
        spec.task_ref = Some(task_ref);
        self.tasks_ask_for_case_in_txn(&mut savepoint, &spec, case.case_ref)?;
        savepoint.commit().map_err(crate::Error::from)?;
        Ok(())
    }
}

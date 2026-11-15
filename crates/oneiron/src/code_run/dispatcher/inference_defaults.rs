//! Governed reads and changes of the resident's inference defaults.
//! Entry: `HostSelfDispatcher::dispatch_inference_defaults`.
//! Default-table definitions belong to `llm`; dispatcher state stays in `code_run::dispatcher`.

use super::*;

/// The reason a change through the app's `inference.defaults.replace` action gives.
const REPLACE_ACTION: &str = "inference.defaults.replace";

impl HostSelfDispatcher<'_> {
    /// The defaults in force, after `replacement` (a whole table as JSON) went through the
    /// setting door `models.purpose_defaults`, when one is given. A host-authenticated owner's
    /// proof makes the change the owner's (WILL-PLAN L13 row 01); without one it is the resident
    /// agent's, which the key's power judges: an agent holding the key's Grant line narrows it at
    /// once, and anyone else's change asks. A change that asks answers
    /// `{"pending": "<check-in>"}`, and the defaults stay as they are.
    pub(super) fn dispatch_inference_defaults(
        &self,
        replacement: Option<&str>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(crate::Error::InvalidConfig(
                "inference defaults require canonical vault".into(),
            ));
        };
        // The shared action registry is not the only caller of SelfDispatcher.
        // Re-check the host-bound actor here so a raw SelfCall cannot bypass
        // the owner's Auto ceiling or a narrowed agent definition.
        crate::code_run::actions::check_ceiling(
            vault,
            self.actor,
            crate::agent_def::AgentCeiling::Auto,
        )?;
        if let Some(json) = replacement {
            let next = crate::llm::PurposeDefaultTable::from_json(json.as_bytes())?;
            #[cfg(test)]
            if let Some(hook) = vault
                .test_hooks()
                .before_resident_defaults_writer
                .lock()
                .expect("resident defaults hook poisoned")
                .take()
            {
                hook(vault);
            }
            let request = crate::setting::SetSetting {
                why: Some(REPLACE_ACTION.to_owned()),
                ..crate::llm::purpose_defaults_change(&next)?
            };
            let caller = match self.owner_proof {
                Some(owner) => crate::setting::SettingCaller::Owner(owner),
                None => crate::setting::SettingCaller::Agent(self.actor.entity_ref()),
            };
            // The check above read its own snapshot. The ceiling is judged again in the write
            // that changes the key, so a narrowing committed in between holds the rows (H147).
            let outcome = vault.with_write_txn_grouped_after_commit(
                |txn| {
                    crate::code_run::actions::check_ceiling_in_txn(
                        vault,
                        txn,
                        self.actor,
                        crate::agent_def::AgentCeiling::Auto,
                    )?;
                    vault.set_setting_in_txn(txn, caller, &request)
                },
                |outcome| {
                    crate::setting::run_after_commit(vault, &[(&request, &outcome)]);
                    Ok(outcome)
                },
            )?;
            if let crate::setting::SetSettingOutcome::Pending { check_in } = outcome {
                return Ok(SelfDispatchOutcome::InferenceDefaults(
                    serde_json::json!({ "pending": check_in }).to_string(),
                ));
            }
        }
        let active = vault.purpose_default_table()?;
        Ok(SelfDispatchOutcome::InferenceDefaults(
            serde_json::to_string(&active)
                .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?,
        ))
    }
}

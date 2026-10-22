//! Governed reads and replacement of resident inference defaults.
//! Entry: `HostSelfDispatcher::dispatch_inference_defaults`.
//! Default-table definitions belong to `llm`; dispatcher state stays in `code_run::dispatcher`.

use super::*;

impl HostSelfDispatcher<'_> {
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
            // The check above read its own snapshot. The setter judges the
            // ceiling again in the transaction that writes, so a narrowing
            // committed in between holds the rows (H147).
            vault.set_resident_purpose_default_table(&next, |txn| {
                crate::code_run::actions::check_ceiling_in_txn(
                    vault,
                    txn,
                    self.actor,
                    crate::agent_def::AgentCeiling::Auto,
                )?;
                // WILL-PLAN L13 row 01: a host-authenticated owner's proof
                // holds in this same transaction, beside the Auto ceiling
                // above, and the owner's act is recorded with the table it
                // replaces.
                if let Some(owner) = self.owner_proof {
                    let actor = crate::dreamer_runner::maintenance::validate_owner_in_txn(
                        vault, txn, owner,
                    )?;
                    let prior = crate::llm::read_effective_defaults(&vault.store, txn)?;
                    crate::policy_setting_doors::record_policy_setting_act_in_txn(
                        vault,
                        txn,
                        crate::policy_setting_doors::PolicySetting::InferenceDefaults,
                        actor,
                        self.owner_surface,
                        prior.table(),
                    )?;
                }
                Ok(())
            })?;
        }
        let active = vault.purpose_default_table()?;
        Ok(SelfDispatchOutcome::InferenceDefaults(
            serde_json::to_string(&active)
                .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?,
        ))
    }
}

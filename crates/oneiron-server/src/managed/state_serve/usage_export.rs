//! Generic original-usage export over ctl (LC191311): read-only managed handler.

use oneiron_vault_contract::{UsageExportCursor, UsageExportPage};

use super::ManagedState;
use crate::managed::ManagedError;

impl ManagedState {
    /// One original usage event's JSON for the meter scope this server bound.
    ///
    /// A read: available under the reap freeze, never through the write gate.
    /// Unbound metering is a read refusal, never an empty page.
    pub(in crate::managed::state_serve) fn usage_export(
        &self,
        cursor: Option<&UsageExportCursor>,
    ) -> Result<UsageExportPage, ManagedError> {
        let Some(meter) = self.server.vault_usage() else {
            return Err(ManagedError::CtlRequestRefused {
                reason: "usage metering unbound".to_owned(),
            });
        };
        self.server
            .usage_ledger
            .export_page(meter.owner(), meter.vault_id(), cursor)
            .map_err(|error| ManagedError::CtlRequestRefused {
                reason: error.to_string(),
            })
    }
}

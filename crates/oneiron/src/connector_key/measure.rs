//! Advisory measurements of a connector key's shape against its `[limits]`
//! rows (FIX 8680, 8685, 8687). They never refuse: past a row's count the
//! installed port is asked whether everything is okay, and the key keeps
//! every budget row, charter cap and catalog verb.
//! Entry: `Vault::measure_connector_key_shape`. Defines its own items.

use crate::Vault;
use crate::limit_ask::EngineLimit;

use super::record::ConnectorKeyRecord;

/// A collection length as a measured count.
fn measured_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

impl Vault {
    /// Measures every counted collection of a finished key record: active
    /// and suggested budget rows, the stamped and the proposed charter's
    /// compiled caps, and the catalog's advertised verbs. Called after the
    /// record's writer commits, so an asking port never runs inside it.
    pub(crate) fn measure_connector_key_shape(&self, record: &ConnectorKeyRecord) {
        self.measure_limit(
            EngineLimit::ConnectorBudgetRows,
            measured_count(record.budgets.len()),
        );
        self.measure_limit(
            EngineLimit::ConnectorSuggestedBudgetRows,
            measured_count(record.suggested_budgets.len()),
        );
        let stamped = record
            .charter
            .as_ref()
            .map(|charter| &charter.compiled.channel_caps);
        let proposed = record
            .pending_charter
            .as_ref()
            .map(|charter| &charter.compiled.channel_caps);
        for caps in stamped.into_iter().chain(proposed) {
            self.measure_limit(
                EngineLimit::ConnectorCharterCaps,
                measured_count(caps.len()),
            );
        }
        if let Some(catalog) = record.catalog.as_ref() {
            self.measure_limit(
                EngineLimit::ConnectorCatalogVerbs,
                measured_count(catalog.verbs.len()),
            );
        }
    }
}

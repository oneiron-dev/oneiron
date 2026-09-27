//! Declared retrieval-telemetry retention rows and restrictive resolution.

use rmpv::Value;

/// The shipped vault ceiling. It is serialized into the default manifest;
/// pruning reads the resolved manifest, never these numbers directly.
pub(crate) const DEFAULT_RETRIEVAL_AGE_SECS: u64 = 7 * 24 * 60 * 60;
pub(crate) const DEFAULT_RETRIEVAL_MAX_RUNS: usize = 1024;
pub(crate) const RETRIEVAL_RETENTION_ROWS_KEY: &str = "retrieval_retention_rows";

/// Local Layer-2 telemetry is sealed to a single account. `holder` means the
/// vault's data holder, not an inferred retrieval actor or a query principal.
/// The precedence row pins the restrictive composition of these two scopes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetrievalRetentionPolicy {
    vault_age_secs: Option<u64>,
    vault_max_runs: Option<usize>,
    holder_age_secs: Option<u64>,
    holder_max_runs: Option<usize>,
}

impl RetrievalRetentionPolicy {
    pub(crate) fn effective(self) -> (u64, usize) {
        let vault_age = self.vault_age_secs.unwrap_or(DEFAULT_RETRIEVAL_AGE_SECS);
        let vault_runs = self.vault_max_runs.unwrap_or(DEFAULT_RETRIEVAL_MAX_RUNS);
        (
            self.holder_age_secs
                .map_or(vault_age, |age| age.min(vault_age)),
            self.holder_max_runs
                .map_or(vault_runs, |runs| runs.min(vault_runs)),
        )
    }

    pub(crate) fn narrow(&mut self, rows: RetrievalRetentionRows) {
        if let Some(age) = rows.vault_age_secs {
            self.vault_age_secs = Some(self.vault_age_secs.map_or(age, |old| old.min(age)));
        }
        if let Some(runs) = rows.vault_max_runs {
            self.vault_max_runs = Some(self.vault_max_runs.map_or(runs, |old| old.min(runs)));
        }
        if let Some(age) = rows.holder_age_secs {
            self.holder_age_secs = Some(self.holder_age_secs.map_or(age, |old| old.min(age)));
        }
        if let Some(runs) = rows.holder_max_runs {
            self.holder_max_runs = Some(self.holder_max_runs.map_or(runs, |old| old.min(runs)));
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RetrievalRetentionRows {
    vault_age_secs: Option<u64>,
    vault_max_runs: Option<usize>,
    holder_age_secs: Option<u64>,
    holder_max_runs: Option<usize>,
}

/// Strict row grammar: one row per scope per pack; duplicate map keys, zero
/// limits, unknown scopes or precedence orders reject the containing manifest.
/// An absent table uses the shipped default row. One account owns this local
/// log, so a holder row narrows that vault's effective retention, not another
/// actor's data. Across trusted packs all contributions restrict componentwise.
pub(crate) fn parse_retrieval_retention_rows(value: &Value) -> Option<RetrievalRetentionRows> {
    let Value::Array(entries) = value else {
        return None;
    };
    if entries.len() > 3 {
        return None;
    }
    let mut rows = RetrievalRetentionRows::default();
    let (mut vault, mut holder, mut precedence) = (false, false, false);
    for entry in entries {
        let Value::Map(fields) = entry else {
            return None;
        };
        if fields.len() < 2 || fields.len() > 3 {
            return None;
        }
        let mut scope = None;
        let mut age = None;
        let mut runs = None;
        let mut order = None;
        for (key, value) in fields {
            match key.as_str()? {
                "scope" if scope.is_none() => scope = Some(value.as_str()?),
                "max_age_secs" if age.is_none() => age = Some(value.as_u64().filter(|v| *v > 0)?),
                "max_runs" if runs.is_none() => {
                    // u16 is the admission bound for one run-count row.
                    runs = Some(usize::from(
                        u16::try_from(value.as_u64().filter(|v| *v > 0)?).ok()?,
                    ));
                }
                "order" if order.is_none() => order = Some(value.as_str()?),
                _ => return None,
            }
        }
        match scope? {
            "vault" if !vault && order.is_none() && (age.is_some() || runs.is_some()) => {
                vault = true;
                rows.vault_age_secs = age;
                rows.vault_max_runs = runs;
            }
            "holder" if !holder && order.is_none() && (age.is_some() || runs.is_some()) => {
                holder = true;
                rows.holder_age_secs = age;
                rows.holder_max_runs = runs;
            }
            "precedence"
                if !precedence
                    && age.is_none()
                    && runs.is_none()
                    && order == Some("nested_narrowing") =>
            {
                precedence = true;
            }
            _ => return None,
        }
    }
    // Every authored table must declare how vault/holder rows compose. A
    // missing table itself resolves to the shipped nested-narrowing default.
    precedence.then_some(rows)
}

pub(crate) fn default_retrieval_retention_rows() -> Value {
    Value::Array(vec![
        Value::Map(vec![
            (Value::from("scope"), Value::from("vault")),
            (
                Value::from("max_age_secs"),
                Value::from(DEFAULT_RETRIEVAL_AGE_SECS),
            ),
            (
                Value::from("max_runs"),
                Value::from(DEFAULT_RETRIEVAL_MAX_RUNS as u64),
            ),
        ]),
        Value::Map(vec![
            (Value::from("scope"), Value::from("precedence")),
            (Value::from("order"), Value::from("nested_narrowing")),
        ]),
    ])
}

#[cfg(test)]
mod tests;

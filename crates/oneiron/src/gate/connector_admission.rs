//! Vault policy rows for connector admission capacity. Persisted connector
//! bodies use independent codec safety bounds, never these mutable quotas.
use rmpv::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectorAdmissionQuotas {
    pub(crate) max_tools: usize,
    pub(crate) max_permissions_per_tool: usize,
    pub(crate) max_triggers_per_tool: usize,
}
impl Default for ConnectorAdmissionQuotas {
    fn default() -> Self {
        Self {
            max_tools: 256,
            max_permissions_per_tool: 128,
            max_triggers_per_tool: 128,
        }
    }
}
impl ConnectorAdmissionQuotas {
    fn narrow(self, other: Self) -> Self {
        Self {
            max_tools: self.max_tools.min(other.max_tools),
            max_permissions_per_tool: self
                .max_permissions_per_tool
                .min(other.max_permissions_per_tool),
            max_triggers_per_tool: self.max_triggers_per_tool.min(other.max_triggers_per_tool),
        }
    }
}

/// One declared policy table; nested holders can override a less restrictive
/// row, but the effective result remains capped by the vault's narrowest row.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorAdmissionPolicy {
    vault: Option<ConnectorAdmissionQuotas>,
    holders: BTreeMap<String, ConnectorAdmissionQuotas>,
    declared_precedence: bool,
}
impl ConnectorAdmissionPolicy {
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let rows = value
            .as_array()
            .filter(|rows| !rows.is_empty() && rows.len() <= 512)?;
        let mut table = Self::default();
        for row in rows {
            let entries = row.as_map()?;
            let mut values = BTreeMap::new();
            for (key, value) in entries {
                if values.insert(key.as_str()?, value).is_some() {
                    return None;
                }
            }
            match values.get("scope")?.as_str()? {
                "precedence" => {
                    if values.len() != 2
                        || values.get("mode")?.as_str()?
                            != "nested_narrow_holder_override_vault_cap"
                        || table.declared_precedence
                    {
                        return None;
                    }
                    table.declared_precedence = true;
                }
                "vault" | "holder" => {
                    let scope = values.get("scope")?.as_str()?;
                    let required_len = if scope == "vault" { 4 } else { 5 };
                    if values.len() != required_len {
                        return None;
                    }
                    let number = |name: &str| -> Option<usize> {
                        let n = usize::try_from(values.get(name)?.as_u64()?).ok()?;
                        (1..=4096).contains(&n).then_some(n)
                    };
                    let quotas = ConnectorAdmissionQuotas {
                        max_tools: number("max_tools")?,
                        max_permissions_per_tool: number("max_permissions_per_tool")?,
                        max_triggers_per_tool: number("max_triggers_per_tool")?,
                    };
                    if scope == "vault" {
                        table.vault = Some(table.vault.map_or(quotas, |old| old.narrow(quotas)));
                    } else {
                        let holder = values.get("holder_ref")?.as_str()?;
                        let id = crate::EntityId::from_hex(holder).ok()?;
                        if id.to_hex() != holder {
                            return None;
                        }
                        table
                            .holders
                            .entry(holder.to_owned())
                            .and_modify(|old| *old = old.narrow(quotas))
                            .or_insert(quotas);
                    }
                }
                _ => return None,
            }
        }
        Some(table)
    }
    pub(crate) fn restrict(&mut self, other: Self) {
        if let Some(vault) = other.vault {
            self.vault = Some(self.vault.map_or(vault, |old| old.narrow(vault)));
        }
        for (holder, quotas) in other.holders {
            self.holders
                .entry(holder)
                .and_modify(|old| *old = old.narrow(quotas))
                .or_insert(quotas);
        }
        self.declared_precedence |= other.declared_precedence;
    }
    pub(crate) fn effective(&self, holder: Option<&str>) -> ConnectorAdmissionQuotas {
        let vault = self.vault.unwrap_or_default();
        holder
            .and_then(|id| self.holders.get(id))
            .map_or(vault, |holder| vault.narrow(*holder))
    }
    pub(crate) fn rows_for_hash(
        &self,
    ) -> Option<(
        ConnectorAdmissionQuotas,
        &BTreeMap<String, ConnectorAdmissionQuotas>,
    )> {
        (self.declared_precedence || self.vault.is_some() || !self.holders.is_empty())
            .then_some((self.vault.unwrap_or_default(), &self.holders))
    }
    pub(crate) fn default_rows() -> Value {
        Value::Array(vec![
            Value::Map(vec![
                (Value::from("scope"), Value::from("precedence")),
                (
                    Value::from("mode"),
                    Value::from("nested_narrow_holder_override_vault_cap"),
                ),
            ]),
            Value::Map(vec![
                (Value::from("scope"), Value::from("vault")),
                (Value::from("max_tools"), Value::from(256)),
                (Value::from("max_permissions_per_tool"), Value::from(128)),
                (Value::from("max_triggers_per_tool"), Value::from(128)),
            ]),
        ])
    }
}

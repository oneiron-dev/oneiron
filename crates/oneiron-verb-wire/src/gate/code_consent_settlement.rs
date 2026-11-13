//! Moved from `crates/oneiron/src/gate/code_consent_settlement.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementEligibility;
pub(crate) use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementOrigin;
pub(crate) use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementSource;
pub(crate) use oneiron_consent_state::gate::code_consent_settlement::ResolvedCodeConsentSettlement;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub const KEY: &str = "code_consent_settlement";

pub const SHIPPED_VERSION: u16 = 1;

/// The row is cited as `code_consent_settlement@version` beside its exact source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeConsentSettlementRow {
    pub version: u16,
    pub eligible: CodeConsentSettlementEligibility,
}

impl CodeConsentSettlementRow {
    pub fn parse(value: &Value) -> Option<Self> {
        let fields = value.as_map()?;
        if fields.len() != 2 {
            return None;
        }
        let version = u16::try_from(field(fields, "version")?.as_u64()?).ok()?;
        let eligible_fields = field(fields, "eligible")?.as_map()?;
        let eligible = match field(eligible_fields, "mode")?.as_str()? {
            "all_power_holders" if eligible_fields.len() == 1 => {
                CodeConsentSettlementEligibility::AllPowerHolders
            }
            "named" if eligible_fields.len() == 2 => {
                let mut holders = BTreeSet::new();
                for value in field(eligible_fields, "holders")?.as_array()? {
                    let reference = value.as_str()?;
                    let person = EntityId::from_hex(reference).ok()?;
                    if person.to_hex() != reference || !holders.insert(reference.to_owned()) {
                        return None;
                    }
                }
                CodeConsentSettlementEligibility::Named(holders)
            }
            _ => return None,
        };
        Some(Self { version, eligible })
    }

    pub fn shipped_entry() -> (Value, Value) {
        (
            Value::from(KEY),
            Value::Map(vec![
                (Value::from("version"), Value::from(SHIPPED_VERSION)),
                (
                    Value::from("eligible"),
                    Value::Map(vec![(
                        Value::from("mode"),
                        Value::from("all_power_holders"),
                    )]),
                ),
            ]),
        )
    }
}

pub fn field<'a>(fields: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let mut matching = fields.iter().filter(|(name, _)| name.as_str() == Some(key));
    let (_, value) = matching.next()?;
    matching.next().is_none().then_some(value)
}

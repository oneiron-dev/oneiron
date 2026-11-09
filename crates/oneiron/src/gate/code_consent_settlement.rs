//! The POLICY_MANIFEST row that names who may settle a held code effect.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::manifest_authenticity::PolicyRowOrigin;
use crate::EntityId;

pub(crate) const KEY: &str = "code_consent_settlement";
const SHIPPED_VERSION: u16 = 1;

#[doc(hidden)]
pub use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementEligibility;
#[doc(hidden)]
pub(crate) use oneiron_consent_state::gate::code_consent_settlement::{
    CodeConsentSettlementOrigin, CodeConsentSettlementSource, ResolvedCodeConsentSettlement,
};

/// The row is cited as `code_consent_settlement@version` beside its exact source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeConsentSettlementRow {
    pub version: u16,
    pub eligible: CodeConsentSettlementEligibility,
}

impl CodeConsentSettlementRow {
    pub(in crate::gate) fn parse(value: &Value) -> Option<Self> {
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

    pub(in crate::gate) fn shipped_entry() -> (Value, Value) {
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

fn field<'a>(fields: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let mut matching = fields.iter().filter(|(name, _)| name.as_str() == Some(key));
    let (_, value) = matching.next()?;
    matching.next().is_none().then_some(value)
}

#[derive(Default)]
pub(in crate::gate) struct CodeConsentSettlementFold {
    seeded: Vec<(CodeConsentSettlementRow, CodeConsentSettlementSource)>,
    authored: Vec<(CodeConsentSettlementRow, CodeConsentSettlementSource)>,
    narrowing: Vec<(CodeConsentSettlementRow, CodeConsentSettlementSource)>,
}

impl CodeConsentSettlementFold {
    pub(in crate::gate) fn add(
        &mut self,
        origin: PolicyRowOrigin,
        manifest: EntityId,
        body: &[u8],
        row: CodeConsentSettlementRow,
    ) {
        let (rows, source_origin) = match origin {
            PolicyRowOrigin::Seeded => (&mut self.seeded, CodeConsentSettlementOrigin::Seeded),
            PolicyRowOrigin::Authored => {
                (&mut self.authored, CodeConsentSettlementOrigin::Authored)
            }
            PolicyRowOrigin::Narrowing => {
                (&mut self.narrowing, CodeConsentSettlementOrigin::Narrowing)
            }
        };
        let source = CodeConsentSettlementSource {
            manifest_ref: manifest.to_hex(),
            body_hash: *blake3::hash(body).as_bytes(),
            version: row.version,
            origin: source_origin,
        };
        rows.push((row, source));
    }

    pub(in crate::gate) fn finish(self) -> Option<ResolvedCodeConsentSettlement> {
        let authored = !self.authored.is_empty();
        let baseline = if authored { self.authored } else { self.seeded };
        let first = &baseline.first()?.0;
        let conflicting_authored_rows = authored && baseline.iter().any(|(row, _)| row != first);
        let mut eligible = first.eligible.clone();
        let mut sources = Vec::new();
        for (row, source) in baseline.into_iter().chain(self.narrowing) {
            eligible = eligible.meet(&row.eligible);
            sources.push(source);
        }
        sources.sort_by(|left, right| left.manifest_ref.cmp(&right.manifest_ref));
        Some(ResolvedCodeConsentSettlement {
            eligible,
            sources,
            conflicting_authored_rows,
        })
    }
}

/// Derives the actual held action triple before the connector/browser producer
/// drops its native gate input. The opener's subject is preserved in the bound.
pub(crate) fn code_consent_action_requirement(
    effect: &crate::gate::ExternalEffectGateInput,
) -> Option<crate::consent::GrantBound> {
    crate::gate::effect::external_effect_action_requirement(effect)
}

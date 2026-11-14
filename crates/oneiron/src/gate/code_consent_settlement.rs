//! The POLICY_MANIFEST row that names who may settle a held code effect.

use super::manifest_authenticity::PolicyRowOrigin;
use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::gate::code_consent_settlement::CodeConsentSettlementRow;
#[doc(hidden)]
pub(crate) use oneiron_verb_wire::gate::code_consent_settlement::KEY;

#[doc(hidden)]
pub use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementEligibility;
#[doc(hidden)]
pub(crate) use oneiron_consent_state::gate::code_consent_settlement::{
    CodeConsentSettlementOrigin, CodeConsentSettlementSource, ResolvedCodeConsentSettlement,
};

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

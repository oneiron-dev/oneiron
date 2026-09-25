//! Two explicit cost controls: uncapped context and neutralized OF-095 decay.
use super::BeamResult;
use oneiron::{EntityId, Vault};
use serde::Serialize;
use std::collections::HashMap;
#[derive(Debug, Serialize)]
pub(super) struct FactorObservation {
    pub claim: String,
    pub baseline: f32,
    pub ablated: f32,
}
pub(super) fn access_factors(
    vault: &Vault,
    now: u64,
) -> BeamResult<(HashMap<EntityId, f32>, Vec<FactorObservation>)> {
    let mut factors = HashMap::new();
    let mut observations = Vec::new();
    let mut after = None;
    loop {
        let ids = vault.entities_by_type_page(
            oneiron::registry::ENTITY_TYPE_CLAIM,
            after.as_ref(),
            4096,
        )?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            if let Some(body) = vault.get_claim(id)? {
                let learned = vault.get_learned_at(id)?;
                let baseline =
                    oneiron::claim::claim_access_factor(&body, learned, now, None)?.access_factor;
                let ablated = oneiron::claim::claim_access_factor(&body, learned, now, Some(1.0))?
                    .access_factor;
                factors.insert(*id, ablated);
                observations.push(FactorObservation {
                    claim: id.to_hex(),
                    baseline,
                    ablated,
                });
            }
        }
        after = ids.last().copied();
    }
    Ok((factors, observations))
}

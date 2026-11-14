//! Stored extraction claim fixtures and native-versus-bound verdict parity doors.
//!
//! A correction pack needs a stored claim about its candidate subject inside the attempt
//! listing. That fixture uses production consolidation and reads source versions as the
//! Dreamer reads them. Resolution fixtures name a bare subject through the named person
//! door. The lender child owns the parity resources and lends them to the engine callback.
//! Its native door reads one pack through the native wrapper without running a pass.

mod lender;

pub use lender::{
    ExtractionVerdictFixture, ExtractionVerdictNativePack, ExtractionVerdictPassResources,
    NativePackAnswer, NativePackSpent, attach_extraction_verdict_lender,
    fixture_charge_binding_count, fixture_charge_units, fixture_spent_observations,
    run_extraction_verdict_native_pack,
};

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::snapshot_read::SourceVersion;
use crate::vault::Vault;

/// Lands one Generated `profile.name` claim about a fresh person through the production
/// unbound consolidation pass over the words `call me owen`, and returns the person with
/// the claim. The pass is the consolidation door pass, and the subject is the derive door
/// claim subject read.
///
/// # Errors
///
/// The vault's, a pass that lands no single claim, or a landed claim with no person
/// subject.
pub fn land_extraction_verdict_listing_claim(vault: &Vault) -> Result<(EntityId, EntityId)> {
    let reply = serde_json::json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "owen"}],
        }],
    })
    .to_string();
    let pass =
        super::consolidation::consolidate_unbound_turn(vault, "call me owen", None, None, &reply)?;
    let &[claim] = pass.landed.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "the verdict listing pass landed {} claims, not one",
            pass.landed.len()
        )));
    };
    let subject = super::derive::claim_subject(vault, claim)?.ok_or_else(|| {
        Error::InvalidConfig("the verdict listing claim has no person subject".into())
    })?;
    Ok((subject, claim))
}

/// Reads the version of `id` as the Dreamer reads it now, through the production scoped
/// version read. The Dreamer is the steward door Dreamer, read as a system actor. `None`
/// when the Dreamer does not read the row.
///
/// # Errors
///
/// The vault's.
pub fn dreamer_extraction_verdict_source_version(
    vault: &Vault,
    id: EntityId,
) -> Result<Option<SourceVersion>> {
    let dreamer = super::steward::dreamer(vault)?;
    super::derive::source_version(vault, dreamer, EdgeActorClass::System, id)
}

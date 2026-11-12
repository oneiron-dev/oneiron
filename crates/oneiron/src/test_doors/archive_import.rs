//! Doors for `tests/archive_import_reserved_families.rs`: the whole-vault
//! import's decision for each reserved predicate family, and a fit install's
//! claim pair to export (ARCHIVE-IMPORT-RESERVED-CLAIM-ABORTS).

use std::sync::atomic::Ordering;

use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::context_board::{PREDICATE_PLUGIN_SECTION_INSTALL, PREDICATE_SKILL_SECTION_FIT};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault};

/// Every reserved predicate family as one predicate of it: the `edge`
/// namespace and each engine-owned reserved namespace as
/// `<namespace>.archive_probe`, then each exact engine-owned reserved
/// predicate. The lists are the ones the reserved-predicate check reads.
#[must_use]
pub fn reserved_family_predicates() -> Vec<String> {
    use crate::write_envelope::claim_predicate::{
        ENGINE_OWNED_RESERVED_NAMESPACES, ENGINE_OWNED_RESERVED_PREDICATES,
        RESERVED_PREDICATE_NAMESPACE,
    };
    std::iter::once(RESERVED_PREDICATE_NAMESPACE)
        .chain(ENGINE_OWNED_RESERVED_NAMESPACES.iter().copied())
        .map(|namespace| format!("{namespace}.archive_probe"))
        .chain(
            ENGINE_OWNED_RESERVED_PREDICATES
                .iter()
                .copied()
                .map(str::to_owned),
        )
        .collect()
}

/// The whole-vault import's decision for a claim of `predicate`, in its
/// `Debug` form (`Restore(..)` or `ArchiveOnly(..)`); `None` when neither a
/// restore door nor an omission reason covers it.
#[must_use]
pub fn reserved_claim_import(predicate: &str) -> Option<String> {
    crate::batch::export::reserved_claim_import(predicate).map(|decision| format!("{decision:?}"))
}

/// Lands, in one writer, a `plugin.section_install` claim about the SKILL
/// `skill` and its `skill.section_fit` receipt. The install claim takes the
/// owner-consent shape (context_board/plugin/claim.rs
/// `land_proposed_install`: Generated, Proposed, through the batch door with
/// pending-consent persistence) under the vault's embedded owner. The Auto
/// shape the fit's landing writes (fit_install.rs `land_in_txn`) pends at
/// the gate of a vault with the shipped policy (`gate.pending.source_trust`,
/// `gate.pending.criticality_floor`; FIX-LIST
/// FIT-INSTALL-AUTO-CLAIM-PENDS-AT-GATE), and the import rewrites either
/// shape to Imported + Proposed. The receipt lands Auto and Observed through
/// the reserved door, as the fit's landing writes it. The install payload
/// stands in as a map naming the install, and the receipt names the install
/// claim; the import reads neither value. Returns the install claim and the
/// receipt.
///
/// # Errors
///
/// The claim doors' refusals and storage errors.
pub fn land_section_install_with_fit_receipt(
    vault: &Vault,
    skill: EntityId,
    now: u64,
) -> Result<(EntityId, EntityId)> {
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| Error::InvariantViolation("embedded owner"))?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::from("archive-import-reserved-families"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        PREDICATE_PLUGIN_SECTION_INSTALL,
        ClaimSubject::Entity(skill),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("section_id"),
            rmpv::Value::from("archive-pin.section"),
        )]),
        1.0,
    );
    vault.with_write_txn_grouped(|txn| {
        let install = vault.store.clock.entity_id()?;
        apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::ClaimCandidate {
                id: install,
                candidate: Box::new(candidate),
                envelope,
                occurred,
                learned_at: now,
                internal_lexical_query_hint: false,
            }],
            vault.text_index_trusted.load(Ordering::Acquire),
            ApplyOpsGateMode::new(true, true),
        )?;
        let receipt = vault.store.clock.entity_id()?;
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_SECTION_FIT,
            ClaimSubject::Entity(skill),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("install_claim"),
                rmpv::Value::from(install.to_hex()),
            )]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(txn, &receipt, &body, occurred, now)?;
        Ok((install, receipt))
    })
}

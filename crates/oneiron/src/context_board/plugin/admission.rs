//! Post-consent execution and the live registry projection.
use super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::errors::{PluginResult, PluginSectionError};
use super::install::ValidatedSectionManifest;
use super::manifest::{
    PluginInstallExecutor, SectionBindingResolver, SectionId, SectionVerbAllowlist, SectionVerbRef,
    SkillLifecycleSource,
};
use super::validate::{provenance_matches_record, validate_manifest_for_admission};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::skill::SkillLifecycle;
use crate::vault::Vault;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// §3 — post-consent execution
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginSectionAdmission {
    /// Skill admission has not settled yet. The next board render's
    /// rebuild-on-read admits the section automatically once the skill is
    /// `Active`. No section renders while it is `Candidate`.
    PendingActivation { skill_ref: EntityId },
    Admitted {
        skill_ref: EntityId,
        section_id: SectionId,
    },
}

/// Executes an already-APPROVED install claim. It reloads the claim, rechecks
/// binding/digest/provenance, imports the pinned bytes as `Candidate` through
/// the existing checked hub-import door, runs the existing Candidate→Active
/// skill-admission door under that SAME approved claim (no second consent
/// prompt), and adopts the section only when the exact skill is `Active`.
///
/// Rejection performs zero import/admission: a claim that never reached
/// `Approved` leaves this function at its first check.
pub fn execute_approved_plugin_section_install(
    vault: &Vault,
    registry: &mut PluginSectionRegistry,
    install_claim_id: EntityId,
    source: &dyn PluginInstallExecutor,
    bindings: &dyn SectionBindingResolver,
    now: u64,
) -> PluginResult<PluginSectionAdmission> {
    let body = vault
        .get_claim(&install_claim_id)?
        .ok_or(PluginSectionError::ClaimNotFound)?;
    if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL {
        return Err(PluginSectionError::ClaimNotFound);
    }
    // A pending-record deletion alone is not proof of consent: the APPROVED
    // claim is.
    if body.approval != ClaimApprovalStatus::Approved
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(PluginSectionError::ClaimNotApproved);
    }

    let payload = PluginInstallClaimPayload::from_value(&body.value)?;
    let envelope = payload.manifest()?;
    let verbs = SectionVerbAllowlist::from_exported_verbs();

    let skill_ref = payload.target.target_skill_ref();
    let existing = source.skill_record(&skill_ref)?;
    let record = match existing {
        Some(record) => record,
        None => {
            // Only now — after consent — do the pinned bytes move, and they
            // land as Candidate through the existing checked import door.
            let imported = source.import_candidate_under_claim(
                vault,
                &payload.target,
                &install_claim_id,
                now,
            )?;
            // The owner consented to an install AT the preallocated ref, and
            // the registry projection re-finds the skill by that ref on every
            // restart. An import that landed elsewhere fails closed rather
            // than admitting a section a rebuild could not reproduce.
            if imported != skill_ref {
                return Err(PluginSectionError::ImportRefDrift {
                    expected: skill_ref.to_hex(),
                    found: imported.to_hex(),
                });
            }
            source
                .skill_record(&skill_ref)?
                .ok_or(PluginSectionError::MissingInstallTarget {
                    reference: skill_ref.to_hex(),
                })?
        }
    };

    let record = if record.lifecycle_status == SkillLifecycle::Candidate {
        // Same approved install claim, existing Candidate→Active door, no
        // second consent prompt.
        source.admit_candidate_under_claim(vault, &skill_ref, &install_claim_id, now)?
    } else {
        record
    };

    if !record.lifecycle_status.loads_as_canon() {
        return Ok(PluginSectionAdmission::PendingActivation { skill_ref });
    }

    let validated = validate_manifest_for_admission(envelope, &record, bindings, &verbs)?;
    if validated.provenance().content_hash_hex != payload.content_hash_hex
        || validated.provenance().skill_version != payload.skill_version
    {
        return Err(PluginSectionError::ProvenanceMismatch);
    }
    let section_id = validated.section_id().clone();
    registry.adopt(install_claim_id, validated)?;
    Ok(PluginSectionAdmission::Admitted {
        skill_ref,
        section_id,
    })
}

// ---------------------------------------------------------------------------
// §4 — the registry is a live projection
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedPluginSection {
    pub install_claim_id: EntityId,
    pub manifest: ValidatedSectionManifest,
}

/// In-memory typed state rebuilt from approved install claims plus current
/// skill lifecycle/content identity. It is a PROJECTION: it mints no entity
/// bytes and is never a second persistent registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginSectionRegistry {
    admitted: BTreeMap<SectionId, AdmittedPluginSection>,
}

impl PluginSectionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn adopt(
        &mut self,
        install_claim_id: EntityId,
        manifest: ValidatedSectionManifest,
    ) -> PluginResult<()> {
        let section_id = manifest.section_id().clone();
        if let Some(existing) = self.admitted.get(&section_id)
            && existing.manifest != manifest
        {
            return Err(PluginSectionError::SectionIdCollision {
                section_id: section_id.0,
            });
        }
        self.admitted.insert(
            section_id,
            AdmittedPluginSection {
                install_claim_id,
                manifest,
            },
        );
        Ok(())
    }

    /// Startup/restart rebuild: derives the same projection from approved
    /// install claims plus exact `Active` skill records. Admits ONLY exact
    /// `Active` skills — a Candidate, Stale, Quarantined, Superseded, missing,
    /// or hash-mismatched pack simply does not appear.
    ///
    /// Duplicate section ids resolve deterministically and fail closed: claims
    /// are folded in claim-id order, and a second claim advertising the same
    /// section id with DIFFERENT content removes the section entirely rather
    /// than letting arrival order pick a winner.
    pub fn rebuild(vault: &Vault, bindings: &dyn SectionBindingResolver) -> PluginResult<Self> {
        let verbs = SectionVerbAllowlist::from_exported_verbs();
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let mut rows =
            vault.claims_with_predicate_in_txn(&rtxn, PREDICATE_PLUGIN_SECTION_INSTALL)?;
        drop(rtxn);
        rows.sort_by_key(|(id, _)| *id.as_bytes());

        let mut admitted: BTreeMap<SectionId, AdmittedPluginSection> = BTreeMap::new();
        let mut poisoned: BTreeSet<SectionId> = BTreeSet::new();
        for (claim_id, body) in rows {
            if body.approval != ClaimApprovalStatus::Approved
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
            {
                continue;
            }
            let Ok(payload) = PluginInstallClaimPayload::from_value(&body.value) else {
                continue;
            };
            let Ok(envelope) = payload.manifest() else {
                continue;
            };
            let Ok(Some(record)) = vault.get_skill_record(&payload.target.target_skill_ref())
            else {
                continue;
            };
            let Ok(validated) =
                validate_manifest_for_admission(envelope, &record, bindings, &verbs)
            else {
                continue;
            };
            let section_id = validated.section_id().clone();
            if poisoned.contains(&section_id) {
                continue;
            }
            match admitted.get(&section_id) {
                Some(existing) if existing.manifest != validated => {
                    admitted.remove(&section_id);
                    poisoned.insert(section_id);
                }
                Some(_) => {}
                None => {
                    admitted.insert(
                        section_id,
                        AdmittedPluginSection {
                            install_claim_id: claim_id,
                            manifest: validated,
                        },
                    );
                }
            }
        }
        Ok(Self { admitted })
    }

    /// Drops every section supplied by `skill_id`, returning how many left.
    /// Removal leaves zero orphan advertised verbs because
    /// [`PluginSectionRegistry::reachable_verbs`] reads only what is still
    /// admitted AND still `Active`.
    pub fn remove_for_skill(&mut self, skill_id: &str) -> usize {
        let doomed: Vec<SectionId> = self
            .admitted
            .iter()
            .filter(|(_, section)| section.manifest.provenance().skill_id == skill_id)
            .map(|(id, _)| id.clone())
            .collect();
        for section_id in &doomed {
            self.admitted.remove(section_id);
        }
        doomed.len()
    }

    pub fn sections(&self) -> impl Iterator<Item = &AdmittedPluginSection> {
        self.admitted.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }

    #[must_use]
    pub fn get(&self, section_id: &SectionId) -> Option<&AdmittedPluginSection> {
        self.admitted.get(section_id)
    }

    /// The verbs a still-live plugin section advertises. Every read re-checks
    /// `loads_as_canon()` plus the approved version/content hash, so a stale
    /// cached membership cannot keep a verb alive.
    pub fn reachable_verbs(
        &self,
        skills: &dyn SkillLifecycleSource,
    ) -> PluginResult<BTreeSet<&SectionVerbRef>> {
        let mut reachable = BTreeSet::new();
        for section in self.admitted.values() {
            if !section_is_live(&section.manifest, skills)? {
                continue;
            }
            for verb in section.manifest.verbs() {
                reachable.insert(verb);
            }
        }
        Ok(reachable)
    }
}

/// The lifecycle re-read every render and reachable-verb read performs.
pub(super) fn section_is_live(
    manifest: &ValidatedSectionManifest,
    skills: &dyn SkillLifecycleSource,
) -> PluginResult<bool> {
    let provenance = manifest.provenance();
    let Some(record) = skills.skill_record(&provenance.skill_id)? else {
        return Ok(false);
    };
    if !record.lifecycle_status.loads_as_canon() {
        return Ok(false);
    }
    Ok(provenance_matches_record(provenance, &record).is_ok())
}

//! The fitted section install (FIX 9752; owner law ARCH-0053 "Everything
//! installs; permissions ask"). An explicit section offer runs a
//! deterministic fit first. A code-free section whose every request the
//! caller already holds installs at once: its skill, its install claim and
//! an engine-issued receipt land in one writer, and the owner's revoke
//! undoes it. Anything else lands as today's owner-consent claim, with the
//! fit's analysis. Requested permissions stay inert either way, and Dreamer
//! suggestions never come here: they stay proposals.
use super::claim::{
    PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload, PluginSectionInstallProposal,
    install_payload, land_proposed_install,
};
use super::codec::digest_to_hex;
use super::errors::{PluginResult, PluginSectionError};
use super::install::{PluginInstallOrigin, PluginInstallTarget};
use super::manifest::{
    ApprovedPluginIdentity, PluginInstallSource, SectionBindingResolver, SectionId,
    SectionManifest, SectionManifestEnvelope, SectionVerbAllowlist,
};
use super::validate::{validate_manifest_for_admission, validate_manifest_for_proposal};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::skill::SkillRecord;
use crate::skill_hub::osv::{OsvDevClient, OsvQuery};
use crate::skill_hub::{
    CallerPermissions, HubRef, MarketplaceFit, RefFetch, SkillFitSetting, pinned_tracking,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteProvenance};
use rmpv::Value;

/// The engine-owned receipt a fitted install leaves on its skill. `skill.*`
/// is a reserved namespace: no generic claim door can write one, so only
/// this door issues it.
pub const PREDICATE_SKILL_SECTION_FIT: &str = "skill.section_fit";

/// One section installed after a ready fit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSectionInstalled {
    /// The Auto install claim the owner's revoke retracts.
    pub claim_id: EntityId,
    pub skill_ref: EntityId,
    pub section_id: SectionId,
    pub manifest_digest: [u8; 32],
    /// The permissions the fit evaluated. Installing grants none of them.
    pub permissions: Vec<String>,
}

/// What one fitted install concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginSectionFitOutcome {
    /// Installed now; the owner's revoke undoes it.
    Installed(PluginSectionInstalled),
    /// Waits for the owner as a proposed install claim.
    PermissionAsk {
        proposal: PluginSectionInstallProposal,
        /// Why it asks: what it requests that the caller does not hold.
        analysis: String,
        /// Every permission the fit evaluated.
        permissions: Vec<String>,
    },
}

/// The fit's verdict before anything lands.
enum Fit {
    Installed(PluginSectionInstalled),
    Ask {
        analysis: String,
        permissions: Vec<String>,
    },
}

impl Fit {
    fn ask(analysis: impl Into<String>, permissions: &[String]) -> Self {
        Self::Ask {
            analysis: analysis.into(),
            permissions: permissions.to_vec(),
        }
    }
}

/// Offers one typed section manifest and installs it when the fit is
/// ready. The manifest is validated exactly as a proposal is; a validation
/// refusal is today's refusal. A ready fit lands skill, claim and receipt in
/// one writer. Everything else, including a ready install that could not
/// land, lands as today's Proposed install claim with the analysis: no new
/// refusal.
#[expect(
    clippy::too_many_arguments,
    reason = "the proposal door's inputs plus what the caller already holds"
)]
pub fn install_plugin_section_after_fit(
    vault: &Vault,
    actor: WriteActor,
    provenance: WriteProvenance,
    target: PluginInstallTarget,
    manifest: &SectionManifestEnvelope,
    origin: PluginInstallOrigin,
    source: &dyn PluginInstallSource,
    bindings: &dyn SectionBindingResolver,
    caller: &dyn CallerPermissions,
    now: u64,
) -> PluginResult<PluginSectionFitOutcome> {
    origin.validate()?;
    let verbs = SectionVerbAllowlist::from_exported_verbs();
    let validated =
        validate_manifest_for_proposal(manifest.clone(), &target, source, bindings, &verbs)?;
    let payload = install_payload(&validated, &target, origin)?;
    let section = section_permissions(validated.manifest());
    let offer = Offer {
        vault,
        actor,
        target: &target,
        payload: &payload,
        bindings,
        now,
    };
    let (analysis, permissions) = match offer.fit(&section, caller) {
        Ok(Fit::Installed(installed)) => return Ok(PluginSectionFitOutcome::Installed(installed)),
        Ok(Fit::Ask {
            analysis,
            permissions,
        }) => (analysis, permissions),
        // A ready install that could not land asks instead: the owner's
        // claim is today's path, never a new refusal.
        Err(error) => (
            format!("the install could not land ({error}); the owner decides"),
            section,
        ),
    };
    let proposal = land_proposed_install(vault, actor, provenance, &target, &payload, None, now)?;
    Ok(PluginSectionFitOutcome::PermissionAsk {
        proposal,
        analysis,
        permissions,
    })
}

/// Whether the install claim `claim_id` authorizes its section: the owner's
/// consent (an Approved claim), or an Auto claim this door landed after a
/// ready fit and receipted on its skill, bound to the claim's manifest
/// digest, package identity, exact source and evaluated permissions. A bare
/// Auto claim authorizes nothing, and nothing here mints an Approved one.
pub(super) fn section_install_authorized(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> PluginResult<bool> {
    if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return Ok(false);
    }
    match body.approval {
        ClaimApprovalStatus::Approved => Ok(true),
        ClaimApprovalStatus::Auto => fit_receipted(vault, txn, claim_id, body),
        _ => Ok(false),
    }
}

/// Whether a live `skill.section_fit` receipt on the claim's skill binds
/// exactly this Auto install claim.
fn fit_receipted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> PluginResult<bool> {
    let payload = PluginInstallClaimPayload::from_value(&body.value)?;
    let envelope = payload.manifest()?;
    let approved = ApprovedPluginIdentity::from_reviewed(&payload, &envelope)?;
    let expected = SectionFitReceipt::expected(*claim_id, &payload, &approved);
    let requested = section_permissions(&envelope.manifest);
    for id in vault.claims_for_subject_in_txn(txn, &payload.target.target_skill_ref())? {
        let Some(receipt) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if receipt.predicate != PREDICATE_SKILL_SECTION_FIT
            || receipt.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let Some(stored) = SectionFitReceipt::from_value(&receipt.value) else {
            continue;
        };
        if stored.fields() == expected.fields()
            && requested
                .iter()
                .all(|permission| stored.permissions.contains(permission))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What a section requests: each advertised verb and its authority lane.
fn section_permissions(manifest: &SectionManifest) -> Vec<String> {
    let mut permissions: Vec<String> = manifest
        .verbs
        .iter()
        .map(|verb| format!("verb:{}", verb.0))
        .collect();
    permissions.push(format!("lane:{}", manifest.authority_lane.0));
    permissions.sort();
    permissions.dedup();
    permissions
}

/// One explicit offer, beside the writer it may land in.
struct Offer<'a> {
    vault: &'a Vault,
    actor: WriteActor,
    target: &'a PluginInstallTarget,
    payload: &'a PluginInstallClaimPayload,
    bindings: &'a dyn SectionBindingResolver,
    now: u64,
}

impl Offer<'_> {
    /// The fit: the owner's setting, then what the section requests, then
    /// the skill itself (an existing skill must be Active; a hub package
    /// runs the chosen skill fit).
    fn fit(&self, section: &[String], caller: &dyn CallerPermissions) -> PluginResult<Fit> {
        if self.vault.marketplace_skill_fit()? == SkillFitSetting::OwnerAsked {
            return Ok(Fit::ask(
                "the owner's skill fit setting asks for every install",
                section,
            ));
        }
        let missing = self.missing(section, caller)?;
        if !missing.is_empty() {
            return Ok(Fit::ask(
                format!(
                    "it requests {}, which the caller does not hold",
                    missing.join(", ")
                ),
                section,
            ));
        }
        let envelope = self.payload.manifest()?;
        let approved = ApprovedPluginIdentity::from_reviewed(self.payload, &envelope)?;
        match self.target {
            PluginInstallTarget::ExistingSkill { skill_ref } => {
                self.existing(&envelope, &approved, *skill_ref, section)
            }
            PluginInstallTarget::HubPackage {
                hub_ref,
                target_skill_ref,
            } => self.hub_package(
                &envelope,
                &approved,
                hub_ref,
                *target_skill_ref,
                section,
                caller,
            ),
        }
    }

    /// The requests the caller does not already hold: its host must hold
    /// each one, and an advertised verb also needs the caller's own standing
    /// for it (for an agent, a live Grant listing it).
    fn missing(
        &self,
        requested: &[String],
        caller: &dyn CallerPermissions,
    ) -> PluginResult<Vec<String>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let mut missing = Vec::new();
        for permission in requested {
            let held = caller.holds(permission)
                && match permission.strip_prefix("verb:") {
                    Some(verb) => crate::authority::principal_standing_in_txn(
                        self.vault,
                        &txn,
                        self.actor.entity_ref(),
                        self.actor.actor_class(),
                        verb,
                    )?
                    .is_some(),
                    None => true,
                };
            if !held {
                missing.push(permission.clone());
            }
        }
        Ok(missing)
    }

    /// An existing skill installs its section when it is exactly the
    /// reviewed package and Active; a Candidate one asks, as today.
    fn existing(
        &self,
        envelope: &SectionManifestEnvelope,
        approved: &ApprovedPluginIdentity,
        skill_ref: EntityId,
        section: &[String],
    ) -> PluginResult<Fit> {
        self.vault
            .try_with_write_txn_grouped(|txn| -> PluginResult<Fit> {
                let record = self.vault.read_skill_record_in_txn(txn, &skill_ref)?;
                approved.check_record(&record)?;
                if !record.lifecycle_status.loads_as_canon() {
                    return Ok(Fit::ask(
                        format!(
                            "the skill is {:?}, not Active; the owner decides",
                            record.lifecycle_status
                        ),
                        section,
                    ));
                }
                self.land_in_txn(txn, envelope, &record, section.to_vec())
                    .map(Fit::Installed)
            })
    }

    /// A hub package installs through the admitted publisher's fitted import
    /// at the preallocated ref, when the owner's chosen skill fit is ready.
    fn hub_package(
        &self,
        envelope: &SectionManifestEnvelope,
        approved: &ApprovedPluginIdentity,
        hub_ref: &HubRef,
        target_skill_ref: EntityId,
        section: &[String],
        caller: &dyn CallerPermissions,
    ) -> PluginResult<Fit> {
        let vault = self.vault;
        let Some(publisher) = vault.admitted_skill_publisher(hub_ref.hub_id)? else {
            return Ok(Fit::ask(
                "no skill publisher is admitted for this hub; the owner decides",
                section,
            ));
        };
        let fit = vault.chosen_skill_fit(caller)?;
        let occurred = TimeRange {
            start: self.now,
            end: self.now,
        };
        let osv = Some(&OsvDevClient as &dyn OsvQuery);
        let fitted = match vault.hub_ref_fetch(&pinned_tracking(hub_ref.clone())?, None)? {
            RefFetch::Git(adapter, _) => vault.fit_marketplace_skill(
                &adapter, hub_ref, &publisher, &*fit, osv, occurred, self.now,
            )?,
            RefFetch::Http(adapter, _) => vault.fit_marketplace_skill(
                &adapter, hub_ref, &publisher, &*fit, osv, occurred, self.now,
            )?,
        };
        let mut permissions = section.to_vec();
        permissions.extend(fitted.requested_permissions());
        permissions.sort();
        permissions.dedup();
        if fitted.outcome() != MarketplaceFit::Ready {
            return Ok(Fit::Ask {
                analysis: fitted.analysis().to_owned(),
                permissions,
            });
        }
        approved.check_package(fitted.package())?;
        vault.try_with_write_txn_grouped(|txn| -> PluginResult<Fit> {
            let entity = vault.commit_fitted_skill_in_txn(txn, &fitted, Some(target_skill_ref))?;
            // The section's ref is where every rebuild re-finds the skill:
            // content held elsewhere aborts this writer, and the offer asks.
            if entity != target_skill_ref {
                return Err(PluginSectionError::ImportRefDrift {
                    expected: target_skill_ref.to_hex(),
                    found: entity.to_hex(),
                });
            }
            let record = vault.read_skill_record_in_txn(txn, &entity)?;
            approved.check_record(&record)?;
            if !record.lifecycle_status.loads_as_canon() {
                return Err(PluginSectionError::SkillNotActive {
                    found: record.lifecycle_status,
                });
            }
            self.land_in_txn(txn, envelope, &record, permissions)
                .map(Fit::Installed)
        })
    }

    /// Lands the Auto install claim and its `skill.section_fit` receipt
    /// beside the Active skill, after admission validation on that record.
    fn land_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        envelope: &SectionManifestEnvelope,
        record: &SkillRecord,
        permissions: Vec<String>,
    ) -> PluginResult<PluginSectionInstalled> {
        let verbs = SectionVerbAllowlist::from_exported_verbs();
        let validated =
            validate_manifest_for_admission(envelope.clone(), record, self.bindings, &verbs)?;
        let occurred = TimeRange {
            start: self.now,
            end: self.now,
        };
        let claim_id = self.vault.store.clock.entity_id()?;
        let mut claim = ClaimBody::new(
            PREDICATE_PLUGIN_SECTION_INSTALL,
            ClaimSubject::Entity(self.target.claim_subject()),
            self.payload.to_value(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        claim.source = Some(ClaimSource::Generated);
        self.vault
            .put_claim_in_txn(txn, &claim_id, &claim, occurred, self.now)?;

        let approved = ApprovedPluginIdentity::from_reviewed(self.payload, envelope)?;
        let mut receipt = SectionFitReceipt::expected(claim_id, self.payload, &approved);
        receipt.permissions = permissions.clone();
        let skill_ref = self.target.target_skill_ref();
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_SECTION_FIT,
            ClaimSubject::Entity(skill_ref),
            receipt.to_value(self.actor.entity_ref()),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Observed);
        let receipt_id = self.vault.store.clock.entity_id()?;
        self.vault
            .put_reserved_claim_in_txn(txn, &receipt_id, &body, occurred, self.now)?;
        Ok(PluginSectionInstalled {
            claim_id,
            skill_ref,
            section_id: validated.section_id().clone(),
            manifest_digest: self.payload.manifest_digest,
            permissions,
        })
    }
}

/// The receipt's value: the exact install it covers, and the permissions
/// the fit evaluated for it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SectionFitReceipt {
    install_claim: String,
    manifest_digest: String,
    skill_id: String,
    skill_version: String,
    content_hash: String,
    hub_id: String,
    hub_ref: String,
    pin_type: String,
    pin: String,
    permissions: Vec<String>,
}

impl SectionFitReceipt {
    /// The binding an install claim's receipt must carry.
    fn expected(
        install_claim: EntityId,
        payload: &PluginInstallClaimPayload,
        approved: &ApprovedPluginIdentity,
    ) -> Self {
        let (hub_id, hub_ref) = match &payload.target {
            PluginInstallTarget::ExistingSkill { .. } => (String::new(), String::new()),
            PluginInstallTarget::HubPackage { hub_ref, .. } => {
                (hub_ref.hub_id.to_hex(), hub_ref.ref_string.clone())
            }
        };
        Self {
            install_claim: install_claim.to_hex(),
            manifest_digest: digest_to_hex(&payload.manifest_digest),
            skill_id: approved.skill_id.clone(),
            skill_version: approved.version.clone(),
            content_hash: approved.content_hash.to_hex(),
            hub_id,
            hub_ref,
            pin_type: payload.package_pin_type.clone(),
            pin: payload.package_pin.clone(),
            permissions: Vec::new(),
        }
    }

    /// Every binding field but the permissions, by its stored key.
    fn fields(&self) -> [(&'static str, &str); 9] {
        [
            ("install_claim", self.install_claim.as_str()),
            ("manifest_digest", self.manifest_digest.as_str()),
            ("skill_id", self.skill_id.as_str()),
            ("skill_version", self.skill_version.as_str()),
            ("content_hash", self.content_hash.as_str()),
            ("hub_id", self.hub_id.as_str()),
            ("hub_ref", self.hub_ref.as_str()),
            ("pin_type", self.pin_type.as_str()),
            ("pin", self.pin.as_str()),
        ]
    }

    fn to_value(&self, actor: EntityId) -> Value {
        let mut entries: Vec<(Value, Value)> = self
            .fields()
            .into_iter()
            .map(|(key, value)| (Value::from(key), Value::from(value)))
            .collect();
        entries.push((
            Value::from("permissions"),
            Value::Array(
                self.permissions
                    .iter()
                    .map(|permission| Value::from(permission.as_str()))
                    .collect(),
            ),
        ));
        entries.push((Value::from("actor"), Value::from(actor.to_hex().as_str())));
        Value::Map(entries)
    }

    /// Strict read of a stored receipt; any missing or mistyped field reads
    /// as no receipt.
    fn from_value(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, value)| value)
        };
        let text = |key: &str| get(key).and_then(Value::as_str).map(str::to_owned);
        let Some(Value::Array(items)) = get("permissions") else {
            return None;
        };
        let permissions = items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            install_claim: text("install_claim")?,
            manifest_digest: text("manifest_digest")?,
            skill_id: text("skill_id")?,
            skill_version: text("skill_version")?,
            content_hash: text("content_hash")?,
            hub_id: text("hub_id")?,
            hub_ref: text("hub_ref")?,
            pin_type: text("pin_type")?,
            pin: text("pin")?,
            permissions,
        })
    }
}

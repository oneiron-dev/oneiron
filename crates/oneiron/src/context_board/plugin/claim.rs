//! Install claim payload and the pre-consent proposal path.
use super::codec::{
    decode_section_manifest, digest_from_hex, digest_to_hex, section_manifest_digest,
};
use super::errors::{PluginResult, PluginSectionError};
use super::install::{PluginInstallOrigin, PluginInstallTarget};
use super::manifest::{
    PluginInstallSource, SectionBindingResolver, SectionId, SectionManifestEnvelope,
    SectionVerbAllowlist,
};
use super::validate::validate_manifest_for_proposal;
use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::skill_hub::{HubPin, HubRef};
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;
use std::sync::atomic::Ordering;

/// Pinned schema version of the install claim's typed payload.
pub const PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION: u16 = 1;

/// The one claim predicate an owner consents to for a plugin section install.
/// One Proposed claim under this predicate covers install PLUS section
/// admission; no second approval object and no new gate consent kind exist.
pub const PREDICATE_PLUGIN_SECTION_INSTALL: &str = "plugin.section_install";

/// Bound on the pending-consent scan used to bind a fresh proposal to its
/// consent record.
const PLUGIN_PENDING_CONSENT_SCAN_LIMIT: usize = 512;

// ---------------------------------------------------------------------------
// §3 — the claim payload
// ---------------------------------------------------------------------------
/// The typed payload of one `plugin.section_install` claim.
///
/// Owner-legible on purpose: consent is given over this map, so the canonical
/// manifest bytes ride alongside their digest and the exact package identity
/// rather than being an opaque blob the reviewer cannot see through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginInstallClaimPayload {
    pub schema_version: u16,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: [u8; 32],
    pub section_id: SectionId,
    pub target: PluginInstallTarget,
    pub origin: PluginInstallOrigin,
    pub skill_id: String,
    pub skill_version: String,
    pub content_hash_hex: String,
    /// The package pin, split into its pinned wire discriminator and value so
    /// the EXACT pin an owner consented to survives the claim boundary. A pin
    /// that round-tripped as a different kind would re-fetch different bytes.
    pub package_pin_type: String,
    pub package_pin: String,
}

impl PluginInstallClaimPayload {
    pub(super) fn to_value(&self) -> Value {
        let (target_kind, hub_id, hub_ref_string) = match &self.target {
            PluginInstallTarget::ExistingSkill { .. } => {
                ("existing_skill", String::new(), String::new())
            }
            PluginInstallTarget::HubPackage { hub_ref, .. } => (
                "hub_package",
                hub_ref.hub_id.to_hex(),
                hub_ref.ref_string.clone(),
            ),
        };
        let origin = match &self.origin {
            PluginInstallOrigin::Conversation { turn_ref } => Value::Map(vec![
                (Value::from("kind"), Value::from("conversation")),
                (Value::from("turn_ref"), Value::from(turn_ref.as_str())),
            ]),
            PluginInstallOrigin::DreamerSuggestion {
                run_id,
                suggestion_key,
                digest_window,
            } => Value::Map(vec![
                (Value::from("kind"), Value::from("dreamer_suggestion")),
                (Value::from("run_id"), Value::from(run_id.as_str())),
                (
                    Value::from("suggestion_key"),
                    Value::from(suggestion_key.as_str()),
                ),
                (
                    Value::from("digest_window"),
                    Value::from(digest_window.as_str()),
                ),
            ]),
        };
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(self.schema_version),
            ),
            (
                Value::from("manifest_bytes"),
                Value::Binary(self.manifest_bytes.clone()),
            ),
            (
                Value::from("manifest_digest"),
                Value::from(digest_to_hex(&self.manifest_digest).as_str()),
            ),
            (
                Value::from("section_id"),
                Value::from(self.section_id.0.as_str()),
            ),
            (Value::from("target_kind"), Value::from(target_kind)),
            (
                Value::from("target_skill_ref"),
                Value::from(self.target.target_skill_ref().to_hex().as_str()),
            ),
            (Value::from("hub_id"), Value::from(hub_id.as_str())),
            (
                Value::from("hub_ref_string"),
                Value::from(hub_ref_string.as_str()),
            ),
            (
                Value::from("hub_pin_type"),
                Value::from(self.package_pin_type.as_str()),
            ),
            (
                Value::from("hub_pin"),
                Value::from(self.package_pin.as_str()),
            ),
            (Value::from("origin"), origin),
            (Value::from("skill_id"), Value::from(self.skill_id.as_str())),
            (
                Value::from("skill_version"),
                Value::from(self.skill_version.as_str()),
            ),
            (
                Value::from("content_hash_hex"),
                Value::from(self.content_hash_hex.as_str()),
            ),
        ])
    }

    /// Strict decode of a stored install payload. Every read of an approved
    /// claim goes through here, so a hand-edited claim value cannot reach the
    /// registry.
    ///
    /// Public since ONE-1707 so the Dreamer suggestion job can read an
    /// existing install claim's ORIGIN through this same strict decoder
    /// instead of minting a second reader for the identical wire shape.
    ///
    /// # Errors
    ///
    /// [`PluginSectionError::MalformedClaimPayload`] for any field that is
    /// missing, mistyped, or outside its pinned schema version.
    pub fn from_value(value: &Value) -> PluginResult<Self> {
        let Value::Map(entries) = value else {
            return Err(PluginSectionError::MalformedClaimPayload { field: "payload" });
        };
        let get = |key: &str| entries.iter().find(|(k, _)| k.as_str() == Some(key));
        let text = |key: &'static str| -> PluginResult<String> {
            get(key)
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned)
                .ok_or(PluginSectionError::MalformedClaimPayload { field: key })
        };

        let schema_version = get("schema_version")
            .and_then(|(_, value)| value.as_u64())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(PluginSectionError::MalformedClaimPayload {
                field: "schema_version",
            })?;
        if schema_version != PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION {
            return Err(PluginSectionError::MalformedClaimPayload {
                field: "schema_version",
            });
        }
        let manifest_bytes = match get("manifest_bytes").map(|(_, value)| value) {
            Some(Value::Binary(bytes)) => bytes.clone(),
            _ => {
                return Err(PluginSectionError::MalformedClaimPayload {
                    field: "manifest_bytes",
                });
            }
        };
        let manifest_digest = digest_from_hex(&text("manifest_digest")?).map_err(|_| {
            PluginSectionError::MalformedClaimPayload {
                field: "manifest_digest",
            }
        })?;
        let target_skill_ref = EntityId::from_hex(&text("target_skill_ref")?).map_err(|_| {
            PluginSectionError::MalformedClaimPayload {
                field: "target_skill_ref",
            }
        })?;
        let package_pin = text("hub_pin").unwrap_or_default();
        let package_pin_type = text("hub_pin_type").unwrap_or_default();
        let target = match text("target_kind")?.as_str() {
            "existing_skill" => PluginInstallTarget::ExistingSkill {
                skill_ref: target_skill_ref,
            },
            "hub_package" => {
                let hub_id = EntityId::from_hex(&text("hub_id")?)
                    .map_err(|_| PluginSectionError::MalformedClaimPayload { field: "hub_id" })?;
                let hub_ref = HubRef::new(
                    hub_id,
                    text("hub_ref_string")?,
                    hub_pin_from_parts(&package_pin_type, &package_pin)?,
                )
                .map_err(|_| PluginSectionError::MalformedClaimPayload {
                    field: "hub_ref_string",
                })?;
                PluginInstallTarget::HubPackage {
                    hub_ref,
                    target_skill_ref,
                }
            }
            _ => {
                return Err(PluginSectionError::MalformedClaimPayload {
                    field: "target_kind",
                });
            }
        };

        let Some((_, Value::Map(origin_entries))) = get("origin") else {
            return Err(PluginSectionError::MalformedClaimPayload { field: "origin" });
        };
        let origin_text = |key: &'static str| -> PluginResult<String> {
            origin_entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned)
                .ok_or(PluginSectionError::MalformedClaimPayload { field: key })
        };
        let origin = match origin_text("kind")?.as_str() {
            "conversation" => PluginInstallOrigin::Conversation {
                turn_ref: origin_text("turn_ref")?,
            },
            "dreamer_suggestion" => PluginInstallOrigin::DreamerSuggestion {
                run_id: origin_text("run_id")?,
                suggestion_key: origin_text("suggestion_key")?,
                digest_window: origin_text("digest_window")?,
            },
            _ => {
                return Err(PluginSectionError::MalformedClaimPayload { field: "origin" });
            }
        };
        origin
            .validate()
            .map_err(|_| PluginSectionError::MalformedClaimPayload { field: "origin" })?;

        Ok(Self {
            schema_version,
            manifest_bytes,
            manifest_digest,
            section_id: SectionId(text("section_id")?),
            target,
            origin,
            skill_id: text("skill_id")?,
            skill_version: text("skill_version")?,
            content_hash_hex: text("content_hash_hex")?,
            package_pin_type,
            package_pin,
        })
    }

    /// Re-derives the manifest from the payload bytes and re-checks the digest
    /// binding. A payload whose bytes and digest disagree never decodes.
    ///
    /// # Errors
    ///
    /// [`PluginSectionError::MalformedClaimPayload`] when bytes and digest
    /// disagree, and [`PluginSectionError::ManifestCodec`] on a strict-decode
    /// failure.
    pub fn manifest(&self) -> PluginResult<SectionManifestEnvelope> {
        if section_manifest_digest(&self.manifest_bytes) != self.manifest_digest {
            return Err(PluginSectionError::MalformedClaimPayload {
                field: "manifest_digest",
            });
        }
        decode_section_manifest(&self.manifest_bytes)
    }
}

/// What one accepted proposal returns to its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSectionInstallProposal {
    pub claim_id: EntityId,
    pub decision_id: GateDecisionId,
    pub manifest_digest: [u8; 32],
}

/// Proposes one plugin-section install: validates the exact candidate bytes,
/// constructs ONE Generated/Proposed claim under
/// [`PREDICATE_PLUGIN_SECTION_INSTALL`], and lands it through the existing
/// batch claim door with pending-consent persistence.
///
/// Performs **zero** package import, lifecycle transition, or registry
/// mutation, and writes no pending row of its own — the gate's own
/// pending-consent persistence produces exactly one bound
/// `PendingGateConsentRecord`, which is why no new consent kind is needed.
#[expect(
    clippy::too_many_arguments,
    reason = "the door carries the full write envelope plus both read-only resolvers; \
              collapsing them into a struct would hide which axis a caller supplied"
)]
pub fn propose_plugin_section_install(
    vault: &Vault,
    actor: WriteActor,
    provenance: WriteProvenance,
    target: PluginInstallTarget,
    manifest: &SectionManifestEnvelope,
    origin: PluginInstallOrigin,
    source: &dyn PluginInstallSource,
    bindings: &dyn SectionBindingResolver,
    now: u64,
) -> PluginResult<PluginSectionInstallProposal> {
    propose_plugin_section_install_with_evidence(
        vault, actor, provenance, target, manifest, origin, source, bindings, None, now,
    )
}

/// [`propose_plugin_section_install`] plus the candidate-local evidence a
/// DREAMER-authored proposal must cite.
///
/// This exists because GATE-12's pre-commit floor is not optional. A write
/// whose envelope carries Dreamer provenance (Agent actor + the Dreamer
/// runner marker + a run id) is validated as a Dreamer claim candidate, and
/// the evidence floor refuses any such candidate that cites no ref which
/// still resolves. A suggestion carrying no evidence is exactly the claim the
/// floor is meant to stop, so the door takes the refs rather than exempting
/// the predicate: ONE-1707's `WorkflowPatternNotice.evidence_refs` are what
/// the Dreamer actually observed, and they ride into the claim here.
///
/// Conversation-initiated installs pass `None` and are unaffected — their
/// envelopes carry no Dreamer provenance, so the floor never engages. This is
/// one door with one body; [`propose_plugin_section_install`] is its
/// no-evidence spelling, not a second implementation.
#[expect(
    clippy::too_many_arguments,
    reason = "the door carries the full write envelope plus both read-only resolvers; \
              collapsing them into a struct would hide which axis a caller supplied"
)]
pub fn propose_plugin_section_install_with_evidence(
    vault: &Vault,
    actor: WriteActor,
    provenance: WriteProvenance,
    target: PluginInstallTarget,
    manifest: &SectionManifestEnvelope,
    origin: PluginInstallOrigin,
    source: &dyn PluginInstallSource,
    bindings: &dyn SectionBindingResolver,
    candidate_evidence: Option<Value>,
    now: u64,
) -> PluginResult<PluginSectionInstallProposal> {
    origin.validate()?;
    let verbs = SectionVerbAllowlist::from_exported_verbs();
    let validated =
        validate_manifest_for_proposal(manifest.clone(), &target, source, bindings, &verbs)?;

    let manifest_bytes = validated.canonical_bytes()?;
    let manifest_digest = section_manifest_digest(&manifest_bytes);
    let (package_pin_type, package_pin) = match &target {
        PluginInstallTarget::ExistingSkill { .. } => (String::new(), String::new()),
        PluginInstallTarget::HubPackage { hub_ref, .. } => hub_pin_parts(hub_ref),
    };
    let payload = PluginInstallClaimPayload {
        schema_version: PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION,
        manifest_bytes,
        manifest_digest,
        section_id: validated.section_id().clone(),
        target: target.clone(),
        origin,
        skill_id: validated.provenance().skill_id.clone(),
        skill_version: validated.provenance().skill_version.clone(),
        content_hash_hex: validated.provenance().content_hash_hex.clone(),
        package_pin_type,
        package_pin,
    };

    let claim_id = EntityId::now();
    let mut candidate = ClaimCandidate::new(
        PREDICATE_PLUGIN_SECTION_INSTALL,
        ClaimSubject::Entity(target.claim_subject()),
        payload.to_value(),
        1.0,
    );
    if let Some(evidence) = candidate_evidence {
        candidate = candidate.with_evidence(evidence);
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        provenance,
        ClaimApprovalStatus::Proposed,
    );

    vault.with_write_txn(|wtxn| {
        apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::ClaimCandidate {
                id: claim_id,
                candidate: Box::new(candidate),
                envelope,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                internal_lexical_query_hint: false,
            }],
            vault.text_index_trusted.load(Ordering::Acquire),
            ApplyOpsGateMode::new(true, true),
        )
    })?;

    let decision_id = vault
        .pending_gate_consents(PLUGIN_PENDING_CONSENT_SCAN_LIMIT)?
        .into_iter()
        .find(|record| record.claim_id == *claim_id.as_bytes())
        .map(|record| record.decision_id)
        .ok_or(PluginSectionError::MissingPendingConsent)?;

    Ok(PluginSectionInstallProposal {
        claim_id,
        decision_id,
        manifest_digest,
    })
}

/// Splits a hub pin into `(pinned wire discriminator, value)`.
fn hub_pin_parts(hub_ref: &HubRef) -> (String, String) {
    let value = match &hub_ref.pin {
        HubPin::Semver(value)
        | HubPin::Tag(value)
        | HubPin::Commit(value)
        | HubPin::ContentHash(value) => value.clone(),
        HubPin::None => String::new(),
    };
    (hub_ref.pin.pin_type().to_owned(), value)
}

/// Rebuilds the exact pin from its persisted discriminator. An unrecognized
/// discriminator fails closed rather than degrading to `None`, which would
/// silently unpin the package an owner consented to.
fn hub_pin_from_parts(pin_type: &str, value: &str) -> PluginResult<HubPin> {
    let pin = match pin_type {
        "semver" => HubPin::Semver(value.to_owned()),
        "tag" => HubPin::Tag(value.to_owned()),
        "commit" => HubPin::Commit(value.to_owned()),
        "content_hash" => HubPin::ContentHash(value.to_owned()),
        "none" => HubPin::None,
        _ => {
            return Err(PluginSectionError::MalformedClaimPayload {
                field: "hub_pin_type",
            });
        }
    };
    Ok(pin)
}

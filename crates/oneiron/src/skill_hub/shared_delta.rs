//! Submitted-byte federation merge-back and company PR staging. No personal-vault read door.
use super::{HubPackage, package_codec::invalid};
use crate::{
    Vault, entity_id::EntityId, error::Result, skill::SkillLifecycle, temporal::TimeRange,
};

/// Both lanes offer bytes to the receiving base. Neither grants access to the sender's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SharedSkillLane {
    FederationMergeBack,
    CompanyPullRequest,
}
/// Durable offered delta; author and foreign fork are source assertions, never authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSkillDelta {
    pub candidate: String,
    pub base: String,
    pub base_binding: String,
    pub content_hash: String,
    pub lane: SharedSkillLane,
    pub submitted_by: String,
    pub submitted_fork: String,
}
impl Vault {
    /// Offers a clean package to THIS vault's base. The API accepts submitted bytes,
    /// not a source vault handle, source path, or a callback that could read one.
    /// Authenticated membership/transport is the ingress host's job. This creates
    /// only an untrusted Candidate; merge still needs a local human and two judges.
    #[expect(
        clippy::too_many_arguments,
        reason = "the submission names the receiving base, untrusted source provenance, bytes, and temporal stamps explicitly"
    )]
    pub fn submit_shared_skill_delta(
        &self,
        base: &EntityId,
        submitted: &[u8],
        lane: SharedSkillLane,
        submitted_by: &str,
        submitted_fork: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.submit_shared_skill_delta_inner(
            base,
            submitted,
            lane,
            submitted_by,
            submitted_fork,
            None,
            occurred,
            learned_at,
        )
    }

    /// Offer an edited session-branch fork to its shared base. This copies only
    /// the fork's source (with its name retargeted to the base); it does not
    /// activate the fork or allow the improver to admit its own proposal.
    pub fn submit_local_skill_refinement(
        &self,
        base: &EntityId,
        fork: &EntityId,
        resident: &EntityId,
        submitted: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        if self.get_entity_type(resident)? != Some(crate::registry::ENTITY_TYPE_AGENT_DEF) {
            return Err(invalid("refinement resident must be an agent"));
        }
        self.submit_shared_skill_delta_inner(
            base,
            submitted,
            SharedSkillLane::FederationMergeBack,
            &resident.to_hex(),
            fork,
            Some(fork),
            occurred,
            learned_at,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the shared submission binds source bytes, origin, lane and time explicitly"
    )]
    fn submit_shared_skill_delta_inner(
        &self,
        base: &EntityId,
        submitted: &[u8],
        lane: SharedSkillLane,
        submitted_by: &str,
        submitted_fork: &EntityId,
        local_fork: Option<&EntityId>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        if submitted_by.trim().is_empty() || submitted_by.len() > 512 {
            return Err(invalid("invalid delta author reference"));
        }
        let envelope = super::decode_hub_package(submitted)?;
        // Derive identity and capabilities from submitted files, not envelope assertions.
        let mut package = super::folder::package_from_files(envelope.files)?;
        let candidate = EntityId::now();
        self.with_write_txn(|txn| {
            let current = super::admission_view::read_skill(self, txn, base)?;
            if let Some(fork) = local_fork {
                let branch = super::admission_view::read_skill(self, txn, fork)?;
                if branch.forked_from != Some(*base)
                    || branch.lifecycle_status != SkillLifecycle::Candidate
                    || branch.desc != package.record.desc
                    || !same_refinement_source(
                        &self.stored_hub_package_in_txn(txn, fork)?,
                        &package,
                    )?
                {
                    return Err(invalid("offered source is not the local branch edit"));
                }
            }
            if current.lifecycle_status != SkillLifecycle::Active
                || current.skill_id != package.record.skill_id
                || current.version == package.record.version
                || current.content_hash == package.record.content_hash
            {
                return Err(invalid(
                    "delta must revise an active shared skill with new version and bytes",
                ));
            }
            if current
                .governance_tier
                .is_some_and(crate::skill::SkillGovernanceTier::is_protected)
            {
                return Err(invalid("protected shared skill cannot merge automatically"));
            }
            package.record.provenance = rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("source"),
                    rmpv::Value::from("shared-skill-delta"),
                ),
                (
                    rmpv::Value::from("submittedFork"),
                    rmpv::Value::from(submitted_fork.to_hex()),
                ),
            ]);
            package.record.governance_tier = current.governance_tier;
            let hash = package.content_hash()?;
            if self
                .skill_entity_for_content_hash_in_txn(txn, hash)?
                .is_some()
            {
                return Err(invalid("shared delta content is already resident"));
            }
            let delta = SharedSkillDelta {
                candidate: candidate.to_hex(),
                base: base.to_hex(),
                base_binding: crate::skill_optimize::skill_body_binding_digest(&current)?,
                content_hash: hash.to_hex(),
                lane,
                submitted_by: submitted_by.to_owned(),
                submitted_fork: submitted_fork.to_hex(),
            };
            self.put_skill_record_in_txn(txn, &candidate, &package.record, occurred, learned_at)?;
            self.persist_hub_package_in_txn(txn, &candidate, &package)?;
            self.write_admitted_capability_surface_in_txn(txn, &candidate, &package.capabilities)?;
            self.scan_and_ingest_on_import_in_txn(
                txn, &candidate, hash, &package, occurred, learned_at,
            )?;
            self.batch_in()
                .edge(
                    &candidate,
                    crate::edge::EdgeKind::DerivedFrom,
                    base,
                    crate::edge::EdgeKind::DerivedFrom
                        .default_weight()
                        .unwrap_or(0.2),
                )
                .apply(txn)?;
            self.store.vault_meta.put(
                txn,
                &delta_key(&candidate),
                &serde_json::to_vec(&delta).map_err(|_| invalid("shared delta encode failed"))?,
            )?;
            Ok(candidate)
        })
    }
    /// Persists an edited local fork through the existing fork/update law. Call
    /// `fork_skill_record` first. The fork keeps its own skillId and parent edge.
    pub fn write_shared_skill_fork_package(
        &self,
        fork: &EntityId,
        package: &HubPackage,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let parsed = super::folder::package_from_files(package.files.clone())?;
        self.with_write_txn(|txn| {
            let mut record = self.read_skill_record_in_txn(txn, fork)?;
            if record.forked_from.is_none()
                || record.lifecycle_status != SkillLifecycle::Candidate
                || record.skill_id != parsed.record.skill_id
            {
                return Err(invalid("edited package must name an open local fork"));
            }
            record.desc = parsed.record.desc;
            record.version = parsed.record.version;
            record.content_hash = parsed.record.content_hash;
            let saved = HubPackage::new(record.clone(), parsed.files, parsed.capabilities);
            self.put_skill_record_in_txn(txn, fork, &record, occurred, learned_at)?;
            self.persist_hub_package_in_txn(txn, fork, &saved)?;
            self.scan_and_ingest_on_import_in_txn(
                txn,
                fork,
                saved.content_hash()?,
                &saved,
                occurred,
                learned_at,
            )?;
            Ok(())
        })
    }
    pub fn shared_skill_delta(&self, candidate: &EntityId) -> Result<Option<SharedSkillDelta>> {
        let txn = self.store.env.read_txn()?;
        self.delta_in_txn(&txn, candidate)
    }
    pub(super) fn delta_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: &EntityId,
    ) -> Result<Option<SharedSkillDelta>> {
        self.store
            .vault_meta
            .get(txn, &delta_key(candidate))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("invalid shared delta row"))
            })
            .transpose()
    }
}
fn delta_key(candidate: &EntityId) -> Vec<u8> {
    let mut key = b"skill_hub/shared-delta/v1\0".to_vec();
    key.extend_from_slice(candidate.as_bytes());
    key
}

/// Fork names differ from the upstream name by design. All other source bytes,
/// capability declarations and companion files must be the actual branch edit.
fn same_refinement_source(fork: &HubPackage, offered: &HubPackage) -> Result<bool> {
    if fork.capabilities != offered.capabilities || fork.files.len() != offered.files.len() {
        return Ok(false);
    }
    let strip_identity = |content: &[u8]| -> Result<String> {
        let text =
            std::str::from_utf8(content).map_err(|_| invalid("invalid fork instructions"))?;
        let front = super::folder::source_frontmatter(text)?
            .ok_or_else(|| invalid("fork needs source frontmatter"))?;
        let body = &text[4 + front.len() + 5..];
        Ok(format!(
            "{}---\n{body}",
            front
                .lines()
                .filter(|line| !line.starts_with("name:")
                    && !line.starts_with("version:")
                    && ![
                        "requires-bins: []",
                        "requires-env: []",
                        "requires-mcp: []",
                        "allowed-tools: []"
                    ]
                    .contains(line))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    };
    for source in &fork.files {
        let Some(target) = offered.files.iter().find(|f| f.path == source.path) else {
            return Ok(false);
        };
        if source.path == "SKILL.md" {
            if strip_identity(&source.content)? != strip_identity(&target.content)? {
                return Ok(false);
            }
        } else if source.content != target.content {
            return Ok(false);
        }
    }
    Ok(true)
}

//! Site skills for the run's browser (CUA E10): the loadable skills whose
//! `site.json` origin matches a page exactly, and the seed programs their
//! folders hold.
//!
//! A load scans the skills the leased try's reader may read for the
//! shared, active approved ones whose stored folder names the page's exact
//! origin and a route that takes its path, then loads them through the
//! lease-fenced site door of the pack load (`load_leased_site_skill_packs`).
//! A URL match never activates a Candidate. Each match carries the skill's
//! knowledge and one candidate per seed: a handle that pins the skill
//! entity, the seed's path and the digest of its exact bytes. A resolve
//! checks the handle against the bytes the skill holds now, under the same
//! reader and lease, and names their provenance from the import's records.
use oneiron_browser::WorkflowSeed;
use oneiron_browser::site::{SeedBody, SeedCandidate, SiteSkillMatch, SiteSkillQuery};

use super::folder::{declared_license, instruction_text};
use super::site_folder::{
    SEED_DIGEST_PREFIX, SiteFolder, is_seed_path, read_seed, seed_digest, seed_files,
};
use super::support::map_value;
use super::{HubFile, HubPin, HubRef, PREDICATE_SKILL_HUB_PROVENANCE};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::browser_library::{PROGRAM_ADMISSION_KIND, ProgramAdmissionJob};
use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{LoadedSkillPack, SkillRecord, resident_of, skill_loadable};
use crate::write_envelope::WriteActor;
use crate::{Result, Vault};

/// What a resolve answers when a seed's bytes no longer match the digest
/// its candidate pinned (CALL 7).
pub const SITE_SEED_DIGEST_MISMATCH: &str =
    "the seed's bytes no longer match the digest its candidate pinned";
/// The prefix of a seed candidate's handle:
/// `site-seed:<skill entity hex>:<sha256 hex>:<path>`.
const SEED_HANDLE_PREFIX: &str = "site-seed:";
/// The hex length of a SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;
/// The licence a seed carries when its skill's frontmatter declares none
/// (SPDX's word for no licence asserted).
const UNDECLARED_LICENSE: &str = "NOASSERTION";

impl Vault {
    /// Loadable (Active + Auto/Approved, shared) skills the leased try's
    /// reader may read whose site.json origin matches exactly and whose
    /// routes take the page's path, each loaded under the lease at the
    /// revision that matched. A URL match never activates a Candidate.
    ///
    /// # Errors
    ///
    /// A leased try that names no reader, a lease that no longer holds, and
    /// storage errors. A skill whose stored package does not read is left
    /// out, never the load's failure.
    pub fn site_skills_for(
        &self,
        leased: &AttemptRecord,
        executor: &str,
        query: &SiteSkillQuery,
        at: u64,
    ) -> Result<Vec<SiteSkillMatch>> {
        let read = self.scoped_read(self.site_reader_key(leased)?);
        let skills = self.entities_by_type(ENTITY_TYPE_SKILL)?;
        // Every skill is admitted and read in one snapshot, under one policy.
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&txn)?;
        let mut matched = Vec::new();
        for id in skills {
            if !read.is_entity_readable_with_policy_in(&txn, &policy, &id)? {
                continue;
            }
            let (record, files) = match self.loadable_skill_files_in_txn(&txn, &id) {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        skill = %id.to_hex(),
                        "a skill's stored package did not read; no site matches it"
                    );
                    continue;
                }
            };
            if SiteFolder::read(&files).is_some_and(|site| site.matches(query)) {
                matched.push((id, record.version));
            }
        }
        drop(txn);
        if matched.is_empty() {
            return Ok(Vec::new());
        }
        let mut found: Vec<SiteSkillMatch> = self
            .load_leased_site_skill_packs(leased, &matched, executor, at)?
            .iter()
            .filter_map(|pack| site_match(pack, query))
            .collect();
        found.sort_by(|left, right| {
            left.skill_id
                .cmp(&right.skill_id)
                .then_with(|| left.revision.cmp(&right.revision))
        });
        Ok(found)
    }

    /// Exact seed bytes and provenance from import metadata for a candidate
    /// handle that site_skills_for returned.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for a handle that names no seed of a
    /// loadable site skill the reader may read;
    /// [`SITE_SEED_DIGEST_MISMATCH`] when the seed's bytes changed; a
    /// leased try that names no reader, a lease that no longer holds, and
    /// storage errors.
    pub fn resolve_seed(
        &self,
        leased: &AttemptRecord,
        candidate: &str,
        _at: u64,
    ) -> Result<SeedBody> {
        let handle = SeedHandle::parse(candidate).ok_or(Error::EntityNotFound)?;
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "a site seed resolves under the caller's live attempt lease",
            ))?;
        let read = self.scoped_read(self.site_reader_key(leased)?);
        // The lease, the reader's admission and the bytes are read in one
        // snapshot.
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        AttemptQueue::new(self).require_skill_load_lease_in_txn(
            &txn,
            leased.id,
            lease_owner,
            leased.attempt_count,
        )?;
        let policy = read.live_policy_manifest_in(&txn)?;
        if !read.is_entity_readable_with_policy_in(&txn, &policy, &handle.skill)? {
            return Err(Error::EntityNotFound);
        }
        let (record, files) = self
            .loadable_skill_files_in_txn(&txn, &handle.skill)?
            .ok_or(Error::EntityNotFound)?;
        if SiteFolder::read(&files).is_none() {
            return Err(Error::EntityNotFound);
        }
        let file = files
            .iter()
            .find(|file| file.path == handle.path)
            .ok_or(Error::EntityNotFound)?;
        if seed_digest(&file.content) != handle.digest {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                SITE_SEED_DIGEST_MISMATCH,
            )));
        }
        let seed = read_seed(file).map_err(|_| Error::EntityNotFound)?;
        let (pack, pinned_ref) = self.seed_source_in_txn(&txn, &handle.skill, &record)?;
        Ok(SeedBody {
            program: seed.program,
            seed: WorkflowSeed {
                pack,
                pinned_ref,
                path: file.path.clone(),
                digest: seed.digest,
                license: seed_license(&files),
            },
        })
    }

    /// The read key of the leased try's reader (CUA E10): an agent
    /// dispatch's own agent, or the caller a program admission job acts as;
    /// the vault owner's own key for the owner, any other actor's under its
    /// access grants. Any other try names no reader.
    fn site_reader_key(&self, leased: &AttemptRecord) -> Result<ScopedReadActorKey> {
        let actor = if let Some(input) = crate::agent_dispatch::record_dispatch_input(leased) {
            crate::agent_dispatch::agent_dispatch_actor(&input)?
        } else if leased.kind == PROGRAM_ADMISSION_KIND {
            let job = ProgramAdmissionJob::decode(leased)?;
            let class = EdgeActorClass::try_from_u8(job.scope.actor_class).ok_or(
                Error::InvalidClaimBody("a program admission job's caller class does not read"),
            )?;
            WriteActor::new(job.scope.actor, class)
        } else {
            return Err(Error::InvalidClaimBody(
                "the leased try names no reader for site skills",
            ));
        };
        let (id, class) = (actor.entity_ref(), actor.actor_class());
        let txn = self.store.env.read_txn()?;
        if crate::memory::actor_is_vault_owner_in_txn(self, &txn, id, class).unwrap_or(false) {
            return Ok(ScopedReadActorKey::vault_owner(id));
        }
        ScopedReadActorKey::with_actor_class(id.to_hex(), class.gate_actor_class())
            .map(|key| key.require_access_grants(Some(id)))
            .ok_or(Error::InvariantViolation(
                "a site skill reader's id builds no read key",
            ))
    }

    /// `id`'s record and stored files while it is a live, shared, loadable
    /// skill with a runtime package, read on `txn`; `None` otherwise.
    fn loadable_skill_files_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<(SkillRecord, Vec<HubFile>)>> {
        if crate::vault::live_entity_row_in_txn(&self.store, txn, id)?.live_type()
            != Some(ENTITY_TYPE_SKILL)
        {
            return Ok(None);
        }
        let Some(record) = self.get_skill_record_in_txn(txn, id)? else {
            return Ok(None);
        };
        if !skill_loadable(&record) || resident_of(&record)?.is_some() {
            return Ok(None);
        }
        Ok(self
            .runtime_skill_package_in_txn(txn, id, &record)?
            .map(|package| (record, package.files)))
    }

    /// Where `skill`'s files came from, as its import recorded them, as the
    /// seed's pack and pinned ref: the pack that bundled it, at the ref that
    /// pack's install is pinned to while the install still lists it, else
    /// at its own pack alias; else the hub that served it, at its pinned
    /// ref; else, for a skill no import brought, the skill itself at its
    /// content hash.
    fn seed_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
        record: &SkillRecord,
    ) -> Result<(String, String)> {
        let mut sources = Vec::new();
        for (_, body, _) in
            self.active_claims_for_predicate_in_txn(txn, skill, PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            if let Some(value) = map_value(&body.value, "hubRef") {
                sources.push(HubRef::from_value(value)?);
            }
        }
        sources.sort_by(|left, right| {
            left.hub_id
                .cmp(&right.hub_id)
                .then_with(|| left.ref_string.cmp(&right.ref_string))
        });
        let mut packs = Vec::new();
        for source in &sources {
            let Some(pack) = self.pack_skill_alias_owner_in_txn(txn, skill, source)? else {
                continue;
            };
            let pinned = match self.mounted_pack_in_txn(txn, &pack)? {
                Some(receipt) if receipt.skills.contains(&skill.to_hex()) => pinned_ref(
                    &receipt.hub_ref,
                    &receipt.pin_type,
                    Some(receipt.pin_value.as_str()),
                ),
                _ => hub_pinned_ref(source),
            };
            packs.push((pack, pinned));
        }
        packs.sort();
        if let Some(pack) = packs.into_iter().next() {
            return Ok(pack);
        }
        if let Some(source) = sources.first() {
            return Ok((source.hub_id.to_hex(), hub_pinned_ref(source)));
        }
        let pinned = record.content_hash.map_or_else(
            || record.version.clone(),
            |hash| format!("content_hash:{}", hash.to_hex()),
        );
        Ok((record.skill_id.clone(), pinned))
    }
}

/// The match a loaded site skill makes on `query`'s page: its knowledge and
/// a candidate for each seed that reads. `None` for a pack whose folder is
/// no site skill on that page.
fn site_match(pack: &LoadedSkillPack, query: &SiteSkillQuery) -> Option<SiteSkillMatch> {
    let files = pack.source_files.as_deref()?;
    let site = SiteFolder::read(files).filter(|site| site.matches(query))?;
    let instructions = instruction_text(files).ok()?;
    let license = seed_license(files);
    let seeds = seed_files(files)
        .into_iter()
        .filter_map(|file| {
            let seed = read_seed(file).ok()?;
            Some(SeedCandidate {
                candidate: seed_handle(&pack.entity, &file.path, &seed.digest),
                path: file.path.clone(),
                digest: seed.digest,
                license: license.clone(),
            })
        })
        .collect();
    Some(SiteSkillMatch {
        skill_id: pack.record.skill_id.clone(),
        revision: pack.record.version.clone(),
        knowledge: site.knowledge(instructions),
        seeds,
    })
}

/// The licence a skill's seeds carry: the one its SKILL.md declares.
fn seed_license(files: &[HubFile]) -> String {
    declared_license(files).unwrap_or_else(|| UNDECLARED_LICENSE.to_owned())
}

/// The handle of the seed at `path` in skill `skill`, at `digest`.
fn seed_handle(skill: &EntityId, path: &str, digest: &str) -> String {
    let hex = digest.strip_prefix(SEED_DIGEST_PREFIX).unwrap_or(digest);
    format!("{SEED_HANDLE_PREFIX}{}:{hex}:{path}", skill.to_hex())
}

/// A seed candidate's handle, parsed: the skill entity, the digest its
/// seed's bytes were listed at, and the seed's path.
struct SeedHandle<'a> {
    skill: EntityId,
    digest: String,
    path: &'a str,
}

impl<'a> SeedHandle<'a> {
    /// The handle `text` names, or `None` for text no listing minted.
    fn parse(text: &'a str) -> Option<Self> {
        let rest = text.strip_prefix(SEED_HANDLE_PREFIX)?;
        let (skill, rest) = rest.split_once(':')?;
        let (hex, path) = rest.split_once(':')?;
        if hex.len() != SHA256_HEX_LEN
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || !is_seed_path(path)
        {
            return None;
        }
        Some(Self {
            skill: EntityId::from_hex(skill).ok()?,
            digest: format!("{SEED_DIGEST_PREFIX}{hex}"),
            path,
        })
    }
}

/// `reference` at its pin, `<ref>@<pin type>:<pin value>`; the bare ref
/// when it is pinned to nothing.
fn pinned_ref(reference: &str, pin_type: &str, pin_value: Option<&str>) -> String {
    match pin_value {
        Some(value) if !value.is_empty() => format!("{reference}@{pin_type}:{value}"),
        _ => reference.to_owned(),
    }
}

/// A hub ref at its pin, as [`pinned_ref`] writes it.
fn hub_pinned_ref(source: &HubRef) -> String {
    let value = match &source.pin {
        HubPin::Semver(value)
        | HubPin::Tag(value)
        | HubPin::Commit(value)
        | HubPin::ContentHash(value) => Some(value.as_str()),
        HubPin::None => None,
    };
    pinned_ref(&source.ref_string, source.pin.pin_type(), value)
}

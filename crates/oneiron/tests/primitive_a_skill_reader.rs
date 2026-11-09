//! Primitive A, slice 6.4d (SLICE6-MAP row A; ENGINE CALL S64-4 = A):
//! `vault.skills.get` and `vault.skills.list` keep their names, and a caller
//! other than the owner reads the library through its own read, with the
//! judgment `site_skills_for` already makes: only a live, loadable, shared
//! skill with a runtime package that its read admits, as the package alone,
//! without the owner's provenance or admission receipts. On main an agent's
//! read is refused as the owner's door; the owner's read is unchanged.
//!
//! Public paths only: the generated engine fns in `oneiron::verbs`.

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::verbs::{HubSkillRequest, SkillLibraryListRequest};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    Ok((dir, vault))
}

/// An owner-authored candidate with no runtime package: in the owner's
/// library, never loadable.
fn put_candidate(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    let tree = canonical_skill_tree_hash([("SKILL.md", b"# a candidate skill\n".as_slice())])?;
    let record = SkillRecord::new(
        "primitive-a.candidate",
        "A candidate skill no reader loads",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("primitive-a-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault.put_skill_record(&id, &record, TimeRange { start: 10, end: 10 }, 11)?;
    Ok(id)
}

fn page() -> SkillLibraryListRequest {
    SkillLibraryListRequest {
        after: None,
        limit: 256,
    }
}

#[test]
fn an_agent_lists_only_loadable_skills_without_the_owners_evidence() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let candidate = put_candidate(&vault)?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    let agent = status.input.target.agent_definition_ref()?;
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);

    // The owner's library holds every skill, the candidate among them.
    let owned = oneiron::verbs::vault_skills_list(&owner, page())?;
    assert!(owned.skills.iter().any(|skill| skill.entity == candidate));

    // The agent reads the seeded loadable skills as packages, and no other.
    let read = oneiron::verbs::vault_skills_list(&reader, page())?;
    assert!(!read.skills.is_empty(), "the seeded skills are loadable");
    assert!(read.skills.len() < owned.skills.len());
    for skill in &read.skills {
        assert!(skill.loadable);
        assert!(skill.files.is_some());
        assert!(skill.provenance.is_null());
        assert!(skill.receipts.sources.is_empty());
        assert!(skill.receipts.imports.is_empty());
        assert!(skill.receipts.admission.is_none());
        assert!(owned.skills.iter().any(|own| own.entity == skill.entity));
    }
    assert!(read.skills.iter().all(|skill| skill.entity != candidate));

    // One skill by id: a loadable one reads as its package; the candidate
    // reads as absent, not as a refusal that names it.
    let first = read.skills[0].entity;
    let got = oneiron::verbs::vault_skills_get(&reader, HubSkillRequest { entity: first })?;
    assert_eq!(got.entity, first);
    assert!(got.provenance.is_null());
    let Err(absent) =
        oneiron::verbs::vault_skills_get(&reader, HubSkillRequest { entity: candidate })
    else {
        return Err("a candidate is not a loadable skill".into());
    };
    assert_eq!(absent.code, MEMORY_CODE_NOT_FOUND);

    // The owner reads the candidate, as before.
    let own = oneiron::verbs::vault_skills_get(&owner, HubSkillRequest { entity: candidate })?;
    assert_eq!(own.entity, candidate);
    Ok(())
}

//! Primitive A, slice 6.4d (SLICE6-MAP row A; ENGINE CALL S64-4 = A):
//! `vault.skills.get` and `vault.skills.list` keep their names, and a caller
//! other than the owner reads the library through its own read, with the
//! judgment `site_skills_for` already makes: only a live, loadable, shared
//! skill with a runtime package that its read admits, as the package alone,
//! without the owner's provenance or admission receipts. An agent reads
//! through the owner's grant of SKILL reads; with none it reads no skill. On
//! main an agent's read is refused as the owner's door; the owner's read is
//! unchanged. A reader is served the state its admitting read saw: an owner
//! archive that commits while the read is held right after it admitted the
//! row does not reach the view (#6976 review round 2). A reader's page and
//! its cursor name only skills it reads: a skill it does not read is never
//! the cursor, and a library it reads nothing of answers as an empty one
//! (#6984 review round 1). A reader that sees stored keys masked is never
//! served a skill whose package files hold a key: it reads as absent, while
//! the owner reads the package as stored (#6986 review round 2).
//!
//! Public paths only: the generated engine fns in `oneiron::verbs`.

use std::collections::BTreeSet;

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::federation::{Scope, ScopeAxis, Sensitivity, SensitivityCeiling};
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::verbs::{
    AgentGrantMintRequest, HubSkillRequest, SkillLibraryLifecycle, SkillLibraryListRequest,
};
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
    // The owner's agent Grant act needs this install profiled in the
    // vault's roster to carry it: a fresh local-origin vault is rooted and
    // profiled here, as a device open with a host root secret does.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    assert_eq!(
        vault.profile_local_open(Some(b"primitive-a-skill-reader"), true)?,
        oneiron::authority::LocalOpenProfile::RootedAndProfiled,
    );
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

/// The agent definition a fresh default-base dispatch spawns.
fn dispatched_agent(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    Ok(status.input.target.agent_definition_ref()?)
}

/// The owner grants `agent` reads of SKILL rows, and no other kind.
fn grant_skill_reads(
    owner: &oneiron::memory::Memory<'_>,
    agent: EntityId,
) -> Result<(), Box<dyn std::error::Error>> {
    oneiron::verbs::vault_agents_grants_mint(
        owner,
        AgentGrantMintRequest {
            agent,
            authority_scope: Scope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::All,
                bands: ScopeAxis::Some(BTreeSet::from([oneiron::registry::ENTITY_TYPE_SKILL])),
                audience: ScopeAxis::All,
                verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
                sensitivity: SensitivityCeiling::AtMost(Sensitivity::Sensitive),
            },
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )?;
    Ok(())
}

/// How long the test waits for the held read to reach its hold point.
const HOLD_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Runs `read` as `agent` on its own thread, held at the point its own read
/// admits a skill row (`test_doors::skill_read_hold`); the owner archives
/// `skill` in that gap, then the read resumes. Returns what the read served.
fn archive_in_admission_gap<T: Send>(
    vault: &Vault,
    owner: &oneiron::memory::Memory<'_>,
    agent: EntityId,
    skill: EntityId,
    read: impl FnOnce(&oneiron::memory::Memory<'_>) -> oneiron::memory::MemoryResult<T> + Send,
) -> Result<T, Box<dyn std::error::Error>> {
    let (admitted_tx, admitted_rx) = std::sync::mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let reading = scope.spawn(move || {
            oneiron::test_doors::skill_read_hold::hold_next_read(admitted_tx, resume_rx);
            read(&vault.memory(agent, EdgeActorClass::Agent))
        });
        admitted_rx.recv_timeout(HOLD_WAIT)?;
        oneiron::verbs::vault_skills_archive(owner, HubSkillRequest { entity: skill })?;
        resume_tx.send(())?;
        Ok(reading.join().map_err(|_| "the held read panicked")??)
    })
}

/// A vault whose agent holds the owner's SKILL-band read grant, with the
/// owner's handle and the first loadable skill the agent reads.
fn granted_reader_fixture(
    vault: &Vault,
) -> Result<(EntityId, EntityId, EntityId), Box<dyn std::error::Error>> {
    let agent = dispatched_agent(vault)?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    grant_skill_reads(&vault.memory(owner_actor, EdgeActorClass::Human), agent)?;
    let listed =
        oneiron::verbs::vault_skills_list(&vault.memory(agent, EdgeActorClass::Agent), page())?;
    let skill = listed
        .skills
        .first()
        .map(|skill| skill.entity)
        .ok_or("the seeded skills are loadable")?;
    Ok((agent, owner_actor, skill))
}

#[test]
fn an_agent_lists_only_loadable_skills_without_the_owners_evidence() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let candidate = put_candidate(&vault)?;
    let agent = dispatched_agent(&vault)?;
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);

    // An agent reads the library through its own read: with no grant it
    // reads no skill at all.
    assert!(
        oneiron::verbs::vault_skills_list(&reader, page())?
            .skills
            .is_empty(),
        "an agent with no read grant reads no skill"
    );
    // The owner grants it reads of SKILL rows, and no other kind.
    grant_skill_reads(&owner, agent)?;

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

/// `vault.skills.get` serves the skill as the read that admitted it saw it:
/// the owner archives the skill after the reader's read admitted its row
/// and before the view is read, and the view is still the loadable package
/// the read admitted. Once the read ends, the archive is in force: the next
/// read finds no such skill.
#[test]
fn a_skill_get_serves_the_state_its_admitting_read_saw() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (agent, owner_actor, skill) = granted_reader_fixture(&vault)?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let before = oneiron::verbs::vault_skills_get(&reader, HubSkillRequest { entity: skill })?;
    assert!(before.loadable);

    let held = archive_in_admission_gap(&vault, &owner, agent, skill, |reader| {
        oneiron::verbs::vault_skills_get(reader, HubSkillRequest { entity: skill })
    })?;
    assert_eq!(held.entity, skill);
    assert_eq!(
        held.lifecycle, before.lifecycle,
        "the view shows the lifecycle the admitting read saw, not the archive after it"
    );
    assert!(
        held.loadable,
        "the view is the loadable skill the read admitted"
    );
    assert_eq!(held.version, before.version);
    assert!(held.files.is_some());

    let own = oneiron::verbs::vault_skills_get(&owner, HubSkillRequest { entity: skill })?;
    assert_eq!(own.lifecycle, SkillLibraryLifecycle::Archived);
    let Err(gone) = oneiron::verbs::vault_skills_get(&reader, HubSkillRequest { entity: skill })
    else {
        return Err("an archived skill is not loadable".into());
    };
    assert_eq!(gone.code, MEMORY_CODE_NOT_FOUND);
    Ok(())
}

/// `vault.skills.list` serves each skill as the page's one read saw it: the
/// owner archives a listed skill after the page's read admitted a row, and
/// the page still lists that skill as the loadable package it was. The next
/// page leaves it out.
#[test]
fn a_skill_list_serves_the_state_its_admitting_read_saw() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (agent, owner_actor, skill) = granted_reader_fixture(&vault)?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let before = oneiron::verbs::vault_skills_list(&reader, page())?;

    let held = archive_in_admission_gap(&vault, &owner, agent, skill, |reader| {
        oneiron::verbs::vault_skills_list(reader, page())
    })?;
    assert_eq!(
        held.skills
            .iter()
            .map(|listed| listed.entity)
            .collect::<Vec<_>>(),
        before
            .skills
            .iter()
            .map(|listed| listed.entity)
            .collect::<Vec<_>>(),
        "the page lists the skills its read admitted"
    );
    for listed in &held.skills {
        assert!(
            listed.loadable && listed.lifecycle != SkillLibraryLifecycle::Archived,
            "every listed view is the loadable state the page's read admitted"
        );
    }

    let after = oneiron::verbs::vault_skills_list(&reader, page())?;
    assert!(after.skills.iter().all(|listed| listed.entity != skill));
    Ok(())
}

/// `vault.skills.list` names no skill the reader does not read
/// (#6984 review round 1). With no read grant, a one-skill page is the empty
/// library's reply: no skill and no cursor. With the owner's SKILL-band
/// grant, a walk one skill at a time has each page's cursor be the one skill
/// it served, never the owner's candidate, and serves the skills of one long
/// page, in its order.
#[test]
fn a_readers_list_cursor_names_only_skills_it_reads() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let candidate = put_candidate(&vault)?;
    let agent = dispatched_agent(&vault)?;
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);
    let one_skill = |after: Option<EntityId>| SkillLibraryListRequest { after, limit: 1 };

    let unread = oneiron::verbs::vault_skills_list(&reader, one_skill(None))?;
    assert!(
        unread.skills.is_empty(),
        "an agent with no read grant reads no skill"
    );
    assert_eq!(
        unread.next_after, None,
        "a reader that reads no skill is given no cursor, as for an empty library"
    );

    grant_skill_reads(&owner, agent)?;
    let whole = oneiron::verbs::vault_skills_list(&reader, page())?;
    assert!(!whole.skills.is_empty(), "the seeded skills are loadable");
    if whole.skills.len() < page().limit {
        assert_eq!(
            whole.next_after, None,
            "a page the index ends before is the last"
        );
    }
    let mut walked = Vec::new();
    let mut after = None;
    for _ in 0..=whole.skills.len() {
        let step = oneiron::verbs::vault_skills_list(&reader, one_skill(after))?;
        let Some(cursor) = step.next_after else {
            assert!(
                step.skills.is_empty(),
                "the page that ends the walk serves no skill"
            );
            break;
        };
        assert_eq!(
            step.skills
                .iter()
                .map(|listed| listed.entity)
                .collect::<Vec<_>>(),
            vec![cursor],
            "the cursor is the one skill the page served"
        );
        assert_ne!(
            cursor, candidate,
            "the owner's candidate is never the cursor"
        );
        walked.push(cursor);
        after = Some(cursor);
    }
    assert_eq!(
        walked,
        whole
            .skills
            .iter()
            .map(|listed| listed.entity)
            .collect::<Vec<_>>(),
        "the walk serves the long page's skills, in its order"
    );
    Ok(())
}

/// A credential in a skill's config file, in a shape the release scan reads.
const CONFIG_KEY: &[u8] = b"ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// An owner-authored, approved skill whose `config.json` holds
/// [`CONFIG_KEY`], landed and activated through the package store's door:
/// a loadable skill whose stored package holds a key.
fn put_keyed_skill(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let mut config = b"{\"token\": \"".to_vec();
    config.extend_from_slice(CONFIG_KEY);
    config.extend_from_slice(b"\"}\n");
    let files = vec![
        HubFile::new("SKILL.md", b"# a skill with a key in its config\n".to_vec()),
        HubFile::new("config.json", config),
    ];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "primitive-a.keyed",
        "A skill whose config file holds a key",
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
    Ok(oneiron::test_doors::skill_package::land_active_skill_with_files(vault, &record, files)?)
}

/// Whether `content` holds [`CONFIG_KEY`].
fn holds_key(content: &[u8]) -> bool {
    content
        .windows(CONFIG_KEY.len())
        .any(|window| window == CONFIG_KEY)
}

/// A reader other than the owner sees stored keys masked, and a skill
/// package's files carry no custody marks to mask by: a skill whose package
/// holds a key is never served to it (#6986 review round 2). Its get answers
/// as an absent skill does and its list leaves the skill out, while the other
/// skills it reads are still served. The owner reads the package as stored.
#[test]
fn a_reader_is_never_served_a_skill_package_that_holds_a_key() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (agent, owner_actor, _) = granted_reader_fixture(&vault)?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let keyed = put_keyed_skill(&vault)?;

    let own = oneiron::verbs::vault_skills_get(&owner, HubSkillRequest { entity: keyed })?;
    assert!(own.loadable, "the keyed skill is loadable");
    assert!(
        own.files
            .iter()
            .flatten()
            .any(|file| file.path == "config.json" && holds_key(&file.content)),
        "the owner reads the package as stored"
    );

    let Err(withheld) =
        oneiron::verbs::vault_skills_get(&reader, HubSkillRequest { entity: keyed })
    else {
        return Err("a reader was served a skill package that holds a key".into());
    };
    assert_eq!(
        withheld.code, MEMORY_CODE_NOT_FOUND,
        "the keyed skill reads as absent"
    );
    let listed = oneiron::verbs::vault_skills_list(&reader, page())?;
    assert!(
        !listed.skills.is_empty(),
        "the seeded skills are still served"
    );
    assert!(
        listed.skills.iter().all(|skill| skill.entity != keyed),
        "the list leaves the keyed skill out"
    );
    assert!(
        listed
            .skills
            .iter()
            .flat_map(|skill| skill.files.iter().flatten())
            .all(|file| !holds_key(&file.content)),
        "no listed file holds the key"
    );
    Ok(())
}

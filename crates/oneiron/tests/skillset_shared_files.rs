//! 0053-SKILLSET (ARCH-0053 §14 "skillset bundles (shared assets across
//! related skills)"; Engine rulings 0053-SKILLSET-OBJECT = A and
//! 0053-SKILLSET-UPDATE-CARD = A, 15 Nov). The skillset is the pack. A pack's
//! `shared/` files ride every bundled skill under `shared/`, so each member's
//! content hash covers exactly what it runs, and one pack put re-pins every
//! member when a shared file changes. A member folder may not hold a
//! `shared/` of its own when the pack holds one (it keeps one as before when
//! the pack does not), and a travelling agent pack, which carries each skill
//! whole, may not hold one at all.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::share_travel::{AgentPackTravelProjection, BornWith};
use oneiron::skill::SkillLifecycle;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallReceipt};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::skill_package::runtime_package_files;
use oneiron::{EntityId, Vault, VaultConfig};
use rmpv::Value;

const SHARED_PATH: &str = "shared/glossary.md";
const GLOSSARY_FIRST: &str = "# Glossary\n\nA ledger is the list of every payment.\n";
const GLOSSARY_SECOND: &str = "# Glossary\n\nA ledger is the dated list of every payment.\n";

/// A vault with the shipped default manifest and its owner's proof, as an
/// embedded owner holds it.
struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            _directory: directory,
        }
    }

    /// The owner's put of `files`, which must install.
    fn install(&self, files: Vec<HubFile>) -> PackInstallReceipt {
        match self.vault.put_pack(&self.owner, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => *receipt,
            other => panic!("the owner's put installs the pack: {other:?}"),
        }
    }

    /// The bytes of `path` in skill `id`'s runtime package.
    fn member_file(&self, id: &str, path: &str) -> Option<Vec<u8>> {
        let id = EntityId::from_hex(id).expect("member id");
        runtime_package_files(&self.vault, &id)
            .expect("read the member's package")
            .expect("the member has a package")
            .into_iter()
            .find(|file| file.path == path)
            .map(|file| file.content)
    }

    fn lifecycle(&self, id: &str) -> SkillLifecycle {
        let id = EntityId::from_hex(id).expect("member id");
        self.vault
            .get_skill_record(&id)
            .expect("read the member")
            .expect("the member exists")
            .lifecycle_status
    }
}

/// A capability pack named `example.ledgerskills` at `version`, with
/// `glossary` as its shared file and two bundled skills that read it. Each
/// skill's frontmatter names `member_version` when one is given; without one
/// the skill's version is named by its content.
fn skillset(version: &str, glossary: &str, member_version: Option<&str>) -> Vec<HubFile> {
    let skill = |name: &str| {
        let version_line = member_version.map_or(String::new(), |v| format!("version: {v}\n"));
        format!(
            "---\nname: {name}\ndescription: Answers ledger questions with the shared glossary.\n{version_line}---\nRead shared/glossary.md first.\n"
        )
    };
    vec![
        HubFile::new(
            "PACK.md",
            format!(
                "---\nname: example.ledgerskills\ndescription: Two ledger skills and their glossary.\nversion: {version}\nkind: capability\n---\nA skillset.\n"
            ),
        ),
        HubFile::new(SHARED_PATH, glossary),
        HubFile::new("skills/ledger-lookup/SKILL.md", skill("ledger-lookup")),
        HubFile::new("skills/ledger-summary/SKILL.md", skill("ledger-summary")),
    ]
}

/// Both bundled skills read the pack's one shared file, at the same path, with
/// the pack's bytes.
#[test]
fn two_bundled_skills_read_one_shared_file() {
    let fixture = Fixture::new();
    let receipt = fixture.install(skillset("1.0.0", GLOSSARY_FIRST, None));

    assert_eq!(receipt.skills.len(), 2, "{:?}", receipt.skills);
    for member in &receipt.skills {
        assert_eq!(
            fixture.member_file(member, SHARED_PATH).as_deref(),
            Some(GLOSSARY_FIRST.as_bytes()),
            "member {member} reads the shared glossary"
        );
    }
}

/// One put with a changed shared file re-pins every member: both new members
/// read the new bytes, and both old members are superseded. The put's one
/// permission card lists both members, and with their powers unchanged it
/// widens nothing (0053-SKILLSET-UPDATE-CARD = A).
#[test]
fn a_shared_file_update_re_pins_every_member_in_one_put() {
    let fixture = Fixture::new();
    let first = fixture.install(skillset("1.0.0", GLOSSARY_FIRST, None));
    let second = fixture.install(skillset("1.1.0", GLOSSARY_SECOND, None));

    assert_eq!(second.skills.len(), 2, "{:?}", second.skills);
    assert_eq!(
        second.permissions.bundled_skills.len(),
        2,
        "{:?}",
        second.permissions
    );
    assert!(
        second.permissions.widening_bundled_skills.is_empty(),
        "{:?}",
        second.permissions
    );
    for member in &second.skills {
        assert!(!first.skills.contains(member), "member {member} is new");
        assert_eq!(
            fixture.member_file(member, SHARED_PATH).as_deref(),
            Some(GLOSSARY_SECOND.as_bytes()),
            "member {member} reads the new glossary"
        );
    }
    for member in &first.skills {
        assert_eq!(fixture.lifecycle(member), SkillLifecycle::Superseded);
    }
}

/// A member that names its version must bump it when a shared file changes,
/// as for any change (ARCH-0053 :276): the put that does not is refused whole,
/// and the members before it stay Active on the old bytes. The put that
/// bumps installs.
#[test]
fn a_shared_file_change_needs_each_versioned_member_to_bump() {
    let fixture = Fixture::new();
    let first = fixture.install(skillset("1.0.0", GLOSSARY_FIRST, Some("1.0.0")));

    let unbumped = fixture.vault.put_pack(
        &fixture.owner,
        skillset("1.1.0", GLOSSARY_SECOND, Some("1.0.0")),
    );
    assert!(unbumped.is_err(), "{unbumped:?}");
    for member in &first.skills {
        assert_eq!(fixture.lifecycle(member), SkillLifecycle::Active);
        assert_eq!(
            fixture.member_file(member, SHARED_PATH).as_deref(),
            Some(GLOSSARY_FIRST.as_bytes())
        );
    }

    let bumped = fixture.install(skillset("1.1.0", GLOSSARY_SECOND, Some("1.1.0")));
    for member in &bumped.skills {
        assert_eq!(
            fixture.member_file(member, SHARED_PATH).as_deref(),
            Some(GLOSSARY_SECOND.as_bytes())
        );
    }
}

/// A bundled skill folder holding its own `shared` entry is refused when the
/// pack holds `shared/`, because the pack's `shared/` would collide with it:
/// a `shared/` folder, a file named `shared`, or `Shared/` in another case.
#[test]
fn a_member_folder_holding_shared_is_refused() {
    let fixture = Fixture::new();
    for member_path in [
        "skills/ledger-lookup/shared/notes.md",
        "skills/ledger-lookup/shared",
        "skills/ledger-lookup/Shared/notes.md",
    ] {
        let mut files = skillset("1.0.0", GLOSSARY_FIRST, None);
        files.push(HubFile::new(member_path, "a member's own notes\n"));

        let refused = fixture.vault.put_pack(&fixture.owner, files);

        let error = refused.expect_err(member_path);
        assert!(
            error
                .to_string()
                .contains("a bundled skill folder cannot hold shared/"),
            "{member_path}: {error}"
        );
    }
}

/// A pack with no `shared/` folds nothing, so a member keeps its own
/// `shared/` folder and reads it, as before this change.
#[test]
fn a_member_keeps_its_own_shared_folder_when_the_pack_has_none() {
    const NOTES_PATH: &str = "shared/notes.md";
    const NOTES: &str = "a member's own notes\n";
    let fixture = Fixture::new();
    let mut files = skillset("1.0.0", GLOSSARY_FIRST, None);
    files.retain(|file| file.path != SHARED_PATH);
    files.push(HubFile::new(
        format!("skills/ledger-lookup/{NOTES_PATH}"),
        NOTES,
    ));

    let receipt = fixture.install(files);

    let readers: Vec<&String> = receipt
        .skills
        .iter()
        .filter(|member| {
            fixture.member_file(member, NOTES_PATH).as_deref() == Some(NOTES.as_bytes())
        })
        .collect();
    assert_eq!(readers.len(), 1, "{:?}", receipt.skills);
    for member in &receipt.skills {
        assert_eq!(fixture.member_file(member, SHARED_PATH), None);
    }
}

/// A travelling agent pack carries each skill whole, so a `shared/` beside
/// them is refused.
#[test]
fn a_travelling_agent_pack_holding_shared_is_refused() {
    let fixture = Fixture::new();
    let definition = AgentDefinition::new(
        "local",
        "skillset travelling fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let mut files = AgentPackTravelProjection::from_definition(
        &definition,
        None,
        Vec::new(),
        Vec::new(),
        BornWith::new(),
    )
    .expect("travel projection")
    .files()
    .expect("travel files");
    files.push(HubFile::new(SHARED_PATH, GLOSSARY_FIRST));

    let refused = fixture.vault.put_pack(&fixture.owner, files);

    let error = refused.expect_err("a travelling pack may not hold shared/");
    assert!(
        error.to_string().contains("a travelling agent pack"),
        "{error}"
    );
}

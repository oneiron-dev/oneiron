//! Census L1-18: the Coach's slow retrieval loop reads the library skill
//! tune-oneiron-retrieval (ARCH-0053 #tune-retrieval: "It reads
//! `skills/tune-oneiron-retrieval` for knob ranges, the symptom → cause →
//! change playbook and the judging rules."). These tests pin the skill in the
//! default hub and find the owner's import.
//!
//! The hub is a local folder fixture. tests/fixtures/tune-oneiron-retrieval-pin
//! holds a byte copy of oneiron-hub's skills/tune-oneiron-retrieval at the
//! released commit (`COMMIT`), and that subtree's Git tree id (`TREE`).
//! Moving the pin means refreshing the copy.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;

use oneiron::consent::AuthenticatedOwner;
use oneiron::skill::SkillLifecycle;
use oneiron::skill_hub::{
    HubPin, HubRef, HubSyncPolicy, InstalledLibrarySkill, SkillHubKind, SkillHubRecord,
    SkillHubTrustTier, TUNE_ONEIRON_RETRIEVAL_SUBTREE, default_skill_hub_commit,
    default_skill_hub_id,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::coach_retrieval_review;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tune-oneiron-retrieval-pin"
);

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

fn fixture_line(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURE).join(name))
        .expect("fixture file")
        .trim()
        .to_owned()
}

/// Runs git offline in `dir`, with no system or user configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .expect("local git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout")
        .trim()
        .to_owned()
}

fn copy_folder(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("fixture folder");
    for entry in std::fs::read_dir(from).expect("fixture listing") {
        let entry = entry.expect("fixture entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_folder(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("fixture copy");
        }
    }
}

/// A local Git repository holding the fixture's skills/ folder in one
/// commit: the folder and that commit.
fn fixture_hub() -> (tempfile::TempDir, String) {
    let repository = tempfile::tempdir().expect("hub folder");
    copy_folder(
        &Path::new(FIXTURE).join("skills"),
        &repository.path().join("skills"),
    );
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["add", "."]);
    git(
        repository.path(),
        &["commit", "-qm", "library skill fixture"],
    );
    let commit = git(repository.path(), &["rev-parse", "HEAD"]);
    (repository, commit)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:fixture-owner",
                true,
                GateDecisionId::now(),
            )
            .expect("authenticated owner");
        Self {
            _dir: dir,
            vault,
            owner,
        }
    }

    /// The owner points the default hub at `folder`, a local folder hub
    /// under the pinned-commit policy. Nothing is fetched.
    fn point_default_hub_at(&self, folder: &Path) {
        let record = SkillHubRecord::new(
            SkillHubKind::LocalDir,
            folder.to_str().expect("utf8 folder"),
            SkillHubTrustTier::Verified,
            HubSyncPolicy::PinnedCommit,
        )
        .expect("hub record");
        self.vault
            .configure_skill_hub(&self.owner, &hub(), &record, at(1), 1)
            .expect("configure the default hub");
    }

    fn import(&self, commit: &str) -> EntityId {
        coach_retrieval_review::import_default_hub_skill_at(
            &self.vault,
            &self.owner,
            TUNE_ONEIRON_RETRIEVAL_SUBTREE,
            commit,
            at(2),
            2,
        )
        .expect("the owner's library import")
    }

    fn installed(&self) -> Option<InstalledLibrarySkill> {
        self.vault
            .installed_default_hub_skill(TUNE_ONEIRON_RETRIEVAL_SUBTREE)
            .expect("installed library skill read")
    }
}

fn hub() -> EntityId {
    default_skill_hub_id().expect("default hub id")
}

#[test]
fn tune_oneiron_retrieval_imports_from_the_pinned_default_hub() {
    // The fixture is the hub's own subtree at the engine's released commit.
    assert_eq!(fixture_line("COMMIT"), default_skill_hub_commit());
    let (folder, commit) = fixture_hub();
    assert_eq!(
        git(
            folder.path(),
            &[
                "rev-parse",
                &format!("HEAD:{TUNE_ONEIRON_RETRIEVAL_SUBTREE}")
            ]
        ),
        fixture_line("TREE"),
        "the fixture folder is the hub's subtree at the released commit, byte for byte"
    );
    let fixture = Fixture::open();
    fixture.point_default_hub_at(folder.path());

    let id = fixture.import(&commit);

    let record = fixture
        .vault
        .get_skill_record(&id)
        .expect("skill read")
        .expect("the imported skill");
    assert_eq!(record.skill_id, "tune-oneiron-retrieval");
    assert_eq!(record.version, "0.1.0");
    assert_eq!(
        record.lifecycle_status,
        SkillLifecycle::Candidate,
        "a library import lands a Candidate; nothing activates it"
    );
    let source = HubRef::new(
        hub(),
        TUNE_ONEIRON_RETRIEVAL_SUBTREE,
        HubPin::Commit(commit.clone()),
    )
    .expect("hub ref");
    let receipt = fixture
        .vault
        .hub_import_receipt(&id, &source)
        .expect("receipt read")
        .expect("an import receipt from the default hub");
    assert_eq!(receipt.ref_string, TUNE_ONEIRON_RETRIEVAL_SUBTREE);
    assert_eq!(receipt.pin_value.as_deref(), Some(commit.as_str()));
}

#[test]
fn the_library_skill_is_found_only_after_the_owner_imports_it() {
    let (folder, commit) = fixture_hub();
    let fixture = Fixture::open();
    assert_eq!(
        fixture.installed(),
        None,
        "nothing imports the library skill on open"
    );
    fixture.point_default_hub_at(folder.path());
    assert_eq!(
        fixture.installed(),
        None,
        "pointing the hub at the skill fetches nothing"
    );
    // Today's nightly retrieval tune runs, and with no skill installed it
    // queues no host-run Coach job.
    coach_retrieval_review::run_retrieval_tune(&fixture.vault, 10)
        .expect("the retrieval tune completes");
    assert!(
        coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 10)
            .expect("Coach host queue read")
            .is_none(),
        "no host-run Coach job waits"
    );

    let id = fixture.import(&commit);

    assert_eq!(
        fixture.installed(),
        Some(InstalledLibrarySkill {
            entity: id,
            skill_id: "tune-oneiron-retrieval".to_owned(),
            version: "0.1.0".to_owned(),
            commit,
        })
    );
}

use super::*;

use crate::checkout::lease::{CheckoutId, CheckoutLeaseAct, CheckoutLeaseState};
use crate::checkout::resolve_checkout_environment;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;

use tempfile::TempDir;

const COMMIT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// Synthetic AWS-access-key-id shaped fixture. It is simultaneously a valid
/// single path segment and a valid environment key, so it proves the detector
/// verdict wins over the contextual grammar errors instead of merely proving
/// that no secret-shaped fixture was present.
const AWS_FIXTURE: &str = "AKIA0123456789ABCDEF";

fn vault_fixture() -> (Vault, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    (vault, dir)
}

fn github_repo(commit: &str) -> RepoRef {
    RepoRef::parse(&format!("github:owner/repo#{commit}")).unwrap()
}

fn other_repo(commit: &str) -> RepoRef {
    RepoRef::parse(&format!("github:owner/other#{commit}")).unwrap()
}

fn local_repo(path: &str, commit: &str) -> RepoRef {
    RepoRef::parse(&format!("local:{path}#{commit}")).unwrap()
}

fn step(id: &str, argv: &[&str]) -> EnvStep {
    EnvStep {
        id: EnvStepId::parse(id).unwrap(),
        argv: argv.iter().copied().map(String::from).collect(),
        cwd: RepoRelativePath::root(),
        timeout_secs: 60,
        env: BTreeMap::new(),
    }
}

fn env_map(key: EnvKey, value: EnvValue) -> BTreeMap<EnvKey, EnvValue> {
    let mut env = BTreeMap::new();
    env.insert(key, value);
    env
}

fn init_stages(steps: Vec<EnvStep>) -> EnvBlueprintStages {
    EnvBlueprintStages {
        init: steps,
        ..EnvBlueprintStages::default()
    }
}

fn knowledge_stages(sources: Vec<KnowledgeSourceSpec>) -> EnvBlueprintStages {
    EnvBlueprintStages {
        knowledge: sources,
        ..EnvBlueprintStages::default()
    }
}

fn knowledge_source(id: &str, inputs: Vec<KnowledgeInput>) -> KnowledgeSourceSpec {
    KnowledgeSourceSpec {
        id: id.to_owned(),
        inputs,
        corpus_hint: None,
    }
}

fn blueprint(stages: EnvBlueprintStages) -> EnvBlueprint {
    EnvBlueprint::new(github_repo(COMMIT_A), stages)
}

/// One blueprint exercising every persisted string field class.
fn full_blueprint(repo_ref: &RepoRef) -> EnvBlueprint {
    let mut install = step("install", &["cargo", "fetch", "--locked"]);
    install.cwd = RepoRelativePath::parse("crates/oneiron").unwrap();
    install.env = env_map(
        EnvKey::parse("TOKEN").unwrap(),
        EnvValue::SecretRef(EnvSecretRef::parse_name("github-token").unwrap()),
    );
    install.env.insert(
        EnvKey::parse("CARGO_TERM_COLOR").unwrap(),
        EnvValue::Literal("never".to_owned()),
    );
    let path = RepoRelativePath::parse("docs/design.md").unwrap();
    let glob = RepoRelativeGlob::parse("docs/**/*.md").unwrap();
    let inputs = vec![KnowledgeInput::Path(path), KnowledgeInput::Glob(glob)];
    let mut docs = knowledge_source("docs", inputs);
    docs.corpus_hint = Some("oneiron-docs".to_owned());
    let stages = EnvBlueprintStages {
        init: vec![install],
        maintenance: vec![step("refresh", &["git", "fetch", "--prune"])],
        knowledge: vec![docs],
    };
    EnvBlueprint::new(repo_ref.clone(), stages)
}

fn read_raw_row(vault: &Vault, repo_ref: &RepoRef) -> Option<Vec<u8>> {
    let key = env_blueprint_key(repo_ref);
    let txn = vault.store.env.read_txn().unwrap();
    let raw = vault.store.vault_meta.get(&txn, &key).unwrap();
    raw.map(std::borrow::Cow::into_owned)
}

fn write_raw_row(vault: &Vault, repo_ref: &RepoRef, raw: &[u8]) {
    let key = env_blueprint_key(repo_ref);
    let written = vault.try_with_write_txn::<_, _, Error>(|txn| {
        vault.store.vault_meta.put(txn, &key, raw)?;
        Ok(())
    });
    written.expect("raw env blueprint row must be written");
}

/// Encodes a row directly, bypassing `put`, so the decode side can be proven to
/// re-run the containment validation on hand-forged bytes.
fn forged_row(repo_ref: &RepoRef, stages: EnvBlueprintStages) -> Vec<u8> {
    let version = ENV_BLUEPRINT_SCHEMA_VERSION;
    forged_row_with_versions(repo_ref, stages, version, version)
}

fn forged_row_with_versions(
    repo_ref: &RepoRef,
    stages: EnvBlueprintStages,
    header: u8,
    body: u8,
) -> Vec<u8> {
    let row = EnvBlueprintRowV1 {
        schema_version: body,
        repo_ref: repo_ref.canonical(),
        light_checkout_materialization: MaterializationSpec::Blobless,
        stages,
    };
    let mut raw = vec![header];
    raw.extend_from_slice(&rmp_serde::to_vec_named(&row).unwrap());
    raw
}

fn expect_secret_shaped(error: &EnvBlueprintError, expected_location: &str) {
    assert!(!error.to_string().contains(AWS_FIXTURE), "no echo");
    match error {
        EnvBlueprintError::SecretShapedBytes { location, reason } => {
            assert_eq!(location, expected_location);
            assert!(!location.contains(AWS_FIXTURE));
            assert!(!reason.contains(AWS_FIXTURE));
        }
        other => panic!("expected {expected_location} secret hit, got {other:?}"),
    }
}

fn validate_argv_only(argv: &[&str]) -> EnvBlueprintResult<()> {
    blueprint(init_stages(vec![step("setup", argv)])).validate()
}

fn lease(repo_ref: &RepoRef, task_class: CheckoutTaskClass) -> CheckoutLeaseAct {
    CheckoutLeaseAct {
        checkout_id: CheckoutId::from_bytes([7; 16]).unwrap(),
        task_ref: EntityId::from_bytes([1; 16]).unwrap(),
        repo_ref: repo_ref.clone(),
        holder_ref: "agent".to_owned(),
        epoch: 1,
        task_class,
        state: CheckoutLeaseState::Active,
        claimed_at: 10,
        lease_expires_at: None,
        updated_at: 10,
    }
}

/// Counting oracle: proves the consult hook reads the store exactly once and
/// never fabricates a blueprint.
struct CountingStore {
    blueprint: Option<EnvBlueprint>,
    gets: std::cell::Cell<usize>,
}

impl CountingStore {
    fn new(blueprint: Option<EnvBlueprint>) -> Self {
        Self {
            blueprint,
            gets: std::cell::Cell::new(0),
        }
    }
}

impl EnvBlueprintStore for CountingStore {
    fn put(&self, _blueprint: &EnvBlueprint) -> EnvBlueprintResult<()> {
        Ok(())
    }

    fn get(&self, _repo_ref: &RepoRef) -> EnvBlueprintResult<Option<EnvBlueprint>> {
        self.gets.set(self.gets.get() + 1);
        Ok(self.blueprint.clone())
    }
}

#[test]
fn env_blueprint_identity_is_commit_stripped_and_domain_separated() {
    let repo_a = github_repo(COMMIT_A);
    let repo_b = github_repo(COMMIT_B);
    assert_eq!(env_blueprint_repo_identity(&repo_a), "github:owner/repo");
    assert_eq!(env_blueprint_repo_identity(&repo_b), "github:owner/repo");
    assert_eq!(env_blueprint_key(&repo_a), env_blueprint_key(&repo_b));

    let local = local_repo("/srv/repo", COMMIT_A);
    assert_eq!(env_blueprint_repo_identity(&local), "local:/srv/repo");
    assert_ne!(env_blueprint_key(&local), env_blueprint_key(&repo_a));

    let key = env_blueprint_key(&repo_a);
    assert!(key.starts_with(ENV_BLUEPRINT_KEY_PREFIX));
    assert_eq!(key.len(), ENV_BLUEPRINT_KEY_PREFIX.len() + 32);
    let hash = env_blueprint_repo_hash(&repo_a);
    assert_eq!(&key[ENV_BLUEPRINT_KEY_PREFIX.len()..], &hash[..]);

    let mut hasher = blake3::Hasher::new();
    hasher.update(ENV_BLUEPRINT_REPO_KEY_DOMAIN);
    hasher.update(b"github:owner/repo");
    assert_eq!(hash, *hasher.finalize().as_bytes());
}

#[test]
fn env_blueprint_round_trips_through_rmp_serde_and_the_vault() {
    let (vault, _dir) = vault_fixture();
    let store = VaultEnvBlueprintStore::new(&vault);
    let repo = github_repo(COMMIT_A);
    let authored = full_blueprint(&repo);

    store.put(&authored).unwrap();
    let loaded = store.get(&repo).unwrap().expect("row must round-trip");
    assert_eq!(loaded, authored);
    assert_eq!(loaded.knowledge_sources().len(), 1);

    let raw = read_raw_row(&vault, &repo).expect("row must exist");
    assert_eq!(raw[0], ENV_BLUEPRINT_SCHEMA_VERSION);
    let row: EnvBlueprintRowV1 = rmp_serde::from_slice(&raw[1..]).unwrap();
    assert_eq!(row.schema_version, ENV_BLUEPRINT_SCHEMA_VERSION);
    assert_eq!(row.repo_ref, repo.canonical());
    assert_eq!(row.stages.init.len(), 1);
    assert_eq!(row.stages.knowledge.len(), 1);
}

#[test]
fn env_blueprint_row_spans_commits_but_not_repositories() {
    let (vault, _dir) = vault_fixture();
    let store = VaultEnvBlueprintStore::new(&vault);
    let repo_a = github_repo(COMMIT_A);
    store.put(&full_blueprint(&repo_a)).unwrap();

    let at_b = store.get(&github_repo(COMMIT_B)).unwrap();
    let at_b = at_b.expect("one row spans every commit of the repository");
    assert_eq!(at_b.repo_ref.canonical(), repo_a.canonical());

    assert!(store.get(&other_repo(COMMIT_A)).unwrap().is_none());
    let local = local_repo("/srv/repo", COMMIT_A);
    assert!(store.get(&local).unwrap().is_none());

    store.put(&full_blueprint(&local)).unwrap();
    let spelling = local_repo("/srv/repo/", COMMIT_A);
    assert!(store.get(&spelling).unwrap().is_none());
    assert!(store.get(&local).unwrap().is_some());
}

#[test]
fn env_blueprint_decode_rejects_empty_version_and_corrupt_rows() {
    let repo = github_repo(COMMIT_A);
    assert!(matches!(
        decode_env_blueprint(&[]),
        Err(EnvBlueprintError::EmptyRow)
    ));

    let unknown = forged_row_with_versions(&repo, EnvBlueprintStages::default(), 2, 2);
    assert!(matches!(
        decode_env_blueprint(&unknown),
        Err(EnvBlueprintError::UnsupportedSchemaVersion { found: 2 })
    ));

    let mismatched = forged_row_with_versions(&repo, EnvBlueprintStages::default(), 1, 3);
    match decode_env_blueprint(&mismatched) {
        Err(EnvBlueprintError::SchemaVersionMismatch { header, body }) => {
            assert_eq!((header, body), (1, 3));
        }
        other => panic!("expected a schema version mismatch, got {other:?}"),
    }

    assert!(matches!(
        decode_env_blueprint(&[ENV_BLUEPRINT_SCHEMA_VERSION, 0xC1]),
        Err(EnvBlueprintError::Encode(_))
    ));

    let row = EnvBlueprintRowV1 {
        schema_version: ENV_BLUEPRINT_SCHEMA_VERSION,
        repo_ref: "not a repo ref".to_owned(),
        light_checkout_materialization: MaterializationSpec::Blobless,
        stages: EnvBlueprintStages::default(),
    };
    let mut raw = vec![ENV_BLUEPRINT_SCHEMA_VERSION];
    raw.extend_from_slice(&rmp_serde::to_vec_named(&row).unwrap());
    assert!(matches!(
        decode_env_blueprint(&raw),
        Err(EnvBlueprintError::Encode(_))
    ));
}

#[test]
fn env_blueprint_get_rejects_a_row_planted_under_a_foreign_key() {
    let (vault, _dir) = vault_fixture();
    let store = VaultEnvBlueprintStore::new(&vault);
    let planted = github_repo(COMMIT_A);
    let requested = other_repo(COMMIT_A);
    let raw = forged_row(&planted, EnvBlueprintStages::default());
    write_raw_row(&vault, &requested, &raw);

    assert!(matches!(
        store.get(&requested),
        Err(EnvBlueprintError::RepoKeyMismatch)
    ));
}

#[test]
fn hand_forged_knowledge_inputs_fail_containment_after_decode() {
    let (vault, _dir) = vault_fixture();
    let store = VaultEnvBlueprintStore::new(&vault);
    let repo = github_repo(COMMIT_A);

    let escaping_path = KnowledgeInput::Path(RepoRelativePath("../etc/passwd".to_owned()));
    let stages = knowledge_stages(vec![knowledge_source("docs", vec![escaping_path])]);
    let raw = forged_row(&repo, stages);
    let decoded = decode_env_blueprint(&raw).expect("transparent newtypes decode unparsed");
    assert!(matches!(
        decoded.validate(),
        Err(EnvBlueprintError::InvalidKnowledgeSource { .. })
    ));
    write_raw_row(&vault, &repo, &raw);
    assert!(matches!(
        store.get(&repo),
        Err(EnvBlueprintError::InvalidKnowledgeSource { .. })
    ));

    let escaping_glob = KnowledgeInput::Glob(RepoRelativeGlob("../**/*.md".to_owned()));
    let stages = knowledge_stages(vec![knowledge_source("docs", vec![escaping_glob])]);
    let decoded = decode_env_blueprint(&forged_row(&repo, stages)).unwrap();
    assert!(matches!(
        decoded.validate(),
        Err(EnvBlueprintError::InvalidKnowledgeSource { .. })
    ));
}

#[test]
fn repo_relative_paths_and_globs_share_a_closed_grammar() {
    for rejected in [
        "",
        "/etc/passwd",
        "C:\\repo",
        "C:/repo",
        "a\0b",
        "a\\b",
        "docs/",
        "/docs",
        "a//b",
        "./docs",
        "docs/./a",
        "..",
        "../docs",
        "docs/../a",
    ] {
        assert!(RepoRelativePath::parse(rejected).is_err(), "{rejected:?}");
        assert!(RepoRelativeGlob::parse(rejected).is_err(), "{rejected:?}");
    }

    assert_eq!(RepoRelativePath::root().as_str(), ".");
    assert!(RepoRelativePath::parse(".").is_ok());
    assert!(RepoRelativePath::parse("crates/oneiron/src").is_ok());
    // The root sentinel is a path-only exception; `.` is not a glob segment the
    // KNOW consumer ever needs, so the traversal grammar rejects it.
    assert!(RepoRelativeGlob::parse(".").is_err());
    assert!(RepoRelativeGlob::parse("docs/**/*.md").is_ok());
    assert!(RepoRelativeGlob::parse("docs/?.md").is_ok());
    assert!(RepoRelativeGlob::parse("**").is_ok());

    let error = RepoRelativePath::parse("/etc").unwrap_err();
    assert!(matches!(
        error,
        EnvBlueprintError::InvalidValue {
            kind: "repo_relative_path",
            ..
        }
    ));
}

#[test]
fn env_step_argv_rejects_shell_strings_and_command_string_interpreters() {
    assert!(matches!(
        validate_argv_only(&[]),
        Err(EnvBlueprintError::EmptyArgv { .. })
    ));
    assert!(matches!(
        validate_argv_only(&["  "]),
        Err(EnvBlueprintError::InvalidArgv { .. })
    ));
    assert!(matches!(
        validate_argv_only(&["git", "sta\0tus"]),
        Err(EnvBlueprintError::InvalidArgv { .. })
    ));
    assert!(matches!(
        validate_argv_only(&["cargo build && rm -rf /"]),
        Err(EnvBlueprintError::ShellStringCommand { .. })
    ));

    for smuggled in [
        vec!["/bin/sh", "-c", "echo hi"],
        vec!["bash", "-lc", "echo hi"],
        vec!["powershell", "-Command", "echo hi"],
        vec!["/usr/bin/env", "-i", "bash", "-c", "echo hi"],
        vec!["C:\\Windows\\System32\\cmd.exe", "/C", "dir"],
        vec!["env", "FOO=bar", "zsh", "-xc", "echo hi"],
        vec!["/usr/local/bin/pwsh", "-EncodedCommand", "ZQBjAGgAbwA="],
    ] {
        let outcome = validate_argv_only(&smuggled);
        assert!(
            matches!(
                outcome,
                Err(EnvBlueprintError::ShellInterpreterCommand { .. })
            ),
            "argv must reject {smuggled:?}"
        );
    }

    for allowed in [
        vec!["git", "status"],
        vec!["/usr/bin/make", "build"],
        vec!["python", "script.py", "a;b"],
        vec!["env", "FOO=bar", "git", "status"],
        vec!["bash", "scripts/setup.sh"],
    ] {
        assert!(validate_argv_only(&allowed).is_ok(), "{allowed:?}");
    }
}

#[test]
fn env_step_cwd_and_keys_are_grammar_checked_on_every_validation() {
    let mut absolute = step("setup", &["git", "status"]);
    absolute.cwd = RepoRelativePath("/etc".to_owned());
    assert!(matches!(
        blueprint(init_stages(vec![absolute])).validate(),
        Err(EnvBlueprintError::InvalidCwd { .. })
    ));

    let mut escaping = step("setup", &["git", "status"]);
    escaping.cwd = RepoRelativePath("../outside".to_owned());
    assert!(matches!(
        blueprint(init_stages(vec![escaping])).validate(),
        Err(EnvBlueprintError::InvalidCwd { .. })
    ));

    for bad_key in ["1BAD", "BAD-KEY", ""] {
        let mut bad_step = step("setup", &["git", "status"]);
        let literal = EnvValue::Literal("value".to_owned());
        bad_step.env = env_map(EnvKey(bad_key.to_owned()), literal);
        assert!(
            matches!(
                blueprint(init_stages(vec![bad_step])).validate(),
                Err(EnvBlueprintError::InvalidEnvKey { .. })
            ),
            "env key must reject {bad_key:?}"
        );
    }
}

#[test]
fn env_literal_values_reject_nul_bytes_without_echoing_them() {
    let mut nul_step = step("setup", &["git", "status"]);
    let key = EnvKey::parse("TOKEN").unwrap();
    nul_step.env = env_map(key, EnvValue::Literal("a\0b".to_owned()));
    let error = blueprint(init_stages(vec![nul_step]))
        .validate()
        .unwrap_err();
    assert!(matches!(
        error,
        EnvBlueprintError::InvalidValue {
            kind: "env_value",
            ..
        }
    ));
    assert!(!error.to_string().contains('\0'));
}

#[test]
fn detector_verdict_wins_over_contextual_cwd_and_env_key_errors() {
    let mut secret_cwd = step("setup", &["git", "status"]);
    secret_cwd.cwd = RepoRelativePath::parse(AWS_FIXTURE).unwrap();
    let stages = init_stages(vec![secret_cwd]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step:setup:cwd");

    let mut secret_key = step("setup", &["git", "status"]);
    let key = EnvKey::parse(AWS_FIXTURE).unwrap();
    secret_key.env = env_map(key, EnvValue::Literal("value".to_owned()));
    let stages = init_stages(vec![secret_key]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step:setup:env_key[0]");
}

#[test]
fn detector_covers_literal_argv_and_corpus_hint_payloads() {
    let mut literal = step("setup", &["git", "status"]);
    let key = EnvKey::parse("TOKEN").unwrap();
    literal.env = env_map(key, EnvValue::Literal(AWS_FIXTURE.to_owned()));
    let error = blueprint(init_stages(vec![literal]))
        .validate()
        .unwrap_err();
    expect_secret_shaped(&error, "step:setup:env:TOKEN");

    let argv_step = step("setup", &["echo", AWS_FIXTURE]);
    let stages = init_stages(vec![argv_step]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step:setup:argv[1]");

    let input = KnowledgeInput::Path(RepoRelativePath::parse("docs/design.md").unwrap());
    let mut source = knowledge_source("docs", vec![input]);
    source.corpus_hint = Some(AWS_FIXTURE.to_owned());
    let stages = knowledge_stages(vec![source]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "knowledge:docs:corpus_hint");
}

#[test]
fn detector_covers_step_ids_knowledge_ids_and_secret_ref_names() {
    let stages = init_stages(vec![step(AWS_FIXTURE, &["git", "status"])]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step_id:init[0]");

    let stages = EnvBlueprintStages {
        init: vec![step("setup", &["git", "status"])],
        maintenance: vec![step(AWS_FIXTURE, &["git", "fetch"])],
        knowledge: Vec::new(),
    };
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step_id:maintenance[0]");

    let input = KnowledgeInput::Path(RepoRelativePath::parse("docs/design.md").unwrap());
    let stages = knowledge_stages(vec![knowledge_source(AWS_FIXTURE, vec![input])]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "knowledge_id:0");

    let mut secret_named = step("setup", &["git", "status"]);
    let key = EnvKey::parse("TOKEN").unwrap();
    let name = EnvSecretRef::parse_name(AWS_FIXTURE).unwrap();
    secret_named.env = env_map(key, EnvValue::SecretRef(name));
    let stages = init_stages(vec![secret_named]);
    let error = blueprint(stages).validate().unwrap_err();
    expect_secret_shaped(&error, "step:setup:secret_ref:TOKEN");
}

#[test]
fn identifiers_and_secret_names_reject_control_bytes_before_the_detector() {
    assert!(EnvStepId::parse("a\u{1}b").is_err());
    assert!(EnvStepId::parse("").is_err());
    assert!(EnvSecretRef::parse_name("a\0b").is_err());
    assert!(EnvSecretRef::parse_name("").is_err());
    assert!(EnvSecretRef::parse_name("github-token").is_ok());
    assert!(EnvKey::parse("1BAD").is_err());
    assert!(EnvKey::parse("_OK1").is_ok());

    let forged_id = EnvStep {
        id: EnvStepId("a\nb".to_owned()),
        ..step("ignored", &["git", "status"])
    };
    assert!(matches!(
        blueprint(init_stages(vec![forged_id])).validate(),
        Err(EnvBlueprintError::InvalidValue {
            kind: "step_id",
            ..
        })
    ));

    let input = KnowledgeInput::Path(RepoRelativePath::parse("docs/design.md").unwrap());
    let stages = knowledge_stages(vec![knowledge_source("a\u{7f}b", vec![input])]);
    assert!(matches!(
        blueprint(stages).validate(),
        Err(EnvBlueprintError::InvalidValue {
            kind: "knowledge_source_id",
            ..
        })
    ));

    let mut empty_named = step("setup", &["git", "status"]);
    let key = EnvKey::parse("TOKEN").unwrap();
    empty_named.env = env_map(key, EnvValue::SecretRef(EnvSecretRef(String::new())));
    assert!(matches!(
        blueprint(init_stages(vec![empty_named])).validate(),
        Err(EnvBlueprintError::EmptySecretRef { .. })
    ));
}

#[test]
fn step_and_knowledge_ids_are_unique_across_stages() {
    let stages = EnvBlueprintStages {
        init: vec![step("setup", &["git", "status"])],
        maintenance: vec![step("setup", &["git", "fetch"])],
        knowledge: Vec::new(),
    };
    assert!(matches!(
        blueprint(stages).validate(),
        Err(EnvBlueprintError::DuplicateStepId { .. })
    ));

    let path = KnowledgeInput::Path(RepoRelativePath::parse("docs/a.md").unwrap());
    let glob = KnowledgeInput::Glob(RepoRelativeGlob::parse("docs/*.md").unwrap());
    let stages = knowledge_stages(vec![
        knowledge_source("docs", vec![path]),
        knowledge_source("docs", vec![glob]),
    ]);
    assert!(matches!(
        blueprint(stages).validate(),
        Err(EnvBlueprintError::DuplicateKnowledgeSourceId { .. })
    ));

    let stages = knowledge_stages(vec![knowledge_source("docs", Vec::new())]);
    assert!(matches!(
        blueprint(stages).validate(),
        Err(EnvBlueprintError::InvalidKnowledgeSource { .. })
    ));
}

#[test]
fn materialization_ladder_is_closed_and_task_class_pinned() {
    assert_eq!(MaterializationSpec::FullClone as u8, 1);
    assert_eq!(MaterializationSpec::Blobless as u8, 2);
    assert_eq!(
        MaterializationSpec::default(),
        MaterializationSpec::Blobless
    );

    for preference in [None, Some(MaterializationSpec::Blobless)] {
        assert_eq!(
            resolve_materialization(CheckoutTaskClass::Build, preference),
            MaterializationSpec::FullClone
        );
        assert_eq!(
            resolve_materialization(CheckoutTaskClass::Verify, preference),
            MaterializationSpec::FullClone
        );
        assert_eq!(
            resolve_materialization(CheckoutTaskClass::Edit, preference),
            MaterializationSpec::Blobless
        );
        assert_eq!(
            resolve_materialization(CheckoutTaskClass::Effect, preference),
            MaterializationSpec::Blobless
        );
    }

    let heavy = Some(MaterializationSpec::FullClone);
    assert_eq!(
        resolve_materialization(CheckoutTaskClass::Edit, heavy),
        MaterializationSpec::FullClone
    );
    assert_eq!(
        resolve_materialization(CheckoutTaskClass::Effect, heavy),
        MaterializationSpec::FullClone
    );

    let mut authored = full_blueprint(&github_repo(COMMIT_A));
    assert_eq!(
        authored.resolve_materialization(CheckoutTaskClass::Build),
        MaterializationSpec::FullClone
    );
    authored.light_checkout_materialization = MaterializationSpec::FullClone;
    assert_eq!(
        authored.resolve_materialization(CheckoutTaskClass::Edit),
        MaterializationSpec::FullClone
    );
}

#[test]
fn checkout_plan_projects_materialization_and_steps_only() {
    let authored = full_blueprint(&github_repo(COMMIT_A));
    let plan = authored.checkout_plan(CheckoutTaskClass::Edit).unwrap();
    assert!(!plan.is_legacy());
    assert_eq!(
        plan.materialization,
        CheckoutMaterializationOptions::resolved(MaterializationSpec::Blobless)
    );
    assert_eq!(plan.init, authored.stages.init);
    assert_eq!(plan.maintenance, authored.stages.maintenance);
    // Knowledge stays retrievable but has no executor-facing field at all.
    assert_eq!(authored.knowledge_sources().len(), 1);

    let build = authored.checkout_plan(CheckoutTaskClass::Build).unwrap();
    assert_eq!(
        build.materialization,
        CheckoutMaterializationOptions::resolved(MaterializationSpec::FullClone)
    );

    let smuggled = step("setup", &["/bin/sh", "-c", "hi"]);
    let invalid = blueprint(init_stages(vec![smuggled]));
    assert!(matches!(
        invalid.checkout_plan(CheckoutTaskClass::Edit),
        Err(EnvBlueprintError::ShellInterpreterCommand { .. })
    ));
}

#[test]
fn resolve_checkout_environment_is_legacy_with_exactly_one_store_get() {
    let repo = github_repo(COMMIT_A);
    let store = CountingStore::new(None);
    let act = lease(&repo, CheckoutTaskClass::Edit);

    let plan = resolve_checkout_environment(&store, &act).unwrap();
    assert_eq!(plan, CheckoutEnvPlan::legacy());
    assert!(plan.is_legacy());
    assert!(plan.materialization.spec.is_none());
    assert!(plan.init.is_empty() && plan.maintenance.is_empty());
    assert_eq!(store.gets.get(), 1);
}

#[test]
fn resolve_checkout_environment_projects_a_stored_blueprint() {
    let repo = github_repo(COMMIT_A);
    let store = CountingStore::new(Some(full_blueprint(&repo)));
    let act = lease(&github_repo(COMMIT_B), CheckoutTaskClass::Build);

    let plan = resolve_checkout_environment(&store, &act).unwrap();
    assert!(!plan.is_legacy());
    let spec = Some(MaterializationSpec::FullClone);
    assert_eq!(plan.materialization.spec, spec);
    assert_eq!(plan.init.len(), 1);
    assert_eq!(plan.maintenance.len(), 1);
    assert_eq!(store.gets.get(), 1);

    let foreign = CountingStore::new(Some(full_blueprint(&other_repo(COMMIT_A))));
    assert!(matches!(
        resolve_checkout_environment(&foreign, &act),
        Err(EnvBlueprintError::RepoKeyMismatch)
    ));
}

#[test]
fn secret_ref_names_round_trip_without_secret_bytes() {
    let (vault, _dir) = vault_fixture();
    let store = VaultEnvBlueprintStore::new(&vault);
    let repo = github_repo(COMMIT_A);
    store.put(&full_blueprint(&repo)).unwrap();

    let loaded = store.get(&repo).unwrap().expect("row must round-trip");
    let install = &loaded.stages.init[0];
    let key = EnvKey::parse("TOKEN").unwrap();
    match install.env.get(&key).unwrap() {
        EnvValue::SecretRef(name) => assert_eq!(name.as_str(), "github-token"),
        other => panic!("expected a custody name, got {other:?}"),
    }

    let raw = read_raw_row(&vault, &repo).expect("row must exist");
    assert!(scan_file_content("row", &raw).is_none());
}

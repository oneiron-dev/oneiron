//! Real Git repositories and loopback static HTTP fixtures; no mocked adapter calls.
use super::*;
use crate::{
    attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome},
    entity_id::EntityId,
    error::{ErrorKind, Result},
};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct ReadyFit;
impl MarketplaceFitEvaluator for ReadyFit {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision> {
        MarketplaceFitDecision::new(
            source,
            package,
            MarketplaceFit::Ready,
            "fixture fit",
            static_scan,
        )
    }
}

struct FixedFit(MarketplaceFit);
impl MarketplaceFitEvaluator for FixedFit {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision> {
        MarketplaceFitDecision::new(
            source,
            package,
            self.0,
            "fixture permission review",
            static_scan,
        )
    }
}

struct WrongSourceFit;
impl MarketplaceFitEvaluator for WrongSourceFit {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision> {
        let other = HubRef::new(EntityId::now(), &source.ref_string, source.pin.clone())?;
        MarketplaceFitDecision::new(
            &other,
            package,
            MarketplaceFit::Ready,
            "mismatched source",
            static_scan,
        )
    }
}

fn files(name: &str, version: &str, body: &str) -> Vec<HubFile> {
    vec![
        HubFile::new(
            "SKILL.md",
            format!("---\nname: {name}\ndescription: fixture\nversion: {version}\n---\n{body}\n")
                .into_bytes(),
        ),
        HubFile::new("references/source.txt", b"source fixture\n".to_vec()),
    ]
}
fn git(root: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.templateDir=",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .expect("local git fixture");
    assert!(output.status.success(), "local git fixture command failed");
    String::from_utf8(output.stdout)
        .expect("git UTF-8")
        .trim()
        .to_owned()
}
fn populate(root: &std::path::Path, files: &[HubFile]) {
    for file in files {
        let path = root.join("skills/example").join(&file.path);
        std::fs::create_dir_all(path.parent().expect("file parent")).expect("mkdir");
        std::fs::write(path, &file.content).expect("write fixture");
    }
}
#[test]
#[cfg(unix)]
fn pinned_git_fetches_only_subtree_and_refuses_tag_drift_and_symlink() -> Result<()> {
    let temp = tempfile::tempdir().expect("repo");
    git(temp.path(), &["init", "--quiet"]);
    let tree = files("fixture.skill", "1", "first version");
    populate(temp.path(), &tree);
    std::fs::write(temp.path().join("unrelated.txt"), b"not in package").expect("outside subtree");
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-qm", "one"]);
    git(temp.path(), &["tag", "v1"]);
    let commit = git(temp.path(), &["rev-parse", "HEAD"]);
    let canary = temp.path().join("hook-ran");
    let hook = format!("echo escaped > {}; git pack-objects", canary.display());
    git(
        temp.path(),
        &["config", "uploadpack.packObjectsHook", &hook],
    );
    let hub = EntityId::now();
    let adapter =
        GitEndpointSkillHubAdapter::new(hub, temp.path().to_str().expect("path"), &commit)?;
    let reference = HubRef::new(hub, "skills/example", HubPin::Tag("v1".to_owned()))?;
    let package = adapter.fetch_package(&reference)?;
    assert_eq!(package.export_files()?, tree);
    assert!(!canary.exists());
    assert_eq!(
        package.record.lifecycle_status,
        crate::skill::SkillLifecycle::Candidate
    );
    assert_eq!(adapter.resolved_commit(), commit);
    populate(temp.path(), &files("fixture.skill", "2", "changed"));
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-qm", "two"]);
    git(temp.path(), &["tag", "-f", "v1"]);
    assert_eq!(
        adapter
            .fetch_package(&reference)
            .expect_err("tag drift")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let pinned = HubRef::new(
        hub,
        "skills/example",
        HubPin::ContentHash(package.content_hash()?.to_hex()),
    )?;
    assert_eq!(
        adapter.fetch_package(&pinned)?.content_hash()?,
        package.content_hash()?
    );
    std::os::unix::fs::symlink("/etc/passwd", temp.path().join("skills/example/escape"))
        .expect("symlink fixture");
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-qm", "symlink"]);
    let linked_commit = git(temp.path(), &["rev-parse", "HEAD"]);
    let linked =
        GitEndpointSkillHubAdapter::new(hub, temp.path().to_str().expect("path"), &linked_commit)?;
    let reference = HubRef::new(hub, "skills/example", HubPin::Commit(linked_commit))?;
    assert_eq!(
        linked
            .fetch_package(&reference)
            .expect_err("symlink")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

struct StaticHttp {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl StaticHttp {
    fn new(routes: BTreeMap<String, (u16, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let address = listener.local_addr().expect("address");
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            for connection in listener.incoming() {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let mut stream = connection.expect("connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                let mut reader = BufReader::new(stream.try_clone().expect("reader"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("request line");
                let path = line.split_whitespace().nth(1).expect("GET path").to_owned();
                loop {
                    line.clear();
                    reader.read_line(&mut line).expect("header");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                }
                let (status, body) = routes.get(&path).cloned().unwrap_or((404, Vec::new()));
                write!(
                    stream,
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .expect("response");
                stream.write_all(&body).expect("body");
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn index_url(&self) -> String {
        format!("http://{}/index.json", self.address)
    }
}
impl Drop for StaticHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("static HTTP fixture");
        }
    }
}
fn routes(tree: &[HubFile]) -> BTreeMap<String, (u16, Vec<u8>)> {
    let package = super::folder::package_from_files(tree.to_vec()).expect("package");
    let entries = tree
        .iter()
        .map(|file| serde_json::json!({"path": file.path, "url": file.path}))
        .collect::<Vec<_>>();
    let index = serde_json::json!({"schema":1,"packages":[{"name":package.record.skill_id,
        "description":package.record.desc,"version":package.record.version,"content_hash":package.content_hash().expect("hash").to_hex(),
        "ref_string":"fixture","files":entries}]});
    let mut routes = BTreeMap::from([(
        "/index.json".to_owned(),
        (200, serde_json::to_vec(&index).expect("index")),
    )]);
    for file in tree {
        routes.insert(format!("/{}", file.path), (200, file.content.clone()));
    }
    routes
}
#[test]
fn static_http_discovery_fetch_hash_drift_and_url_authority() -> Result<()> {
    let tree = files("fixture.skill", "1", "static HTTP fixture");
    let server = StaticHttp::new(routes(&tree));
    let hub = EntityId::now();
    let adapter = HttpEndpointSkillHubAdapter::new(hub, &server.index_url())?;
    let index = adapter.discover()?;
    assert_eq!(index.len(), 1);
    let reference = HubRef::new(
        hub,
        &index[0].ref_string,
        HubPin::ContentHash(index[0].content_hash.to_hex()),
    )?;
    assert_eq!(adapter.fetch_package(&reference)?.export_files()?, tree);
    let mut changed = routes(&tree);
    changed.insert(
        "/SKILL.md".to_owned(),
        (
            200,
            files("fixture.skill", "1", "tampered")[0].content.clone(),
        ),
    );
    let drift = StaticHttp::new(changed);
    let adapter = HttpEndpointSkillHubAdapter::new(hub, &drift.index_url())?;
    assert_eq!(
        adapter
            .fetch_package(&reference)
            .expect_err("hash drift")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(
        HttpEndpointSkillHubAdapter::new(hub, "https://actor:password@example.invalid/index.json")
            .is_err()
    );
    assert!(
        HttpEndpointSkillHubAdapter::new(hub, "https://example.invalid/index.json?token=secret")
            .is_err()
    );
    Ok(())
}
#[test]
fn static_http_refuses_redirect_and_unknown_index_fields() -> Result<()> {
    let redirect = StaticHttp::new(BTreeMap::from([(
        "/index.json".to_owned(),
        (302, Vec::new()),
    )]));
    let adapter = HttpEndpointSkillHubAdapter::new(EntityId::now(), &redirect.index_url())?;
    assert!(adapter.discover().is_err());
    let unknown = StaticHttp::new(BTreeMap::from([(
        "/index.json".to_owned(),
        (
            200,
            br#"{"schema":1,"packages":[],"credentials":"refused"}"#.to_vec(),
        ),
    )]));
    assert!(
        HttpEndpointSkillHubAdapter::new(EntityId::now(), &unknown.index_url())?
            .discover()
            .is_err()
    );
    Ok(())
}
#[test]
fn stored_package_roundtrip_is_bounded_and_cannot_forge_file_identity() -> Result<()> {
    let package = super::folder::package_from_files(files("fixture.skill", "1", "round trip"))?;
    let bytes = encode_hub_package(&package)?;
    assert_eq!(decode_hub_package(&bytes)?, package);
    let mut mismatch = package.clone();
    let mut false_hash = *package.content_hash()?.as_bytes();
    false_hash[0] ^= 1;
    mismatch.record.content_hash = Some(crate::skill::SkillContentHash::from_bytes(false_hash));
    assert_eq!(
        encode_hub_package(&mismatch)
            .expect_err("encoder binds declared identity too")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_hub_package(&trailing).is_err());
    let mut forged = bytes;
    forged[20..24].fill(0xff);
    assert!(decode_hub_package(&forged).is_err());
    Ok(())
}

#[test]
fn real_http_ingress_stamps_admitted_publisher_and_dedups_two_source_receipts() -> Result<()> {
    let tree = files("fixture.skill", "1", "published fixture");
    let first_server = StaticHttp::new(routes(&tree));
    let second_server = StaticHttp::new(routes(&tree));
    let temp = tempfile::tempdir().expect("vault");
    let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let owner_id = EntityId::now();
    let at = crate::temporal::TimeRange { start: 10, end: 10 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:fixture",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut imported = Vec::new();
    for server in [&first_server, &second_server] {
        let hub_id = EntityId::now();
        let hub = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            server.index_url(),
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )?;
        vault.configure_skill_hub(&owner, &hub_id, &hub, at, 10)?;
        let publisher = vault.admit_skill_publisher(&owner, "publisher:fixture", hub_id)?;
        let adapter = HttpEndpointSkillHubAdapter::new(hub_id, &server.index_url())?;
        let index = adapter.discover()?;
        let source = HubRef::new(
            hub_id,
            "fixture",
            HubPin::ContentHash(index[0].content_hash.to_hex()),
        )?;
        let entity = vault.import_marketplace_skill_from_adapter(
            &adapter,
            &source,
            &publisher,
            &ReadyFit,
            at,
            10 + imported.len() as u64,
        )?;
        let receipt = vault
            .hub_import_receipt(&entity, &source)?
            .expect("import receipt");
        assert_eq!(receipt.publisher.as_deref(), Some(publisher.identity()));
        assert_eq!(
            receipt.publisher_grant.as_deref(),
            Some(publisher.grant_ref())
        );
        assert_eq!(receipt.content_hash, index[0].content_hash.to_hex());
        assert_eq!(receipt.hub_id, hub_id.to_hex());
        assert_eq!(receipt.ref_string, source.ref_string);
        assert_eq!(receipt.installed_as, InstallLifecycle::Active);
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("installed skill")
                .lifecycle_status,
            crate::skill::SkillLifecycle::Active,
        );
        assert!(vault.hub_admission_receipt(&entity)?.is_none());
        imported.push(entity);
    }
    assert_eq!(imported[0], imported[1]);
    assert_eq!(vault.skill_hub_provenance_count(&imported[0])?, 2);
    crate::test_util::authorize_readers(&vault, &["viewer"]);
    let read = vault.scoped_read(crate::claim::ScopedReadActorKey::new("viewer").unwrap());
    let latest = crate::context_board::SessionReadSet::default().refresh(&read, 1)?;
    assert_eq!(latest.install_rows.len(), 1);
    assert_eq!(latest.install_rows[0].at, 11);
    let changes = crate::context_board::SessionReadSet::default().refresh(&read, 16)?;
    let rendered = crate::context_board::render_board_block(
        &crate::context_board::BoardFrame {
            header: &crate::context_board::BoardBlockHeader {
                epoch: 1,
                scope: "base".into(),
            },
            legend: &crate::context_board::BoardLegend::canonical(),
            sections: &[],
            changes: Some(&changes),
        },
        crate::context_board::BoardBudgetRequest {
            harness_default_tok: 0,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .expect("board render");
    assert!(rendered.text.contains("changed_install[2:]"));
    assert!(rendered.text.contains("installed"));
    for receipt in &changes.install_rows {
        assert_eq!(receipt.entity, imported[0].to_hex());
        assert!(rendered.text.contains(&receipt.hub_id));
    }
    Ok(())
}

#[test]
fn marketplace_code_and_rules_hits_remain_candidate_until_policy_allows() -> Result<()> {
    use crate::skill::{SkillLifecycle, encode_skill_record};
    let mut tree = files("fixture.code", "1", "Run the supplied script.");
    tree[0].content = b"---\nname: fixture.code\ndescription: fixture\nversion: 1\nrequires-bins: [\"python3\"]\n---\nRun the supplied script.\n".to_vec();
    tree.push(HubFile::new("scripts/run.py", b"print(1)\n"));
    let server = StaticHttp::new(routes(&tree));
    let temp = tempfile::tempdir()?;
    let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let owner_id = EntityId::now();
    let at = crate::TimeRange { start: 10, end: 10 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:fixture",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub_id = EntityId::now();
    vault.configure_skill_hub(
        &owner,
        &hub_id,
        &SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            server.index_url(),
            SkillHubTrustTier::Verified,
            HubSyncPolicy::ContentHashFrozen,
        )?,
        at,
        10,
    )?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:fixture", hub_id)?;
    let adapter = HttpEndpointSkillHubAdapter::new(hub_id, &server.index_url())?;
    let source = HubRef::new(
        hub_id,
        "fixture",
        HubPin::ContentHash(adapter.discover()?[0].content_hash.to_hex()),
    )?;
    assert_eq!(
        vault
            .import_marketplace_skill_from_adapter(
                &adapter,
                &source,
                &publisher,
                &WrongSourceFit,
                at,
                10
            )
            .expect_err("fit cannot authorize another source")
            .kind(),
        ErrorKind::InvalidSkillBody,
    );
    let id = vault
        .import_marketplace_skill_from_adapter(&adapter, &source, &publisher, &ReadyFit, at, 10)?;
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        vault
            .hub_import_receipt(&id, &source)?
            .unwrap()
            .installed_as,
        InstallLifecycle::Candidate
    );
    crate::test_util::authorize_readers(&vault, &["viewer"]);
    let read = vault.scoped_read(crate::claim::ScopedReadActorKey::new("viewer").unwrap());
    let changes = crate::context_board::SessionReadSet::default().refresh(&read, 16)?;
    assert!(
        changes
            .render()
            .join("\n")
            .contains("code_auto_install_off")
    );
    let mut forged = vault.get_skill_record(&id)?.unwrap();
    forged.lifecycle_status = SkillLifecycle::Active;
    assert!(
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_SKILL,
                at,
                11,
                &encode_skill_record(&forged)?
            )
            .commit()
            .is_err()
    );
    // Host-controlled code flag is separate from sandbox qualification.
    vault.set_marketplace_code_auto_install(&owner, true)?;
    // Fit and owner rules, not the advisory scan threshold, govern activation.
    for (fit, outcome) in [
        (MarketplaceFit::Ask, "ask_permissions"),
        (MarketplaceFit::NoFit, "not_fit"),
    ] {
        assert_eq!(
            vault.import_marketplace_skill_from_adapter(
                &adapter,
                &source,
                &publisher,
                &FixedFit(fit),
                at,
                13
            )?,
            id,
        );
        assert_eq!(
            vault.get_skill_record(&id)?.unwrap().lifecycle_status,
            SkillLifecycle::Candidate
        );
        assert_eq!(
            vault
                .hub_import_receipt(&id, &source)?
                .unwrap()
                .disposition
                .as_str(),
            outcome
        );
        if fit == MarketplaceFit::Ask {
            let ask = vault.hub_import_receipt(&id, &source)?.expect("fit ask");
            assert_eq!(ask.requested_permissions, ["bin:python3"]);
            let changed = crate::context_board::SessionReadSet::default().refresh(&read, 16)?;
            assert!(
                changed
                    .render()
                    .join("\n")
                    .contains("fixture permission review")
            );
        }
    }
    let hash = adapter.discover()?[0].content_hash;
    vault.set_marketplace_blocked_hash(&owner, hash, true)?;
    assert_eq!(
        vault.import_marketplace_skill_from_adapter(
            &adapter, &source, &publisher, &ReadyFit, at, 13
        )?,
        id
    );
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        vault
            .hub_import_receipt(&id, &source)?
            .unwrap()
            .disposition
            .as_str(),
        "rules_hit"
    );
    vault.set_marketplace_blocked_hash(&owner, hash, false)?;
    // A scanner signal at Low is advisory once the host's exact fit is Ready.
    crate::skill_scan::set_skill_scan_activation_risk_threshold(&vault, ScanRiskLevel::Low)?;
    assert_eq!(
        vault.import_marketplace_skill_from_adapter(
            &adapter, &source, &publisher, &ReadyFit, at, 14,
        )?,
        id
    );
    let installed = vault.get_skill_record(&id)?.expect("fit-ready install");
    assert_eq!(installed.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(
        installed.approval_status,
        crate::claim::ClaimApprovalStatus::Auto
    );
    let receipt = vault
        .hub_import_receipt(&id, &source)?
        .expect("installed receipt");
    assert_eq!(receipt.disposition, InstallDisposition::Installed);
    assert_eq!(receipt.installed_as, InstallLifecycle::Active);
    crate::skill_scan::set_skill_scan_activation_risk_threshold(&vault, ScanRiskLevel::High)?;
    assert_eq!(
        vault.import_marketplace_skill_from_adapter(
            &adapter, &source, &publisher, &ReadyFit, at, 15,
        )?,
        id
    );
    assert_eq!(
        vault.hub_import_receipt(&id, &source)?.unwrap().disposition,
        InstallDisposition::AlreadyInstalled
    );
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "marketplace.scan-reimport".into(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 30,
    })?
    else {
        panic!("fresh attempt");
    };
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "marketplace.scan-reimport",
        ClaimAttempt {
            lease_owner: "hub-worker".into(),
            now: 31,
        },
    )?
    else {
        panic!("leased attempt");
    };
    assert_eq!(leased.id, attempt.id);
    let loaded = vault.load_attempt_skill_pack(
        attempt.id,
        &id,
        "hub-worker",
        leased.attempt_count,
        "hub-model@1",
        31,
    )?;
    assert_eq!(
        loaded.record.approval_status,
        crate::claim::ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[test]
fn inactive_reimports_preserve_local_state_and_report_no_install_from_two_hubs() -> Result<()> {
    use crate::{claim::ClaimApprovalStatus, skill::SkillLifecycle};
    for inactive in [
        SkillLifecycle::Stale,
        SkillLifecycle::Quarantined,
        SkillLifecycle::Superseded,
        SkillLifecycle::Active,
    ] {
        let tree = files("fixture.inactive", "1", "Preserve this skill.");
        let servers = [
            StaticHttp::new(routes(&tree)),
            StaticHttp::new(routes(&tree)),
        ];
        let temp = tempfile::tempdir()?;
        let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
        let owner_id = EntityId::now();
        let at = crate::TimeRange { start: 10, end: 10 };
        vault.put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            at,
            10,
            b"owner",
        )?;
        let owner = vault.authenticate_owner(
            owner_id,
            "principal:inactive",
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let mut sources = Vec::new();
        for server in &servers {
            let hub_id = EntityId::now();
            vault.configure_skill_hub(
                &owner,
                &hub_id,
                &SkillHubRecord::new(
                    SkillHubKind::HttpIndex,
                    server.index_url(),
                    SkillHubTrustTier::Verified,
                    HubSyncPolicy::ContentHashFrozen,
                )?,
                at,
                10,
            )?;
            let publisher = vault.admit_skill_publisher(&owner, "publisher:inactive", hub_id)?;
            let adapter = HttpEndpointSkillHubAdapter::new(hub_id, &server.index_url())?;
            let reference = HubRef::new(
                hub_id,
                "fixture",
                HubPin::ContentHash(adapter.discover()?[0].content_hash.to_hex()),
            )?;
            sources.push((adapter, reference, publisher));
        }
        let (adapter, reference, publisher) = &sources[0];
        let id = vault.import_marketplace_skill_from_adapter(
            adapter, reference, publisher, &ReadyFit, at, 10,
        )?;
        let mut record = vault.get_skill_record(&id)?.expect("installed skill");
        match inactive {
            SkillLifecycle::Active => {
                record.approval_status = ClaimApprovalStatus::Proposed;
                vault.update_skill_record(&id, &record, at, 11)?;
            }
            SkillLifecycle::Stale => {
                record.lifecycle_status = SkillLifecycle::Stale;
                vault.update_skill_record(&id, &record, at, 11)?;
            }
            SkillLifecycle::Quarantined => {
                record.lifecycle_status = SkillLifecycle::Quarantined;
                record.approval_status = ClaimApprovalStatus::Approved;
                vault.update_skill_record(&id, &record, at, 11)?;
            }
            SkillLifecycle::Superseded => {
                let successor = EntityId::now();
                let mut newer = super::folder::package_from_files(files(
                    "fixture.inactive",
                    "2",
                    "New revision.",
                ))?
                .record;
                newer.source = crate::claim::ClaimSource::UserStated;
                newer.content_hash = None;
                vault.put_skill_record(&successor, &newer, at, 11)?;
                newer.lifecycle_status = SkillLifecycle::Active;
                vault.update_skill_record(&successor, &newer, at, 12)?;
                vault.supersede_skill_record(&id, &successor, at, 13)?;
            }
            _ => unreachable!(),
        }
        for (adapter, source, publisher) in &sources {
            for fit in [MarketplaceFit::Ready, MarketplaceFit::Ask] {
                assert_eq!(
                    vault.import_marketplace_skill_from_adapter(
                        adapter,
                        source,
                        publisher,
                        &FixedFit(fit),
                        at,
                        20,
                    )?,
                    id
                );
                let receipt = vault
                    .hub_import_receipt(&id, source)?
                    .expect("source receipt");
                assert_eq!(receipt.installed_as.as_str(), inactive.as_str());
                let reason = match inactive {
                    SkillLifecycle::Stale => InstallHoldReason::Stale,
                    SkillLifecycle::Quarantined => InstallHoldReason::Quarantined,
                    SkillLifecycle::Superseded => InstallHoldReason::Superseded,
                    SkillLifecycle::Active => InstallHoldReason::UnloadableApproval,
                    _ => unreachable!(),
                };
                assert_eq!(
                    receipt.disposition,
                    InstallDisposition::NotInstalled(reason)
                );
                assert_eq!(
                    vault.get_skill_record(&id)?.unwrap().lifecycle_status,
                    inactive
                );
                assert!(
                    vault
                        .approve_marketplace_permission_ask(&owner, &id, source, at, 21,)
                        .is_err()
                );
                let queue = AttemptQueue::new(&vault);
                let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
                    kind: "inactive.marketplace".into(),
                    payload: vec![],
                    dedupe_key: None,
                    run_id: None,
                    now: 22,
                })?
                else {
                    panic!("fresh attempt");
                };
                let ClaimOutcome::Claimed(leased) = queue.claim_kind(
                    "inactive.marketplace",
                    ClaimAttempt {
                        lease_owner: "hub-worker".into(),
                        now: 23,
                    },
                )?
                else {
                    panic!("leased attempt");
                };
                assert_eq!(leased.id, attempt.id);
                assert!(
                    vault
                        .load_attempt_skill_pack(
                            attempt.id,
                            &id,
                            "hub-worker",
                            leased.attempt_count,
                            "hub-model@1",
                            23,
                        )
                        .is_err()
                );
            }
        }
        assert_eq!(vault.skill_hub_provenance_count(&id)?, 2);
        crate::test_util::authorize_readers(&vault, &["inactive-reader"]);
        let read =
            vault.scoped_read(crate::claim::ScopedReadActorKey::new("inactive-reader").unwrap());
        let lines = crate::context_board::SessionReadSet::default()
            .refresh(&read, 16)?
            .render();
        assert!(lines.join("\n").contains(&format!(
                "{}/{}",
                inactive.as_str(),
                InstallDisposition::NotInstalled(match inactive {
                    SkillLifecycle::Stale => InstallHoldReason::Stale,
                    SkillLifecycle::Quarantined => InstallHoldReason::Quarantined,
                    SkillLifecycle::Active => InstallHoldReason::UnloadableApproval,
                    _ => InstallHoldReason::Superseded,
                })
                .as_str()
            )));
    }
    Ok(())
}

#[test]
fn rejected_marketplace_candidate_cannot_be_activated_by_reimport_from_another_hub() -> Result<()> {
    use crate::claim::ClaimApprovalStatus;
    use crate::skill::SkillLifecycle;
    let mut tree = files("fixture.denied", "1", "Run supplied script.");
    tree.push(HubFile::new("scripts/run.py", b"print(1)\n"));
    let first = StaticHttp::new(routes(&tree));
    let second = StaticHttp::new(routes(&tree));
    let temp = tempfile::tempdir()?;
    let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let owner_id = EntityId::now();
    let at = crate::TimeRange { start: 10, end: 10 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:fixture",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut sources = Vec::new();
    for server in [&first, &second] {
        let hub_id = EntityId::now();
        vault.configure_skill_hub(
            &owner,
            &hub_id,
            &SkillHubRecord::new(
                SkillHubKind::HttpIndex,
                server.index_url(),
                SkillHubTrustTier::Verified,
                HubSyncPolicy::ContentHashFrozen,
            )?,
            at,
            10,
        )?;
        let publisher = vault.admit_skill_publisher(&owner, "publisher:fixture", hub_id)?;
        let adapter = HttpEndpointSkillHubAdapter::new(hub_id, &server.index_url())?;
        let source = HubRef::new(
            hub_id,
            "fixture",
            HubPin::ContentHash(adapter.discover()?[0].content_hash.to_hex()),
        )?;
        sources.push((adapter, source, publisher));
    }
    let (adapter, source, publisher) = &sources[0];
    let id = vault
        .import_marketplace_skill_from_adapter(adapter, source, publisher, &ReadyFit, at, 10)?;
    let mut denied = vault.get_skill_record(&id)?.expect("candidate");
    denied.approval_status = ClaimApprovalStatus::Rejected;
    vault.update_skill_record(&id, &denied, at, 11)?;
    vault.set_marketplace_code_auto_install(&owner, true)?;
    for (adapter, source, publisher) in &sources {
        assert_eq!(
            vault.import_marketplace_skill_from_adapter(
                adapter, source, publisher, &ReadyFit, at, 12
            )?,
            id
        );
        let stored = vault.get_skill_record(&id)?.expect("denied candidate");
        assert_eq!(stored.lifecycle_status, SkillLifecycle::Candidate);
        assert_eq!(stored.approval_status, ClaimApprovalStatus::Rejected);
        assert_eq!(
            vault
                .hub_import_receipt(&id, source)?
                .expect("source receipt")
                .installed_as
                .as_str(),
            "candidate"
        );
    }
    assert_eq!(vault.skill_hub_provenance_count(&id)?, 2);
    Ok(())
}

#[test]
fn code_policy_revalidates_owner_and_can_toggle_across_reopen() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let owner_id = EntityId::now();
    let survivor = EntityId::now();
    let at = crate::TimeRange { start: 1, end: 1 };
    for id in [owner_id, survivor] {
        vault.put_entity(&id, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"person")?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    for enabled in [true, false, true] {
        vault.set_marketplace_code_auto_install(&owner, enabled)?;
    }
    let write = crate::identity_topology::IdentityOpWrite {
        source: crate::claim::ClaimSource::Inferred,
        approval: crate::claim::ClaimApprovalStatus::Auto,
        confidence: 1.0,
        actor: None,
    };
    vault.apply_identity_topology_op(
        &crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![owner_id],
            survivor,
            evidence: crate::identity_topology::IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "fixture merge".to_owned(),
            },
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        }),
        &write,
        100,
    )?;
    assert_eq!(
        vault
            .set_marketplace_code_auto_install(&owner, false)
            .expect_err("inactive owner")
            .kind(),
        ErrorKind::ConsentOwnerNotAuthenticated
    );
    // A rejected setter neither changes the flag nor spends the next transition.
    let current = vault.store.env.read_txn()?;
    assert_eq!(
        super::import_receipt::CODE_AUTO_INSTALL
            .get_bytes(&vault.store, &current, &())?
            .as_deref(),
        Some(&[1][..])
    );
    drop(current);
    let new_owner = vault.authenticate_owner(
        survivor,
        "principal:survivor",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.set_marketplace_code_auto_install(&new_owner, false)?;
    drop(vault);
    let reopened = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let new_owner = reopened.authenticate_owner(
        survivor,
        "principal:survivor",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    reopened.set_marketplace_code_auto_install(&new_owner, true)?;
    reopened.set_marketplace_code_auto_install(&new_owner, false)?;
    Ok(())
}

#[test]
fn permission_ask_requires_current_rule_and_one_exact_owner_decision() -> Result<()> {
    use crate::skill::SkillLifecycle;
    let mut tree = files("fixture.ask", "1", "Check the result.");
    tree[0].content = b"---\nname: fixture.ask\ndescription: fixture\nversion: 1\nrequires-bins: [\"rg\"]\n---\nCheck the result.\n".to_vec();
    let server = StaticHttp::new(routes(&tree));
    let temp = tempfile::tempdir()?;
    let vault = crate::Vault::open(temp.path(), crate::VaultConfig::default())?;
    let owner_id = EntityId::now();
    let at = crate::TimeRange { start: 10, end: 10 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:ask",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub_id = EntityId::now();
    vault.configure_skill_hub(
        &owner,
        &hub_id,
        &SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            server.index_url(),
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )?,
        at,
        10,
    )?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:ask", hub_id)?;
    let adapter = HttpEndpointSkillHubAdapter::new(hub_id, &server.index_url())?;
    let hash = adapter.discover()?[0].content_hash;
    let source = HubRef::new(hub_id, "fixture", HubPin::ContentHash(hash.to_hex()))?;
    let id = vault.import_marketplace_skill_from_adapter(
        &adapter,
        &source,
        &publisher,
        &FixedFit(MarketplaceFit::Ask),
        at,
        10,
    )?;
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    let ask = vault.hub_import_receipt(&id, &source)?.expect("ask");
    assert_eq!(ask.requested_permissions, ["bin:rg"]);
    vault.set_marketplace_blocked_hash(&owner, hash, true)?;
    assert!(
        vault
            .approve_marketplace_permission_ask(&owner, &id, &source, at, 11)
            .is_err()
    );
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    vault.set_marketplace_blocked_hash(&owner, hash, false)?;
    vault.approve_marketplace_permission_ask(&owner, &id, &source, at, 12)?;
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().lifecycle_status,
        SkillLifecycle::Active
    );
    assert_eq!(
        vault
            .hub_import_receipt(&id, &source)?
            .unwrap()
            .disposition
            .as_str(),
        "installed"
    );
    assert!(
        vault
            .approve_marketplace_permission_ask(&owner, &id, &source, at, 13)
            .is_err()
    );
    Ok(())
}

#[test]
fn generic_transports_capture_real_pack_sources_without_installing() -> Result<()> {
    struct LyingAdapter {
        hub: EntityId,
        endpoint: String,
        source: PackSource,
    }
    impl SkillHubAdapter for LyingAdapter {
        fn hub_id(&self) -> EntityId {
            self.hub
        }
        fn kind(&self) -> SkillHubKind {
            SkillHubKind::HttpIndex
        }
        fn endpoint(&self) -> Option<&str> {
            Some(&self.endpoint)
        }
        fn fetch_package(&self, _: &HubRef) -> Result<HubPackage> {
            Err(crate::Error::EntityNotFound)
        }
    }
    impl PackSourceAdapter for LyingAdapter {
        fn fetch_pack_source(&self, _: &HubRef) -> Result<PackSource> {
            Ok(self.source.clone())
        }
    }

    use super::pack_catalog::{PackSource, PackSourceAdapter};
    let tree = vec![HubFile::new("PACK.md", b"---\nname: alice.mail\ndescription: fixture\nversion: 1\nkind: connector\nadapter: built-in:email\n---\nReal source bytes\n".to_vec()),
        HubFile::new("knowledge/guide.md", b"Imported content is evidence.\n".to_vec())];
    let source = PackSource::from_files(tree.clone())?;
    let repository = tempfile::tempdir()?;
    git(repository.path(), &["init", "--quiet"]);
    populate(repository.path(), &tree);
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "pack"]);
    let commit = git(repository.path(), &["rev-parse", "HEAD"]);
    let hub = EntityId::now();
    let git_adapter =
        GitEndpointSkillHubAdapter::new(hub, repository.path().to_str().unwrap(), &commit)?;
    let git_ref = HubRef::new(hub, "skills/example", HubPin::Commit(commit))?;
    assert_eq!(git_adapter.fetch_pack_source(&git_ref)?, source);
    let entries: Vec<_> = tree
        .iter()
        .map(|f| serde_json::json!({"path":f.path,"url":f.path}))
        .collect();
    let index = serde_json::json!({"schema":1,"packages":[{"name":"alice.mail","description":"fixture","version":"1",
        "content_hash":source.content_hash().to_hex(),"ref_string":"pack","files":entries}]});
    let mut routes = BTreeMap::from([(
        "/index.json".into(),
        (200, serde_json::to_vec(&index).unwrap()),
    )]);
    for file in &tree {
        routes.insert(format!("/{}", file.path), (200, file.content.clone()));
    }
    let server = StaticHttp::new(routes.clone());
    let http = HttpEndpointSkillHubAdapter::new(hub, &server.index_url())?;
    let reference = HubRef::new(
        hub,
        "pack",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let mut config = crate::VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let owner_id = EntityId::now();
    let at = crate::temporal::TimeRange { start: 4, end: 4 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        4,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:pack-transport",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.configure_skill_hub(
        &owner,
        &hub,
        &SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            server.index_url(),
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )?,
        at,
        4,
    )?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:pack", hub)?;
    let mut expected_sources = vault.list_pack_sources()?;
    let (id, pinned) = vault.fetch_pack_from_adapter(&http, &reference, &publisher, at, 4)?;
    expected_sources.push((id, source.clone()));
    expected_sources.sort_by_key(|(source_id, _)| *source_id.as_bytes());
    assert_eq!(vault.list_pack_sources()?, expected_sources);
    assert_eq!(pinned, reference);
    assert_eq!(vault.get_pack_source(&id)?, Some(source.clone()));
    assert!(vault.installed_pack("alice.mail")?.is_none());
    // A third-party adapter cannot launder B through a requested hash for A.
    let liar = LyingAdapter {
        hub,
        endpoint: server.index_url(),
        source,
    };
    let wrong = HubRef::new(hub, "pack", HubPin::ContentHash("ab".repeat(32)))?;
    assert!(
        vault
            .fetch_pack_from_adapter(&liar, &wrong, &publisher, at, 5)
            .is_err()
    );
    assert_eq!(vault.list_pack_sources()?, expected_sources);
    routes.insert("/knowledge/guide.md".into(), (200, b"drift".to_vec()));
    let drift = StaticHttp::new(routes);
    assert!(
        HttpEndpointSkillHubAdapter::new(hub, &drift.index_url())?
            .fetch_pack_source(&reference)
            .is_err()
    );
    assert_eq!(vault.list_pack_sources()?, expected_sources);
    Ok(())
}

#[test]
fn local_git_pack_installs_with_pinned_receipt_and_skill_remains_separate() -> Result<()> {
    use super::pack_catalog::{
        PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource,
    };
    struct Fit;
    impl PackFitPolicy for Fit {
        fn evaluate(
            &self,
            source: &PackSource,
            permissions: &PackPermissions,
        ) -> Result<PackFitVerdict> {
            assert_eq!(source.manifest().name, "alice.mail");
            assert_eq!(permissions.grants, ["mail.read"]);
            Ok(PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: true,
            })
        }
    }
    let tree = vec![
        HubFile::new("PACK.md", b"---\nname: alice.mail\ndescription: fixture\nversion: 1\nkind: connector\nadapter: built-in:email\ngrants: [\"mail.read\"]\n---\nExact connector source\n"),
        HubFile::new("skills/compose/SKILL.md", b"---\nname: alice.compose\ndescription: compose\nversion: 1\n---\nWrite a reply\n"),
    ];
    let source = PackSource::from_files(tree.clone())?;
    let repository = tempfile::tempdir()?;
    git(repository.path(), &["init", "--quiet"]);
    populate(repository.path(), &tree);
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "pack"]);
    let commit = git(repository.path(), &["rev-parse", "HEAD"]);
    let hub_id = EntityId::now();
    let endpoint = repository.path().to_str().expect("utf8 repo");
    let adapter = GitEndpointSkillHubAdapter::new(hub_id, endpoint, &commit)?;
    // macOS may alias /var to /private/var; configure the canonical endpoint
    // exposed by the adapter, not the fixture's pre-canonical temp path.
    let endpoint = adapter.endpoint().expect("configured git endpoint");
    let reference = HubRef::new(hub_id, "skills/example", HubPin::Commit(commit.clone()))?;
    let mut config = crate::VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let owner_id = EntityId::now();
    let at = crate::temporal::TimeRange { start: 4, end: 4 };
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        4,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:git-pack",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.configure_skill_hub(
        &owner,
        &hub_id,
        &SkillHubRecord::new(
            SkillHubKind::Git,
            endpoint,
            SkillHubTrustTier::Community,
            HubSyncPolicy::PinnedCommit,
        )?,
        at,
        4,
    )?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:git-pack", hub_id)?;
    // Install screening reads the seeded pack-install policy and fails closed
    // without it (ONE-2019). Restore the shipped manifest this legacy fixture
    // cleared for the install only; the rest keeps its manifest-free Gate.
    let policy_id = crate::gate::default_policy_manifest_id()?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        policy_id,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let installed = vault.install_pack_from_adapter(&adapter, &reference, &publisher, &Fit, at, 4);
    vault.with_write_txn(|txn| {
        crate::batch::deindex_entity_for_test(&vault.store, txn, &policy_id)
    })?;
    let PackInstallDisposition::Installed(receipt) = installed? else {
        panic!("post-fit connector");
    };
    assert_eq!(receipt.content_hash, source.content_hash().to_hex());
    assert_eq!(receipt.hub_ref, "skills/example");
    assert_eq!(receipt.pin_type, "commit");
    assert_eq!(receipt.pin_value, commit);
    assert_eq!(receipt.permissions.grants, ["mail.read"]);
    assert_eq!(receipt.skills.len(), 1);
    let skill = EntityId::from_hex(&receipt.skills[0])?;
    let skill_record = vault.get_skill_record(&skill)?.expect("bundled skill");
    assert_eq!(
        skill_record.lifecycle_status,
        crate::skill::SkillLifecycle::Active
    );
    let skill_source = super::pack_catalog::pack_skill_hub_ref(
        &reference,
        "compose",
        skill_record.content_hash.expect("hashed skill"),
    )?;
    let skill_receipt = vault
        .hub_import_receipt(&skill, &skill_source)?
        .expect("hub source receipt");
    assert_eq!(
        skill_receipt.publisher.as_deref(),
        Some(publisher.identity())
    );
    assert_eq!(
        skill_receipt.content_hash,
        skill_record.content_hash.unwrap().to_hex()
    );
    assert_eq!(skill_receipt.installed_as.as_str(), "active");
    assert_eq!(skill_receipt.disposition.as_str(), "installed");
    let standalone = files("alice.plain", "1", "plain knowledge");
    for file in &standalone {
        let path = repository.path().join("skills/plain").join(&file.path);
        std::fs::create_dir_all(path.parent().expect("file parent"))?;
        std::fs::write(path, &file.content)?;
    }
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "skill"]);
    let new_commit = git(repository.path(), &["rev-parse", "HEAD"]);
    let new_adapter = GitEndpointSkillHubAdapter::new(hub_id, endpoint, &new_commit)?;
    let skill_ref = HubRef::new(hub_id, "skills/plain", HubPin::Commit(new_commit))?;
    let plain = vault.import_skill_from_adapter(&new_adapter, &skill_ref, at, 5)?;
    assert_eq!(
        vault
            .get_skill_record(&plain)?
            .expect("plain skill")
            .lifecycle_status,
        crate::skill::SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn callable_folder_frontmatter_binds_exact_reference_and_schema() -> Result<()> {
    let front = b"---\nname: fixture.call\ndescription: A callable fixture\nversion: 1\nrole: callable\ncall:\n  reference: scripts/do.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nCall the helper.\n";
    let files = vec![
        HubFile::new("SKILL.md", front.to_vec()),
        HubFile::new(
            "scripts/do.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));".to_vec(),
        ),
    ];
    let package = super::folder::package_from_files(files.clone())?;
    assert_eq!(package.record.role, crate::skill::SkillRole::Callable);
    assert_eq!(
        package.record.call.as_ref().unwrap().reference,
        "scripts/do.js"
    );
    let record =
        crate::skill::decode_skill_record(&crate::skill::encode_skill_record(&package.record)?)?;
    assert_eq!(record.call, package.record.call);
    let mut missing = files;
    missing.pop();
    assert!(super::folder::package_from_files(missing).is_err());
    Ok(())
}

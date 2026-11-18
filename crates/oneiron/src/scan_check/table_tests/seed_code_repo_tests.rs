//! Threshold fixtures of the code_repo scans for `no_engine_scan_refuses_for_its_row_count`
//! (FIX LIBTEST-SCAN-CHECK-TABLE-UNSEEDED-SCANS).

use super::*;

pub(super) fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    match scan {
        EngineScan::OriginTreeEntries => {
            // One commit with PAST files; the tree walk counts PAST entries.
            let (dir, root, head) = git_seeded_repo("tree", PAST);
            let tree =
                crate::git_wire::GitOid::parse_hex(git_run(&root, &["rev-parse", "HEAD^{tree}"]))
                    .expect("tree");
            let wire = crate::git_wire::GitWire::new(vault).expect("wire");
            let repo = git_open_repo(&wire, &root, &head);
            Some((
                PAST,
                Box::new(move || {
                    let _keep = &dir;
                    let wire = crate::git_wire::GitWire::new(vault)?;
                    Ok(crate::origin::tree::read_tree_files(&wire, &repo, &tree)?.len())
                }),
            ))
        }
        EngineScan::OriginTagPeelSteps => {
            let (dir, root, head) = git_seeded_repo("peel", 1);
            for (name, target) in [("peel-inner", "HEAD"), ("peel-outer", "peel-inner")] {
                git_run(
                    &root,
                    &[
                        "-c",
                        "user.name=Oneiron",
                        "-c",
                        "user.email=oneiron@example.invalid",
                        "tag",
                        "-a",
                        name,
                        "-m",
                        name,
                        target,
                    ],
                );
            }
            let tip =
                crate::git_wire::GitOid::parse_hex(git_run(&root, &["rev-parse", "peel-outer"]))
                    .expect("outer tag");
            let wire = crate::git_wire::GitWire::new(vault).expect("wire");
            let repo = git_open_repo(&wire, &root, &head);
            Some((
                1,
                Box::new(move || {
                    let _keep = &dir;
                    let wire = crate::git_wire::GitWire::new(vault)?;
                    Ok(crate::origin::peel_tag_files_for_scan_tests(&wire, &repo, &tip)?.len())
                }),
            ))
        }
        EngineScan::GitWirePlanObjects => {
            // One commit pins the repo; 3 blobs written and counted per call.
            let (dir, root, head) = git_seeded_repo("base", 1);
            let wire = crate::git_wire::GitWire::new(vault).expect("wire");
            let repo = git_open_repo(&wire, &root, &head);
            let mut plan = crate::git_wire::GitWirePlan::new();
            for i in 0..PAST {
                plan.write_blob(format!("plan blob {i}").into_bytes())
                    .expect("blob");
            }
            Some((
                PAST,
                Box::new(move || {
                    let _keep = &dir;
                    let wire = crate::git_wire::GitWire::new(vault)?;
                    Ok(wire.write_objects(&repo, &plan, LEARNED_AT)?.len())
                }),
            ))
        }
        EngineScan::GitWirePublications => {
            // One commit; 3 refs published, expectations read fresh each call
            // so both calls apply (create, then no-op) and count PAST.
            let (dir, root, head) = git_seeded_repo("base", 1);
            let wire = crate::git_wire::GitWire::new(vault).expect("wire");
            let repo = git_open_repo(&wire, &root, &head);
            let names: Vec<crate::git_wire::GitRefName> = (0..PAST)
                .map(|i| {
                    crate::git_wire::GitRefName::parse_full(format!("refs/heads/wire-{i}"))
                        .expect("ref")
                })
                .collect();
            Some((
                PAST,
                Box::new(move || {
                    let _keep = &dir;
                    let wire = crate::git_wire::GitWire::new(vault)?;
                    let mut pubs = Vec::with_capacity(PAST);
                    for name in &names {
                        let cur = wire.read_ref(&repo, name)?;
                        pubs.push(crate::git_wire::GitRefPublication::update(
                            name.clone(),
                            crate::git_wire::GitRefExpectation::from_observed(cur.as_ref()),
                            head.clone(),
                        ));
                    }
                    let outcome = wire.publish_refs(&repo, pubs, LEARNED_AT)?;
                    assert!(outcome.is_applied(), "isolated ref transaction applies");
                    let mut served = 0;
                    for name in &names {
                        if wire.read_ref(&repo, name)?.as_ref() == Some(&head) {
                            served += 1;
                        }
                    }
                    Ok(served)
                }),
            ))
        }
        EngineScan::OriginPublicationObligations => {
            // Commit, tree and blob obligations. Published replay
            // proves availability again, so both calls walk all three.
            let (dir, root, head) = git_seeded_repo("base", 1);
            let wire = crate::git_wire::GitWire::new(vault).expect("wire");
            let repo = git_open_repo(&wire, &root, &head);
            let repo_id =
                crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex()).expect("repo id");
            let oids: Vec<_> = ["HEAD", "HEAD^{tree}", "HEAD:base-0.txt"]
                .into_iter()
                .map(|name| {
                    crate::git_wire::GitOid::parse_hex(git_run(&root, &["rev-parse", name]))
                        .expect("required object")
                })
                .collect();
            let request = pub_req(
                vault,
                &repo,
                repo_id,
                "refs/heads/obligations",
                &oids,
                &head,
                id(0x80, 0),
                id(0x80, 1),
            );
            Some((
                PAST,
                Box::new(move || {
                    let _keep = &dir;
                    let wire = crate::git_wire::GitWire::new(vault)?;
                    let receipt = vault.publish_origin_ref(&wire, request.clone())?;
                    assert_eq!(
                        receipt.record.status,
                        crate::origin::publication::OriginPublicationStatus::Published
                    );
                    Ok(receipt.record.required_objects.len())
                }),
            ))
        }
        EngineScan::RepoProposalSnapshotRows => {
            // Three proposals; a fork mount for an absent hash walks all past ROW.
            let repo = init_repo(&[("README.md", "base\n")]);
            let (actor, session, prov) = proposal_bindings(vault);
            for index in 0..PAST {
                make_proposal(
                    vault,
                    &repo,
                    actor,
                    session,
                    prov,
                    &format!("edit {index}\n"),
                );
            }
            let missing: crate::repo_mutation::RepoForkHash = [0xAA; 32];
            let repo_ref = repo_ref(&repo);
            Some((
                0,
                Box::new(move || {
                    let _keep = &repo;
                    match vault.mount_repo_ref(
                        &repo_ref,
                        crate::repo_mutation::mount::RepoMountRef::Fork(missing),
                    ) {
                        Err(crate::Error::Code(
                            crate::error::CodeError::InvalidRepoMutationRecord(
                                "fork is not recorded for this repo",
                            ),
                        )) => Ok(0),
                        Err(error) => Err(error),
                        Ok(_) => panic!("an absent fork must not mount"),
                    }
                }),
            ))
        }

        EngineScan::RepoSnapshotFiles => {
            // PAST files; the code-capture walk reads each past ROW.
            let dir = tempfile::tempdir().expect("files");
            for index in 0..PAST {
                std::fs::write(dir.path().join(format!("f{index}.txt")), b"x").expect("file");
            }
            Some((
                PAST,
                Box::new(move || {
                    let mut found = 0;
                    crate::repo_mutation::visit_code_capture_files(vault, dir.path(), |_, _| {
                        found += 1;
                        Ok(())
                    })?;
                    Ok(found)
                }),
            ))
        }

        EngineScan::RepoProposalCritiques => {
            // One proposal with two votes; the closure casts the third past ROW.
            let repo = init_repo(&[("README.md", "base\n")]);
            let (actor, session, prov) = proposal_bindings(vault);
            let proposal = make_proposal(vault, &repo, actor, session, prov, "edit\n");
            vote(vault, &proposal, id(0x82, 4));
            vote(vault, &proposal, id(0x82, 5));
            let third = id(0x82, 6);
            Some((
                PAST,
                Box::new(move || {
                    let _keep = &repo;
                    vote(vault, &proposal, third);
                    Ok(vault
                        .repo_proposal(proposal.id)?
                        .expect("proposal")
                        .critiques
                        .len())
                }),
            ))
        }

        EngineScan::RepoConflictPaths => {
            // Left/right conflict on PAST files; recording serves the path count.
            let repo = init_conflict_repo();
            let subject = id(0x82, 0);
            vault
                .put_entity(
                    &subject,
                    crate::registry::ENTITY_TYPE_TASK,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
                )
                .expect("subject");
            let repo_ref = repo_ref(&repo);
            Some((
                PAST,
                Box::new(move || {
                    let _ = repo.path();
                    vault.apply_repo_mutation(crate::repo_mutation::RepoMutationRequest::new(
                        repo_ref.clone(),
                        crate::repo_mutation::RepoMutationOperation::RecordConflict {
                            branch_subject: subject,
                            branch_name: "left".to_owned(),
                            ours_ref: "left".to_owned(),
                            theirs_ref: "right".to_owned(),
                        },
                    ))?;
                    Ok(vault
                        .repo_conflict_claims(&subject)?
                        .iter()
                        .map(|c| c.conflicted_paths.len())
                        .max()
                        .unwrap_or(0))
                }),
            ))
        }
        EngineScan::SymbolManifestRows | EngineScan::SymbolOperationChain => {
            let (artifact, repo) = code_repo_artifact(vault, 0x86);
            // Three chunks, each carrying three producing operations. Both
            // observations happen on put, so the closure repeats that door.
            let chunks = (0..PAST)
                .map(|index| {
                    let mut chunk = crate::code_symbol::CodeChunk::new(
                        format!("file-{index}.rs"),
                        1,
                        1,
                        [0x86; 32],
                    );
                    chunk.producing_operations = (0..PAST)
                        .map(|op| crate::code_symbol::CodeProducingOperation {
                            operation: id(0x87, op),
                            actor: None,
                            turn: id(0x87, 3),
                            activity: id(0x87, 4),
                            intent: id(0x87, 5),
                        })
                        .collect();
                    chunk
                })
                .collect();
            let manifest = crate::code_symbol::CodeSymbolManifest::new(
                repo.clone(),
                crate::codebase::RepoIdentity::from_location(&repo),
                None,
                chunks,
                Vec::new(),
            )
            .expect("manifest");
            Some((
                PAST,
                Box::new(move || {
                    vault.put_code_symbol_manifest(&artifact, &manifest)?;
                    Ok(vault
                        .get_code_symbol_manifest(&artifact)?
                        .expect("stored manifest")
                        .chunks
                        .len())
                }),
            ))
        }
        EngineScan::CodebaseFileRows => {
            let (artifact, snapshot) = code_repo_snapshot(vault, 0x86);
            // All three files survive custody. The counted manifest door is
            // a write, repeated before reading back the complete snapshot.
            Some((
                PAST,
                Box::new(move || {
                    vault.put_codebase_snapshot(&artifact, &snapshot, &|_| {
                        Some(b"fixture\n".to_vec())
                    })?;
                    Ok(vault
                        .get_codebase_snapshot(&artifact)?
                        .expect("stored snapshot")
                        .files
                        .len())
                }),
            ))
        }
        EngineScan::RepoDiffFiles => {
            let (artifact, snapshot) = code_repo_snapshot(vault, 0x86);
            vault
                .put_codebase_snapshot(&artifact, &snapshot, &|_| Some(b"fixture\n".to_vec()))
                .expect("snapshot");
            let actor = crate::vault::embedded_owner_actor_id().expect("embedded owner");
            let tree = crate::code_document::CodeTreeRequest {
                revision_ref: None,
                repo: Some(snapshot.repo_ref.canonical()),
                snapshot_ref: Some(artifact.to_hex()),
            };
            let request = crate::code_document::CodeRepoDiffRequest {
                before: tree.clone(),
                after: tree,
            };
            // Both sides read all three visible text files. Identical trees
            // serve no changes; neither side may stop at ROW files.
            Some((
                0,
                Box::new(move || {
                    let result = vault
                        .memory(actor, crate::edge::EdgeActorClass::Human)
                        .code_repo_diff(&request)
                        .map_err(|error| crate::Error::InvalidConfig(format!("{error:?}")))?;
                    Ok(result.expect("visible trees").files.len())
                }),
            ))
        }
        EngineScan::DeclaredSymbols | EngineScan::DeclaredSymbolBytes => {
            let (task, holder) = (id(0x87, 7), id(0x87, 8));
            vault
                .with_write_txn(|txn| {
                    for (entity, kind) in [
                        (task, crate::registry::ENTITY_TYPE_TASK),
                        (holder, crate::registry::ENTITY_TYPE_PERSON),
                    ] {
                        let row = crate::test_util::entity_record(
                            kind,
                            crate::temporal::TimeRange { start: 1, end: 1 },
                            LEARNED_AT,
                            1,
                            b"fixture",
                        );
                        vault.store.entities.put(txn, entity.as_bytes(), &row)?;
                    }
                    Ok(())
                })
                .expect("lease endpoints");
            // Three distinct symbols, each three bytes. An identical live
            // declaration by the same holder may be repeated unchanged.
            Some((
                PAST,
                Box::new(move || {
                    let symbols = ["one", "two", "tri"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let outcome = vault.declare_symbols(task, holder, symbols, 60, LEARNED_AT)?;
                    match outcome {
                        crate::task_verb::SymbolLeaseOutcome::Granted(lease) => {
                            Ok(lease.symbols.len())
                        }
                        crate::task_verb::SymbolLeaseOutcome::Waiting { .. } => {
                            panic!("isolated declaration has no blocker")
                        }
                    }
                }),
            ))
        }
        EngineScan::CodeMemorySlotValues => {
            // One slot with 2 values; the closure attaches the 3rd (same
            // value twice: first inserts, second dedups) and reads back 3.
            let symbol = cm_symbol(vault, 0);
            let slot = cm_slot();
            let locator = cm_locator();
            for index in 0..2 {
                vault
                    .attach_code_memory(cm_attach_input(
                        symbol,
                        slot.clone(),
                        locator.clone(),
                        id(0x84, 1 + index),
                        id(0x84, 10 + index),
                        index as u8,
                        100 + index as u64,
                    ))
                    .expect("seed value");
            }
            let third = cm_attach_input(symbol, slot, locator, id(0x84, 3), id(0x84, 12), 2, 102);
            Some((
                PAST,
                Box::new(move || {
                    vault.attach_code_memory(third.clone())?;
                    Ok(vault
                        .code_memory_slots(symbol)?
                        .first()
                        .map_or(0, |s| s.values.len()))
                }),
            ))
        }
        EngineScan::CodeMemoryAlwaysOnContracts => {
            // 2 contracts; the closure registers the 3rd (same key twice:
            // first is new and crosses, second is an idempotent upsert).
            let symbol = cm_symbol(vault, 10);
            let (author, subject) = (id(0x84, 20), id(0x84, 21));
            for person in [&author, &subject] {
                vault
                    .put_entity(
                        person,
                        crate::registry::ENTITY_TYPE_PERSON,
                        cm_range(1),
                        1,
                        b"person",
                    )
                    .expect("person");
            }
            let slot = cm_slot();
            let p0 = crate::code_memory::CodeMemoryPayloadRef::NoteEntity(cm_note(
                vault, author, subject,
            ));
            let p1 = crate::code_memory::CodeMemoryPayloadRef::NoteEntity(cm_note(
                vault, author, subject,
            ));
            let p2 = crate::code_memory::CodeMemoryPayloadRef::NoteEntity(cm_note(
                vault, author, subject,
            ));
            vault
                .register_always_on_contract(cm_contract(symbol, slot.clone(), p0, author))
                .expect("seed");
            vault
                .register_always_on_contract(cm_contract(symbol, slot.clone(), p1, author))
                .expect("seed");
            let third = cm_contract(symbol, slot, p2, author);
            Some((
                PAST,
                Box::new(move || {
                    vault.register_always_on_contract(third.clone())?;
                    Ok(vault.code_memory_always_on_contracts(symbol)?.len())
                }),
            ))
        }
        EngineScan::CodeMemoryPullSeeds => {
            // 3 seeds; the pull names all 3 (limit 1 keeps the note row
            // quiet) and serves 0 notes whole past ROW.
            let seeds = vec![
                cm_symbol(vault, 30),
                cm_symbol(vault, 31),
                cm_symbol(vault, 32),
            ];
            let reader = cm_reader(vault);
            let request = crate::code_memory::CodeMemoryPullRequest {
                seed_symbols: seeds,
                minimum_relevance: 0.0,
                limit: 1,
                include_always_on_contracts: false,
            };
            Some((
                0,
                Box::new(move || {
                    Ok(vault
                        .pull_code_memory(reader.clone(), request.clone())?
                        .notes
                        .len())
                }),
            ))
        }
        EngineScan::CodeMemoryPullNotes => {
            // 1 seed; the pull asks for PAST notes and serves 0 whole past ROW.
            let seed = cm_symbol(vault, 40);
            let reader = cm_reader(vault);
            let request = crate::code_memory::CodeMemoryPullRequest {
                seed_symbols: vec![seed],
                minimum_relevance: 0.0,
                limit: PAST,
                include_always_on_contracts: false,
            };
            Some((
                0,
                Box::new(move || {
                    Ok(vault
                        .pull_code_memory(reader.clone(), request.clone())?
                        .notes
                        .len())
                }),
            ))
        }
        EngineScan::CodeMemoryPullSymbols => {
            // 3 isolated readable seeds; PPR retains all 3 past ROW (limit
            // 32 keeps the note row quiet); the pull serves 0 notes.
            let seeds = vec![
                cm_symbol(vault, 50),
                cm_symbol(vault, 51),
                cm_symbol(vault, 52),
            ];
            let reader = cm_reader(vault);
            let request = crate::code_memory::CodeMemoryPullRequest {
                seed_symbols: seeds,
                minimum_relevance: 0.0,
                limit: 32,
                include_always_on_contracts: false,
            };
            Some((
                0,
                Box::new(move || {
                    Ok(vault
                        .pull_code_memory(reader.clone(), request.clone())?
                        .notes
                        .len())
                }),
            ))
        }
        other => unreachable!("{} is seeded in another module", other.code()),
    }
}

fn git_run(root: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn git_seeded_repo(
    prefix: &str,
    n_files: usize,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    crate::git_wire::GitOid,
) {
    let dir = tempfile::tempdir().expect("repo dir");
    let root = dir.path().canonicalize().expect("canonical root");
    git_run(&root, &["init", "--initial-branch=main"]);
    for i in 0..n_files {
        std::fs::write(
            root.join(format!("{prefix}-{i}.txt")),
            format!("{prefix} {i}\n"),
        )
        .expect("write file");
    }
    git_run(&root, &["add", "."]);
    git_run(
        &root,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "seed",
        ],
    );
    let head =
        crate::git_wire::GitOid::parse_hex(git_run(&root, &["rev-parse", "--verify", "HEAD"]))
            .expect("head");
    (dir, root, head)
}

fn git_open_repo(
    wire: &crate::git_wire::GitWire<'_>,
    root: &std::path::Path,
    head: &crate::git_wire::GitOid,
) -> crate::git_wire::GitWireRepo {
    let repo_ref = crate::codebase::RepoRef::parse(&format!(
        "local:{}#{}",
        root.to_str().expect("utf-8 root"),
        head.as_str()
    ))
    .expect("repo ref");
    wire.open_repo(repo_ref, root).expect("open repo")
}

fn pub_req(
    vault: &Vault,
    repo: &crate::git_wire::GitWireRepo,
    repo_id: EntityId,
    ref_name: &str,
    oids: &[crate::git_wire::GitOid],
    new: &crate::git_wire::GitOid,
    prov: EntityId,
    actor: EntityId,
) -> crate::origin::publication::OriginPublicationRequest {
    let req = crate::origin::publication::OriginPublicationRequest {
        repo_id,
        repo: repo.clone(),
        ref_name: crate::git_wire::GitRefName::parse_full(ref_name).expect("ref"),
        expected_old_oid: None,
        new_oid: new.clone(),
        required_objects: oids.to_vec(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: prov,
        actor_id: actor,
        occurred: crate::temporal::TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        learned_at: LEARNED_AT,
    };
    vault.put_origin_publication_intent(&req).expect("intent");
    req
}

fn git(path: &std::path::Path, args: &[&str]) -> Vec<u8> {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    crate::git_wire::mutation_commands::run_git_at_path(path, &owned).expect("git")
}

fn init_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("repo");
    git(dir.path(), &["init"]);
    for &(name, body) in files {
        std::fs::write(dir.path().join(name), body).expect("write");
        git(dir.path(), &["add", "--", name]);
    }
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
    );
    dir
}

fn head_commit(dir: &tempfile::TempDir) -> String {
    String::from_utf8(git(dir.path(), &["rev-parse", "--verify", "HEAD"]))
        .expect("utf8")
        .trim()
        .to_owned()
}

fn repo_ref(dir: &tempfile::TempDir) -> crate::codebase::RepoRef {
    crate::codebase::RepoRef::LocalFolder {
        path: dir.path().to_string_lossy().into_owned(),
        commit: head_commit(dir),
    }
}

fn repo_text_map(fields: &[(&str, &str)]) -> rmpv::Value {
    rmpv::Value::Map(
        fields
            .iter()
            .map(|(key, value)| (rmpv::Value::from(*key), rmpv::Value::from(*value)))
            .collect(),
    )
}

fn put_provenance(vault: &Vault) -> EntityId {
    let subject = id(0x82, 2);
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_TASK,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
        )
        .expect("subject");
    let rmpv::Value::Map(mut fields) = repo_text_map(&[
        ("actor", "agent:oneiron-test"),
        ("model", "oneiron/test-model@1"),
        ("prompt_hash", "sha256:test-prompt"),
    ]) else {
        unreachable!("map helper")
    };
    fields.push((
        "derivation_envelope".into(),
        repo_text_map(&[
            ("content_hash", "sha256:test-content"),
            ("model_id", "oneiron/test-model@1"),
            ("version", "1"),
            ("params_hash", "sha256:test-params"),
        ]),
    ));
    fields.push((
        "diff_lineage_receipt".into(),
        repo_text_map(&[("base_tree", "base-tree"), ("result_tree", "result-tree")]),
    ));
    let body = crate::claim::ClaimBody::new(
        crate::repo_mutation::REPO_PROVENANCE_PREDICATE,
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::Map(fields),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .expect("body");
    let data = crate::claim::encode_claim_body(&body).expect("encode");
    let claim = id(0x82, 3);
    vault
        .with_write_txn(|wtxn| {
            let payload = crate::test_util::entity_record(
                crate::registry::ENTITY_TYPE_CLAIM,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                1,
                &data,
            );
            vault.store.entities.put(wtxn, claim.as_bytes(), &payload)?;
            Ok(())
        })
        .expect("provenance");
    claim
}

fn proposal_bindings(vault: &Vault) -> (EntityId, EntityId, EntityId) {
    let (actor, session) = (id(0x82, 0), id(0x82, 1));
    for (entity, kind) in [
        (actor, crate::registry::ENTITY_TYPE_PERSON),
        (session, crate::registry::ENTITY_TYPE_SESSION),
    ] {
        vault
            .put_entity(
                &entity,
                kind,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"fixture",
            )
            .expect("proposal binding");
    }
    (actor, session, put_provenance(vault))
}

fn make_proposal(
    vault: &Vault,
    repo: &tempfile::TempDir,
    actor: EntityId,
    session: EntityId,
    prov: EntityId,
    body: &str,
) -> crate::repo_mutation::proposal::RepoProposal {
    let request = crate::repo_mutation::RepoMutationRequest::new(
        repo_ref(repo),
        crate::repo_mutation::RepoMutationOperation::CommitFile {
            path: "README.md".to_owned(),
            content: body.as_bytes().to_vec(),
            message: "edit".to_owned(),
        },
    )
    .with_actor_id(actor)
    .with_session_id(session)
    .with_provenance_claim_id(prov);
    vault
        .propose_repo_mutation(
            request,
            crate::critic::LensCatalog {
                schema_version: 1,
                lenses: vec![
                    crate::critic::CriticLens::new(
                        "correctness",
                        "host supplied review contract",
                        "critique.v1",
                        true,
                        "code_review",
                    )
                    .expect("lens"),
                ],
            },
        )
        .expect("propose")
}

fn vote(vault: &Vault, proposal: &crate::repo_mutation::proposal::RepoProposal, critic: EntityId) {
    vault
        .put_entity(
            &critic,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"critic",
        )
        .expect("critic");
    let provenance = crate::critic::CritiqueProvenance::new(
        crate::WriteActor::new(critic, crate::edge::EdgeActorClass::Human),
        "test_model",
        None,
    )
    .expect("prov");
    let calibration =
        crate::learning::LearningCell::new(crate::learning::LearningPredicate::Reliability, critic)
            .executor(provenance.executor().expect("exec"))
            .type_ref(crate::learning::TypeRef {
                node_id: "code_review".to_owned(),
                tree_version: 1,
            })
            .axis("quality");
    let critique = crate::critic::CritiqueArtifact::new(
        format!("review_{}", critic.to_hex()),
        "repo_review",
        crate::attempt_queue::AttemptId::from_bytes(proposal.id.as_bytes()).expect("attempt"),
        proposal.id.to_hex(),
        &proposal.review.catalog().expect("catalog").lenses[0],
        provenance,
        calibration,
        crate::critic::CritiqueVerdict::Accept,
        crate::critic::CritiqueSeverity::High,
        Some(true),
        vec!["checked_tree".to_owned()],
        None,
        2,
    )
    .expect("critique");
    vault
        .review_repo_proposal(proposal.id, critic, critique)
        .expect("vote");
}

fn init_conflict_repo() -> tempfile::TempDir {
    let dir = init_repo(&[
        ("f0.txt", "base\n"),
        ("f1.txt", "base\n"),
        ("f2.txt", "base\n"),
    ]);
    let base = head_commit(&dir);
    git(dir.path(), &["checkout", "-B", "left", base.as_str()]);
    for name in ["f0.txt", "f1.txt", "f2.txt"] {
        std::fs::write(dir.path().join(name), "left\n").expect("left");
        git(dir.path(), &["add", "--", name]);
    }
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "left",
        ],
    );
    git(dir.path(), &["checkout", "-B", "right", base.as_str()]);
    for name in ["f0.txt", "f1.txt", "f2.txt"] {
        std::fs::write(dir.path().join(name), "right\n").expect("right");
        git(dir.path(), &["add", "--", name]);
    }
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "right",
        ],
    );
    git(dir.path(), &["checkout", "left"]);
    dir
}

fn code_repo_artifact(vault: &Vault, seed: u8) -> (EntityId, crate::codebase::RepoRef) {
    let artifact = id(seed, 0);
    let repo = crate::codebase::RepoRef::parse("capture:/scan-check-code-repo").expect("repo");
    let body = crate::code_artifact::CodeArtifactBody::new("fixture", [0x86; 32], repo.canonical());
    vault
        .put_code_artifact(
            &artifact,
            &body,
            crate::temporal::TimeRange { start: 1, end: 1 },
            LEARNED_AT,
        )
        .expect("artifact");
    (artifact, repo)
}

fn code_repo_snapshot(vault: &Vault, seed: u8) -> (EntityId, crate::codebase::CodebaseSnapshot) {
    let (artifact, repo) = code_repo_artifact(vault, seed);
    let hash = *blake3::hash(b"fixture\n").as_bytes();
    let asset = crate::codebase::snapshot_asset_entity_id(&hash).expect("asset id");
    vault
        .put_entity(
            &asset,
            crate::registry::ENTITY_TYPE_ASSET,
            crate::temporal::TimeRange { start: 1, end: 1 },
            LEARNED_AT,
            b"fixture\n",
        )
        .expect("asset");
    let files = (0..PAST)
        .map(|index| crate::codebase::CodebaseFileEntry::new(format!("file-{index}.txt"), hash, 8))
        .collect();
    let snapshot =
        crate::codebase::CodebaseSnapshot::new("scan-check", repo, None, files).expect("snapshot");
    (artifact, snapshot)
}

// Private helpers for the CodeMemory fixtures (seeds 0x84-0x85).
// Assumes `use super::*` from table_tests (id, PAST, Vault, EntityId, Result).

fn cm_range(at: u64) -> crate::temporal::TimeRange {
    crate::temporal::TimeRange { start: at, end: at }
}

fn cm_slot() -> crate::code_memory::CodeMemorySlotName {
    crate::code_memory::CodeMemorySlotName::new("interface.contract").expect("slot")
}

fn cm_locator() -> crate::code_memory::CodeMemoryLocator {
    crate::code_memory::CodeMemoryLocator {
        span: crate::code_document::CodeSpanAnchor {
            document_id: [0xD0; 32],
            start: b"cursor-start".to_vec(),
            end: b"cursor-end".to_vec(),
            content_hash: [0xC0; 32],
        },
        version: vec![(1, 0)],
        validity: cm_range(1_780_000_000),
    }
}

fn cm_value(
    payload: crate::code_memory::CodeMemoryPayloadRef,
    actor: EntityId,
    content: u8,
    recorded_at: u64,
) -> crate::code_memory::CodeMemorySlotValue {
    crate::code_memory::CodeMemorySlotValue {
        payload,
        actor_id: actor,
        valid_time: cm_range(recorded_at),
        recorded_at,
        content_hash: [content; 32],
        provenance_claim_id: id(0x85, content as usize),
    }
}

fn cm_symbol(vault: &Vault, index: usize) -> EntityId {
    let symbol = id(0x84, index);
    vault
        .put_entity(
            &symbol,
            crate::registry::ENTITY_TYPE_CODE_SYMBOL,
            cm_range(1),
            1,
            b"symbol",
        )
        .expect("seed CODE_SYMBOL");
    symbol
}

fn cm_attach_input(
    symbol: EntityId,
    slot: crate::code_memory::CodeMemorySlotName,
    locator: crate::code_memory::CodeMemoryLocator,
    payload: EntityId,
    actor: EntityId,
    content: u8,
    at: u64,
) -> crate::code_memory::AttachCodeMemory {
    crate::code_memory::AttachCodeMemory {
        anchor: crate::code_memory::CodeMemoryAnchor {
            symbol_id: symbol,
            locator,
        },
        slot,
        value: cm_value(
            crate::code_memory::CodeMemoryPayloadRef::NoteEntity(payload),
            actor,
            content,
            at,
        ),
    }
}

fn cm_contract(
    symbol: EntityId,
    slot: crate::code_memory::CodeMemorySlotName,
    payload: crate::code_memory::CodeMemoryPayloadRef,
    author: EntityId,
) -> crate::code_memory::AlwaysOnCodeMemoryContract {
    crate::code_memory::AlwaysOnCodeMemoryContract {
        symbol_id: symbol,
        slot,
        payload,
        kind: crate::code_memory::CodeMemoryContractKind::Interface,
        actor_id: author,
        valid_time: cm_range(1_780_000_500),
        recorded_at: 1_780_000_500,
        provenance_claim_id: id(0x85, 30),
    }
}

fn cm_note(vault: &Vault, author: EntityId, subject: EntityId) -> EntityId {
    let receipt = vault
        .memory(author, crate::edge::EdgeActorClass::Human)
        .author_take(crate::note::TakeTarget::Subject(subject), "fixture take")
        .expect("mint NOTE");
    EntityId::from_hex(&receipt.id_hex).expect("receipt id")
}

fn cm_reader(vault: &Vault) -> crate::claim::ScopedReadActorKey {
    let mut scope = crate::federation::scope_codec::read_preset();
    scope.bands = crate::federation::ScopeAxis::Some(
        [
            crate::registry::ENTITY_TYPE_CODE_SYMBOL,
            crate::registry::ENTITY_TYPE_NOTE,
        ]
        .into(),
    );
    let grant = rmpv::Value::Map(vec![
        ("actor_ref".into(), "agent:cm-reader".into()),
        ("effector".into(), "core:read".into()),
        (
            "scope".into(),
            crate::federation::scope_codec::encode_scope_value(&scope).expect("scope"),
        ),
        ("receipt_required".into(), false.into()),
    ]);
    let manifest =
        crate::gate::default_policy_manifest_with_scoped_grants(vec![grant]).expect("manifest");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &manifest,
    )
    .expect("put manifest");
    crate::claim::ScopedReadActorKey::new("agent:cm-reader").expect("key")
}

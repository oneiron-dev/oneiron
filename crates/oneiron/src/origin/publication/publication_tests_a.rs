//! Tests: fixtures plus provenance, dependency-retention, happy-path, atomicity, availability and CAS-mismatch suites.

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command as StdCommand;

    use super::super::*;
    use crate::Vault;
    use crate::claim::ClaimLifecycleStatus;
    use crate::codebase::RepoRef;
    use crate::entity_id::EntityId;
    use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWire, GitWireRepo};
    use crate::origin::lfs::LfsOid;
    use crate::temporal::TimeRange;
    use crate::test_util::{embedding_test_config, open_test_vault_with};
    use rmpv::Value;

    pub(crate) const LEARNED_AT: u64 = 1_700_000_000;

    pub(crate) fn occurred() -> TimeRange {
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        }
    }

    pub(crate) fn test_vault() -> (tempfile::TempDir, Vault) {
        open_test_vault_with(embedding_test_config())
    }

    pub(crate) fn git(repo: &Path, args: &[&str]) -> String {
        let output = StdCommand::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    pub(crate) fn commit(root: &Path, message: &str, body: &str) -> GitOid {
        std::fs::write(root.join("README.md"), body).expect("write readme");
        git(root, &["add", "--", "README.md"]);
        git(
            root,
            &[
                "-c",
                "user.name=Oneiron",
                "-c",
                "user.email=oneiron@example.invalid",
                "commit",
                "-m",
                message,
            ],
        );
        GitOid::parse_hex(git(root, &["rev-parse", "--verify", "HEAD"])).expect("head oid")
    }

    /// A repository with one commit on `refs/heads/main`.
    pub(crate) fn seeded_repo() -> (tempfile::TempDir, PathBuf, GitOid) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let root = dir.path().canonicalize().expect("canonical repo root");
        git(&root, &["init", "--initial-branch=main"]);
        let head = commit(&root, "initial", "base\n");
        (dir, root, head)
    }

    pub(crate) fn open_repo(wire: &GitWire<'_>, root: &Path, pin: &GitOid) -> GitWireRepo {
        let path = root.to_str().expect("utf-8 repo path");
        let repo_ref = RepoRef::parse(&format!("local:{path}#{}", pin.as_str())).expect("repo ref");
        wire.open_repo(repo_ref, root).expect("open repo")
    }

    pub(crate) fn main_ref() -> GitRefName {
        GitRefName::parse_full("refs/heads/main").expect("ref name")
    }

    pub(crate) fn fixture_provenance(
        vault: &Vault,
        request: &OriginPublicationRequest,
    ) -> EntityId {
        let id = EntityId::now();
        let body = origin_publication_intent_claim(request);
        vault
            .put_claim(&id, &body, occurred(), LEARNED_AT)
            .expect("durable target-bound fixture provenance");
        id
    }

    pub(crate) fn authorize_fixture(vault: &Vault, request: &mut OriginPublicationRequest) {
        request.provenance_claim_id = fixture_provenance(vault, request);
    }

    pub(crate) fn request(
        vault: &Vault,
        repo: &GitWireRepo,
        repo_id: EntityId,
        expected_old_oid: Option<GitOid>,
        new_oid: GitOid,
    ) -> OriginPublicationRequest {
        let mut request = OriginPublicationRequest {
            repo_id,
            repo: repo.clone(),
            ref_name: main_ref(),
            expected_old_oid,
            new_oid,
            required_objects: Vec::new(),
            required_lfs_oids: Vec::new(),
            provenance_claim_id: EntityId::now(),
            actor_id: EntityId::now(),
            occurred: occurred(),
            learned_at: LEARNED_AT,
        };
        authorize_fixture(vault, &mut request);
        request
    }

    /// The repo id the protocol itself derives, so a fixture and the code
    /// under test always agree about which repository a row belongs to.
    pub(crate) fn repo_id_of(vault: &Vault, repo: &GitWireRepo) -> EntityId {
        vault.origin_repo_id_for(repo).expect("repo id")
    }

    /// Rewinds `refs/heads/main` behind the protocol's back, which is what a
    /// crash before the CAS looks like from the journal's point of view.
    pub(crate) fn force_ref(root: &Path, oid: &GitOid) {
        git(root, &["update-ref", "refs/heads/main", oid.as_str()]);
    }

    #[test]
    fn publication_rejects_unrelated_and_retargeted_active_sources() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let mut unrelated = origin_publication_intent_claim(&ask);
        unrelated.predicate = "test.unrelated".to_owned();
        unrelated.value = Value::from("an active claim is not publication authority");
        let unrelated_id = EntityId::now();
        vault
            .put_claim(&unrelated_id, &unrelated, occurred(), LEARNED_AT)
            .expect("claim");
        let mut variants = Vec::new();
        let mut changed = ask.clone();
        changed.provenance_claim_id = unrelated_id;
        variants.push(changed);
        let mut changed = ask.clone();
        changed.actor_id = EntityId::now();
        variants.push(changed);
        let mut changed = ask.clone();
        changed.ref_name = GitRefName::parse_full("refs/heads/other").expect("ref");
        variants.push(changed);
        let mut changed = ask.clone();
        changed.new_oid = base.clone();
        variants.push(changed);
        let mut changed = ask.clone();
        changed.expected_old_oid = None;
        variants.push(changed);
        let mut changed = ask.clone();
        changed.required_objects = vec![next];
        variants.push(changed);
        let mut changed = ask.clone();
        changed.required_lfs_oids = vec![(LfsOid::parse_hex(&"a".repeat(64)).expect("oid"), 1)];
        variants.push(changed);
        let (_other_dir, other_root, other_base) = seeded_repo();
        let other_repo = open_repo(&wire, &other_root, &other_base);
        let mut changed = ask;
        changed.repo_id = repo_id_of(&vault, &other_repo);
        changed.repo = other_repo;
        variants.push(changed);
        for changed in variants {
            assert!(vault.publish_origin_ref(&wire, changed).is_err());
        }
        assert!(vault.origin_publication_ids(None).expect("ids").is_empty());
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(base));
    }

    #[test]
    fn publication_retains_independent_required_objects_until_superseded() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        std::fs::write(root.join("independent"), b"not in any commit").expect("bytes");
        let extra =
            GitOid::parse_hex(git(&root, &["hash-object", "-w", "independent"])).expect("blob");
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let mut ask = request(&vault, &repo, repo_id, Some(base.clone()), base.clone());
        ask.required_objects = vec![extra.clone()];
        authorize_fixture(&vault, &mut ask);
        let published = vault.publish_origin_ref(&wire, ask).expect("publish");
        assert_eq!(published.record.status, OriginPublicationStatus::Published);
        let keep = origin_keep_ref_name(&extra).expect("keep");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("root"),
            Some(extra.clone())
        );
        git(&root, &["reflog", "expire", "--expire=now", "--all"]);
        git(&root, &["gc", "--prune=now"]);
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census retains dependency");
        assert!(wire.object_exists(&repo, &extra).expect("still present"));
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("visible")
                .len(),
            1
        );
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let ask = request(&vault, &repo, repo_id, Some(base), next);
        vault.publish_origin_ref(&wire, ask).expect("supersede");
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 2)
            .expect("release old dependency");
        assert_eq!(wire.read_ref(&repo, &keep).expect("retired"), None);
    }

    #[test]
    fn publication_happy_path_single_claim_single_ref_advance() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let wrong_repo_id = EntityId::now();
        assert!(
            vault
                .publish_origin_ref(
                    &wire,
                    request(
                        &vault,
                        &repo,
                        wrong_repo_id,
                        Some(base.clone()),
                        next.clone()
                    ),
                )
                .is_err(),
            "a caller-chosen repository id cannot redirect publication or keep accounting"
        );
        assert!(
            vault
                .published_origin_refs(&wire, wrong_repo_id, &repo)
                .is_err()
        );
        assert!(
            vault
                .reconcile_origin_publications(&wire, wrong_repo_id, &repo, LEARNED_AT)
                .is_err()
        );

        let receipt = vault
            .publish_origin_ref(
                &wire,
                request(&vault, &repo, repo_id, Some(base), next.clone()),
            )
            .expect("publish");

        assert_eq!(receipt.record.status, OriginPublicationStatus::Published);
        assert!(
            !receipt.ref_was_already_applied,
            "the publication moved the ref itself"
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next.clone()),
            "exactly one ref advanced from expected to new oid"
        );

        // Exactly one active repo.publication claim.
        let claim_id = receipt
            .record
            .publication_claim_id
            .expect("published record carries its claim");
        let body = vault
            .get_claim(&claim_id)
            .expect("read claim")
            .expect("claim exists");
        assert_eq!(body.predicate, ORIGIN_PUBLICATION_PREDICATE);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
        );
        assert_eq!(
            vault
                .prepared_origin_publication_count(repo_id)
                .expect("prepared count"),
            0,
        );
    }

    #[test]
    fn publication_finalize_txn_atomic() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base), next.clone());

        let first = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish");
        let claim_id = first.record.publication_claim_id.expect("claim id");
        // CAS precedes finalize. T2 atomically writes claim and Published,
        // and identical replay must not invoke the claim writer a second time.
        // The claim and the Published mark are one transaction: a record that
        // says Published always has a claim behind it.
        assert!(
            vault.get_claim(&claim_id).expect("read claim").is_some(),
            "the finalize transaction wrote both halves"
        );

        let mut altered = ask.clone();
        altered
            .required_objects
            .push(GitOid::parse_hex("d".repeat(40)).expect("missing oid"));
        assert!(
            vault.publish_origin_ref(&wire, altered).is_err(),
            "replay cannot replace the availability set behind an existing claim"
        );
        let replay = vault.publish_origin_ref(&wire, ask).expect("replay");
        assert_eq!(replay.record.publication_id, first.record.publication_id);
        assert_eq!(replay.record.publication_claim_id, Some(claim_id));
        assert!(
            replay.ref_was_already_applied,
            "an identical replay moves no ref"
        );
        let commit_anchor = origin_published_commit_id(&next).expect("commit anchor");
        assert_eq!(
            vault
                .claims_for_subject(&commit_anchor)
                .expect("claims for subject")
                .len(),
            0,
            "an EdgeRef subject writes no claim_of edge, so the anchor is not an entity subject"
        );
        assert_eq!(
            vault
                .origin_publication_rows(Some(repo_id))
                .expect("rows")
                .len(),
            1,
            "an identical replay is one publication, not two"
        );
    }

    #[test]
    fn publication_advertisement_gated_on_object_and_lfs_availability() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        // A required git object this store does not carry.
        let mut missing_object = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        missing_object.required_objects =
            vec![GitOid::parse_hex("b".repeat(40)).expect("absent oid")];
        authorize_fixture(&vault, &mut missing_object);
        let refused = vault
            .publish_origin_ref(&wire, missing_object)
            .expect("publish refuses rather than errors");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused
                .record
                .failure
                .as_deref()
                .expect("bounded failure text")
                .contains("not present"),
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "a refused publication leaves the public ref unchanged"
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "the advertisement omits a row that never published"
        );

        // A missing tip must also produce a bounded durable refusal, even
        // though GitWire cannot create a keep-ref for it.
        let absent = GitOid::parse_hex("d".repeat(40)).expect("missing tip");
        let missing_tip = request(&vault, &repo, repo_id, Some(base.clone()), absent);
        let refused = vault
            .publish_origin_ref(&wire, missing_tip)
            .expect("missing tip refusal");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused.record.failure.as_ref().expect("failure").len()
                <= ORIGIN_PUBLICATION_MAX_FAILURE_BYTES
        );
        assert_eq!(
            vault
                .origin_publication(refused.record.publication_id)
                .expect("read refusal"),
            Some(refused.record)
        );

        // A row with the right length is not evidence that its bytes still
        // exist. Delete only the ASSET body to model corruption after upload.
        let bytes = b"publication lfs content";
        let oid = LfsOid::digest(bytes);
        let size = u64::try_from(bytes.len()).expect("size");
        let object = vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("upload")
            .object;
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .delete(wtxn, object.asset_id.as_bytes())?;
                Ok(())
            })
            .expect("lose asset body");
        assert!(vault.has_lfs_object(oid, size).expect("metadata remains"));
        let mut corrupt_lfs = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        corrupt_lfs.required_lfs_oids = vec![(oid, size)];
        authorize_fixture(&vault, &mut corrupt_lfs);
        let refused = vault
            .publish_origin_ref(&wire, corrupt_lfs)
            .expect("corrupt lfs refusal");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused
                .record
                .failure
                .expect("failure")
                .contains("not locally readable")
        );

        // An LFS pointer whose bytes this vault does not hold.
        let mut missing_lfs = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        missing_lfs.required_lfs_oids =
            vec![(LfsOid::parse_hex(&"c".repeat(64)).expect("lfs oid"), 11)];
        authorize_fixture(&vault, &mut missing_lfs);
        let refused = vault
            .publish_origin_ref(&wire, missing_lfs)
            .expect("publish refuses rather than errors");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "a missing lfs object never moves the public ref"
        );
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("released owner"),
            0
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
        );

        let bytes = b"lfs bytes lost after publication";
        let oid = LfsOid::digest(bytes);
        let object = vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("upload readable bytes")
            .object;
        let mut ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        ask.required_lfs_oids = vec![(oid, u64::try_from(bytes.len()).expect("size"))];
        authorize_fixture(&vault, &mut ask);
        let published = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish with lfs");
        assert_eq!(published.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("visible"),
            vec![(main_ref(), next)]
        );
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .delete(wtxn, object.asset_id.as_bytes())?;
                Ok(())
            })
            .expect("lose published bytes");
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("projection")
                .is_empty()
        );
        force_ref(&root, &base);
        assert!(
            vault.publish_origin_ref(&wire, ask).is_err(),
            "replay must not move a ref onto unavailable LFS bytes"
        );
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(base));
    }

    #[test]
    fn publication_cas_mismatch_records_conflicted() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let other_writer = commit(&root, "other writer", "other\n");
        let mine = commit(&root, "mine", "mine\n");
        // The repository carries the OTHER writer's value; this publication was
        // decided against `base`.
        force_ref(&root, &other_writer);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &other_writer);
        let repo_id = repo_id_of(&vault, &repo);

        let ask = request(&vault, &repo, repo_id, Some(base.clone()), mine);
        let receipt = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish");
        assert_eq!(receipt.record.status, OriginPublicationStatus::Conflicted);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(other_writer),
            "the other writer's ref is intact"
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
        );
        // Never retried: a second call answers from the durable record.
        assert_eq!(
            vault
                .origin_publication(receipt.record.publication_id)
                .expect("record")
                .expect("row")
                .status,
            OriginPublicationStatus::Conflicted,
        );
        // Even if the old precondition becomes true again, a terminal conflict
        // must not be retried as a fresh CAS.
        force_ref(&root, &base);
        let replay = vault
            .publish_origin_ref(&wire, ask)
            .expect("replay conflict");
        assert_eq!(replay.record, receipt.record);
        assert!(
            replay.wire.is_none(),
            "a conflicted publication never reaches GitWire again"
        );
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(base));
    }

    #[test]
    fn publication_keep_ref_shape_and_shared_owner_counting() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        let name = vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                "owner-a",
                &base,
                LEARNED_AT,
            )
            .expect("pin");
        assert_eq!(
            name.as_str(),
            format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", base.as_str()),
            "the physical root is the landed keep-ref shape"
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            Some(base.clone()),
        );

        // A second, DIFFERENT logical reason for the same object.
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Change,
                "owner-b",
                &base,
                LEARNED_AT,
            )
            .expect("pin change owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            2,
        );

        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                "owner-a",
                &base,
                LEARNED_AT,
            )
            .expect("unpin publication owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            1,
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            Some(base.clone()),
            "the physical root survives while another owner references it"
        );

        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Change,
                "owner-b",
                &base,
                LEARNED_AT,
            )
            .expect("unpin change owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            0,
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            None,
            "the physical root is retired only at zero owners"
        );

        for kind in OriginKeepRefKind::ALL {
            vault
                .pin_origin_object(&wire, &repo, kind, "shared-key", &base, LEARNED_AT)
                .expect("pin each owner kind");
        }
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("count"),
            5
        );
        for (index, kind) in OriginKeepRefKind::ALL.into_iter().enumerate() {
            vault
                .unpin_origin_object(&wire, &repo, kind, "shared-key", &base, LEARNED_AT)
                .expect("unpin each owner kind");
            assert_eq!(
                wire.read_ref(&repo, &name).expect("root"),
                (index < 4).then(|| base.clone()),
                "all five kinds participate in zero-owner retirement"
            );
        }
    }

    pub(crate) fn claim_count(vault: &Vault) -> usize {
        let txn = vault.store.env.read_txn().expect("read claims");
        vault
            .store
            .entities
            .iter(&txn)
            .expect("entities")
            .filter(|entry| {
                let (_, raw) = entry.as_ref().expect("entity");
                let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
                    return false;
                };
                header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && crate::claim::decode_claim_body(
                        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                        true,
                    )
                    .is_ok_and(|body| body.predicate == ORIGIN_PUBLICATION_PREDICATE)
            })
            .count()
    }

    pub(crate) fn reflog(root: &Path) -> String {
        git(
            root,
            &["reflog", "show", "--format=%H %gs", "refs/heads/main"],
        )
    }
}

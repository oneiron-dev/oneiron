//! Tests: crash-window recovery, advertisement projection, terminal-wins, duplicate-intent, stale-outcome, uncertain-error, missing-data and isolation-guard suites.

#[cfg(test)]
mod tests {
    use super::super::publication_tests_a::tests::*;
    use super::super::*;
    use crate::entity_id::EntityId;
    use crate::git_wire::{GitOid, GitRefName, GitWire};
    use crate::origin::lfs::LfsOid;

    #[test]
    fn publication_crash_after_prepared_retries_safely() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: a durable Prepared row and nothing else.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert_eq!(
            vault
                .prepared_origin_publication_count(repo_id)
                .expect("prepared count"),
            1,
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "no public ref moved before the census ran"
        );

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::RetriedAndPublished)],
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next),
        );

        // The other half of the window: the live ref no longer matches the
        // expected old oid, so the retry refuses instead of clobbering.
        let third = commit(&root, "third", "third\n");
        let stale = request(&vault, &repo, repo_id, Some(base.clone()), third);
        let stale_id = origin_publication_id(&stale).expect("stale id");
        force_ref(&root, &base);
        vault
            .stage_origin_publication(&wire, &stale, stale_id)
            .expect("stage stale");
        let moved_on = commit(&root, "fourth", "fourth\n");
        force_ref(&root, &moved_on);
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 2)
            .expect("census");
        assert!(
            report
                .items
                .contains(&(stale_id, OriginCensusDisposition::MarkedConflicted)),
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(moved_on.clone()),
            "a refused retry moves no ref"
        );

        let fifth = commit(&root, "fifth", "fifth\n");
        force_ref(&root, &moved_on);
        std::fs::write(root.join("extra-object"), "detached dependency\n").expect("extra object");
        let extra = GitOid::parse_hex(git(&root, &["hash-object", "-w", "--", "extra-object"]))
            .expect("extra oid");
        let mut unavailable = request(&vault, &repo, repo_id, Some(moved_on.clone()), fifth);
        unavailable.required_objects = vec![extra.clone()];
        authorize_fixture(&vault, &mut unavailable);
        let unavailable_id = origin_publication_id(&unavailable).expect("publication id");
        vault
            .stage_origin_publication(&wire, &unavailable, unavailable_id)
            .expect("stage");
        std::fs::remove_file(
            root.join(".git/objects")
                .join(&extra.as_str()[..2])
                .join(&extra.as_str()[2..]),
        )
        .expect("lose dependency");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 3)
            .expect("census with missing dependency");
        assert!(
            report
                .items
                .contains(&(unavailable_id, OriginCensusDisposition::MarkedFailed))
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("ref"),
            Some(moved_on)
        );
    }

    #[test]
    fn publication_crash_after_cas_before_finalize_recovers() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: Prepared is durable and the real GitWire CAS happened,
        // but the publication finalize transaction never committed.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            wire.update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
                .expect("CAS before crash")
                .is_applied()
        );
        let log = reflog(&root);
        assert_eq!(claim_count(&vault), 0);

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::FinalizedPublished)],
        );
        let record = vault
            .origin_publication(publication_id)
            .expect("record")
            .expect("row");
        assert_eq!(record.status, OriginPublicationStatus::Published);
        assert!(record.publication_claim_id.is_some());
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next),
            "the census finalized without moving the ref again"
        );

        // The same window through the ordinary door reports the receipt flag.
        let receipt = vault.publish_origin_ref(&wire, ask).expect("publish");
        assert!(receipt.ref_was_already_applied);
        assert!(
            receipt.wire_replayed(),
            "the GitWire effect was not run again"
        );
        assert_eq!(receipt.record.publication_id, publication_id);
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(reflog(&root), log);
    }

    #[test]
    fn publication_crash_after_finalize_cleanup_leak_safe() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: finalize committed, cleanup never ran. Reconstructed by
        // staging the pin and committing T2 without physical retirement.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            wire.update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
                .expect("CAS before T2")
                .is_applied()
        );
        let record = vault
            .origin_publication(publication_id)
            .expect("record")
            .expect("row");
        let published = vault
            .finalize_origin_publication(record, LEARNED_AT)
            .expect("finalize");
        assert_eq!(published.status, OriginPublicationStatus::Published);

        // A second, independent owner of the same object: the leak sweep must
        // not retire a root somebody else still references.
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Snapshot,
                "snapshot-owner",
                &next,
                LEARNED_AT,
            )
            .expect("snapshot pin");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner count"),
            1,
            "T2 already removed the publication owner atomically",
        );

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::NoChange)],
            "cleanup is not a state change"
        );
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner count"),
            1,
            "the census dropped the publication owner after the live-ref proof"
        );
        let keep = origin_keep_ref_name(&next).expect("keep name");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("read keep ref"),
            Some(next.clone()),
            "the physical root survives while the snapshot owner references it"
        );

        // The interrupted-cleanup leak: a later census removes it.
        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Snapshot,
                "snapshot-owner",
                &next,
                LEARNED_AT + 2,
            )
            .expect("unpin snapshot");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("read keep ref"),
            None,
            "a later pass removes the leaked root at zero owners"
        );
        wire.write_keep_ref(&repo, &next, LEARNED_AT + 3)
            .expect("restore leaked root");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("count"),
            0
        );
        let lock = root.join(".git").join(format!("{}.lock", keep.as_str()));
        std::fs::write(&lock, b"held by another operation").expect("block keep cleanup");
        let replay = vault
            .publish_origin_ref(&wire, ask)
            .expect("cleanup leak is not rejection");
        assert_eq!(replay.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("leaked root"),
            Some(next.clone())
        );
        std::fs::remove_file(lock).expect("unblock cleanup");
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 4)
            .expect("sweep an ownerless physical root");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("root after census"),
            None
        );
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
            "cleanup never disturbs the advertisement"
        );
    }

    #[test]
    fn published_origin_refs_is_the_only_advertisement_projection() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        // A raw repository ref that no publication ever produced.
        git(&root, &["update-ref", "refs/heads/raw", base.as_str()]);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a raw repository ref is never an advertisement authority"
        );

        // A non-Published row is omitted.
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a Prepared row is not advertisable"
        );

        // Published and live: advertised.
        let receipt = vault.publish_origin_ref(&wire, ask).expect("publish");
        assert_eq!(receipt.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
        );

        // Live-ref mismatch: the row is omitted the moment the repository
        // disagrees with it, without any journal write.
        force_ref(&root, &base);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a Published row whose live ref moved is not advertisable"
        );
    }

    #[test]
    fn publication_terminal_wins_and_duplicate_finalize_is_inert() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let ask = request(&vault, &repo, repo_id_of(&vault, &repo), Some(base), next);
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        let mut conflicted = prepared.clone();
        conflicted.status = OriginPublicationStatus::Conflicted;
        conflicted.finished_at = Some(LEARNED_AT);
        vault
            .put_origin_publication_record(&conflicted)
            .expect("competing terminal write");
        assert!(
            vault
                .finalize_origin_publication(prepared.clone(), LEARNED_AT + 1)
                .is_err()
        );
        assert_eq!(
            vault.origin_publication(id).expect("row"),
            Some(conflicted.clone())
        );
        assert_eq!(claim_count(&vault), 0);
        assert!(
            vault
                .finish_origin_publication(prepared, LEARNED_AT + 1)
                .is_err()
        );
        assert_eq!(vault.origin_publication(id).expect("row"), Some(conflicted));

        // A distinct ref proves duplicate Published T2 is a byte-preserving no-op.
        let mut second = ask;
        second.ref_name = GitRefName::parse_full("refs/heads/other").expect("ref");
        second.expected_old_oid = None;
        authorize_fixture(&vault, &mut second);
        let landed = vault
            .publish_origin_ref(&wire, second)
            .expect("publish")
            .record;
        let raw = vault
            .get_raw(&landed.publication_claim_id.expect("claim"))
            .expect("claim bytes");
        assert_eq!(
            vault
                .finalize_origin_publication(landed.clone(), LEARNED_AT + 2)
                .expect("same terminal"),
            landed
        );
        assert_eq!(
            vault
                .get_raw(&landed.publication_claim_id.expect("claim"))
                .expect("claim bytes"),
            raw
        );
        assert_eq!(claim_count(&vault), 1);
    }

    #[test]
    fn publication_duplicate_intent_reconciles_without_second_claim() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let first = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&first).expect("id");
        vault
            .stage_origin_publication(&wire, &first, id)
            .expect("T1");
        let mut duplicate = first.clone();
        duplicate.provenance_claim_id = fixture_provenance(&vault, &duplicate);
        let duplicate_id = origin_publication_id(&duplicate).expect("duplicate id");
        assert!(vault.publish_origin_ref(&wire, duplicate.clone()).is_err());
        assert_eq!(
            vault
                .origin_publication(id)
                .expect("owner")
                .expect("row")
                .status,
            OriginPublicationStatus::Published
        );
        assert!(
            vault
                .origin_publication(duplicate_id)
                .expect("no duplicate row")
                .is_none()
        );
        let log = reflog(&root);
        assert!(vault.publish_origin_ref(&wire, duplicate).is_err());
        let replay = vault
            .publish_origin_ref(&wire, first.clone())
            .expect("identical replay");
        assert!(replay.ref_was_already_applied);
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            vault
                .origin_visible_ref_rows(&repo_id)
                .expect("visible rows"),
            vec![id]
        );
        assert_eq!(reflog(&root), log);
        force_ref(&root, &base);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        let replay = vault
            .publish_origin_ref(&wire, first)
            .expect("CAS replay from expected");
        assert!(replay.wire.as_ref().expect("wire proof").is_applied());
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(next));
        assert_eq!(claim_count(&vault), 1);
    }

    #[test]
    fn publication_stale_applied_outcome_cannot_finalize_without_live_ref() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        let outcome = wire
            .update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
            .expect("real applied outcome");
        assert!(outcome.is_applied());
        // An external Git writer does not obey the engine's advisory lock.
        force_ref(&root, &base);
        assert!(
            vault
                .finish_origin_cas_outcome(
                    &wire,
                    &repo,
                    prepared.clone(),
                    false,
                    LEARNED_AT,
                    outcome
                )
                .is_err()
        );
        assert_eq!(vault.origin_publication(id).expect("row"), Some(prepared));
        assert_eq!(claim_count(&vault), 0);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("retry same triple through GitWire");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::RetriedAndPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("live proof"),
            Some(next)
        );
    }

    #[test]
    fn publication_uncertain_git_error_keeps_intent_for_census() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        // A real Git lockfile failure, not a process/coordinator proof. Unlike
        // chmod this also fails when the test runner has elevated privileges.
        let blocked = root.join(".git/refs/heads/main.lock");
        std::fs::write(&blocked, b"another git ref transaction").expect("block CAS");
        let mut duplicate = ask.clone();
        duplicate.provenance_claim_id = fixture_provenance(&vault, &duplicate);
        let duplicate_id = origin_publication_id(&duplicate).expect("duplicate id");
        assert!(vault.publish_origin_ref(&wire, duplicate).is_err());
        assert!(
            vault
                .origin_publication(duplicate_id)
                .expect("no new owner")
                .is_none()
        );
        assert!(vault.publish_origin_ref(&wire, ask).is_err());
        assert_eq!(vault.origin_publication(id).expect("row"), Some(prepared));
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("unchanged"),
            Some(base)
        );
        assert_eq!(claim_count(&vault), 0);
        std::fs::remove_file(blocked).expect("unblock CAS");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("retry uncertainty");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::RetriedAndPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("published"),
            Some(next)
        );
    }

    #[test]
    fn publication_live_ref_missing_data_stays_prepared_and_orphan_owner_is_swept() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let orphan = EntityId::now().to_hex();
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                &orphan,
                &next,
                LEARNED_AT,
            )
            .expect("pin before T1 crash");
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT)
            .expect("sweep");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owners"),
            0
        );
        assert_eq!(
            wire.read_ref(&repo, &origin_keep_ref_name(&next).expect("keep"))
                .expect("root"),
            None
        );

        let bytes = b"recoverable lfs";
        let oid = LfsOid::digest(bytes);
        let size = bytes.len() as u64;
        let mut ask = request(&vault, &repo, repo_id, Some(base), next.clone());
        ask.required_lfs_oids = vec![(oid, size)];
        authorize_fixture(&vault, &mut ask);
        let id = origin_publication_id(&ask).expect("id");
        vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        // Model a crash after the Git subprocess, before its journal transition.
        // Census must use GitWire's already-published path, not infer a claim.
        force_ref(&root, &next);
        let log = reflog(&root);
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT)
            .expect("census missing bytes");
        assert_eq!(report.items, vec![(id, OriginCensusDisposition::NoChange)]);
        assert_eq!(claim_count(&vault), 0);
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner"),
            1
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("restore bytes");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census readable bytes");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::FinalizedPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(reflog(&root), log);
    }

    /// Static guard: this module touches only the surfaces the claim allows.
    ///
    /// The forbidden spellings are assembled at compile time from fragments, so
    /// the guard's own source does not contain the strings it refuses and the
    /// scan cannot trip over itself.
    #[test]
    fn origin_publication_module_isolation_guard() {
        let source = concat!(
            include_str!("mod.rs"),
            include_str!("publication_types.rs"),
            include_str!("publication_codec.rs"),
            include_str!("publication_protocol.rs"),
            include_str!("publication_machine.rs"),
            include_str!("publication_journal.rs"),
            include_str!("publication_tests_a.rs"),
            include_str!("publication_tests_b.rs"),
        );
        let forbidden: [&str; 7] = [
            concat!("repo_", "mutation"),
            concat!("RepoMutation", "Status"),
            concat!("sync_", "state"),
            concat!("refs/", "jj/keep"),
            concat!("change_", "index"),
            concat!("conflict_", "tree"),
            concat!("origin::", "residence"),
        ];
        for spelling in forbidden {
            assert!(
                !source.contains(spelling),
                "publication module must not reference {spelling}"
            );
        }
        for required in [
            "published_origin_refs",
            "update_ref_cas",
            "has_lfs_object",
            "put_claim_in_txn",
            "write_keep_ref",
            "delete_keep_ref",
        ] {
            assert!(
                source.contains(required),
                "publication module must ride {required}"
            );
        }
    }
}

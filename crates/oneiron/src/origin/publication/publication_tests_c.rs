//! Tests: a saved ref effect from a previous authority epoch, reached through generic GitWire recovery.

#[cfg(test)]
mod tests {
    use super::super::publication_tests_a::tests::*;
    use super::super::*;
    use crate::entity_id::EntityId;
    use crate::git_wire::{GitOid, GitWire, GitWireRecordState, GitWireRepo};
    use crate::origin::residence::OriginResidence;
    use crate::vault::Vault;

    struct StaleRedrive {
        _vault_dir: tempfile::TempDir,
        _repo_dir: tempfile::TempDir,
        vault: Vault,
        repo: GitWireRepo,
        base: GitOid,
        publication: OriginPublicationRecord,
        first_epoch: u64,
        host: EntityId,
    }

    /// A publication P (base -> next) is Published under epoch 1. The ref goes
    /// back to base, and an explicit re-drive of P under epoch 1 leaves its
    /// GitWire attempt Prepared: a real Git lockfile makes the CAS uncertain.
    /// Nothing on the origin side is pending, so a cutover is free to happen.
    fn stale_redrive() -> StaleRedrive {
        let (vault_dir, vault) = test_vault();
        let (repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let host = EntityId::now();
        let first = vault
            .set_origin_authority(&repo, None, OriginResidence::LocalVault, host, false)
            .expect("epoch 1");
        let lease = vault.lease_origin_authority(&repo, host).expect("lease");
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&ask).expect("id");
        vault
            .publish_origin_ref_authorized(&wire, ask.clone(), &lease)
            .expect("published under epoch 1");
        force_ref(&root, &base);
        let blocked = root.join(".git/refs/heads/main.lock");
        std::fs::write(&blocked, b"another git ref transaction").expect("block CAS");
        assert!(
            vault
                .publish_origin_ref_authorized(&wire, ask, &lease)
                .is_err()
        );
        std::fs::remove_file(blocked).expect("unblock CAS");
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("still base"),
            Some(base.clone())
        );
        let publication = vault
            .origin_publication(id)
            .expect("row")
            .expect("published");
        assert_eq!(publication.status, OriginPublicationStatus::Published);
        drop(wire);
        StaleRedrive {
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            vault,
            repo,
            base,
            publication,
            first_epoch: first.epoch,
            host,
        }
    }

    fn assert_ref_and_publication_untouched(state: &StaleRedrive) {
        let wire = GitWire::new(&state.vault).expect("wire");
        assert_eq!(
            wire.read_ref(&state.repo, &main_ref()).expect("ref"),
            Some(state.base.clone()),
            "an effect decided under a previous epoch moved the ref"
        );
        assert_eq!(
            state
                .vault
                .origin_publication(state.publication.publication_id)
                .expect("row"),
            Some(state.publication.clone())
        );
        assert_eq!(claim_count(&state.vault), 1);
        assert!(
            wire.recover(&state.repo, LEARNED_AT + 3)
                .expect("nothing left to retry")
                .is_empty()
        );
    }

    #[test]
    fn generic_recovery_after_a_cutover_never_applies_the_old_epochs_effect() {
        let state = stale_redrive();
        state
            .vault
            .set_origin_authority(
                &state.repo,
                Some(state.first_epoch),
                OriginResidence::CloudVault,
                EntityId::now(),
                false,
            )
            .expect("epoch 2 on another host");
        let wire = GitWire::new(&state.vault).expect("wire");
        let receipts = wire.recover(&state.repo, LEARNED_AT + 2).expect("recover");
        assert_eq!(
            wire.read_ref(&state.repo, &main_ref()).expect("ref"),
            Some(state.base.clone()),
            "an effect decided under epoch 1 moved the ref under epoch 2"
        );
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].state, GitWireRecordState::Failed);
        drop(wire);
        assert_ref_and_publication_untouched(&state);
    }

    #[test]
    fn repo_mutation_recovery_on_a_mirror_never_applies_the_old_epochs_effect() {
        let state = stale_redrive();
        state
            .vault
            .set_origin_authority(
                &state.repo,
                Some(state.first_epoch),
                OriginResidence::LocalVault,
                state.host,
                true,
            )
            .expect("same host, now a read-only mirror");
        let repo_ref = state.repo.repo_ref().clone();
        state
            .vault
            .recover_prepared_repo_mutations(&repo_ref)
            .expect("repo mutation recovery");
        assert_ref_and_publication_untouched(&state);
    }
}

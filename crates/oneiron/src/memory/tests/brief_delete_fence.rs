//! [BRIEF-DELETE-RESERVATION-NEVER-RELEASED-ON-REFUSAL]: a user delete fences
//! its target against new brief shares before it linearizes. A delete refused
//! before that point releases the fence; one refused after it keeps it.

use super::support::*;
use super::*;

/// A brief share of one target, by a fresh PERSON issuer to a fresh PERSON
/// recipient, both put before the test roots the vault.
#[cfg(feature = "sync")]
struct BriefShare {
    issuer: crate::write_envelope::WriteActor,
    share: crate::share::Share,
    share_id: EntityId,
}

#[cfg(feature = "sync")]
impl BriefShare {
    /// `seed` names the issuer, `seed + 1` the recipient and `seed + 2` the
    /// share.
    fn of(vault: &crate::Vault, brief: EntityId, seed: u8) -> Self {
        let issuer =
            crate::write_envelope::WriteActor::new(put_person(vault, seed), EdgeActorClass::Human);
        let share = crate::share::Share {
            recipient_ref: put_person(vault, seed.wrapping_add(1)),
            brief_ref: brief.to_hex(),
            world_refs: std::collections::BTreeSet::new(),
            facet_refs: std::collections::BTreeSet::new(),
            include_unscoped: true,
            status: crate::access_grant::AccessGrantStatus::Active,
            created_at: 42,
            revoked_at: None,
            expires_at: None,
            mention: None,
        };
        let share_id = EntityId::from_bytes([seed.wrapping_add(2); 16]).expect("share id");
        Self {
            issuer,
            share,
            share_id,
        }
    }

    /// Admits the issuer's share in the policy, then creates the share.
    fn create(&self, vault: &crate::Vault) -> crate::error::Result<()> {
        crate::share::tests::policy(vault, &self.issuer, &self.share, true, None)?;
        vault.create_share(&self.share_id, &self.issuer, &self.share)
    }
}

/// Whether `brief` holds a brief delete fence.
#[cfg(feature = "sync")]
fn brief_fenced(vault: &crate::Vault, brief: EntityId) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::share::brief_delete_reserved(&vault.store, &txn, &brief).expect("read the fence")
}

/// A hard delete refused before its tombstone publish commits releases the
/// brief fence it reserved: the owner's binding is revoked while the delete
/// waits before its publish, the publish refuses, and a brief share of the
/// still-whole target is admitted again; red at main `7b962d25833`, where the
/// refused delete's fence stayed and the share was refused as "cannot share a
/// deleting brief".
#[cfg(feature = "sync")]
#[test]
fn a_hard_delete_refused_before_its_publication_releases_its_brief_fence() {
    let harness = PublishBoundaryHarness::open("brief-fence-hard-refused", true);
    let owner = put_owner(&harness.vault);
    let brief = put_person(&harness.vault, 0xB1);
    let brief_share = BriefShare::of(&harness.vault, brief, 0xB4);
    let revoke = root_binding_with_pending_revocation(&harness.vault, 0xB2, owner);
    let err = safe_delete_with_revocation_at(
        &harness.vault,
        owner,
        brief,
        SafeDeleteReason::UserHardDelete,
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        revoke,
    )
    .expect_err("a revocation before the publish commit refuses the delete");
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
    assert_eq!(
        harness
            .vault
            .get_entity_type(&brief)
            .expect("read the target"),
        Some(ENTITY_TYPE_PERSON),
        "the refused delete leaves its target whole"
    );
    assert!(
        !brief_fenced(&harness.vault, brief),
        "a delete refused before it published releases the fence it reserved"
    );
    brief_share
        .create(&harness.vault)
        .expect("a target whose delete was refused before it published can be shared again");
}

/// A soft delete refused after its scrub committed keeps its brief fence: the
/// scrub linearized the delete, so the shelled target stays unshareable
/// (green at main and on the fix).
#[cfg(feature = "sync")]
#[test]
fn a_soft_delete_refused_after_its_scrub_keeps_its_brief_fence() {
    let harness = PublishBoundaryHarness::open("brief-fence-soft-refused", true);
    let owner = put_owner(&harness.vault);
    let brief = put_person(&harness.vault, 0xC1);
    let brief_share = BriefShare::of(&harness.vault, brief, 0xC4);
    let revoke = root_binding_with_pending_revocation(&harness.vault, 0xC2, owner);
    let err = safe_delete_with_revocation_at(
        &harness.vault,
        owner,
        brief,
        SafeDeleteReason::UserDelete,
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        revoke,
    )
    .expect_err("a revocation before the publish commit refuses the delete");
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
    assert!(
        harness
            .vault
            .is_deleted_shell(&brief)
            .expect("read the target"),
        "the soft arm scrubbed its target before the publication refused"
    );
    assert!(
        brief_fenced(&harness.vault, brief),
        "a delete refused after its scrub keeps its fence"
    );
    let refused = brief_share
        .create(&harness.vault)
        .expect_err("the scrubbed target keeps its brief fence");
    assert!(
        matches!(
            refused,
            Error::InvariantViolation("cannot share a deleting brief")
        ),
        "{refused:?}"
    );
}

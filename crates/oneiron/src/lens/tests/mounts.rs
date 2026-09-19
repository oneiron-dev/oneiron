use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::{EntityId, Result, TimeRange, Vault};

fn revision(stale: bool, extra_read: bool) -> Result<LensEvaluatedRevision> {
    let mut root = LensNode::new(id("root"), LensAtom::StatusDot(status()));
    if extra_read {
        root.bindings
            .push(binding("extra", LensHandleRole::ClaimSet));
    }
    let mut lens = GeneratedLens::new(root)?;
    if stale {
        let mut value = serde_json::to_value(&lens).unwrap();
        value["apps_contract_version"] = serde_json::json!(0);
        lens = serde_json::from_value(value).unwrap();
    }
    let fingerprint = LensBehaviorFingerprint::from_golden_renders([("fixture", &lens)])?;
    Ok(LensEvaluatedRevision::new(lens, fingerprint))
}
fn registry(intent: EntityId, stale: bool) -> Result<LensMountRegistry> {
    Ok(LensMountRegistry::new(
        (intent, render_id("vault"), revision(stale, false)?),
        (intent, render_id("admin"), revision(stale, false)?),
    ))
}
fn put_intent(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_lens_intent(id, "stored lens intent", TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}
#[test]
fn pack_lens_rereads_active_stale_quarantine_and_removal_on_each_render() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let intent = put_intent(&vault)?;
    let skill_id = EntityId::now();
    let mut skill = SkillRecord::new(
        "crm",
        "CRM pack",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![("source".into(), "fixture".into())]),
    );
    let at = TimeRange { start: 1, end: 1 };
    vault.put_skill_record(&skill_id, &skill, at, 1)?;
    let mut mounts = registry(intent, false)?;
    mounts.register_pack(
        "crm".into(),
        skill_id,
        intent,
        render_id("crm"),
        revision(false, false)?,
    )?;
    let crm = LensMountId::Pack("crm".into());
    assert!(mounts.render(&vault, &crm)?.is_none());
    for state in [
        SkillLifecycle::Active,
        SkillLifecycle::Stale,
        SkillLifecycle::Active,
        SkillLifecycle::Quarantined,
    ] {
        skill.lifecycle_status = state;
        vault.update_skill_record(&skill_id, &skill, at, 2)?;
        assert_eq!(
            mounts.render(&vault, &crm)?.is_some(),
            state == SkillLifecycle::Active
        );
        assert!(mounts.render(&vault, &LensMountId::Vault)?.is_some());
        assert!(mounts.render(&vault, &LensMountId::Admin)?.is_some());
    }
    assert!(mounts.remove_pack("crm"));
    assert!(mounts.render(&vault, &crm)?.is_none());
    Ok(())
}
struct Regen {
    extra_read: bool,
    fail: bool,
    seen: std::cell::RefCell<Vec<String>>,
}
impl LensIntentRegenerator for Regen {
    fn regenerate(
        &self,
        prompt: &str,
        _: &LensRegenRequest,
    ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure> {
        self.seen.borrow_mut().push(prompt.into());
        if self.fail {
            return Err(LensRegenFailure::new(
                LensRegenFailurePhase::Compile,
                "fixture failure",
            ));
        }
        Ok(revision(false, self.extra_read).unwrap())
    }
}
#[test]
fn upgrade_reads_stored_intent_and_gates_adoption_preserving_last_good() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let intent = put_intent(&vault)?;
    for (extra_read, fail) in [(false, false), (true, false), (false, true)] {
        let mut mounts = registry(intent, true)?;
        let before = mounts.render(&vault, &LensMountId::Vault)?.unwrap();
        let regen = Regen {
            extra_read,
            fail,
            seen: Default::default(),
        };
        let result = mounts
            .regenerate_on_upgrade(&vault, &LensMountId::Vault, &regen)?
            .unwrap();
        assert_eq!(*regen.seen.borrow(), vec!["stored lens intent"]);
        match result {
            LensRegenOutcome::AutoAdopt { .. } => {
                assert!(!extra_read && !fail);
                assert!(
                    mounts
                        .regenerate_on_upgrade(&vault, &LensMountId::Vault, &regen)?
                        .is_none()
                );
            }
            LensRegenOutcome::NeedsHumanStamp { .. } => {
                assert!(extra_read);
                assert!(mounts.pending_candidate(&LensMountId::Vault).is_some());
                assert_eq!(mounts.render(&vault, &LensMountId::Vault)?.unwrap(), before);
            }
            LensRegenOutcome::RolledBack { .. } => {
                assert!(fail);
                assert_eq!(mounts.render(&vault, &LensMountId::Vault)?.unwrap(), before);
            }
        }
    }
    Ok(())
}

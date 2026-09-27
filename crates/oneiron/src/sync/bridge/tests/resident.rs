use super::*;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::sync::manager::WindowManager;
use crate::sync::types::WindowKey;

#[test]
fn resident_active_fork_replays_after_owner_in_either_delivery_order() -> Result<()> {
    for (skill_first, wrong_kind) in [(false, false), (true, false), (false, true), (true, true)] {
        let vault = test_vault();
        let window_key = WindowKey::new("2026-03");
        let materializer = Arc::new(Materializer::new());
        let parent = EntityId::now();
        let owner = EntityId::now();
        let fork = EntityId::now();
        let at = TimeRange { start: 1, end: 1 };
        let base = SkillRecord::new(
            "shared.parent",
            "instructions",
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Vec::new(),
            Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
        );
        vault.put_skill_record(&parent, &base, at, 1)?;
        let mut record = SkillRecord::new(
            "resident.fork",
            "instructions",
            "2",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Vec::new(),
            Value::Map(vec![
                (Value::from("forkOf"), Value::from("shared.parent")),
                (Value::from("residentActor"), Value::from(owner.to_hex())),
            ]),
        );
        record.forked_from = Some(parent);
        let manager = Arc::new(WindowManager::new(
            vault.clone(),
            materializer,
            "sync-resident",
        ));
        let window = manager.open_window(&window_key)?;
        // Independent peer histories: neither update depends causally on the
        // other, so the receiver really can see the current Active blob first.
        let owner_doc = LoroDoc::new();
        let owner_body = if wrong_kind {
            task_body()
        } else {
            b"resident".to_vec()
        };
        map_insert_bytes(
            &owner_doc.get_map("entities"),
            &owner.to_hex(),
            &entity_blob(
                if wrong_kind {
                    ENTITY_TYPE_TASK
                } else {
                    ENTITY_TYPE_PERSON
                },
                at,
                1,
                &owner_body,
            ),
        )?;
        owner_doc.commit();
        let owner_update = export_snapshot(&owner_doc)?;
        let skill_doc = LoroDoc::new();
        map_insert_bytes(
            &skill_doc.get_map("entities"),
            &fork.to_hex(),
            &entity_blob(
                ENTITY_TYPE_SKILL,
                at,
                2,
                &crate::skill::encode_skill_record(&record)?,
            ),
        )?;
        skill_doc.commit();
        let skill_update = export_snapshot(&skill_doc)?;
        if skill_first {
            import_doc(&window.doc, &skill_update)?;
            assert!(vault.get_skill_record(&fork)?.is_none());
            let marker = format!("rm:w:{}:{}", window_key, fork.to_hex());
            assert!(
                vault.sync_state_get(&marker)?.is_some(),
                "dependency keeps its retry"
            );
            assert!(
                crate::sync::quarantine::quarantined_records(&vault)?
                    .iter()
                    .any(|(_, q)| { q.reason_code == "ResidentOwnerDependencyPending" })
            );
            import_doc(&window.doc, &owner_update)?;
            assert!(
                vault.get_skill_record(&fork)?.is_none(),
                "no second skill import"
            );
            // A cached manager open must run pending forward recovery rather
            // than returning the existing window without a retry.
            let reopened = manager.open_window(&window_key)?;
            assert!(Arc::ptr_eq(&window, &reopened));
            assert!(vault.sync_state_get(&marker)?.is_none());
        } else {
            import_doc(&window.doc, &owner_update)?;
            import_doc(&window.doc, &skill_update)?;
        }
        if wrong_kind {
            assert!(
                vault.get_skill_record(&fork)?.is_none(),
                "a wrong-kind owner cannot activate the resident skill"
            );
            assert!(
                crate::sync::quarantine::quarantined_records(&vault)?
                    .iter()
                    .any(|(_, q)| q.reason_code == "InvalidSkillBody")
            );
        } else {
            assert_eq!(vault.get_skill_record(&fork)?, Some(record));
        }
    }
    Ok(())
}

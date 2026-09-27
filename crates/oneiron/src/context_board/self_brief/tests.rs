use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::llm::BudgetExhaustionPolicy;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::temporal::TimeRange;
use rmpv::Value;

#[test]
fn complete_self_brief_reuses_the_same_projection_at_open_and_fold() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let self_ref = EntityId::from_bytes_unchecked([1; 16]);
    let principal = EntityId::from_bytes_unchecked([2; 16]);
    let skill = EntityId::from_bytes_unchecked([3; 16]);
    let working = EntityId::from_bytes_unchecked([4; 16]);
    let hash = SkillContentHash::from_bytes([0xab; 32]);
    let record = SkillRecord::new(
        "fixture.skill",
        "Fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.01,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
    .with_content_hash(hash);
    vault.put_skill_record(&skill, &record, TimeRange { start: 1, end: 1 }, 2)?;
    let mut read_set = SessionReadSet::default();
    read_set.loaded_skill("fixture.skill", "1.0.0");
    let budget = BudgetRead {
        attempt_id: "run-1".into(),
        limit_units: 100,
        cap_units: 100,
        used_units: 25,
        reserved_units: 10,
        remaining_units: 65,
        on_budget_exhausted: BudgetExhaustionPolicy::Suspend,
        fired_thresholds: vec![],
    };
    let scope = Scope::top();
    let comm = CommunicationLimits {
        scope: Scope::default(),
        recipients: vec![principal],
        max_messages: Some(2),
    };
    let classes = [
        ClassLimit {
            class: "read".into(),
            verdict: ClassVerdict::Allow,
        },
        ClassLimit {
            class: "send".into(),
            verdict: ClassVerdict::WouldAsk,
        },
        ClassLimit {
            class: "delete".into(),
            verdict: ClassVerdict::Deny,
        },
    ];
    let cast = [principal];
    let skills = [skill];
    let working_set = [working];
    let input = SelfBriefInput {
        self_ref,
        principal,
        cast: &cast,
        grant_revision: 7,
        effective_scope: &scope,
        communication: &comm,
        classes: &classes,
        budget_lease_id: "lease-1",
        budget: &budget,
        clock_ms: 123,
        skill_index: &skills,
        read_set: &read_set,
        working_set: &working_set,
    };
    let brief = SelfBrief::describe(&vault, input)?;
    assert_eq!(brief.skills[0].reliability, 2.0 / 3.0); // not record.confidence
    assert_eq!(
        brief.skills[0].hash.as_deref(),
        Some(hash.to_hex().as_str())
    );
    assert_eq!(brief.skills[0].loaded_hash, brief.skills[0].hash);
    let open = PlacedSelfBrief::assemble(&brief, BriefPlacement::TurnOne);
    let folded = PlacedSelfBrief::assemble(&brief, BriefPlacement::Fold);
    assert_eq!(open, folded);
    let prefix = open.prefix.as_deref().expect("turn-one prefix");
    let (skill_block, identity_block) = prefix.split_once("</skills>\n<identity>").unwrap();
    let skill_rows: serde_json::Value =
        serde_json::from_str(skill_block.strip_prefix("<skills>").unwrap()).unwrap();
    let data: serde_json::Value =
        serde_json::from_str(identity_block.strip_suffix("</identity>").unwrap()).unwrap();
    assert_eq!(data["self_ref"], serde_json::json!(self_ref.to_hex()));
    assert_eq!(data["principal"], serde_json::json!(principal.to_hex()));
    assert_eq!(data["cast"][0], serde_json::json!(principal.to_hex()));
    assert_eq!(data["grant_revision"], 7);
    assert_eq!(
        data["effective_scope"],
        serde_json::to_value(&scope).unwrap()
    );
    assert_eq!(data["communication"]["max_messages"], 2);
    assert_eq!(data["classes"][0]["verdict"], "allow");
    assert_eq!(data["classes"][1]["verdict"], "would_ask");
    assert_eq!(data["classes"][2]["verdict"], "deny");
    assert_eq!(data["budget_lease_id"], "lease-1");
    assert_eq!(data["budget"]["reserved_units"], 10);
    assert_eq!(data["budget"]["remaining_units"], 65);
    assert_eq!(data["clock_ms"], 123);
    assert_eq!(skill_rows[0]["hash"], hash.to_hex());
    assert_eq!(skill_rows[0]["loaded_hash"], hash.to_hex());
    assert_eq!(
        skill_rows[0]["reliability"],
        serde_json::json!(brief.skills[0].reliability)
    );
    assert_eq!(data["working_set"][0], working.to_hex());

    let midrun = PlacedSelfBrief::assemble(&brief, BriefPlacement::MidRun);
    assert_eq!(midrun.prefix, None);
    assert_eq!(midrun.tail.as_deref(), Some(prefix));
    let revised_budget = BudgetRead {
        remaining_units: 20,
        reserved_units: 15,
        ..budget.clone()
    };
    let revised_classes = [ClassLimit {
        class: "read".into(),
        verdict: ClassVerdict::Deny,
    }];
    let revised = SelfBrief::describe(
        &vault,
        SelfBriefInput {
            self_ref,
            principal,
            cast: &cast,
            grant_revision: 8,
            effective_scope: &scope,
            communication: &comm,
            classes: &revised_classes,
            budget_lease_id: "lease-1",
            budget: &revised_budget,
            clock_ms: 456,
            skill_index: &skills,
            read_set: &read_set,
            working_set: &working_set,
        },
    )?;
    let update = PlacedSelfBrief::assemble(&revised, BriefPlacement::MidRun);
    assert_eq!(update.prefix, None);
    assert_ne!(update.tail, open.prefix);
    assert_eq!(
        update.tail,
        PlacedSelfBrief::assemble(&revised, BriefPlacement::Fold).prefix
    );
    assert!(
        update
            .tail
            .as_deref()
            .unwrap()
            .contains("\"remaining_units\":20")
    );
    assert!(
        update
            .tail
            .as_deref()
            .unwrap()
            .contains("\"verdict\":\"deny\"")
    );
    // One context assembly entry point places the exact same card in the
    // correct surface; a mid-run refresh does not replace the cached prefix.
    let bundle = || {
        crate::context_board::AssembledContext::new(
            crate::context_board::SessionContext {
                api_version: "v1".into(),
                counts: Default::default(),
                last_activity: None,
            },
            vec![],
            vec![],
            crate::context_board::HydrationBudget::from_meter(0, 1),
            crate::context_board::MemoriesCursor::new("test"),
            None,
        )
    };
    assert_eq!(
        bundle()
            .with_self_brief(&brief, BriefPlacement::Fold)
            .self_brief,
        Some(open)
    );
    assert_eq!(
        bundle()
            .with_self_brief(&brief, BriefPlacement::MidRun)
            .self_brief,
        Some(midrun)
    );
    Ok(())
}

#[test]
fn missing_index_skill_cannot_claim_a_reliability() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let id = EntityId::from_bytes_unchecked([7; 16]);
    let scope = Scope::default();
    let comm = CommunicationLimits {
        scope: scope.clone(),
        recipients: vec![],
        max_messages: None,
    };
    let budget = BudgetRead {
        attempt_id: "run".into(),
        limit_units: 1,
        cap_units: 1,
        used_units: 0,
        reserved_units: 0,
        remaining_units: 1,
        on_budget_exhausted: BudgetExhaustionPolicy::Suspend,
        fired_thresholds: vec![],
    };
    assert!(matches!(
        SelfBrief::describe(
            &vault,
            SelfBriefInput {
                self_ref: id,
                principal: id,
                cast: &[],
                grant_revision: 0,
                effective_scope: &scope,
                communication: &comm,
                classes: &[],
                budget_lease_id: "lease",
                budget: &budget,
                clock_ms: 0,
                skill_index: &[id],
                read_set: &SessionReadSet::default(),
                working_set: &[],
            }
        ),
        Err(crate::Error::EntityNotFound)
    ));
    Ok(())
}

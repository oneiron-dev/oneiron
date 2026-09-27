use super::*;
use crate::EntityId;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass, DisclosureEnvelope,
};
use crate::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use std::collections::BTreeSet;

fn action(
    actor: ActorBound,
    selectors: &[&str],
    target: Option<&str>,
    budget: Option<u64>,
) -> GrantBound {
    let mut envelope =
        ActionEnvelope::new(selectors.iter().map(|s| (*s).to_owned())).expect("valid selectors");
    if let Some(target) = target {
        envelope = envelope.with_target(target).expect("valid target");
    }
    if let Some(budget) = budget {
        envelope = envelope.with_budget(budget);
    }
    GrantBound::action(actor, ActionClass::new("send").expect("class"), envelope)
        .expect("action bound")
}

fn actor() -> ActorBound {
    ActorBound::new("agent-a").expect("actor")
}

fn candidate(index: usize, bound: GrantBound, required: &GrantBound, id: u8) -> ReasonCandidate {
    ReasonCandidate::new(index, bound, required.clone(), [id; 16])
        .expect("eligible same-class reason")
}

#[test]
fn three_rule_cycle_is_order_independent_with_fixed_issuance_identities() {
    let required = action(actor(), &["channel:team"], None, Some(5));
    let a = action(actor(), &["channel:team", "channel:ops0"], None, Some(10));
    let c = action(actor(), &["channel:team", "channel:other0"], None, Some(50));
    let b = action(actor(), &["channel:team", "channel:ops0"], None, Some(100));
    assert!(b.contains(&a));
    assert!(!a.contains(&b));
    assert!(!c.contains(&a) && !a.contains(&c));
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let bounds = [&a, &c, &b];
        let ids = [1, 2, 3];
        let candidates =
            order.map(|index| candidate(index, bounds[index].clone(), &required, ids[index]));
        // B has the newest ID but A dominates it. The retained fallback
        // chooses C over A because they are incomparable and C has ID 2.
        assert_eq!(
            select_reason(&candidates),
            ReasonSelection::Covering(1),
            "order {order:?}"
        );
    }
}

#[test]
fn selected_covering_reason_has_no_strictly_narrower_live_covering_reason() {
    let wide_action = action(actor(), &["channel:team", "channel:ops"], None, None);
    let narrow_action = action(actor(), &["channel:team"], None, None);
    let selector_request = action(actor(), &["channel:team"], None, Some(5));
    let wide_budget = action(actor(), &["channel:team"], None, Some(100));
    let narrow_budget = action(actor(), &["channel:team"], None, Some(10));
    let budget_request = action(actor(), &["channel:team"], None, Some(5));
    let wide_target = action(actor(), &["channel:team"], None, None);
    let narrow_target = action(actor(), &["channel:team"], Some("contact:alice"), None);
    let target_request = action(actor(), &["channel:team"], Some("contact:alice"), Some(5));
    let wide_actor = action(actor(), &["channel:team"], None, None);
    let narrow_actor = action(
        actor().with_actor_class("agent").expect("actor class"),
        &["channel:team"],
        None,
        None,
    );
    let actor_request = action(
        actor().with_actor_class("agent").expect("actor class"),
        &["channel:team"],
        None,
        Some(5),
    );
    let disclosure = |audience: AudienceBound, scope: Scope| {
        GrantBound::disclosure(
            audience,
            DisclosureClass::new("health").expect("disclosure class"),
            DisclosureEnvelope::from_scope(scope).expect("typed scope"),
        )
        .expect("disclosure bound")
    };
    let wide_audience = disclosure(
        AudienceBound::new(["alice".to_owned(), "bob".to_owned()]).expect("audience"),
        Scope::top(),
    );
    let narrow_audience = disclosure(
        AudienceBound::singleton("alice").expect("audience"),
        Scope::top(),
    );
    let audience_request = narrow_audience.clone();
    let world = ScopeId(EntityId::from_bytes([0x45; 16]).expect("world id"));
    let mut narrow_scope = Scope::top();
    narrow_scope.worlds = ScopeAxis::Some(BTreeSet::from([world]));
    narrow_scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private);
    let mut requested_scope = narrow_scope.clone();
    requested_scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Public);
    let wide_scope = disclosure(
        AudienceBound::singleton("alice").expect("audience"),
        Scope::top(),
    );
    let narrow_scope = disclosure(
        AudienceBound::singleton("alice").expect("audience"),
        narrow_scope,
    );
    let scope_request = disclosure(
        AudienceBound::singleton("alice").expect("audience"),
        requested_scope,
    );

    for (wide, narrow, request) in [
        (wide_action, narrow_action, selector_request),
        (wide_budget, narrow_budget, budget_request),
        (wide_target, narrow_target, target_request),
        (wide_actor, narrow_actor, actor_request),
        (wide_audience, narrow_audience, audience_request),
        (wide_scope, narrow_scope, scope_request),
    ] {
        let candidates = [
            candidate(0, narrow, &request, 1),
            candidate(1, wide, &request, 3),
        ];
        let ReasonSelection::Covering(chosen) = select_reason(&candidates) else {
            panic!("expected covering selection");
        };
        let selected = candidates
            .iter()
            .find(|c| c.rule_index == chosen)
            .expect("selected candidate");
        assert!(
            !candidates.iter().any(|other| {
                selected.bound.contains(&other.bound) && !other.bound.contains(&selected.bound)
            }),
            "selected bound was dominated for requirement {request:?}"
        );
        assert_eq!(
            chosen, 0,
            "narrow bound must survive for requirement {request:?}"
        );
    }
}

#[test]
fn advisory_and_absent_candidates_never_select_covering_authority() {
    let required = action(actor(), &["channel:team", "channel:new"], None, None);
    let advisory = candidate(
        7,
        action(actor(), &["channel:team"], None, None),
        &required,
        8,
    );
    assert_eq!(select_reason(&[]), ReasonSelection::None);
    assert_eq!(select_reason(&[advisory]), ReasonSelection::PrefillOnly(7));
    assert!(
        ReasonCandidate::new(
            9,
            action(
                ActorBound::new("agent-b").expect("other actor"),
                &["channel:team"],
                None,
                None
            ),
            required,
            [9; 16],
        )
        .is_none()
    );
}

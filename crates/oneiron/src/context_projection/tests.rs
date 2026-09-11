//! Descriptor, narrowing, resolution-order, and scan-behaviour contract tests.

use self::test_support::*;
use super::*;
use crate::error::ArtifactError;

mod panel;
mod resolution;
mod test_support;

#[test]
fn one_1709_t1_empty_map_facade_witness_projects_default_and_recent() {
    let (_dir, vault) = open_vault();
    let (turn, body) = f6_empty_turn(&vault, 0xC0, NOW);
    f6_message(&vault, 0xC1, &turn, NOW + 1);
    assert!(is_conversational_turn_body(&vault, &turn, &body).expect("classify"));
    let default = resolve(&vault, ContextSpec::default()).expect("default resolves");
    assert_eq!(default.chat_sections, [format!("tn_{}", turn.to_hex())]);
    let recent = resolve(
        &vault,
        ContextSpec {
            chat: ChatProjection::Recent { last_n: 1 },
            ..ContextSpec::excluded()
        },
    )
    .expect("recent resolves");
    assert_eq!(recent.chat_sections, [format!("tn_{}", turn.to_hex())]);
}

#[test]
fn one_1709_t2_kind_qualified_window_survives_513_authoredby_edges() {
    let (_dir, vault) = open_vault();
    let (turn, body) = f6_empty_turn(&vault, 0xC2, NOW);
    for i in 0..513u32 {
        vault
            .put_edge(&f6_other_id(i), EdgeKind::AuthoredBy, &turn, 1.0)
            .expect("noise edge");
    }
    f6_message(&vault, 0xC3, &turn, NOW + 1);
    assert!(is_conversational_turn_body(&vault, &turn, &body).expect("classify"));
    let resolved = resolve(&vault, ContextSpec::default()).expect("default resolves");
    assert!(
        resolved
            .chat_sections
            .contains(&format!("tn_{}", turn.to_hex()))
    );
    let pre_f4_window_has_part_of = vault
        .edges_in(&turn)
        .expect("edges_in")
        .into_iter()
        .take(CONTEXT_SPEC_MEMORY_SCAN_LIMIT)
        .any(|e| e.kind == EdgeKind::PartOf);
    assert!(
        !pre_f4_window_has_part_of,
        "pre-F4 edge window must lose PartOf"
    );
}

#[test]
fn one_1709_t3_child_scoped_memory_must_be_a_strict_parent_subset() {
    let (_dir, vault) = open_vault();
    let world = f6_other_id(700);
    let base = f6_claim(&vault, 0xC4, "base.fact", None, NOW);
    let foreign = f6_claim(&vault, 0xC5, "world.fact", Some(world), NOW + 1);
    let parent_base = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec {
                memory: MemoryProjection::Default,
                ..ContextSpec::excluded()
            },
            parent: None,
            context_from: Vec::new(),
            world_scope: Some(WorldScope::Base),
        },
    )
    .expect("base parent projection");
    assert!(
        parent_base
            .memory_sections
            .contains(&format!("base:cl_{}", base.to_hex()))
    );
    assert!(
        !parent_base
            .memory_sections
            .contains(&format!("world:cl_{}", foreign.to_hex()))
    );

    let inherited_base = ContextSpec {
        memory: MemoryProjection::Scoped {
            domains: vec!["base".into()],
            limit: 1,
        },
        ..ContextSpec::excluded()
    };
    let child_base = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: inherited_base,
            parent: Some(parent_base.clone()),
            context_from: Vec::new(),
            world_scope: Some(WorldScope::Base),
        },
    )
    .expect("child may request the parent's base domain");
    assert!(
        child_base
            .memory_sections
            .contains(&format!("base:cl_{}", base.to_hex()))
    );
    assert!(
        !child_base
            .memory_sections
            .contains(&format!("world:cl_{}", foreign.to_hex()))
    );

    let invalid_child = ContextSpec {
        memory: MemoryProjection::Scoped {
            domains: vec!["base".into(), "world".into()],
            limit: 1,
        },
        ..ContextSpec::excluded()
    };
    let error = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: invalid_child,
            parent: Some(parent_base),
            context_from: Vec::new(),
            world_scope: Some(WorldScope::Base),
        },
    )
    .expect_err("child must not request a domain absent from the parent projection");
    assert!(matches!(
        error,
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(_))
    ));

    let standalone = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec {
                memory: MemoryProjection::Scoped {
                    domains: vec!["base".into(), "world".into()],
                    limit: 32,
                },
                ..ContextSpec::excluded()
            },
            parent: None,
            context_from: Vec::new(),
            world_scope: None,
        },
    )
    .expect("foreign domain remains available without a parent grant");
    assert!(
        standalone
            .memory_sections
            .contains(&format!("world:cl_{}", foreign.to_hex()))
    );
}

#[test]
fn one_1709_t4_world_a_to_world_b_membership() {
    let (_dir, vault) = open_vault();
    let world_a = f6_other_id(701);
    let world_b = f6_other_id(702);
    let base = f6_claim(&vault, 0xC6, "base.fact", None, NOW);
    let a = f6_claim(&vault, 0xC7, "alpha.fact", Some(world_a), NOW + 1);
    let b = f6_claim(&vault, 0xC8, "beta.fact", Some(world_b), NOW + 2);
    let projection = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec::default(),
            parent: None,
            context_from: Vec::new(),
            world_scope: Some(WorldScope::World(world_b)),
        },
    )
    .expect("world B");
    assert!(
        projection
            .memory_sections
            .contains(&format!("base:cl_{}", base.to_hex()))
    );
    assert!(
        projection
            .memory_sections
            .contains(&format!("beta:cl_{}", b.to_hex()))
    );
    assert!(
        !projection
            .memory_sections
            .contains(&format!("alpha:cl_{}", a.to_hex()))
    );
}

#[test]
fn one_1709_t5_default_is_implicit_base_under_base_scope() {
    let (_dir, vault) = open_vault();
    let base = f6_claim(&vault, 0xC9, "implicit.fact", None, NOW);
    let world = f6_claim(
        &vault,
        0xCA,
        "implicit.fact",
        Some(f6_other_id(703)),
        NOW + 1,
    );
    let projection = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec::default(),
            parent: None,
            context_from: Vec::new(),
            world_scope: Some(WorldScope::Base),
        },
    )
    .expect("base default");
    assert!(
        projection
            .memory_sections
            .contains(&format!("implicit:cl_{}", base.to_hex()))
    );
    assert!(
        !projection
            .memory_sections
            .contains(&format!("implicit:cl_{}", world.to_hex()))
    );
}

// ── descriptor identity + normalization ─────────────────────────────

/// `self.context` is an identity call over a DESCRIPTOR: normalization is
/// idempotent and nothing is resolved. The no-vault-read half is proven by
/// signature — `context` takes no vault — and exercised at the code_run
/// bridge.
#[test]
fn context_round_trips_the_descriptor_after_normalization() {
    let authored = ContextSpec {
        layers: vec![
            "  identity ".to_owned(),
            "identity".to_owned(),
            String::new(),
            "project".to_owned(),
        ],
        memory: MemoryProjection::Scoped {
            domains: vec![" health ".to_owned(), "health".to_owned()],
            limit: 3,
        },
        chat: ChatProjection::Recent { last_n: 2 },
        briefing: Some("  summarize the thread  ".to_owned()),
        annotation: Some(" dev note ".to_owned()),
    };

    let once = normalize_context_spec(authored);
    assert_eq!(once.layers, ["identity", "project"]);
    assert_eq!(
        once.memory,
        MemoryProjection::Scoped {
            domains: vec!["health".to_owned()],
            limit: 3,
        }
    );
    assert_eq!(once.briefing.as_deref(), Some("summarize the thread"));
    assert_eq!(once.annotation.as_deref(), Some("dev note"));

    // Idempotent, and `context` hands the descriptor straight back.
    let twice = normalize_context_spec(once.clone());
    assert_eq!(twice, once);
    assert_eq!(context(once.clone()), once);
    validate_context_spec(&once).expect("normalized descriptor validates");
}

#[test]
fn malformed_descriptors_are_refused() {
    let rejects = [
        scoped(&[], 1),
        scoped(&["health"], 0),
        scoped(&["health"], CONTEXT_SPEC_MAX_MEMORY_LIMIT + 1),
        scoped(&["bad:domain"], 1),
        ContextSpec {
            chat: ChatProjection::Recent { last_n: 0 },
            ..ContextSpec::default()
        },
        ContextSpec {
            chat: ChatProjection::Recent {
                last_n: CONTEXT_SPEC_MAX_CHAT_LAST_N + 1,
            },
            ..ContextSpec::default()
        },
        ContextSpec {
            layers: vec!["x".repeat(CONTEXT_SPEC_MAX_LABEL_BYTES + 1)],
            ..ContextSpec::default()
        },
        ContextSpec {
            briefing: Some("b".repeat(CONTEXT_SPEC_MAX_TEXT_BYTES + 1)),
            ..ContextSpec::default()
        },
    ];
    let refusals = rejects
        .iter()
        .filter(|spec| validate_context_spec(spec).is_err())
        .count();
    assert_eq!(refusals, rejects.len());
}

// ── resolution order + freshness ────────────────────────────────────

/// Dispatch-time resolution reads LIVE state. A claim and a turn added
/// AFTER the descriptor was authored are both projected, which is exactly
/// what a create-time snapshot could not do.
#[test]
fn resolution_sees_state_added_after_the_descriptor_was_authored() {
    let (_dir, vault) = open_vault();
    let spec = scoped(&["health"], 4);
    put_domain_claim(&vault, 0x21, "health.weight", NOW);

    let before = resolve(&vault, spec.clone()).expect("resolve before");
    assert_eq!(before.memory_sections.len(), 1);

    put_domain_claim(&vault, 0x22, "health.sleep", NOW + 1);
    let after = resolve(&vault, spec).expect("resolve after");

    assert_eq!(after.memory_sections.len(), 2);
    // Newest-first, and every token names its domain.
    assert!(
        after
            .memory_sections
            .iter()
            .all(|section| section.starts_with("health:cl_"))
    );
    assert_eq!(after.memory_domains(), ["health"]);
}

/// Resolution runs Layers → Memory → Chat → Briefing and STRIPS the
/// dev-only `_annotation`: it reaches no resolved projection, so it can
/// reach no prompt.
#[test]
fn resolution_follows_the_fixed_order_and_strips_the_annotation() {
    let (_dir, vault) = open_vault();
    put_domain_claim(&vault, 0x23, "health.weight", NOW);
    put_turn(&vault, 0x24, NOW + 1);

    let resolved = resolve(
        &vault,
        ContextSpec {
            layers: vec!["identity".to_owned()],
            memory: MemoryProjection::Scoped {
                domains: vec!["health".to_owned()],
                limit: 4,
            },
            chat: ChatProjection::Recent { last_n: 4 },
            briefing: Some("delegated slice".to_owned()),
            annotation: Some("dev note".to_owned()),
        },
    )
    .expect("resolve");

    assert_eq!(resolved.layers, ["identity"]);
    assert_eq!(resolved.memory_sections.len(), 1);
    assert_eq!(resolved.chat_sections.len(), 1);
    assert!(resolved.chat_sections[0].starts_with("tn_"));
    assert_eq!(resolved.briefing.as_deref(), Some("delegated slice"));
    // The whole resolved shape carries no annotation field at all.
    assert!(
        !format!("{resolved:?}").contains("dev note"),
        "the dev-only annotation must not survive resolution"
    );
}

#[test]
fn excluded_projections_resolve_to_nothing() {
    let (_dir, vault) = open_vault();
    put_domain_claim(&vault, 0x25, "health.weight", NOW);
    put_turn(&vault, 0x26, NOW);

    let resolved = resolve(&vault, ContextSpec::excluded()).expect("resolve");

    assert_eq!(resolved.memory_sections.len(), 0);
    assert_eq!(resolved.chat_sections.len(), 0);
    assert_eq!(resolved.layers.len(), 0);
}

// ── narrowing ───────────────────────────────────────────────────────

/// Layers, domains, and limits can only narrow. Every widening request in
/// the matrix is refused against the parent's RESOLVED projection.
#[test]
fn recursive_projections_can_only_narrow() {
    let (_dir, vault) = open_vault();
    put_domain_claim(&vault, 0x27, "health.weight", NOW);
    put_domain_claim(&vault, 0x28, "health.sleep", NOW + 1);
    put_domain_claim(&vault, 0x29, "work.role", NOW + 2);
    put_turn(&vault, 0x2A, NOW + 3);
    put_turn(&vault, 0x2B, NOW + 4);

    let parent = resolve(
        &vault,
        ContextSpec {
            layers: vec!["identity".to_owned(), "project".to_owned()],
            memory: MemoryProjection::Scoped {
                domains: vec!["health".to_owned()],
                limit: 2,
            },
            chat: ChatProjection::Recent { last_n: 2 },
            briefing: None,
            annotation: None,
        },
    )
    .expect("resolve parent");
    assert_eq!(parent.memory_sections.len(), 2);
    assert_eq!(parent.chat_sections.len(), 2);

    // Narrower requests all pass.
    let narrowed = resolve_under(
        &vault,
        &parent,
        ContextSpec {
            layers: vec!["identity".to_owned()],
            memory: MemoryProjection::Scoped {
                domains: vec!["health".to_owned()],
                limit: 1,
            },
            chat: ChatProjection::Recent { last_n: 1 },
            briefing: Some("only the weight question".to_owned()),
            annotation: None,
        },
    )
    .expect("narrower child resolves");
    assert_eq!(narrowed.layers, ["identity"]);
    assert_eq!(narrowed.memory_sections.len(), 1);
    assert_eq!(narrowed.chat_sections.len(), 1);
    // Briefing adds parent-authored text and grants no read scope.
    assert_eq!(
        narrowed.briefing.as_deref(),
        Some("only the weight question")
    );

    let widenings = [
        // A layer the parent did not project.
        ContextSpec {
            layers: vec!["secrets".to_owned()],
            ..ContextSpec::default()
        },
        // A domain outside the parent's scope.
        scoped(&["work"], 1),
        // A limit above the parent's projected section count.
        scoped(&["health"], 3),
        // A chat bound above the parent's.
        ContextSpec {
            chat: ChatProjection::Recent { last_n: 3 },
            ..ContextSpec::default()
        },
    ];
    let refusals = widenings
        .iter()
        .filter(|spec| resolve_under(&vault, &parent, (*spec).clone()).is_err())
        .count();
    assert_eq!(refusals, widenings.len());
}

/// A parent that EXCLUDED a channel cannot be widened back to included.
#[test]
fn excluded_parents_cannot_be_widened_back_to_included() {
    let (_dir, vault) = open_vault();
    put_domain_claim(&vault, 0x2C, "health.weight", NOW);
    put_turn(&vault, 0x2D, NOW);

    let parent = resolve(&vault, ContextSpec::excluded()).expect("resolve excluding parent");

    assert!(resolve_under(&vault, &parent, scoped(&["health"], 1)).is_err());
    assert!(
        resolve_under(
            &vault,
            &parent,
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 1 },
                ..ContextSpec::default()
            },
        )
        .is_err()
    );
    // `Default` INHERITS, so it stays admissible and resolves to nothing.
    let inherited = resolve_under(&vault, &parent, ContextSpec::default())
        .expect("Default inherits an excluding parent");
    assert_eq!(inherited.memory_sections.len(), 0);
    assert_eq!(inherited.chat_sections.len(), 0);
}

/// The DECLARED bound is checked spec-against-spec, independently of what
/// either side happens to resolve to today.
#[test]
fn declared_bounds_narrow_independently_of_content() {
    let parent = ContextSpec {
        layers: vec!["identity".to_owned()],
        memory: MemoryProjection::Scoped {
            domains: vec!["health".to_owned(), "work".to_owned()],
            limit: 4,
        },
        chat: ChatProjection::Recent { last_n: 4 },
        briefing: None,
        annotation: None,
    };

    validate_spec_narrows(&parent, &scoped(&["health"], 4)).expect("subset domain, same limit");
    validate_spec_narrows(&parent, &ContextSpec::excluded()).expect("exclude always narrows");
    validate_spec_narrows(&parent, &ContextSpec::default()).expect("Default inherits");

    let widenings = [
        scoped(&["secrets"], 1),
        scoped(&["health"], 5),
        ContextSpec {
            layers: vec!["secrets".to_owned()],
            ..ContextSpec::default()
        },
        ContextSpec {
            chat: ChatProjection::Recent { last_n: 5 },
            ..ContextSpec::default()
        },
    ];
    let refusals = widenings
        .iter()
        .filter(|child| validate_spec_narrows(&parent, child).is_err())
        .count();
    assert_eq!(refusals, widenings.len());

    // An excluding parent refuses any explicit request.
    let excluded = ContextSpec::excluded();
    assert!(validate_spec_narrows(&excluded, &scoped(&["health"], 1)).is_err());
    assert!(
        validate_spec_narrows(
            &excluded,
            &ContextSpec {
                chat: ChatProjection::Recent { last_n: 1 },
                ..ContextSpec::default()
            }
        )
        .is_err()
    );
}

/// Property: over arbitrary chains of narrowing requests, every level's
/// resolved sections are a subset of the level above it.
#[test]
fn every_level_of_a_chain_is_a_subset_of_the_level_above() {
    let (_dir, vault) = open_vault();
    for (index, predicate) in [
        "health.weight",
        "health.sleep",
        "health.steps",
        "health.mood",
    ]
    .into_iter()
    .enumerate()
    {
        put_domain_claim(
            &vault,
            0x50 + u8::try_from(index).expect("small index"),
            predicate,
            NOW + index as u64,
        );
    }

    let mut projection = resolve(&vault, scoped(&["health"], 4)).expect("root resolves");
    assert_eq!(projection.memory_sections.len(), 4);

    for limit in [3usize, 2, 1] {
        let child = resolve_under(&vault, &projection, scoped(&["health"], limit))
            .expect("narrowing child resolves");
        assert_eq!(child.memory_sections.len(), limit);
        let contained = child
            .memory_sections
            .iter()
            .filter(|section| projection.memory_sections.contains(section))
            .count();
        assert_eq!(contained, child.memory_sections.len());
        projection = child;
    }
}

//! Pure ladder, novelty-guard, magistrate, and A2A-projection tests
//! (ONE-1888). Everything here runs without a vault by construction.

use super::*;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test entity id")
}

// ── OF-399 novelty guard ────────────────────────────────────────────────

struct StubLookup {
    graduated: std::result::Result<bool, String>,
    approved: std::result::Result<bool, String>,
}

impl StubLookup {
    fn graduated_with(approved: bool) -> Self {
        Self {
            graduated: Ok(true),
            approved: Ok(approved),
        }
    }
}

impl GraduationLookup for StubLookup {
    fn scope_is_graduated(&self, _scope: &GraduationScope) -> std::result::Result<bool, String> {
        self.graduated.clone()
    }

    fn shape_was_approved(
        &self,
        _scope: &GraduationScope,
        _fingerprint: DeltaShapeFingerprint,
    ) -> std::result::Result<bool, String> {
        self.approved.clone()
    }
}

fn shape(paths: &[&str]) -> EntityDeltaShape {
    EntityDeltaShape {
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: 4,
        normalized_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
    }
}

fn scope() -> GraduationScope {
    GraduationScope {
        proposer_actor_ref: id(0x51),
        owning_actor_ref: id(0x52),
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: 4,
        skill_or_agent_ref: None,
        standing_grant_ref: id(0x53),
    }
}

/// A graduated pair reuses its standing grant only for an already-receipted
/// shape. The same pair proposing a new field, operation family, or target
/// class returns to consult.
#[test]
fn graduation_admits_a_known_shape_and_returns_a_novel_one_to_consult() {
    let known = novelty_guard(
        &StubLookup::graduated_with(true),
        &scope(),
        &shape(&["person.email"]),
    );
    assert_eq!(
        known,
        NoveltyDecision::AutoKnownShape {
            standing_grant_ref: id(0x53)
        }
    );

    let novel_field = shape(&["person.email", "person.home_address"]);
    assert_eq!(
        novelty_guard(&StubLookup::graduated_with(false), &scope(), &novel_field),
        NoveltyDecision::ConsultNovelShape {
            fingerprint: novel_field.fingerprint()
        }
    );

    // A new OPERATION family under the same paths is a different bound, so the
    // graduated scope no longer covers it at all.
    let mut novel_operation = shape(&["person.email"]);
    novel_operation.operation_kind = "claim.retract".to_owned();
    assert_eq!(
        novelty_guard(
            &StubLookup::graduated_with(true),
            &scope(),
            &novel_operation
        ),
        NoveltyDecision::ConsultUncertainShape
    );

    // A new TARGET class likewise.
    let mut novel_class = shape(&["person.email"]);
    novel_class.target_entity_type = 17;
    assert_eq!(
        novelty_guard(&StubLookup::graduated_with(true), &scope(), &novel_class),
        NoveltyDecision::ConsultUncertainShape
    );
}

/// Every failure direction is consult. A missing grant, a malformed shape, and
/// a lookup that cannot answer all mint the owner-agent ask; none of them can
/// produce the auto arm.
#[test]
fn novelty_guard_fails_toward_consult_and_never_toward_auto() {
    let no_grant = StubLookup {
        graduated: Ok(false),
        approved: Ok(true),
    };
    assert_eq!(
        novelty_guard(&no_grant, &scope(), &shape(&["person.email"])),
        NoveltyDecision::ConsultNoGrant
    );

    let broken_scope_lookup = StubLookup {
        graduated: Err("index unavailable".to_owned()),
        approved: Ok(true),
    };
    let broken_shape_lookup = StubLookup {
        graduated: Ok(true),
        approved: Err("receipt history unreadable".to_owned()),
    };
    for lookup in [broken_scope_lookup, broken_shape_lookup] {
        assert_eq!(
            novelty_guard(&lookup, &scope(), &shape(&["person.email"])),
            NoveltyDecision::ConsultUncertainShape
        );
    }

    let malformed = [
        shape(&[]),
        shape(&["", "person.email"]),
        shape(&["person.email", "person.email"]),
        shape(&["person.email\u{7}injected"]),
        shape(&[" person.email"]),
        EntityDeltaShape {
            operation_kind: String::new(),
            target_entity_type: 4,
            normalized_paths: vec!["person.email".to_owned()],
        },
    ];
    for (index, entry) in malformed.into_iter().enumerate() {
        assert!(!entry.is_decodable(), "case {index} must not decode");
        assert_eq!(
            novelty_guard(&StubLookup::graduated_with(true), &scope(), &entry),
            NoveltyDecision::ConsultUncertainShape,
            "case {index} must fall back to consult"
        );
    }
}

/// The fingerprint hashes STRUCTURE. Path order is not structure; a new path
/// is.
#[test]
fn delta_shape_fingerprint_is_order_free_but_structure_sensitive() {
    let forward = shape(&["person.email", "person.phone"]);
    let reversed = shape(&["person.phone", "person.email"]);
    let extended = shape(&["person.email", "person.phone", "person.address"]);

    assert_eq!(forward.fingerprint(), reversed.fingerprint());
    assert_ne!(forward.fingerprint(), extended.fingerprint());
}

//! Memory- and chat-projection scan behaviour against a live vault.

use super::test_support::*;
use super::*;

// ── claim surfacing gate (FIX-1) ───────────────────────────────────

/// The canonical claim-surfacing gate applies inside the memory
/// projection: each suppressed class yields NO section — at the root and
/// under `Scoped` — while control claims still resolve, and suppressed
/// rows never displace the limit accounting.
#[test]
fn memory_projection_suppresses_unsurfaced_claims() {
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};

    let put = |vault: &Vault,
               seed: u8,
               approval: ClaimApprovalStatus,
               lifecycle: ClaimLifecycleStatus,
               stale: bool| {
        let subject = put_subject(vault);
        let id = entity(seed);
        let mut claim = crate::claim::ClaimBody::new(
            "health.metric",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("v"),
            1.0,
            approval,
            lifecycle,
        );
        claim.stale = stale;
        vault
            .put_claim(
                &id,
                &claim,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("store claim");
        id
    };

    let (_dir, vault) = open_vault();
    // Controls first (oldest), then one claim per suppressed class as the
    // NEWER rows: suppression must not silently widen the scan.
    let control_a = put(
        &vault,
        0x30,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        false,
    );
    let control_b = put(
        &vault,
        0x31,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    );
    let suppressed = [
        put(
            &vault,
            0x32,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
            false,
        ),
        put(
            &vault,
            0x33,
            ClaimApprovalStatus::Rejected,
            ClaimLifecycleStatus::Active,
            false,
        ),
        put(
            &vault,
            0x34,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Superseded,
            false,
        ),
        put(
            &vault,
            0x35,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Retracted,
            false,
        ),
        put(
            &vault,
            0x36,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            true,
        ),
    ];

    let expected: Vec<String> = [control_b, control_a]
        .iter()
        .map(|id| format!("health:cl_{}", id.to_hex()))
        .collect();
    // Root Default projection: exactly the two controls, newest-first;
    // no suppressed id appears anywhere.
    let root = resolve(&vault, ContextSpec::default()).expect("root resolves");
    assert_eq!(root.memory_sections, expected);
    for id in suppressed {
        assert!(
            !root
                .memory_sections
                .iter()
                .any(|s| s.contains(&id.to_hex())),
            "suppressed claim {id:?} must not surface"
        );
    }

    // Scoped child with limit 1: contents, not just length — the single
    // section is the newest CONTROL, so suppressed rows did not count.
    let child = resolve(&vault, scoped(&["health"], 1)).expect("scoped resolves");
    assert_eq!(child.memory_sections, expected[..1]);
}

// ── conversational-turn filter (FIX-5) ────────────────────────────

/// Non-conversational TURN artifacts — the persisted panel spec and a
/// consult-expiry receipt — never reach a chat projection and never
/// displace conversational turns under `last_n`.
#[test]
fn chat_projection_skips_non_conversational_turn_artifacts() {
    let (_dir, vault) = open_vault();
    // Two conversational turns, then two NEWER artifact TURNs that must
    // not displace them under last_n = 2.
    let first = put_turn(&vault, 0x40, NOW);
    let second = put_turn(&vault, 0x41, NOW + 1);
    // Panel-spec artifact TURN (role = "lead_panel_spec" discriminant).
    persist_lead_panel_spec(&vault, &panel_spec(), NOW + 2).expect("persist panel spec");
    // Consult-expiry-style artifact: a kind map with neither a speaker
    // marker nor a text payload key.
    // 0x42 is a production-pinned seed byte (gate local-write actor ref);
    // 0x44 is free in this test's 0x4* block.
    let expiry = entity(0x44);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("kind"),
            rmpv::Value::from("consult.expiry"),
        )]),
    )
    .expect("encode artifact body");
    vault
        .put_entity(
            &expiry,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW + 3,
                end: NOW + 3,
            },
            NOW + 3,
            &body,
        )
        .expect("store expiry artifact");

    let resolved = resolve(
        &vault,
        ContextSpec {
            chat: ChatProjection::Recent { last_n: 2 },
            ..ContextSpec::excluded()
        },
    )
    .expect("chat resolves");
    assert_eq!(
        resolved.chat_sections,
        [
            format!("tn_{}", second.to_hex()),
            format!("tn_{}", first.to_hex())
        ],
        "artifacts are filtered before last_n, so they cannot displace chat"
    );

    // The legacy spkr/txt shape still projects.
    let (_dir2, legacy_vault) = open_vault();
    let legacy = entity(0x43);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from("legacy turn")),
        ]),
    )
    .expect("encode legacy body");
    legacy_vault
        .put_entity(
            &legacy,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            &body,
        )
        .expect("store legacy turn");
    let resolved = resolve(&legacy_vault, ContextSpec::default()).expect("default resolves");
    assert_eq!(resolved.chat_sections, [format!("tn_{}", legacy.to_hex())]);
}

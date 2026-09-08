//! Shared test fixtures for the `context_projection` test suite.

use super::*;

pub(super) const NOW: u64 = 1_800_000_000;

pub(super) fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

/// The shared claim subject. A PERSON, deliberately not a TURN: a TURN
/// subject would land in every chat projection the tests count.
pub(super) fn put_subject(vault: &Vault) -> EntityId {
    let id = entity(0x10);
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("store claim subject");
    id
}

/// One CLAIM whose predicate namespace IS the memory domain.
pub(super) fn put_domain_claim(
    vault: &Vault,
    seed: u8,
    predicate: &str,
    learned_at: u64,
) -> EntityId {
    let subject = put_subject(vault);
    let id = entity(seed);
    vault
        .put_claim(
            &id,
            &crate::claim::ClaimBody::new(
                predicate,
                crate::claim::ClaimSubject::Entity(subject),
                rmpv::Value::from("v"),
                1.0,
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .expect("store claim");
    id
}

/// One CONVERSATIONAL turn: speaker marker plus text payload, the shape
/// the chat projection admits. Legacy `spkr`/`txt` keys ride the legacy
/// arm so both markers stay covered.
pub(super) fn put_turn(vault: &Vault, seed: u8, learned_at: u64) -> EntityId {
    let id = entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("speaker"), rmpv::Value::from("user")),
            (
                rmpv::Value::from("text"),
                rmpv::Value::from(format!("turn {seed:02x}")),
            ),
        ]),
    )
    .expect("encode turn body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .expect("store turn");
    id
}

// ONE-1709 F6 fixture helpers: IDs intentionally stay outside the
// pinned-id byte range and fan-out IDs are distinct from one another.

pub(super) fn f6_other_id(n: u32) -> EntityId {
    let mut bytes = [0x5Au8; 16];
    bytes[0] = 0x5A;
    bytes[1] = (n & 0xff) as u8;
    bytes[2] = ((n >> 8) & 0xff) as u8;
    EntityId::from_bytes(bytes).expect("valid distinct fixture id")
}

pub(super) fn f6_empty_turn(vault: &Vault, seed: u8, learned_at: u64) -> (EntityId, Vec<u8>) {
    let id = entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
        .expect("encode empty turn map");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .expect("store empty turn");
    (id, body)
}

pub(super) fn f6_message(vault: &Vault, seed: u8, turn: &EntityId, learned_at: u64) -> EntityId {
    let id = entity(seed);
    // ONE-1686: canonical witness envelope bytes through the crate's
    // test-only seeding door — the public raw MESSAGE put is closed.
    let body =
        crate::gate::canonical_witness_message_body_for_test("user", "dialogue", "hello", true, 0)
            .expect("canonical message body");
    vault
        .batch()
        .put_canonical_message_for_test(
            &id,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
        .expect("store message");
    vault
        .put_edge(&id, EdgeKind::PartOf, turn, 1.0)
        .expect("store PartOf edge");
    id
}

pub(super) fn f6_claim(
    vault: &Vault,
    seed: u8,
    predicate: &str,
    world: Option<EntityId>,
    learned_at: u64,
) -> EntityId {
    let id = entity(seed);
    let mut claim = crate::claim::ClaimBody::new(
        predicate,
        crate::claim::ClaimSubject::Entity(put_subject(vault)),
        rmpv::Value::from("value"),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    claim.world = world;
    vault
        .put_claim(
            &id,
            &claim,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .expect("store fixture claim");
    id
}

pub(super) fn scoped(domains: &[&str], limit: usize) -> ContextSpec {
    ContextSpec {
        memory: MemoryProjection::Scoped {
            domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            limit,
        },
        ..ContextSpec::default()
    }
}

pub(super) fn resolve(vault: &Vault, spec: ContextSpec) -> Result<ResolvedContextProjection> {
    resolve_context_spec(
        vault,
        ContextResolutionRequest {
            spec,
            parent: None,
            context_from: Vec::new(),
            world_scope: None,
        },
    )
}

pub(super) fn resolve_under(
    vault: &Vault,
    parent: &ResolvedContextProjection,
    spec: ContextSpec,
) -> Result<ResolvedContextProjection> {
    resolve_context_spec(
        vault,
        ContextResolutionRequest {
            spec,
            parent: Some(parent.clone()),
            context_from: Vec::new(),
            world_scope: None,
        },
    )
}

pub(super) fn assignee(seed: u8) -> TaskAssignee {
    TaskAssignee::Peer {
        actor_ref: entity(seed),
    }
}

pub(super) fn panel_spec() -> LeadPanelSpec {
    LeadPanelSpec {
        members: (0..3)
            .map(|index| PanelMemberSpec {
                responder: assignee(0x30 + index),
                instructions: format!("member {index} answers alone"),
                context_spec: ContextSpec::excluded(),
            })
            .collect(),
        judge: PanelJudgeSpec {
            responder: assignee(0x40),
            rubric: "rank the answers".to_owned(),
            context_spec: ContextSpec::excluded(),
        },
        synthesis: PanelSynthesisSpec {
            responder: assignee(0x41),
            instructions: "write one final answer".to_owned(),
            context_spec: ContextSpec::excluded(),
        },
    }
}

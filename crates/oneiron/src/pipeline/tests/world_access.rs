//! World-access authority tiers, strict decoding, and bitemporal precedence.

use super::*;

use crate::claim::ClaimSource;

/// The run clock the authority queries pin, so valid-time windows are read
/// against a fixed point instead of the wall clock.
pub(super) const WORLD_ACCESS_NOW: u64 = 5_000;

/// One agent, two worlds, and the four vector-ranked candidates the world
/// filter must sort out: a base-reality claim, a claim in each world, and a
/// non-claim entity (which has no world at all).
pub(super) struct WorldAccessFixture {
    pub(super) agent: EntityId,
    pub(super) world_w: EntityId,
    pub(super) world_v: EntityId,
    pub(super) claim_base: EntityId,
    pub(super) claim_w: EntityId,
    pub(super) claim_v: EntityId,
    pub(super) plain: EntityId,
}

pub(super) fn world_access_fixture(vault: &Vault) -> Result<WorldAccessFixture> {
    let fixture = WorldAccessFixture {
        agent: entity_id(0xA0),
        world_w: entity_id(0xA7),
        world_v: entity_id(0xA8),
        claim_base: entity_id(0xA9),
        claim_w: entity_id(0xAA),
        claim_v: entity_id(0xAB),
        plain: entity_id(0xAC),
    };
    put_entity(
        vault,
        fixture.agent,
        crate::registry::ENTITY_TYPE_PERSON,
        1,
        1,
        1,
    )?;
    put_claim_with_vector_world(vault, fixture.claim_base, [1.0, 0.0, 0.0, 0.0], None)?;
    put_claim_with_vector_world(
        vault,
        fixture.claim_w,
        [0.9, 0.1, 0.0, 0.0],
        Some(fixture.world_w),
    )?;
    put_claim_with_vector_world(
        vault,
        fixture.claim_v,
        [0.8, 0.2, 0.0, 0.0],
        Some(fixture.world_v),
    )?;
    put_vector(vault, fixture.plain, [0.7, 0.3, 0.0, 0.0])?;
    Ok(fixture)
}

pub(super) fn world_access_query(vault: &Vault, now: u64) -> PipelineBuilder<'_> {
    let execution = crate::code_run::HostSelfDispatcher::new(
        vault,
        crate::write_envelope::WriteActor::new(entity_id(0xA0), crate::edge::EdgeActorClass::Agent),
        "world-access-test",
    )
    .expect("host execution");
    vault
        .query_for_execution(&execution)
        .expect("same canonical vault")
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(now)
}

pub(super) fn world_access_ids(scores: &[ScoredEntity]) -> HashSet<EntityId> {
    scores.iter().map(|scored| scored.id).collect()
}

/// One authority CLAIM row to write, built through the shipped
/// [`world_access_claim_body`] door so the tests exercise the real encoder.
pub(super) struct WorldAccessRowSpec {
    id: EntityId,
    predicate: &'static str,
    agent: EntityId,
    include_base: bool,
    worlds: Vec<EntityId>,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
    learned_at: u64,
}

impl WorldAccessRowSpec {
    /// An OWNER grant: user-stated and approved, the only shape the resolver
    /// folds into the ALLOWED-SET.
    pub(super) fn owner_grant(
        id: EntityId,
        agent: EntityId,
        include_base: bool,
        worlds: &[EntityId],
    ) -> Self {
        Self {
            id,
            predicate: PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            agent,
            include_base,
            worlds: worlds.to_vec(),
            source: ClaimSource::UserStated,
            approval: ClaimApprovalStatus::Approved,
            valid_from: None,
            valid_to: None,
            learned_at: 1,
        }
    }

    /// An AGENT-authored default: an ordinary inferred/auto row, which is
    /// exactly what the second tier is allowed to be.
    pub(super) fn agent_default(
        id: EntityId,
        agent: EntityId,
        include_base: bool,
        worlds: &[EntityId],
    ) -> Self {
        Self {
            id,
            predicate: PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            agent,
            include_base,
            worlds: worlds.to_vec(),
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            valid_from: None,
            valid_to: None,
            learned_at: 1,
        }
    }

    fn source(mut self, source: ClaimSource) -> Self {
        self.source = source;
        self
    }

    fn approval(mut self, approval: ClaimApprovalStatus) -> Self {
        self.approval = approval;
        self
    }

    fn valid(mut self, valid_from: Option<u64>, valid_to: Option<u64>) -> Self {
        self.valid_from = valid_from;
        self.valid_to = valid_to;
        self
    }

    fn learned_at(mut self, learned_at: u64) -> Self {
        self.learned_at = learned_at;
        self
    }

    pub(super) fn put(self, vault: &Vault) -> Result<()> {
        let value = WorldAuthoritySet::new(self.include_base, self.worlds.iter().copied())?;
        let mut body = world_access_claim_body(
            self.predicate,
            self.agent,
            &value,
            self.source,
            self.approval,
            self.valid_from,
            self.valid_to,
        )?;
        if self.predicate == PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET {
            body.evidence = Some(world_default_evidence(self.agent)?);
        }
        vault.put_claim(
            &self.id,
            &body,
            TimeRange {
                start: self.learned_at,
                end: self.learned_at,
            },
            self.learned_at,
        )
    }
}

pub(super) fn world_default_evidence(agent: EntityId) -> Result<rmpv::Value> {
    use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

    let envelope = WriteEnvelope::new(
        WriteActor::new(agent, crate::edge::EdgeActorClass::Agent),
        ClaimSource::Inferred,
        WriteProvenance::new(rmpv::Value::from("world-default-test"))?,
        ClaimApprovalStatus::Auto,
    );
    Ok(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ))
}

/// Done-means 4 + 7: an explicit per-turn selection restricts the read to the
/// selected members, and base reality is a MEMBER of that decision — base
/// claims and non-claim entities survive only when `include_base` is set.
/// Nothing about the two runs is stored: the same vault answers both.
#[test]
fn active_set_selection_restricts_reads_and_makes_base_explicit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;

    let without_base = world_access_ids(
        &world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(false, [fixture.world_w])?,
            )
            .run()?,
    );
    assert_eq!(
        without_base,
        HashSet::from([fixture.claim_w]),
        "an explicit selection of W alone reads W's claim and nothing else"
    );

    let with_base = world_access_ids(
        &world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(true, [fixture.world_w])?,
            )
            .run()?,
    );
    assert_eq!(
        with_base,
        HashSet::from([fixture.claim_base, fixture.claim_w, fixture.plain]),
        "include_base admits base claims AND non-claim entities, still never world V"
    );
    Ok(())
}

/// Done-means 4: with no explicit selection the turn inherits the stored
/// DEFAULT-SUBSET, which is narrower than the owner grant it sits inside.
#[test]
fn default_active_worlds_uses_the_stored_default_subset() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    WorldAccessRowSpec::agent_default(entity_id(0xB1), fixture.agent, false, &[fixture.world_v])
        .put(&vault)?;

    let visible = world_access_ids(
        &world_access_query(&vault, WORLD_ACCESS_NOW)
            .default_active_worlds(fixture.agent)
            .run()?,
    );
    assert_eq!(
        visible,
        HashSet::from([fixture.claim_v]),
        "the default subset — not the wider owner grant — is what the turn reads"
    );
    Ok(())
}

/// Done-means 5: no self-widen path. A per-turn selection outside the grant
/// is a typed refusal, an agent-authored ALLOWED-SET row is not a grant at
/// all, and a DEFAULT-SUBSET row that exceeds the grant refuses instead of
/// being clamped. No arm here returns the unrestricted result set.
#[test]
fn selections_outside_the_owner_grant_fail_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    // Neither of these is an owner grant: one is not user-stated, the other
    // carries no explicit approval. Both name world V, which the owner never
    // granted.
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB1),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .source(ClaimSource::Inferred)
    .put(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB2),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .approval(ClaimApprovalStatus::Auto)
    .put(&vault)?;

    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(false, [fixture.world_v])?,
            )
            .run(),
        Err(Error::InvalidConfig(_)),
        "selecting an ungranted world refuses; it never silently drops the member"
    );
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(true, [fixture.world_w])?,
            )
            .run(),
        Err(Error::InvalidConfig(_)),
        "base is a member of the grant: asking for it ungranted refuses too"
    );

    // The grant the owner DID make still reads, so the refusals above are the
    // authority check and not a broken pipeline.
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .active_worlds(
                    fixture.agent,
                    WorldAuthoritySet::new(false, [fixture.world_w])?,
                )
                .run()?
        ),
        HashSet::from([fixture.claim_w]),
        "the granted selection still reads exactly world W"
    );

    // An agent-written default that exceeds the grant refuses rather than
    // being clamped down to it.
    WorldAccessRowSpec::agent_default(
        entity_id(0xB3),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .default_active_worlds(fixture.agent)
            .run(),
        Err(Error::InvalidConfig(_)),
        "an over-wide stored default is refused, never trimmed into the grant"
    );
    Ok(())
}

/// Done-means 6: with no owner row the authority is EMPTY. The default path
/// reads nothing at all (never everything), and any explicit selection
/// refuses.
#[test]
fn missing_allowed_set_resolves_empty_not_unrestricted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;

    assert!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .default_active_worlds(fixture.agent)
            .run()?
            .is_empty(),
        "no owner grant means an empty authority, so the turn reads nothing"
    );
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(true, [fixture.world_w])?,
            )
            .run(),
        Err(Error::InvalidConfig(_)),
        "selecting anything at all without an owner grant refuses"
    );
    // The very same vault is unrestricted under the default scope, so the
    // empty read above is the authority tier and not an empty index.
    assert_eq!(
        world_access_ids(&world_access_query(&vault, WORLD_ACCESS_NOW).run()?).len(),
        4,
        "WorldScope::All is untouched by the authority tiers"
    );
    Ok(())
}

/// Done-means 6: multiple active owner rows INTERSECT, so adding a row can
/// only narrow. The same selection that read world V before the second grant
/// refuses after it.
#[test]
fn multiple_allowed_set_rows_intersect_and_only_narrow() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;

    let select_v = |vault: &Vault| -> Result<Vec<ScoredEntity>> {
        world_access_query(vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(false, [fixture.world_v])?,
            )
            .run()
    };
    assert_eq!(
        world_access_ids(&select_v(&vault)?),
        HashSet::from([fixture.claim_v]),
        "the first grant admits world V"
    );

    // A second owner row that omits V (and base) narrows the fold.
    WorldAccessRowSpec::owner_grant(entity_id(0xB1), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    assert_matches!(
        select_v(&vault),
        Err(Error::InvalidConfig(_)),
        "the intersection dropped V, so the same selection now refuses"
    );
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(true, [fixture.world_w])?,
            )
            .run(),
        Err(Error::InvalidConfig(_)),
        "base survives the intersection only if BOTH rows grant it"
    );
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .active_worlds(
                    fixture.agent,
                    WorldAuthoritySet::new(false, [fixture.world_w])?,
                )
                .run()?
        ),
        HashSet::from([fixture.claim_w]),
        "what both rows grant survives the fold"
    );
    Ok(())
}

/// Done-means 3: the tiers are bitemporal CLAIM rows, so valid-time decides
/// which default is in force. The closed row is ignored at the later clock
/// and the replacement takes over — one vault, two answers, no supersession
/// bookkeeping in the pipeline.
#[test]
fn default_subset_follows_bitemporal_replacement() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    WorldAccessRowSpec::agent_default(entity_id(0xB1), fixture.agent, false, &[fixture.world_v])
        .valid(Some(1_000), Some(4_000))
        .learned_at(10)
        .put(&vault)?;
    WorldAccessRowSpec::agent_default(entity_id(0xB2), fixture.agent, false, &[fixture.world_w])
        .valid(Some(4_000), None)
        .learned_at(20)
        .put(&vault)?;

    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, 2_000)
                .default_active_worlds(fixture.agent)
                .run()?
        ),
        HashSet::from([fixture.claim_v]),
        "inside the first window the earlier default is the one in force"
    );
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .default_active_worlds(fixture.agent)
                .run()?
        ),
        HashSet::from([fixture.claim_w]),
        "past its valid_to the first row is closed and the replacement rules"
    );
    Ok(())
}

/// Done-means 5: a malformed value on a row the resolver WOULD honour fails
/// the read closed. The same malformed row leaves every other scope alone —
/// the refusal belongs to the authority path, not to retrieval at large.
#[test]
fn malformed_authority_row_fails_the_read_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let mut malformed = ClaimBody::new(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        ClaimSubject::Entity(fixture.agent),
        rmpv::Value::from("not-a-world-access-map"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    malformed.source = Some(ClaimSource::UserStated);
    vault.put_claim(
        &entity_id(0xB0),
        &malformed,
        TimeRange { start: 1, end: 1 },
        1,
    )?;

    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(false, [fixture.world_w])?,
            )
            .run(),
        Err(Error::InvalidConfig(_)),
        "an undecodable owner row is never read as a grant of anything"
    );
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .default_active_worlds(fixture.agent)
            .run(),
        Err(Error::InvalidConfig(_)),
        "the default path consumes the same owner tier and refuses with it"
    );
    assert_eq!(
        world_access_ids(&world_access_query(&vault, WORLD_ACCESS_NOW).run()?).len(),
        4,
        "an unrelated scope is untouched by the malformed authority row"
    );
    Ok(())
}

/// The scope token alone is not a selection: `.world(WorldScope::ActiveSet)`
/// with no helper refuses at execution time, and switching scopes CLEARS the
/// sidecar so an earlier turn's selection cannot come back to life.
#[test]
fn bare_active_set_scope_refuses_and_world_clears_the_selection() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, true, &[fixture.world_w])
        .put(&vault)?;

    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .world(WorldScope::ActiveSet)
            .run(),
        Err(Error::InvalidConfig(_)),
        "ActiveSet without a selection refuses; it never degrades to All"
    );
    assert_matches!(
        world_access_query(&vault, WORLD_ACCESS_NOW)
            .active_worlds(
                fixture.agent,
                WorldAuthoritySet::new(false, [fixture.world_w])?,
            )
            .world(WorldScope::Base)
            .world(WorldScope::ActiveSet)
            .run(),
        Err(Error::InvalidConfig(_)),
        "leaving ActiveSet drops the selection, so returning to it has none"
    );
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .active_worlds(
                    fixture.agent,
                    WorldAuthoritySet::new(false, [fixture.world_w])?,
                )
                .world(WorldScope::Base)
                .run()?
        ),
        HashSet::from([fixture.claim_base, fixture.plain]),
        "a cleared selection restricts nothing: Base is exactly Base"
    );
    Ok(())
}

/// Done-means 1: `WorldSet` keeps its repository-backed meaning. It clamps to
/// codebase membership and consults NO authority claim, so an owner grant
/// naming both worlds cannot widen it.
#[test]
fn world_set_scope_keeps_codebase_semantics_without_consulting_authority() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let scope_key: CodebaseScopeKey = [0x7B; CODEBASE_SCOPE_KEY_LEN];

    let before = world_access_ids(
        &world_access_query(&vault, WORLD_ACCESS_NOW)
            .world(WorldScope::WorldSet(scope_key))
            .run()?,
    );
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    let after = world_access_ids(
        &world_access_query(&vault, WORLD_ACCESS_NOW)
            .world(WorldScope::WorldSet(scope_key))
            .run()?,
    );

    assert!(
        before.is_empty(),
        "non-member candidates never pass the codebase scope clamp"
    );
    assert_eq!(
        before, after,
        "the world-access grant does not reach the WorldSet branch at all"
    );
    // World(W) is likewise byte-for-byte what it always was.
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .world(WorldScope::World(fixture.world_w))
                .run()?
        ),
        HashSet::from([fixture.claim_base, fixture.claim_w, fixture.plain]),
        "World(W) still means W plus base reality"
    );
    Ok(())
}

/// Two different per-turn selections must never share a replay key: the
/// selection is part of the query fork hash, and "use my stored default"
/// hashes distinctly from an explicit selection of the same members.
#[test]
fn active_set_selection_forks_the_retrieval_trace_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    WorldAccessRowSpec::agent_default(entity_id(0xB1), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;

    let selected_w = captured_retrieval_trace(
        &vault,
        world_access_query(&vault, WORLD_ACCESS_NOW).active_worlds(
            fixture.agent,
            WorldAuthoritySet::new(false, [fixture.world_w])?,
        ),
    )?;
    let selected_w_again = captured_retrieval_trace(
        &vault,
        world_access_query(&vault, WORLD_ACCESS_NOW).active_worlds(
            fixture.agent,
            WorldAuthoritySet::new(false, [fixture.world_w])?,
        ),
    )?;
    let selected_v = captured_retrieval_trace(
        &vault,
        world_access_query(&vault, WORLD_ACCESS_NOW).active_worlds(
            fixture.agent,
            WorldAuthoritySet::new(false, [fixture.world_v])?,
        ),
    )?;
    let selected_w_with_base = captured_retrieval_trace(
        &vault,
        world_access_query(&vault, WORLD_ACCESS_NOW).active_worlds(
            fixture.agent,
            WorldAuthoritySet::new(true, [fixture.world_w])?,
        ),
    )?;
    let from_default = captured_retrieval_trace(
        &vault,
        world_access_query(&vault, WORLD_ACCESS_NOW).default_active_worlds(fixture.agent),
    )?;
    let unscoped = captured_retrieval_trace(&vault, world_access_query(&vault, WORLD_ACCESS_NOW))?;

    assert_eq!(
        selected_w.fork_hash, selected_w_again.fork_hash,
        "the same selection replays under one fork key"
    );
    for (name, other) in [
        ("another world", selected_v),
        ("base included", selected_w_with_base),
        ("stored default", from_default),
        ("no scope at all", unscoped),
    ] {
        assert_ne!(
            selected_w.fork_hash, other.fork_hash,
            "{name} must not share the selected-W fork key"
        );
    }
    Ok(())
}

/// Builds an ALLOWED-SET body around an arbitrary value, so the strict
/// decoder can be aimed at one malformed shape at a time.
pub(super) fn world_access_body(value: rmpv::Value) -> ClaimBody {
    ClaimBody::new(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        ClaimSubject::Entity(entity_id(0xA0)),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

/// The canonical three-key value map, with every part caller-supplied.
fn world_access_value_map(
    schema_version: rmpv::Value,
    include_base: rmpv::Value,
    worlds: rmpv::Value,
) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (rmpv::Value::from("schema_version"), schema_version),
        (rmpv::Value::from("include_base"), include_base),
        (rmpv::Value::from("worlds"), worlds),
    ])
}

fn world_access_version() -> rmpv::Value {
    rmpv::Value::from(WORLD_ACCESS_SCHEMA_VERSION)
}

fn world_access_world_array(worlds: &[EntityId]) -> rmpv::Value {
    let members = worlds
        .iter()
        .map(|world| rmpv::Value::Binary(world.as_bytes().to_vec()))
        .collect();
    rmpv::Value::Array(members)
}

/// The strict claim-value shape, exercised through the shipped decoder: the
/// canonical round trip, then one fail-closed row per malformed shape. A value
/// that does not decode can never be read as a WIDER authority than it holds.
#[test]
fn world_access_claim_value_decoding_is_strict() -> Result<()> {
    let agent = entity_id(0xA0);
    let first = entity_id(0x31);
    let second = entity_id(0x32);
    let set = WorldAuthoritySet::new(true, [second, first])?;
    let canonical = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        agent,
        &set,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )?;
    assert_eq!(
        decode_world_access_claim_value(&canonical)?,
        set,
        "the encoder's own output round-trips to the same set"
    );
    assert!(
        set.is_subset_of(&set),
        "a set contains itself, base flag included"
    );
    assert!(
        WorldAuthoritySet::default().is_empty(),
        "the default authority reads nothing at all"
    );
    assert!(
        !set.is_subset_of(&WorldAuthoritySet::new(true, [first])?),
        "containment is membership: a missing world is not a subset"
    );
    assert!(
        !WorldAuthoritySet::new(true, [first])?
            .is_subset_of(&WorldAuthoritySet::new(false, [first])?),
        "base is a member of containment, not a side channel"
    );

    for (name, malformed) in [
        (
            "unknown key",
            world_access_body(rmpv::Value::Map(vec![
                (rmpv::Value::from("schema_version"), world_access_version()),
                (
                    rmpv::Value::from("include_base"),
                    rmpv::Value::Boolean(false),
                ),
                (
                    rmpv::Value::from("worlds"),
                    world_access_world_array(&[first]),
                ),
                (rmpv::Value::from("extra"), rmpv::Value::Boolean(true)),
            ])),
        ),
        (
            "duplicate key",
            world_access_body(rmpv::Value::Map(vec![
                (rmpv::Value::from("schema_version"), world_access_version()),
                (
                    rmpv::Value::from("include_base"),
                    rmpv::Value::Boolean(false),
                ),
                (
                    rmpv::Value::from("include_base"),
                    rmpv::Value::Boolean(true),
                ),
                (
                    rmpv::Value::from("worlds"),
                    world_access_world_array(&[first]),
                ),
            ])),
        ),
        (
            "missing include_base",
            world_access_body(rmpv::Value::Map(vec![
                (rmpv::Value::from("schema_version"), world_access_version()),
                (
                    rmpv::Value::from("worlds"),
                    world_access_world_array(&[first]),
                ),
            ])),
        ),
        (
            "non-string key",
            world_access_body(rmpv::Value::Map(vec![(
                rmpv::Value::from(1),
                world_access_version(),
            )])),
        ),
        (
            "unsupported schema version",
            world_access_body(world_access_value_map(
                rmpv::Value::from(WORLD_ACCESS_SCHEMA_VERSION + 1),
                rmpv::Value::Boolean(false),
                world_access_world_array(&[first]),
            )),
        ),
        (
            "non-integer schema version",
            world_access_body(world_access_value_map(
                rmpv::Value::from("1"),
                rmpv::Value::Boolean(false),
                world_access_world_array(&[first]),
            )),
        ),
        (
            "non-boolean include_base",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::from(1),
                world_access_world_array(&[first]),
            )),
        ),
        (
            "non-array worlds",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::Boolean(false),
                rmpv::Value::from("cl_first"),
            )),
        ),
        (
            "non-binary world id",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::Boolean(false),
                rmpv::Value::Array(vec![rmpv::Value::from("cl_first")]),
            )),
        ),
        (
            "wrong-width world id",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::Boolean(false),
                rmpv::Value::Array(vec![rmpv::Value::Binary(vec![0x31; 15])]),
            )),
        ),
        (
            "duplicate world id",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::Boolean(false),
                world_access_world_array(&[first, first]),
            )),
        ),
        (
            "unsorted world ids",
            world_access_body(world_access_value_map(
                world_access_version(),
                rmpv::Value::Boolean(false),
                world_access_world_array(&[second, first]),
            )),
        ),
        (
            "non-map value",
            world_access_body(rmpv::Value::from("worlds")),
        ),
    ] {
        assert_matches!(
            decode_world_access_claim_value(&malformed),
            Err(Error::InvalidConfig(_)),
            "{name} must fail closed"
        );
    }

    // The member cap is enforced where sets are built, never silently trimmed.
    let cap = u32::try_from(MAX_WORLD_ACCESS_MEMBERS).expect("cap fits u32");
    let oversized = (0..=cap)
        .map(|index| {
            let mut raw = [0x5A_u8; 16];
            raw[1] = u8::try_from(index >> 8).expect("high byte");
            raw[2] = u8::try_from(index & 0xFF).expect("low byte");
            EntityId::from_bytes(raw).expect("non-reserved world id")
        })
        .collect::<Vec<_>>();
    assert_eq!(oversized.len(), MAX_WORLD_ACCESS_MEMBERS + 1);
    assert_matches!(
        WorldAuthoritySet::new(false, oversized),
        Err(Error::InvalidConfig(_)),
        "a set above the member cap is refused, never trimmed"
    );

    // The body door mints the two pinned predicates and nothing else, and it
    // refuses a window that could never be in force.
    assert_matches!(
        world_access_claim_body(
            "core.world_access.something_else",
            agent,
            &set,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        ),
        Err(Error::InvalidConfig(_)),
        "an off-contract predicate is not a world-access row"
    );
    assert_matches!(
        world_access_claim_body(
            PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            agent,
            &set,
            ClaimSource::Inferred,
            ClaimApprovalStatus::Auto,
            Some(10),
            Some(10),
        ),
        Err(Error::InvalidConfig(_)),
        "an empty validity window is refused at the door"
    );
    Ok(())
}

/// An active malformed default must not hide behind a newer valid default.
/// Only closing it through ordinary CLAIM lifecycle removes the refusal.
#[test]
fn malformed_older_active_default_fails_closed_until_superseded() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let malformed_id = entity_id(0xB2);
    let replacement_id = entity_id(0xB1);
    let selected = WorldAuthoritySet::new(false, [fixture.world_w])?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    // The valid winner sorts BEFORE the malformed row in the adjacency scan.
    WorldAccessRowSpec::agent_default(replacement_id, fixture.agent, false, &[fixture.world_w])
        .valid(Some(2_000), None)
        .put(&vault)?;
    let mut malformed = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
        fixture.agent,
        &selected,
        ClaimSource::Inferred,
        ClaimApprovalStatus::Auto,
        Some(1_000),
        None,
    )?;
    malformed.value = rmpv::Value::from("not-a-world-access-map");
    malformed.evidence = Some(world_default_evidence(fixture.agent)?);
    vault.put_claim(&malformed_id, &malformed, TimeRange { start: 1, end: 1 }, 1)?;

    for explicit in [false, true] {
        let query = world_access_query(&vault, WORLD_ACCESS_NOW);
        let query = if explicit {
            query.active_worlds(fixture.agent, selected.clone())
        } else {
            query.default_active_worlds(fixture.agent)
        };
        assert_matches!(query.run(), Err(Error::InvalidConfig(_)));
    }
    {
        // A failed resolution supplies no authority to the post-fusion door.
        // That door must refuse rather than resolve again or admit everything.
        let rtxn = vault.store.env.read_txn()?;
        let mut scores = vec![ScoredEntity {
            id: fixture.claim_w,
            score: 1.0,
        }];
        assert_matches!(
            super::filters::apply_world_filter(
                &mut scores,
                &vault.store,
                &rtxn,
                WorldScope::ActiveSet,
                None,
            ),
            Err(Error::InvalidConfig(_))
        );
    }

    vault.supersede_claim(&replacement_id, &malformed_id, 4_000)?;
    assert_eq!(
        vault
            .get_claim(&malformed_id)?
            .expect("retained history")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .default_active_worlds(fixture.agent)
                .run()?
        ),
        HashSet::from([fixture.claim_w]),
        "a closed malformed row is ignored, not decoded or folded"
    );
    Ok(())
}

/// Value validation is strict only for in-force rows. Preserve the ordinary
/// CLAIM status gate and half-open Unix-second validity windows for both tiers.
#[test]
fn closed_malformed_world_access_values_are_ignored() -> Result<()> {
    for predicate in [
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
    ] {
        for (approval, lifecycle, stale, from, to) in [
            (
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
                false,
                None,
                Some(WORLD_ACCESS_NOW),
            ),
            (
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
                false,
                Some(WORLD_ACCESS_NOW + 1),
                None,
            ),
            (
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
                false,
                None,
                None,
            ),
            (
                ClaimApprovalStatus::Rejected,
                ClaimLifecycleStatus::Active,
                false,
                None,
                None,
            ),
            (
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Superseded,
                false,
                None,
                None,
            ),
            (
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Retracted,
                false,
                None,
                None,
            ),
            (
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
                true,
                None,
                None,
            ),
        ] {
            let (_dir, vault) = open_test_vault();
            let fixture = world_access_fixture(&vault)?;
            WorldAccessRowSpec::owner_grant(
                entity_id(0xB0),
                fixture.agent,
                false,
                &[fixture.world_w],
            )
            .put(&vault)?;
            WorldAccessRowSpec::agent_default(
                entity_id(0xB1),
                fixture.agent,
                false,
                &[fixture.world_w],
            )
            .put(&vault)?;
            let mut malformed = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(fixture.agent),
                rmpv::Value::from("not-a-world-access-map"),
                1.0,
                approval,
                lifecycle,
            );
            malformed.source = Some(ClaimSource::UserStated);
            malformed.evidence = Some(world_default_evidence(fixture.agent)?);
            malformed.stale = stale;
            malformed.valid_from = from;
            malformed.valid_to = to;
            vault.put_claim(
                &entity_id(0xB2),
                &malformed,
                TimeRange { start: 1, end: 1 },
                1,
            )?;
            assert_eq!(
                world_access_ids(
                    &world_access_query(&vault, WORLD_ACCESS_NOW)
                        .default_active_worlds(fixture.agent)
                        .run()?
                ),
                HashSet::from([fixture.claim_w]),
                "closed {predicate} row: {approval:?}/{lifecycle:?}, stale={stale}, from={from:?}, to={to:?}"
            );
        }
    }
    Ok(())
}

/// Decoding every active default does not change the winner's pinned order.
#[test]
fn default_subset_precedence_uses_valid_time_learned_time_then_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        false,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    let selection = ActiveWorldSelection {
        agent_ref: fixture.agent,
        selected: None,
    };
    for (id, valid_from, learned_at, world) in [
        (entity_id(0xB4), 1_000, 100, fixture.world_w),
        (entity_id(0xB3), 1_001, 50, fixture.world_v),
        (entity_id(0xB2), 1_001, 51, fixture.world_w),
        (entity_id(0xB5), 1_001, 51, fixture.world_v),
    ] {
        WorldAccessRowSpec::agent_default(id, fixture.agent, false, &[world])
            .valid(Some(valid_from), None)
            .learned_at(learned_at)
            .put(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        let resolved = super::world_authority::resolve_world_authority(
            &vault.store,
            &rtxn,
            &selection,
            WORLD_ACCESS_NOW,
        )?;
        assert_eq!(resolved.default_claim_id, Some(id));
        assert_eq!(
            resolved.default_subset,
            WorldAuthoritySet::new(false, [world])?
        );
        assert_eq!(resolved.active_set, resolved.default_subset);
    }
    Ok(())
}

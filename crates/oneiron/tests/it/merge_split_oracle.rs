// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Identity-topology forward test oracle (ARCH-0055, ONE-1742 epic) —
//! authored by the ONE-1743 path opener.
//!
//! Every test here is a CONTRACT from a downstream MS ticket's acceptance
//! criteria plus the ratified ARCH-0055 ruling it cites, and is parked
//! behind `#[ignore = "armed by ONE-XXXX"]`. Arming discipline (board
//! ruling): the arming ticket removes the ignore, swaps the `seam` stubs
//! below for the real engine APIs, and adapts signatures — it NEVER
//! weakens, widens, or deletes an assert. Counts stay counts.
//!
//! The `seam` module is the thinnest plausible surface each ticket must
//! provide; every stub is `unimplemented!` so an armed-but-unbuilt contract
//! fails RED instead of vacuously passing. MS-01 surfaces (merge/split
//! apply, lifecycle reads, ledger events) are exercised through the REAL
//! public API.
//!
//! # Recorded polarity flips
//!
//! A flip is the ONE edit arming discipline permits beyond removing an
//! ignore: a `[NEG]` contract that asserts a slot is RESERVED must invert
//! when the ticket that reserved it says so, or the reservation could never
//! be consumed. Each is pre-declared in the owning lane's CLAIMS §6 before
//! it happens, and inverts only the reservation assert — every other
//! assertion in the test carries over unweakened.
//!
//! * **ONE-1757 (ED-01) flips ONE-1747's `ms05_delta_field_is_reserved_…`**
//!   into `ms05_amendment_body_stays_opaque_while_ed01_fills_the_reserved_delta_slot`
//!   (MS/CLAIMS §6 edge #1). The six ARCH-0056 §2 Δ names are now projected;
//!   the inherited byte-exact `amended_body` round-trip is asserted intact.

use oneiron::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, EntityId, HnswConfig, Vault, VaultConfig,
    consent_graduation::RampScope, identity_topology::FacetOp, identity_topology::FacetSpec,
    identity_topology::IdentityOpEvidence, identity_topology::IdentityOpOutcome,
    identity_topology::IdentityOpWrite, identity_topology::IdentityTopologyOp,
    identity_topology::MergeOp, identity_topology::ProposalOutcome,
    identity_topology::ProposalRuling, identity_topology::ReassignmentMap,
    identity_topology::SplitOp, identity_topology::StoredIdentityOpAction,
    identity_topology::SurvivorshipPlan, receipt::ReceiptKind, receipt::ReceiptQuery,
};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test/model@v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    (dir, vault)
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).expect("fixture id");
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"oracle person fixture",
        )
        .expect("put person");
    id
}

/// Applies a REAL MS-01 merge (auto by default, r3) and returns its ledger
/// event id.
fn real_merge(vault: &Vault, sources: Vec<EntityId>, survivor: EntityId, now: u64) -> EntityId {
    let outcome = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources,
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "oracle fixture merge".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            now,
        )
        .expect("apply merge");
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("auto merge must apply, got {outcome:?}");
    };
    event
}

/// Applies a REAL MS-01 split (≥1 head) and returns its ledger event id.
fn real_split(vault: &Vault, entity: EntityId, heads: Vec<EntityId>, now: u64) -> EntityId {
    let outcome = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Split(SplitOp {
                entity,
                heads,
                reassignment: ReassignmentMap::default(),
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "oracle fixture split".to_owned(),
                },
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            now,
        )
        .expect("apply split");
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("auto split must apply, got {outcome:?}");
    };
    event
}

// `ProposalRuling` / `ProposalOutcome` were local stand-ins here until
// ONE-1747 built them; they are now the REAL `oneiron::` types, imported
// above. The vocabularies are identical (r7: exactly three outcome states),
// so every assert below binds unchanged — the stand-ins are simply gone.

/// Fixture clocks: a proposal is parked, then ruled strictly later.
const PROPOSAL_AT: u64 = 200;
const RULING_AT: u64 = 300;

/// The merge op the ONE-1747 fixtures propose: `sources` folded into
/// `survivor`.
fn merge_op(sources: Vec<EntityId>, survivor: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Merge(MergeOp {
        sources,
        survivor,
        evidence: IdentityOpEvidence {
            refs: Vec::new(),
            rationale: "oracle fixture merge proposal".to_owned(),
        },
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    })
}

/// An amended merge body for a proposal parked by
/// [`seam::submit_merge_proposal`], as raw op bytes.
///
/// FIXTURE ADAPTATION (arming, not weakening): the parked contracts were
/// authored against placeholder byte strings, before ONE-1747 ruled that an
/// amendment may only NARROW what the decider reviewed — same op kind, and a
/// subject subset of the proposal's. Arbitrary bytes are precisely what that
/// pin must reject, so the fixtures become REAL encoded amended bodies. The
/// asserts are untouched: the payload still round-trips byte-exact (which is
/// what "opaque slot, not a shaped struct" means — the engine stores the
/// decider's bytes verbatim and never reshapes them) and the reserved-Δ
/// negative is unchanged.
fn amendment_body(sources: Vec<EntityId>, survivor: EntityId) -> Vec<u8> {
    oneiron::identity_topology::encode_identity_op_amendment(&merge_op(sources, survivor))
        .expect("encode amendment")
}

/// A split's reassignment map from `(claim, head)` pairs — `None` is the
/// explicit residue row (r2), not an absent one.
fn reassignment_map(assignments: &[(EntityId, Option<EntityId>)]) -> ReassignmentMap {
    ReassignmentMap {
        entries: assignments
            .iter()
            .map(
                |(claim, head)| oneiron::identity_topology::ReassignmentEntry {
                    item: ClaimSubject::Entity(*claim),
                    target: head.map_or(
                        oneiron::identity_topology::ReassignmentTarget::Residue,
                        oneiron::identity_topology::ReassignmentTarget::Head,
                    ),
                },
            )
            .collect(),
    }
}

/// A facet op's scoping map from `(claim, facet index)` pairs.
fn facet_reassignment_map(assignments: &[(EntityId, u32)]) -> ReassignmentMap {
    ReassignmentMap {
        entries: assignments
            .iter()
            .map(
                |(claim, index)| oneiron::identity_topology::ReassignmentEntry {
                    item: ClaimSubject::Entity(*claim),
                    target: oneiron::identity_topology::ReassignmentTarget::Facet { index: *index },
                },
            )
            .collect(),
    }
}

/// The propose lane's write: `Proposed` parks with zero topology effects.
fn proposed_write() -> IdentityOpWrite {
    IdentityOpWrite {
        approval: ClaimApprovalStatus::Proposed,
        ..IdentityOpWrite::auto(ClaimSource::Inferred)
    }
}

/// The decider's write: a ruling is the act of deciding, so it is effective.
fn ruling_write() -> IdentityOpWrite {
    IdentityOpWrite::auto(ClaimSource::UserStated)
}

/// The single proposal-outcome receipt projected for a resolution event.
///
/// Read back through the PUBLIC `ReceiptQuery` surface (not a direct ledger
/// peek), so the oracle also witnesses the blueprint's "queryable by kind"
/// contract on every payload assert.
fn outcome_receipt(vault: &Vault, receipt: EntityId) -> oneiron::receipt::ReceiptRecord {
    let receipt_id = format!("proposal_outcome:{}", receipt.to_hex());
    let mut query = ReceiptQuery::default();
    query.kinds.insert(ReceiptKind::ProposalOutcome);
    let mut matched: Vec<oneiron::receipt::ReceiptRecord> = vault
        .receipts(query)
        .expect("query proposal-outcome receipts")
        .into_iter()
        .filter(|record| record.receipt_id == receipt_id)
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "a resolution must project exactly one outcome receipt"
    );
    matched.remove(0)
}

/// Thinnest plausible seams for the downstream MS tickets. Each stub names
/// the ticket that must replace it with the real engine API.
#[allow(dead_code)]
mod seam {
    use super::{
        ClaimApprovalStatus, ClaimSource, ClaimSubject, EntityId, IdentityOpOutcome,
        IdentityOpWrite, IdentityTopologyOp, ProposalOutcome, ProposalRuling, RampScope,
        ReceiptKind, ReceiptQuery, Vault,
    };

    // ---- ONE-1744 (MS-02): redirect projection + read-time resolution ----
    // ARMED: every stub below is the real engine API.

    /// Resolves an entity id through the redirect projection to its current
    /// head set (r6 read-time canonicalization; Senzing 0/1/N semantics).
    pub(crate) fn resolve_entity(vault: &Vault, id: &EntityId) -> Vec<EntityId> {
        vault.resolve_entity(id).expect("resolve entity")
    }

    /// Splits an entity into ZERO heads (r2 "gone" semantics) — MS-01
    /// rejected the zero-head form (`EmptyHeads`) because only the redirect
    /// projection can express an empty resolution set; ONE-1744 lifted it,
    /// so this is now an ordinary applied split.
    pub(crate) fn split_into_zero_heads(vault: &Vault, entity: &EntityId) {
        super::real_split(vault, *entity, Vec::new(), 200);
    }

    /// Drops the materialized redirect projection (cache, never truth).
    pub(crate) fn drop_redirect_projection(vault: &Vault) {
        vault
            .drop_redirect_projection()
            .expect("drop redirect projection");
    }

    /// Rebuilds the redirect projection from engine-authored truth: the
    /// `merged_into` / `split_into` edges for every edge-ful op, plus the
    /// type-76 ledger for the zero-head arm no edge can witness
    /// (CID-7 / ARCH-0035 rebuildability).
    pub(crate) fn rebuild_redirect_projection_from_edges(vault: &Vault) {
        vault
            .rebuild_redirect_projection_from_edges()
            .expect("rebuild redirect projection");
    }

    /// Writes a claim whose subject is `subject`; returns the claim id.
    ///
    /// The predicate sits under `profile.`, the one prefix the DEFAULT policy
    /// manifest rates `criticality: normal` — every unmatched predicate
    /// defaults to `critical`, which the Gate queues for consent
    /// (`gate.pending.criticality_floor`) instead of committing. This fixture
    /// needs a plain COMMITTED claim to witness that its subject is never
    /// rewritten, so it writes on the auto-commit lane. The subject, not the
    /// predicate, is what these contracts assert.
    pub(crate) fn write_note_claim_about(vault: &Vault, subject: &EntityId) -> EntityId {
        let note = EntityId::now();
        vault
            .put_claim(
                &note,
                &oneiron::ClaimBody::new(
                    "profile.note",
                    ClaimSubject::Entity(*subject),
                    rmpv::Value::from("oracle note claim"),
                    0.9,
                    ClaimApprovalStatus::Auto,
                    oneiron::ClaimLifecycleStatus::Active,
                ),
                oneiron::temporal::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
            )
            .expect("write note claim");
        note
    }

    // ---- ONE-1745 (MS-03): reassignment application + FACET minting ----
    // ARMED: every stub below is the real engine API.

    /// Applies a split whose reassignment map assigns each listed claim to
    /// a head (`None` = explicit residue), and APPLIES the map (r2).
    pub(crate) fn apply_split_with_map(
        vault: &Vault,
        entity: &EntityId,
        heads: &[EntityId],
        assignments: &[(EntityId, Option<EntityId>)],
    ) {
        let outcome = vault
            .apply_identity_topology_op(
                &super::IdentityTopologyOp::Split(super::SplitOp {
                    entity: *entity,
                    heads: heads.to_vec(),
                    reassignment: super::reassignment_map(assignments),
                    evidence: super::IdentityOpEvidence {
                        refs: Vec::new(),
                        rationale: "oracle fixture split with map".to_owned(),
                    },
                }),
                &super::IdentityOpWrite::auto(super::ClaimSource::Inferred),
                200,
            )
            .expect("apply split with map");
        assert!(
            matches!(outcome, IdentityOpOutcome::Applied { .. }),
            "auto split must apply, got {outcome:?}"
        );
    }

    /// Claims that read through `head` after a split (assigned + residue
    /// read-through per r2).
    pub(crate) fn count_claims_assigned_to_head(vault: &Vault, head: &EntityId) -> usize {
        claim_ids_assigned_to_head(vault, head).len()
    }

    /// The EXACT claim-id set assigned to `head` (identity, not just count).
    pub(crate) fn claim_ids_assigned_to_head(vault: &Vault, head: &EntityId) -> Vec<EntityId> {
        vault.claims_assigned_to(head).expect("claims assigned")
    }

    /// Claims still stored on the split original.
    ///
    /// The engine surface is `claims_remaining_on_origin`, not
    /// `claims_for_subject`: r6 keeps every stored SUBJECT pointing at the
    /// original forever, so subject-bound membership is the provenance
    /// reading and stays 3 here. What the split moved is the ASSIGNMENT, and
    /// this is the query that reports it.
    pub(crate) fn count_claims_on_original(vault: &Vault, entity: &EntityId) -> usize {
        vault
            .claims_remaining_on_origin(entity)
            .expect("claims remaining on origin")
            .len()
    }

    /// Claims on the original explicitly marked ambiguous residue (r2:
    /// never force-assigned).
    pub(crate) fn count_ambiguous_residue_claims(vault: &Vault, entity: &EntityId) -> usize {
        vault
            .ambiguous_residue_claims(entity)
            .expect("ambiguous residue claims")
            .len()
    }

    /// Applies a facet op: mints one FACET entity per label and backfills
    /// `facet_of` scoping per `assignments` (claim id → facet index).
    /// Returns the minted FACET entity ids, in label order.
    pub(crate) fn apply_facet(
        vault: &Vault,
        entity: &EntityId,
        labels: &[&str],
        assignments: &[(EntityId, u32)],
    ) -> Vec<EntityId> {
        let outcome = vault
            .apply_identity_topology_op(
                &super::IdentityTopologyOp::Facet(super::FacetOp {
                    entity: *entity,
                    facets: labels
                        .iter()
                        .map(|label| super::FacetSpec {
                            label: (*label).to_owned(),
                        })
                        .collect(),
                    reassignment: super::facet_reassignment_map(assignments),
                    evidence: super::IdentityOpEvidence {
                        refs: Vec::new(),
                        rationale: "oracle fixture facet".to_owned(),
                    },
                }),
                &super::IdentityOpWrite::auto(super::ClaimSource::Inferred),
                200,
            )
            .expect("apply facet");
        let IdentityOpOutcome::Applied { event, .. } = outcome else {
            panic!("auto facet must apply, got {outcome:?}");
        };
        // Minted ids in LABEL ORDER come off the ledger event, which stores
        // them in the op's spec order — the same order the map's facet
        // indices address.
        let record = vault
            .identity_topology_event(&event)
            .expect("read facet event")
            .expect("facet event exists");
        let super::StoredIdentityOpAction::Facet { facets, .. } = record.action else {
            panic!("facet op must record a facet action");
        };
        facets
    }

    /// FACET (type-13) entities attached to `entity`.
    pub(crate) fn count_facet_entities_of(vault: &Vault, entity: &EntityId) -> usize {
        vault.facets_of(entity).expect("facets of").len()
    }

    /// Behavioral claims scoped to `facet` via `facet_of`.
    pub(crate) fn count_facet_of_scoped_claims(vault: &Vault, facet: &EntityId) -> usize {
        claim_ids_scoped_to_facet(vault, facet).len()
    }

    /// The EXACT claim-id set scoped to `facet` (membership, not count).
    ///
    /// Same engine surface as the head query — `claims_assigned_to` reads a
    /// facet target through its canonical `facet_of` stamps.
    pub(crate) fn claim_ids_scoped_to_facet(vault: &Vault, facet: &EntityId) -> Vec<EntityId> {
        vault.claims_assigned_to(facet).expect("claims scoped")
    }

    /// Total entities of one registry type byte (base-id conservation
    /// probe: facet ops mint no non-FACET ids, r6).
    pub(crate) fn count_entities_of_type(vault: &Vault, type_byte: u8) -> usize {
        vault
            .entities_by_type(type_byte)
            .expect("entities by type")
            .len()
    }

    // ---- ONE-1746 (MS-04): entity.distinct_from + re-proposal suppression ----
    // ARMED: the REAL op door mints the claim, and the REAL vault reads count
    // it — no stand-ins left.

    /// Asserts the anti-merge claim for (a, b) (§9 G.1 row).
    pub(crate) fn assert_distinct(vault: &Vault, a: &EntityId, b: &EntityId) {
        let outcome = vault
            .apply_identity_topology_op(
                &IdentityTopologyOp::AssertDistinct(oneiron::identity_topology::AssertDistinctOp {
                    a: *a,
                    b: *b,
                    reason: "oracle fixture assertion".to_owned(),
                }),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                super::PROPOSAL_AT,
            )
            .expect("assert distinct");
        // r6/§6: an assertion moves no lifecycle state — its whole effect is
        // the claim.
        let IdentityOpOutcome::Applied { transitions, .. } = outcome else {
            panic!("auto assert_distinct must apply, got {outcome:?}");
        };
        assert!(transitions.is_empty());
    }

    /// ACTIVE `entity.distinct_from` claims keyed by the normalized
    /// symmetric pair.
    pub(crate) fn count_active_distinct_claims(vault: &Vault, a: &EntityId, b: &EntityId) -> usize {
        vault
            .distinct_claims_for_pair(a, b)
            .expect("distinct claims for pair")
            .len()
    }

    /// Surfaces a merge proposal for (a, b) from any producer.
    pub(crate) fn propose_merge(vault: &Vault, a: &EntityId, b: &EntityId) {
        // §6 intake has exactly two legitimate outcomes: the pair parks, or
        // an effective distinct claim suppresses it with the typed rejection.
        // Anything else is a real failure, so only that one rejection is
        // swallowed here.
        match vault.apply_identity_topology_op(
            &super::merge_op(vec![*b], *a),
            &super::proposed_write(),
            super::PROPOSAL_AT,
        ) {
            Ok(IdentityOpOutcome::Parked { .. }) => {}
            Err(oneiron::Error::IdentityTopologyRejected(
                oneiron::identity_topology::IdentityTopologyRejection::DistinctPairSuppressed {
                    ..
                },
            )) => {}
            other => panic!("merge proposal intake must park or be suppressed, got {other:?}"),
        }
    }

    /// Open (non-suppressed) merge proposals for the pair.
    pub(crate) fn count_open_merge_proposals(vault: &Vault, a: &EntityId, b: &EntityId) -> usize {
        vault
            .open_merge_proposals_for_pair(a, b)
            .expect("open merge proposals")
            .len()
    }

    // ---- ONE-1747 (MS-05): proposal-outcome receipts + reserved delta ----
    // ARMED: handles are real `EntityId`s (the parked event id and the
    // resolution event id), not the u64 placeholders.

    /// Parks an identity-topology merge proposal for the pair; returns the
    /// parked event id.
    pub(crate) fn submit_merge_proposal(vault: &Vault, a: &EntityId, b: &EntityId) -> EntityId {
        let outcome = vault
            .apply_identity_topology_op(
                &super::merge_op(vec![*b], *a),
                &super::proposed_write(),
                super::PROPOSAL_AT,
            )
            .expect("park proposal");
        let IdentityOpOutcome::Parked { event, .. } = outcome else {
            panic!("a Proposed merge must park, got {outcome:?}");
        };
        event
    }

    /// Applies a ruling to a parked proposal; returns the outcome state and
    /// the resolution event id, which is also the receipt handle.
    pub(crate) fn resolve_proposal(
        vault: &Vault,
        proposal: EntityId,
        ruling: ProposalRuling<'_>,
    ) -> (ProposalOutcome, EntityId) {
        vault
            .resolve_identity_proposal(&proposal, ruling, &super::ruling_write(), super::RULING_AT)
            .expect("resolve proposal")
    }

    /// The receipt's amendment payload, verbatim (r7: opaque bytes, byte-
    /// exact round-trip).
    pub(crate) fn receipt_delta_payload(vault: &Vault, receipt: EntityId) -> Option<Vec<u8>> {
        oneiron::receipt::proposal_outcome_amended_body(&super::outcome_receipt(vault, receipt))
    }

    /// Field names the receipt projects.
    pub(crate) fn receipt_field_names(vault: &Vault, receipt: EntityId) -> Vec<String> {
        super::outcome_receipt(vault, receipt)
            .fields
            .keys()
            .cloned()
            .collect()
    }

    // ---- ONE-1757 (ED-01): the built ARCH-0056 Δ in the reserved slot ----
    // ARMED: every stub below is the real engine API.

    /// Parks a merge proposal folding `sources` into `survivor` — the
    /// multi-source shape an amendment can NARROW.
    pub(crate) fn submit_merge_proposal_of(
        vault: &Vault,
        sources: Vec<EntityId>,
        survivor: EntityId,
    ) -> EntityId {
        let outcome = vault
            .apply_identity_topology_op(
                &super::merge_op(sources, survivor),
                &super::proposed_write(),
                super::PROPOSAL_AT,
            )
            .expect("park proposal");
        let IdentityOpOutcome::Parked { event, .. } = outcome else {
            panic!("a Proposed merge must park, got {outcome:?}");
        };
        event
    }

    /// Runs ED-01's receipt-projection pass, returning how many Δs it wrote.
    pub(crate) fn project_amendment_deltas(vault: &Vault) -> usize {
        oneiron::edit_distance::delta::project_identity_amendment_deltas(vault)
            .expect("project amendment deltas")
    }

    /// The RESERVED ARCH-0056 Δ slot — distinct from the producer artifact
    /// [`receipt_delta_payload`] reads.
    pub(crate) fn receipt_amendment_delta(vault: &Vault, receipt: EntityId) -> Option<Vec<u8>> {
        oneiron::receipt::proposal_outcome_delta(&super::outcome_receipt(vault, receipt))
    }

    // ---- ONE-1748 (MS-06): consent-graduation ramp ----
    // ARMED: the handle is the real `RampScope` tuple, not the u64
    // placeholder, and every stub below is the real engine door.

    /// Resolves the ramp scope handle for the exact tuple
    /// (op kind × target class × skill/agent) — a DEC-0006 bound.
    pub(crate) fn ramp_scope(
        vault: &Vault,
        op_kind: &str,
        target_class: &str,
        agent: &str,
    ) -> RampScope {
        vault
            .ramp_scope(op_kind, target_class, agent)
            .expect("resolve ramp scope")
    }

    /// Records one outcome receipt on a propose-lane scope.
    pub(crate) fn record_outcome_receipt(
        vault: &Vault,
        scope: &RampScope,
        outcome: ProposalOutcome,
    ) {
        vault
            .record_proposal_outcome_for_ramp(scope, outcome)
            .expect("record ramp outcome");
    }

    /// Standing graduation OFFERS currently surfaced (proposed
    /// `create_standing_grant(bound)` rows — DEC-0006 invariant 5).
    pub(crate) fn count_graduation_offers(vault: &Vault) -> usize {
        vault.graduation_offers().expect("graduation offers").len()
    }

    /// Standing grants actually in force.
    ///
    /// ARMED by ONE-1606: this reads the REAL DEC-0006 consent registry, so a
    /// count of 0 means no grant row exists and a count of 1 means exactly one
    /// bound is live and revocable from surface (b).
    pub(crate) fn count_standing_grants(vault: &Vault) -> usize {
        vault
            .active_standing_consent_grants()
            .expect("read the consent registry")
            .len()
    }

    /// The owner taps the surfaced graduation offer.
    ///
    /// ARMED with the [`AuthenticatedOwner`] the engine door demands: a tap is
    /// an owner act, and the type system is where DEC-0006 invariant 5 is
    /// enforced — a seam that could accept without one would document a door
    /// the engine deliberately does not have.
    pub(crate) fn accept_graduation_offer(
        vault: &Vault,
        owner: &oneiron::consent::AuthenticatedOwner,
        scope: &RampScope,
    ) {
        vault
            .accept_graduation_offer(owner, scope)
            .expect("accept graduation offer");
    }

    /// The agent self-demotes an auto scope back to propose (r7: its own
    /// judgment, said out loud, receipted).
    pub(crate) fn demote_scope_to_propose(vault: &Vault, scope: &RampScope) {
        vault
            .demote_scope_to_propose(
                scope,
                oneiron::consent_graduation::DemotionReason::AgentJudgment,
            )
            .expect("self-demote scope");
    }

    /// Receipts recorded for self-demotions (never silent).
    ///
    /// Read back through the PUBLIC [`ReceiptQuery`] surface, so the count also
    /// witnesses that the demotion projector is REGISTERED in the `Gate`
    /// receipt family rather than reachable only through a private door.
    pub(crate) fn count_demotion_receipts(vault: &Vault) -> usize {
        vault
            .receipts(ReceiptQuery::default().with_kind(ReceiptKind::Gate))
            .expect("query gate receipts")
            .iter()
            .filter(|record| oneiron::consent_graduation::is_ramp_demotion_receipt(record))
            .count()
    }

    /// The scope's current consent posture (pinned wire strings, e.g.
    /// "auto" / "proposed").
    pub(crate) fn scope_state(vault: &Vault, scope: &RampScope) -> String {
        vault
            .ramp_scope_state(scope)
            .expect("ramp scope state")
            .as_str()
            .to_owned()
    }

    /// Whether an op kind's scopes sit on the propose→auto ramp at all.
    pub(crate) fn scope_is_on_ramp(_vault: &Vault, op_kind: &str) -> bool {
        oneiron::consent_graduation::op_kind_is_ramp_eligible(op_kind)
    }

    /// Pending ramp proposal rows for an op kind.
    pub(crate) fn count_ramp_proposals_for(vault: &Vault, op_kind: &str) -> usize {
        vault
            .graduation_offers()
            .expect("graduation offers")
            .iter()
            .filter(|scope| scope.op_kind == op_kind)
            .count()
    }

    // ---- ONE-1749 (MS-07): redirect-aware HardErase ----
    // ARMED: every stub below is the real engine API.

    /// HardErases an entity through the ARCH-0038 path — the destructive
    /// `user_hard_delete` contract, which is the door r6 §9 rules on.
    pub(crate) fn hard_erase_entity(vault: &Vault, id: &EntityId) {
        assert!(
            vault.delete_entity(id).expect("hard erase entity"),
            "the fixture entity must exist to be erased"
        );
    }

    /// Readable payload bytes still reachable for `id` after erasure
    /// (body, indexes, projections — anything that would leak content).
    ///
    /// `Vault::get` is the public content read, and it answers for all three
    /// at once: a purged id has no row, a SoftErased one has only its 25 B
    /// header, and either way there is nothing left to read.
    pub(crate) fn readable_payload_bytes(vault: &Vault, id: &EntityId) -> usize {
        vault
            .get(id)
            .expect("read entity")
            .map_or(0, |body| body.len())
    }

    /// The ARCH-0038 carrier-class enumeration.
    ///
    /// SIGNATURE ADAPTATION (arming, not weakening): the enumeration is a
    /// static read of the contract, not of a vault, so the engine fn takes no
    /// argument and the stub's already-unused parameter absorbs the
    /// difference. The membership assert is untouched.
    pub(crate) fn arch0038_carrier_classes(_vault: &Vault) -> Vec<String> {
        oneiron::deletion::arch0038_carrier_classes()
    }

    /// The carrier-class name the redirect table registers under.
    pub(crate) fn redirect_carrier_class() -> String {
        oneiron::identity_redirect::REDIRECT_CARRIER_CLASS.to_owned()
    }

    /// Dangling redirect payloads after erase + projection rebuild.
    pub(crate) fn count_dangling_redirect_payloads(vault: &Vault) -> usize {
        vault
            .count_dangling_redirect_payloads()
            .expect("dangling redirect payload census")
    }
}

// ===== ONE-1744 (MS-02) — redirect projection + read-time resolution =====

/// r2/§4: a split into ZERO heads makes the original resolve to the EMPTY
/// set — the id is "gone" but the ledger event and shell remain.
#[test]
fn ms02_redirect_zero_heads_resolves_to_empty_set() {
    let (_dir, vault) = open_vault();
    let entity = put_person(&vault, 0x21);
    seam::split_into_zero_heads(&vault, &entity);
    assert_eq!(seam::resolve_entity(&vault, &entity).len(), 0);
}

/// r1/§3: after merge(B → A), B resolves to exactly ONE canonical head.
#[test]
fn ms02_redirect_one_head_resolves_to_single_survivor() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    real_merge(&vault, vec![loser], survivor, 200);
    assert_eq!(seam::resolve_entity(&vault, &loser), vec![survivor]);
}

/// r2/§4: a split into N heads resolves the original to the EXACT set of
/// N heads (residue claims read through all heads).
#[test]
fn ms02_redirect_n_heads_resolves_to_exact_head_set() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x21);
    let head_a = put_person(&vault, 0x22);
    let head_b = put_person(&vault, 0x23);
    real_split(&vault, original, vec![head_a, head_b], 200);
    let mut resolved = seam::resolve_entity(&vault, &original);
    resolved.sort();
    let mut expected = vec![head_a, head_b];
    expected.sort();
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved, expected);
}

/// r1/§3 + CID-7/ARCH-0035: the redirect table is a rebuildable projection
/// — dropping it and rebuilding from ENGINE-AUTHORED TRUTH ALONE yields
/// identical resolution. The projection is never authoritative.
///
/// DOC RE-SCOPED BY ONE-1744 (arming, not weakening — every assert below is
/// kept and the op sequence is STRENGTHENED): the contract was authored as
/// "from the `merged_into`/`split_into` edges ALONE / edges are the sole
/// truth". That holds for every edge-ful op, but this ticket lifts the
/// zero-head split, which shells its entity while writing NO edge — so no
/// edge set can distinguish a retired id from a live one. The rebuild input
/// is therefore edges PLUS the type-76 identity-topology event ledger, both
/// append-only engine-authored truth. D11's "edges are canonical" is
/// unchanged; the TABLE remains the only droppable projection, so CID-7 is
/// intact.
///
/// Per that lift the fixture now carries a zero-head split alongside the
/// merge, because it is exactly the arm a from-edges-only rebuild would get
/// wrong, and a rebuild-identity test that omits it cannot see the
/// difference.
#[test]
fn ms02_redirect_table_rebuilds_identically_from_edges_alone() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    let retired = put_person(&vault, 0x24);
    real_merge(&vault, vec![loser], survivor, 200);
    seam::split_into_zero_heads(&vault, &retired);

    let before = seam::resolve_entity(&vault, &loser);
    let before_retired = seam::resolve_entity(&vault, &retired);
    seam::drop_redirect_projection(&vault);
    seam::rebuild_redirect_projection_from_edges(&vault);
    let after = seam::resolve_entity(&vault, &loser);
    assert_eq!(before, after);
    assert_eq!(after, vec![survivor]);
    // The zero-head arm survives the round trip identically: still the empty
    // set, not the live-entity identity a from-edges-only rebuild would give.
    assert_eq!(seam::resolve_entity(&vault, &retired), before_retired);
    assert_eq!(seam::resolve_entity(&vault, &retired).len(), 0);
}

/// [NEG] r6/§9: claim subjects keep original entity ids FOREVER. After
/// merge(B → A) the stored subject is still B — provenance truth; the
/// redirect resolves B → A only at read time. An eager reference-rewrite
/// implementation (the Wikidata unmerge killer) must fail here.
#[test]
fn ms02_refs_never_rewritten_after_merge() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    let note = seam::write_note_claim_about(&vault, &loser);
    real_merge(&vault, vec![loser], survivor, 200);

    let stored = vault
        .get_claim(&note)
        .expect("read note")
        .expect("note exists");
    assert_eq!(stored.subject, ClaimSubject::Entity(loser));
    assert_eq!(seam::resolve_entity(&vault, &loser), vec![survivor]);
}

// ===== ONE-1745 (MS-03) — reassignment map + FACET minting =====

/// r2/§4: the reassignment map assigns each claim of the split entity to a
/// specific head — exact per-head counts, nothing lost, nothing doubled.
#[test]
fn ms03_reassignment_assigns_each_claim_to_a_head() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x21);
    let head_a = put_person(&vault, 0x22);
    let head_b = put_person(&vault, 0x23);
    let claim_1 = seam::write_note_claim_about(&vault, &original);
    let claim_2 = seam::write_note_claim_about(&vault, &original);
    let claim_3 = seam::write_note_claim_about(&vault, &original);

    seam::apply_split_with_map(
        &vault,
        &original,
        &[head_a, head_b],
        &[
            (claim_1, Some(head_a)),
            (claim_2, Some(head_a)),
            (claim_3, Some(head_b)),
        ],
    );
    assert_eq!(seam::count_claims_assigned_to_head(&vault, &head_a), 2);
    assert_eq!(seam::count_claims_assigned_to_head(&vault, &head_b), 1);

    // Fully assigned map: ZERO claims remain on the split original.
    assert_eq!(seam::count_claims_on_original(&vault, &original), 0);

    // Identity, not just cardinality: each head carries EXACTLY the claim
    // ids the map assigned, and the head sets are disjoint.
    let mut on_a = seam::claim_ids_assigned_to_head(&vault, &head_a);
    on_a.sort();
    let mut expected_a = vec![claim_1, claim_2];
    expected_a.sort();
    assert_eq!(on_a, expected_a);
    assert_eq!(
        seam::claim_ids_assigned_to_head(&vault, &head_b),
        vec![claim_3]
    );
}

/// [NEG] r2/§4: unattributable residue is NEVER force-assigned — it stays
/// on the original entity marked ambiguous. A force-assign-everything
/// implementation must fail here.
#[test]
fn ms03_reassignment_residue_stays_ambiguous_on_original() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x21);
    let head_a = put_person(&vault, 0x22);
    let head_b = put_person(&vault, 0x23);
    let assigned = seam::write_note_claim_about(&vault, &original);
    let residue = seam::write_note_claim_about(&vault, &original);

    seam::apply_split_with_map(
        &vault,
        &original,
        &[head_a, head_b],
        &[(assigned, Some(head_a)), (residue, None)],
    );
    assert_eq!(seam::count_claims_assigned_to_head(&vault, &head_a), 1);
    assert_eq!(seam::count_claims_assigned_to_head(&vault, &head_b), 0);
    assert_eq!(seam::count_claims_on_original(&vault, &original), 1);
    assert_eq!(seam::count_ambiguous_residue_claims(&vault, &original), 1);
}

/// r5/§5: facet(entity, facets[]) mints exactly N ARCH-0022 FACET
/// (type-13) entities.
#[test]
fn ms03_facet_mints_exactly_n_type13_entities() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0x21);
    let minted = seam::apply_facet(&vault, &person, &["reg-a", "reg-b"], &[]);
    assert_eq!(minted.len(), 2);
    assert_ne!(minted[0], minted[1]);
    assert_eq!(seam::count_facet_entities_of(&vault, &person), 2);
}

/// r5/r6: the facet op backfills `facet_of` scoping on the named
/// behavioral claims and mints NO new base entity ids — facet ops touch no
/// entity ids beyond the FACET entities themselves.
#[test]
fn ms03_facet_backfills_scoping_and_mints_no_base_ids() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0x21);
    let people_before = seam::count_entities_of_type(&vault, oneiron::registry::ENTITY_TYPE_PERSON);
    let claim_1 = seam::write_note_claim_about(&vault, &person);
    let claim_2 = seam::write_note_claim_about(&vault, &person);

    let minted = seam::apply_facet(
        &vault,
        &person,
        &["reg-a", "reg-b"],
        &[(claim_1, 0), (claim_2, 1)],
    );
    assert_eq!(minted.len(), 2);
    assert_eq!(seam::count_facet_of_scoped_claims(&vault, &minted[0]), 1);
    assert_eq!(seam::count_facet_of_scoped_claims(&vault, &minted[1]), 1);
    assert_eq!(
        seam::count_entities_of_type(&vault, oneiron::registry::ENTITY_TYPE_PERSON),
        people_before
    );
}

/// [NEG] r5/§5 + ARCH-0022 no-merge canon: a facet op never blends
/// behavioral profiles across masks — a claim scoped to one facet is not
/// readable as the other facet's profile.
#[test]
fn ms03_facet_never_blends_profiles_across_masks() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0x21);
    let claim_a = seam::write_note_claim_about(&vault, &person);
    let claim_b = seam::write_note_claim_about(&vault, &person);

    let minted = seam::apply_facet(
        &vault,
        &person,
        &["reg-a", "reg-b"],
        &[(claim_a, 0), (claim_b, 1)],
    );
    // Exactly one claim per mask; a blending implementation reads 2.
    assert_eq!(seam::count_facet_of_scoped_claims(&vault, &minted[0]), 1);
    assert_eq!(seam::count_facet_of_scoped_claims(&vault, &minted[1]), 1);

    // Exact per-facet MEMBERSHIP, not just counts: each mask carries the
    // one claim the map scoped to it, and never the other's.
    assert_eq!(
        seam::claim_ids_scoped_to_facet(&vault, &minted[0]),
        vec![claim_a]
    );
    assert_eq!(
        seam::claim_ids_scoped_to_facet(&vault, &minted[1]),
        vec![claim_b]
    );
}

// ===== ONE-1746 (MS-04) — entity.distinct_from =====

/// §9 G.1 row: the pair key is the normalized symmetric order
/// `(min(a,b), max(a,b))` — asserting both directions yields exactly ONE
/// claim.
#[test]
fn ms04_assert_distinct_is_symmetric_single_claim() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    seam::assert_distinct(&vault, &a, &b);
    seam::assert_distinct(&vault, &b, &a);
    assert_eq!(seam::count_active_distinct_claims(&vault, &a, &b), 1);
    assert_eq!(seam::count_active_distinct_claims(&vault, &b, &a), 1);
}

/// §6: after assert_distinct(a, b), a merge proposal for (a, b) is
/// suppressed — rejections route, they don't dead-end into re-asks
/// (Wikidata P1889 semantics).
#[test]
fn ms04_distinct_from_suppresses_merge_reproposal() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    seam::assert_distinct(&vault, &a, &b);
    seam::propose_merge(&vault, &a, &b);
    assert_eq!(seam::count_open_merge_proposals(&vault, &a, &b), 0);
}

/// [NEG] §6: distinct_from(a, b) suppresses ONLY the asserted pair — a
/// proposal for (a, c) still surfaces. A suppress-everything-touching-a
/// implementation must fail here.
#[test]
fn ms04_distinct_from_does_not_suppress_unrelated_pairs() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);
    seam::assert_distinct(&vault, &a, &b);
    seam::propose_merge(&vault, &a, &c);
    assert_eq!(seam::count_open_merge_proposals(&vault, &a, &c), 1);
}

// ===== ONE-1747 (MS-05) — proposal-outcome receipts + reserved delta =====

/// r7/§7: a resolved proposal yields exactly one of approved-untouched /
/// approved-amended / rejected.
#[test]
fn ms05_proposal_outcome_has_exactly_three_states() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);
    let d = put_person(&vault, 0x24);

    let untouched = seam::submit_merge_proposal(&vault, &a, &b);
    let (outcome, _) = seam::resolve_proposal(&vault, untouched, ProposalRuling::Approve);
    assert_eq!(outcome, ProposalOutcome::ApprovedUntouched);

    let amended = seam::submit_merge_proposal(&vault, &a, &c);
    let narrowed = amendment_body(vec![c], a);
    let (outcome, _) =
        seam::resolve_proposal(&vault, amended, ProposalRuling::AmendThenApprove(&narrowed));
    assert_eq!(outcome, ProposalOutcome::ApprovedAmended);

    let rejected = seam::submit_merge_proposal(&vault, &a, &d);
    let (outcome, _) = seam::resolve_proposal(&vault, rejected, ProposalRuling::Reject);
    assert_eq!(outcome, ProposalOutcome::Rejected);
}

/// r7/§7: an approved-amended outcome carries a present, non-empty
/// amendment-delta payload; approved-untouched and rejected carry none.
#[test]
fn ms05_amended_receipt_carries_delta_others_do_not() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);
    let d = put_person(&vault, 0x24);

    let amended = seam::submit_merge_proposal(&vault, &a, &b);
    let narrowed = amendment_body(vec![b], a);
    let (_, amended_receipt) =
        seam::resolve_proposal(&vault, amended, ProposalRuling::AmendThenApprove(&narrowed));
    assert_eq!(
        seam::receipt_delta_payload(&vault, amended_receipt),
        Some(narrowed)
    );

    let untouched = seam::submit_merge_proposal(&vault, &a, &c);
    let (_, untouched_receipt) = seam::resolve_proposal(&vault, untouched, ProposalRuling::Approve);
    assert_eq!(seam::receipt_delta_payload(&vault, untouched_receipt), None);

    let rejected = seam::submit_merge_proposal(&vault, &a, &d);
    let (_, rejected_receipt) = seam::resolve_proposal(&vault, rejected, ProposalRuling::Reject);
    assert_eq!(seam::receipt_delta_payload(&vault, rejected_receipt), None);
}

/// r7 + ARCH-0056 boundary — POLARITY FLIPPED BY ONE-1757 (ED-01), the
/// pre-declared seam artifact for §6 edge #1.
///
/// At ONE-1747 this read `[NEG] …_is_reserved_opaque_not_built`: the delta
/// field was a reserved forward-compatible slot and the receipt must NOT
/// project the six ARCH-0056 §2 names, because building them there would
/// over-build the ED epic's surface. ED-01 built that surface, so the same
/// boundary now reads the other way — the reserved slot carries a Δ
/// projecting all six names.
///
/// What did NOT change, and is asserted here exactly as before: the PRODUCER
/// artifact (`amended_body`) still round-trips opaque bytes byte-for-byte. It
/// is the input the Δ is measured FROM, never overwritten by it — two slots,
/// two meanings.
#[test]
fn ms05_amendment_body_stays_opaque_while_ed01_fills_the_reserved_delta_slot() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);

    // The payload is carried as OPAQUE bytes: raw binary (embedded id bytes
    // make it non-UTF-8), stored verbatim and handed back byte-for-byte
    // rather than reshaped into a struct the engine understands. The
    // amendment NARROWS the proposal (c is dropped), so the Δ has something
    // real to measure.
    let opaque = amendment_body(vec![b], a);
    assert!(
        std::str::from_utf8(&opaque).is_err(),
        "fixture must be genuinely binary, else byte-exactness proves nothing"
    );
    let proposal = seam::submit_merge_proposal_of(&vault, vec![b, c], a);
    let (_, receipt) =
        seam::resolve_proposal(&vault, proposal, ProposalRuling::AmendThenApprove(&opaque));
    assert_eq!(seam::receipt_delta_payload(&vault, receipt), Some(opaque));

    // The producer never writes the reserved slot: it is ED-01's projection
    // pass that fills it, which is what keeps ONE-1747's files untouched.
    assert_eq!(seam::receipt_amendment_delta(&vault, receipt), None);
    assert_eq!(seam::project_amendment_deltas(&vault), 1);

    let payload = seam::receipt_amendment_delta(&vault, receipt)
        .expect("the reserved slot now carries the built Δ");
    let projected: serde_json::Value =
        serde_json::from_slice(&payload).expect("Δ decodes as canonical json");
    for built in [
        "proposed_ref",
        "final_ref",
        "source",
        "d_norm",
        "ops_summary",
        "engine_ver",
    ] {
        assert!(
            projected.get(built).is_some(),
            "receipt must now project the ARCH-0056 Δ field {built:?}"
        );
    }
    assert_eq!(projected["source"], "field_diff");
    let d_norm = projected["d_norm"].as_f64().expect("d_norm is a number");
    assert!(
        d_norm > 0.0 && d_norm <= 1.0,
        "a narrowing amendment measures a real distance, got {d_norm}"
    );

    // The producer artifact survives the projection byte-for-byte.
    assert_eq!(
        seam::receipt_delta_payload(&vault, receipt),
        Some(amendment_body(vec![b], a))
    );

    // Idempotent: a re-run measures nothing new. A Δ describes a window that
    // is already closed.
    assert_eq!(seam::project_amendment_deltas(&vault), 0);
}

/// The Δ slot follows the PRODUCER artifact exactly: outcomes that amended
/// nothing carry neither, even after the projection pass runs over them.
#[test]
fn ms05_unamended_outcomes_carry_no_delta_after_the_projection_pass() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);

    let untouched = seam::submit_merge_proposal(&vault, &a, &b);
    let (_, untouched_receipt) = seam::resolve_proposal(&vault, untouched, ProposalRuling::Approve);
    let rejected = seam::submit_merge_proposal(&vault, &a, &c);
    let (_, rejected_receipt) = seam::resolve_proposal(&vault, rejected, ProposalRuling::Reject);

    assert_eq!(seam::project_amendment_deltas(&vault), 0);
    assert_eq!(
        seam::receipt_amendment_delta(&vault, untouched_receipt),
        None
    );
    assert_eq!(
        seam::receipt_amendment_delta(&vault, rejected_receipt),
        None
    );
}

// ===== ONE-1748 (MS-06) — consent-graduation ramp =====

/// r7/§7: a ramp scope keys on the EXACT tuple
/// (op kind × target class × skill/agent) — two scopes differing only in
/// agent are distinct; identical tuples resolve to the same scope.
#[test]
fn ms06_ramp_scope_keys_on_op_class_agent_tuple() {
    let (_dir, vault) = open_vault();
    let scope_a = seam::ramp_scope(&vault, "send_email", "client_followup", "agent-a");
    let scope_b = seam::ramp_scope(&vault, "send_email", "client_followup", "agent-b");
    let scope_a_again = seam::ramp_scope(&vault, "send_email", "client_followup", "agent-a");
    assert_ne!(scope_a, scope_b);
    assert_eq!(scope_a, scope_a_again);
}

/// The MS-06 ramp guard: a streak of untouched approvals raises its confidence
/// and, at the streak floor, surfaces ONE graduation offer for the scope. It is
/// a [`oneiron::consent::ConsentGuard`], so the type system already forbids it
/// from granting anything (DEC-0006 invariant 5).
struct RampGuard {
    bound: oneiron::consent::GrantBound,
    untouched_streak: usize,
}

impl oneiron::consent::ConsentGuard for RampGuard {
    fn propose(&self, facts: &oneiron::consent::EffectFacts) -> oneiron::consent::ConsentProposal {
        oneiron::consent::ConsentProposal {
            effect_digest: oneiron::consent::ComposedEffect::new(facts.clone()).digest(),
            // Confidence rises with the streak; authority does not.
            #[allow(clippy::cast_precision_loss)]
            confidence: (self.untouched_streak as f32 / 12.0).min(1.0),
            suggested_bound: self.bound.clone(),
        }
    }
}

/// r7/§7 + DEC-0006 invariant 5: a streak of approved-untouched receipts
/// produces a graduation OFFER (a proposed create_standing_grant) — the
/// system offers, it NEVER auto-grants; the grant lands only on the tap.
///
/// ARMED by ONE-1606. `count_standing_grants` reads the real consent
/// registry; the offer half stays on the ONE-1748 ramp seam, so this test
/// drives the streak through the ramp and the ACCEPTANCE through the real
/// owner-only `create_standing_grant` door. The counts are unchanged: twelve
/// untouched approvals create ONE proposal and ZERO grants until the
/// authenticated owner accepts, which creates exactly one.
#[test]
fn ms06_streak_offers_standing_grant_never_auto_grants() {
    use oneiron::consent::{
        ActionClass, ActionEnvelope, ActorBound, ConsentGuard, ConsentProposal, EffectFacts,
        GrantBound,
    };
    use oneiron::store::GateDecisionId;

    const STREAK_FLOOR: usize = 12;

    let (_dir, vault) = open_vault();
    let owner_id = put_person(&vault, 0x25);
    let owner = vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");

    let scope_bound = GrantBound::action(
        ActorBound::new("agent-a").expect("actor"),
        ActionClass::new("send_email").expect("class"),
        ActionEnvelope::new(["client_followup".to_owned()]).expect("envelope"),
    )
    .expect("bound");
    let facts = EffectFacts::new("send_email").expect("facts");

    let mut graduation_offers: Vec<ConsentProposal> = Vec::new();
    for approvals in 1..=STREAK_FLOOR {
        let guard = RampGuard {
            bound: scope_bound.clone(),
            untouched_streak: approvals,
        };
        // The offer surfaces once, at the floor — and it is only ever an offer.
        if approvals >= STREAK_FLOOR && graduation_offers.is_empty() {
            graduation_offers.push(guard.propose(&facts));
        }
        assert_eq!(
            seam::count_standing_grants(&vault),
            0,
            "no number of untouched approvals may create a grant — the system \
             offers, it NEVER auto-grants"
        );
    }
    assert_eq!(graduation_offers.len(), 1, "one offer for one scope");
    assert_eq!(
        seam::count_standing_grants(&vault),
        0,
        "twelve untouched approvals create one proposal and zero grants"
    );

    // The owner taps the surfaced offer. Only this act creates authority, and
    // it creates exactly one grant.
    let offer = graduation_offers.pop().expect("the graduation offer");
    vault
        .create_standing_grant(&owner, offer.suggested_bound)
        .expect("owner accepts the graduation offer");
    assert_eq!(
        seam::count_standing_grants(&vault),
        1,
        "the owner tap creates exactly one grant"
    );
}

/// r7/§7: an auto scope accumulating amendments may be SELF-DEMOTED by the
/// agent — said out loud and receipted, never a silent capability
/// reduction.
#[test]
fn ms06_self_demotion_is_receipted_never_silent() {
    let (_dir, vault) = open_vault();
    let scope = seam::ramp_scope(&vault, "send_email", "client_followup", "agent-a");
    for _ in 0..3 {
        seam::record_outcome_receipt(&vault, &scope, ProposalOutcome::ApprovedAmended);
    }
    assert_eq!(seam::count_demotion_receipts(&vault), 0);
    seam::demote_scope_to_propose(&vault, &scope);
    assert_eq!(seam::count_demotion_receipts(&vault), 1);
    // The demotion actually moved the scope's consent posture.
    assert_eq!(seam::scope_state(&vault, &scope), "proposed");
}

/// r7/§7 companion to the above, added by ONE-1748 (additive, no assert
/// weakened): the demotion that matters is the one taken from a GRADUATED
/// scope, and it must take the standing grant with it. The parked contract
/// could not express this — `create_standing_grant` did not exist when it was
/// authored — so the transition assert lands here rather than by loosening
/// anything above.
#[test]
fn ms06_demotion_from_graduated_revokes_the_standing_grant() {
    use oneiron::store::GateDecisionId;

    let (_dir, vault) = open_vault();
    let owner_id = put_person(&vault, 0x25);
    let owner = vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");
    let scope = seam::ramp_scope(&vault, "send_email", "client_followup", "agent-a");

    for _ in 0..oneiron::consent_graduation::DEFAULT_GRADUATION_STREAK_FLOOR {
        seam::record_outcome_receipt(&vault, &scope, ProposalOutcome::ApprovedUntouched);
    }
    assert_eq!(seam::count_graduation_offers(&vault), 1);
    assert_eq!(seam::count_standing_grants(&vault), 0);

    seam::accept_graduation_offer(&vault, &owner, &scope);
    assert_eq!(seam::count_standing_grants(&vault), 1);
    assert_eq!(seam::scope_state(&vault, &scope), "auto");

    seam::demote_scope_to_propose(&vault, &scope);
    assert_eq!(seam::scope_state(&vault, &scope), "proposed");
    assert_eq!(
        seam::count_standing_grants(&vault),
        0,
        "a demotion that leaves the grant standing is a silent non-demotion"
    );
    assert_eq!(seam::count_demotion_receipts(&vault), 1);
}

/// [NEG] r7: merge/split are AUTO day one — they are never placed on the
/// propose→auto ramp. The ramp is only the exit path for scopes that
/// honestly start at propose (external effects, cross-person, tinkerer
/// dials). A ramp-everything implementation must fail here.
#[test]
fn ms06_merge_split_never_gated_by_ramp() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    // MS-01 ground truth: the merge applies immediately, auto by default.
    real_merge(&vault, vec![loser], survivor, 200);
    assert!(
        vault
            .entity_lifecycle_state(&loser)
            .expect("loser state")
            .is_redirect_shell()
    );

    assert!(!seam::scope_is_on_ramp(&vault, "merge"));
    assert!(!seam::scope_is_on_ramp(&vault, "split"));
    assert_eq!(seam::count_ramp_proposals_for(&vault, "merge"), 0);
    assert_eq!(seam::count_ramp_proposals_for(&vault, "split"), 0);
}

// ===== ONE-1749 (MS-07) — redirect-aware HardErase =====

/// r6/§9: HardErase of a canonical survivor erases its redirect shells'
/// payloads too — a readable shell would leak what erasure hid.
#[test]
fn ms07_harderase_of_head_cascades_to_redirect_shells() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    real_merge(&vault, vec![loser], survivor, 200);

    seam::hard_erase_entity(&vault, &survivor);
    assert_eq!(seam::readable_payload_bytes(&vault, &survivor), 0);
    assert_eq!(seam::readable_payload_bytes(&vault, &loser), 0);
}

/// r6/§9: the redirect table joins the ARCH-0038 carrier enumeration —
/// membership assert against the sweep's carrier classes.
#[test]
fn ms07_redirect_table_is_an_arch0038_carrier() {
    let (_dir, vault) = open_vault();
    let classes = seam::arch0038_carrier_classes(&vault);
    let redirect_class = seam::redirect_carrier_class();
    assert!(
        classes.contains(&redirect_class),
        "ARCH-0038 carrier enumeration must include the redirect table \
         (got {classes:?})"
    );
}

/// [NEG] r6/§9: after HardErase of the head and a redirect-projection
/// rebuild, exactly ZERO dangling redirect payloads remain.
///
/// The zero must be a census that LOOKED. The erase takes the head's
/// incident shell edges, and a rebuild re-derives every projection row from
/// exactly those edges — so both STRUCTURAL witnesses of the cascade are
/// gone by the time this runs, and a census reading only them would report
/// zero for a shell it simply cannot see. The negative control below plants
/// readable bytes back on that shell through the ordinary public write door:
/// the census must name it, or the assertion above proves nothing about the
/// half of §9 it exists for.
#[test]
fn ms07_no_dangling_payload_after_erase_and_rebuild() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x21);
    let loser = put_person(&vault, 0x22);
    real_merge(&vault, vec![loser], survivor, 200);

    seam::hard_erase_entity(&vault, &survivor);
    seam::rebuild_redirect_projection_from_edges(&vault);
    assert_eq!(seam::count_dangling_redirect_payloads(&vault), 0);

    let planted = b"oracle planted shell payload";
    vault
        .put_entity(
            &loser,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::temporal::TimeRange {
                start: 400,
                end: 400,
            },
            400,
            planted,
        )
        .expect("plant readable payload on the cascaded shell");
    seam::drop_redirect_projection(&vault);
    seam::rebuild_redirect_projection_from_edges(&vault);
    assert_eq!(seam::readable_payload_bytes(&vault, &survivor), 0);
    assert_eq!(
        seam::readable_payload_bytes(&vault, &loser),
        planted.len(),
        "the negative control must leave readable bytes on the shell"
    );
    assert_eq!(
        seam::count_dangling_redirect_payloads(&vault),
        1,
        "the census must count the cascaded shell — the erased head reads \
         zero, so the one dangling payload is exactly the shell's planted bytes"
    );

    // Removing exactly those bytes restores the clean end state the first
    // assertion asserts — through the same shell-preserving SoftErase door
    // the erase cascade itself uses on a shell.
    let removed = vault
        .delete_entity_with_reason(&loser, oneiron::deletion::DeleteReason::UserDelete)
        .expect("soft erase the shell");
    assert!(removed.existed);
    assert_eq!(seam::readable_payload_bytes(&vault, &loser), 0);
    assert_eq!(seam::count_dangling_redirect_payloads(&vault), 0);
}

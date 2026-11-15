//! Door for `tests/fingerprint_keep_typed_feeds.rs` (PLAN-UC-04 3.4c): the three typed
//! feeds and the digests they write into (a branch identity; an evidence attachment's id
//! and source revision; a shape plan's frontier and an approval's pin), which the engine
//! computes in private code over private rows.

use crate::ClaimSource;
use crate::connector_key::SlateDisposition;
use crate::consent::GrantBound;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, MessageSpan, PartitionAudience, PartitionThing, SwarmEvidenceRef,
    VerifiedLocator,
};
use crate::entity_id::EntityId;
use crate::outbound_grant::StandingOutboundGrantScope;
use crate::vault_shape::{ShapeRow, ShapeSeed};

/// A nightly thing's private grouping identity, by `PartitionAudience`'s variants.
#[derive(Clone, Copy, Debug)]
pub enum Audience {
    Thread(EntityId),
    Person(EntityId),
}

/// A nightly thing a branch is cut for: its entity and its grouping identity.
#[must_use]
pub fn partition_thing(entity: Option<EntityId>, audience: Option<Audience>) -> PartitionThing {
    PartitionThing {
        entity,
        audience: audience.map(|audience| match audience {
            Audience::Thread(id) => PartitionAudience::Thread(id),
            Audience::Person(id) => PartitionAudience::Person(id),
        }),
    }
}

/// A branch's identity.
#[must_use]
pub fn branch_identity<T>(branch: &ConsolidationBranchPlan<T>) -> [u8; 32] {
    branch.identity()
}

/// One MESSAGE-local slice a citation covers, by `MessageSpan`'s fields.
#[derive(Clone, Debug)]
pub struct MessageSlice {
    pub message: EntityId,
    pub start: usize,
    pub end: usize,
    pub revision: [u8; 32],
    pub frontier: Option<Vec<u8>>,
    pub attribution: Option<[u8; 32]>,
}

/// One verified citation: its locator, its quote hash and the slices it covers.
pub type Citation = (SwarmEvidenceRef, [u8; 32], Vec<MessageSlice>);

/// A support assertion's attachment hash and the source revision it pins, over the
/// head's and the source's ids and stored bodies.
#[must_use]
pub fn attachment_digests(
    (head, source): (EntityId, EntityId),
    (head_raw, source_raw): (&[u8], &[u8]),
    evidence_meet: ClaimSource,
    citations: &[Citation],
) -> ([u8; 32], [u8; 32]) {
    let locators: Vec<VerifiedLocator> = citations
        .iter()
        .map(|(locator, digest, slices)| {
            let spans = slices
                .iter()
                .map(|slice| MessageSpan {
                    message: slice.message,
                    start: slice.start,
                    end: slice.end,
                    revision: slice.revision,
                    frontier: slice.frontier.clone(),
                    attribution: slice.attribution,
                })
                .collect();
            (*locator, *digest, spans)
        })
        .collect();
    crate::dreamer_promotion::attachment_digests_for_test(
        (head, source),
        (head_raw, source_raw),
        evidence_meet,
        &locators,
    )
}

/// A roster actor as the reach reads it.
#[derive(Clone, Debug)]
pub struct ReachActor {
    pub entity: EntityId,
    pub agent_id: String,
    pub enabled: bool,
}

/// A sending identity as the reach reads it.
#[derive(Clone, Debug)]
pub struct ReachSender {
    pub entity: EntityId,
    pub actor: EntityId,
    pub channel: String,
    pub address: String,
    pub may_send: bool,
}

/// A connector key's outward tool as the reach reads it.
#[derive(Clone, Debug)]
pub struct ReachConnector {
    pub key: EntityId,
    pub connector: String,
    pub actor: Option<EntityId>,
    pub except: Vec<EntityId>,
    pub tool: String,
    pub setting: SlateDisposition,
    pub held: bool,
}

/// A standing outbound grant as the reach reads it.
#[derive(Clone, Debug)]
pub struct ReachOutbound {
    pub grant: EntityId,
    pub principal: String,
    pub scope: StandingOutboundGrantScope,
    pub digest: [u8; 32],
}

/// The typed rows the reach joins.
#[derive(Clone, Debug, Default)]
pub struct ReachRows {
    pub actors: Vec<ReachActor>,
    pub grants: Vec<GrantBound>,
    pub senders: Vec<ReachSender>,
    pub connectors: Vec<ReachConnector>,
    pub outbound: Vec<ReachOutbound>,
}

/// A shape plan's frontier for `seed` over these live rows, policy read-frontier and
/// reach.
///
/// # Errors
/// A seed or row that does not encode.
pub fn shape_frontier(
    seed: &ShapeSeed,
    rows: Vec<(ShapeRow, Option<EntityId>)>,
    policy_frontier: [u8; 32],
    reach: &ReachRows,
) -> crate::Result<String> {
    crate::vault_shape::frontier_for_test(seed, rows, policy_frontier, reach)
}

/// The approval pin of this policy read-frontier and reach.
#[must_use]
pub fn approval_dependencies(policy_frontier: [u8; 32], reach: &ReachRows) -> String {
    crate::vault_shape::approval_dependencies_for_test(policy_frontier, reach).digest
}

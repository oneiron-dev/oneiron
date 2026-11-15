//! K-proof (oracle) for PLAN-UC-04 stage 3.4c: the three typed feeds and the digests they
//! write into keep their bytes.
//!
//! A consolidation branch's identity (`purposes::dreamer::BRANCH_IDENTITY`, fed by the
//! thing's grouping identity), an evidence attachment's id and the source revision it pins
//! (`purposes::dreamer::{EVIDENCE_ATTACHMENT, EVIDENCE_SOURCE_REVISION}`, fed by each
//! MESSAGE slice), and a shape plan's frontier and an approval's pin
//! (`purposes::vault_shape::{FRONTIER, APPROVAL_DEPENDENCIES}`, fed by the reach rows) now
//! start their BLAKE3 through the fingerprint crate's K door. The attempt and projection
//! keys hold the branch identity's hex; the provenance claim id and `source_revision_ref`
//! are the attachment digests' first 16 bytes; apply compares the frontier and a journal
//! item stores the pin. So each must give main's bytes for every value. The `base_*`
//! modules hold main's lines at 4692e7ed3a60, copied by range (each range is named above its
//! copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and
//! differing from them only in indentation. The few lines around the copies give them
//! main's names: stand-in rows with the fields main's lines read, and a wrapper around
//! the attachment lines, which main writes inline.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_typed_feeds`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::connector_key::SlateDisposition;
use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass, DisclosureEnvelope,
    GrantBound,
};
use oneiron::dreamer_consolidation::{ConsolidationBranchPlan, ConversationPart, SwarmEvidenceRef};
use oneiron::outbound_grant::StandingOutboundGrantScope;
use oneiron::test_doors::fingerprint_keep_typed_feeds::{self as door, Audience, MessageSlice};
use oneiron::vault_shape::{ShapeRow, ShapeSeed};
use oneiron::{ClaimSource, EntityId, Result};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's. The copies keep main's
// `pub`, which these private modules cannot export.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_branch {
    use oneiron::EntityId;
    use oneiron::dreamer_consolidation::ConsolidationPartitionKey;

    /// A thing's grouping identity, by main's name and variants.
    #[derive(Clone, Copy)]
    pub(crate) enum PartitionAudience {
        Thread(EntityId),
        Person(EntityId),
    }

    /// A nightly thing, by main's names.
    #[derive(Clone, Copy)]
    pub(crate) struct PartitionThing {
        pub(crate) entity: Option<EntityId>,
        pub(crate) audience: Option<PartitionAudience>,
    }

    /// A branch part: the fields main's identity reads.
    pub(crate) struct ConversationPart {
        pub(crate) conversation_ref: EntityId,
        pub(crate) turns: Vec<EntityId>,
    }

    /// A branch: the fields main's identity reads.
    pub(crate) struct ConsolidationBranchPlan {
        pub(crate) world_ref: Option<EntityId>,
        pub(crate) facet_ref: Option<EntityId>,
        pub(crate) thing: Option<PartitionThing>,
        pub(crate) parts: Vec<ConversationPart>,
    }

    /// Main's branch domain, which is private there.
    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/branch.rs:22-22
    const BRANCH_IDENTITY_DOMAIN: &[u8] = b"oneiron:dreamer-branch:v1";

    /// The same bytes, for the tag test outside this module.
    pub(crate) const MAIN_BRANCH_IDENTITY_DOMAIN: &[u8] = BRANCH_IDENTITY_DOMAIN;

    impl PartitionAudience {
    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/partition/payload.rs:42-46
        pub(crate) fn entity(self) -> EntityId {
            match self {
                Self::Thread(id) | Self::Person(id) => id,
            }
        }

    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/partition/payload.rs:55-61
        pub(crate) fn hash_into(self, hasher: &mut blake3::Hasher) {
            hasher.update(&[match self {
                Self::Thread(_) => 1,
                Self::Person(_) => 2,
            }]);
            hasher.update(self.entity().as_bytes());
        }
    }

    impl ConsolidationBranchPlan {
    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/branch.rs:88-95
        /// The structural partition key of the part reading `conversation_ref`.
        pub(crate) fn part_key(&self, conversation_ref: EntityId) -> ConsolidationPartitionKey {
            ConsolidationPartitionKey {
                conversation_ref,
                world_ref: self.world_ref,
                facet_ref: self.facet_ref,
            }
        }

    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/branch.rs:121-154
        /// The branch's exact identity. A one-part branch is its partition's
        /// hash, so a Micro or Meso round keeps every key it had; a multi-part
        /// branch hashes its axes, its thing and every ordered part with its
        /// TURN count.
        pub(crate) fn identity(&self) -> [u8; 32] {
            if let [part] = self.parts.as_slice() {
                return self.part_key(part.conversation_ref).partition_hash();
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(BRANCH_IDENTITY_DOMAIN);
            hash_optional_entity(&mut hasher, self.world_ref.as_ref());
            hash_optional_entity(&mut hasher, self.facet_ref.as_ref());
            match self.thing {
                Some(thing) => {
                    hasher.update(&[1]);
                    hash_optional_entity(&mut hasher, thing.entity.as_ref());
                    match thing.audience {
                        Some(audience) => audience.hash_into(&mut hasher),
                        None => {
                            hasher.update(&[0]);
                        }
                    }
                }
                None => {
                    hasher.update(&[0]);
                }
            }
            hasher.update(&(self.parts.len() as u64).to_be_bytes());
            for part in &self.parts {
                hasher.update(&self.part_key(part.conversation_ref).partition_hash());
                hasher.update(&(part.turns.len() as u64).to_be_bytes());
            }
            *hasher.finalize().as_bytes()
        }
    }

    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/support.rs:97-107
    pub(super) fn hash_optional_entity(hasher: &mut blake3::Hasher, entity: Option<&EntityId>) {
        match entity {
            Some(entity) => {
                hasher.update(&[1]);
                hasher.update(entity.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_attachment {
    use oneiron::dreamer_consolidation::SwarmEvidenceRef;
    use oneiron::{ClaimSource, EntityId};

    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/turn_text.rs:82-90
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct MessageSpan {
        pub(crate) message: EntityId,
        pub(crate) start: usize,
        pub(crate) end: usize,
        pub(crate) revision: [u8; 32],
        pub(crate) frontier: Option<Vec<u8>>,
        pub(crate) attribution: Option<[u8; 32]>,
    }

    // main 4692e7ed3a60: crates/oneiron/src/dreamer_consolidation/turn_text.rs:92-113
    impl MessageSpan {
        /// Folds every field into an identity hash. A slice with no source
        /// attribution folds exactly the bytes it folded before slices carried
        /// one.
        pub(crate) fn hash_into(&self, hasher: &mut blake3::Hasher) {
            hasher.update(self.message.as_bytes());
            hasher.update(&(self.start as u64).to_be_bytes());
            hasher.update(&(self.end as u64).to_be_bytes());
            hasher.update(&self.revision);
            if let Some(frontier) = &self.frontier {
                hasher.update(&[1]);
                hasher.update(&(frontier.len() as u64).to_be_bytes());
                hasher.update(frontier);
            } else {
                hasher.update(&[0]);
            }
            if let Some(attribution) = &self.attribution {
                hasher.update(b"source_attribution");
                hasher.update(attribution);
            }
        }
    }

    /// Main's attachment hash and source revision, which `attach_ref` writes inline over
    /// the head's and the source's stored bodies.
    pub(crate) fn main_attachment_digests(
        (head, source): (EntityId, EntityId),
        (head_raw, source_raw): (&[u8], &[u8]),
        evidence_meet: ClaimSource,
        locators: Vec<(SwarmEvidenceRef, [u8; 32], Vec<MessageSpan>)>,
    ) -> ([u8; 32], [u8; 32]) {
    // main 4692e7ed3a60: crates/oneiron/src/dreamer_promotion/scoped.rs:563-599
        let head_hash = blake3::hash(&head_raw);
        let source_hash = blake3::hash(&source_raw);
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-evidence-attachment:v1");
        hash.update(head.as_bytes());
        hash.update(source.as_bytes());
        hash.update(head_hash.as_bytes());
        hash.update(source_hash.as_bytes());
        hash.update(evidence_meet.as_str().as_bytes());
        // A witnessed TURN's revision is its row plus the MESSAGE revisions the
        // citation names; any other source keeps its row hash exactly.
        let mut revision = blake3::Hasher::new();
        revision.update(b"oneiron:dreamer-evidence-source-revision:v1");
        revision.update(source_hash.as_bytes());
        let mut named = false;
        for (locator, digest, messages) in &locators {
            hash.update(&[u8::from(locator.claim_id.is_some())]);
            if let Some(claim) = locator.claim_id {
                hash.update(claim.as_bytes());
            }
            hash.update(&[u8::from(locator.byte_range.is_some())]);
            if let Some((start, end)) = locator.byte_range {
                hash.update(&(start as u64).to_be_bytes());
                hash.update(&(end as u64).to_be_bytes());
            }
            hash.update(digest);
            for message in messages {
                message.hash_into(&mut hash);
                message.hash_into(&mut revision);
                named = true;
            }
        }
        let source_revision = if named {
            revision.finalize()
        } else {
            source_hash
        };
        (*hash.finalize().as_bytes(), *source_revision.as_bytes())
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_shape {
    use oneiron::connector_key::SlateDisposition;
    use oneiron::consent::GrantBound;
    use oneiron::outbound_grant::StandingOutboundGrantScope;
    use oneiron::vault_shape::{ShapeApprovalDependencies, ShapeRow, ShapeSeed};
    use oneiron::{EntityId, Result};
    use oneiron_verb_wire::vault_shape::invalid;
    use oneiron_verb_wire::vault_shape::seed::hex;

    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/reach.rs:64-113
    /// One roster actor as the reach reads it.
    #[derive(Debug, Clone)]
    pub(super) struct ReachActor {
        pub(super) entity: EntityId,
        pub(super) agent_id: String,
        pub(super) enabled: bool,
    }

    /// One sending identity an actor holds, as the reach reads it.
    #[derive(Debug, Clone)]
    pub(super) struct ReachSender {
        pub(super) entity: EntityId,
        /// The actor its binding head names.
        pub(super) actor: EntityId,
        pub(super) channel: String,
        pub(super) address: String,
        /// Active, and its send permitted by the manifest's act policy now.
        pub(super) may_send: bool,
    }

    /// One outward tool of an active connector key, as the reach reads it.
    #[derive(Debug, Clone)]
    pub(super) struct ReachConnector {
        pub(super) key: EntityId,
        pub(super) connector: String,
        /// The actor the key is bound to; none is any actor on the connector.
        pub(super) actor: Option<EntityId>,
        /// For a key bound to no actor: the actors a key of their own on the
        /// same connector governs instead.
        pub(super) except: Vec<EntityId>,
        pub(super) tool: String,
        /// What a call on the tool meets under the key's slate.
        pub(super) setting: SlateDisposition,
        /// The key's manifest holds the tool for confirmation: every call asks.
        pub(super) held: bool,
    }

    /// The typed rows the reach joins, read on one snapshot. No secret value is
    /// ever among them; a connector key names its custody record, never reads
    /// it.
    #[derive(Debug, Clone, Default)]
    pub(super) struct ReachRows {
        pub(super) actors: Vec<ReachActor>,
        /// Every active standing grant's bound.
        pub(super) grants: Vec<GrantBound>,
        pub(super) senders: Vec<ReachSender>,
        pub(super) connectors: Vec<ReachConnector>,
        /// Every standing outbound grant that counts now (FIX 2801).
        pub(super) outbound: Vec<ReachOutbound>,
    }

    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/outbound_reach.rs:36-45
    /// One standing outbound grant that counts now, as the reach reads it.
    #[derive(Debug, Clone)]
    pub(super) struct ReachOutbound {
        pub(super) grant: EntityId,
        /// The actor it lets act, by the principal ref it was minted for.
        pub(super) principal: String,
        pub(super) scope: StandingOutboundGrantScope,
        /// Its stored row's digest, which the frontier pins.
        pub(super) digest: [u8; 32],
    }

    impl ReachRows {
    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/reach.rs:116-162
        /// Feeds these rows to a frontier, so a plan pins the reach it showed.
        pub(super) fn hash_into(&self, hasher: &mut blake3::Hasher) {
            hasher.update(b"reach\0");
            for actor in &self.actors {
                hasher.update(actor.entity.as_bytes());
                hasher.update(&(actor.agent_id.len() as u64).to_be_bytes());
                hasher.update(actor.agent_id.as_bytes());
                hasher.update(&[u8::from(actor.enabled)]);
            }
            hasher.update(b"\0");
            for grant in &self.grants {
                hasher.update(grant.digest().as_bytes());
            }
            hasher.update(b"\0");
            for sender in &self.senders {
                hasher.update(sender.entity.as_bytes());
                hasher.update(sender.actor.as_bytes());
                for text in [&sender.channel, &sender.address] {
                    hasher.update(&(text.len() as u64).to_be_bytes());
                    hasher.update(text.as_bytes());
                }
                hasher.update(&[u8::from(sender.may_send)]);
            }
            hasher.update(b"\0");
            for tool in &self.connectors {
                hasher.update(tool.key.as_bytes());
                hasher.update(&[u8::from(tool.actor.is_some())]);
                if let Some(actor) = tool.actor {
                    hasher.update(actor.as_bytes());
                }
                hasher.update(&(tool.except.len() as u64).to_be_bytes());
                for actor in &tool.except {
                    hasher.update(actor.as_bytes());
                }
                for text in [&tool.connector, &tool.tool] {
                    hasher.update(&(text.len() as u64).to_be_bytes());
                    hasher.update(text.as_bytes());
                }
                hasher.update(tool.setting.as_str().as_bytes());
                hasher.update(&[u8::from(tool.held)]);
            }
            hasher.update(b"\0");
            for grant in &self.outbound {
                hasher.update(grant.grant.as_bytes());
                hasher.update(&grant.digest);
            }
        }
    }

    /// A live shape: the fields main's two digests read.
    pub(crate) struct LiveShape {
        pub(crate) rows: Vec<(ShapeRow, Option<EntityId>)>,
        pub(crate) policy_frontier: [u8; 32],
        pub(crate) reach: ReachRows,
    }

    /// Main's frontier, which is private there.
    pub(crate) fn main_frontier(seed: &ShapeSeed, live: &LiveShape) -> Result<String> {
        frontier(seed, live)
    }

    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/seed.rs:43-51
    /// The digest a seed's rows hash to, independent of who stored them when.
    pub(super) fn seed_digest(seed: &ShapeSeed) -> Result<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(&seed.rows).map_err(|_| invalid("seed encoding failed"))?;
        Ok(*blake3::Hasher::new()
            .update(b"oneiron.vault_shape.seed_digest.v1\0")
            .update(&bytes)
            .finalize()
            .as_bytes())
    }

    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/plan.rs:251-264
    fn frontier(seed: &ShapeSeed, live: &LiveShape) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.vault_shape.frontier.v1\0");
        hasher.update(&seed_digest(seed)?);
        hasher.update(&live.policy_frontier);
        for (row, entity) in &live.rows {
            let bytes = rmp_serde::to_vec_named(row).map_err(|_| invalid("row encoding failed"))?;
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
            hasher.update(entity.map(|id| id.to_hex()).unwrap_or_default().as_bytes());
        }
        live.reach.hash_into(&mut hasher);
        Ok(hex(hasher.finalize().as_bytes()))
    }

    // main 4692e7ed3a60: crates/oneiron/src/vault_shape/approval.rs:30-39
    /// The dependencies `live` stands on.
    pub(super) fn approval_dependencies(live: &LiveShape) -> ShapeApprovalDependencies {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.vault_shape.approval.v1\0");
        hasher.update(&live.policy_frontier);
        live.reach.hash_into(&mut hasher);
        ShapeApprovalDependencies {
            digest: hex(hasher.finalize().as_bytes()),
        }
    }
}

fn id(byte: u8) -> EntityId {
    let mut bytes = [byte; 16];
    bytes[0] = 0x01;
    EntityId::from_bytes_unchecked(bytes)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn the_branch_purpose_keeps_main_s_domain() {
    let purpose = purposes::dreamer::BRANCH_IDENTITY;
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(
        purpose.tag().as_bytes(),
        base_branch::MAIN_BRANCH_IDENTITY_DOMAIN
    );
}

type Thing = Option<(Option<EntityId>, Option<Audience>)>;

fn head_branch(
    axes: (Option<EntityId>, Option<EntityId>),
    thing: Thing,
    parts: &[(EntityId, usize)],
) -> ConsolidationBranchPlan<EntityId> {
    ConsolidationBranchPlan {
        world_ref: axes.0,
        facet_ref: axes.1,
        thing: thing.map(|(entity, audience)| door::partition_thing(entity, audience)),
        parts: parts
            .iter()
            .map(|&(conversation_ref, turns)| ConversationPart {
                conversation_ref,
                turns: (0..turns).map(|turn| id(turn as u8)).collect(),
                watermark_last_learned_at: 7,
                line: 0,
            })
            .collect(),
    }
}

fn main_branch(
    axes: (Option<EntityId>, Option<EntityId>),
    thing: Thing,
    parts: &[(EntityId, usize)],
) -> base_branch::ConsolidationBranchPlan {
    base_branch::ConsolidationBranchPlan {
        world_ref: axes.0,
        facet_ref: axes.1,
        thing: thing.map(|(entity, audience)| base_branch::PartitionThing {
            entity,
            audience: audience.map(|audience| match audience {
                Audience::Thread(id) => base_branch::PartitionAudience::Thread(id),
                Audience::Person(id) => base_branch::PartitionAudience::Person(id),
            }),
        }),
        parts: parts
            .iter()
            .map(|&(conversation_ref, turns)| base_branch::ConversationPart {
                conversation_ref,
                turns: (0..turns).map(|turn| id(turn as u8)).collect(),
            })
            .collect(),
    }
}

#[test]
fn the_branch_identity_keeps_its_bytes() {
    let axes = [
        (None, None),
        (Some(id(0xb0)), None),
        (None, Some(id(0xc0))),
        (Some(id(0xb0)), Some(id(0xc0))),
    ];
    let things: [Thing; 6] = [
        None,
        Some((None, None)),
        Some((Some(id(0xd0)), None)),
        Some((None, Some(Audience::Thread(id(0xe0))))),
        Some((Some(id(0xd0)), Some(Audience::Person(id(0xe1))))),
        Some((Some(id(0xd1)), Some(Audience::Thread(id(0xd1))))),
    ];
    // One part (the partition's hash), two, three (one with 300 TURNs: its count has a
    // second byte) and none.
    let part_sets: [&[(EntityId, usize)]; 4] = [
        &[(id(0x10), 3)],
        &[(id(0x10), 0), (id(0x11), 1)],
        &[(id(0x12), 2), (id(0x10), 2), (id(0x11), 300)],
        &[],
    ];
    let mut seen = BTreeSet::new();
    for axes in axes {
        for thing in things {
            for parts in part_sets {
                let main = main_branch(axes, thing, parts).identity();
                let head = door::branch_identity(&head_branch(axes, thing, parts));
                assert_eq!(head, main, "{axes:?} {thing:?} {parts:?}");
                seen.insert(main);
            }
        }
    }
    // A one-part branch hashes only its partition key: 4 of them; every other shape is
    // its own.
    assert_eq!(seen.len(), 4 + 4 * 6 * 3);
}

#[test]
fn the_evidence_purposes_keep_main_s_tags() {
    for (purpose, tag) in [
        (
            purposes::dreamer::EVIDENCE_ATTACHMENT,
            "oneiron:dreamer-evidence-attachment:v1",
        ),
        (
            purposes::dreamer::EVIDENCE_SOURCE_REVISION,
            "oneiron:dreamer-evidence-source-revision:v1",
        ),
    ] {
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
        assert_eq!(purpose.tag(), tag);
    }
}

type SliceFacts = (
    EntityId,
    usize,
    usize,
    [u8; 32],
    Option<Vec<u8>>,
    Option<[u8; 32]>,
);

/// Citation sets: none; a whole TURN with no slice (the revision is the body's hash); a
/// claim and range over one bare slice; a range over two slices (an empty frontier, then a
/// 300-byte one with an attribution) beside a claim with none.
fn citation_sets(source: EntityId) -> Vec<Vec<(SwarmEvidenceRef, [u8; 32], Vec<SliceFacts>)>> {
    let slice = |byte: u8,
                 start: usize,
                 end: usize,
                 frontier: Option<Vec<u8>>,
                 attribution: Option<[u8; 32]>| {
        (id(byte), start, end, [byte; 32], frontier, attribution)
    };
    vec![
        Vec::new(),
        vec![(SwarmEvidenceRef::whole_turn(source), [0x11; 32], Vec::new())],
        vec![(
            SwarmEvidenceRef {
                source_id: source,
                claim_id: Some(id(0x21)),
                byte_range: Some((0, 5)),
            },
            [0x22; 32],
            vec![slice(0x23, 0, 5, None, None)],
        )],
        vec![
            (
                SwarmEvidenceRef {
                    source_id: source,
                    claim_id: None,
                    byte_range: Some((3, usize::MAX)),
                },
                [0x31; 32],
                vec![
                    slice(0x32, 3, 300, Some(Vec::new()), None),
                    slice(0x33, 0, 1, Some(vec![0xfe; 300]), Some([0x34; 32])),
                ],
            ),
            (
                SwarmEvidenceRef {
                    source_id: source,
                    claim_id: Some(id(0x35)),
                    byte_range: None,
                },
                [0x36; 32],
                Vec::new(),
            ),
        ],
    ]
}

#[test]
fn the_attachment_digests_keep_their_bytes() {
    let edges = [(id(0x01), id(0x02)), (id(0x03), id(0x04))];
    let bodies: [(&[u8], &[u8]); 2] = [(b"head body", b"source body"), (b"", &[b'x'; 300])];
    let meets = [
        ClaimSource::Observed,
        ClaimSource::Imported,
        ClaimSource::Generated,
    ];
    let mut seen = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    for (head, source) in edges {
        for (head_raw, source_raw) in bodies {
            for meet in meets {
                for citations in citation_sets(source) {
                    let main_locators = citations
                        .iter()
                        .map(|(locator, digest, slices)| {
                            let spans: Vec<base_attachment::MessageSpan> = slices
                                .iter()
                                .map(|(message, start, end, revision, frontier, attribution)| {
                                    base_attachment::MessageSpan {
                                        message: *message,
                                        start: *start,
                                        end: *end,
                                        revision: *revision,
                                        frontier: frontier.clone(),
                                        attribution: *attribution,
                                    }
                                })
                                .collect();
                            (*locator, *digest, spans)
                        })
                        .collect();
                    let head_citations: Vec<door::Citation> = citations
                        .iter()
                        .map(|(locator, digest, slices)| {
                            let slices: Vec<MessageSlice> = slices
                                .iter()
                                .map(|(message, start, end, revision, frontier, attribution)| {
                                    MessageSlice {
                                        message: *message,
                                        start: *start,
                                        end: *end,
                                        revision: *revision,
                                        frontier: frontier.clone(),
                                        attribution: *attribution,
                                    }
                                })
                                .collect();
                            (*locator, *digest, slices)
                        })
                        .collect();
                    let main = base_attachment::main_attachment_digests(
                        (head, source),
                        (head_raw, source_raw),
                        meet,
                        main_locators,
                    );
                    let head_digests = door::attachment_digests(
                        (head, source),
                        (head_raw, source_raw),
                        meet,
                        &head_citations,
                    );
                    assert_eq!(
                        head_digests, main,
                        "{head:?} {source:?} {meet:?} {citations:?}"
                    );
                    seen.insert(main.0);
                    revisions.insert(main.1);
                }
            }
        }
    }
    assert_eq!(seen.len(), 2 * 2 * 3 * 4);
    // The revision reads only the source body and the slices: per body, the body's own
    // hash (no slice named) and one per set that names slices.
    assert_eq!(revisions.len(), 2 * 3);
}

#[test]
fn the_shape_purposes_keep_main_s_tags() {
    for (purpose, tag) in [
        (
            purposes::vault_shape::FRONTIER,
            "oneiron.vault_shape.frontier.v1\0",
        ),
        (
            purposes::vault_shape::APPROVAL_DEPENDENCIES,
            "oneiron.vault_shape.approval.v1\0",
        ),
    ] {
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
        assert_eq!(purpose.tag(), tag);
    }
}

fn grants() -> Result<Vec<GrantBound>> {
    Ok(vec![
        GrantBound::disclosure(
            AudienceBound::new(strings(&["bob", "alice"]))?,
            DisclosureClass::new("contact")?,
            DisclosureEnvelope::new(strings(&["notes"]))?,
        )?,
        GrantBound::action(
            ActorBound::new("agent:alpha")?.with_actor_class("agent")?,
            ActionClass::new("send")?,
            ActionEnvelope::new(strings(&["thread:1"]))?.with_target("room")?,
        )?,
    ])
}

/// Reach rows: none; each kind alone; all of them; and all of them with one hashed field
/// changed each.
fn reaches() -> Result<Vec<door::ReachRows>> {
    let actors = vec![
        door::ReachActor {
            entity: id(0x31),
            agent_id: "agent:alpha".to_owned(),
            enabled: true,
        },
        door::ReachActor {
            entity: id(0x32),
            agent_id: String::new(),
            enabled: false,
        },
        door::ReachActor {
            entity: id(0x33),
            agent_id: format!("ü{}", "x".repeat(300)),
            enabled: true,
        },
    ];
    let senders = vec![
        door::ReachSender {
            entity: id(0x41),
            actor: id(0x31),
            channel: "email".to_owned(),
            address: "a@example.org".to_owned(),
            may_send: true,
        },
        door::ReachSender {
            entity: id(0x42),
            actor: id(0x32),
            channel: String::new(),
            address: String::new(),
            may_send: false,
        },
    ];
    let connector = |key: u8, setting: SlateDisposition| door::ReachConnector {
        key: id(key),
        connector: "github".to_owned(),
        actor: Some(id(0x31)),
        except: Vec::new(),
        tool: "create_issue".to_owned(),
        setting,
        held: false,
    };
    let connectors = vec![
        connector(0x51, SlateDisposition::AlwaysAllow),
        connector(0x52, SlateDisposition::Auto),
        connector(0x53, SlateDisposition::AlwaysAsk),
        door::ReachConnector {
            key: id(0x54),
            connector: "slack".to_owned(),
            actor: None,
            except: vec![id(0x31), id(0x32)],
            tool: String::new(),
            setting: SlateDisposition::NeverAllow,
            held: true,
        },
    ];
    let outbound = vec![door::ReachOutbound {
        grant: id(0x61),
        principal: "agent:alpha".to_owned(),
        scope: StandingOutboundGrantScope::Channel {
            channel: "email".to_owned(),
        },
        digest: [0x62; 32],
    }];
    let full = door::ReachRows {
        actors: actors.clone(),
        grants: grants()?,
        senders: senders.clone(),
        connectors: connectors.clone(),
        outbound: outbound.clone(),
    };
    let mut reaches = vec![
        door::ReachRows::default(),
        door::ReachRows {
            actors,
            ..Default::default()
        },
        door::ReachRows {
            grants: grants()?,
            ..Default::default()
        },
        door::ReachRows {
            senders,
            ..Default::default()
        },
        door::ReachRows {
            connectors,
            ..Default::default()
        },
        door::ReachRows {
            outbound,
            ..Default::default()
        },
        full.clone(),
    ];
    let mut changed = full.clone();
    changed.actors[0].enabled = false;
    reaches.push(changed);
    let mut changed = full.clone();
    changed.senders[1].may_send = true;
    reaches.push(changed);
    let mut changed = full.clone();
    changed.connectors[3].held = false;
    reaches.push(changed);
    let mut changed = full.clone();
    changed.connectors[0].setting = SlateDisposition::NeverAllow;
    reaches.push(changed);
    let mut changed = full;
    changed.outbound[0].digest = [0x63; 32];
    reaches.push(changed);
    Ok(reaches)
}

fn main_reach(reach: &door::ReachRows) -> base_shape::ReachRows {
    base_shape::ReachRows {
        actors: reach
            .actors
            .iter()
            .map(|actor| base_shape::ReachActor {
                entity: actor.entity,
                agent_id: actor.agent_id.clone(),
                enabled: actor.enabled,
            })
            .collect(),
        grants: reach.grants.clone(),
        senders: reach
            .senders
            .iter()
            .map(|sender| base_shape::ReachSender {
                entity: sender.entity,
                actor: sender.actor,
                channel: sender.channel.clone(),
                address: sender.address.clone(),
                may_send: sender.may_send,
            })
            .collect(),
        connectors: reach
            .connectors
            .iter()
            .map(|tool| base_shape::ReachConnector {
                key: tool.key,
                connector: tool.connector.clone(),
                actor: tool.actor,
                except: tool.except.clone(),
                tool: tool.tool.clone(),
                setting: tool.setting,
                held: tool.held,
            })
            .collect(),
        outbound: reach
            .outbound
            .iter()
            .map(|grant| base_shape::ReachOutbound {
                grant: grant.grant,
                principal: grant.principal.clone(),
                scope: grant.scope.clone(),
                digest: grant.digest,
            })
            .collect(),
    }
}

#[test]
fn the_shape_frontier_keeps_its_bytes() -> Result<()> {
    let seeds = [
        ShapeSeed { rows: Vec::new() },
        ShapeSeed {
            rows: vec![
                ShapeRow::World {
                    name: "home".to_owned(),
                },
                ShapeRow::Pack {
                    name: "notes".to_owned(),
                    version: Some("1.0.0".to_owned()),
                },
            ],
        },
    ];
    let row_sets: [Vec<(ShapeRow, Option<EntityId>)>; 2] = [
        Vec::new(),
        vec![
            (
                ShapeRow::World {
                    name: "home".to_owned(),
                },
                Some(id(0x71)),
            ),
            (
                ShapeRow::Facet {
                    person: id(0x72).to_hex(),
                    name: "x".repeat(300),
                },
                None,
            ),
        ],
    ];
    let reaches = reaches()?;
    assert_eq!(reaches.len(), 12);
    let mut seen = BTreeSet::new();
    for seed in &seeds {
        for rows in &row_sets {
            for policy_frontier in [[0; 32], [0xaa; 32]] {
                for reach in &reaches {
                    let live = base_shape::LiveShape {
                        rows: rows.clone(),
                        policy_frontier,
                        reach: main_reach(reach),
                    };
                    let main = base_shape::main_frontier(seed, &live)?;
                    let head = door::shape_frontier(seed, rows.clone(), policy_frontier, reach)?;
                    assert_eq!(
                        head, main,
                        "{seed:?} {rows:?} {policy_frontier:?} {reach:?}"
                    );
                    seen.insert(main);
                }
            }
        }
    }
    assert_eq!(seen.len(), 2 * 2 * 2 * 12);
    Ok(())
}

#[test]
fn the_approval_pin_keeps_its_bytes() -> Result<()> {
    let reaches = reaches()?;
    let mut seen = BTreeSet::new();
    for policy_frontier in [[0; 32], [0x01; 32], [0xaa; 32]] {
        for reach in &reaches {
            let live = base_shape::LiveShape {
                rows: Vec::new(),
                policy_frontier,
                reach: main_reach(reach),
            };
            let main = base_shape::approval_dependencies(&live).digest;
            assert_eq!(
                door::approval_dependencies(policy_frontier, reach),
                main,
                "{policy_frontier:?} {reach:?}"
            );
            seen.insert(main);
        }
    }
    assert_eq!(seen.len(), 3 * 12);
    Ok(())
}

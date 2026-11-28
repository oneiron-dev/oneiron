//! K-proof for dreamer-consolidation legacy digests at 13a57d8b3026: existing stored,
//! sent and compared identities keep main's bytes through the fingerprint K
//! door.
//!
//! A request carries its call-label digest. DREAMER_FOLLOWER_STATE stores the
//! follower's reported-cache and route pins, and the route pin is compared to
//! decide a cold resend. A summary source note stores its text fingerprint.
//! DREAMER_CURSOR rows and queue rows are keyed by the partition hash; an
//! attempt's stored dedupe key holds the partition-round hash. ROOTS stores a
//! child receipt's judgement hash, and the bridge compares it with the rebuilt
//! one (the same digest at two sites). ARC_WORK and the summary derivation
//! store the Arc params hashes, and a paged composition's params hash is
//! compared with the stored one. A MESSAGE slice stores its attribution pin,
//! compared when its projection is read again.
//!
//! The base modules copy exact main lines. Inline hash lines have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: the label
//! map's id and choice tables (the door takes each kind by its prefix letter)
//! and the child receipt's judgement field.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_dreamer_consolidation_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::dreamer_consolidation::{ConsolidationPartitionKey, WorkingSetTurn};
use oneiron::dreamer_runner::DreamerTurnRole;
use oneiron::test_doors::fingerprint_keep_dreamer_consolidation_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_model::llm::{ModelId, ModelLocality};

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_labels {
    use std::collections::BTreeMap;
    use std::fmt;
    use oneiron::EntityId;
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:50-50
    const DIGEST_DOMAIN: &[u8] = b"oneiron:dreamer-call-labels:v1";
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:54-75
    /// What a label names, by its one-letter prefix.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) enum LabelKind {
        /// `P`: a listed entity, a person, an organisation or a place.
        Entity,
        /// `C`: a listed claim.
        Claim,
        /// `T`: a turn.
        Turn,
        /// `N`: a note.
        Note,
        /// `V`: the conversation.
        Conversation,
        /// `S`: another source, such as the MESSAGE a sieve span indexes.
        Source,
        /// `R`: a relationship a listed claim or the branch holds within.
        Relationship,
        /// `Q`: a decision read's question, its paired and person questions too.
        /// Only that read names one back ([`DecisionWireLabels`]); a reply's
        /// own label never parses as a question.
        Question,
    }
    impl LabelKind {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:78-89
            const fn prefix(self) -> char {
                match self {
                    Self::Entity => 'P',
                    Self::Claim => 'C',
                    Self::Turn => 'T',
                    Self::Note => 'N',
                    Self::Conversation => 'V',
                    Self::Source => 'S',
                    Self::Relationship => 'R',
                    Self::Question => 'Q',
                }
            }
    }
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:105-110
    /// One label as a call writes it: a prefix letter, then its number from 1.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) struct CallLabel {
        kind: LabelKind,
        number: usize,
    }
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:149-153
    impl fmt::Display for CallLabel {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}{}", self.kind.prefix(), self.number)
        }
    }
    // Stand-in: the two tables main's digest reads.
    pub(crate) struct CallLabelMap {
        ids: BTreeMap<LabelKind, Vec<EntityId>>,
        choices: BTreeMap<EntityId, Vec<String>>,
    }
    impl CallLabelMap {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/call_labels.rs:290-327
            fn digest(&self, mint: Option<&[u8]>) -> [u8; 32] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(DIGEST_DOMAIN);
                match mint {
                    Some(mint) => {
                        hasher.update(&[1]);
                        hasher.update(&(mint.len() as u64).to_be_bytes());
                        hasher.update(mint);
                    }
                    None => {
                        hasher.update(&[0]);
                    }
                }
                for (kind, ids) in &self.ids {
                    for (index, id) in ids.iter().enumerate() {
                        let label = CallLabel {
                            kind: *kind,
                            number: index + 1,
                        }
                        .to_string();
                        hasher.update(&(label.len() as u64).to_be_bytes());
                        hasher.update(label.as_bytes());
                        hasher.update(id.as_bytes());
                    }
                }
                // A map that shows no choice digests as it did before choices were
                // shown (FIX 7506 P1's extraction, NOTE and listing calls).
                for (question, shown) in &self.choices {
                    hasher.update(b"choices");
                    hasher.update(question.as_bytes());
                    hasher.update(&(shown.len() as u64).to_be_bytes());
                    for option in shown {
                        hasher.update(&(option.len() as u64).to_be_bytes());
                        hasher.update(option.as_bytes());
                    }
                }
                *hasher.finalize().as_bytes()
            }
    }
    const KINDS: [LabelKind; 8] = [
        LabelKind::Entity,
        LabelKind::Claim,
        LabelKind::Turn,
        LabelKind::Note,
        LabelKind::Conversation,
        LabelKind::Source,
        LabelKind::Relationship,
        LabelKind::Question,
    ];
    pub(crate) fn digest(
        mint: Option<&[u8]>,
        ids: &[(char, Vec<EntityId>)],
        choices: &BTreeMap<EntityId, Vec<String>>,
    ) -> [u8; 32] {
        let ids = ids
            .iter()
            .filter_map(|(prefix, kind_ids)| {
                KINDS.into_iter().find(|kind| kind.prefix() == *prefix).map(|kind| (kind, kind_ids.clone()))
            })
            .collect();
        CallLabelMap { ids, choices: choices.clone() }.digest(mint)
    }
    pub(crate) fn tag() -> &'static [u8] { DIGEST_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_cache {
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/follower_attempt/output.rs:16-16
    const CACHE_DOMAIN: &[u8] = b"oneiron:dreamer-follower:cache-identity:v1";
    pub(crate) fn digest(identity_json: &[u8]) -> Option<[u8; 32]> {
        let bytes = identity_json.to_vec();
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/follower_attempt/output.rs:118-124
            Some(
                *blake3::Hasher::new()
                    .update(CACHE_DOMAIN)
                    .update(&bytes)
                    .finalize()
                    .as_bytes(),
            )
    }
    pub(crate) fn tag() -> &'static [u8] { CACHE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_route {
    use oneiron_model::llm::{ModelId, ModelLocality};
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/follower_attempt/request.rs:25-25
    const ROUTE_DOMAIN: &[u8] = b"oneiron:dreamer-follower:route:v1";
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/follower_attempt/request.rs:106-117
    /// The model and locality a follower call goes out on, hashed: a change
    /// resends the prefix cold under a new epoch.
    pub(super) fn route_digest(model: &ModelId, locality: ModelLocality) -> [u8; 32] {
        let locality = format!("{locality:?}");
        *blake3::Hasher::new()
            .update(ROUTE_DOMAIN)
            .update(&(model.as_str().len() as u64).to_be_bytes())
            .update(model.as_str().as_bytes())
            .update(locality.as_bytes())
            .finalize()
            .as_bytes()
    }
    pub(crate) fn tag() -> &'static [u8] { ROUTE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_note {
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/note_text.rs:19-19
    const FINGERPRINT_DOMAIN: &[u8] = b"oneiron:dreamer-note-text:v1";
    pub(crate) fn fingerprint(mode: &str, text: &str) -> [u8; 32] {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/note_text.rs:73-78
            let mut hash = blake3::Hasher::new();
            hash.update(FINGERPRINT_DOMAIN);
            hash.update(&(mode.len() as u64).to_be_bytes());
            hash.update(mode.as_bytes());
            hash.update(&(text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        *hash.finalize().as_bytes()
    }
    pub(crate) fn tag() -> &'static [u8] { FINGERPRINT_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_partition {
    use oneiron::EntityId;
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/support.rs:18-18
    pub const DREAMER_PARTITION_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-bucket:v1";
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/support.rs:97-107
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
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/partition.rs:60-65
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ConsolidationPartitionKey {
        pub conversation_ref: EntityId,
        pub world_ref: Option<EntityId>,
        pub facet_ref: Option<EntityId>,
    }
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/partition.rs:67-80
    impl ConsolidationPartitionKey {
        /// Domain-separated BLAKE3 over the partition key (domain unchanged
        /// from D6's cursor derivation, DESIGN-PIN A2).
        #[must_use]
        pub fn partition_hash(&self) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(DREAMER_PARTITION_HASH_DOMAIN);
            hasher.update(b"partition");
            hasher.update(self.conversation_ref.as_bytes());
            hash_optional_entity(&mut hasher, self.world_ref.as_ref());
            hash_optional_entity(&mut hasher, self.facet_ref.as_ref());
            *hasher.finalize().as_bytes()
        }
    }
    pub(crate) fn tag() -> &'static [u8] { DREAMER_PARTITION_HASH_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_round {
    use std::collections::BTreeMap;
    use oneiron::EntityId;
    use oneiron::dreamer_consolidation::WorkingSetTurn;
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/support.rs:54-54
    pub(super) const DREAMER_PARTITION_ROUND_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-partition-round:v1";
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/partition.rs:344-369
    /// Domain-separated BLAKE3 over the EXACT ordered TURN batch of one round:
    /// `domain || u64_be(count) || repeated(u64_be(learned_at) || turn_id)`. The
    /// count is hashed so a batch can never be a prefix-ambiguous concatenation of
    /// another.
    pub(crate) fn partition_round_hash(turns: &[WorkingSetTurn]) -> [u8; 32] {
        keyed_partition_round_hash(turns, &BTreeMap::new())
    }

    /// [`partition_round_hash`] over each TURN's selection key: a TURN in
    /// `carried` stood at its re-dirty carrier, whose id replaces the TURN id in
    /// the preimage. Every other TURN hashes byte-identically, and a TURN changed
    /// again, even in the same second, takes a new carrier id and a new round.
    pub(super) fn keyed_partition_round_hash(
        turns: &[WorkingSetTurn],
        carried: &BTreeMap<EntityId, EntityId>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DREAMER_PARTITION_ROUND_HASH_DOMAIN);
        hasher.update(&(turns.len() as u64).to_be_bytes());
        for turn in turns {
            let id = carried.get(&turn.turn_id).unwrap_or(&turn.turn_id);
            hasher.update(&turn.learned_at.to_be_bytes());
            hasher.update(id.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
    pub(crate) fn tag() -> &'static [u8] { DREAMER_PARTITION_ROUND_HASH_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_judgement {
    fn bridge_hash(encoded: Vec<u8>) -> Result<[u8; 32], ()> {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/root_evidence/bridge.rs:468-468
            Ok(*blake3::hash(&encoded).as_bytes())
    }
    pub(crate) fn bridge(encoded: &[u8]) -> [u8; 32] {
        bridge_hash(encoded.to_vec()).expect("main digest")
    }
    // Stand-in: the receipt field main's line writes.
    struct Receipt {
        judgement_hash: [u8; 32],
    }
    pub(crate) fn work(encoded: &[u8]) -> [u8; 32] {
        let encoded = encoded.to_vec();
        Receipt {
            // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/root_evidence/work.rs:128-128
                            judgement_hash: *blake3::hash(&encoded).as_bytes(),
        }
        .judgement_hash
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_params {
    pub(crate) fn arc_parts(params: &[u8]) -> [u8; 32] {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_children.rs:189-189
                let params_hash = *blake3::hash(&params).as_bytes();
        params_hash
    }
    pub(crate) fn arc_composition(params: &[u8]) -> [u8; 32] {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_compose.rs:82-82
                let params_hash = *blake3::hash(&params).as_bytes();
        params_hash
    }
    pub(crate) fn session_pages(params: &[u8]) -> [u8; 32] {
        // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/chunks.rs:73-73
                        let params_hash = *blake3::hash(&params).as_bytes();
        params_hash
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_attribution {
    use oneiron::EntityId;
    // main 13a57d8b3026: crates/oneiron/src/dreamer_consolidation/turn_text/attribution.rs:61-85
    pub(super) fn attribution_hash(
        imported: bool,
        authors: &[EntityId],
        speaker: Option<EntityId>,
    ) -> Option<[u8; 32]> {
        if !imported || authors.is_empty() {
            return None;
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:message-attribution:v1");
        hash.update(&(authors.len() as u64).to_be_bytes());
        for author in authors {
            hash.update(author.as_bytes());
        }
        match speaker {
            Some(speaker) => {
                hash.update(&[1]);
                hash.update(speaker.as_bytes());
            }
            None => {
                hash.update(&[0]);
            }
        }
        Some(*hash.finalize().as_bytes())
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("unreserved entity id")
}

fn texts() -> Vec<String> {
    vec![
        String::new(),
        "ordinary".into(),
        "é 日本 α".into(),
        "a\0b".into(),
        " \t\n".into(),
        "長x".repeat(600),
    ]
}

fn byte_rows() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        b"ab".to_vec(),
        "é 日本".as_bytes().to_vec(),
        b"{\"predicate\":\"knows\"}".to_vec(),
        "長x".repeat(600).into_bytes(),
        vec![0xa5; 70_000],
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // attribution.rs:70 writes its tag inline; its bytes are written out here.
    let recipes: [(LegacyPurpose, TagMode, &[u8]); 11] = [
        (
            purposes::dreamer_consolidation::ARC_COMPOSITION_PARAMS,
            TagMode::NotHashed,
            b"oneiron.dreamer_consolidation.arc_composition_params.v1",
        ),
        (
            purposes::dreamer_consolidation::ARC_PARTS_PARAMS,
            TagMode::NotHashed,
            b"oneiron.dreamer_consolidation.arc_parts_params.v1",
        ),
        (
            purposes::dreamer_consolidation::CALL_LABELS,
            TagMode::HashedFirst,
            base_labels::tag(),
        ),
        (
            purposes::dreamer_consolidation::CHILD_JUDGEMENT,
            TagMode::NotHashed,
            b"oneiron.dreamer_consolidation.child_judgement.v1",
        ),
        (
            purposes::dreamer_consolidation::FOLLOWER_REPORTED_CACHE,
            TagMode::HashedFirst,
            base_cache::tag(),
        ),
        (
            purposes::dreamer_consolidation::FOLLOWER_ROUTE,
            TagMode::HashedFirst,
            base_route::tag(),
        ),
        (
            purposes::dreamer_consolidation::MESSAGE_ATTRIBUTION,
            TagMode::HashedFirst,
            b"oneiron:message-attribution:v1",
        ),
        (
            purposes::dreamer_consolidation::NOTE_TEXT,
            TagMode::HashedFirst,
            base_note::tag(),
        ),
        (
            purposes::dreamer_consolidation::PARTITION,
            TagMode::HashedFirst,
            base_partition::tag(),
        ),
        (
            purposes::dreamer_consolidation::PARTITION_ROUND,
            TagMode::HashedFirst,
            base_round::tag(),
        ),
        (
            purposes::dreamer_consolidation::SESSION_PAGES_PARAMS,
            TagMode::NotHashed,
            b"oneiron.dreamer_consolidation.session_pages_params.v1",
        ),
    ];
    for (purpose, mode, tag) in recipes {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), mode);
    }
}

#[test]
fn call_labels_keep_main_s_bytes() {
    let long = vec![0x61; 70_000];
    let mints: [Option<&[u8]>; 5] = [
        None,
        Some(b""),
        Some(b"m"),
        Some("é".as_bytes()),
        Some(&long),
    ];
    let twelve: Vec<EntityId> = (1..=12).map(id).collect();
    let tables: Vec<Vec<(char, Vec<EntityId>)>> = vec![
        vec![],
        vec![('P', vec![id(1)])],
        vec![('C', vec![id(1)])],
        vec![('P', vec![id(1), id(2)])],
        vec![('P', vec![id(2), id(1)])],
        vec![('P', vec![id(1)]), ('C', vec![id(2)])],
        vec![('Q', vec![id(3)]), ('P', vec![id(1)])],
        vec![('P', twelve.clone())],
        "PCTNVSRQ"
            .chars()
            .enumerate()
            .map(|(n, prefix)| (prefix, vec![id(40 + n as u8)]))
            .collect(),
        vec![('P', vec![])],
    ];
    let question = id(0x71);
    let other = id(0x72);
    let choice_sets: Vec<BTreeMap<EntityId, Vec<String>>> = vec![
        BTreeMap::new(),
        BTreeMap::from([(question, vec![])]),
        BTreeMap::from([(question, vec!["ab".into(), "c".into()])]),
        BTreeMap::from([(question, vec!["a".into(), "bc".into()])]),
        BTreeMap::from([(question, texts())]),
        BTreeMap::from([(question, vec!["yes".into()]), (other, vec!["no".into()])]),
    ];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for mint in mints {
        for table in &tables {
            for choices in &choice_sets {
                let head = door::call_labels(mint, table, choices);
                assert_eq!(head, base_labels::digest(mint, table, choices));
                digests.insert(head);
                rows += 1;
            }
        }
    }
    // An empty kind writes nothing: tables 0 and 9 digest alike.
    assert_eq!((rows, digests.len()), (300, 270));
}

#[test]
fn follower_reported_cache_keeps_main_s_bytes() {
    let rows = byte_rows();
    let mut digests = BTreeSet::new();
    for bytes in &rows {
        let head = door::follower_reported_cache(bytes);
        assert_eq!(Some(head), base_cache::digest(bytes));
        digests.insert(head);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn follower_route_keeps_main_s_bytes() {
    let models = ["local/llama@1", "anthropic/claude-x@2026-01-01", "p/m@r"]
        .map(|model| ModelId::new(model).expect("model id"));
    let localities = [
        ModelLocality::OnDevice,
        ModelLocality::OwnServer,
        ModelLocality::ThirdParty,
    ];
    let mut digests = BTreeSet::new();
    for model in &models {
        for locality in localities {
            let head = door::follower_route(model, locality);
            assert_eq!(head, base_route::route_digest(model, locality));
            digests.insert(head);
        }
    }
    assert_eq!(digests.len(), 9);
}

#[test]
fn note_text_keeps_main_s_bytes() {
    let modes = ["sealed_pad", "sealed", "plain", ""];
    let mut digests = BTreeSet::new();
    for mode in modes {
        for text in texts() {
            let head = door::note_text(mode, &text);
            assert_eq!(head, base_note::fingerprint(mode, &text));
            digests.insert(head);
        }
    }
    assert_eq!(digests.len(), modes.len() * texts().len());
    // Each field carries its length: a moved boundary moves the digest.
    assert_ne!(door::note_text("ab", "c"), door::note_text("a", "bc"));
    assert_eq!(
        door::note_text("ab", "c"),
        base_note::fingerprint("ab", "c")
    );
}

#[test]
fn partition_keeps_main_s_bytes() {
    let sides = [None, Some(id(0x21)), Some(id(0x22))];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for conversation_ref in [id(0x11), id(0x12)] {
        for world_ref in sides {
            for facet_ref in sides {
                let head = ConsolidationPartitionKey {
                    conversation_ref,
                    world_ref,
                    facet_ref,
                    project: Some(oneiron::claim::default_project_id()),
                }
                .partition_hash();
                let base = base_partition::ConsolidationPartitionKey {
                    conversation_ref,
                    world_ref,
                    facet_ref,
                }
                .partition_hash();
                assert_eq!(head, base);
                digests.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, digests.len()), (18, 18));
}

#[test]
fn partition_round_keeps_main_s_bytes() {
    let turn = |n: u8, learned_at: u64| WorkingSetTurn {
        turn_id: id(n),
        role: DreamerTurnRole::User,
        learned_at,
        carrier: None,
        conversation: None,
    };
    let batches: Vec<Vec<WorkingSetTurn>> = vec![
        vec![],
        vec![turn(1, 900)],
        vec![turn(1, 900), turn(2, 900)],
        vec![turn(2, 900), turn(1, 900)],
        vec![turn(1, 0), turn(2, u64::MAX)],
        vec![turn(1, 901), turn(2, 900)],
        (1..=40)
            .map(|n| turn(n, 1_700_000_000 + u64::from(n)))
            .collect(),
    ];
    let carried_sets: Vec<BTreeMap<EntityId, EntityId>> = vec![
        BTreeMap::new(),
        BTreeMap::from([(id(1), id(0x81))]),
        BTreeMap::from([(id(1), id(0x81)), (id(2), id(0x82))]),
        BTreeMap::from([(id(0x99), id(0x83))]),
    ];
    let mut plain = BTreeSet::new();
    for batch in &batches {
        let head = door::partition_round(batch);
        assert_eq!(head, base_round::partition_round_hash(batch));
        plain.insert(head);
        for carried in &carried_sets {
            assert_eq!(
                door::keyed_partition_round(batch, carried),
                base_round::keyed_partition_round_hash(batch, carried)
            );
        }
    }
    assert_eq!(plain.len(), batches.len());
    // A carrier replaces its TURN's id; a carrier of a TURN not in the batch changes nothing.
    let batch = &batches[2];
    assert_ne!(
        door::keyed_partition_round(batch, &carried_sets[1]),
        door::partition_round(batch)
    );
    assert_eq!(
        door::keyed_partition_round(batch, &carried_sets[3]),
        door::partition_round(batch)
    );
}

#[test]
fn child_judgement_keeps_main_s_bytes_at_both_sites() {
    let rows = byte_rows();
    let mut digests = BTreeSet::new();
    for encoded in &rows {
        let head = door::child_judgement(encoded);
        assert_eq!(head, base_judgement::bridge(encoded));
        assert_eq!(head, base_judgement::work(encoded));
        digests.insert(head);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn summary_params_keep_main_s_bytes() {
    let schema = serde_json::json!({"type": "object", "required": ["summary"]});
    let mut rows = byte_rows();
    for domain in [
        "oneiron:arc-summary-parts:v1",
        "oneiron:arc-summary-composition:v1",
        "oneiron:session-summary-pages:v1",
    ] {
        rows.push(serde_json::to_vec(&("Summarise.", "p/m@r", &schema, domain)).expect("json"));
        rows.push(
            serde_json::to_vec(&("Summarise.", "p/m@r", &schema, domain, 4096_u64)).expect("json"),
        );
    }
    let mut digests = BTreeSet::new();
    for params in &rows {
        let parts = door::arc_parts_params(params);
        assert_eq!(parts, base_params::arc_parts(params));
        let composition = door::arc_composition_params(params);
        assert_eq!(composition, base_params::arc_composition(params));
        let pages = door::session_pages_params(params);
        assert_eq!(pages, base_params::session_pages(params));
        // No tag is hashed: the three agree on one input, as main's do.
        assert_eq!((parts, composition), (pages, pages));
        digests.insert(parts);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn message_attribution_keeps_main_s_bytes() {
    let forty: Vec<EntityId> = (1..=40).map(id).collect();
    let author_sets: Vec<Vec<EntityId>> = vec![
        vec![],
        vec![id(1)],
        vec![id(1), id(2)],
        vec![id(2), id(1)],
        forty,
    ];
    let speakers = [None, Some(id(1)), Some(id(0x63))];
    let mut digests = BTreeSet::new();
    let mut some_rows = 0;
    for imported in [false, true] {
        for authors in &author_sets {
            for speaker in speakers {
                let head = door::message_attribution(imported, authors, speaker);
                assert_eq!(
                    head,
                    base_attribution::attribution_hash(imported, authors, speaker)
                );
                assert_eq!(head.is_some(), imported && !authors.is_empty());
                if let Some(head) = head {
                    digests.insert(head);
                    some_rows += 1;
                }
            }
        }
    }
    assert_eq!((some_rows, digests.len()), (12, 12));
}

//! One fixture, multiple phases and caller-observable diary admission doors.
use super::*;
use crate::claim::{ScopedReadActorKey, ScopedReadResult};
use crate::context_pack::ContextEntity;
use crate::note::{NoteScope, NoteWriteEnvelope};
use crate::vault::ReadMode;

struct DiaryMatrix {
    _dir: tempfile::TempDir,
    vault: crate::Vault,
    a: EntityId,
    b: EntityId,
    a1: EntityId,
    a2: EntityId,
    foreign: EntityId,
    key: ScopedReadActorKey,
}
impl DiaryMatrix {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            crate::Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
        let a = put_person(&vault, 0xD1);
        let b = put_person(&vault, 0xD2);
        let diary = |owner: EntityId| -> EntityId {
            let receipt = facade_for(&vault, owner)
                .author_note(&NoteWriteEnvelope {
                    kind: NoteKind::Diary,
                    scope: NoteScope::ActorPrivate { owner_ref: owner },
                    markdown: "matrix diary evidence".into(),
                    source_revision_ref: [0xD3; 16],
                    mask: None,
                })
                .unwrap();
            EntityId::from_hex(&receipt.id_hex).unwrap()
        };
        let (a1, a2, foreign) = (diary(a), diary(a), diary(b));
        assert!(a1 < a2 && a2 < foreign);
        let issuer = crate::authority::HostSlipIssuer::from_secret(b"diary matrix proof").unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        let mut claims = root.claims;
        claims.slip_id = *blake3::hash(a.as_bytes()).as_bytes();
        claims.holder_ref = a.to_hex();
        claims.actor_class = Some("human".into());
        let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
        let sig = issuer.binding_proof(&slip, b"diary matrix").unwrap();
        let proof = vault
            .verify_capability_slip(&issuer.public_key(), &slip, b"diary matrix", &sig)
            .unwrap();
        let key = ScopedReadActorKey::from_verified_slip(&proof).unwrap();
        Self {
            _dir: dir,
            vault,
            a,
            b,
            a1,
            a2,
            foreign,
            key,
        }
    }
    fn check(&self, phase: &str, node: bool, exact_pair: bool, independent: bool) {
        let read = self.vault.scoped_read(self.key.clone());
        let missing = EntityId::from_bytes([0xF3; 16]).unwrap();
        let point = read.get(&self.foreign).unwrap();
        assert_eq!(point.value.is_some(), node, "{phase}: point");
        if !node {
            assert_eq!(
                point.receipt,
                read.get(&missing).unwrap().receipt,
                "{phase}: opaque receipt"
            );
        }
        let batch = read
            .get_entities_parts_with_receipt(&[self.foreign], None)
            .unwrap();
        assert_eq!(batch.value[0].is_some(), node, "{phase}: batch");
        let pin = self.vault.pin_entity_revision(&self.foreign).unwrap();
        for mode in [ReadMode::Live, ReadMode::Indexed, ReadMode::Pinned(pin)] {
            let parts = read
                .get_entity_parts_with_mode_with_receipt(&self.foreign, mode, None)
                .unwrap();
            assert_eq!(parts.value.is_some(), node, "{phase}: {mode:?}");
        }
        let reference = facade_for(&self.vault, self.b)
            .short_ref_or_hex(&self.foreign)
            .unwrap();
        let (short, hash) = crate::entity_id::parse_short_ref_syntax(&reference).unwrap();
        let short_read = read.hydrate_short_id(short, hash).unwrap();
        assert_eq!(short_read.value.is_some(), node, "{phase}: short-id");
        let timeline = read.memory_timeline(&self.foreign).unwrap();
        assert_eq!(
            !timeline.value.records.is_empty(),
            node,
            "{phase}: timeline"
        );
        let record = crate::deletion::MemoryTimelineRecord {
            id: self.foreign,
            state: crate::deletion::MemoryTimelineRecordState::Live,
            entity_type: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body_bytes: None,
            deletion: None,
            supersedes: Vec::new(),
            superseded_by: Vec::new(),
        };
        let projection = read
            .memory_timeline_parts_with_receipt(&[record], None)
            .unwrap();
        assert_eq!(projection.value, vec![None]);
        assert_eq!(
            projection.receipt.suppressed_count, 0,
            "{phase}: projection receipt"
        );
        let edges = read.edges_out(&self.a1).unwrap().value.unwrap();
        let saw_same_as = edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == self.foreign);
        assert_eq!(saw_same_as, exact_pair, "{phase}: exact edge");
        let options = NeighborOpts {
            edge_kind: Some("same_as".into()),
            limit: 1,
            ..Default::default()
        };
        assert_eq!(
            !facade_for(&self.vault, self.a)
                .neighbors(&self.a1.to_hex(), &options)
                .unwrap()
                .is_empty(),
            exact_pair,
            "{phase}: facade"
        );
        let ask = read
            .graph_ask_neighbors(&self.a1, 5, 5, 16_384)
            .unwrap()
            .unwrap();
        assert_eq!(
            ask.iter().any(|row| row.0 == self.foreign),
            exact_pair || independent,
            "{phase}: graph ask"
        );
        let source = ContextEntity {
            critical: false,
            id: self.a1,
            short_id: self.a1.to_hex(),
            content_hash: 0,
            source_revision_ref: None,
            entity_type: ENTITY_TYPE_NOTE,
            score: 1.0,
            fields: None,
            edges: Some(self.vault.edges_out(&self.a1).unwrap()),
            vector: None,
        };
        let neighbor = ContextEntity {
            id: self.foreign,
            short_id: self.foreign.to_hex(),
            edges: None,
            ..source.clone()
        };
        let mut pack = self
            .vault
            .context_pack()
            .search_text("absent-matrix-query", 4)
            .run()
            .unwrap();
        pack.results = vec![source];
        pack.neighbors = vec![neighbor];
        let receipt = read.filter_context_pack(&mut pack).unwrap();
        assert_eq!(
            pack.results[0]
                .edges
                .as_ref()
                .unwrap()
                .iter()
                .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == self.foreign),
            exact_pair,
            "{phase}: pack edge"
        );
        assert_eq!(
            pack.neighbors
                .iter()
                .any(|neighbor| neighbor.id == self.foreign),
            exact_pair || independent,
            "{phase}: pack reachability"
        );
        if !exact_pair {
            assert_eq!(receipt.suppressed_count, 0, "{phase}: pack receipt");
        }
        let scored = read
            .filter_scored_entities(vec![crate::ScoredEntity {
                id: self.foreign,
                score: 1.0,
            }])
            .unwrap();
        assert_eq!(!scored.value.is_empty(), node, "{phase}: scored");
        let ScopedReadResult { value, receipt: _ } = read.get(&self.a1).unwrap();
        assert!(value.is_some(), "{phase}: local diary remains readable");
    }
}

#[test]
fn diary_states_share_one_admission_matrix_across_read_doors() {
    let m = DiaryMatrix::new();
    let am = facade_for(&m.vault, m.a);
    let bm = facade_for(&m.vault, m.b);
    let absent = EntityId::from_bytes([0xF4; 16]).unwrap();
    let wrong_kind = put_person(&m.vault, 0xD4);
    for candidate in [absent, wrong_kind] {
        am.link_diary_coreference(m.a1, candidate).unwrap();
        let intent = am.grant_diary_coreference(m.a1, candidate).unwrap();
        assert!(
            !m.vault
                .edge_exists(&m.a1, EdgeKind::SameAs, &candidate)
                .unwrap()
        );
        am.revoke_diary_coreference_grant(intent).unwrap();
    }
    am.link_diary_coreference(m.a1, m.foreign).unwrap();
    m.check("no consent", false, false, false);
    let grant_a = am.grant_diary_coreference(m.a1, m.foreign).unwrap();
    m.check("one consent", false, false, false);
    bm.grant_diary_coreference(m.a1, m.foreign).unwrap();
    m.check("both consents", true, true, false);
    am.revoke_diary_coreference_grant(grant_a).unwrap();
    m.check("revoked", false, false, false);
    am.link_diary_coreference(m.a2, m.foreign).unwrap();
    am.grant_diary_coreference(m.a2, m.foreign).unwrap();
    bm.grant_diary_coreference(m.a2, m.foreign).unwrap();
    m.check(
        "other pair shares node, original pair empty",
        true,
        false,
        false,
    );
    m.vault
        .batch()
        .edge(&m.a1, EdgeKind::BlockedBy, &m.foreign, 1.0)
        .commit()
        .unwrap();
    m.check("independent edge to same target", true, false, true);
}

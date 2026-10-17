//! Authenticated wrong labels emitted by the live weave report: one on a
//! link, and one on a claim, project or budget item.
use super::{ScopedRead, WeaveItem, WeaveReader, WeaveSectionKind, WeaveSectionSpec};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::decode_claim_body;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::provenance::{EDGE_REF_LEN, EdgeRef};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// Wrong-link labels, keyed by the link's edge ref, then the label's receipt id.
const LABELS: SideTable<([u8; EDGE_REF_LEN], EntityId), StoredCorrection, Named> =
    SideTable::new(&side_table::WEAVE_WRONG_LINK_LABEL);

/// Wrong-item labels, keyed by the item's id (a claim, project or budget id,
/// unique across the three), then the label's receipt id.
const ITEM_LABELS: SideTable<(EntityId, EntityId), StoredItemCorrection, Named> =
    SideTable::new(&side_table::WEAVE_WRONG_ITEM_LABEL);

/// The report sections that read claims by predicate: every one but the
/// project and budget sections. A claim's item check reads it under the
/// first its reader's policy allows; the plain ones lead.
const CLAIM_SECTIONS: [WeaveSectionKind; 8] = [
    WeaveSectionKind::Changes,
    WeaveSectionKind::OpenAsks,
    WeaveSectionKind::Conflicts,
    WeaveSectionKind::Exceptions,
    WeaveSectionKind::Admissions,
    WeaveSectionKind::SieveScore,
    WeaveSectionKind::Links,
    WeaveSectionKind::Digest,
];

/// An immutable negative training label for one weave link. The edge reference
/// is the link's stable id; the receipt id distinguishes independent taps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeaveLinkCorrection {
    pub id: EntityId,
    pub link: EdgeRef,
    pub actor: EntityId,
    pub recorded_at: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredCorrection {
    id: EntityId,
    link: Vec<u8>,
    actor: EntityId,
    recorded_at: u64,
}

/// A claim, project or budget row of a reader's weave report: the item a
/// wrong-item label names. A budget stands under the project the report
/// shows it with; its label keys on the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeaveItemTarget {
    Claim(EntityId),
    Project(EntityId),
    Budget { project: EntityId, budget: EntityId },
}

impl WeaveItemTarget {
    /// The target a report row is, when it takes a wrong-item label. A link
    /// takes a wrong-link label; a health card settles through the concern
    /// door; a resident's dream progress takes none.
    #[must_use]
    pub fn of(item: &WeaveItem) -> Option<Self> {
        match item {
            WeaveItem::Claim { id, .. } => Some(Self::Claim(*id)),
            WeaveItem::Project { id, .. } => Some(Self::Project(*id)),
            WeaveItem::Budget {
                project,
                budget_ref,
            } => Some(Self::Budget {
                project: *project,
                budget: *budget_ref,
            }),
            WeaveItem::Link { .. }
            | WeaveItem::DreamProgress { .. }
            | WeaveItem::AgentHealth { .. } => None,
        }
    }

    /// The id its labels key on.
    #[must_use]
    pub fn id(self) -> EntityId {
        match self {
            Self::Claim(id) | Self::Project(id) | Self::Budget { budget: id, .. } => id,
        }
    }
}

/// An immutable negative training label for one claim, project or budget
/// item. The receipt id distinguishes independent taps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeaveItemCorrection {
    pub id: EntityId,
    pub item: WeaveItemTarget,
    pub actor: EntityId,
    pub recorded_at: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredItemCorrection {
    id: EntityId,
    item: WeaveItemTarget,
    actor: EntityId,
    recorded_at: u64,
}

impl ScopedRead<'_> {
    /// File a wrong-link tap only for an authenticated human viewing that live
    /// link in their own report. A caller-chosen edge reference alone grants no
    /// write authority. The persisted label is not an edge retraction.
    pub fn report_wrong_link(
        &self,
        auth: &AuthenticatedOwner,
        reader: WeaveReader<'_>,
        link: EdgeRef,
    ) -> Result<WeaveLinkCorrection> {
        self.file_weave_label(
            auth,
            reader,
            |txn| self.require_visible_weave_link_in(txn, reader, link),
            |txn, actor| {
                Ok(self
                    .vault
                    .weave_link_correction_labels_in_txn(txn, link)?
                    .iter()
                    .filter(|label| label.actor == actor)
                    .count())
            },
            |txn, actor, now| {
                let correction = WeaveLinkCorrection {
                    id: EntityId::now(),
                    link,
                    actor,
                    recorded_at: now,
                };
                LABELS.put(
                    &self.vault.store,
                    txn,
                    &(link.encode(), correction.id),
                    &StoredCorrection {
                        id: correction.id,
                        link: link.encode().to_vec(),
                        actor: correction.actor,
                        recorded_at: correction.recorded_at,
                    },
                )?;
                Ok(correction)
            },
        )
    }

    /// File a wrong-item tap only for an authenticated human viewing that
    /// claim, project or budget row in their own report, under the same
    /// bound as a link label. A caller-chosen id alone grants no write
    /// authority. The persisted label changes no record.
    pub fn report_wrong_item(
        &self,
        auth: &AuthenticatedOwner,
        reader: WeaveReader<'_>,
        item: WeaveItemTarget,
    ) -> Result<WeaveItemCorrection> {
        self.file_weave_label(
            auth,
            reader,
            |txn| self.require_visible_weave_item_in(txn, reader, item),
            |txn, actor| {
                Ok(self
                    .vault
                    .weave_item_correction_labels_in_txn(txn, item.id())?
                    .iter()
                    .filter(|label| label.actor == actor)
                    .count())
            },
            |txn, actor, now| {
                let correction = WeaveItemCorrection {
                    id: EntityId::now(),
                    item,
                    actor,
                    recorded_at: now,
                };
                ITEM_LABELS.put(
                    &self.vault.store,
                    txn,
                    &(item.id(), correction.id),
                    &StoredItemCorrection {
                        id: correction.id,
                        item,
                        actor: correction.actor,
                        recorded_at: correction.recorded_at,
                    },
                )?;
                Ok(correction)
            },
        )
    }

    /// One wrong tap: `reader` bound to `auth`, then in one writer its
    /// clock, the visibility check `admit`, the reader's own bound on the
    /// labels `own` counts, and the label `put` writes.
    ///
    /// No reader is refused for how many labels it files (rule 5): past the
    /// policy's bound on one link or item, a reader's label files anyway, and
    /// the first such report on it leaves the typed own-rate check.
    fn file_weave_label<T>(
        &self,
        auth: &AuthenticatedOwner,
        reader: WeaveReader<'_>,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        own: impl FnOnce(&heed::RoTxn<'_>, EntityId) -> Result<usize>,
        put: impl FnOnce(&mut heed::RwTxn<'_>, EntityId, u64) -> Result<T>,
    ) -> Result<T> {
        // A person reports a row they see as themselves; the owner reader
        // reads with the owner role, so it takes the owner tier.
        let as_owner = matches!(reader, WeaveReader::Owner(_));
        let auth_actor = if as_owner {
            auth.revalidate(self.vault)?
        } else {
            auth.revalidate_person(self.vault)?
        };
        let bound = match &reader {
            WeaveReader::Person(id) => *id == auth_actor,
            WeaveReader::Owner(owner) => *owner == auth,
            WeaveReader::Agent(_) => false,
        };
        if !bound {
            return Err(Error::InvalidConfig(
                "weave correction actor mismatch".into(),
            ));
        }
        #[cfg(test)]
        self.vault
            .test_hooks()
            .signal_before_weave_correction_writer();
        let mut txn = self.vault.store.env.write_txn()?;
        // Persist the injected authorization clock in the SAME writer before
        // relationship grants are checked against its floor.
        let now = crate::ports::recorded_at_in_txn(&self.vault.store, &mut txn)?;
        let actor = if as_owner {
            auth.revalidate_in_txn(self.vault, &txn)?
        } else {
            auth.revalidate_person_in_txn(self.vault, &txn)?
        };
        admit(&txn)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let limit = policy
            .weave_correction_limit(&actor.to_hex())
            .ok_or(Error::InvalidConfig(
                "weave correction policy unavailable".into(),
            ))?;
        // Writers count the reader's own labels in this SAME serialized txn;
        // another reader's labels never count toward its bound.
        let own = own(&txn, actor)?;
        if own >= limit {
            // Capabilities first: a count never refuses a label. Past the
            // bound it leaves the advisory check instead.
            crate::own_rate::observe_in_txn(
                &self.vault.store,
                &mut txn,
                crate::own_rate::OwnRateKind::WeaveCorrection,
                actor,
                0,
                u64::try_from(own).unwrap_or(u64::MAX).saturating_add(1),
                crate::own_rate::OwnRate {
                    threshold: u64::try_from(limit).unwrap_or(u64::MAX),
                    window_seconds: 0,
                },
            )?;
        }
        let label = put(&mut txn, actor, now)?;
        txn.commit()?;
        Ok(label)
    }

    /// Read labels for a link this actor can currently see in the live report.
    /// Loop consumers inside the engine can use the same typed receipt reader.
    pub fn weave_link_corrections(
        &self,
        reader: WeaveReader<'_>,
        link: EdgeRef,
    ) -> Result<Vec<WeaveLinkCorrection>> {
        let txn = self.grant_read_txn()?;
        self.require_visible_weave_link_in(&txn, reader, link)?;
        self.vault.weave_link_correction_labels_in_txn(&txn, link)
    }

    /// Re-use the full report's reader binding, current policy, project
    /// membership, endpoint gates, and edge-liveness check in the given txn.
    fn require_visible_weave_link_in(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
        link: EdgeRef,
    ) -> Result<()> {
        let recipe = [WeaveSectionSpec {
            kind: WeaveSectionKind::Links,
            predicates: Vec::new(),
            edge_kinds: vec![link.kind],
        }];
        let report = self.weave_report_in_txn(txn, reader, &recipe)?;
        if report.value.sections[0].items.iter().any(|item| {
            matches!(item, WeaveItem::Link { source, kind, target }
                if *source == link.source && *kind == link.kind && *target == link.target)
        }) {
            Ok(())
        } else {
            Err(Error::EntityNotFound)
        }
    }

    /// The same check for an item: its own section, read under the reader's
    /// binding and current policy, must show it. A claim reads under its own
    /// predicate, in the first claim section the reader's policy allows; a
    /// budget must show under the project named with it. An id that is no
    /// claim fails as an unseen one does.
    fn require_visible_weave_item_in(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
        item: WeaveItemTarget,
    ) -> Result<()> {
        let (kind, predicates) = match item {
            WeaveItemTarget::Claim(id) => {
                let Some(record) = self.entity_record_in(txn, &id)? else {
                    return Err(Error::EntityNotFound);
                };
                let raw = record.encode();
                match EntityMetadataHeader::parse(&raw) {
                    Some(header) if header.entity_type == ENTITY_TYPE_CLAIM => {}
                    _ => return Err(Error::EntityNotFound),
                }
                let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
                let row = crate::gate::weave_policy::effective_resolved(
                    &policy,
                    reader.role(),
                    reader.id(self.vault, txn)?,
                )
                .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?;
                let kind = CLAIM_SECTIONS
                    .into_iter()
                    .find(|kind| row.sections.contains(kind.policy_name()))
                    .ok_or(Error::EntityNotFound)?;
                (kind, vec![body.predicate])
            }
            WeaveItemTarget::Project(_) => (WeaveSectionKind::Projects, Vec::new()),
            WeaveItemTarget::Budget { .. } => (WeaveSectionKind::Budgets, Vec::new()),
        };
        let recipe = [WeaveSectionSpec {
            kind,
            predicates,
            edge_kinds: Vec::new(),
        }];
        let report = self.weave_report_in_txn(txn, reader, &recipe)?;
        if report.value.sections[0]
            .items
            .iter()
            .any(|shown| WeaveItemTarget::of(shown) == Some(item))
        {
            Ok(())
        } else {
            Err(Error::EntityNotFound)
        }
    }
}

impl crate::Vault {
    /// Trusted loops can read labels, including on retracted links, in their
    /// own snapshot. Caller-facing reads must go through ScopedRead instead.
    pub(crate) fn weave_link_correction_labels_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        link: EdgeRef,
    ) -> Result<Vec<WeaveLinkCorrection>> {
        let mut labels = Vec::new();
        for row in LABELS.iter_from(&self.store, txn, &link.encode())? {
            let ((_, receipt_id), stored) = row?;
            if stored.link != link.encode() || receipt_id != stored.id {
                return Err(Error::CorruptedIndex("weave correction link"));
            }
            labels.push(WeaveLinkCorrection {
                id: stored.id,
                link,
                actor: stored.actor,
                recorded_at: stored.recorded_at,
            });
        }
        Ok(labels)
    }

    /// An item's labels, read as a link's are, in the loop's own snapshot.
    pub(crate) fn weave_item_correction_labels_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        item: EntityId,
    ) -> Result<Vec<WeaveItemCorrection>> {
        let mut labels = Vec::new();
        for row in ITEM_LABELS.iter_from(&self.store, txn, item.as_bytes())? {
            let ((id, receipt_id), stored) = row?;
            if id != item || stored.item.id() != item || receipt_id != stored.id {
                return Err(Error::CorruptedIndex("weave correction item"));
            }
            labels.push(WeaveItemCorrection {
                id: stored.id,
                item: stored.item,
                actor: stored.actor,
                recorded_at: stored.recorded_at,
            });
        }
        Ok(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::ScopedReadActorKey;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
    use crate::{EdgeKind, TimeRange};

    fn fixture() -> Result<(tempfile::TempDir, crate::Vault, EntityId, EdgeRef)> {
        let (tmp, vault) = open_test_vault_with(embedding_test_config());
        let person = entity(0xb1);
        let peer = entity(0xb2);
        for id in [person, peer] {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"reader",
            )?;
        }
        vault.put_edge(&person, EdgeKind::Mentions, &peer, 0.5)?;
        crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
        Ok((
            tmp,
            vault,
            person,
            EdgeRef::new(person, EdgeKind::Mentions, peer),
        ))
    }

    #[test]
    fn revoked_reader_cannot_file_or_read_after_an_earlier_report_admitted_link() -> Result<()> {
        let (_tmp, vault, person, link) = fixture()?;
        let auth = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
        let recipe = [WeaveSectionSpec {
            kind: WeaveSectionKind::Links,
            predicates: Vec::new(),
            edge_kinds: vec![link.kind],
        }];
        assert!(
            read.weave_report(WeaveReader::Person(person), &recipe)?
                .value
                .sections[0]
                .items
                .contains(&WeaveItem::Link {
                    source: link.source,
                    kind: link.kind,
                    target: link.target,
                })
        );
        // The previous report is stale; the actor and graph edge remain live.
        crate::test_util::authorize_readers(&vault, &[]);
        assert!(
            read.report_wrong_link(&auth, WeaveReader::Person(person), link)
                .is_err()
        );
        assert!(
            read.weave_link_corrections(WeaveReader::Person(person), link)
                .is_err()
        );
        assert!(
            vault
                .weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?
                .is_empty()
        );
        Ok(())
    }

    // H420: one reader's labels on a link never spend another reader's
    // allowance there; each reader's own allowance still bounds it.
    #[test]
    fn a_readers_correction_allowance_is_its_own() -> Result<()> {
        use rmpv::Value;
        let (_tmp, vault, person, link) = fixture()?;
        let peer = link.target;
        crate::test_util::authorize_readers_with(
            &vault,
            &[&person.to_hex(), &peer.to_hex()],
            vec![(
                Value::from("weave_correction_policy"),
                Value::Map(vec![
                    (Value::from("vault_max"), Value::from(1)),
                    (Value::from("default"), Value::from(1)),
                    (Value::from("holders"), Value::Map(Vec::new())),
                    (
                        Value::from("precedence"),
                        Value::from("holder_then_default"),
                    ),
                ]),
            )],
        );
        let file = |reader: EntityId| {
            let auth = vault.authenticate_owner(
                reader,
                &reader.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )?;
            vault
                .scoped_read(ScopedReadActorKey::new(reader.to_hex()).unwrap())
                .report_wrong_link(&auth, WeaveReader::Person(reader), link)
        };
        assert_eq!(file(person)?.actor, person);
        assert!(matches!(file(person), Err(Error::IndexOverflow(_))));
        let other = file(peer);
        assert!(
            matches!(&other, Ok(label) if label.actor == peer),
            "H420: another reader's label spent this reader's allowance ({other:?})"
        );
        Ok(())
    }

    // H420, capabilities first: the vault owner's own reports are never
    // refused on count. Past the bound the owner's report lands, and the
    // first one past it leaves the typed own-rate check instead.
    #[test]
    fn the_owners_reports_past_the_bound_land_with_a_typed_check() -> Result<()> {
        use rmpv::Value;
        let (_tmp, vault) = open_test_vault_with(embedding_test_config());
        // The bootstrap already wrote the embedded owner's PERSON.
        let owner_id = crate::vault::embedded_owner_actor_id()?;
        let peer = entity(0xb2);
        vault.put_entity(
            &peer,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
        vault.put_edge(&owner_id, EdgeKind::Mentions, &peer, 0.5)?;
        let link = EdgeRef::new(owner_id, EdgeKind::Mentions, peer);
        crate::test_util::authorize_readers_with(
            &vault,
            &[&owner_id.to_hex()],
            vec![(
                Value::from("weave_correction_policy"),
                Value::Map(vec![
                    (Value::from("vault_max"), Value::from(1)),
                    (Value::from("default"), Value::from(1)),
                    (Value::from("holders"), Value::Map(Vec::new())),
                    (
                        Value::from("precedence"),
                        Value::from("holder_then_default"),
                    ),
                ]),
            )],
        );
        let owner = vault.authenticate_owner(
            owner_id,
            &owner_id.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let read = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
        for _ in 0..3 {
            let filed = read.report_wrong_link(&owner, WeaveReader::Owner(&owner), link);
            assert!(
                matches!(&filed, Ok(label) if label.actor == owner_id),
                "FAILBEFORE H420: the owner's own report was refused on count ({filed:?})"
            );
        }
        let check =
            vault.own_rate_check(owner_id, crate::own_rate::OwnRateKind::WeaveCorrection)?;
        assert_eq!(
            check.map(|check| (check.count, check.threshold)),
            Some((2, 1)),
            "the first report past the bound leaves the check"
        );
        Ok(())
    }

    /// H420: the owner narrows their own bound below their running count.
    /// The next report still lands, and as the first past the narrowed bound
    /// it leaves the typed check. The check used to wait for a count of
    /// exactly bound + 1, which had already gone by.
    #[test]
    fn a_narrowed_bound_still_leaves_the_owners_check() -> Result<()> {
        use rmpv::Value;
        let (_tmp, vault) = open_test_vault_with(embedding_test_config());
        let owner_id = crate::vault::embedded_owner_actor_id()?;
        let peer = entity(0xb3);
        vault.put_entity(
            &peer,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
        vault.put_edge(&owner_id, EdgeKind::Mentions, &peer, 0.5)?;
        let link = EdgeRef::new(owner_id, EdgeKind::Mentions, peer);
        let bound = |limit: i64| {
            crate::test_util::authorize_readers_with(
                &vault,
                &[&owner_id.to_hex()],
                vec![(
                    Value::from("weave_correction_policy"),
                    Value::Map(vec![
                        (Value::from("vault_max"), Value::from(limit)),
                        (Value::from("default"), Value::from(limit)),
                        (Value::from("holders"), Value::Map(Vec::new())),
                        (
                            Value::from("precedence"),
                            Value::from("holder_then_default"),
                        ),
                    ]),
                )],
            );
        };
        let report = || -> Result<()> {
            let owner = vault.authenticate_owner(
                owner_id,
                &owner_id.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )?;
            let read = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
            read.report_wrong_link(&owner, WeaveReader::Owner(&owner), link)?;
            Ok(())
        };
        bound(3);
        report()?;
        report()?;
        let kind = crate::own_rate::OwnRateKind::WeaveCorrection;
        assert!(vault.own_rate_check(owner_id, kind)?.is_none());
        bound(1);
        report()?;
        assert_eq!(
            vault
                .own_rate_check(owner_id, kind)?
                .map(|check| (check.count, check.threshold)),
            Some((3, 1)),
            "FAILBEFORE H420: a narrowed bound left the owner no check"
        );
        Ok(())
    }

    #[test]
    fn revocation_between_report_preflight_and_writer_admission_refuses_label() -> Result<()> {
        let (_tmp, vault, person, link) = fixture()?;
        let auth = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        vault
            .test_hooks()
            .install_before_weave_correction_writer(move || {
                arrived_tx
                    .send(())
                    .expect("test receives pre-writer arrival");
                resume_rx.recv().expect("test resumes correction");
            });
        std::thread::scope(|scope| {
            let attempt = scope.spawn(|| {
                vault
                    .scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap())
                    .report_wrong_link(&auth, WeaveReader::Person(person), link)
            });
            arrived_rx
                .recv()
                .expect("correction reaches writer boundary");
            crate::test_util::authorize_readers(&vault, &[]);
            resume_tx.send(()).expect("correction still waiting");
            assert!(attempt.join().expect("correction thread").is_err());
        });
        assert!(
            vault
                .weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn expired_message_grant_blocks_correction_and_scoped_receipt_without_other_writes()
    -> Result<()> {
        use crate::access_grant::{
            AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
        };
        let clock = crate::ports::ManualClock::new(1_000);
        let mut config = embedding_test_config();
        config.store_clock = clock.bundle();
        let (_tmp, vault) = open_test_vault_with(config);
        let person = entity(0xc1);
        let message = entity(0xc2);
        let space = entity(0xc3);
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        vault
            .memory(person, crate::EdgeActorClass::Human)
            .witness(&crate::memory::WitnessTurn {
                conversation_ref: entity(0xc4).to_hex(),
                turn_ref: None,
                occurred_at: 1_000,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(message.to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "dialogue".into(),
                    content: "grant-bound message".into(),
                    metadata: Some(serde_json::json!({"rel": space.to_hex()})),
                    is_visible: true,
                    order: 0,
                }],
            })
            .expect("witness message");
        vault.put_edge(&person, EdgeKind::Mentions, &message, 0.5)?;
        vault.create_access_grant(
            &entity(0xc5),
            &AccessGrant {
                authority_scope: crate::federation::scope_codec::read_preset(),
                principal_ref: person,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1_000,
                revoked_at: None,
                expires_at: Some(2_000),
            },
        )?;
        crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
        let auth = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let read = vault.scoped_read(
            ScopedReadActorKey::new(person.to_hex())
                .unwrap()
                .require_access_grants(Some(person)),
        );
        let link = EdgeRef::new(person, EdgeKind::Mentions, message);
        let filed = read.report_wrong_link(&auth, WeaveReader::Person(person), link)?;
        assert_eq!(
            read.weave_link_corrections(WeaveReader::Person(person), link)?,
            vec![filed]
        );
        // No grant mutation or other write: the persisted floor stays at 1,000
        // until this door observes the injected clock in its own transaction.
        clock.set(2_001);
        assert!(
            read.report_wrong_link(&auth, WeaveReader::Person(person), link)
                .is_err()
        );
        assert!(
            read.weave_link_corrections(WeaveReader::Person(person), link)
                .is_err()
        );
        let recipe = [WeaveSectionSpec {
            kind: WeaveSectionKind::Links,
            predicates: Vec::new(),
            edge_kinds: vec![EdgeKind::Mentions],
        }];
        assert!(
            !read
                .weave_report(WeaveReader::Person(person), &recipe)?
                .value
                .sections[0]
                .items
                .contains(&WeaveItem::Link {
                    source: person,
                    kind: EdgeKind::Mentions,
                    target: message,
                })
        );
        assert_eq!(
            vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
            vec![filed]
        );
        Ok(())
    }
}

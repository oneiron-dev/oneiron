//! Authenticated wrong-link labels emitted by the live weave report.
use super::{ScopedRead, WeaveItem, WeaveReader, WeaveSectionKind, WeaveSectionSpec};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::provenance::{EDGE_REF_LEN, EdgeRef};
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// Wrong-link labels, keyed by the link's edge ref, then the label's receipt id.
const LABELS: SideTable<([u8; EDGE_REF_LEN], EntityId), StoredCorrection, Named> =
    SideTable::new(&side_table::WEAVE_WRONG_LINK_LABEL);

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

impl ScopedRead<'_> {
    /// File a wrong-link tap only for an authenticated human viewing that live
    /// link in their own report. A caller-chosen edge reference alone grants no
    /// write authority. The persisted label is not an edge retraction.
    ///
    /// Each reader's labels on a link are bounded by the policy, except the
    /// vault owner's: an owner past the bound files anyway, and the first such
    /// report on a link leaves the typed own-rate check.
    pub fn report_wrong_link(
        &self,
        auth: &AuthenticatedOwner,
        reader: WeaveReader<'_>,
        link: EdgeRef,
    ) -> Result<WeaveLinkCorrection> {
        let bound = match &reader {
            WeaveReader::Person(id) => *id == auth.actor(),
            WeaveReader::Owner(owner) => owner.actor() == auth.actor() && *owner == auth,
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
        auth.revalidate_in_txn(self.vault, &txn)?;
        self.require_visible_weave_link_in(&txn, reader, link)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let limit = policy
            .weave_correction_limit(&auth.actor().to_hex())
            .ok_or(Error::InvalidConfig(
                "weave correction policy unavailable".into(),
            ))?;
        // Writers enforce the reader's bound in this SAME serialized txn. The
        // bound is the reader's own: another reader's labels never spend it.
        let own = self
            .vault
            .weave_link_correction_labels_in_txn(&txn, link)?
            .iter()
            .filter(|label| label.actor == auth.actor())
            .count();
        if own >= limit {
            // Capabilities first: the owner's own reports are never refused
            // on count. Every other reader stays bounded.
            if !crate::policy_model::is_live_vault_owner_in_txn(self.vault, &txn, &auth.actor())? {
                return Err(Error::IndexOverflow("weave correction labels"));
            }
            crate::own_rate::observe_in_txn(
                &self.vault.store,
                &mut txn,
                crate::own_rate::OwnRateKind::WeaveCorrection,
                auth.actor(),
                0,
                u64::try_from(own).unwrap_or(u64::MAX).saturating_add(1),
                crate::own_rate::OwnRate {
                    threshold: u64::try_from(limit).unwrap_or(u64::MAX),
                    window_seconds: 0,
                },
            )?;
        }
        let correction = WeaveLinkCorrection {
            id: EntityId::now(),
            link,
            actor: auth.actor(),
            recorded_at: now,
        };
        LABELS.put(
            &self.vault.store,
            &mut txn,
            &(link.encode(), correction.id),
            &StoredCorrection {
                id: correction.id,
                link: link.encode().to_vec(),
                actor: correction.actor,
                recorded_at: correction.recorded_at,
            },
        )?;
        txn.commit()?;
        Ok(correction)
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

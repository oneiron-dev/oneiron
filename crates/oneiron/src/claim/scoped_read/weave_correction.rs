//! Authenticated wrong-link labels emitted by the live weave report.
use super::{ScopedRead, WeaveItem, WeaveReader, WeaveSectionKind, WeaveSectionSpec};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::provenance::EdgeRef;
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"weave:wrong-link:v1:";
const MAX_LABELS: usize = 10_000;

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

fn prefix(link: EdgeRef) -> Vec<u8> {
    [PREFIX, &link.encode()].concat()
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
        let mut txn = self.vault.store.env.write_txn()?;
        auth.revalidate_in_txn(self.vault, &txn)?;
        self.require_visible_weave_link_in(&txn, reader, link)?;
        // Writers enforce the reader's bound in this SAME serialized txn.
        // Refuse a tap before it can make all prior labels unreadable.
        let key_prefix = prefix(link);
        let mut count = 0;
        for row in self.vault.store.vault_meta.prefix_iter(&txn, &key_prefix)? {
            row?;
            count += 1;
            if count >= MAX_LABELS {
                return Err(Error::IndexOverflow("weave correction labels"));
            }
        }
        let correction = WeaveLinkCorrection {
            id: EntityId::now(),
            link,
            actor: auth.actor(),
            recorded_at: self.vault.store.clock.now_recorded_at(),
        };
        let key = [key_prefix, correction.id.as_bytes().to_vec()].concat();
        let bytes = rmp_serde::to_vec_named(&StoredCorrection {
            id: correction.id,
            link: link.encode().to_vec(),
            actor: correction.actor,
            recorded_at: correction.recorded_at,
        })
        .map_err(|_| Error::InvariantViolation("weave correction encode"))?;
        self.vault.store.vault_meta.put(&mut txn, &key, &bytes)?;
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
        let txn = self.vault.store.env.read_txn()?;
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
        let prefix = prefix(link);
        for row in self.store.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, raw) = row?;
            if labels.len() >= MAX_LABELS {
                return Err(Error::IndexOverflow("weave correction labels"));
            }
            let stored: StoredCorrection = rmp_serde::from_slice(&raw)
                .map_err(|_| Error::CorruptedIndex("weave correction label"))?;
            if stored.link != link.encode()
                || key.len() != prefix.len() + stored.id.as_bytes().len()
                || &key[prefix.len()..] != stored.id.as_bytes()
            {
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

    #[test]
    fn last_allowed_label_is_readable_and_next_tap_does_not_write() -> Result<()> {
        let (_tmp, vault, person, link) = fixture()?;
        let auth = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        // Seed the first 9,999 valid encoded receipts in one transaction to
        // reach the production bound without 9,999 independent report scans.
        let mut txn = vault.store.env.write_txn()?;
        for i in 1..MAX_LABELS {
            let id = EntityId::from_bytes((i as u128).to_be_bytes())?;
            let key = [prefix(link), id.as_bytes().to_vec()].concat();
            let bytes = rmp_serde::to_vec_named(&StoredCorrection {
                id,
                link: link.encode().to_vec(),
                actor: person,
                recorded_at: 1,
            })
            .expect("fixture encodes");
            vault.store.vault_meta.put(&mut txn, &key, &bytes)?;
        }
        txn.commit()?;
        let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
        let final_label = read.report_wrong_link(&auth, WeaveReader::Person(person), link)?;
        let labels = read.weave_link_corrections(WeaveReader::Person(person), link)?;
        assert_eq!(labels.len(), MAX_LABELS);
        assert!(labels.contains(&final_label));
        assert!(matches!(
            read.report_wrong_link(&auth, WeaveReader::Person(person), link),
            Err(Error::IndexOverflow("weave correction labels"))
        ));
        assert_eq!(
            vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
            labels
        );
        Ok(())
    }
}

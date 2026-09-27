//! Authenticated wrong-link labels emitted by the live weave report.
use super::{ScopedRead, WeaveItem, WeaveReader, WeaveSectionKind, WeaveSectionSpec};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::provenance::EdgeRef;
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"weave:wrong-link:v1:";

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
        #[cfg(test)]
        self.vault
            .test_hooks()
            .signal_before_weave_correction_writer();
        let mut txn = self.vault.store.env.write_txn()?;
        auth.revalidate_in_txn(self.vault, &txn)?;
        self.require_visible_weave_link_in(&txn, reader, link)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let limit = policy
            .weave_correction_limit(&auth.actor().to_hex())
            .ok_or(Error::InvalidConfig(
                "weave correction policy unavailable".into(),
            ))?;
        // Writers enforce the reader's bound in this SAME serialized txn.
        // Refuse a tap before it can make all prior labels unreadable.
        let key_prefix = prefix(link);
        let mut count = 0;
        for row in self.vault.store.vault_meta.prefix_iter(&txn, &key_prefix)? {
            row?;
            count += 1;
            if count >= limit {
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

    fn set_quota(
        vault: &crate::Vault,
        vault_max: u32,
        default: u32,
        holder: Option<(EntityId, u32)>,
    ) -> Result<()> {
        use crate::ports::EntityStoreRead;
        let id = crate::gate::default_policy_manifest_id()?;
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .port_entity_record(&txn, &id)?
            .expect("seeded manifest");
        let rmpv::Value::Map(mut entries) =
            rmpv::decode::read_value(&mut raw.body.as_slice()).expect("manifest decodes")
        else {
            panic!("manifest map")
        };
        drop(txn);
        entries.retain(|(key, _)| key.as_str() != Some("weave_correction_policy"));
        let holders = holder.map_or_else(Vec::new, |(id, limit)| {
            vec![(rmpv::Value::from(id.to_hex()), rmpv::Value::from(limit))]
        });
        entries.push((
            rmpv::Value::from("weave_correction_policy"),
            rmpv::Value::Map(vec![
                (rmpv::Value::from("vault_max"), rmpv::Value::from(vault_max)),
                (rmpv::Value::from("default"), rmpv::Value::from(default)),
                (rmpv::Value::from("holders"), rmpv::Value::Map(holders)),
            ]),
        ));
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).expect("encodes");
        crate::test_util::put_policy_manifest_bytes(vault, id, &bytes)
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
    fn policy_quota_override_is_capped_at_vault_and_changes_never_hide_old_labels() -> Result<()> {
        let (_tmp, vault, person, link) = fixture()?;
        let auth = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
        // Holder overrides the default of 1, but cannot exceed vault cap 3.
        set_quota(&vault, 3, 1, Some((person, 9)))?;
        let mut labels = Vec::new();
        for _ in 0..3 {
            labels.push(read.report_wrong_link(&auth, WeaveReader::Person(person), link)?);
        }
        assert_eq!(
            read.weave_link_corrections(WeaveReader::Person(person), link)?,
            labels
        );
        assert!(matches!(
            read.report_wrong_link(&auth, WeaveReader::Person(person), link),
            Err(Error::IndexOverflow("weave correction labels"))
        ));
        // Narrow the admission policy below the historic count, without
        // changing what the sieve and the scoped reader can still read.
        set_quota(&vault, 1, 1, None)?;
        assert_eq!(
            read.weave_link_corrections(WeaveReader::Person(person), link)?,
            labels
        );
        assert!(
            read.report_wrong_link(&auth, WeaveReader::Person(person), link)
                .is_err()
        );
        // A later vault edit can raise the limit: 10,000 is not a lifetime cap.
        set_quota(&vault, 4, 4, None)?;
        labels.push(read.report_wrong_link(&auth, WeaveReader::Person(person), link)?);
        assert_eq!(
            read.weave_link_corrections(WeaveReader::Person(person), link)?,
            labels
        );
        assert_eq!(
            vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
            labels
        );
        Ok(())
    }
}

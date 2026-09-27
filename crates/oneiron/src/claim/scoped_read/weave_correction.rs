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
        let recipe = [WeaveSectionSpec {
            kind: WeaveSectionKind::Links,
            predicates: Vec::new(),
            edge_kinds: vec![link.kind],
        }];
        let report = self.weave_report(reader, &recipe)?;
        if !report.value.sections[0].items.iter().any(|item| {
            matches!(item, WeaveItem::Link { source, kind, target }
                if *source == link.source && *kind == link.kind && *target == link.target)
        }) {
            return Err(Error::EntityNotFound);
        }
        let mut txn = self.vault.store.env.write_txn()?;
        auth.revalidate_in_txn(self.vault, &txn)?;
        if !self.live_weave_edge_in(&txn, link.source, link.kind, link.target)? {
            return Err(Error::EntityNotFound);
        }
        let correction = WeaveLinkCorrection {
            id: EntityId::now(),
            link,
            actor: auth.actor(),
            recorded_at: self.vault.store.clock.now_recorded_at(),
        };
        let key = [prefix(link), correction.id.as_bytes().to_vec()].concat();
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
        let recipe = [WeaveSectionSpec {
            kind: WeaveSectionKind::Links,
            predicates: Vec::new(),
            edge_kinds: vec![link.kind],
        }];
        let report = self.weave_report(reader, &recipe)?;
        if !report.value.sections[0].items.iter().any(|item| {
            matches!(item, WeaveItem::Link { source, kind, target }
                if *source == link.source && *kind == link.kind && *target == link.target)
        }) {
            return Err(Error::EntityNotFound);
        }
        self.vault.weave_link_correction_labels(link)
    }
}

impl crate::Vault {
    /// The trusted sieve, child and link loops can consume labels by edge id
    /// even after that edge is retracted. Caller-facing reads use the report
    /// projection above and cannot use this internal unscoped door.
    pub(crate) fn weave_link_correction_labels(
        &self,
        link: EdgeRef,
    ) -> Result<Vec<WeaveLinkCorrection>> {
        let txn = self.store.env.read_txn()?;
        let mut labels = Vec::new();
        let prefix = prefix(link);
        for row in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
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

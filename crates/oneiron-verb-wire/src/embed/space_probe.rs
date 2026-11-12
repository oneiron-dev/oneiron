//! Moved from `crates/oneiron/src/embed/space_probe.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::machine_destination::PeerMachine;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::embedding::EgressDecision;
use oneiron_store::embedding::EgressPredicate;
use oneiron_store::embedding::MediaEmbedReport;
use oneiron_store::embedding::MediaEmbeddingInput;
use oneiron_store::embedding_vocabulary::InputKind;
use oneiron_store::ports::records::EdgeDirection;
use oneiron_wake_contract::settings::destination::ReadDestination;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Longest probe query, in bytes.
pub const SPACE_PROBE_QUERY_MAX_LEN: usize = 2048;

/// One retrieval probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpaceProbe {
    /// The kind of the documents it finds; a move's check runs it for that kind's slot.
    pub kind: InputKind,
    /// A text query, through each space's text tower; beside a media query, what it asks in
    /// words, which may be empty.
    pub query: String,
    /// A stored image or audio ASSET whose bytes are the query, through each space's tower of
    /// that media kind; `None` for a text query. Never one of its targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_media: Option<EntityId>,
    /// Its source family (FIX 9831): for a probe the vault's author wrote, the least source
    /// root of the `DerivedFrom` component its document is in, so a document and those derived
    /// from it, or it from them, are one family; for one put by hand, the document it was
    /// written from.
    pub family: EntityId,
    /// The document the vault's author wrote it from, one of its targets; `None` for a probe
    /// put by hand, whose family is that document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_from: Option<EntityId>,
    /// The other stored rows its query was written from (FIX 9829): the rows its document's
    /// words or bytes are read from, and every record those derive from. Erasing any of them,
    /// its document or its media query erases the probe ([`Self::query_sources`]).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub source_refs: BTreeSet<EntityId>,
    /// Every document that answers the query.
    pub targets: BTreeSet<EntityId>,
    /// The model that wrote it.
    pub author: String,
    /// Vault seconds.
    pub written_at: u64,
    /// Its family's date cut: the start, in vault seconds, of the [`SPACE_PROBE_COHORT_SECS`]
    /// window the vault learned its source document in; `None` for a probe put by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<u64>,
}

impl SpaceProbe {
    /// The probe's id: its kind, family and query, and its media query when it has one.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron/space_probe/v1");
        hasher.update(&[self.kind as u8]);
        hasher.update(self.family.as_bytes());
        hasher.update(self.query.as_bytes());
        if let Some(media) = &self.query_media {
            hasher.update(b"\0query_media");
            hasher.update(media.as_bytes());
        }
        let mut id = [0_u8; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    /// The document its query was written from: the author's, or for a probe put by hand the
    /// family it names.
    #[must_use]
    pub fn document(&self) -> EntityId {
        self.written_from.unwrap_or(self.family)
    }

    /// Every stored row its query was written from: its document, its media query and its
    /// [`Self::source_refs`].
    #[must_use]
    pub fn query_sources(&self) -> BTreeSet<EntityId> {
        let mut sources = self.source_refs.clone();
        sources.insert(self.document());
        sources.extend(self.query_media);
        sources
    }

    fn validate(&self) -> Result<()> {
        let query = self.query.trim();
        if (query.is_empty() && self.query_media.is_none())
            || self.query.len() > SPACE_PROBE_QUERY_MAX_LEN
        {
            return Err(Error::InvalidConfig(format!(
                "a space probe's query must hold 1..={SPACE_PROBE_QUERY_MAX_LEN} bytes of text"
            )));
        }
        if self
            .query_media
            .is_some_and(|media| self.targets.contains(&media))
        {
            return Err(Error::InvalidConfig(
                "a space probe's media query is none of its targets".into(),
            ));
        }
        // Every target it names is kept and run (FIX 8199): no count of them is refused.
        if self.targets.is_empty() {
            return Err(Error::InvalidConfig(
                "a space probe names at least one target document".into(),
            ));
        }
        // A family is a grouping, not always a document that answers (FIX 9831): what the
        // query was written from is.
        if !self
            .query_sources()
            .iter()
            .any(|source| self.targets.contains(source))
        {
            return Err(Error::InvalidConfig(
                "a space probe's query is written from one of its targets".into(),
            ));
        }
        if self.author.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "a space probe names the model that wrote it".into(),
            ));
        }
        Ok(())
    }
}

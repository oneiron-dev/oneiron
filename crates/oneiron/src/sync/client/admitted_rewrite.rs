//! The write over a window of what an admitted part lost to an earlier
//! admission (FEDERATED-ADMISSION-FRESH-DOC-LAMPORT-TIE).
//!
//! Admission authors each part in a fresh document whose peer id derives from
//! the update (FIX 3891), so its operations start at Lamport 0 whatever the
//! window already holds. A key an earlier admission wrote at a higher op
//! index, or at the same one under a larger peer id, kept its old value
//! against the later write: a peer's second image of a row, or its hard delete
//! after its soft one, never landed. After a part imports, each such key is
//! written again over the window, above every operation the window holds. A
//! key whose value any other writer set (this vault, one of its machines)
//! keeps that value, as before.

use super::base::SyncClient;
use super::federated::map_federated_admission_err;
use crate::deletion::decode_tombstone_value;
use crate::error::{Error, Result, SyncEngineContext, SyncError};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::transport::TransportError;
use crate::sync::window::LoadedWindow;
use loro::{
    ExportMode, ID, IdSpan, LoroDoc, LoroMap, LoroValue, PeerID, ValueOrContainer, VersionVector,
};
use oneiron_contracts::fingerprint::ContentHasher;

/// The commit message of a write over a window: a later admission's write to
/// one of its keys is written again over it, as over the admission it wrote.
const REWRITE_MESSAGE: &str = "federation-admission-rewrite:v1";

/// The context a write's peer id derives under.
const REWRITE_PEER_CONTEXT: &str = "oneiron 2026-11-21 federation admission rewrite peer v1";

impl SyncClient {
    /// Imports `part`, an admitted part's bytes, into `window`, then writes
    /// again over the window each key the part lost to an earlier admission.
    /// The write imports as the part did, under the scopes its caller holds,
    /// so each row it lands is judged and attributed as the part's own.
    pub(super) fn import_admitted_part(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        part: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let held = window.doc.oplog_vv();
        self.import_accepted_window_update(window_key, window, part)?;
        match admitted_rewrite(&window.doc, part, &held).map_err(map_federated_admission_err)? {
            Some(rewrite) => self.import_accepted_window_update(window_key, window, &rewrite),
            None => Ok(()),
        }
    }
}

/// The update writing again over `window` each key `part` wrote whose value
/// there an earlier admission set, or `None` when there is none. A part the
/// window held before its import (`held`) writes nothing: its first import
/// wrote what it lost then. So does one the window does not hold after it.
pub(crate) fn admitted_rewrite(
    window: &LoroDoc,
    part: &[u8],
    held: &VersionVector,
) -> Result<Option<Vec<u8>>> {
    let admitted = LoroDoc::new();
    admitted.import(part).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted part",
            source,
        })
    })?;
    // An admitted part is one admission document's, by one peer.
    let authors = admitted.oplog_vv();
    let mut peers = authors.iter();
    let (Some((&author, &end)), None) = (peers.next(), peers.next()) else {
        return Ok(None);
    };
    if held.get(&author).is_some() || window.oplog_vv().get(&author) != Some(&end) {
        return Ok(None);
    }
    let LoroValue::Map(roots) = admitted.get_value() else {
        return Ok(None);
    };
    let mut lost = Vec::new();
    for name in roots.keys() {
        let in_window = window.get_map(name.as_str());
        admitted.get_map(name.as_str()).for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && lost_to_admission(window, &in_window, name, key, &bytes)
            {
                lost.push((name.clone(), key.to_owned(), bytes.to_vec()));
            }
        });
    }
    if lost.is_empty() {
        return Ok(None);
    }
    // One order on every machine: one peer id never writes two payloads.
    lost.sort();
    let target = window.fork();
    let peer = rewrite_peer(author, &target.oplog_vv());
    if target.oplog_vv().get(&peer).is_some() {
        return Ok(None);
    }
    target
        .set_peer_id(peer)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;
    for (name, key, bytes) in &lost {
        map_insert_bytes(&target.get_map(name.as_str()), key, bytes)?;
    }
    target.set_next_commit_message(REWRITE_MESSAGE);
    target.commit();
    let Some(&written) = target.oplog_vv().get(&peer) else {
        return Ok(None);
    };
    target
        .export(ExportMode::updates_in_range(vec![IdSpan::new(
            peer, 0, written,
        )]))
        .map(Some)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))
}

/// Whether the window's value for `key` in its root map `name` differs from
/// `ours`, the part's, and an admission set it. A hard tombstone is never
/// written over by a soft one (ONE-1132 never-downgrade).
fn lost_to_admission(
    window: &LoroDoc,
    in_window: &LoroMap,
    name: &str,
    key: &str,
    ours: &[u8],
) -> bool {
    // Admission only inserts bytes: a key the window deleted or holds
    // another value under was written by another writer.
    let Some(ValueOrContainer::Value(LoroValue::Binary(theirs))) = in_window.get(key) else {
        return false;
    };
    if theirs[..] == *ours {
        return false;
    }
    if name == "tombstones"
        && decode_tombstone_value(&theirs).is_hard()
        && !decode_tombstone_value(ours).is_hard()
    {
        return false;
    }
    in_window
        .get_last_editor(key)
        .is_some_and(|editor| admission_authored(window, editor))
}

/// Whether `peer`'s operations in `window` are an admission's: a fresh
/// admission document's, which depend on nothing and start at Lamport 0, or a
/// write over the window this module made.
fn admission_authored(window: &LoroDoc, peer: PeerID) -> bool {
    window.get_change(ID::new(peer, 0)).is_some_and(|change| {
        (change.deps.is_empty() && change.lamport == 0)
            || change.message.as_deref() == Some(REWRITE_MESSAGE)
    })
}

/// The peer id writing over a window that held `window` when `author`'s part
/// lost keys in it: two machines at one window state write the same
/// operations, and at two states never under one peer id.
fn rewrite_peer(author: PeerID, window: &VersionVector) -> PeerID {
    let mut counters = window
        .iter()
        .map(|(peer, counter)| (*peer, *counter))
        .collect::<Vec<_>>();
    counters.sort_unstable();
    let mut hasher = ContentHasher::new();
    hasher
        .update(REWRITE_PEER_CONTEXT.as_bytes())
        .update(&author.to_be_bytes());
    for (peer, counter) in counters {
        hasher.update(&peer.to_be_bytes());
        hasher.update(&counter.to_be_bytes());
    }
    let hash = hasher.finish().into_bytes();
    let mut low = [0_u8; 8];
    low.copy_from_slice(&hash[..8]);
    // Loro refuses the largest peer id.
    u64::from_be_bytes(low) >> 1
}

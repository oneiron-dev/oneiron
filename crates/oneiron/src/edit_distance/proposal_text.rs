//! ED-00: a proposal artifact's body lives in a `LoroText` container for its
//! proposal→outcome window, and every edit commits under an engine-written
//! actor stamp.
//!
//! # Why the stamp rides the commit MESSAGE
//!
//! Loro carries two pieces of commit metadata. `CommitOptions::origin` is
//! local event metadata — the sync bridge filters live events on it, and it
//! does NOT survive snapshot/reopen. `CommitOptions::commit_msg` is persisted
//! in the durable `Change` record (id / deps / timestamp / commit_msg / ops)
//! and replicates with the doc. Attribution must survive a mid-window
//! snapshot/reopen, so it rides the message. Loro also merges consecutive
//! same-peer changes only when their commit messages are EQUAL, which is what
//! keeps one change from ever mixing two actors' ops.
//!
//! # The window base is the open commit
//!
//! `proposed_ref` cannot be stored inside the doc — writing it would change
//! the very version it names. Instead the opening commit marks itself
//! ([`StampKind::Open`]) and the window base is derived as the version right
//! after that change. A reopened artifact therefore needs nothing but its
//! snapshot bytes. EXACTLY ONE open marker is admissible: the marker is a
//! commit message, and commit messages replicate, so "the latest open marker
//! wins" would let a synced peer move the window base forward over earlier
//! edits. See [`ProposalTextArtifact::finalize`].
//!
//! # Trust
//!
//! Commit messages replicate, so a remote peer can write any stamp it likes.
//! A stamp is honored only when the actor it names is bound to the WRITING peer
//! at commit time — see
//! [`peer_actor_stamp_is_honored`](crate::edit_distance::peer_actor_stamp_is_honored)
//! for the rule and why it is drawn there. A rejected stamp (mismatched or
//! unregistered actor) falls back to the writing peer's own binding, and
//! failing that to the device peer. No public door accepts a caller-supplied
//! stamp string — [`ProposalTextArtifact`] builds every stamp from the
//! authenticated [`WriteActor`] in hand.

use std::ops::ControlFlow;

use loro::{ChangeMeta, CommitOptions, ExportMode, Frontiers, ID, IdSpan, LoroDoc, LoroText};

use super::{
    FinalizedProposalText, LoroOpRef, OpAttribution, OpSpan, ProposalArtifactRef,
    actor_class_from_token, actor_class_token, peer_actor_at, peer_actor_stamp_is_honored,
    put_finalized_proposal_text,
};
use crate::Vault;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::sync::loro_support::{
    doc_from_snapshot, export_snapshot, import_doc, map_get_bytes, map_insert_bytes,
};
use crate::sync::window::PROPOSAL_TEXT_COMMIT_MSG_PREFIX;
use crate::write_envelope::WriteActor;

/// Root container holding the proposal body.
const TEXT_CONTAINER: &str = "proposal_text";
/// Root container holding the artifact header.
const META_CONTAINER: &str = "proposal_meta";
const META_KEY_ARTIFACT: &str = "artifact";
const META_KEY_SOURCE_TURN: &str = "source_turn";

/// Commit-message segment carrying the actor.
const STAMP_ACTOR_PREFIX: &str = "actor=";

/// Which commit of an artifact's life a stamp marks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StampKind {
    /// The single opening commit — also the window base marker.
    Open,
    /// Any later edit.
    Edit,
}

impl StampKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Edit => "edit",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        match token {
            "open" => Some(Self::Open),
            "edit" => Some(Self::Edit),
            _ => None,
        }
    }
}

/// A proposal body under live CRDT editing.
///
/// Holds no derived state: `proposed_ref`, the proposed text and the op
/// window are all read back out of the doc at finalize, so a reopened
/// artifact and a never-closed one behave identically.
pub struct ProposalTextArtifact {
    doc: LoroDoc,
    artifact_ref: ProposalArtifactRef,
    source_turn_ref: Option<EntityId>,
}

impl ProposalTextArtifact {
    /// Opens a new proposal artifact holding `initial`, attributed to `actor`.
    ///
    /// `source_turn_ref` is the TURN/entity the proposal derives from and is
    /// recorded at mint — ED-09's off-record fence probe resolves it by
    /// entity id, so it cannot be back-filled later.
    pub fn open(
        initial: &str,
        actor: &WriteActor,
        source_turn_ref: Option<EntityId>,
    ) -> Result<Self> {
        let doc = LoroDoc::new();
        // Change timestamps are OFF by default and are runtime config, not
        // serialized — so this is re-applied on every reopen too. Attribution
        // resolves the peer's binding as of the commit instant; without
        // timestamps every change would resolve at epoch 0.
        doc.set_record_timestamp(true);

        let artifact_ref = ProposalArtifactRef::mint();
        let meta = doc.get_map(META_CONTAINER);
        map_insert_bytes(
            &meta,
            META_KEY_ARTIFACT,
            artifact_ref.entity_id().as_bytes(),
        )?;
        if let Some(turn) = source_turn_ref {
            map_insert_bytes(&meta, META_KEY_SOURCE_TURN, turn.as_bytes())?;
        }
        // Position 0 of a fresh container: reachable only if a Loro invariant
        // broke, never through caller input.
        doc.get_text(TEXT_CONTAINER)
            .insert(0, initial)
            .map_err(|_| {
                Error::InvariantViolation("proposal artifact initial text insert failed")
            })?;
        commit_stamped(&doc, StampKind::Open, actor);

        Ok(Self {
            doc,
            artifact_ref,
            source_turn_ref,
        })
    }

    /// Reopens an artifact from a snapshot produced by
    /// [`ProposalTextArtifact::export_snapshot`].
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let doc = doc_from_snapshot(bytes)?;
        doc.set_record_timestamp(true);
        let meta = doc.get_map(META_CONTAINER);
        let artifact_ref =
            ProposalArtifactRef::new(meta_entity_id(&meta, META_KEY_ARTIFACT)?.ok_or(
                Error::CorruptedIndex("proposal artifact snapshot missing its artifact ref"),
            )?);
        Ok(Self {
            doc,
            artifact_ref,
            source_turn_ref: meta_entity_id(&meta, META_KEY_SOURCE_TURN)?,
        })
    }

    /// This artifact's durable handle.
    #[must_use]
    pub const fn artifact_ref(&self) -> ProposalArtifactRef {
        self.artifact_ref
    }

    /// The Loro peer id writing this artifact — the id
    /// [`crate::edit_distance::register_peer_actor`] binds.
    #[must_use]
    pub fn peer_id(&self) -> u64 {
        self.doc.peer_id()
    }

    /// The artifact's current text.
    #[must_use]
    pub fn text(&self) -> String {
        self.doc.get_text(TEXT_CONTAINER).to_string()
    }

    /// Applies `edit` to the body and commits it under `actor`'s stamp.
    ///
    /// The commit happens even when `edit` fails: the ops it managed to apply
    /// before failing are already in the pending transaction, and leaving them
    /// there would fold them into the NEXT commit — under whatever actor
    /// happened to write next. Stamping what the actor actually wrote, then
    /// surfacing the failure, keeps attribution honest.
    pub fn edit_as(
        &mut self,
        actor: &WriteActor,
        edit: impl FnOnce(&LoroText) -> Result<()>,
    ) -> Result<()> {
        let outcome = edit(&self.doc.get_text(TEXT_CONTAINER));
        commit_stamped(&self.doc, StampKind::Edit, actor);
        outcome
    }

    /// Exports the artifact for mid-window persistence, through the same
    /// `loro_support` helper the sync layer uses.
    pub fn export_snapshot(&self) -> Result<Vec<u8>> {
        export_snapshot(&self.doc)
    }

    /// Freezes the artifact: resolves the op window, replays it into
    /// per-actor spans, persists the proposed/final pair, and returns the
    /// record.
    ///
    /// Persistence is not optional — ED-09's reservoir resolves its training
    /// pairs from these rows by artifact ref, so a finalize that only returned
    /// the record would silently make the export impossible.
    pub fn finalize(self, vault: &Vault) -> Result<FinalizedProposalText> {
        let proposed_frontiers = self.window_base()?;
        let final_frontiers = self.doc.oplog_frontiers();

        // The base fork doubles as the replay scratch: read the proposed text
        // out of it, then feed it the window one change at a time.
        let scratch = self
            .doc
            .fork_at(&proposed_frontiers)
            .map_err(|_| Error::CorruptedIndex("proposal artifact window base"))?;
        let proposed_text = scratch.get_text(TEXT_CONTAINER).to_string();

        let ops_by_actor =
            self.replay_window(vault, &scratch, &proposed_frontiers, &final_frontiers)?;
        let final_text = self.doc.get_text(TEXT_CONTAINER).to_string();
        if scratch.get_text(TEXT_CONTAINER).to_string() != final_text {
            return Err(Error::InvariantViolation(
                "proposal artifact replay did not reconstruct the final text",
            ));
        }

        let record = FinalizedProposalText {
            artifact_ref: self.artifact_ref,
            proposed_ref: LoroOpRef::from_bytes(proposed_frontiers.encode()),
            final_ref: LoroOpRef::from_bytes(final_frontiers.encode()),
            ops_by_actor,
            proposed_text,
            final_text,
            source_turn_ref: self.source_turn_ref,
        };
        put_finalized_proposal_text(vault, &record)?;
        Ok(record)
    }

    /// The version right after the opening commit — the window's lower bound.
    ///
    /// Fails closed on a SECOND open marker rather than picking one. The marker
    /// rides a commit message, which replicates: a peer that syncs the artifact
    /// can commit its own `open` stamp, and honoring the latest one would move
    /// the base past every edit before it — dropping them out of the window
    /// with no trace. Replay-equality cannot catch that, because replay starts
    /// at the shifted base and reconstructs the final text perfectly from
    /// there. Two open markers means the artifact's history is not the history
    /// this engine wrote, so there is nothing to attribute.
    fn window_base(&self) -> Result<Frontiers> {
        let heads = self.doc.oplog_frontiers().to_vec();
        let mut opens = Vec::new();
        self.doc
            .travel_change_ancestors(&heads, &mut |meta: ChangeMeta| {
                if matches!(
                    parse_stamp(meta.message.as_deref()),
                    Some((StampKind::Open, _))
                ) {
                    opens.push(meta);
                }
                ControlFlow::Continue(())
            })
            .map_err(|_| Error::CorruptedIndex("proposal artifact history"))?;
        match opens.as_slice() {
            [] => Err(Error::CorruptedIndex(
                "proposal artifact has no open commit",
            )),
            [meta] => Ok(Frontiers::from_id(change_last_op(meta)?)),
            _ => Err(Error::CorruptedIndex(
                "proposal artifact has more than one open commit",
            )),
        }
    }

    /// Replays every change in the window into `scratch`, one change at a
    /// time, in causal order — so each span carries the exact text on either
    /// side of its own ops even when the window contains concurrent edits.
    fn replay_window(
        &self,
        vault: &Vault,
        scratch: &LoroDoc,
        from: &Frontiers,
        to: &Frontiers,
    ) -> Result<Vec<(OpAttribution, OpSpan)>> {
        let mut window = self.window_changes(from, to)?;
        window.sort_by_key(|change| (change.lamport, change.peer_id));

        let mut spans = Vec::with_capacity(window.len());
        let mut before_text = scratch.get_text(TEXT_CONTAINER).to_string();
        for change in window {
            let updates = self
                .doc
                .export(ExportMode::updates_in_range(vec![IdSpan::new(
                    change.peer_id,
                    change.counter,
                    change.counter + i32::from(change.len),
                )]))
                .map_err(|_| Error::CorruptedIndex("proposal artifact window export"))?;
            import_doc(scratch, &updates)?;
            let after_text = scratch.get_text(TEXT_CONTAINER).to_string();

            let attribution = self.attribute(vault, &change)?;
            spans.push((
                attribution,
                OpSpan {
                    peer_id: change.peer_id,
                    counter: change.counter,
                    len: u32::from(change.len),
                    lamport: change.lamport,
                    timestamp: change.timestamp,
                    before_text: std::mem::replace(&mut before_text, after_text.clone()),
                    after_text,
                },
            ));
        }
        Ok(spans)
    }

    /// Every change (clipped to the window) between the two versions.
    fn window_changes(&self, from: &Frontiers, to: &Frontiers) -> Result<Vec<WindowChange>> {
        let mut changes = Vec::new();
        for (peer, counters) in &self.doc.find_id_spans_between(from, to).forward {
            let mut counter = counters.start;
            while counter < counters.end {
                let meta = self
                    .doc
                    .get_change(ID::new(*peer, counter))
                    .ok_or(Error::CorruptedIndex("proposal artifact window change"))?;
                let change_end = change_last_op(&meta)?.counter + 1;
                let clipped_end = change_end.min(counters.end);
                changes.push(WindowChange {
                    peer_id: *peer,
                    counter,
                    len: u16::try_from(clipped_end - counter)
                        .map_err(|_| Error::CorruptedIndex("proposal artifact change length"))?,
                    lamport: meta.lamport.saturating_add(lamport_offset(&meta, counter)?),
                    timestamp: meta.timestamp,
                    message: meta.message.as_deref().map(str::to_owned),
                });
                counter = change_end;
            }
        }
        Ok(changes)
    }

    /// Resolves who wrote a change: an honored stamp, else the peer's
    /// registration at commit time, else the device peer.
    fn attribute(&self, vault: &Vault, change: &WindowChange) -> Result<OpAttribution> {
        let at = u64::try_from(change.timestamp).unwrap_or(0);
        if let Some((_, actor)) = parse_stamp(change.message.as_deref())
            && peer_actor_stamp_is_honored(vault, change.peer_id, at, &actor)?
        {
            return Ok(OpAttribution::Stamped(actor));
        }
        Ok(peer_actor_at(vault, change.peer_id, at)?
            .map_or(OpAttribution::DevicePeer, OpAttribution::Registered))
    }
}

/// One change of the window, flattened out of Loro's borrow-bound metadata.
struct WindowChange {
    peer_id: u64,
    counter: i32,
    len: u16,
    lamport: u32,
    timestamp: i64,
    message: Option<String>,
}

fn commit_stamped(doc: &LoroDoc, kind: StampKind, actor: &WriteActor) {
    doc.commit_with(CommitOptions::new().commit_msg(&stamp(kind, actor)));
}

/// The engine-written commit message for one artifact write.
///
/// There is no door that accepts a stamp string: every stamp is built here
/// from an authenticated [`WriteActor`], which is what makes a caller-forged
/// stamp structurally impossible rather than merely rejected.
fn stamp(kind: StampKind, actor: &WriteActor) -> String {
    format!(
        "{PROPOSAL_TEXT_COMMIT_MSG_PREFIX} {} {STAMP_ACTOR_PREFIX}{}.{}",
        kind.as_str(),
        actor.entity_ref().to_hex(),
        actor_class_token(actor.actor_class()),
    )
}

/// Inverse of [`stamp`]. Tolerant by design: any message that is not ours —
/// absent, another layer's, a legacy one — simply carries no stamp.
fn parse_stamp(message: Option<&str>) -> Option<(StampKind, WriteActor)> {
    let mut tokens = message?.split_whitespace();
    if tokens.next() != Some(PROPOSAL_TEXT_COMMIT_MSG_PREFIX) {
        return None;
    }
    let kind = StampKind::parse(tokens.next()?)?;
    let (entity_hex, class_token) = tokens
        .next()?
        .strip_prefix(STAMP_ACTOR_PREFIX)?
        .split_once('.')?;
    let entity_ref = EntityId::from_hex(entity_hex).ok()?;
    Some((
        kind,
        WriteActor::new(entity_ref, actor_class_from_token(class_token)?),
    ))
}

/// The id of a change's LAST op — the version that change advanced the doc to.
fn change_last_op(meta: &ChangeMeta) -> Result<ID> {
    let len = i32::try_from(meta.len)
        .map_err(|_| Error::CorruptedIndex("proposal artifact change length"))?;
    if len < 1 {
        return Err(Error::CorruptedIndex("proposal artifact empty change"));
    }
    Ok(ID::new(meta.id.peer, meta.id.counter + len - 1))
}

/// How far into its change `counter` sits — Lamport clocks advance one per op,
/// so this is also the Lamport offset of a clipped span's first op.
fn lamport_offset(meta: &ChangeMeta, counter: i32) -> Result<u32> {
    u32::try_from(counter - meta.id.counter)
        .map_err(|_| Error::CorruptedIndex("proposal artifact change offset"))
}

fn meta_entity_id(meta: &loro::LoroMap, key: &str) -> Result<Option<EntityId>> {
    let Some(bytes) = map_get_bytes(meta, key) else {
        return Ok(None);
    };
    let bytes: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("proposal artifact meta entity id"))?;
    EntityId::from_bytes(bytes)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("proposal artifact meta entity id"))
}

#[cfg(test)]
mod tests;

//! MCP connector actor registry: cursors, board epochs, and stream proxy.

use super::actors::{
    McpBoardSnapshot, McpConnectorActorRecord, McpConnectorActorRegistrationError,
    McpConnectorActorResolutionError, McpConnectorActorRevokeStatus, McpCredentialFingerprint,
    McpCredentialHashKey, McpResolvedActor,
};
use super::paging::{McpPageContinuation, McpPageCursorError, McpPageCursorState, McpPageSnapshot};
use super::surface::MCP_MAX_LIVE_PAGE_CONTINUATIONS;
use oneiron::context_board::{
    BoardRenderMode, BoardStreamFrame, BoardStreamRegistry, FrameEnqueueOutcome, StreamConnectionId,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

pub struct McpConnectorActorRegistry {
    credential_hash_key: McpCredentialHashKey,
    records: BTreeMap<McpCredentialFingerprint, McpConnectorActorRecord>,
    /// Process-local STREAM state, one connection per registered credential.
    ///
    /// The engine's own registry, not a second implementation: coalescing,
    /// keyframe supersession, and teardown are all its semantics.
    streams: BoardStreamRegistry,
    /// Monotonic board snapshot epochs, keyed by the board/connection identity
    /// the frame belongs to (ONE-1704 M5). No clock reaches this map.
    board_epochs: BTreeMap<StreamConnectionId, McpBoardSnapshot>,
    /// The live producer continuations, keyed by CONNECTION AND CURSOR
    /// (ONE-1704 M6, repaired).
    ///
    /// This registry — the one that already owns the credential key, the STREAM
    /// state, and the board snapshot — is where continuation state belongs;
    /// there is no second registry. A handle is minted here, consumed ONCE
    /// here, and dropped with the connection it belongs to.
    ///
    /// One connection owns as MANY outstanding continuations as it minted: a
    /// per-connection "latest row" made a second `More` page silently destroy
    /// the first one's handle, so two live reads could not be interleaved and a
    /// refused presentation could consume an unrelated cursor. The key carries
    /// the connection, so no connector can name another's handle.
    ///
    /// The set one connection owns is BOUNDED by
    /// [`MCP_MAX_LIVE_PAGE_CONTINUATIONS`]; see
    /// [`McpConnectorActorRegistry::make_room_for_page_continuation`].
    page_continuations: BTreeMap<(StreamConnectionId, String), McpPageContinuation>,
    /// Monotonic mint counter for the retention bound's eviction order. It
    /// orders mints within this registry and is never published, never a clock,
    /// and never part of a cursor token.
    page_continuation_seq: u64,
}

impl fmt::Debug for McpConnectorActorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpConnectorActorRegistry")
            .field("credential_hash_key", &"<redacted>")
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl McpConnectorActorRegistry {
    #[must_use]
    pub fn new(credential_hash_key: McpCredentialHashKey) -> Self {
        Self {
            credential_hash_key,
            records: BTreeMap::new(),
            streams: BoardStreamRegistry::default(),
            board_epochs: BTreeMap::new(),
            page_continuations: BTreeMap::new(),
            page_continuation_seq: 0,
        }
    }

    /// Mints and RETAINS one BOUND continuation handle for this connection
    /// (ONE-1704 M6).
    ///
    /// The token is a domain-separated KEYED hash over every input the
    /// continuation is only valid for — the registered credential's
    /// fingerprint-derived connection, the endpoint tool, the canonical
    /// argument bytes with the entire page member excluded, the producer
    /// snapshot epoch, and the successor position — so it is opaque,
    /// unforgeable without this registry's credential key, and publishes no
    /// offset. The retained row is what makes it consumable exactly once.
    pub fn mint_page_cursor(
        &mut self,
        connection: &StreamConnectionId,
        tool: &str,
        argument_digest: [u8; 32],
        snapshot_epoch: u64,
        position: u32,
    ) -> String {
        self.mint_page_cursor_with_snapshot(
            connection,
            tool,
            argument_digest,
            snapshot_epoch,
            position,
            None,
        )
    }

    /// Mints a cursor while retaining the exact producer result it continues.
    /// The old five-argument method remains useful for registry-only callers;
    /// gateway continuations always use this snapshot-bearing form.
    ///
    /// The retention this mint adds is BOUNDED: see
    /// [`Self::make_room_for_page_continuation`].
    pub(crate) fn mint_page_cursor_with_snapshot(
        &mut self,
        connection: &StreamConnectionId,
        tool: &str,
        argument_digest: [u8; 32],
        snapshot_epoch: u64,
        position: u32,
        snapshot: Option<McpPageSnapshot>,
    ) -> String {
        let cursor =
            self.page_cursor_token(connection, tool, argument_digest, snapshot_epoch, position);
        let key = (connection.clone(), cursor.clone());
        // Re-minting the SAME handle — same connection, tool, arguments,
        // producer epoch, and position — replaces its row in place and is not a
        // second retention, so it never evicts a sibling.
        if !self.page_continuations.contains_key(&key) {
            self.make_room_for_page_continuation(connection);
        }
        self.page_continuation_seq = self.page_continuation_seq.saturating_add(1);
        let minted_seq = self.page_continuation_seq;
        self.page_continuations.insert(
            key,
            McpPageContinuation {
                cursor: cursor.clone(),
                tool: tool.to_owned(),
                argument_digest,
                snapshot_epoch,
                position,
                snapshot,
                minted_seq,
            },
        );
        cursor
    }

    /// Enforces this connection's continuation retention bound BEFORE one more
    /// handle is retained (ONE-1704 repair).
    ///
    /// The policy is EXPLICIT and deterministic: a connection holds at most
    /// [`MCP_MAX_LIVE_PAGE_CONTINUATIONS`] outstanding handles, and the mint
    /// that would exceed it evicts this connection's OLDEST-minted handles
    /// until there is room for exactly one more. Eviction is chosen over
    /// refusing the mint because refusing it would publish a `More` end marker
    /// with no handle to continue from — a page a caller can neither finish nor
    /// re-enter — while an evicted handle stays fail-closed at the door: the
    /// next presentation of it is [`McpPageCursorError::Unknown`], never a
    /// silent restart at page one that would re-ship rows the caller already
    /// has and then call the enumeration complete.
    ///
    /// Only THIS connection's rows are considered and only its own oldest rows
    /// are dropped, so one connector's mint pattern can never evict another's
    /// continuation, and nothing here weakens the connector/tool/argument/
    /// producer binding or the one-time consumption a surviving handle carries.
    fn make_room_for_page_continuation(&mut self, connection: &StreamConnectionId) {
        while self.live_page_continuations(connection) >= MCP_MAX_LIVE_PAGE_CONTINUATIONS {
            let Some(oldest) = self
                .page_continuations
                .iter()
                .filter(|((owner, _), _)| owner == connection)
                .min_by_key(|(_, state)| state.minted_seq)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.page_continuations.remove(&oldest);
        }
    }

    /// Consumes one presented continuation handle and returns the producer
    /// position it continues from, pinning the producer snapshot epoch the
    /// caller expects.
    ///
    /// # Errors
    ///
    /// Returns [`McpPageCursorError`] when the handle is unknown to this
    /// connection, already consumed (replay), or bound to another tool,
    /// argument set, or snapshot epoch. Every one of those is a refusal; none
    /// silently restarts at page one.
    pub fn consume_page_cursor(
        &mut self,
        connection: &StreamConnectionId,
        tool: &str,
        argument_digest: [u8; 32],
        snapshot_epoch: u64,
        cursor: &str,
    ) -> Result<u32, McpPageCursorError> {
        Ok(self
            .consume_page_cursor_state(
                connection,
                tool,
                argument_digest,
                Some(snapshot_epoch),
                cursor,
            )?
            .position)
    }

    /// Consumes a cursor and returns its retained producer snapshot. This is
    /// the pre-dispatch door: the gateway calls it before it invokes any facade,
    /// board dispatcher, stream operation, or vault write.
    ///
    /// `expected_snapshot_epoch` is the epoch the CALLER pins. `None` — what
    /// the gateway passes — validates against the IMMUTABLE producer snapshot
    /// retained with this handle, which is the only snapshot the continuation
    /// is a continuation of. The latest board epoch of an unrelated later
    /// render is deliberately not consulted: a board mutation elsewhere cannot
    /// invalidate a page that is served from retained producer rows, and
    /// letting it did exactly that. Producer identity stays enforced by the
    /// connection, tool, argument digest, and the keyed token over the retained
    /// epoch and position.
    ///
    /// # Errors
    ///
    /// Returns [`McpPageCursorError`] on any mismatch. A refusal consumes
    /// NOTHING: this connection's other live continuations survive it.
    pub(crate) fn consume_page_cursor_state(
        &mut self,
        connection: &StreamConnectionId,
        tool: &str,
        argument_digest: [u8; 32],
        expected_snapshot_epoch: Option<u64>,
        cursor: &str,
    ) -> Result<McpPageCursorState, McpPageCursorError> {
        // A handle minted for another connection is unknown HERE: the key
        // carries the credential's own fingerprint-derived connection, so no
        // connector can present another connector's continuation, and no
        // sibling cursor of this connection is touched by a lookup miss.
        let key = (connection.clone(), cursor.to_owned());
        let Some(state) = self.page_continuations.get(&key) else {
            return Err(McpPageCursorError::Unknown);
        };
        if state.cursor != cursor {
            return Err(McpPageCursorError::Unknown);
        }
        if state.tool != tool {
            return Err(McpPageCursorError::ToolMismatch);
        }
        if state.argument_digest != argument_digest {
            return Err(McpPageCursorError::ArgumentsMismatch);
        }
        let snapshot_epoch = state.snapshot_epoch;
        if expected_snapshot_epoch.is_some_and(|expected| expected != snapshot_epoch) {
            return Err(McpPageCursorError::SnapshotMismatch);
        }
        // The retained row must ALSO agree with the keyed mint over exactly
        // these inputs, so a stored row can never admit a token this key would
        // not have produced for this position.
        let position = state.position;
        let expected =
            self.page_cursor_token(connection, tool, argument_digest, snapshot_epoch, position);
        if expected != cursor {
            return Err(McpPageCursorError::Unknown);
        }
        let snapshot = state.snapshot.clone();
        // One-time use: the same handle presented twice is a replay refusal.
        // Only THIS cursor's row is removed.
        self.page_continuations.remove(&key);
        Ok(McpPageCursorState {
            position,
            snapshot_epoch,
            snapshot,
        })
    }

    /// True while this connection still holds at least one live continuation.
    #[must_use]
    pub fn page_continuation_live(&self, connection: &StreamConnectionId) -> bool {
        self.live_page_continuations(connection) > 0
    }

    /// True while this connection still holds THIS exact continuation handle.
    #[must_use]
    pub fn page_continuation_live_cursor(
        &self,
        connection: &StreamConnectionId,
        cursor: &str,
    ) -> bool {
        self.page_continuations
            .contains_key(&(connection.clone(), cursor.to_owned()))
    }

    /// How many continuations this connection currently owns. A connection may
    /// hold several at once, one per outstanding `More` page.
    #[must_use]
    pub fn live_page_continuations(&self, connection: &StreamConnectionId) -> usize {
        self.page_continuations
            .keys()
            .filter(|(owner, _)| owner == connection)
            .count()
    }

    pub(super) fn page_cursor_token(
        &self,
        connection: &StreamConnectionId,
        tool: &str,
        argument_digest: [u8; 32],
        snapshot_epoch: u64,
        position: u32,
    ) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.credential_hash_key.0);
        hasher.update(b"oneiron.mcp.page-cursor.v2");
        hasher.update(&(connection.0.len() as u64).to_be_bytes());
        hasher.update(connection.0.as_bytes());
        hasher.update(&(tool.len() as u64).to_be_bytes());
        hasher.update(tool.as_bytes());
        hasher.update(&argument_digest);
        hasher.update(&snapshot_epoch.to_be_bytes());
        hasher.update(&position.to_be_bytes());
        let digest = hasher.finalize();
        let mut cursor = String::with_capacity(38);
        cursor.push_str("mcpc1:");
        for byte in &digest.as_bytes()[..16] {
            let _ = write!(cursor, "{byte:02x}");
        }
        cursor
    }

    /// The board snapshot epoch for one board/connection identity, given the
    /// board STATE this call rendered (ONE-1704 M5).
    ///
    /// Monotonic and state-derived: an unchanged state keeps its epoch however
    /// far the clock has moved, a changed state advances by exactly one however
    /// little the clock has moved, and a clock that runs backwards cannot make
    /// any epoch go back — nothing here reads a clock at all.
    pub fn board_snapshot_epoch(
        &mut self,
        connection: &StreamConnectionId,
        state_hash: [u8; 32],
    ) -> u64 {
        match self.board_epochs.get_mut(connection) {
            Some(snapshot) => {
                if snapshot.state_hash != state_hash {
                    snapshot.epoch = snapshot.epoch.saturating_add(1);
                    snapshot.state_hash = state_hash;
                }
                snapshot.epoch
            }
            None => {
                self.board_epochs.insert(
                    connection.clone(),
                    McpBoardSnapshot {
                        epoch: 1,
                        state_hash,
                    },
                );
                1
            }
        }
    }

    /// The retained snapshot a later `board.expand`/`board.refresh` fences
    /// against. `None` before this connection has ever rendered a board.
    #[must_use]
    pub fn board_snapshot(&self, connection: &StreamConnectionId) -> Option<McpBoardSnapshot> {
        self.board_epochs.get(connection).copied()
    }

    pub fn register(
        &mut self,
        credential: impl Into<String>,
        record: McpConnectorActorRecord,
    ) -> Result<(), McpConnectorActorRegistrationError> {
        let credential = credential.into();
        let Some(credential) = normalize_credential(&credential) else {
            return Err(McpConnectorActorRegistrationError::EmptyCredential);
        };
        let fingerprint = self.fingerprint_credential(credential);
        if self.records.contains_key(&fingerprint) {
            return Err(McpConnectorActorRegistrationError::DuplicateCredential);
        }
        // Registration is what mints the STREAM connection; the id is the
        // fingerprint's, so nothing on the wire can claim another one. The
        // ALLOWED set is the credential's own scope ceiling, never
        // `SubscriptionScope::ALL` for a narrowed credential: the engine's
        // registry refuses any later subscribe outside what is stored here.
        self.streams.attach_connection(
            fingerprint.stream_connection(),
            BoardRenderMode::Stream,
            record.actor_ref.to_hex(),
            record.scope.subscription_ceiling(),
            0,
        );
        self.records.insert(fingerprint, record);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        credential: &str,
        revoked_at: u64,
    ) -> Result<McpConnectorActorRevokeStatus, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get_mut(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if let Some(existing_revoked_at) = record.revoked_at {
            return Ok(McpConnectorActorRevokeStatus::AlreadyRevoked {
                revoked_at: existing_revoked_at,
            });
        }

        record.revoked_at = Some(revoked_at);
        // A revoked connector keeps no queued frames, no board snapshot, and no
        // live continuation: the STREAM and paging state go with the authority
        // that minted them.
        self.streams.detach(&fingerprint.stream_connection());
        self.board_epochs.remove(&fingerprint.stream_connection());
        self.drop_page_continuations(&fingerprint.stream_connection());
        Ok(McpConnectorActorRevokeStatus::Revoked)
    }

    pub fn resolve(
        &self,
        credential: &str,
        now: u64,
        actor_ceiling_exists: impl FnOnce(&str, &str) -> bool,
    ) -> Result<McpResolvedActor, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if record.is_revoked() {
            return Err(McpConnectorActorResolutionError::RevokedCredential);
        }
        if record.is_expired(now) {
            return Err(McpConnectorActorResolutionError::ExpiredCredential);
        }

        let gate_actor_class = record.gate_actor_class();
        let gate_actor_ref = record.gate_actor_ref();
        if !actor_ceiling_exists(gate_actor_class, &gate_actor_ref) {
            return Err(McpConnectorActorResolutionError::MissingActorCeiling);
        }

        Ok(McpResolvedActor {
            actor_ref: record.actor_ref,
            actor_class: record.actor_class,
            gate_actor_class,
            gate_actor_ref,
            scope: record.scope.clone(),
            stream_connection: fingerprint.stream_connection(),
            bound_verbs: record.bound_verbs.clone(),
            subscription_ceiling: record.scope.subscription_ceiling(),
        })
    }

    pub fn unregister(&mut self, credential: &str) -> bool {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return false;
        };
        let removed = self.records.remove(&fingerprint).is_some();
        if removed {
            self.streams.detach(&fingerprint.stream_connection());
            self.board_epochs.remove(&fingerprint.stream_connection());
            self.drop_page_continuations(&fingerprint.stream_connection());
        }
        removed
    }

    /// Drops EVERY continuation this connection owns. Teardown takes the whole
    /// set with the authority that minted it, not just the newest handle.
    fn drop_page_continuations(&mut self, connection: &StreamConnectionId) {
        self.page_continuations
            .retain(|(owner, _), _| owner != connection);
    }

    pub fn prune_revoked_or_expired(&mut self, now: u64) -> usize {
        let stale = self
            .records
            .iter()
            .filter(|(_, record)| record.is_stale(now))
            .map(|(fingerprint, _)| *fingerprint)
            .collect::<Vec<_>>();
        for fingerprint in &stale {
            self.records.remove(fingerprint);
            self.streams.detach(&fingerprint.stream_connection());
            self.board_epochs.remove(&fingerprint.stream_connection());
            self.drop_page_continuations(&fingerprint.stream_connection());
        }
        stale.len()
    }

    /// True while this credential still owns a live process-local STREAM
    /// connection.
    #[must_use]
    pub fn stream_connection_attached(&self, credential: &str) -> bool {
        self.fingerprint_lookup_credential(credential)
            .is_some_and(|fingerprint| {
                self.streams
                    .connection_state(&fingerprint.stream_connection())
                    .is_some()
            })
    }

    /// Queues one frame on a connector's carrier lane, with the engine's own
    /// coalescing: a keyframe supersedes everything queued behind it.
    pub fn enqueue_stream_frame(
        &mut self,
        connection: &StreamConnectionId,
        frame: BoardStreamFrame,
    ) -> FrameEnqueueOutcome {
        self.streams.enqueue(connection, frame)
    }

    /// Takes EXACTLY ONE pending coalesced carrier payload (ONE-1704 M7).
    ///
    /// One successful result rides at most one frame, and the engine's own
    /// coalescing buffer is what decides which: it hands a pending KEYFRAME
    /// back first and keeps the delta rows accumulated behind it for the next
    /// drain. Those rows are a NEWER transition than the keyframe renders —
    /// the engine's router enqueues own-task/child deltas at the retained
    /// keyframe's current epoch — so the server takes one payload and leaves
    /// the remainder queued for the NEXT successful result instead of draining
    /// it away. The only legitimate drop stays engine-side: a newer keyframe
    /// push clears the deltas it supersedes. No server branch discards a valid
    /// engine payload.
    pub fn next_carrier_frame(
        &mut self,
        connection: &StreamConnectionId,
    ) -> Option<BoardStreamFrame> {
        self.streams.next_carrier_payload(connection)
    }

    /// The engine STREAM registry, for verbs the engine itself dispatches.
    pub fn streams_mut(&mut self) -> &mut BoardStreamRegistry {
        &mut self.streams
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn fingerprint_lookup_credential(&self, credential: &str) -> Option<McpCredentialFingerprint> {
        normalize_credential(credential).map(|credential| self.fingerprint_credential(credential))
    }

    fn fingerprint_credential(&self, credential: &str) -> McpCredentialFingerprint {
        McpCredentialFingerprint(
            *blake3::keyed_hash(&self.credential_hash_key.0, credential.as_bytes()).as_bytes(),
        )
    }
}

fn normalize_credential(credential: &str) -> Option<&str> {
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

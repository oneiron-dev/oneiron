//! The guarded transport's constructors: the socket, its revocation registry,
//! and what each consult then asks of the served vault.

use std::sync::Arc;

use axum::extract::ws::Message as WsMessage;
use futures_util::{SinkExt, Stream};
use oneiron::sync::transport::{LinkBytes, MAX_CODEC_INNER_BYTES, WireCodecs};

use super::{GuardedTransport, WS_WRITE_BUFFER_SIZE, live_person};
use crate::auth::RevokedTokenJtis;

impl<S, E> GuardedTransport<S>
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
{
    pub(in crate::handler) fn new(
        socket: S,
        revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti: Option<String>,
        conn_id: u32,
    ) -> Self {
        Self::with_write_through_threshold(
            socket,
            revoked,
            session_jti,
            conn_id,
            WS_WRITE_BUFFER_SIZE,
        )
    }

    /// The constructor that names the threshold, for a socket built with a
    /// `write_buffer_size` other than [`WS_WRITE_BUFFER_SIZE`].
    ///
    /// The two must be the SAME number: this is the guard's model of the
    /// codec's write-through point, and a guard modelling a different socket
    /// than the one it holds guarantees nothing.
    pub(in crate::handler) fn with_write_through_threshold(
        socket: S,
        revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti: Option<String>,
        conn_id: u32,
        write_through_threshold: usize,
    ) -> Self {
        Self {
            socket: Some(socket),
            revoked,
            session_jti,
            vault: None,
            live_owner: None,
            live_member: None,
            live_person: None,
            app_jti: None,
            answer: None,
            conn_id,
            write_through_threshold,
            peer_codecs: WireCodecs::NONE,
            max_inner: MAX_CODEC_INNER_BYTES,
            link_bytes: LinkBytes::default(),
            refused: None,
        }
    }

    /// Caps what an inbound codec frame may unwrap to: the socket's own
    /// `max_frame_size`, so a compressed frame never carries more than a plain
    /// one could (ARCH-0081 §7).
    pub(in crate::handler) fn with_inbound_cap(mut self, max_inner: usize) -> Self {
        self.max_inner = max_inner.min(MAX_CODEC_INNER_BYTES);
        self
    }

    /// Serves `vault`, and `owner`, its managed attested owner, when there is
    /// one: every consult then asks `vault` whether its Owners deleted it
    /// (FIX 1930) and whether he is still its live owner, so a session no
    /// token id names is never unguarded.
    pub(in crate::handler) fn with_live_owner(
        mut self,
        vault: &Arc<oneiron::Vault>,
        owner: Option<crate::auth::CoreAuth>,
    ) -> Self {
        self.vault = Some(Arc::clone(vault));
        self.live_owner = owner;
        self
    }

    /// Serves the member lane `lane`, when there is one: every consult then
    /// asks the served vault whether the lane still stands. Set after
    /// [`Self::with_live_owner`], which names the vault.
    pub(in crate::handler) fn with_member_lane(
        mut self,
        lane: Option<Arc<crate::handler::member_lane::MemberLane>>,
    ) -> Self {
        self.live_member = lane;
        self
    }

    /// Tracks an admitted member's lifetime without refusing an invitee.
    pub(in crate::handler) fn with_live_person(
        mut self,
        holder: Option<oneiron::EntityId>,
    ) -> Self {
        self.live_person = self
            .vault
            .as_deref()
            .zip(holder)
            .map(|(vault, holder)| live_person::LivePerson::new(vault, holder));
        self
    }
}

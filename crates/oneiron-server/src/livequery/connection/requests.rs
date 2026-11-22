//! Subscription requests on a socket: control dispatch, request application,
//! push framing, and subscription identity.
use super::*;

impl Connection {
    pub(crate) fn control(
        &mut self,
        auth: &CoreAuth,
        request: SubRequest,
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let id = request.id();
        let result = auth
            .require(CoreScope::Read)
            .map_err(AppError::from)
            .and_then(|()| self.apply(auth, request));
        // A turn the request did not use goes back to its line.
        self.give_back();
        self.session_turn = None;
        self.subscription_turn = None;
        self.resumed = None;
        self.waited_out = false;
        match result {
            Ok(pushes) => self.frames(pushes),
            Err(error) => Ok(vec![sub_error(id, error)?]),
        }
    }

    fn apply(&mut self, auth: &CoreAuth, request: SubRequest) -> Result<Vec<Push>, AppError> {
        let id = request.id();
        let opening = matches!(&request, SubRequest::Open { .. });
        if opening && std::mem::take(&mut self.waited_out) {
            return Err(AppError::waited_out());
        }
        if self.session.is_none() {
            if let SubRequest::Open { cursor, .. } = &request {
                self.session = Some(self.hub.session(
                    auth,
                    self.conn_id,
                    cursor.as_ref(),
                    self.session_turn.take(),
                    self.resumed.take(),
                )?);
            } else if matches!(&request, SubRequest::Close { .. }) {
                return Ok(Vec::new());
            } else {
                return Err(AppError::not_found("subscription", None));
            }
        }
        let session = self.session.as_ref().ok_or_else(unavailable)?;
        if !session.auth.same_authority(auth)
            || session.attached.load(Ordering::Acquire) != self.conn_id
        {
            return Err(AppError::unauthorized());
        }
        if !opening && !self.active.contains_key(&id) {
            return Err(AppError::not_found("subscription", None));
        }
        let closing = matches!(&request, SubRequest::Close { .. });
        let pushes = match request {
            SubRequest::Open {
                scoped_view,
                channel,
                cursor,
                origin,
                ..
            } => {
                let server = self.hub.server.upgrade().ok_or_else(unavailable)?;
                let memory = bound_memory(server.vault(), auth)?;
                memory.subscribe(
                    &SocketOwner {
                        queries: &session.queries,
                        channel,
                        cursor,
                        origin,
                        turn: std::cell::Cell::new(self.subscription_turn.take()),
                    },
                    id,
                    scoped_view,
                )?
            }
            SubRequest::Close { .. } => {
                let server = self.hub.server.upgrade().ok_or_else(unavailable)?;
                let memory = bound_memory(server.vault(), auth)?;
                memory.unsubscribe(
                    &SocketOwner {
                        queries: &session.queries,
                        channel: Channel::View,
                        cursor: None,
                        origin: None,
                        turn: std::cell::Cell::new(None),
                    },
                    id,
                )?;
                Vec::new()
            }
            request => session.queries.control(request)?,
        };
        if opening {
            self.incarnations += 1;
            self.active.insert(id, self.incarnations);
            self.sent.remove(&id);
            self.withheld.remove(&id);
        }
        if closing {
            self.active.remove(&id);
            self.sent.remove(&id);
            self.withheld.remove(&id);
        }
        Ok(pushes)
    }

    /// Each push's frames, routed to this socket's release with the
    /// subscription's incarnation and the rows the push was derived from.
    pub(super) fn frames(&mut self, pushes: Vec<Push>) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let mut frames = Vec::new();
        for push in pushes {
            let incarnation = self.active.get(&push.subscription_id).copied();
            frames.extend(push.encode()?.into_iter().map(|frame| {
                super::super::routing::wrap(
                    self.conn_id,
                    push.subscription_id,
                    incarnation.unwrap_or_default(),
                    Some(push.rows.as_slice()),
                    frame,
                )
            }));
            let entry = self
                .sent
                .entry(push.subscription_id)
                .or_insert_with(|| (push.cursor.batch, BTreeSet::new()));
            if entry.0 != push.cursor.batch {
                *entry = (push.cursor.batch, BTreeSet::new());
            }
            entry.1.insert(push.kind);
        }
        Ok(frames)
    }

    pub(crate) const fn conn_id(&self) -> u32 {
        self.conn_id
    }

    /// The open instance of subscription `id` on this socket, for a call the
    /// bound credential `auth` makes over it (FIX 2612 (b)):
    /// `socket:<conn>:sub:<id>:open:<incarnation>`, so each reopen is a new
    /// instance. Host-only: the socket names it from its own table, never
    /// from the request's id, a cursor's document or a kept session. `None`
    /// when `id` is not open here, or this socket's session is no longer
    /// `auth`'s or no longer attached to it.
    pub(crate) fn subscription_instance(&self, auth: &CoreAuth, id: u64) -> Option<String> {
        let session = self.session.as_ref()?;
        if !session.auth.same_authority(auth)
            || session.attached.load(Ordering::Acquire) != self.conn_id
        {
            return None;
        }
        let incarnation = self.active.get(&id)?;
        Some(format!(
            "socket:{}:sub:{id}:open:{incarnation}",
            self.conn_id
        ))
    }

    pub(crate) fn is_scoped_broadcast(data: &[u8]) -> bool {
        super::super::routing::is_routed(data)
    }
}

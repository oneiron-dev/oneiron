//! One admitted Soniox socket segment.

use super::*;

/// One socket and the lease its audio is metered on.
pub(super) struct Segment {
    pub(super) stream: LeasedAsrStream<SonioxAsrClient<queues::Outbox>>,
    pub(super) socket: Socket,
    /// What it sent that Soniox has not made final.
    pub(super) journal: queues::Journal,
    /// Its end is queued: it is read on until `finished`.
    pub(super) ending: bool,
}

impl Segment {
    /// Admitted first, so a refused stream opens no socket; its config is
    /// the first frame queued.
    pub(super) async fn open(
        rung: Arc<SonioxRung>,
        door: Arc<dyn VoiceStreamDoor>,
        route: MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
        spool: Arc<AudioSpool>,
        vault: Arc<Vault>,
    ) -> oneiron::Result<Self> {
        let mut outbox = queues::Outbox::new(Arc::clone(&spool), Arc::clone(&vault));
        outbox.push_text(rung.config(sample_rate, channels))?;
        let stream = LeasedAsrStream::open(
            &*door,
            &route,
            sample_rate,
            channels,
            SonioxAsrClient::new(outbox),
        )
        .await?;
        let mut request = rung
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| invalid("base_url is not a socket request"))?;
        for (name, value) in &rung.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let (socket, _) =
            tokio::time::timeout(rung.timeout, tokio_tungstenite::connect_async(request))
                .await
                .map_err(|_| invalid("the socket did not open in time"))?
                .map_err(|error| invalid(&format!("the socket did not open: {error}")))?;
        Ok(Self {
            stream,
            socket,
            journal: queues::Journal::new(sample_rate, channels, spool, vault),
            ending: false,
        })
    }

    /// Sends what the outbox holds, as far as the socket takes it now.
    /// Each frame leaves the outbox only once the socket has room for it,
    /// so a poll dropped part-way loses none. Whether any frame went out.
    pub(super) fn send(&mut self, cx: &mut Context<'_>) -> oneiron::Result<bool> {
        let mut sent = false;
        loop {
            if self.stream.inner_mut().transport().frames.is_empty() {
                break;
            }
            match Pin::new(&mut self.socket).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Err(socket_error(&error)),
                Poll::Pending => break,
            }
            let Some(frame) = self.stream.inner_mut().transport_mut().pop() else {
                break;
            };
            // A spilled frame is read back only now, for the socket; one
            // that cannot be read waits for the next segment unsent.
            let frame = match frame {
                queues::OutFrame::Audio(audio) => match audio.bytes() {
                    Ok(pcm) => {
                        self.journal.record_audio(&pcm);
                        Message::binary(pcm)
                    }
                    Err(error) => {
                        self.stream
                            .inner_mut()
                            .transport_mut()
                            .push_front(queues::OutFrame::Audio(audio));
                        return Err(error);
                    }
                },
                queues::OutFrame::Text(text) => {
                    self.journal.record_text(&text);
                    Message::text(text)
                }
            };
            Pin::new(&mut self.socket)
                .start_send(frame)
                .map_err(|error| socket_error(&error))?;
            sent = true;
        }
        // Also carries the pong a ping is answered with.
        if let Poll::Ready(Err(error)) = Pin::new(&mut self.socket).poll_flush(cx) {
            return Err(socket_error(&error));
        }
        Ok(sent)
    }

    /// The socket's next frame, once what is queued went out as far as the
    /// socket takes it, with a keepalive after [`KEEPALIVE_AFTER`] quiet. A
    /// frame that does not parse is an error, not a drop.
    pub(super) fn poll_heard(
        &mut self,
        quiet: &mut Pin<Box<tokio::time::Sleep>>,
        cx: &mut Context<'_>,
    ) -> Poll<oneiron::Result<Heard>> {
        loop {
            match self.send(cx) {
                Ok(true) => quiet
                    .as_mut()
                    .reset(tokio::time::Instant::now() + KEEPALIVE_AFTER),
                Ok(false) => {}
                Err(error) => return Poll::Ready(Ok(Heard::Dropped(error))),
            }
            if !self.ending && quiet.as_mut().poll(cx).is_ready() {
                self.stream
                    .inner_mut()
                    .transport_mut()
                    .push_text(r#"{"type":"keepalive"}"#.to_owned())?;
                quiet
                    .as_mut()
                    .reset(tokio::time::Instant::now() + KEEPALIVE_AFTER);
                continue;
            }
            let text = match Pin::new(&mut self.socket).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(Message::Text(text)))) => text,
                // The pong a ping asks for goes out with the next send.
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => {
                    continue;
                }
                Poll::Ready(None | Some(Ok(Message::Binary(_) | Message::Close(_)))) => {
                    return Poll::Ready(Ok(Heard::Dropped(invalid("the socket closed early"))));
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Ok(Heard::Dropped(socket_error(&error))));
                }
            };
            let frame: serde_json::Value =
                serde_json::from_str(text.as_str()).map_err(|_| invalid("a frame is not JSON"))?;
            if let Some(refusal) = quota::classify_soniox_limit(&frame) {
                return Poll::Ready(Ok(Heard::Limited(refusal)));
            }
            return Poll::Ready(Ok(match retriable_error(&frame) {
                Some(error) => Heard::Dropped(error),
                None => Heard::Frame(frame),
            }));
        }
    }
}

/// What a segment's socket said next.
pub(super) enum Heard {
    Frame(serde_json::Value),
    /// The socket failed or closed before its `finished`, or Soniox sent an
    /// error a fresh socket may clear.
    Dropped(oneiron::Error),
    /// Soniox said a rate or quota limit (FIX 9515).
    Limited(oneiron::RetryableLlmError),
}

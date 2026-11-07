//! Document import and durable local-journal confirmation on the one socket.
use super::SyncClient;
use crate::sync::transport::{self, DocumentFrame, TransportError, document_sub_tags};

impl SyncClient {
    pub(super) fn handle_document_frame(
        &self,
        frame: DocumentFrame<'_>,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if frame.kind == document_sub_tags::PART {
            let joined = self
                .document_parts
                .lock()
                .map_err(|_| TransportError::Storage("document assembly poisoned".into()))?
                .accept(frame)?;
            return match joined {
                Some(joined) => self.handle_document_frame(joined.frame()),
                None => Ok(Vec::new()),
            };
        }
        match frame.kind {
            document_sub_tags::WAITED_OUT => {
                transport::decode_document_waited_out(frame.payload)?;
                // A reply uses the subscribed wire id, even when the server
                // opened a different source behind that copy alias.
                let subscribed = (|| -> crate::Result<bool> {
                    let txn = self.vault.store.env.read_txn()?;
                    crate::sync::documents::DS_E.contains(
                        &self.vault.store,
                        &txn,
                        &crate::side_table::HexId(frame.entity),
                    )
                })();
                match subscribed {
                    Ok(false) => return Ok(Vec::new()),
                    Err(error) => self.report_document_retry_error(&error),
                    Ok(true) => {}
                }
                self.document_retries
                    .lock()
                    .map_err(|_| TransportError::Storage("document retry state poisoned".into()))?
                    .insert(frame.entity);
                return Ok(Vec::new());
            }
            document_sub_tags::ARTIFACT_RECEIPT => {
                self.accept_artifact_receipt(frame.entity, frame.payload)
                    .map_err(storage)?;
                return Ok(Vec::new());
            }
            document_sub_tags::ARTIFACT_PUBLICATION => {
                return Err(TransportError::InvalidPayload(
                    "server sent an artifact publication",
                ));
            }
            _ => {}
        }
        // On a federation lane a document frame is a peer's text: its write is
        // admitted in the writer that lands it (FIX 8861), on a row this vault
        // already admitted through the window gate (OF-149).
        let federated = self.config.federation_peer.as_ref();
        let refused = |error: crate::Error| match federated {
            Some(_) => super::federated::map_federated_admission_err(error),
            None => storage(error),
        };
        let doc = self
            .manager
            .documents()
            .open(frame.entity)
            .map_err(refused)?;
        if doc.is_note().map_err(storage)? {
            if self.config.note_session.is_none() || !self.note_session_bound {
                return Err(TransportError::InvalidPayload(
                    "NOTE authority session is not bound",
                ));
            }
            match frame.kind {
                document_sub_tags::STATE | document_sub_tags::UPDATE => {
                    crate::note::import_note_from_authority(
                        &self.vault,
                        frame.entity,
                        frame.kind,
                        frame.payload,
                    )
                    .map_err(storage)?;
                    self.report_note_document(frame.entity).map_err(storage)?;
                    let mut out = vec![
                        transport::encode_document(
                            frame.entity,
                            document_sub_tags::ACK,
                            &doc.version_vector().map_err(storage)?,
                        )
                        .into_result()?,
                    ];
                    let pending = self
                        .manager
                        .documents()
                        .pending_note_requests(frame.entity)
                        .map_err(storage)?;
                    if pending.is_empty() {
                        self.clear_document_retry(frame.entity)?;
                    }
                    out.extend(pending);
                    return Ok(out);
                }
                document_sub_tags::NOTE_RECEIPT => {
                    let receipt = serde_json::from_slice(frame.payload)
                        .map_err(|_| TransportError::InvalidPayload("invalid NOTE receipt"))?;
                    self.manager
                        .documents()
                        .accept_note_receipt(frame.entity, &receipt)
                        .map_err(storage)?;
                    return Ok(Vec::new());
                }
                document_sub_tags::NOTE_FORK_RECEIPT => {
                    let receipt = serde_json::from_slice(frame.payload)
                        .map_err(|_| TransportError::InvalidPayload("invalid NOTE fork receipt"))?;
                    self.manager
                        .documents()
                        .accept_note_fork_receipt(frame.entity, &receipt)
                        .map_err(storage)?;
                    return Ok(Vec::new());
                }
                // The authority's pending forks (FIX 12789). A fork this
                // replica cannot take stays at the authority and never
                // costs the lane its text.
                document_sub_tags::NOTE_FORK_STATE | document_sub_tags::NOTE_FORK_SET
                    if federated.is_none() =>
                {
                    let taken = if frame.kind == document_sub_tags::NOTE_FORK_STATE {
                        crate::note::install_authority_fork(
                            &self.vault,
                            frame.entity,
                            frame.payload,
                        )
                    } else {
                        crate::note::settle_authority_forks(
                            &self.vault,
                            frame.entity,
                            frame.payload,
                        )
                    };
                    match taken {
                        Ok(()) => self.report_note_document(frame.entity).map_err(storage)?,
                        Err(error) => tracing::warn!(
                            %error,
                            note = %frame.entity.to_hex(),
                            "a NOTE fork from the authority was not taken"
                        ),
                    }
                    return Ok(Vec::new());
                }
                document_sub_tags::ACK => return Ok(Vec::new()),
                _ => {
                    return Err(TransportError::InvalidPayload(
                        "invalid NOTE authority frame",
                    ));
                }
            }
        }
        match frame.kind {
            document_sub_tags::ACK => {
                doc.acknowledge(frame.payload).map_err(storage)?;
                let settled = (|| -> Result<bool, TransportError> {
                    if !self
                        .document_retries
                        .lock()
                        .map_err(|_| {
                            TransportError::Storage("document retry state poisoned".into())
                        })?
                        .contains(&frame.entity)
                        || !doc.pending_frames().map_err(storage)?.is_empty()
                    {
                        return Ok(false);
                    }
                    let remote = loro::VersionVector::decode(frame.payload)
                        .map_err(|_| TransportError::InvalidPayload("invalid document ack"))?;
                    let current =
                        loro::VersionVector::decode(&doc.version_vector().map_err(storage)?)
                            .map_err(|_| {
                                TransportError::InvalidPayload("invalid document vector")
                            })?;
                    Ok(matches!(
                        remote.partial_cmp(&current),
                        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
                    ))
                })();
                match settled {
                    Ok(true) => self.clear_document_retry(frame.entity)?,
                    Ok(false) => {}
                    Err(error) => self.report_document_retry_error(&error),
                }
                Ok(Vec::new())
            }
            document_sub_tags::STATE | document_sub_tags::UPDATE => {
                match federated {
                    Some(peer) => doc.import_admitted(frame.kind, frame.payload, |txn| {
                        peer.admit_document_write_in_txn(
                            &self.vault,
                            txn,
                            frame.entity,
                            self.home_peer,
                        )
                    }),
                    None => doc.import(frame.kind, frame.payload),
                }
                .map_err(refused)?;
                let mut out = vec![
                    transport::encode_document(
                        frame.entity,
                        document_sub_tags::ACK,
                        &doc.version_vector().map_err(storage)?,
                    )
                    .into_result()?,
                ];
                // Text a device-only world keeps here, or a federation peer may
                // not read now, stays journaled; each reply loop asks again
                // right before its send.
                let pending = doc.pending_frames().map_err(storage)?;
                if pending.is_empty() {
                    self.clear_document_retry(frame.entity)?;
                }
                // Until the remote covers a nonempty journal, keep retrying
                // even if its resend is withheld or the socket send fails.
                out.extend(
                    pending
                        .into_iter()
                        .filter(|frame| !self.frame_withheld(frame)),
                );
                Ok(out)
            }
            _ => Err(TransportError::InvalidPayload(
                "server sent document request",
            )),
        }
    }
}
impl SyncClient {
    fn clear_document_retry(&self, id: crate::EntityId) -> Result<(), TransportError> {
        self.document_retries
            .lock()
            .map_err(|_| TransportError::Storage("document retry state poisoned".into()))?
            .remove(&id);
        Ok(())
    }

    fn report_document_retry_error(&self, error: &impl std::fmt::Display) {
        let _ = self.event_tx.send(super::SyncEvent::Error(format!(
            "Document retry failed: {error}"
        )));
    }

    /// Reuse the connection's existing housekeeping tick and outgoing batch.
    /// Only an absent subscription/deleted row retires a retry without a reply;
    /// a read/open error leaves it owed and does not close unrelated traffic.
    pub(crate) fn retry_document_requests(&self) -> Vec<Vec<u8>> {
        let ids = match self.document_retries.lock() {
            Ok(retries) => retries.iter().copied().collect::<Vec<_>>(),
            Err(error) => {
                self.report_document_retry_error(&error);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for id in ids {
            match self.manager.documents().retry_request_frame(id) {
                Ok(Some(frame)) if !self.frame_withheld(&frame) => out.push(frame),
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(error) = self.clear_document_retry(id) {
                        self.report_document_retry_error(&error);
                    }
                }
                Err(error) => self.report_document_retry_error(&error),
            }
        }
        out
    }

    /// A document-only change to a NOTE reaches live queries as its entity
    /// path in the NOTE's learned window.
    fn report_note_document(&self, note: crate::EntityId) -> crate::Result<()> {
        let Some(raw) = self.vault.get_raw(&note)? else {
            return Ok(());
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("entity header"))?;
        let window = crate::sync::WindowKey::from_timestamp(header.learned_at);
        self.manager.materializer().notify_live_queries(
            &format!("w:{window}"),
            &crate::sync::bridge::MaterializedDiffSummary {
                containers: vec![format!("w:{window}/entities/{}", note.to_hex())],
                bytes: 0,

                revision_events: Vec::new(),
            },
            &crate::sync::bridge::OriginMark {
                conn_id: None,
                origin: Some(crate::sync::bridge::BRIDGE_ORIGIN.to_owned()),
            },
        );
        Ok(())
    }

    /// An own device's NOTE client subscribes every NOTE row it holds on the
    /// owner lane: at connect, then each row born here or materialized from
    /// a window.
    pub(super) fn owner_note_requests(&self) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() || self.config.note_session.is_none() {
            return Ok(Vec::new());
        }
        self.manager
            .documents()
            .subscribe_owner_notes()
            .map_err(storage)
    }
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

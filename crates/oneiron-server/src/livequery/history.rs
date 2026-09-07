//! Retained scoped app payloads live in the cursor document, not the delivery ring.
use super::budget::{Budget, Reservation};
use super::subscriptions::Push;
use super::*;
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use std::sync::Arc;

const HISTORY_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct History {
    session: Arc<Budget>,
    hub: Arc<Budget>,
    reservation: Option<Reservation>,
    bytes: usize,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    view: ScopedView,
    channel: Channel,
    subscription_id: u64,
    cursor: Cursor,
    kind: String,
    result: Option<Value>,
}

impl History {
    pub(super) fn new(session: Arc<Budget>, hub: Arc<Budget>) -> Self {
        Self {
            session,
            hub,
            reservation: None,
            bytes: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.reservation = None;
        self.bytes = 0;
    }

    /// False expires this document's retention. Never keep an unbudgeted journal.
    pub(super) fn record(
        &mut self,
        doc: &LoroDoc,
        view: &ScopedView,
        channel: Channel,
        pushes: &[Push],
    ) -> Result<bool, AppError> {
        let mut rows = Vec::new();
        for push in pushes {
            let bytes = wire::packed(&Entry {
                view: view.clone(),
                channel,
                subscription_id: push.subscription_id,
                cursor: push.cursor.clone(),
                kind: push.kind.to_owned(),
                result: push.result.clone(),
            })
            .map_err(|_| error())?;
            rows.push((format!("{}:{}", push.cursor.batch, push.kind), bytes));
        }
        // Covers journal bytes, Loro operation/state copies and index metadata.
        let bytes = self.bytes + rows.iter().map(|(_, b)| b.len() * 8 + 1024).sum::<usize>();
        if bytes > HISTORY_BYTES {
            return Ok(false);
        }
        if let Some(reservation) = &mut self.reservation {
            if reservation.resize(bytes).is_err() {
                return Ok(false);
            }
        } else {
            let Ok(reservation) = Reservation::new(self.session.clone(), self.hub.clone(), bytes)
            else {
                return Ok(false);
            };
            self.reservation = Some(reservation);
        }
        for (key, bytes) in rows {
            doc.get_map("history")
                .insert(&key, bytes.as_slice())
                .map_err(|_| error())?;
        }
        doc.commit();
        self.bytes = bytes;
        Ok(true)
    }

    pub(super) fn value_at(
        doc: &LoroDoc,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<Option<Value>, AppError> {
        for kind in ["data", "snapshot"] {
            if let Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) = doc
                .get_map("history")
                .get(&format!("{}:{kind}", cursor.batch))
            {
                let entry: Entry = rmp_serde::from_slice(&bytes).map_err(|_| error())?;
                if &entry.view == view && entry.channel == channel && &entry.cursor == cursor {
                    return Ok(entry.result);
                }
            }
        }
        Ok(None)
    }

    pub(super) fn replay(
        doc: &LoroDoc,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<Option<Vec<Push>>, AppError> {
        // Reconstruct the retained tail through Loro's actual delta door.
        // The fork is scoped app state only, never a full sync window.
        let vv = loro::VersionVector::decode(&cursor.version_vector).map_err(|_| error())?;
        let delta = doc
            .export(loro::ExportMode::updates(&vv))
            .map_err(|_| error())?;
        let replay = doc
            .fork_at(&doc.vv_to_frontiers(&vv))
            .map_err(|_| error())?;
        replay.import(&delta).map_err(|_| error())?;
        let mut entries = Vec::new();
        let mut failed = false;
        replay.get_map("history").for_each(|_, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
                match rmp_serde::from_slice::<Entry>(&bytes) {
                    Ok(entry) if &entry.view == view && entry.channel == channel => {
                        entries.push(entry);
                    }
                    Ok(_) => {}
                    Err(_) => failed = true,
                }
            } else {
                failed = true;
            }
        });
        if failed {
            return Err(error());
        }
        let Some(id) = entries
            .iter()
            .find(|entry| &entry.cursor == cursor)
            .map(|entry| entry.subscription_id)
        else {
            return Ok(None);
        };
        entries.retain(|entry| entry.subscription_id == id && entry.cursor.batch > cursor.batch);
        entries.sort_by_key(|entry| {
            (
                entry.cursor.batch,
                match entry.kind.as_str() {
                    "gap" => 0,
                    "snapshot" | "data" => 1,
                    _ => 2,
                },
            )
        });
        entries
            .into_iter()
            .map(|entry| {
                let kind = match entry.kind.as_str() {
                    "snapshot" => "snapshot",
                    "data" => "data",
                    "eose" => "eose",
                    "gap" => "gap",
                    _ => return Err(error()),
                };
                Ok(Push {
                    subscription_id: id,
                    cursor: entry.cursor,
                    kind,
                    result: entry.result,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}
fn error() -> AppError {
    AppError::internal_server_error("retained app history unavailable")
}

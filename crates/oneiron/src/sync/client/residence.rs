//! Bounded on-demand home reads on an independent short-lived authenticated
//! socket. The steady sync socket keeps sole ownership of its own reader.

use std::collections::HashSet;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use super::base::SyncClient;
use super::types::{SyncClientConfig, SyncResidenceMode};
use crate::EntityId;
use crate::sync::residence::WindowIndexEntry;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::{self, TAG_RPC, TransportError};
use crate::sync::types::WindowKey;

const RPC_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_RPC_REPLY_BYTES: usize = 32 * 1024 * 1024;
const MAX_INDEX_PAGES: usize = 1024;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Search explicitly distinguishes a complete home answer from a partial
/// offline answer over this device's previously opened, cached items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSource {
    Home,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceHit {
    pub entity_id: String,
    pub score: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceSearch {
    pub hits: Vec<ResidenceHit>,
    pub source: SearchSource,
    pub complete: bool,
}

#[derive(Serialize)]
struct RequestEnvelope {
    #[serde(rename = "type")]
    kind: &'static str,
    id: u64,
    seq: u64,
    last: bool,
    payload: Value,
}

#[derive(Deserialize)]
struct ReplyEnvelope {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: rmpv::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexReply {
    window: String,
    items: Vec<WindowIndexEntry>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TouchReply {
    window: String,
    entity_id: String,
    blob: String,
    document: String,
}

/// One grant-checked read cache entry. It is NOT a writable ledger replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinItem {
    pub entity_id: EntityId,
    pub window: WindowKey,
    /// The entity header and body, exactly as returned by the home.
    pub raw: Vec<u8>,
    /// The separately grant-checked text document frame.
    pub document: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchReply {
    hits: Vec<SearchHit>,
    source: String,
    complete: bool,
}

#[derive(Deserialize)]
struct PromotionReply {
    window: String,
    snapshot: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    entity_id: String,
    score: f32,
}

struct ResidenceRpc {
    socket: Socket,
    next_id: u64,
}

impl ResidenceRpc {
    /// `None` is only a transport outage. A refused bind or malformed reply
    /// is an error, not permission to label the search local-only.
    async fn connect(config: &SyncClientConfig) -> Result<Option<Self>, TransportError> {
        let session = config.note_session.as_ref().ok_or_else(refused)?;
        config.residence_selector.as_ref().ok_or_else(refused)?;
        let mut request = config
            .server_url
            .as_str()
            .into_client_request()
            .map_err(|_| refused())?;
        if !config.auth_token.is_empty() {
            let header = format!("Bearer {}", config.auth_token)
                .parse()
                .map_err(|_| refused())?;
            request.headers_mut().insert(AUTHORIZATION, header);
        }
        let mut socket = match tokio::time::timeout(
            RPC_TIMEOUT,
            tokio_tungstenite::connect_async(request),
        )
        .await
        {
            Ok(Ok((socket, _))) => socket,
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(_))) => return Err(refused()),
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
        socket
            .send(Message::Binary(
                transport::encode_residence_protocol_hello().into(),
            ))
            .await
            .map_err(|_| refused())?;
        socket
            .send(Message::Binary(
                super::note_session::bind_frame(session)?.into(),
            ))
            .await
            .map_err(|_| refused())?;
        // A future server may send an ephemeral snapshot before the bind ack.
        // Only the exact fixed-ID null reply opens the RPC lane.
        for _ in 0..16 {
            let msg = tokio::time::timeout(RPC_TIMEOUT, socket.next())
                .await
                .map_err(|_| refused())?
                .ok_or_else(refused)?
                .map_err(|_| refused())?;
            let Message::Binary(frame) = msg else {
                return Err(refused());
            };
            match frame.first() {
                Some(&TAG_RPC) => {
                    super::note_session::accept_bind_reply(&frame[1..])?;
                    return Ok(Some(Self { socket, next_id: 1 }));
                }
                Some(&transport::TAG_EPHEMERAL) | Some(&transport::TAG_SYNC_UPDATE) => continue,
                _ => return Err(refused()),
            }
        }
        Err(refused())
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or_else(refused)?;
        let request = RequestEnvelope {
            kind: "rpc.req",
            id,
            seq: 0,
            last: true,
            payload: json!({"method": method, "params": params}),
        };
        let bytes = rmp_serde::to_vec_named(&request).map_err(|_| refused())?;
        if bytes.len() > transport::MAX_DECODED_PAYLOAD_BYTES {
            return Err(refused());
        }
        let mut frame = vec![TAG_RPC];
        frame.extend(bytes);
        self.socket
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|_| refused())?;
        let mut assembled = Vec::new();
        for seq in 0..512u64 {
            let msg = tokio::time::timeout(RPC_TIMEOUT, self.socket.next())
                .await
                .map_err(|_| refused())?
                .ok_or_else(refused)?
                .map_err(|_| refused())?;
            let Message::Binary(frame) = msg else {
                return Err(refused());
            };
            if frame.first() != Some(&TAG_RPC) {
                return Err(refused());
            }
            let reply: ReplyEnvelope = rmp_serde::from_slice(&frame[1..]).map_err(|_| refused())?;
            if reply.id != id || reply.seq != seq {
                return Err(refused());
            }
            if reply.kind == "rpc.err" {
                return Err(TransportError::InvalidPayload("home refused residence RPC"));
            }
            if reply.kind != "rpc.res" {
                return Err(refused());
            }
            let chunk = reply.payload.as_slice().ok_or_else(refused)?;
            if assembled.len().saturating_add(chunk.len()) > MAX_RPC_REPLY_BYTES {
                return Err(refused());
            }
            assembled.extend_from_slice(chunk);
            if reply.last {
                return rmp_serde::from_slice(&assembled).map_err(|_| refused());
            }
        }
        Err(refused())
    }
}

fn refused() -> TransportError {
    TransportError::InvalidPayload("opened-item RPC unavailable")
}

impl SyncClient {
    /// Fetch the current windows' thin index without a full-window VV exchange.
    pub async fn fetch_current_index(&self, now_secs: u64) -> Result<usize, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector_bytes = encode_sync_selector(selector).map_err(|_| refused())?;
        let selector = base64::engine::general_purpose::STANDARD.encode(selector_bytes);
        let Some(mut rpc) = ResidenceRpc::connect(&self.config).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        let current = WindowKey::from_timestamp(now_secs);
        let previous = current.previous_month();
        let mut total = 0;
        for key in self.server_windows() {
            let Some(window) = WindowKey::try_new(&key) else {
                continue;
            };
            if window.start_timestamp() != current.start_timestamp()
                && window.start_timestamp()
                    != previous.as_ref().and_then(WindowKey::start_timestamp)
            {
                continue;
            }
            let mut cursor: Option<String> = None;
            let mut items = Vec::new();
            let mut finished = false;
            for _ in 0..MAX_INDEX_PAGES {
                let reply: IndexReply = serde_json::from_value(
                    rpc.request(
                        "residence.index",
                        json!({
                            "window": key, "selector": selector, "after": cursor, "limit": 256
                        }),
                    )
                    .await?,
                )
                .map_err(|_| refused())?;
                if reply.window != key {
                    return Err(refused());
                }
                let next = reply.next_cursor;
                items.extend(reply.items);
                match next {
                    Some(next) if cursor.as_ref() != Some(&next) => cursor = Some(next),
                    Some(_) => return Err(refused()),
                    None => {
                        finished = true;
                        break;
                    }
                }
            }
            if !finished {
                return Err(refused());
            }
            let prefix = format!("ri:w:{key}:");
            self.vault
                .with_write_txn(|txn| {
                    let old: Vec<_> = self
                        .vault
                        .store
                        .sync_state
                        .prefix_iter(txn, &prefix)?
                        .map(|row| row.map(|(key, _)| key.to_string()))
                        .collect::<std::result::Result<_, _>>()?;
                    for key in old {
                        self.vault.store.sync_state.delete(txn, &key)?;
                    }
                    for entry in &items {
                        let key = format!("{prefix}{}", entry.entity_id);
                        let bytes = rmp_serde::to_vec_named(entry)
                            .map_err(|_| crate::Error::InvariantViolation("index codec"))?;
                        self.vault.store.sync_state.put(txn, &key, &bytes)?;
                    }
                    Ok(())
                })
                .map_err(|e| TransportError::Storage(e.to_string()))?;
            total += items.len();
        }
        Ok(total)
    }

    /// Resolve and import one grant-selected ledger item on first touch.
    pub async fn fetch_item(
        &mut self,
        window: &WindowKey,
        item: EntityId,
    ) -> Result<(), TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.config).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        let reply: TouchReply = serde_json::from_value(
            rpc.request(
                "residence.touch",
                json!({
                    "window": window.as_str(), "selector": selector, "entityId": item.to_hex()
                }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        if reply.entity_id != item.to_hex() || reply.window != window.as_str() {
            return Err(refused());
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(reply.blob)
            .map_err(|_| refused())?;
        let header = crate::batch::EntityMetadataHeader::parse(&blob).ok_or_else(refused)?;
        if blob.len() > transport::MAX_DECODED_PAYLOAD_BYTES
            || window
                .start_timestamp()
                .is_none_or(|start| header.learned_at < start)
            || window
                .end_timestamp()
                .is_some_and(|end| header.learned_at >= end)
        {
            return Err(refused());
        }
        let document = base64::engine::general_purpose::STANDARD
            .decode(reply.document)
            .map_err(|_| refused())?;
        if document.len() > transport::MAX_DECODED_PAYLOAD_BYTES
            || document.first() != Some(&transport::TAG_DOCUMENT)
        {
            return Err(refused());
        }
        let document_frame = transport::decode_document(&document[1..])?;
        if document_frame.entity != item
            || !matches!(
                document_frame.kind,
                transport::document_sub_tags::STATE | transport::document_sub_tags::UPDATE
            )
        {
            return Err(refused());
        }
        // The grant-checked body and text are one atomic READ-ONLY cache
        // entry. Neither reaches the observed Loro window or LMDB entity
        // tables until the canonical window is promoted before a write.
        self.vault
            .with_write_txn(|txn| {
                self.vault
                    .store
                    .sync_state
                    .put(txn, &format!("ri:b:{}", item.to_hex()), &blob)?;
                self.vault.store.sync_state.put(
                    txn,
                    &format!("ri:d:{}", item.to_hex()),
                    &document,
                )?;
                self.vault.store.sync_state.put(
                    txn,
                    &format!("ro:e:{}", item.to_hex()),
                    window.as_str().as_bytes(),
                )?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Promote a thin item's whole canonical window before the first edit.
    /// A denied or oversized full-window grant leaves the thin cache read-only.
    pub async fn promote_window(
        &mut self,
        window: &WindowKey,
        item: EntityId,
    ) -> Result<(), TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let cache = self.thin_item(item)?.ok_or_else(refused)?;
        if &cache.window != window {
            return Err(refused());
        }
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.config).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        let reply: PromotionReply = serde_json::from_value(
            rpc.request(
                "residence.promote",
                json!({
                    "window": window.as_str(), "selector": selector, "entityId": item.to_hex()
                }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        if reply.window != window.as_str() {
            return Err(refused());
        }
        let snapshot = base64::engine::general_purpose::STANDARD
            .decode(reply.snapshot)
            .map_err(|_| refused())?;
        if snapshot.len() > crate::sync::residence::MAX_PROMOTION_SNAPSHOT_BYTES {
            return Err(refused());
        }
        // Do not merge a canonical frontier into an independently authored
        // sparse window. Its prior ops would not be a causal continuation.
        let loaded = self.ensure_window(window.as_str())?;
        if !loaded.doc.oplog_vv().is_empty() {
            return Err(TransportError::InvalidPayload(
                "unpromoted window has local CRDT history",
            ));
        }
        if loaded.doc.import(&snapshot).is_err() {
            self.manager.discard_window(window);
            return Err(refused());
        }
        if let Err(error) = loaded.persist_state(&self.vault) {
            self.manager.discard_window(window);
            return Err(TransportError::Storage(error.to_string()));
        }
        // Publish the writable marker only AFTER the canonical doc is
        // durable. Cached thin bodies in this window can no longer shadow it.
        self.vault
            .with_write_txn(|txn| {
                let stale: Vec<_> = self
                    .vault
                    .store
                    .sync_state
                    .prefix_iter(txn, "ro:e:")?
                    .map(|row| row.map(|(key, value)| (key.to_string(), value.to_vec())))
                    .collect::<std::result::Result<_, _>>()?;
                for (key, value) in stale {
                    if value == window.as_str().as_bytes() {
                        let id = key.strip_prefix("ro:e:").ok_or(crate::Error::InvalidKey)?;
                        self.vault.store.sync_state.delete(txn, &key)?;
                        self.vault
                            .store
                            .sync_state
                            .delete(txn, &format!("ri:b:{id}"))?;
                        self.vault
                            .store
                            .sync_state
                            .delete(txn, &format!("ri:d:{id}"))?;
                    }
                }
                self.vault
                    .store
                    .sync_state
                    .put(txn, &format!("rp:w:{window}"), &[1])?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        self.manager.notify_promotion(window);
        Ok(())
    }

    /// Read a previously fetched thin item. This cache has no writable Loro
    /// handle; callers must promote its window before any edit.
    pub fn thin_item(&self, item: EntityId) -> Result<Option<ThinItem>, TransportError> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        let id = item.to_hex();
        let Some(raw_window) = self
            .vault
            .store
            .sync_state
            .get(&txn, &format!("ro:e:{id}"))
            .map_err(|e| TransportError::Storage(e.to_string()))?
        else {
            return Ok(None);
        };
        let window = std::str::from_utf8(&raw_window)
            .ok()
            .and_then(WindowKey::try_new)
            .ok_or_else(refused)?;
        let raw = self
            .vault
            .store
            .sync_state
            .get(&txn, &format!("ri:b:{id}"))
            .map_err(|e| TransportError::Storage(e.to_string()))?
            .ok_or_else(refused)?;
        let document = self
            .vault
            .store
            .sync_state
            .get(&txn, &format!("ri:d:{id}"))
            .map_err(|e| TransportError::Storage(e.to_string()))?
            .ok_or_else(refused)?;
        Ok(Some(ThinItem {
            entity_id: item,
            window,
            raw: raw.to_vec(),
            document: document.to_vec(),
        }))
    }

    /// Home results when reachable; offline results are explicitly local-only.
    pub async fn search_resident(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ResidenceSearch, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened
            || query.trim().is_empty()
            || query.len() > 4096
            || limit == 0
            || limit > 100
        {
            return Err(refused());
        }
        match ResidenceRpc::connect(&self.config).await? {
            Some(mut rpc) => {
                let reply: SearchReply = serde_json::from_value(
                    rpc.request("residence.search", json!({"query": query, "limit": limit}))
                        .await?,
                )
                .map_err(|_| refused())?;
                if reply.source != "home" || !reply.complete || reply.hits.len() > limit {
                    return Err(refused());
                }
                Ok(ResidenceSearch {
                    hits: reply
                        .hits
                        .into_iter()
                        .map(|hit| ResidenceHit {
                            entity_id: hit.entity_id,
                            score: hit.score,
                        })
                        .collect(),
                    source: SearchSource::Home,
                    complete: true,
                })
            }
            None => {
                let opened: HashSet<_> = self
                    .vault
                    .sync_state_keys_with_prefix("ro:e:")
                    .map_err(|e| TransportError::Storage(e.to_string()))?
                    .into_iter()
                    .filter_map(|key| {
                        key.strip_prefix("ro:e:")
                            .and_then(|id| EntityId::from_hex(id).ok())
                    })
                    .collect();
                let promoted: HashSet<_> = self
                    .vault
                    .sync_state_keys_with_prefix("rp:w:")
                    .map_err(|e| TransportError::Storage(e.to_string()))?
                    .into_iter()
                    .filter_map(|key| key.strip_prefix("rp:w:").map(str::to_owned))
                    .collect();
                let needle = query.to_lowercase();
                let mut hits = Vec::new();
                for id in &opened {
                    let Some(item) = self.thin_item(*id)? else {
                        continue;
                    };
                    let raw = String::from_utf8_lossy(&item.raw).to_lowercase();
                    let text = String::from_utf8_lossy(&item.document).to_lowercase();
                    if raw.contains(&needle) || text.contains(&needle) {
                        hits.push(ResidenceHit {
                            entity_id: id.to_hex(),
                            score: 1.0,
                        });
                    }
                }
                for hit in self
                    .vault
                    .search_text(query, 1000)
                    .map_err(|e| TransportError::Storage(e.to_string()))?
                {
                    let Some(raw) = self
                        .vault
                        .get_raw(&hit.id)
                        .map_err(|e| TransportError::Storage(e.to_string()))?
                    else {
                        continue;
                    };
                    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                        continue;
                    };
                    let window = WindowKey::from_timestamp(header.learned_at);
                    if promoted.contains(window.as_str())
                        && !hits
                            .iter()
                            .any(|existing| existing.entity_id == hit.id.to_hex())
                    {
                        hits.push(ResidenceHit {
                            entity_id: hit.id.to_hex(),
                            score: hit.score,
                        });
                    }
                }
                hits.truncate(limit);
                Ok(ResidenceSearch {
                    hits,
                    source: SearchSource::LocalOnly,
                    complete: false,
                })
            }
        }
    }
}

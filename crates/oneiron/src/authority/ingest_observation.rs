//! Non-refusing authority replay observation with one typed check per peer/window.

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;

use super::sequence_observation::authority_observation_peer_id;
use super::*;

/// Local sliding-window replay-ingest counter. Key: string (peer id).
const INGEST_COUNT: SideTable<String, IngestCountRow, Raw> =
    SideTable::new(&side_table::AUTHLOG_INGEST_COUNT);
/// One recorded OF-520 ingest-burst check. Key: hex64(peer id) ":" u64hex16(window start).
const INGEST_CHECK: SideTable<IngestCheckKey, IngestCheckValue, Raw> =
    SideTable::new(&side_table::AUTHLOG_INGEST_CHECK);

/// The sliding-window row: window start, admitted count, and whether this window already
/// raised a check. 17 raw bytes: start (u64be) + count (u64be) + raised (0/1).
struct IngestCountRow {
    start: u64,
    count: u64,
    raised: bool,
}

impl RawValue for IngestCountRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = Vec::with_capacity(17);
        value.extend_from_slice(&self.start.to_be_bytes());
        value.extend_from_slice(&self.count.to_be_bytes());
        value.push(u8::from(self.raised));
        Ok(value)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        if raw.len() == 17 && raw[16] <= 1 {
            Ok(Self {
                start: observation_u64(&raw[..8])?,
                count: observation_u64(&raw[8..16])?,
                raised: raw[16] == 1,
            })
        } else {
            Err(Error::CorruptedIndex("authority ingest observation").into())
        }
    }
}

/// Key of one raised check: the peer id, a literal `:`, then the window start rendered as
/// 16 lowercase hex digits — exactly the pre-migration `{CHECK_PREFIX}{peer_id}:{start:016x}`
/// spelling, minus the shared prefix the typed table now carries.
struct IngestCheckKey {
    peer_id: String,
    start: u64,
}

impl SideKey for IngestCheckKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.peer_id.as_bytes());
        out.push(b':');
        out.extend_from_slice(format!("{:016x}", self.start).as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (peer_id, start_hex) = text.split_once(':')?;
        if peer_id.len() != 64 || start_hex.len() != 16 {
            return None;
        }
        Some(Self {
            peer_id: peer_id.to_owned(),
            start: u64::from_str_radix(start_hex, 16).ok()?,
        })
    }
}

/// One raised check's window start, admitted count, and threshold: 24 raw bytes, three
/// big-endian `u64`s.
struct IngestCheckValue {
    window_started_at_secs: u64,
    count: u64,
    threshold: u64,
}

impl RawValue for IngestCheckValue {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = Vec::with_capacity(24);
        for part in [self.window_started_at_secs, self.count, self.threshold] {
            value.extend_from_slice(&part.to_be_bytes());
        }
        Ok(value)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        if raw.len() != 24 {
            return Err(Error::CorruptedIndex("authority ingest check").into());
        }
        Ok(Self {
            window_started_at_secs: observation_u64(&raw[..8])?,
            count: observation_u64(&raw[8..16])?,
            threshold: observation_u64(&raw[16..])?,
        })
    }
}

/// OF-520 question raised after a peer crosses its configured observation
/// threshold. It is evidence for a caller's verdict, never a replay refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityIngestCheck {
    /// Stable suite-separated digest of the row's verified origin signer.
    pub peer_id: String,
    /// Local monotonic start of the observation window.
    pub window_started_at_secs: u64,
    /// Admitted unique rows at the first crossing of the threshold.
    pub count: u64,
    /// Policy threshold that caused this check.
    pub threshold: u64,
}

impl AuthorityIngestCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "authority_ingest_burst";

    /// Identity used by this authority-origin check (not a transport identity).
    #[must_use]
    pub fn peer_id_for_signer(signer: &AuthorityKey) -> String {
        authority_observation_peer_id(signer)
    }
}

pub(crate) fn observe_authority_replay_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    signer: &AuthorityKey,
    now_secs: u64,
) -> Result<()> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    let peer_id = authority_observation_peer_id(signer);
    let IngestCountRow {
        mut start,
        mut count,
        mut raised,
    } = match INGEST_COUNT.get(store, txn, &peer_id)? {
        None => IngestCountRow {
            start: now_secs,
            count: 0,
            raised: false,
        },
        Some(row) => row,
    };
    if now_secs.saturating_sub(start) >= policy.ingest_window_secs {
        start = now_secs;
        count = 0;
        raised = false;
    }
    // Saturation cannot turn a valid replay into a rate/overflow refusal.
    count = count.saturating_add(1);
    if !raised && count > policy.ingest_check_threshold {
        let check_key = IngestCheckKey {
            peer_id: peer_id.clone(),
            start,
        };
        // The key is stable for the window. Re-rematerialization cannot emit
        // another question, even if a metadata-only echo changed the row.
        if !INGEST_CHECK.contains(store, txn, &check_key)? {
            INGEST_CHECK.put(
                store,
                txn,
                &check_key,
                &IngestCheckValue {
                    window_started_at_secs: start,
                    count,
                    threshold: policy.ingest_check_threshold,
                },
            )?;
        }
        raised = true;
    }
    INGEST_COUNT.put(
        store,
        txn,
        &peer_id,
        &IngestCountRow {
            start,
            count,
            raised,
        },
    )?;
    Ok(())
}

fn observation_u64(raw: &[u8]) -> Result<u64> {
    decode_authority_first_seen_secs(raw)
        .ok_or(Error::CorruptedIndex("authority ingest observation"))
}

impl Vault {
    /// Lists durable OF-520 checks. Checks are local-only and never enter Loro.
    pub fn authority_ingest_checks(&self) -> Result<Vec<AuthorityIngestCheck>> {
        let txn = self.store.env.read_txn()?;
        Ok(INGEST_CHECK
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(key, value)| AuthorityIngestCheck {
                peer_id: key.peer_id,
                window_started_at_secs: value.window_started_at_secs,
                count: value.count,
                threshold: value.threshold,
            })
            .collect())
    }
}

//! Non-refusing authority replay observation with one typed check per peer/window.

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

use super::sequence_observation::authority_observation_peer_id;
use super::*;

const CHECK_PREFIX: &str = "authlog:ingest_check:";

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
    let key = format!("authlog:ingest_count:{peer_id}");
    let (mut start, mut count, mut raised) = match store.sync_state.get(txn, &key)? {
        None => (now_secs, 0, false),
        Some(raw) if raw.len() == 17 && raw[16] <= 1 => (
            observation_u64(&raw[..8])?,
            observation_u64(&raw[8..16])?,
            raw[16] == 1,
        ),
        Some(_) => return Err(Error::CorruptedIndex("authority ingest observation")),
    };
    if now_secs.saturating_sub(start) >= policy.ingest_window_secs {
        start = now_secs;
        count = 0;
        raised = false;
    }
    // Saturation cannot turn a valid replay into a rate/overflow refusal.
    count = count.saturating_add(1);
    if !raised && count > policy.ingest_check_threshold {
        let check_key = format!("{CHECK_PREFIX}{peer_id}:{start:016x}");
        let mut value = Vec::with_capacity(24);
        for value_part in [start, count, policy.ingest_check_threshold] {
            value.extend_from_slice(&value_part.to_be_bytes());
        }
        // The key is stable for the window. Re-rematerialization cannot emit
        // another question, even if a metadata-only echo changed the row.
        if store.sync_state.get(txn, &check_key)?.is_none() {
            store.sync_state.put(txn, &check_key, &value)?;
        }
        raised = true;
    }
    let mut value = Vec::with_capacity(17);
    value.extend_from_slice(&start.to_be_bytes());
    value.extend_from_slice(&count.to_be_bytes());
    value.push(u8::from(raised));
    store.sync_state.put(txn, &key, &value)?;
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
        let mut checks = Vec::new();
        for row in self.store.sync_state.prefix_iter(&txn, CHECK_PREFIX)? {
            let (key, raw) = row?;
            let Some((peer_id, _)) = key
                .strip_prefix(CHECK_PREFIX)
                .and_then(|suffix| suffix.split_once(':'))
            else {
                return Err(Error::CorruptedIndex("authority ingest check key"));
            };
            if peer_id.len() != 64 || raw.len() != 24 {
                return Err(Error::CorruptedIndex("authority ingest check"));
            }
            checks.push(AuthorityIngestCheck {
                peer_id: peer_id.to_owned(),
                window_started_at_secs: observation_u64(&raw[..8])?,
                count: observation_u64(&raw[8..16])?,
                threshold: observation_u64(&raw[16..])?,
            });
        }
        Ok(checks)
    }
}

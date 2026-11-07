//! Generic original-usage export over ctl (LC191311): one stored event's original JSON in framed chunks.

use oneiron_vault_contract::{
    CtlResponse, MAX_CTL_LINE, UsageExportChunk, UsageExportCursor, UsageExportPage,
};

use super::codec::{UsageError, decode_entry};
use super::keys::{
    MAX_IDEMPOTENCY_KEY_LEN, usage_event_key, usage_event_prefix, validate_dimension, validate_key,
};
use super::ledger::{StoredUsageEvent, UsageLedger};

impl UsageLedger {
    /// One original stored event's JSON, framed to a ctl line.
    ///
    /// `owner`/`vault_id` is the meter scope the managed handler resolved
    /// from `server.vault_usage()`; cursors name original idempotency keys,
    /// never storage keys. `None` reads the first scoped event, `After`
    /// the strictly next one, `InEvent` the exact id at its byte offset
    /// with its digest checked. A missing, changed or corrupt row is a read
    /// error, never an empty page; terminal `{None, None}` means no further
    /// scoped event.
    pub(crate) fn export_page(
        &self,
        owner: &str,
        vault_id: &str,
        cursor: Option<&UsageExportCursor>,
    ) -> Result<UsageExportPage, UsageError> {
        Self::validate_scope(owner, vault_id)?;
        let prefix = usage_event_prefix(owner, vault_id);
        match cursor {
            None => self.export_next_after(owner, vault_id, &prefix, None),
            Some(UsageExportCursor::After { key }) => {
                let full = full_key_for(owner, vault_id, key)?;
                self.export_next_after(owner, vault_id, &prefix, Some(&full))
            }
            Some(UsageExportCursor::InEvent {
                key,
                offset,
                digest,
            }) => self.export_at(owner, vault_id, key, *offset, digest),
        }
    }

    fn export_next_after(
        &self,
        owner: &str,
        vault_id: &str,
        prefix: &str,
        after: Option<&str>,
    ) -> Result<UsageExportPage, UsageError> {
        // One event per chunk is a wire operation, not a user count cap.
        let mut found: Option<(String, Vec<u8>)> = None;
        self.vault
            .sync_state_prefix_page(prefix, after, 1, |key, raw| {
                found = Some((key.to_owned(), raw.to_vec()));
                Ok(())
            })?;
        let Some((key, raw)) = found else {
            return Ok(UsageExportPage {
                chunk: None,
                next: None,
            });
        };
        let stored = checked_original(owner, vault_id, &key, &raw)?;
        let full = original_json(&stored)?;
        let digest = original_digest(&full);
        let id = stored.event.idempotency_key.clone();
        let (chunk, next) = fit_chunk(&id, &digest, &full, 0)?;
        Ok(UsageExportPage {
            chunk: Some(chunk),
            next: Some(next),
        })
    }

    fn export_at(
        &self,
        owner: &str,
        vault_id: &str,
        id: &str,
        offset: u64,
        digest: &str,
    ) -> Result<UsageExportPage, UsageError> {
        let full_key = full_key_for(owner, vault_id, id)?;
        let Some(raw) = self.vault.sync_state_get(&full_key)? else {
            return Err(UsageError::InvalidField {
                field: "key",
                message: "no such usage event",
            });
        };
        let stored = checked_original(owner, vault_id, &full_key, &raw)?;
        if stored.event.idempotency_key != id {
            return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
        }
        let full = original_json(&stored)?;
        let current = original_digest(&full);
        if current != digest {
            return Err(UsageError::InvalidField {
                field: "digest",
                message: "usage event changed",
            });
        }
        let start = usize::try_from(offset).map_err(|_| UsageError::InvalidField {
            field: "offset",
            message: "offset too large",
        })?;
        if start > full.len() {
            return Err(UsageError::InvalidField {
                field: "offset",
                message: "offset past event end",
            });
        }
        if !full.is_char_boundary(start) {
            return Err(UsageError::InvalidField {
                field: "offset",
                message: "offset splits a character",
            });
        }
        if start == full.len() {
            return Ok(UsageExportPage {
                chunk: None,
                next: Some(UsageExportCursor::After { key: id.to_owned() }),
            });
        }
        let (chunk, next) = fit_chunk(id, &current, &full, start)?;
        Ok(UsageExportPage {
            chunk: Some(chunk),
            next: Some(next),
        })
    }
}

fn full_key_for(owner: &str, vault: &str, id: &str) -> Result<String, UsageError> {
    validate_dimension("idempotencyKey", id, MAX_IDEMPOTENCY_KEY_LEN)?;
    let full = usage_event_key(owner, vault, id);
    validate_key(&full)?;
    Ok(full)
}

fn checked_original(
    owner: &str,
    vault: &str,
    key: &str,
    raw: &[u8],
) -> Result<StoredUsageEvent, UsageError> {
    let stored = decode_entry(raw)?;
    stored.event.validate()?;
    if let Some(cost) = &stored.cost {
        cost.validate()?;
    }
    if stored.event.owner != owner
        || stored.event.vault_id != vault
        || usage_event_key(owner, vault, &stored.event.idempotency_key) != key
    {
        return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
    }
    Ok(stored)
}

fn original_json(stored: &StoredUsageEvent) -> Result<String, UsageError> {
    serde_json::to_string(stored).map_err(|_| UsageError::InvalidField {
        field: "event",
        message: "did not serialize",
    })
}

fn original_digest(full: &str) -> String {
    blake3::hash(full.as_bytes()).to_hex().to_string()
}

fn fit_chunk(
    event_key: &str,
    digest: &str,
    full: &str,
    start: usize,
) -> Result<(UsageExportChunk, UsageExportCursor), UsageError> {
    // Full remaining first with its completion cursor; partials below use InEvent.
    let remaining = &full[start..];
    let after = UsageExportCursor::After {
        key: event_key.to_owned(),
    };
    if fits(event_key, digest, start, remaining, &after)? {
        let chunk = UsageExportChunk {
            event_key: event_key.to_owned(),
            digest: digest.to_owned(),
            offset: start as u64,
            json: remaining.to_owned(),
        };
        return Ok((chunk, after));
    }
    // Strict partials by byte index, each midpoint rounded down to its UTF8
    // boundary, constant auxiliary memory; full already tried.
    let total = remaining.len();
    let at_start = UsageExportCursor::InEvent {
        key: event_key.to_owned(),
        offset: start as u64,
        digest: digest.to_owned(),
    };
    if !fits(event_key, digest, start, "", &at_start)? {
        return Err(UsageError::InvalidField {
            field: "event_key",
            message: "leaves no room in a line",
        });
    }
    let mut lo = 0;
    let mut hi = total;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let mut adj = mid;
        while !full.is_char_boundary(start + adj) {
            adj -= 1;
        }
        if adj == lo {
            let Some(ch) = remaining[lo..].chars().next() else {
                break;
            };
            let next = lo + ch.len_utf8();
            if next >= hi {
                break;
            }
            let cursor = UsageExportCursor::InEvent {
                key: event_key.to_owned(),
                offset: (start + next) as u64,
                digest: digest.to_owned(),
            };
            if fits(event_key, digest, start, &remaining[..next], &cursor)? {
                lo = next;
            } else {
                hi = next;
            }
        } else {
            let cursor = UsageExportCursor::InEvent {
                key: event_key.to_owned(),
                offset: (start + adj) as u64,
                digest: digest.to_owned(),
            };
            if fits(event_key, digest, start, &remaining[..adj], &cursor)? {
                lo = adj;
            } else {
                hi = adj;
            }
        }
    }
    if lo == 0 {
        return Err(UsageError::InvalidField {
            field: "event_key",
            message: "leaves no room in a line",
        });
    }
    let next = UsageExportCursor::InEvent {
        key: event_key.to_owned(),
        offset: (start + lo) as u64,
        digest: digest.to_owned(),
    };
    let chunk = UsageExportChunk {
        event_key: event_key.to_owned(),
        digest: digest.to_owned(),
        offset: start as u64,
        json: remaining[..lo].to_owned(),
    };
    Ok((chunk, next))
}

fn fits(
    event_key: &str,
    digest: &str,
    start: usize,
    json: &str,
    next: &UsageExportCursor,
) -> Result<bool, UsageError> {
    let page = UsageExportPage {
        chunk: Some(UsageExportChunk {
            event_key: event_key.to_owned(),
            digest: digest.to_owned(),
            offset: start as u64,
            json: json.to_owned(),
        }),
        next: Some(next.clone()),
    };
    let wire =
        serde_json::to_vec(&CtlResponse::UsageExport { usage_export: page }).map_err(|_| {
            UsageError::InvalidField {
                field: "usage_export",
                message: "did not serialize",
            }
        })?;
    // The framing newline is exact, as the ctl writer's `push('\n')`.
    Ok(wire.len() + 1 <= MAX_CTL_LINE)
}

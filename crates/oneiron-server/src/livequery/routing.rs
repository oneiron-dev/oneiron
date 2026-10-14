//! Private routing header for the EXISTING server broadcast channel and a
//! socket's own reply queue. This is never a peer wire tag; every socket
//! strips it only after recipient checks. Beside the recipient it carries
//! what the socket's release judges again (DEC-0005): the incarnation of the
//! subscription a frame belongs to, and the rows its body was derived from.
use crate::protocol::{TAG_RPC, TAG_SUB};
use oneiron::EntityId;

const ROUTED_APP: u8 = 255;
/// Marker, recipient, id, incarnation and row count.
const HEADER: usize = 25;
/// The row count of a body whose producer could not name its rows.
const UNNAMED: u32 = u32::MAX;

/// A frame as its routing header addressed it.
pub(super) struct Routed<'a> {
    /// The subscription or request id.
    pub(super) id: u64,
    /// The subscription's incarnation; zero for a request.
    pub(super) incarnation: u64,
    /// The rows its body was derived from; `None` when its producer could
    /// not name them.
    pub(super) rows: Option<Vec<EntityId>>,
    pub(super) frame: &'a [u8],
}

pub(super) fn is_routed(data: &[u8]) -> bool {
    data.first() == Some(&ROUTED_APP)
}

pub(super) fn wrap(
    conn: u32,
    id: u64,
    incarnation: u64,
    rows: Option<&[EntityId]>,
    frame: Vec<u8>,
) -> Vec<u8> {
    let count = rows
        .and_then(|rows| u32::try_from(rows.len()).ok())
        .filter(|count| *count != UNNAMED);
    let rows = count.and(rows).unwrap_or_default();
    let count = count.unwrap_or(UNNAMED);
    let mut data = Vec::with_capacity(HEADER + rows.len() * 16 + frame.len());
    data.push(ROUTED_APP);
    data.extend_from_slice(&conn.to_be_bytes());
    data.extend_from_slice(&id.to_be_bytes());
    data.extend_from_slice(&incarnation.to_be_bytes());
    data.extend_from_slice(&count.to_be_bytes());
    for row in rows {
        data.extend_from_slice(row.as_bytes());
    }
    data.extend(frame);
    data
}

pub(super) fn addressed(data: &[u8], conn: u32) -> Option<Routed<'_>> {
    if !is_routed(data) || data.len() < HEADER {
        return None;
    }
    let recipient = u32::from_be_bytes(data[1..5].try_into().ok()?);
    let id = u64::from_be_bytes(data[5..13].try_into().ok()?);
    let incarnation = u64::from_be_bytes(data[13..21].try_into().ok()?);
    let count = u32::from_be_bytes(data[21..HEADER].try_into().ok()?);
    let (rows, body) = if count == UNNAMED {
        (None, HEADER)
    } else {
        let end = HEADER.checked_add(usize::try_from(count).ok()?.checked_mul(16)?)?;
        let rows = data
            .get(HEADER..end)?
            .chunks_exact(16)
            .map(|bytes| EntityId::from_bytes(bytes.try_into().ok()?).ok())
            .collect::<Option<Vec<_>>>()?;
        (Some(rows), end)
    };
    let frame = data.get(body..)?;
    if recipient != conn || !matches!(frame.first(), Some(&(TAG_SUB | TAG_RPC))) {
        return None;
    }
    Some(Routed {
        id,
        incarnation,
        rows,
        frame,
    })
}

/// A routed frame's app frame, whoever it is addressed to.
#[cfg(test)]
pub(super) fn unwrapped(data: &[u8]) -> &[u8] {
    if !is_routed(data) || data.len() < HEADER {
        return data;
    }
    let count = u32::from_be_bytes(data[21..HEADER].try_into().unwrap_or_default());
    let rows = if count == UNNAMED {
        0
    } else {
        usize::try_from(count).unwrap_or_default()
    };
    data.get(HEADER + rows * 16..).unwrap_or(data)
}

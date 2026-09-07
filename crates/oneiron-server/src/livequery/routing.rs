//! Private routing header for the EXISTING server broadcast channel. This is
//! never a peer wire tag; every socket strips it only after recipient checks.
const ROUTED_APP: u8 = 255;
const HEADER: usize = 13;

pub(super) fn is_routed(data: &[u8]) -> bool {
    data.first() == Some(&ROUTED_APP)
}

pub(super) fn wrap(conn: u32, id: u64, frame: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::with_capacity(HEADER + frame.len());
    data.push(ROUTED_APP);
    data.extend_from_slice(&conn.to_be_bytes());
    data.extend_from_slice(&id.to_be_bytes());
    data.extend(frame);
    data
}

pub(super) fn addressed(data: &[u8], conn: u32) -> Option<(u64, &[u8])> {
    if !is_routed(data) || data.len() <= HEADER {
        return None;
    }
    let recipient = u32::from_be_bytes(data[1..5].try_into().ok()?);
    if recipient != conn || data[HEADER] != crate::protocol::TAG_SUB {
        return None;
    }
    Some((
        u64::from_be_bytes(data[5..13].try_into().ok()?),
        &data[HEADER..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_frames_have_one_recipient_and_no_wire_header() {
        let frame = vec![crate::protocol::TAG_SUB, 0x80];
        let data = wrap(7, 9, frame.clone());
        assert_eq!(addressed(&data, 7), Some((9, frame.as_slice())));
        assert!(addressed(&data, 8).is_none());
        assert!(addressed(&data[..5], 7).is_none());
        assert!(addressed(&wrap(7, 9, vec![crate::protocol::TAG_RPC]), 7).is_none());
    }
}

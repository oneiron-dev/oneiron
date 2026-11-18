//! `SnapshotId`'s side-table key (UC-06 PR 9). The key is derived now, and it spells and reads
//! what the hand-written impls did (M-1 STORED-CHANGE-RULE = A: keep): the id's 16 bytes as they
//! are, read back from exactly 16 bytes and from no other length. Green on main (the hand impls)
//! and on the head (the derive).

use oneiron_records::store::snapshot_catalog::SnapshotId;
use oneiron_store::side_table::key::{FixedSideKey, SideKey};

/// All zero, all `0xff`, the bytes 0x00, 0x11, .. 0xff, and all `:` (the separator byte of the
/// text keys).
fn fixtures() -> [[u8; 16]; 4] {
    let mut pattern = [0_u8; 16];
    for (index, byte) in pattern.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("below 16") * 0x11;
    }
    [[0; 16], [0xff; 16], pattern, [b':'; 16]]
}

fn spelled(id: &SnapshotId) -> Vec<u8> {
    let mut out = Vec::new();
    id.encode_into(&mut out);
    out
}

#[test]
fn the_key_is_the_ids_sixteen_bytes() {
    assert_eq!(<SnapshotId as FixedSideKey>::WIDTH, 16);
    for bytes in fixtures() {
        assert_eq!(spelled(&SnapshotId(bytes)), bytes.to_vec());
    }
}

#[test]
fn a_key_reads_back_as_its_id() {
    for bytes in fixtures() {
        let id = SnapshotId(bytes);
        assert_eq!(SnapshotId::decode_key(&spelled(&id)), Some(id));
    }
}

#[test]
fn only_sixteen_bytes_read_as_an_id() {
    for bytes in fixtures() {
        let key = spelled(&SnapshotId(bytes));
        let wrong_lengths = [
            Vec::new(),
            key[..15].to_vec(),
            key[1..].to_vec(),
            [key.as_slice(), &[0]].concat(),
            [key.as_slice(), key.as_slice()].concat(),
        ];
        for wrong in wrong_lengths {
            assert_eq!(
                SnapshotId::decode_key(&wrong),
                None,
                "{} bytes of {key:?}",
                wrong.len()
            );
        }
    }
}

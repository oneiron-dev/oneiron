//! The `SealedPosition` encoding of a `String` page position, which the
//! historical snapshot pages of core's `graph_fs::snapshot` seal and reopen.
//! It lives beside the trait because `String` is not a core type.

use crate::graph_fs::paging::SealedPosition;

impl SealedPosition for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

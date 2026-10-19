//! The pages LMDB lays rows out in, bounded before an environment exists
//! (FIX 5613): what a restore's copy takes on its disk past its rows' own
//! bytes, so a host's floor can claim it ahead.
//!
//! The model is LMDB data format 3's own layout (mdb.master3, the library
//! this store links), at the page size a new environment on this host
//! takes:
//! - a page is the system page, held to LMDB's 256 bytes to 64 KiB; it loses
//!   a 24-byte header, and on a sealed environment a 40-byte nonce and tag,
//!   which every page is counted to lose;
//! - a leaf node is an 8-byte header, then its key and its value, each
//!   rounded up to an even length, and a 2-byte pointer to it; a value whose
//!   node would pass half a page's room goes to whole overflow pages of its
//!   own, and its node keeps an 8-byte page number;
//! - a full page splits at its middle, so a page a load fills and leaves
//!   behind holds at least half its room: leaves are counted half full;
//! - a branch page holds one node per child, an 8-byte header and the
//!   child's first key, and has two children at least: each level up is
//!   counted half full as well, and no larger than half the level below,
//!   until one page is left.

/// LMDB's page header in data format 3.
const PAGE_HEADER: u64 = 24;
/// A sealed page's nonce and tag, at its end (`heed::page_seal`).
const SEALED_TAIL: u64 = 40;
/// A node's header: its sizes and flags, or a branch's child page number.
const NODE_HEADER: u64 = 8;
/// A node's pointer in its page's index.
const NODE_POINTER: u64 = 2;
/// The page number a node keeps for a value in overflow pages.
const OVERFLOW_PAGE_NUMBER: u64 = 8;
/// The smallest page LMDB writes in.
const MIN_PAGE: u64 = 256;
/// The largest page LMDB writes in, past which it holds a larger system page.
const MAX_PAGE: u64 = 0x10000;

/// The page layout a new environment on this host writes in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PageLayout {
    page: u64,
}

/// One tree's rows, summed as LMDB lays them out ([`PageLayout::add`]).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TreeRows {
    /// Leaf node bytes, pointers included.
    leaf: u64,
    /// Overflow pages its large values take.
    overflow: u64,
    /// Its longest key, rounded up to even.
    longest_key: u64,
    rows: u64,
}

impl PageLayout {
    /// The layout of an environment created on this host now: LMDB takes
    /// the system page, held to its bounds. A system page this host cannot
    /// read is counted as LMDB's largest.
    pub(crate) fn for_new_env() -> Self {
        let page = system_page()
            .filter(|page| page.is_power_of_two())
            .map_or(MAX_PAGE, |page| page.clamp(MIN_PAGE, MAX_PAGE));
        Self { page }
    }

    /// The page size, in bytes.
    pub(crate) fn page(self) -> u64 {
        self.page
    }

    /// The bytes of a page left for nodes.
    fn room(self) -> u64 {
        self.page - PAGE_HEADER - SEALED_TAIL
    }

    /// The largest node a leaf keeps whole: half a page's room, even, less
    /// its pointer.
    fn node_max(self) -> u64 {
        ((self.room() / 2) & !1) - NODE_POINTER
    }

    /// Adds one row of `key` and `value` bytes to `tree`.
    pub(crate) fn add(self, tree: &mut TreeRows, key: u64, value: u64) {
        let key = even(key);
        let mut node = NODE_HEADER.saturating_add(key).saturating_add(even(value));
        if node > self.node_max() {
            let pages = PAGE_HEADER
                .saturating_add(SEALED_TAIL - 1)
                .saturating_add(value)
                / self.page
                + 1;
            tree.overflow = tree.overflow.saturating_add(pages);
            node = NODE_HEADER + key.saturating_add(OVERFLOW_PAGE_NUMBER);
        }
        tree.leaf = tree.leaf.saturating_add(node + NODE_POINTER);
        tree.longest_key = tree.longest_key.max(key);
        tree.rows = tree.rows.saturating_add(1);
    }

    /// The bytes `tree` takes in whole pages: its leaves and branches, each
    /// level half full, and its overflow pages. An empty tree takes none.
    pub(crate) fn bytes(self, tree: &TreeRows) -> u64 {
        if tree.rows == 0 {
            return 0;
        }
        let room = self.room();
        let mut level = tree.leaf.saturating_mul(2).div_ceil(room).max(1);
        let mut pages = level;
        let branch = even(NODE_HEADER.saturating_add(tree.longest_key)) + NODE_POINTER;
        while level > 1 {
            let by_room = level
                .saturating_mul(branch)
                .saturating_mul(2)
                .div_ceil(room)
                .max(1);
            level = by_room.min((level / 2).max(1));
            pages = pages.saturating_add(level);
        }
        pages
            .saturating_add(tree.overflow)
            .saturating_mul(self.page)
    }
}

/// `n` rounded up to an even length, as LMDB places keys and values.
fn even(n: u64) -> u64 {
    n.saturating_add(1) & !1
}

#[cfg(unix)]
fn system_page() -> Option<u64> {
    // SAFETY: `sysconf` reads a system constant: it takes no pointer and has
    // no precondition, and a negative answer is read as unknown.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(page).ok()
}

#[cfg(not(unix))]
fn system_page() -> Option<u64> {
    None
}

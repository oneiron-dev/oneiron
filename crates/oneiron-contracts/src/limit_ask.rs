//! The engine's `[limits]` rows and the port a crossed row asks through
//! (ARCH-0044 C5, OF-520).
//!
//! A row is a bound, set far above everyday use, on work an engine door
//! serves. Crossing one never refuses: the door measures where the bound
//! lives, tells the installed [`LimitAsk`] port, and serves the work whole.
//! The server installs its OF-520 questions as the port when it opens the
//! vault; an embedding app may install its own. With no port installed, a
//! crossing asks nobody.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

/// What a memory-derived row comes to when the machine's memory cannot be
/// read.
const MEMORY_FALLBACK_BYTES: u64 = 256 << 20;

/// One engine `[limits]` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EngineLimit {
    /// Serialized bytes of one keyed-memory search filter
    /// (`vault.kv.search`).
    KeyedFilterJsonBytes,
    /// Bytes of one code-mode result kept inline in its LMDB row. A body past
    /// it is written to the vault's file-backed body store instead; the row
    /// picks where a result lives and never refuses one.
    CodeResultInlineBytes,
    /// Free disk the result body store keeps. Writing a body that leaves less
    /// asks whether everything is okay and stores the body whole anyway.
    CodeResultDiskFloorBytes,
    /// Bytes one result read (a search or query facet) scans before it
    /// answers with a cursor, never a false "no match".
    CodeResultScanBytes,
    /// Bytes of result bodies every code-mode run in the process keeps in
    /// memory at once: an eighth of the machine's memory (the least of its
    /// RAM and its container limit, [`machine_memory_bytes`]), 256 MiB when
    /// that cannot be read. Past it, a body stays in its file and is read
    /// from there by range.
    CodeResultMemoryBytes,
    /// Bytes of result bodies one run keeps in memory at once: a sixty-fourth
    /// of the machine's memory, 256 MiB when that cannot be read. A run's
    /// live share is the least of this and the pool split between the runs
    /// open on it.
    CodeResultSessionMemoryBytes,
    /// Bytes of image forms one model call's context takes when its host
    /// names no room of its own (OF-329's lazy images). Past the room each
    /// image steps down its ladder: the full image, then a thumbnail beside
    /// its description, then the description alone, each with its view
    /// handle. An image no form of which fits the room a read had left is
    /// served as its handle alone, and asks whether everything is okay: the
    /// crossing measures the bytes its smallest form needed.
    ImageRoomBytes,
    /// Readers one run has queued and not yet started. Past it asks whether
    /// everything is okay and keeps queueing; it never refuses and never
    /// bounds the active window.
    CodeReaderBacklog,
    /// Options one ask offers (`tasks.ask` `what.options`). Every option is
    /// kept and validated past it.
    AskOptions,
    /// UTF-8 bytes of one ask option's display text, each option measured on
    /// its own. The text is kept whole; a board or UI shows its own preview.
    AskOptionTextBytes,
    /// Context references one ask names (`what.context_refs`). Each is still
    /// read and held to its disclosure past it.
    AskContextRefs,
    /// Recipients one ask resolves to, each a member TASK of its group.
    AskRecipients,
    /// MessagePack bytes of one ask spec as its caller sent it, before its
    /// task's class fills it in.
    AskSpecMsgpackBytes,
    /// Reminder delays one ask carries once its class's are inherited.
    AskReminders,
    /// Provenance references one ask answer cites (`tasks.answer`).
    AnswerProvenanceRefs,
    /// Distinct wait identities one ask holds, consumed ones included: the
    /// step keys external `tasks.wait` calls bind, or the waiting steps of
    /// one run branch.
    AskWaitIdentities,
    /// Messages a LINE Official Account has sent this month, as LINE counts
    /// them (`totalUsage`), read before each push. The bound is the account
    /// plan's monthly push allowance (`[line]`), told at the send itself.
    /// Past it the push still goes: a paid plan bills the overage, and LINE
    /// itself refuses a free plan's.
    LinePushMonthly,
    /// Bytes of text one notes import or folder rescan holds, every note of
    /// the folder together, while their links resolve. Past it the folder is
    /// read and imported whole.
    ImportFolderTextBytes,
    /// Notes one notes import or folder rescan reads from its folder,
    /// continuation parts included. Past it the folder is read and imported
    /// whole.
    ImportFolderNotes,
    /// Messages one history import, or one session serve's queue lands,
    /// holds decoded until it lands them all. Past it the import lands whole.
    ImportDecodedMessages,
    /// Bytes those decoded messages hold, ids and titles included. Past it
    /// the import lands whole.
    ImportDecodedBytes,
    /// Bytes one signature image decode (`POST /sign/image`) may allocate,
    /// its decoded raster included: the decoder's own alloc bound is set from
    /// it. An image whose header declares a raster past it asks whether
    /// everything is okay, and is decoded whole.
    SignatureDecodeBytes,
    /// Comment edits one PowerPoint comment proposal carries: new threads,
    /// replies and resolutions together. Past it the proposal is written
    /// and served whole.
    PptxCommentPatches,
    /// Stored cells one workbook import writes into a live office body,
    /// every sheet together. Past it the workbook is imported whole.
    ImportXlsxLiveCells,
}

impl EngineLimit {
    /// Every engine row.
    pub const ALL: [Self; 23] = [
        Self::KeyedFilterJsonBytes,
        Self::CodeResultInlineBytes,
        Self::CodeResultDiskFloorBytes,
        Self::CodeResultScanBytes,
        Self::CodeResultMemoryBytes,
        Self::CodeResultSessionMemoryBytes,
        Self::ImageRoomBytes,
        Self::CodeReaderBacklog,
        Self::AskOptions,
        Self::AskOptionTextBytes,
        Self::AskContextRefs,
        Self::AskRecipients,
        Self::AskSpecMsgpackBytes,
        Self::AskReminders,
        Self::AnswerProvenanceRefs,
        Self::AskWaitIdentities,
        Self::LinePushMonthly,
        Self::ImportFolderTextBytes,
        Self::ImportFolderNotes,
        Self::ImportDecodedMessages,
        Self::ImportDecodedBytes,
        Self::SignatureDecodeBytes,
        Self::PptxCommentPatches,
        Self::ImportXlsxLiveCells,
    ];

    /// The config key that sets the row.
    pub const fn key(self) -> &'static str {
        match self {
            Self::KeyedFilterJsonBytes => "limits.keyed_filter_json_bytes",
            Self::CodeResultInlineBytes => "limits.code_result_inline_bytes",
            Self::CodeResultDiskFloorBytes => "limits.code_result_disk_floor_bytes",
            Self::CodeResultScanBytes => "limits.code_result_scan_bytes",
            Self::CodeResultMemoryBytes => "limits.code_result_memory_bytes",
            Self::CodeResultSessionMemoryBytes => "limits.code_result_session_memory_bytes",
            Self::ImageRoomBytes => "limits.image_room_bytes",
            Self::CodeReaderBacklog => "limits.code_reader_backlog",
            Self::AskOptions => "limits.ask_options",
            Self::AskOptionTextBytes => "limits.ask_option_text_bytes",
            Self::AskContextRefs => "limits.ask_context_refs",
            Self::AskRecipients => "limits.ask_recipients",
            Self::AskSpecMsgpackBytes => "limits.ask_spec_msgpack_bytes",
            Self::AskReminders => "limits.ask_reminders",
            Self::AnswerProvenanceRefs => "limits.answer_provenance_refs",
            Self::AskWaitIdentities => "limits.ask_wait_identities",
            Self::LinePushMonthly => "line.monthly_push_allowance",
            Self::ImportFolderTextBytes => "limits.import_folder_text_bytes",
            Self::ImportFolderNotes => "limits.import_folder_notes",
            Self::ImportDecodedMessages => "limits.import_decoded_messages",
            Self::ImportDecodedBytes => "limits.import_decoded_bytes",
            Self::SignatureDecodeBytes => "limits.signature_decode_bytes",
            Self::PptxCommentPatches => "limits.pptx_comment_patches",
            Self::ImportXlsxLiveCells => "limits.import_xlsx_live_cells",
        }
    }

    /// What the row is set to when nothing sets it.
    pub fn default_bound(self) -> u64 {
        match self {
            Self::KeyedFilterJsonBytes => 64 << 20,
            Self::CodeResultInlineBytes => 1 << 20,
            Self::CodeResultDiskFloorBytes => 1 << 30,
            Self::CodeResultScanBytes => 256 << 20,
            Self::CodeResultMemoryBytes => memory_share(8),
            Self::CodeResultSessionMemoryBytes => memory_share(64),
            Self::ImageRoomBytes => 32 << 20,
            Self::CodeReaderBacklog => 256,
            Self::AskOptions => 65_536,
            Self::AskOptionTextBytes => 1 << 20,
            Self::AskContextRefs => 65_536,
            Self::AskRecipients => 65_536,
            Self::AskSpecMsgpackBytes => 256 << 20,
            Self::AskReminders => 65_536,
            Self::AnswerProvenanceRefs => 65_536,
            Self::AskWaitIdentities => 1 << 20,
            // LINE's free plan allowance, as the plan row defaults.
            Self::LinePushMonthly => 200,
            Self::ImportFolderTextBytes => 256 << 20,
            Self::ImportFolderNotes => 100_000,
            Self::ImportDecodedMessages => 1_000_000,
            Self::ImportDecodedBytes => 1 << 30,
            Self::SignatureDecodeBytes => 1 << 30,
            Self::PptxCommentPatches => 10_000,
            Self::ImportXlsxLiveCells => 200_000,
        }
    }
}

/// `1/divisor` of the machine's memory, or the fallback when it cannot be
/// read.
fn memory_share(divisor: u64) -> u64 {
    machine_memory_bytes()
        .map(|memory| memory / divisor)
        .filter(|bytes| *bytes > 0)
        .unwrap_or(MEMORY_FALLBACK_BYTES)
}

/// The memory this process may use: the least of the machine's RAM and the
/// limit of the container it runs in (cgroup v2 `memory.max`, or v1
/// `memory.limit_in_bytes`). Read once. `None` when neither can be read.
pub fn machine_memory_bytes() -> Option<u64> {
    static MEMORY: OnceLock<Option<u64>> = OnceLock::new();
    *MEMORY.get_or_init(
        || match (physical_memory_bytes(), container_memory_bytes()) {
            (Some(physical), Some(container)) => Some(physical.min(container)),
            (physical, container) => physical.or(container),
        },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn physical_memory_bytes() -> Option<u64> {
    // SAFETY: `sysconf` reads a system constant: it takes no pointer and has
    // no precondition, and a negative answer is read as unknown below.
    let (pages, page_bytes) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    u64::try_from(pages)
        .ok()?
        .checked_mul(u64::try_from(page_bytes).ok()?)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn physical_memory_bytes() -> Option<u64> {
    None
}

/// The container's memory limit. An unlimited group reads `max` (v2) or a
/// number past any RAM (v1), which the minimum above discards.
fn container_memory_bytes() -> Option<u64> {
    [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .iter()
    .find_map(|path| std::fs::read_to_string(path).ok()?.trim().parse().ok())
}

/// What each engine row is set to: its default, unless set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineLimits {
    set: BTreeMap<EngineLimit, u64>,
}

impl EngineLimits {
    /// What `row` is set to.
    pub fn bound(&self, row: EngineLimit) -> u64 {
        self.set
            .get(&row)
            .copied()
            .unwrap_or_else(|| row.default_bound())
    }

    /// Sets `row` to `bound`.
    pub fn set(&mut self, row: EngineLimit, bound: u64) {
        self.set.insert(row, bound);
    }
}

/// Where a crossed engine row asks whether everything is okay. It is told on
/// the serving path, possibly inside a write transaction, so it must not wait
/// on storage or on the work it is told about; keeping the question is its
/// own business.
pub trait LimitAsk: Send + Sync {
    /// `row`, set to `bound`, measured `measured`. The work is served either
    /// way.
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64);
}

/// One open vault's engine rows: what they are set to, fixed when it opened,
/// and the port they ask through, none until a host installs one.
#[derive(Default)]
pub struct LimitWatch {
    bounds: EngineLimits,
    ask: RwLock<Option<Arc<dyn LimitAsk>>>,
}

impl LimitWatch {
    /// Rows set to `bounds`, asking nobody yet.
    pub fn new(bounds: EngineLimits) -> Self {
        Self {
            bounds,
            ask: RwLock::default(),
        }
    }

    /// Installs the port crossings ask through, in place of any before it.
    pub fn install(&self, ask: Arc<dyn LimitAsk>) {
        *self.ask.write().unwrap_or_else(PoisonError::into_inner) = Some(ask);
    }

    /// What `row` is set to.
    pub fn bound(&self, row: EngineLimit) -> u64 {
        self.bounds.bound(row)
    }

    /// Work measured `measured` against `row`: past what the row is set to,
    /// the installed port is asked. It never refuses; the caller serves the
    /// work either way.
    pub fn measure(&self, row: EngineLimit, measured: u64) {
        let bound = self.bound(row);
        if measured > bound {
            self.crossed(row, bound, measured);
        }
    }

    /// A floor measured `measured` against `row`: below what the row is set
    /// to, the installed port is asked. It never refuses either.
    pub fn floor(&self, row: EngineLimit, measured: u64) {
        let bound = self.bound(row);
        if measured < bound {
            self.crossed(row, bound, measured);
        }
    }

    /// Tells the installed port that `row`, standing at `bound` for this
    /// work, measured `measured`: for a bound computed at the site, such as a
    /// run's live share of a memory pool.
    pub fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        let ask = self
            .ask
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(ask) = ask {
            ask.crossed(row, bound, measured);
        }
    }
}

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

// Every row's list, config key and default: the row tables.
mod engine_rows;

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
    /// Bytes of one foreign pack script run's typed output. Past it the
    /// output is read whole, up to the sandbox's own file bound.
    PackScriptOutputBytes,
    /// Inbound events, verbs or connector events one foreign pack script run
    /// emits, whichever is most. Past it every row is served.
    PackScriptOutputRows,
    /// Entries accumulated in one attempt's append-only pack manifest
    /// (skill-index, skill and actor-claim loads). Past it, the row asks
    /// whether everything is okay and every entry is kept.
    AttemptManifestEntries,
    /// Receipts accumulated in one attempt's append-only cancel protocol
    /// history (requests, refusals, landing rows and the terminal receipt).
    /// Past it, the row asks whether everything is okay and every receipt is
    /// kept.
    AttemptCancelReceipts,
    /// Attempt rows one retry-tip walk visits along a single retry lineage.
    /// Past it, the row asks whether everything is okay while the whole
    /// lineage is still read.
    AttemptRetryTipRows,
    /// Steps one saved workflow holds, measured at every put of it (its
    /// save, update and fork, raw and batch puts, and sync replay) and where
    /// it is snapshotted for a dispatch. Past it, the row asks whether
    /// everything is okay and every step is kept.
    WorkflowSteps,
    /// Bytes of one saved workflow's name, measured at every put of it.
    /// Past it, the row asks whether everything is okay and the name is
    /// stored whole.
    WorkflowNameBytes,
    /// Bytes of the judge's rubric (the active shared `judge` skill's text)
    /// one judgment or label re-check reads. Past it the rubric is read whole.
    JudgeRubricBytes,
    /// Items one Dreamer-maintenance or Coach row holds: an owner policy's
    /// rules, aliases, groups, voices or evidence refs, a diagnostic's or
    /// card's evidence refs, a training offer's losses or refs. Past it the
    /// row is kept whole.
    MaintenanceRowItems,
    /// Bytes of one text field a Dreamer-maintenance or Coach row holds (a
    /// template, a rule's instruction, a route, a draft, an offer's note).
    /// Past it the text is kept whole.
    MaintenanceTextBytes,
    /// Rows one Dreamer-maintenance or Coach pass reads to find its work
    /// (receipts, calls, runs). Past it the pass reads them all.
    MaintenanceScanRows,
    /// Bytes of the skill instructions one held-out replay judgment reads.
    /// Past it the instructions are read whole.
    JudgeInstructionsBytes,
    /// Bytes of replay text (runs' tasks and responses) one held-out replay
    /// judgment's state carries. Past it the replays are read whole, cut only
    /// where the decision ladder's state bound would refuse the call.
    JudgeReplayTextBytes,
    /// UTF-8 bytes of the task a contribution check's judge reads for one
    /// fork: the replayed step's non-system message text. Past it the row
    /// asks whether everything is okay and the judge reads the task whole.
    ContributionJudgeTaskBytes,
    /// UTF-8 bytes of one contribution fork's answer its judge reads. Past
    /// it the row asks and the judge reads the answer whole.
    ContributionJudgeAnswerBytes,
    /// Callable skills one call nests, itself included: a callable that
    /// calls another runs the inner one's step inside its own. Past it the
    /// row asks whether everything is okay and the call runs.
    CallableNestDepth,
    /// Model steps one engine executor run takes. When a run reaches it, the
    /// row asks whether everything is okay, and the run keeps going.
    ExecutorRunSteps,
    /// Bytes of the banked source clip one cloned-voice render sends as its
    /// reference. Past it the whole clip is still sent.
    VoiceReferenceBytes,
    /// Bytes of one signing item's PDF the e-sign seal holds in memory: its
    /// original or its prepared copy, whichever is larger. Past it asks
    /// whether everything is okay, and the item is prepared and sealed whole.
    EsignPdfBytes,
    /// VAD turns one affect state read takes in, supplied or derived. Past it
    /// every turn is read.
    StateVadTurns,
    /// Seconds of look-back one affect state window asks for. Past it the
    /// whole window is read.
    StateWindowSeconds,
    /// Observations one detector pass selects before its detectors see them.
    /// Past it every observation is read.
    DetectorObservations,
    /// Events one deterministic or signed detector run persists. Past it
    /// every event is kept.
    DetectorEvents,
    /// Scoped receipts one tripwire or consent-detector window reads or is
    /// handed. Past it every receipt is projected.
    DetectorReceiptRows,
    /// Dreamer run facts one output-tripwire pass is handed. Past it every
    /// fact is projected.
    DreamerFactsRows,
    /// Proposals one healer bundle carries. Past it the whole bundle is
    /// reviewed.
    HealerProposals,
    /// Diagnostic refs one repair proposal or dev-runner corpus names. Past
    /// it every ref is kept.
    RepairDiagnosticRefs,
    /// Labeled examples one centroid classification reads. Past it every
    /// label is kept in its snapshot and its finding's evidence.
    CentroidLabels,
    /// Consecutive raised runs a model-graded detector policy asks for, or
    /// reviewed positives its mint needs. Past it the policy runs as set.
    DetectorConsecutive,
    /// Runs in one ordered telemetry window a model-graded detector
    /// validates. Past it the whole window is validated and kept.
    DetectorWindowRuns,
    /// Bytes of one blocked report's canonical stored detail. Past it the
    /// detail is kept whole.
    BlockedDetailBytes,
    /// Bytes of one executor, judge or evidence reference a seal check names.
    /// Past it the reference is kept whole.
    SealReferenceBytes,
    /// Each count threshold a tripwire policy sets: consent depth, actor
    /// writes and retrieval regressions. Past it the tripwire runs at that
    /// threshold.
    TripwireThreshold,
    /// Documents one e-sign sweep is handed: a seal backstop, expiry or
    /// reminder batch. Past it the row asks whether everything is okay and
    /// every document in the batch is swept.
    EsignSweepDocuments,
    /// Signing principals one owner names for e-sign. Past it the row asks
    /// and every principal is kept.
    EsignSigningPrincipals,
    /// Bytes of one uploaded signature image, as it arrived. Past it the
    /// envelope's sender is asked whether everything is okay, and the image
    /// is decoded, stored and bound.
    EsignSignatureInputBytes,
    /// Bytes of one signature image's canonical PNG re-encoding. Past it the
    /// envelope's sender is asked, and the image is stored and bound.
    EsignSignaturePngBytes,
    /// Canonical signature image bytes one signing document holds in all.
    /// Past it the envelope's sender is asked, and the image is stored and
    /// bound.
    EsignSignatureDocumentBytes,
    /// Signature images one recipient of a signing document holds. Past it
    /// the envelope's sender is asked, and the image is stored and bound.
    EsignSignatureRecipientImages,
    /// Bytes of one request body a public signing door spools once its
    /// capability is admitted: an act, a PDF or preview read, a signature
    /// image or its read-back. Past it the envelope's sender is asked whether
    /// everything is okay, and the body is read whole. The owner's field
    /// editor measures its admitted layout body here too (FIX 5618); past it
    /// the vault owner is asked, and the layout is computed whole.
    EsignBodyBytes,
    /// Bytes of one PDF the owner's field editor sends `POST /sign/geometry`
    /// under its editor token (FIX 5618). Past it the vault owner is asked
    /// whether everything is okay, and the PDF is spooled and inspected whole.
    EsignGeometryBodyBytes,
    /// Bytes of one sealed PDF the seal host accepted. Past it the row asks
    /// whether everything is okay, and the sealed PDF is kept whole.
    SealOutputBytes,
    /// Bytes one seal adds to its prepared PDF: the signature revision, its
    /// validation material and timestamps. Past it the row asks, and the
    /// sealed PDF is kept whole.
    SealGrowthBytes,
    /// Objects of one PDF snapshot the seal parses. Past it the row asks
    /// and the PDF is sealed or verified whole; only ISO 32000-1's
    /// 8,388,607 objects refuse it.
    SealPdfObjects,
    /// Raw object definitions in one revision of a PDF the seal analyzes,
    /// shadowed and unindexed ones included. Past it the row asks and every
    /// definition is accounted for.
    SealRawDefinitions,
    /// Bytes of the largest frame the seal host sends its organ in one call,
    /// as encoded: the call, or an answer. Past it the row asks and the
    /// frame is sent whole.
    SealCallFrameBytes,
    /// Bytes of the largest frame the seal organ sends back in one call, as
    /// encoded: its reply, which carries the sealed PDF inline on macOS, or
    /// an ask. Past it the row asks and the frame is read whole.
    SealReplyFrameBytes,
    /// Tokens one structural pass of the seal lexes: a revision analysis, or
    /// one classic xref section. Past it the row asks and the pass runs to
    /// its end.
    SealStructuralWork,
    /// Revisions in the xref chain of a PDF the seal reads. Past it the row
    /// asks and every revision is followed.
    SealRevisions,
    /// Prefix bytes one pass of the seal over a revision chain parses,
    /// summed over its revisions. Past it the row asks and every prefix is
    /// parsed.
    SealPrefixBytes,
    /// Bytes one extraction of a PDF's DSS validation material decodes,
    /// across its Certs, CRLs and OCSPs. Past it the row asks and the
    /// material is read whole, each stream decoded whole.
    SealDssDecodeBytes,
    /// Signing-identity asks (`seal.identity`) one seal call makes. Past it the
    /// row asks and the pinned identity is answered again.
    SealIdentityAsks,
    /// Signature asks (`seal.sign`) one seal call makes, one at most for each
    /// revision the engine wrote. Past it the row asks and each is answered.
    SealSignAsks,
    /// Fetch asks (`net.fetch`, timestamps and CRLs) one seal call makes. Past
    /// it the row asks and each fetch inside the grant's allowlist runs.
    SealFetchAsks,
    /// Asks of every verb one seal call makes. Past it the row asks and the
    /// call's asks are answered.
    SealAsks,
    /// Answer bytes one seal call is lent: values and data, identity, signatures
    /// and fetched bodies. Past it the row asks and the call's booking grows to
    /// hold them.
    SealAnswerBytes,
    /// Bytes of one CRL a seal fetches. Past it the row asks and the CRL is read
    /// whole.
    SealCrlBytes,
    /// Bytes of one timestamp reply a seal fetches. Past it the row asks and the
    /// reply is read whole.
    SealTsaBytes,
    /// Bytes of one seal verdict's report JSON. Past it the row asks and the
    /// report is carried whole.
    SealReportJsonBytes,
    /// Bytes the largest object stream of a prepared PDF decodes to, read where
    /// the engine writes its signature revisions. Past it the row asks and the
    /// PDF is read whole, each stream decoded whole.
    SealPreparedStreamBytes,
    /// Bytes the largest single stream a seal reads decodes to: an object or
    /// xref stream its loader decodes, or one DSS entry. Past it the row asks
    /// and the stream is decoded whole.
    SealStreamDecodeBytes,
    /// Tokens the seal lexes in one stream dictionary to find its `/Length`.
    /// Past it the row asks and the header is lexed to its `stream` keyword.
    SealStreamHeaderTokens,
    /// Nesting depth of one PDF value the seal lexes: literal-string
    /// parentheses, or arrays and dictionaries. Past it the row asks and the
    /// value is read whole.
    SealPdfDepth,
    /// Reference links behind one security-checked name (`/Type`, `/FT`,
    /// `/S`) the seal resolves. Past it the row asks and the chain is followed
    /// to its name.
    SealSecurityNameHops,
    /// Reference links of one other chain the seal follows. Past it the row
    /// asks and the chain is followed to its object.
    SealReferenceHops,
    /// Reference steps one measurement of a PDF's DSS coverage takes over all
    /// its chains. Past it the row asks and every chain is followed.
    SealDssReferenceWork,
    /// Nodes one descent of a PDF's AcroForm field tree visits. Past it the row
    /// asks and the tree is walked whole.
    SealFieldTreeWork,
    /// DER bytes of the largest CMS or timestamp token one seal writes into a
    /// signature hole. Past it the row asks; a revision the seal writes grows
    /// its hole to hold it.
    SealContentsBytes,
    /// Asks of every verb one organ call makes, against its install grant's own
    /// count, or this row's for a grant that keeps the factory one. Past it the
    /// row asks and each granted ask is answered.
    OrganAsks,
    /// Asks of one verb one organ call makes, against the count its install
    /// grant names for the verb. Past it the row asks and each is answered.
    OrganAskPerVerb,
    /// Answer bytes one organ call is lent, values and data, against its install
    /// grant's own. Past it the row asks and the call's booking grows to hold
    /// them.
    OrganAnswerBytes,
    /// Body bytes of one granted fetch, against its install grant's own. Past it
    /// the row asks and the body is read to its end.
    OrganFetchBytes,
    /// Redirects one granted fetch follows, each hop checked against the
    /// allowlist afresh. Past it the row asks and the fetch goes on.
    OrganFetchRedirects,
    /// Bytes of one ask's value, as encoded. Past it the row asks and the ask is
    /// read whole.
    OrganAskValueBytes,
    /// Bytes of one fetch ask's purpose. Past it the row asks and the purpose is
    /// kept whole.
    OrganFetchPurposeBytes,
    /// Bytes one organ call's outputs hold together, against its install grant's
    /// own. Past it the row asks and the call's booking grows to keep them.
    OrganOutputBytes,
    /// Bytes of the largest frame the host sends an organ in one call, as
    /// encoded, against its install grant's own. Past it the row asks and the
    /// frame is sent whole.
    OrganCallFrameBytes,
    /// Bytes of the largest frame an organ sends back in one call, as encoded,
    /// against its install grant's own. Past it the row asks and the frame is
    /// read whole.
    OrganReplyFrameBytes,
    /// Bytes of one organ error's or ask refusal's detail. Past it the row asks
    /// and the detail is kept whole.
    OrganDetailBytes,
    /// Bytes of one ask's verb on its receipt line. Past it the row asks and the
    /// verb is kept whole.
    OrganVerbBytes,
    /// Bytes of one organ output's name. Past it the row asks and the name is
    /// kept whole.
    OrganOutputNameBytes,
    /// Bytes of one organ output's media type. Past it the row asks and the
    /// media type is kept whole.
    OrganMediaTypeBytes,
    /// Bytes of one fetch's origin on its receipt line. Past it the row asks and
    /// the origin is kept whole.
    OrganFetchOriginBytes,
    /// Bytes of one fetched body's Content-Type. Past it the row asks and the
    /// Content-Type is kept whole.
    OrganContentTypeBytes,
    /// Notes of one kind one organ call's receipt keeps: touched locators,
    /// warnings or losses, each kind on its own. Past it the row asks and
    /// every note is kept, in order.
    OrganNoteItems,
    /// Bytes of one note an organ call's receipt keeps: an encoded locator, a
    /// warning or a loss's detail. Past it the row asks and the note is kept
    /// whole.
    OrganNoteBytes,
    /// Bytes of one loss's code an organ call's receipt keeps. Past it the row
    /// asks and the code is kept whole.
    OrganLossCodeBytes,
    /// Bytes the organ host's budget holds at its peak when a live call grows
    /// past it: one elected call goes on, its overcommit accounted and on its
    /// receipt, while new calls wait for the budget to drain. Measured against
    /// the host's own budget.
    OrganMemoryBytes,
    /// Deadline jobs one caller has running at once: the recalls and searches
    /// a door answers at their deadline, each counted until its work ends,
    /// after its answer too (SCAN C030). Past it the job runs on and the row
    /// asks, as the typed `deadline_jobs_high` check naming the caller and the
    /// count, once per caller per window; nothing is refused, queued or
    /// dropped.
    DeadlineJobsPerCaller,
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

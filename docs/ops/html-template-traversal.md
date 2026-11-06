# HTML template traversal

HTML templates use explicit worklists for validation, text merge and rendering.
Supported nesting does not fail solely because its DOM depth exceeds 64.

Rendering keeps the caller-owned flow. Nested table cells use separate owned
flows. A cell is flushed before it joins its original row band, and that band
is committed before the next band starts. CSS cascade, list numbering, page
breaks, margins and table geometry keep their existing order and rules.

This does not change the supported tags, attributes, selectors, fonts or PDF
codecs. Invalid content and invalid geometry still return their existing errors.
The minimum table-cell width remains 12 points, with the existing 6-point spacing.

The explicit stacks remove the parser and renderer's structural depth refusals.
They do not establish complete heap admission or deadline coverage for the HTML
parser, CSS helpers, worklists or layout buffers. Those parts of FIX 9615 remain
open. Rebuild the matching engine and server to deploy this change; there is no
storage-format, configuration or client-schema change.

## Admitted traversal and work deadline

`template::render_html_template_admitted` keeps the same HTML, merge and geometry
rules. The caller supplies an `Arc<dyn render::InspectionMemory>` and an absolute
`std::time::Instant` work deadline. The ordinary `render_html_template` and
`prepare_content*` entry points remain unadmitted and set no work deadline.
No timer, default duration or new content limit is installed.

Traversal and layout-container backing is admitted before its requested allocation:
validation and render stacks, CSS rule/match containers, row and band containers,
nested-flow containers, table-row descriptors, Flow page/line containers and
per-page operation containers. Growth holds the old
backing admission while reserving the full replacement. It then settles the
reported capacity, moves the elements and frees the old backing before returning
its admission. Popping an element does not return live capacity. Owned iterators
keep their container's admission until they free that backing.

The requested allocation is admitted before `try_reserve_exact`; any capacity
surplus reported by the standard allocator is settled after allocation. This is
not a bound on transient allocator surplus or allocator metadata. Container
backing by itself does not count the heap payload owned by its elements.
DOM/parser and selector internals, merge/CSS and text-normalization strings,
encoding scratch, sorting scratch, other operation payloads, fonts, PDF objects
and output bytes remain outside this admission slice.
A drained line keeps its backing admission. Page-operation containers remain
owned by the generic native `Content` while it encodes them; `AsRef` borrows the
operations without detaching their backing guard. Cell-page operations move to
the parent container while their source iterator keeps its backing admission.

Owned Windows-1252 run-text bytes also use the caller's memory admission. Each
run retains its actual backing capacity, including an optional leading space.
Moving text into a PDF string transfers that exact admission to the owning
page before moving the bytes, without cloning or charging them again. A page
owns its operations before its aggregate text guard, so it frees those bytes
before returning their admission. Table-cell pages transfer both their text
admission and operations into the parent. The generic native `Content` owns
that page through encoding, including error returns. The encoded PDF buffer
and the codec's own string-escaping scratch are not counted by this guard.

Cooperative checkpoints run through validation, merge/CSS, render, text/run,
table and page loops, and around parsing and PDF writing. Expiry returns
`ContentTemplateError::WorkDeadline`. A real host memory-admission refusal still
uses its existing `ContentTemplateError::Pdf` route. Memory-floor wait deadlines
are not substituted for work checkpoints. An individual parser, matcher,
encoding, sort or PDF-codec call is not preempted; this is not a wall-time bound
on those calls. Full FIX 9615 memory and deadline coverage remains open.

Native PDF output writing also checks the same work deadline at its `Write`
callbacks before forwarding bytes or flushes to the original output vector.
The first actual work-deadline refusal survives the native I/O error channel as
`WorkDeadline`; a non-deadline I/O failure keeps the existing `Overflow` result.
This adds no output copy or output-memory admission. Work between callbacks,
including an allocation or one write, is not preempted.

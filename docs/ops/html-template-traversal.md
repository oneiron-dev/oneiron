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
DOM/parser and selector internals, sorting scratch, font
dictionaries, PDF document/codec objects and output bytes remain outside this
admission slice.
A drained line keeps its backing admission. Page-operation containers remain
owned by the generic native `Content` while it encodes them; `AsRef` borrows the
operations without detaching their backing guard. Cell-page operations move to
the parent container while their source iterator keeps its backing admission.

Owned Windows-1252 run-text bytes also use the caller's memory admission. Each
run retains its actual backing capacity, including an optional leading space.
Moving text into a PDF string transfers that exact admission to the owning
page before moving the bytes, without cloning or charging them again. A page
owns its operations before its aggregate payload guard, so it frees those bytes
before returning their admission. Table-cell pages transfer both their text
admission and operations into the parent. The generic native `Content` owns
that page through encoding, including error returns. The encoded PDF buffer
and the codec's own string-escaping scratch are not counted by this guard.

PDF operation names, operand-vector backing and the `F0`–`F3` font-name byte
vectors use that same page payload admission. Numeric operands own no further
heap allocation. Each owned allocation transfers its measured capacity to the
page before the native operation takes it; the original buffers move without
cloning or a second charge. Operation names keep their original valid UTF-8
bytes when their admitted vector becomes a `String`. This does not admit the
PDF font dictionaries or the document/codec's own allocations.

Cooperative checkpoints run through validation, merge/CSS, render, text/run,
table and page loops, and around parsing and PDF writing. Expiry returns
`ContentTemplateError::WorkDeadline`. A real host memory-admission refusal still
uses its existing `ContentTemplateError::Pdf` route. Memory-floor wait deadlines
are not substituted for work checkpoints. An individual parser, matcher,
encoding, sort or PDF-codec call is not preempted; this is not a wall-time bound
on those calls. Full FIX 9615 memory and deadline coverage remains open.

Native page-content encoding and final PDF output writing check the same work
deadline at their `Write` callbacks before forwarding bytes or flushes to the
original page or output vector.
The first actual work-deadline refusal survives the native I/O error channel as
`WorkDeadline`; a non-deadline I/O failure keeps the existing `Overflow` result.
This adds no output copy or output-memory admission. Work between callbacks,
including an allocation or one write, is not preempted.

The native `Content::encode` vector-returning API delegates its unchanged
encoding loop to `encode_to`, which also accepts a caller-owned `Write` target.
The HTML flow keeps each page's original vector behind its work-deadline writer.
Its owned operation/payload carrier stays alive through content encoding and
error returns. Checkpoints now run at the native operand/separator/operator
write boundaries within a page, not only before the page starts. Work inside
one native formatting, string-escaping, allocation or forwarded write remains
opaque and is not preempted. Page bytes and codec scratch remain unadmitted.

Preformatted normalization and ordinary Unicode word scratch also own admitted
UTF-8 byte capacity. Normalization keeps the same CRLF/CR-to-newline and literal
four-space tab rules. Word splitting keeps the existing Unicode whitespace and
non-breaking-space rules. Both buffers retain their admission through borrowed
word calls; clearing a word reuses its capacity without returning live backing.
Their UTF-8 character encoding uses only stack scratch.

Windows-1252 word encoding borrows ASCII bytes without allocation. Non-ASCII
words use the native encoder's whole-input upper bound to fill an admitted
byte buffer, not a guessed multiplier. The same buffer owns its full actual
capacity through the original wrapping and run-building loop, including unused
spare capacity and error returns. Unmappable characters and controls still return
`Font` before any run for that word is emitted. The native encoding call is not
preempted. This does not admit native PDF string-escaping scratch or output bytes.

CSS rule declarations and the per-element cascade buffer own admitted UTF-8
capacity. A rule keeps its declaration backing until the rule is dropped; the
cascade buffer keeps its backing through declaration parsing, including errors.
Selectors keep the same ID/class specificity and source-order precedence. Their
counts are stored instead of a second owned selector string. Declaration bytes,
separator order and inline-style order remain unchanged. Native style selection,
attribute/tendril copies, matcher internals and sorting scratch are not covered.

Text merge also builds its temporary UTF-8 result in admitted scratch. The
buffer retains its full capacity while the native DOM setter consumes a borrowed
view, including errors, and frees its bytes before returning their admission.
Merge-field syntax, validation and expansion order are unchanged. The native
DOM's resulting text/tendril allocation is separate and remains unadmitted;
this guard covers only the caller-owned expansion buffer, not stored DOM text.

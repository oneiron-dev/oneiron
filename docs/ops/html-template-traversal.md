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

Native HTML tokenization also polls that same caller deadline between state
steps and before token, parse-error and EOF delivery to the original tree
builder. The checked driver retains the first typed checkpoint error, stops
further delivery, skips successful-EOF assertions on a stopped parse, and drops
its partial parser and DOM before returning that error. Character, comment and
doctype delivery use this path too; it does not reuse script or encoding
indicators as failures. Ordinary native parser APIs keep their original sink
output and default to no checkpoint. HTML parsing keeps the exact tokenizer
options and disabled scripting used by `dom_query::Document::from`.

This is cooperative parser deadline coverage, not native DOM arena admission.
Input conversion, one tokenizer step, character-reference processing and one
native insertion-mode step (including recursive/internal work) remain
non-preemptible. DOM
arena, attribute, atom/tendril, parser-stack and parse-error allocations remain
outside the memory guard. Full FIX 9615 remains open.

The native tree builder also receives a borrowed view of that same checkpoint
when it consumes a token. Its existing reprocess/split-whitespace queue loop
polls before its next insertion-mode step. A refusal returns to the already
latched tokenizer without another step or queued-token use; the checked driver
then drops the partial tree and returns the same original error. The ordinary
`TokenSink::process_token` API remains unchanged and uses an always-true
checkpoint. Existing token-conversion and insertion-mode rule bodies are not
duplicated or changed. Internal recursion, creation, formatting and adoption
work within one insertion-mode step remains non-preemptible and unadmitted.

## Native storage admission

The caller-memory path now reserves the actual DOM node arena and parse-error
vector before growth. Separate parser-owned reservations cover the private
open-element vector and temporary/tag-name/attribute-name String backing.
Strings and parser vectors free before their reservations; their parser-only
reservations release at parsing completion rather than during rendering.
The Document keeps its node and error-vector backing through rendering and drop.
Owned diagnostic strings, interned atoms and other private payloads remain separate.

Comment payloads use the native tendril allocation rather than a length proxy or
separate scratch copy. Before each actual UTF-8 append, the checked tokenizer
reserves a full native replacement while the old backing is still live, then
settles the reported allocation extent before copying. That extent includes
the shared header and rounding. Refusal leaves the old value intact and stops
before the failed append through the same first typed error channel.

The emitted comment moves through the existing native token and sink into DOM
comment storage. Its shared allocation header retains the caller reservation
through those moves, native clones and long subtendrils. The last owner extracts
the reservation, frees the native header/backing, then returns admission.
Owned atomic-wrapper conversion preserves that same allocation. Ordinary APIs
remain unadmitted; their allocating copies/growth can create new unadmitted
backing. The boxed guard's metadata, allocator-private overhead, other tendril
payloads and opaque native work remain outside this slice. This is not complete
HTML heap admission or a hard wall-time bound; FIX 9615 remains PART.

Attribute-value payloads also preflight their actual UTF-8 tendril before each
character or slice append, including decoded character references. They use the
same native allocation header and caller admission as comments. Moving a value
into an attribute or tag retains that header, and duplicate-value clearing
keeps any owned capacity and its admission until reuse or drop. Native tag or
attribute clones may share the admitted allocation; a later allocating copy,
including shared-value atomic conversion, has separate unadmitted backing.
This covers the tokenizer's value allocation, not every downstream attribute
copy, attribute-vector backing or interned name.

Doctype names and public/system identifiers use that native backing reservation
before every UTF-8 character append. Initial inline values need no heap, and
clearing an owned identifier retains its capacity and admission. An accepted
doctype token moves all three payloads through the tree builder and DOM sink;
owned atomic conversion preserves their headers. Ignored doctypes drop their
payloads. A stopped parse drops its partial parser and DOM before returning the
first typed error. Diagnostic formatting, allocating later copies and other
private payloads remain unadmitted; this does not complete FIX 9615 or bound
opaque native work.

Native parser text insertion constructs its final atomic or non-atomic DOM
payload with the caller's native tendril reservation before creating a node.
Coalescing reserves the actual mutable DOM text destination before appending
UTF-8 bytes; zero new node slots does not imply zero payload allocation. Both
paths retain admission in that same native allocation header, including full
old-plus-new growth, reported capacity and last-owner free-before-release.
A refused construction creates no node. A refused append is distinct from
"not a text node" and returns from the native sink before fallback or sibling
insertion. The caller retains the first typed failure and exposes it before
later budget checkpoints to the checked driver's existing error channel; the
driver drops the partial parser and DOM instead of returning success.
Ordinary parser calls keep their original wrapping and coalescing behavior.
This covers parser text insertion, not later DOM setters, ordinary allocating
clones or mutations, incoming token storage, callback
metadata, other private payloads or allocator-private overhead. Those gaps and
opaque native work keep full FIX 9615 PART; no default cap or timer is added.

Pending table-text payloads also reserve their actual native tendrils before
storage or coalescing. A first entry is built in a fresh final destination,
then moved into the existing pending vector; already allocated input is not
retrospectively admitted. A coalesced append reserves the actual stored payload
before copying the additional UTF-8 bytes. Refusal stops that insertion-mode
step through the checked parser's same first typed error channel.
The native allocation header retains its reservation through pending-vector
moves, whitespace inspection, foster-parent or ordinary flush, and early-error
drop. Split status, scalar-stream coalescing, bytes, order and the ordinary
no-reservation paths remain unchanged. Incoming token storage, callback metadata
and other private allocations remain unadmitted. This does not complete
FIX 9615 or make opaque native work preemptible.

The pending table vector also owns its native backing admission. Its private
carrier reserves a full replacement while the old vector and its reservation
are live, settles actual tuple-vector capacity, moves entries and publishes
the replacement before freeing old storage and returning the old admission.
Taking the pending work moves that whole carrier into the original flush.
Its owning iterator frees the remaining entries and vector allocation before
returning admission, including early refusals. Coalescing an existing payload
does not allocate another vector slot. Native capacity or allocation failures
use the same first typed error channel; ordinary no-reservation paths retain
their original vector growth and flush behavior. Boxed guard metadata and
allocator-private overhead remain outside the reported capacity.

Native parser element construction also preflights its final attribute-vector
storage. The checked tree-sink operation carries the actual attribute count;
a native prepared vector owns full capacity admission and moves into the same
immediate element creation. The lower constructor passes the same attributes
without filtering or growth. Each attribute is converted directly into the
prepared final destination; incoming token-vector storage is not retroactively
admitted. Ordinary calls without preparation retain their original constructor
and wrapping paths.

Both parser HTML/body attribute-merge sites preflight the actual mutable final
element before calling the sink. Incoming names are compared with the original
destination names, so incoming duplicates absent from that original set remain
accepted as before. Growth admits a full replacement while the old allocation
and guard are live, settles actual capacity, publishes both replacement fields,
frees old storage and then returns old admission. Failure stops the native
operation through the same first typed error without an attribute push or a
dummy node handle. Existing node-arena preflight remains first; retained arena
capacity after a later refusal is freed with the partial DOM, not rolled back.

The final vector's reservation is stored on its element after the attribute
field, and pending prepared storage frees before its guard. Tree cloning does
not duplicate an in-flight prepared destination. Existing allocating clones
may retain the original reservation through an Arc; that does not admit their
new allocations. This slice covers the original parser/render element-owned
vectors, not arbitrary public attribute extraction or later mutations. Atomic
value copies, merge wrapping/name temporaries, external allocating clones,
guard metadata and allocator-private overhead remain separate gaps. Full
FIX 9615 stays PART; no cap, timer or default is added.

A separate pre-input tag-attribute reservation now admits the tokenizer's actual
attribute vector before each new entry. Its native carrier keeps the vector
before its owned guard; token, formatting-entry and owning-iterator moves retain
both until the allocation frees. Growth admits full old-plus-new storage,
settles reported capacity, publishes both replacement fields, frees the old
allocation and then returns its old admission. Every internal checked tag or
attribute-vector clone reserves its own independent destination before copying.
Order-insensitive formatting comparison uses two independently admitted copies
and allocation-free unstable sorting; equal attribute multiplicities are kept.
The ordinary unhooked parser and public allocating Clone APIs stay unadmitted.

The same checked builder installs native element and attribute-merge consumers
alongside that reservation. They receive the whole input carrier by move, not a
separate guard stash or a plain-vector copy-out. Prepared element construction
and guarded merges consume its owning iterator, which frees all remaining input
entries and vector storage before releasing the input guard, including early
drop. Final DOM-vector admission remains independent and overlaps input storage.
The unprepared public constructor retains an original-input hold because atomic
wrapping may reuse that allocation; that hold does not admit a distinct wrapping
destination or later replacement. Existing original-name duplicate filtering,
node-arena preflight order, flags and first typed error channel are unchanged.
Tag field storage is now the native TagAttributes carrier; mutable borrows expose
only the attribute slice, and plain Vec extraction returns the carrier instead
when it still has an owned guard. No markup5ever trait, package version, manifest,
content cap, default, deadline or configuration setting changes. Atomic payload
copies outside checked element construction and native attribute merge, ordinary unhooked merge-name
scratch, public extraction/mutations/clones, other parser
vectors, boxed callback/guard metadata, allocator-private work and opaque native
intervals remain unadmitted; this does not complete FIX 9615.

The native checked attribute-merge callback now compares incoming names only
with the original destination prefix, recorded before its first push. Incoming
entries never become part of that prefix, so duplicate incoming names absent
from the original destination remain accepted. The callback no longer copies
original names into a temporary vector, including when the incoming carrier is
empty. Its owning iterator still frees input storage before releasing admission.
The ordinary unhooked TreeSink Vec entry keeps its original wrapping and copied
names; that separate public path remains unadmitted.

The native checked element-creation callback also admits attribute-value backing
when conversion to an atomic DOM value must copy a shared input tendril. It uses
the owned value, not a borrowed clone: inline and uniquely owned values transfer
without allocation, while a shared value reserves header-rounded storage before
copying and settles to its actual capacity. The new header retains that guard
until its last owner frees the allocation, before returning admission. Old input
and new destination storage are both charged while they overlap.

Conversion fills the already prepared final attribute vector after the existing
arena/vector preflight and before any element or template-fragment node is
pushed. The one checked create callback returns a typed result. A refusal drops
partial values and the remaining owning input, records the same first parser
error, and stops without publishing a dummy handle or a partial element. The
ordinary unhooked TreeSink Vec entry retains its original behavior. Atomic value
copies through ordinary unhooked paths, public extraction/mutations/clones, interned
names, other parser storage, boxed guard/callback metadata, allocator-private
work and opaque native intervals remain unadmitted; FIX 9615 is still partial.

The same checked hook now returns a typed result for native attribute merge.
It retains the original destination-name prefix and skips matching input names
before value conversion. Such ignored values cannot cause a new copy reservation
or refusal. Accepted names absent from the original destination keep their input
order, including incoming duplicates, and their owned values use the same
shared-only atomic conversion as element creation. Inline and uniquely owned
values transfer without copying. Missing targets and non-element targets remain
successful no-ops.

The existing destination-vector preflight remains in place; the native merge
entry also ensures that same storage before appending. Both HTML and BODY rule
sites stop immediately when the one typed merge callback refuses. Any earlier
accepted values remain only in the private partial DOM, which is dropped with
input storage before the first typed error is returned, never as prefix success.
The ordinary unhooked Vec merge keeps its original copied-name scratch and value
wrapping. Public extraction/mutations/clones, interned names, other parser
storage, boxed guard/callback metadata, allocator-private work and opaque native
intervals remain unadmitted; FIX 9615 remains partial.

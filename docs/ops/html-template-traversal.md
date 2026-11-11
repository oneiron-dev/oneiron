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

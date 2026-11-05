# LinkedIn inbox parsing

Scheduled inbox polls use the existing per-seat cursor and per-thread message window.
The conversation parsers emit messages in the same deduplicated page order. The poll
skips its handled prefix, retains the current window, and reads one more message to
learn whether the thread must stay queued. The claim, seen marker, backfill filter and
durable surface-event handoff are unchanged. These counts are not delivery evidence.

Plain-text conversations keep the same heading/time grammar and message hashes, but
normalize a small line lookahead instead of retaining every normalized line. Existing
structured MCP values are borrowed; JSON embedded in MCP text is still parsed into an
owned value. The full conversation normalizer still reads every message.

Only reached pages are validated. A malformed later page can fail when the cursor
reaches it, after earlier valid pages were admitted. A page failure does not advance
the cursor. The provider's complete JSON value, skipped-prefix deduplication set and
individual message allocations still exist; this is not a whole-response memory bound.
No poll limit, format, credential or authority setting changed.

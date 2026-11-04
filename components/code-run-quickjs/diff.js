// `diff(a, b, {by})`: an SDK helper over `can`, `slice` and `store`, not an
// engine verb. It states its algorithm in its reply. By lines (the default)
// both results are read in windows of 4096 lines, Myers' O(ND) diff runs
// inside each window pair with DIFF_CONTEXT_LINES lines of context around
// each change, and a hunk a window edge cuts is closed there and marked
// `edge`; a window pair too changed for one Myers pass is split and diffed
// in halves, so only a small segment is ever one `coarse` hunk. By bytes,
// fixed 64 KiB blocks are compared and a changed block's hunk names its
// first differing byte runs. It holds two windows and its hunk text at
// once; hunks past 1 MiB are stored as a result made from both, so the
// taint of either is the stored one's. A diff past one step's calls
// answers `next` — each side's own offset, mid-window when a read stopped
// there — which `{from}` goes on from; a `{window}` cursor from before
// per-side offsets still reads as that many whole windows on both sides.
// The helper's calls: every default and bound a caller would notice is one
// named value here, so a ruling changes one line. They are top-level in the
// bundle's closure, never globals. A diff spends at most
// HOST_CALLS_PER_STEP (reader_forks.js, bundled first) calls a step, and
// calls built-ins only through that file's primordials.

// Lockstep window sizes: lines by line, bytes by block.
const DIFF_WINDOW_LINES = 4096;
const DIFF_WINDOW_BYTES = 65536;
// Hunk text past this many bytes is stored as a result of the run, made
// from both sides, in place of the reply's hunks.
const DIFF_STORE_PAST_BYTES = 1 << 20;
// Edits one Myers pass may take; a window pair past it is split in halves
// and each half diffed again, down to DIFF_COARSE_MAX_LINES-line segments.
const DIFF_MAX_EDITS = 512;
// Unchanged lines a hunk carries either side of its changes; changes at
// most twice this many unchanged lines apart share one hunk.
const DIFF_CONTEXT_LINES = 3;
// A segment this small that still defeats Myers is one coarse hunk; the
// split depth caps the halvings either way.
const DIFF_COARSE_MAX_LINES = 128;
const DIFF_SPLIT_DEPTH = 6;
// Differing byte runs one bytes hunk names, and bytes of each run it
// spells in hex; past either, the hunk is marked `truncated`.
const DIFF_BYTES_RUNS_MAX = 8;
const DIFF_BYTES_RUN_HEX_BYTES = 32;
// The mode a diff takes when the caller names none.
const DIFF_DEFAULT_BY = "lines";
// The algorithm each mode states in its reply.
const DIFF_ALGORITHM_LINES = "myers-windowed/v2";
const DIFF_ALGORITHM_BYTES = "blocks/v2";

function makeDiff(api) {
  "use strict";
  const {slice, can, store} = api;

  const refOf = r => {
    const ref = typeof r === "string" ? r : (r?.ref ?? r?.handle ?? r?.name);
    if (typeof ref !== "string") throw new TypeError("result ref must be a name, handle or card");
    return ref;
  };
  // Lines with their newlines kept, so a hunk's text is byte-true.
  const lines = text => {
    const out = [];
    let at = 0;
    while (at < text.length) {
      const nl = indexOf(text, "\n", at);
      const end = nl < 0 ? text.length : nl + 1;
      push(out, strSlice(text, at, end));
      at = end;
    }
    return out;
  };
  // Myers' greedy forward pass, each round's frontier kept, then the edit
  // script walked back from the end: "=", "-" or "+" per step. `null` past
  // DIFF_MAX_EDITS.
  const myers = (x, y) => {
    const n = x.length, m = y.length, offset = DIFF_MAX_EDITS + 1, size = 2 * offset + 2;
    const v = new Int32(size);
    const trace = [];
    for (let d = 0; d <= min(n + m, DIFF_MAX_EDITS); ++d) {
      const frontier = new Int32(size);
      for (let i = 0; i < size; ++i) frontier[i] = v[i];
      push(trace, frontier);
      for (let k = -d; k <= d; k += 2) {
        let i = k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])
          ? v[offset + k + 1] : v[offset + k - 1] + 1;
        let j = i - k;
        while (i < n && j < m && x[i] === y[j]) { ++i; ++j; }
        v[offset + k] = i;
        if (i >= n && j >= m) return backtrack(trace, n, m, offset);
      }
    }
    return null;
  };
  const backtrack = (trace, n, m, offset) => {
    const ops = [];
    let i = n, j = m;
    for (let d = trace.length - 1; d >= 0; --d) {
      const v = trace[d];
      const k = i - j;
      const prevK = k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1]) ? k + 1 : k - 1;
      const pi = v[offset + prevK], pj = pi - prevK;
      while (i > pi && j > pj) { --i; --j; push(ops, "="); }
      if (d > 0) push(ops, i === pi ? "+" : "-");
      i = pi; j = pj;
    }
    reverse(ops);
    return ops;
  };
  const lineText = (sign, line) =>
    sign + line + (endsWith(line, "\n") ? "" : "\n\\ No newline at end of file\n");
  const sideText = (sign, side) => {
    let text = "";
    for (let i = 0; i < side.length; ++i) text += lineText(sign, side[i]);
    return text;
  };
  const hunk = (aStart, aLen, bStart, bLen, text, edge, coarse) => {
    const h = {
      a: [aStart, aStart + aLen],
      b: [bStart, bStart + bLen],
      text: "@@ -" + (aStart + 1) + "," + aLen + " +" + (bStart + 1) + "," + bLen + " @@\n" + text,
    };
    if (edge) h.edge = true;
    if (coarse) h.coarse = true;
    return h;
  };
  // The hunks of one window pair (or of a split half of one), in both
  // sides' line offsets: shared head and tail lines trim away, Myers runs
  // on what is left, and its changes group into hunks carrying
  // DIFF_CONTEXT_LINES unchanged lines either side. A core past
  // DIFF_MAX_EDITS splits both sides at their midpoints and diffs the
  // halves (their hunks are `edge`, cut at the split), so a coarse hunk
  // spans at most DIFF_COARSE_MAX_LINES lines of a side.
  const diffRange = (x, y, aBase, bBase, edge, depth) => {
    let head = 0;
    while (head < x.length && head < y.length && x[head] === y[head]) ++head;
    let tail = 0;
    while (tail < x.length - head && tail < y.length - head
      && x[x.length - 1 - tail] === y[y.length - 1 - tail]) ++tail;
    const xs = copyOf(x, head, x.length - tail), ys = copyOf(y, head, y.length - tail);
    if (!xs.length && !ys.length) return [];
    const ops = myers(xs, ys);
    if (!ops) {
      if (xs.length + ys.length <= DIFF_COARSE_MAX_LINES || depth >= DIFF_SPLIT_DEPTH)
        return [hunk(aBase + head, xs.length, bBase + head, ys.length,
          sideText("-", xs) + sideText("+", ys), edge, true)];
      const mx = x.length >> 1, my = y.length >> 1;
      const out = diffRange(copyOf(x, 0, mx), copyOf(y, 0, my), aBase, bBase, true, depth + 1);
      const rest = diffRange(copyOf(x, mx), copyOf(y, my), aBase + mx, bBase + my, true, depth + 1);
      for (let i = 0; i < rest.length; ++i) push(out, rest[i]);
      return out;
    }
    // Change spans in core coordinates, each with the ops that spell it.
    const spans = [];
    let ai = 0, bi = 0, open = null;
    for (let i = 0; i < ops.length; ++i) {
      const op = ops[i];
      if (op === "=") {
        if (open) { open.op1 = i; open = null; }
        ++ai; ++bi;
        continue;
      }
      if (!open) { open = {a0: ai, b0: bi, a1: ai, b1: bi, op0: i, op1: ops.length}; push(spans, open); }
      if (op === "-") open.a1 = ++ai;
      else open.b1 = ++bi;
    }
    const out = [];
    for (let s = 0; s < spans.length; ++s) {
      const span = spans[s];
      // Changes at most 2 * DIFF_CONTEXT_LINES unchanged lines apart share
      // one hunk, their between-lines as context.
      while (s + 1 < spans.length && spans[s + 1].a0 - span.a1 <= 2 * DIFF_CONTEXT_LINES) {
        ++s;
        span.a1 = spans[s].a1; span.b1 = spans[s].b1; span.op1 = spans[s].op1;
      }
      const pre = min(DIFF_CONTEXT_LINES, head + span.a0);
      const post = min(DIFF_CONTEXT_LINES, x.length - (head + span.a1));
      let text = "";
      for (let i = head + span.a0 - pre; i < head + span.a0; ++i) text += lineText(" ", x[i]);
      let ci = span.a0, cj = span.b0;
      for (let i = span.op0; i < span.op1; ++i) {
        const op = ops[i];
        if (op === "=") { text += lineText(" ", xs[ci]); ++ci; ++cj; }
        else if (op === "-") text += lineText("-", xs[ci++]);
        else text += lineText("+", ys[cj++]);
      }
      for (let i = head + span.a1; i < head + span.a1 + post; ++i) text += lineText(" ", x[i]);
      push(out, hunk(
        aBase + head + span.a0 - pre, pre + (span.a1 - span.a0) + post,
        bBase + head + span.b0 - pre, pre + (span.b1 - span.b0) + post,
        text, edge, false));
    }
    return out;
  };
  const hunks = (x, y, aBase, bBase, edge) => diffRange(x, y, aBase, bBase, edge, 0);

  // One base64 character's value, by char code; -1 for padding or any
  // other character.
  const b64Value = code => {
    if (code >= 65 && code <= 90) return code - 65;
    if (code >= 97 && code <= 122) return code - 71;
    if (code >= 48 && code <= 57) return code + 4;
    if (code === 43) return 62;
    if (code === 47) return 63;
    return -1;
  };
  // A slice piece's base64 (each piece is encoded whole) onto `out`, as
  // byte numbers.
  const pushBase64 = (out, b64) => {
    let acc = 0, bits = 0;
    for (let i = 0; i < b64.length; ++i) {
      const v = b64Value(charCodeAt(b64, i));
      if (v < 0) continue;
      acc = (acc << 6) | v;
      bits += 6;
      if (bits >= 8) { bits -= 8; push(out, (acc >> bits) & 255); }
    }
  };
  // A slice piece's text onto `out`, as its UTF-8 bytes.
  const pushUtf8 = (out, text) => {
    for (let i = 0; i < text.length; ++i) {
      let cp = charCodeAt(text, i);
      if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < text.length) {
        const low = charCodeAt(text, i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00); ++i; }
      }
      if (cp < 0x80) push(out, cp);
      else if (cp < 0x800) { push(out, 0xc0 | (cp >> 6)); push(out, 0x80 | (cp & 63)); }
      else if (cp < 0x10000) {
        push(out, 0xe0 | (cp >> 12)); push(out, 0x80 | ((cp >> 6) & 63)); push(out, 0x80 | (cp & 63));
      } else {
        push(out, 0xf0 | (cp >> 18)); push(out, 0x80 | ((cp >> 12) & 63));
        push(out, 0x80 | ((cp >> 6) & 63)); push(out, 0x80 | (cp & 63));
      }
    }
  };
  const hexOf = (bytes, from, to) => {
    let hex = "";
    const end = min(to, from + DIFF_BYTES_RUN_HEX_BYTES);
    for (let i = from; i < end; ++i) {
      const h = toRadix(bytes[i], 16);
      hex += (h.length < 2 ? "0" : "") + h;
    }
    return {hex, cut: to > end};
  };
  // The differing runs of two byte windows over the same span, compared
  // positionally from each window's own start: a
  // run past a side's end is empty on that side. At most
  // DIFF_BYTES_RUNS_MAX runs are listed; `truncated` says more followed.
  const byteRuns = (xb, yb) => {
    const list = [];
    let truncated = false, start = -1;
    const n = max(xb.length, yb.length);
    for (let i = 0; i <= n; ++i) {
      const differ = i < n && (i >= xb.length || i >= yb.length || xb[i] !== yb[i]);
      if (differ && start < 0) start = i;
      if (!differ && start >= 0) {
        if (list.length < DIFF_BYTES_RUNS_MAX)
          push(list, {a: [start, min(i, xb.length)], b: [start, min(i, yb.length)]});
        else truncated = true;
        start = -1;
      }
    }
    return {list, truncated};
  };

  return async function diff(a, b, options = {}) {
    const by = options.by ?? DIFF_DEFAULT_BY;
    if (by !== "lines" && by !== "bytes") throw new TypeError('diff takes {by: "lines" | "bytes"}');
    const left = refOf(a), right = refOf(b);
    let calls = 0;
    const host = async (f, ...args) => { ++calls; return await apply(f, undefined, args); };
    const refs = [left, right];
    for (let i = 0; i < refs.length; ++i) {
      const ref = refs[i];
      const verdict = await host(can, {read: ref});
      if (!verdict?.can) return freeze({refused: verdict?.reason ?? "denied", ref, detail: verdict});
    }
    const window = by === "lines" ? DIFF_WINDOW_LINES : DIFF_WINDOW_BYTES;
    const off = value => isInteger(value) && value >= 0 ? value : 0;
    const from = options.from ?? {};
    // `a`/`b` are each side's own next offset (lines or bytes); a cursor
    // from before them names whole windows on both sides.
    let aAt = isInteger(from.a) ? off(from.a) : off(from.window) * window;
    let bAt = isInteger(from.b) ? off(from.b) : off(from.window) * window;
    let w = off(from.window);
    // One window of one side, read across replies. Once this step's calls
    // are spent the read stops inside the window — bytes anywhere, lines
    // at a whole line (a trailing partial line is read again next step) —
    // and the caller diffs the span both reads reached and resumes from
    // there. A lines read
    // that holds no whole line yet reads on past the step's calls rather
    // than resume to the same line step after step. `units` is what the
    // window consumed (lines or bytes); `eof` is a fully read window that
    // came back short. Bytes windows also collect their raw bytes, piece
    // by piece, for the differing runs.
    const read = async (ref, start) => {
      let text = "", reached = start, stopped = false;
      // A bytes read of a text body starts at a character boundary, up to
      // three bytes before the offset asked for; the first piece names
      // where it truly started, and those backed-up bytes are dropped
      // below so the window stands at the offset asked for.
      let at = start, first = true;
      const raw = by === "bytes" ? [] : null;
      let sel = by === "lines" ? {lines: [start, start + window]} : {bytes: [start, start + window]};
      for (;;) {
        const piece = await host(slice, ref, sel);
        if (piece.withheld) throw new TypeError("diff_withheld: " + ref);
        if (first) { first = false; if (by === "bytes" && typeof piece.start === "number") at = piece.start; }
        text += piece.text ?? "";
        if (raw) {
          if (piece.base64) pushBase64(raw, piece.base64);
          else if (piece.text) pushUtf8(raw, piece.text);
        }
        if (typeof piece.end === "number") reached = piece.end;
        if (piece.done || !piece.next) break;
        sel = piece.next;
        if (calls >= HOST_CALLS_PER_STEP && (by === "bytes" || indexOf(text, "\n") >= 0)) {
          stopped = true;
          break;
        }
      }
      if (by === "bytes") {
        const units = max(0, reached - start);
        const trimmed = at < start ? copyOf(raw, start - at) : raw;
        return {raw: trimmed, at: start, units, eof: !stopped && units < window};
      }
      const readLines = lines(text);
      // A stopped read's last line may be only part of one: it is read
      // again from its start next step.
      if (stopped && readLines.length && !endsWith(text, "\n")) readLines.length -= 1;
      return {lines: readLines, at: start, units: readLines.length, eof: !stopped && readLines.length < window};
    };
    const found = [];
    let bytes = 0, done = false;
    while (!done && calls < HOST_CALLS_PER_STEP) {
      const aWas = aAt, bWas = bAt;
      const x = await read(left, aAt), y = await read(right, bAt);
      done = x.eof && y.eof;
      // A window pair compares positionally, so both sides must cover the
      // same span. The two reads share one budget and run in turn, so the
      // later read stops sooner: when the shorter read stopped inside its
      // window (not at its body's end), both windows trim to that shorter
      // span and both sides resume from there — the longer read's tail is
      // read again next step, still aligned. A side that reached its end
      // never trims the other: positions past that end are real.
      let xUnits = x.units, yUnits = y.units;
      const common = xUnits < yUnits && !x.eof ? xUnits : yUnits < xUnits && !y.eof ? yUnits : -1;
      if (common >= 0) {
        if (by === "lines") { x.lines.length = common; y.lines.length = common; }
        else { x.raw.length = common; y.raw.length = common; }
        xUnits = common;
        yUnits = common;
      }
      if (by === "lines") {
        const made = hunks(x.lines, y.lines, x.at, y.at, !done);
        for (let i = 0; i < made.length; ++i) { push(found, made[i]); bytes += made[i].text.length; }
      } else {
        const runs = byteRuns(x.raw, y.raw);
        if (runs.list.length || runs.truncated) {
          let text = "@@ bytes -" + x.at + "," + xUnits + " +" + y.at + "," + yUnits + " @@\n";
          const named = [];
          let truncated = runs.truncated;
          for (let i = 0; i < runs.list.length; ++i) {
            const run = runs.list[i];
            const aHex = hexOf(x.raw, run.a[0], run.a[1]), bHex = hexOf(y.raw, run.b[0], run.b[1]);
            if (aHex.cut || bHex.cut) truncated = true;
            push(named, {a: [x.at + run.a[0], x.at + run.a[1]], b: [y.at + run.b[0], y.at + run.b[1]], aHex: aHex.hex, bHex: bHex.hex});
            text += "-" + (x.at + run.a[0]) + ": " + aHex.hex + (aHex.cut ? "..." : "") + "\n"
              + "+" + (y.at + run.b[0]) + ": " + bHex.hex + (bHex.cut ? "..." : "") + "\n";
          }
          const h = {a: [x.at, x.at + xUnits], b: [y.at, y.at + yUnits], text, runs: named};
          if (truncated) h.truncated = true;
          push(found, h);
          bytes += h.text.length;
        }
      }
      aAt = x.at + xUnits;
      bAt = y.at + yUnits;
      ++w;
      // No side moved and neither ended (a read answered empty with more
      // promised): answer `next` at these offsets instead of spinning.
      if (!done && aAt <= aWas && bAt <= bWas) break;
    }
    const reply = {algorithm: by === "lines" ? DIFF_ALGORITHM_LINES : DIFF_ALGORITHM_BYTES, window, by, count: found.length, done};
    if (!done) reply.next = {window: w, a: aAt, b: bAt};
    if (bytes > DIFF_STORE_PAST_BYTES) {
      let text = "";
      for (let i = 0; i < found.length; ++i) text += found[i].text;
      reply.stored = await host(store, text, options.name, {sources: [left, right]});
    } else {
      reply.hunks = found;
    }
    return freeze(reply);
  };
}

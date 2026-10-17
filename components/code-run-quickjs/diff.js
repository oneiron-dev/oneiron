// `diff(a, b, {by})`: an SDK helper over `can`, `slice` and `store`, not an
// engine verb. It states its algorithm in its reply. By lines (the default)
// both results are read in lockstep windows of 4096 lines, Myers' O(ND) diff
// runs inside each window pair, and a hunk a window edge cuts is closed
// there and marked `edge`; by bytes, fixed 64 KiB blocks are compared. It
// holds two windows and its hunk text at once; hunks past 1 MiB are stored
// as a result made from both, so the taint of either is the stored one's.
// A diff past one step's calls answers `next`, which `{from}` goes on from.
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
// Edits one window pair may take before it is one coarse hunk.
const DIFF_MAX_EDITS = 512;
// The mode a diff takes when the caller names none.
const DIFF_DEFAULT_BY = "lines";
// The algorithm each mode states in its reply.
const DIFF_ALGORITHM_LINES = "myers-windowed/v1";
const DIFF_ALGORITHM_BYTES = "blocks/v1";

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
  const sideText = (sign, side) => {
    let text = "";
    for (let i = 0; i < side.length; ++i)
      text += sign + side[i] + (endsWith(side[i], "\n") ? "" : "\n\\ No newline at end of file\n");
    return text;
  };
  const hunk = (aStart, del, bStart, add, edge, coarse) => {
    const h = {
      a: [aStart, aStart + del.length],
      b: [bStart, bStart + add.length],
      text: "@@ -" + (aStart + 1) + "," + del.length + " +" + (bStart + 1) + "," + add.length + " @@\n"
        + sideText("-", del) + sideText("+", add),
    };
    if (edge) h.edge = true;
    if (coarse) h.coarse = true;
    return h;
  };
  // The hunks of one window pair, with no context lines, in both sides'
  // line offsets.
  const hunks = (x, y, aBase, bBase, edge) => {
    let head = 0;
    while (head < x.length && head < y.length && x[head] === y[head]) ++head;
    let tail = 0;
    while (tail < x.length - head && tail < y.length - head
      && x[x.length - 1 - tail] === y[y.length - 1 - tail]) ++tail;
    const xs = copyOf(x, head, x.length - tail), ys = copyOf(y, head, y.length - tail);
    if (!xs.length && !ys.length) return [];
    const ops = myers(xs, ys);
    if (!ops) return [hunk(aBase + head, xs, bBase + head, ys, edge, true)];
    const out = [];
    let ai = 0, bi = 0, aAt = 0, bAt = 0, del = [], add = [];
    const flush = () => {
      if (del.length || add.length) push(out, hunk(aBase + head + aAt, del, bBase + head + bAt, add, edge, false));
      del = []; add = [];
    };
    for (let i = 0; i < ops.length; ++i) {
      const op = ops[i];
      if (op === "=") { flush(); ++ai; ++bi; continue; }
      if (!del.length && !add.length) { aAt = ai; bAt = bi; }
      if (op === "-") push(del, xs[ai++]);
      else push(add, ys[bi++]);
    }
    flush();
    return out;
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
    // One window of one side, read whole across replies.
    const read = async (ref, start) => {
      let text = "", base64 = "", reached = start;
      let sel = by === "lines" ? {lines: [start, start + window]} : {bytes: [start, start + window]};
      for (;;) {
        const piece = await host(slice, ref, sel);
        if (piece.withheld) throw new TypeError("diff_withheld: " + ref);
        text += piece.text ?? "";
        base64 += piece.base64 ?? "";
        if (typeof piece.end === "number") reached = piece.end;
        if (piece.done || !piece.next) break;
        sel = piece.next;
      }
      return {text, base64, reached};
    };
    const found = [];
    let bytes = 0, w = options.from?.window ?? 0, done = false;
    while (!done && calls < HOST_CALLS_PER_STEP) {
      const start = w * window;
      const x = await read(left, start), y = await read(right, start);
      if (by === "lines") {
        const xl = lines(x.text), yl = lines(y.text);
        done = xl.length < window && yl.length < window;
        const made = hunks(xl, yl, start, start, !done);
        for (let i = 0; i < made.length; ++i) { push(found, made[i]); bytes += made[i].text.length; }
      } else {
        done = x.reached - start < window && y.reached - start < window;
        if (x.text !== y.text || x.base64 !== y.base64) {
          const h = {
            a: [start, max(start, x.reached)],
            b: [start, max(start, y.reached)],
            text: "@@ bytes -" + start + "," + max(0, x.reached - start) + " +" + start + "," + max(0, y.reached - start) + " @@\n",
          };
          push(found, h);
          bytes += h.text.length;
        }
      }
      ++w;
    }
    const reply = {algorithm: by === "lines" ? DIFF_ALGORITHM_LINES : DIFF_ALGORITHM_BYTES, window, by, count: found.length, done};
    if (!done) reply.next = {window: w};
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

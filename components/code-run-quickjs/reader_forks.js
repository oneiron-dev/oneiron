// `readAll(r, {ask, ...})` (ARCH-0079 #reader-forks): reader forks as an SDK
// helper over `can`, `chunks`, `self.spawn`, `tasks.wait`, `slice`,
// `summarize` and `store`. It is not an engine verb: every step it takes is
// one of those calls, checked and recorded as the program's own.
//
// It runs in resumable phases. Its progress is one stored JSON result,
// `rf_<key>_state`, so a phase cut by a step's call budget, or by a park on
// `tasks.wait`, goes on from there when it is called again with the same
// key: spawns dedupe by intent key and summaries by memo, so a phase run
// again repeats no work. The host computes the fold receipt; this only names
// its inputs.
// The helper's calls: every default, bound and policy a caller would notice
// is one named value or function here, so a ruling changes one line. They
// are top-level in the bundle's closure, never globals, and use no method a
// program could patch.

// Host calls one phase of a helper spends in a step: the sandbox allows 256,
// and the rest is left for the program around it. diff.js, bundled after
// this file, spends by the same bound.
const HOST_CALLS_PER_STEP = 200;
// The child window `readAll` sizes by when the seat names none, in tokens.
const READ_ALL_FALLBACK_WINDOW_TOKENS = 16384;
// A caller's key; the read's result is `rf_<key>` and its progress
// `rf_<key>_state`.
const READ_ALL_KEY_PATTERN = /^[A-Za-z0-9_]{1,40}$/;
const READ_ALL_RESULT_PREFIX = "rf_";
const READ_ALL_STATE_SUFFIX = "_state";
// Why a summary too big for its window settles; its group is split.
const READ_ALL_SPLIT_REASON = "group_exceeds_window";
// The fold a receipt's recipe names, and the effort it names when the
// caller names none (the host's own default).
const READ_ALL_FOLD_RECIPE = "dedupe-cites/v1";
const READ_ALL_DEFAULT_EFFORT = "medium";
// What `readAll` stores when no finding was made.
const READ_ALL_EMPTY_RESULT = '{"answer":null,"findings":0,"note":"no finding was made"}';
// The fold ends once a stage leaves this many summaries.
const READ_ALL_FOLD_TO = 1;
// Why a read ends refused when a chunk page is withheld.
const READ_ALL_WITHHELD_REASON = "tainted";

// What `readAll` chunks by when the caller names no `by`: `tokens` a chunk,
// at most the memory one child may hold.
function readAllChunkBy(tokens, child) {
  return {tokens, ...(child.memory_bytes ? {max_bytes: child.memory_bytes} : {})};
}

// When the wait on the children ends when the caller names no `until`: the
// children's cutoff.
function readAllWaitUntil(child) {
  return child.cutoff_unix_ms;
}

// How many children the wait ends on: the caller's `n_of`, at most the
// children; none (all of them) without one.
function readAllWaitCount(nOf, children) {
  return Number.isInteger(nOf) ? Math.min(nOf, children) : undefined;
}

// The chunk size, in tokens: half the child window, which `window` may only
// lower.
function readAllChunkTokens(windowTokens, window) {
  const half = Math.floor(windowTokens / 2);
  return Number.isInteger(window) && window > 0 && window < half ? window : half;
}

// One summary group's byte cap: the window's tokens as bytes, about half the
// window at two bytes a token.
function readAllGroupBytes(windowTokens) {
  return windowTokens;
}

// The default key: FNV-1a over the source's ref and the ask.
function readAllDefaultKey(ref, ask) {
  const text = ref + "\n" + ask;
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; ++i) {
    h ^= text.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return "k" + h.toString(16);
}

// One chunk's spawn key, and the step key of one of the read's waits.
function readAllIntentKey(key, chunk) {
  return key + ":" + chunk.start + "-" + chunk.end;
}
function readAllStepKey(key, stage) {
  return key + ":" + stage;
}

// Cites as sorted, merged byte ranges; anything else in them is dropped.
function readAllNormaliseCites(cites) {
  const spans = [];
  if (!Array.isArray(cites)) return spans;
  for (let i = 0; i < cites.length; ++i) {
    const c = cites[i];
    if (!Array.isArray(c) || !Number.isInteger(c[0]) || !Number.isInteger(c[1]) || c[0] >= c[1]) continue;
    let at = spans.length;
    while (at > 0 && (spans[at - 1][0] > c[0] || spans[at - 1][0] === c[0] && spans[at - 1][1] > c[1])) {
      spans[at] = spans[at - 1];
      --at;
    }
    spans[at] = [c[0], c[1]];
  }
  const merged = [];
  for (let i = 0; i < spans.length; ++i) {
    const last = merged[merged.length - 1];
    if (last && spans[i][0] <= last[1]) last[1] = Math.max(last[1], spans[i][1]);
    else merged[merged.length] = spans[i];
  }
  return merged;
}

// The fold's code-first pass: findings that cite the same ranges are one,
// the first in chunk order kept; findings with no cites all stay.
function readAllDedupe(findings) {
  const seen = Object.create(null), kept = [];
  for (let i = 0; i < findings.length; ++i) {
    const f = findings[i];
    if (f.cites && f.cites.length) {
      const id = JSON.stringify(f.cites);
      if (seen[id]) continue;
      seen[id] = true;
    }
    kept[kept.length] = {ref: f.ref, bytes: f.bytes};
  }
  return kept;
}

// Refs packed in order into summary groups of at most `cap` bytes; a member
// past the cap is a group of its own.
function readAllPack(items, cap) {
  const groups = [];
  let group = [], bytes = 0;
  for (let i = 0; i < items.length; ++i) {
    if (group.length && bytes + items[i].bytes > cap) {
      groups[groups.length] = {refs: group};
      group = [];
      bytes = 0;
    }
    group[group.length] = items[i].ref;
    bytes += items[i].bytes;
  }
  if (group.length) groups[groups.length] = {refs: group};
  return groups;
}

// A group whose summary was too big for its window, split: its halves.
function readAllSplit(refs) {
  const half = Math.floor(refs.length / 2), a = [], b = [];
  for (let i = 0; i < refs.length; ++i) {
    const part = i < half ? a : b;
    part[part.length] = refs[i];
  }
  return [{refs: a}, {refs: b}];
}

function makeReaderForks(api) {
  "use strict";
  const {slice, chunks, store, spawn, wait, can, summarize, describe} = api;
  // Primordials, taken before any program runs.
  const call = Function.prototype.call;
  const parse = JSON.parse;
  const min = Math.min;
  const isArray = Array.isArray, isInteger = Number.isInteger;
  const push = call.bind(Array.prototype.push);
  const sort = call.bind(Array.prototype.sort);
  const startsWith = call.bind(String.prototype.startsWith);
  const test = call.bind(RegExp.prototype.test);
  const freeze = Object.freeze;

  const refOf = r => {
    const ref = typeof r === "string" ? r : (r?.ref ?? r?.handle ?? r?.name);
    if (typeof ref !== "string") throw new TypeError("result ref must be a name, handle or card");
    return ref;
  };
  // What a refused call threw: the host's code when it named one.
  const reasonOf = error => {
    const text = typeof error === "string" ? error : error?.message;
    if (typeof text === "string") {
      try {
        const value = parse(text);
        if (value && typeof value === "object") return value.denied ?? (value.failed ? "failed" : text);
      } catch (_) { /* plain text */ }
      return text;
    }
    return "refused";
  };

  return async function readAll(r, options = {}) {
    const source = refOf(r);
    const ask = options.ask;
    if (typeof ask !== "string" || !ask) throw new TypeError("readAll takes {ask}");
    const key = options.key ?? readAllDefaultKey(source, ask);
    if (typeof key !== "string" || !test(READ_ALL_KEY_PATTERN, key)) throw new TypeError("readAll key must be 1-40 of [A-Za-z0-9_]");
    const resultName = READ_ALL_RESULT_PREFIX + key;
    const stateName = resultName + READ_ALL_STATE_SUFFIX;
    let calls = 0;
    const host = async (f, ...args) => { ++calls; return await f(...args); };
    const spent = () => calls >= HOST_CALLS_PER_STEP;

    // The state as the last call left it, or a fresh one.
    let state;
    try {
      let text = "", next = {bytes: [0]}, done = false;
      while (!done) {
        const piece = await host(slice, stateName, next);
        text += piece.text ?? "";
        done = piece.done || !piece.next;
        next = piece.next;
      }
      state = parse(text);
    } catch (_) {
      state = {phase: "start", source, ask};
    }
    if (state.source !== source || state.ask !== ask) throw new TypeError("readAll key names another read");
    const save = async () => { await host(store, state, stateName); };
    const pause = async () => {
      await save();
      return freeze({done: false, phase: state.phase, progress: progress()});
    };
    const progress = () => ({
      chunks: state.chunks?.length ?? 0,
      spawned: state.tasks?.length ?? 0,
      findings: state.findings?.length ?? 0,
      groups: state.groups?.length ?? 0,
      level: state.level ?? 0,
    });

    if (state.phase === "start") {
      const verdict = await host(can, {read: source, child: {}});
      if (!verdict?.can) return freeze({done: true, refused: verdict?.reason ?? "denied", detail: verdict});
      const child = verdict.child ?? {};
      const window = child.window_tokens || READ_ALL_FALLBACK_WINDOW_TOKENS;
      const tokens = readAllChunkTokens(window, options.window);
      state.window_tokens = window;
      state.by = options.by ?? readAllChunkBy(tokens, child);
      state.until = options.until ?? readAllWaitUntil(child);
      state.chunks = [];
      state.cursor = null;
      state.phase = "chunk";
    }

    if (state.phase === "chunk") {
      const pages = chunks(source, state.by);
      while (state.phase === "chunk") {
        if (spent()) return await pause();
        const page = await host(pages.page, state.cursor ?? undefined);
        if (page.withheld) return freeze({done: true, refused: READ_ALL_WITHHELD_REASON, detail: page});
        for (const c of page.chunks) push(state.chunks, {ref: c.ref, start: c.start, end: c.end});
        if (page.done || !page.next) { state.phase = "spawn"; state.tasks = []; }
        else state.cursor = page.next;
      }
    }

    if (state.phase === "spawn") {
      while (state.tasks.length < state.chunks.length) {
        if (spent()) return await pause();
        const c = state.chunks[state.tasks.length];
        try {
          const receipt = await host(spawn, {source: c.ref, ask, intent_key: readAllIntentKey(key, c)});
          push(state.tasks, receipt.task);
        } catch (error) {
          // The rest is not spawned: it stays unread, and the receipt says so.
          state.spawn_refused = reasonOf(error);
          break;
        }
      }
      state.phase = state.tasks.length ? "wait" : "pack";
      state.findings = [];
    }

    if (state.phase === "wait") {
      if (spent()) return await pause();
      const request = {tasks: state.tasks, step_key: readAllStepKey(key, "wait")};
      const count = readAllWaitCount(options.n_of, state.tasks.length);
      if (count !== undefined) request.n_of = count;
      if (isInteger(state.until)) request.until = state.until;
      let settled;
      try {
        settled = await host(wait, request);
      } catch (_) {
        // Parked: the run resumes once the wait settles, and the next call
        // goes on from here.
        await save();
        return freeze({done: false, phase: "wait", waiting: true, progress: progress()});
      }
      const byTask = Object.create(null);
      state.chunks.forEach((c, i) => { if (i < state.tasks.length) byTask[state.tasks[i]] = i; });
      state.ready = [];
      for (const found of [...(settled.ready ?? []), ...(settled.partial ?? [])])
        push(state.ready, {task: found.task, ref: found.ref, bytes: found.bytes, at: byTask[found.task] ?? 0, reason: found.reason});
      sort(state.ready, (x, y) => x.at - y.at);
      state.read = 0;
      state.phase = "read";
    }

    if (state.phase === "read") {
      while (state.read < state.ready.length) {
        if (spent()) return await pause();
        const found = state.ready[state.read];
        let cites = null;
        try {
          const piece = await host(slice, found.ref, {bytes: [0]});
          const finding = piece.done && typeof piece.text === "string" ? parse(piece.text) : null;
          if (finding && isArray(finding.cites)) cites = readAllNormaliseCites(finding.cites);
        } catch (_) { /* unreadable: kept, with no cites */ }
        push(state.findings, {ref: found.ref, bytes: found.bytes, cites});
        ++state.read;
      }
      state.kept = readAllDedupe(state.findings);
      state.phase = "pack";
    }

    if (state.phase === "pack") {
      state.level = 0;
      state.round = 0;
      state.tree = [];
      state.groups = readAllPack(state.kept ?? [], readAllGroupBytes(state.window_tokens));
      state.phase = state.groups.length ? "summarize" : "store";
    }

    // Each stage summarizes its groups in parallel, waits for all of them,
    // and packs their summaries into the next stage until one is left.
    while (state.phase === "summarize") {
      for (const group of state.groups) {
        if (group.result || group.task || group.failed) continue;
        if (spent()) return await pause();
        const [first, ...rest] = group.refs;
        try {
          const reply = await host(summarize, first, {group: rest, effort: options.effort, defer: true});
          if (typeof reply.handle === "string") group.result = {ref: reply.handle, bytes: reply.bytes};
          else group.task = reply.task;
        } catch (error) {
          group.failed = reasonOf(error);
        }
      }
      const pending = state.groups.filter(g => g.task && !g.result && !g.failed);
      if (pending.length) {
        if (spent()) return await pause();
        let settled;
        try {
          settled = await host(wait, {tasks: pending.map(g => g.task), step_key: readAllStepKey(key, "sum" + state.level + "_" + state.round)});
        } catch (_) {
          await save();
          return freeze({done: false, phase: "summarize", waiting: true, progress: progress()});
        }
        const groups = [];
        for (const group of state.groups) {
          const done = [...(settled.ready ?? []), ...(settled.partial ?? [])].find(f => f.task === group.task);
          const failed = (settled.failed ?? []).find(f => f.task === group.task);
          if (done) { group.result = {ref: done.ref, bytes: done.bytes}; delete group.task; push(groups, group); }
          else if (failed && startsWith(failed.reason, READ_ALL_SPLIT_REASON) && group.refs.length > 1) {
            // Split, and each part summarized on its own.
            for (const part of readAllSplit(group.refs)) push(groups, part);
          } else if (failed) { group.failed = failed.reason; delete group.task; push(groups, group); }
          else push(groups, group);
        }
        state.groups = groups;
        ++state.round;
        continue;
      }
      const made = state.groups.filter(g => g.result);
      for (const g of made) push(state.tree, {summary: g.result.ref, inputs: g.refs});
      if (made.length <= READ_ALL_FOLD_TO) {
        state.final = made.length ? made[0].result.ref : null;
        state.phase = "store";
        break;
      }
      ++state.level;
      state.round = 0;
      state.groups = readAllPack(made.map(g => g.result), readAllGroupBytes(state.window_tokens));
    }

    if (state.phase === "store") {
      let text = "";
      if (state.final) {
        let next = {bytes: [0]}, done = false;
        while (!done) {
          if (spent()) return await pause();
          const piece = await host(slice, state.final, next);
          text += piece.text ?? "";
          done = piece.done || !piece.next;
          next = piece.next;
        }
      } else {
        text = READ_ALL_EMPTY_RESULT;
      }
      const receipt = {
        source,
        tasks: state.tasks ?? [],
        tree: state.tree ?? [],
        recipe: {
          fold: READ_ALL_FOLD_RECIPE,
          group_bytes: readAllGroupBytes(state.window_tokens),
          effort: options.effort ?? READ_ALL_DEFAULT_EFFORT,
        },
      };
      const card = await host(store, text, resultName, {receipt});
      state.phase = "done";
      state.coverage = card.receipt ?? null;
      await save();
      return freeze({done: true, result: card, coverage: state.coverage});
    }

    // A finished read answers its result again.
    if (state.phase === "done") {
      const card = await host(describe, resultName);
      return freeze({done: true, result: card, coverage: state.coverage ?? null});
    }
    return freeze({done: false, phase: state.phase, progress: progress()});
  };
}

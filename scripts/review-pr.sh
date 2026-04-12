#!/bin/bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
BRANCH=$(git branch --show-current)
BASE="${1:-main}"
PR_NUM=$(gh pr list --head "$BRANCH" --json number --jq '.[0].number' 2>/dev/null || echo "")
REVIEW_BASE="$REPO_ROOT/.reviews/$BRANCH"

if [ "$BRANCH" = "main" ]; then
  echo "Error: switch to a feature branch first"
  exit 1
fi

# Find next run number (run-1, run-2, ...) so we never overwrite
RUN=1
while [ -d "$REVIEW_BASE/run-$RUN" ]; do
  RUN=$((RUN + 1))
done
REVIEW_DIR="$REVIEW_BASE/run-$RUN"
mkdir -p "$REVIEW_DIR"

# Symlink "latest" for convenience
ln -sfn "run-$RUN" "$REVIEW_BASE/latest"

LABEL="branch $BRANCH"
[ -n "$PR_NUM" ] && LABEL="PR #$PR_NUM ($BRANCH)"
echo "Reviewing $LABEL against $BASE"
echo "Output: $REVIEW_DIR/"
echo ""

DIFF=$(git diff "$BASE"..."$BRANCH" --stat)
echo "Changed files:"
echo "$DIFF"
echo ""

REVIEW_CONTEXT="You are reviewing branch '$BRANCH' against '$BASE' in the oneiron repo.
Use git diff $BASE...$BRANCH to see the full diff. Read changed files as needed.
Read CLAUDE.md, BUILD-PROMPT.md, and SCHEMA-DESIGN.md for project context.

Stack: Rust, LMDB (heed), Loro CRDT (v1.10), Axum, tokio, tokio-tungstenite.
Crate structure: crates/oneiron (core engine + sync module), crates/oneiron-server (sync server binary).
Sync layer: CrdtEngine trait abstraction with Loro implementation, time-windowed Docs, Observer A (persist+broadcast) + Observer B (materialize), custom WebSocket protocol (tags 0/1/10/20/21).

Output your findings as markdown with sections: Summary, Issues (severity: critical/major/minor/nit), and Verdict (approve/request-changes)."

SECURITY_PROMPT="$REVIEW_CONTEXT

Focus on SECURITY concerns only:
- Unsafe Rust usage (soundness, UB potential)
- Buffer overflows, out-of-bounds access
- LMDB transaction safety (leaked txns, deadlocks)
- CRDT sync security (origin spoofing, update injection)
- WebSocket handler security (auth, frame limits, decompression bombs)
- FFI boundary safety (for future napi-rs consumers)
- Data corruption vectors (key encoding, byte layout, edge value format)

You may use subagents to split the review across files if the diff is large."

CODE_PROMPT="$REVIEW_CONTEXT

Focus on CODE QUALITY:
- Bugs, logic errors, race conditions
- Rust idioms (ownership, borrowing, error handling)
- Performance (unnecessary allocations, missing capacity hints, LMDB patterns)
- CrdtEngine trait design (ergonomics, completeness, future-proofing)
- Observer pattern correctness (echo suppression, materializer mutex, lock ordering)
- Type safety, API ergonomics
- Naming, structure, dead code

You may use subagents to split the review across files if the diff is large."

GEMINI_PROMPT="$REVIEW_CONTEXT

Provide a thorough code review covering:
- Correctness and potential bugs
- Design and architecture alignment with SCHEMA-DESIGN.md
- Performance and scalability
- Test coverage gaps
- Sync layer spec compliance (ONEIRON-ARCH-023/023b)"

# Check which tools are available
has() { command -v "$1" >/dev/null 2>&1; }

TOTAL=0
SKIPPED=0
PIDS=()
NAMES=()

launch() {
  local name="$1"
  shift
  NAMES+=("$name")
  PIDS+=($!)
  TOTAL=$((TOTAL + 1))
}

skip() {
  echo "  [$1] skipped ($2 not installed)"
  SKIPPED=$((SKIPPED + 1))
}

echo "Launching reviewers..."

# 1. Claude — security review
if has claude; then
  claude -p "$SECURITY_PROMPT" \
    --model claude-opus-4-6 \
    --dangerously-skip-permissions \
    --no-session-persistence \
    --max-turns 200 \
    > "$REVIEW_DIR/claude-security.md" 2>/dev/null &
  launch "claude-security"
else skip "claude-security" "claude"; fi

# 2. Claude — code quality review
if has claude; then
  claude -p "$CODE_PROMPT" \
    --model claude-opus-4-6 \
    --dangerously-skip-permissions \
    --no-session-persistence \
    --max-turns 200 \
    > "$REVIEW_DIR/claude-code.md" 2>/dev/null &
  launch "claude-code"
else skip "claude-code" "claude"; fi

# 3. Codex — review (xhigh reasoning)
if has codex; then
  codex review -c 'model_reasoning_effort="xhigh"' --base "$BASE" \
    > "$REVIEW_DIR/codex.md" 2>&1 &
  launch "codex"
else skip "codex" "codex"; fi

# 4. Gemini — code review
if has gemini; then
  gemini -p "$GEMINI_PROMPT" \
    --yolo \
    > "$REVIEW_DIR/gemini.md" 2>&1 &
  launch "gemini"
else skip "gemini" "gemini"; fi

# 5. CodeRabbit — pattern analysis + learnings
if has coderabbit; then
  coderabbit review \
    --base "$BASE" \
    --plain \
    > "$REVIEW_DIR/coderabbit.md" 2>&1 &
  launch "coderabbit"
else skip "coderabbit" "coderabbit"; fi

echo ""
echo "Running $TOTAL reviewer(s) in parallel ($SKIPPED skipped). Waiting..."
echo ""

FAILED=0
for i in "${!PIDS[@]}"; do
  name="${NAMES[$i]}"
  pid="${PIDS[$i]}"
  if wait "$pid" 2>/dev/null; then
    SIZE=$(wc -c < "$REVIEW_DIR/$name.md" 2>/dev/null || echo "0")
    echo "  $name: done (${SIZE} bytes)"
  else
    echo "  $name: FAILED (exit $?)"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
if [ "$SKIPPED" -gt 0 ]; then
  echo "Note: $SKIPPED reviewer(s) skipped (not installed)."
fi
if [ "$FAILED" -gt 0 ]; then
  echo "Warning: $FAILED review(s) failed. Check output files for details."
fi
if [ "$TOTAL" -eq 0 ]; then
  echo "Error: no review tools found. Install at least claude."
  exit 1
fi
echo "Reviews saved to $REVIEW_DIR/"
echo "Run /validate-reviews in Claude Code to triage findings."

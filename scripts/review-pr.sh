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

# 1. Claude — security review
echo "[1/6] Claude security review..."
claude -p "$REVIEW_CONTEXT

Focus on SECURITY concerns only:
- Unsafe Rust usage (soundness, UB potential)
- Buffer overflows, out-of-bounds access
- LMDB transaction safety (leaked txns, deadlocks)
- CRDT sync security (origin spoofing, update injection)
- WebSocket handler security (auth, frame limits, decompression bombs)
- FFI boundary safety (for future napi-rs consumers)
- Data corruption vectors (key encoding, byte layout, edge value format)

You may use subagents to split the review across files if the diff is large." \
  --model claude-opus-4-6 \
  --dangerously-skip-permissions \
  --no-session-persistence \
  --max-turns 200 \
  > "$REVIEW_DIR/claude-security.md" 2>/dev/null &
PID1=$!

# 2. Claude — code quality review
echo "[2/6] Claude code review..."
claude -p "$REVIEW_CONTEXT

Focus on CODE QUALITY:
- Bugs, logic errors, race conditions
- Rust idioms (ownership, borrowing, error handling)
- Performance (unnecessary allocations, missing capacity hints, LMDB patterns)
- CrdtEngine trait design (ergonomics, completeness, future-proofing)
- Observer pattern correctness (echo suppression, materializer mutex, lock ordering)
- Type safety, API ergonomics
- Naming, structure, dead code

You may use subagents to split the review across files if the diff is large." \
  --model claude-opus-4-6 \
  --dangerously-skip-permissions \
  --no-session-persistence \
  --max-turns 200 \
  > "$REVIEW_DIR/claude-code.md" 2>/dev/null &
PID2=$!

# 3. Codex — review
echo "[3/6] Codex review..."
codex review --base "$BASE" \
  > "$REVIEW_DIR/codex.md" 2>&1 &
PID3=$!

# 4. Gemini — code review
echo "[4/6] Gemini code review..."
gemini -p "$REVIEW_CONTEXT

Provide a thorough code review covering:
- Correctness and potential bugs
- Design and architecture alignment with SCHEMA-DESIGN.md
- Performance and scalability
- Test coverage gaps
- Sync layer spec compliance (ONEIRON-ARCH-023/023b)" \
  --yolo \
  > "$REVIEW_DIR/gemini.md" 2>&1 &
PID4=$!

# 5. Qodo — combined security + code review (GPT-5.4, high reasoning)
echo "[5/6] Qodo review (GPT-5.4)..."
qodo oneiron_review \
  --model gpt-5.4 \
  --set target_branch="$BASE" \
  --set reasoning_effort=high \
  --yes \
  --silent \
  > "$REVIEW_DIR/qodo.md" 2>&1 &
PID5=$!

# 6. CodeRabbit — pattern analysis + learnings
echo "[6/6] CodeRabbit review..."
coderabbit review \
  --base "$BASE" \
  --plain \
  > "$REVIEW_DIR/coderabbit.md" 2>&1 &
PID6=$!

echo ""
echo "All reviews running in parallel. Waiting..."
echo ""

FAILED=0
PID_NAMES="PID1:claude-security PID2:claude-code PID3:codex PID4:gemini PID5:qodo PID6:coderabbit"
for PID_NAME in $PID_NAMES; do
  PID_VAR="${PID_NAME%%:*}"
  NAME="${PID_NAME##*:}"
  PID="${!PID_VAR}"
  if wait "$PID" 2>/dev/null; then
    SIZE=$(wc -c < "$REVIEW_DIR/$NAME.md" 2>/dev/null || echo "0")
    echo "  $NAME: done (${SIZE} bytes)"
  else
    echo "  $NAME: FAILED (exit $?)"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
if [ "$FAILED" -gt 0 ]; then
  echo "Warning: $FAILED review(s) failed. Check output files for details."
fi
echo "Reviews saved to $REVIEW_DIR/"
echo "Run /validate-reviews in Claude Code to triage findings."

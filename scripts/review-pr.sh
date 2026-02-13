#!/bin/bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
BRANCH=$(git branch --show-current)
BASE="${1:-main}"
PR_NUM=$(gh pr list --head "$BRANCH" --json number --jq '.[0].number' 2>/dev/null || echo "")
REVIEW_DIR="$REPO_ROOT/.reviews/$BRANCH"

if [ "$BRANCH" = "main" ]; then
  echo "Error: switch to a feature branch first"
  exit 1
fi

mkdir -p "$REVIEW_DIR"

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
Output your findings as markdown with sections: Summary, Issues (severity: critical/major/minor/nit), and Verdict (approve/request-changes)."

# 1. Claude — security review
echo "[1/4] Claude security review..."
claude -p "$REVIEW_CONTEXT

Focus on SECURITY concerns only:
- Unsafe Rust usage (soundness, UB potential)
- Buffer overflows, out-of-bounds access
- LMDB transaction safety (leaked txns, deadlocks)
- FFI boundary safety (for future C consumers)
- Data corruption vectors (key encoding, byte layout)

You may use subagents to split the review across files if the diff is large." \
  --model claude-opus-4-6 \
  --dangerously-skip-permissions \
  --no-session-persistence \
  --max-turns 200 \
  > "$REVIEW_DIR/claude-security.md" 2>/dev/null &
PID1=$!

# 2. Claude — code quality review
echo "[2/4] Claude code review..."
claude -p "$REVIEW_CONTEXT

Focus on CODE QUALITY:
- Bugs, logic errors, race conditions
- Rust idioms (ownership, borrowing, error handling)
- Performance (unnecessary allocations, missing capacity hints, LMDB patterns)
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
echo "[3/4] Codex review..."
codex review --base "$BASE" \
  > "$REVIEW_DIR/codex.md" 2>&1 &
PID3=$!

# 4. Gemini — code review
echo "[4/4] Gemini code review..."
gemini -p "$REVIEW_CONTEXT

Provide a thorough code review covering:
- Correctness and potential bugs
- Design and architecture alignment with SCHEMA-DESIGN.md
- Performance and scalability
- Test coverage gaps" \
  --yolo \
  > "$REVIEW_DIR/gemini.md" 2>&1 &
PID4=$!

echo ""
echo "All 4 reviews running in parallel. Waiting..."
echo ""

FAILED=0
for PID_NAME in "PID1:claude-security" "PID2:claude-code" "PID3:codex" "PID4:gemini"; do
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

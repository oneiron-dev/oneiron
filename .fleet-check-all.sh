export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
head=$(cat .l04-head 2>/dev/null)
out=/tmp/l04-check-$$-all.out
cargo check --locked --workspace --all-features > "$out" 2>&1
rc_all=$?
echo "## ===== cargo check --locked --workspace --all-features"
grep -E '^error' -A60 "$out" | head -1500
echo "## errors: $(grep -cE '^error' "$out")"
echo "## warnings: $(grep -cE '^warning' "$out")"
tail -3 "$out"
rm -f "$out"
echo "## CHECK-ALL rc=$rc_all head=$head"

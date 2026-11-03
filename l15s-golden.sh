export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=${L15S_JOBS:-6} CARGO_INCREMENTAL=1 CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_TARGET_DIR=$HOME/l15s-target
head=$(git rev-parse HEAD 2>/dev/null || echo nogit)
start=$(date +%s)
cargo build --locked --release -p oneiron --bin l15s_bench
rc=$?
echo "## BUILD rc=$rc head=$head secs=$(( $(date +%s) - start ))"
if [ $rc -ne 0 ]; then exit $rc; fi
for stage in bm25 hydrate temporal secret; do
  for i in 1 2; do "$CARGO_TARGET_DIR/release/l15s_bench" $stage; done
done
echo "## GOLDEN-DONE"

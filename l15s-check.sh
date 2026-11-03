export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=1 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR=$HOME/l15s-target
cargo check --locked -p oneiron --bin l15s_bench 2>&1 | tail -40
echo "## CHECK-DONE rc=${PIPESTATUS[0]}"

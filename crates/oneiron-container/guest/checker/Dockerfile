# The merge queue checker guest (README.md): the trusted helper, Python 3,
# Git, Rust 1.96 under /opt, the native build closure of the workspace's
# `cargo check --locked --workspace --all-features`, and a dependency store
# preseeded from the baseline lockfile. Built on a Linux host by build.sh
# here, which puts this directory's checker.py, this checkout's builds of
# oneiron-fence and oneiron-guest, and a `git archive` of its HEAD (`tree/`)
# in the context; deployments pin the built image's id. The runtime adds
# --network none, --read-only, a non-root user, --cap-drop ALL and tmpfs
# scratch (crates/oneiron-container/src/lib.rs).
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS base

# What each package is for:
# - build-essential: the C compiler and linker for build scripts, proc-macros
#   and the C that cc-built crates compile (ring, blake3, zstd-sys, bzip2-sys,
#   lmdb-master3-sys, onig_sys, tree-sitter, wasmtime).
# - cmake: expat-sys builds its bundled libexpat with CMake when pkg-config
#   finds no system expat.
# - pkg-config: every pkg-config and system-deps probe below.
# - git: the image contract (README.md).
# - python3: the helper's interpreter, and pyo3-build-config's probe
#   (oneiron-py).
# - perl: build scripts that run it (build-essential pulls it as well).
# - ca-certificates, curl: this build's downloads (rustup-init, the
#   toolchain, `cargo fetch`); a check itself runs offline.
# - libasound2-dev: alsa-sys (cpal) probes `alsa`.
# - libdbus-1-dev: libdbus-sys (tao's dbus feature) probes `dbus-1`.
# - libgtk-3-dev: gtk-sys, gdk-sys, gdkx11-sys, atk-sys, cairo-sys-rs,
#   pango-sys, gdk-pixbuf-sys, glib-sys, gio-sys and gobject-sys (tauri, tao,
#   wry and muda on Linux) probe gtk+-3.0, gdk-3.0, gdk-x11-3.0, atk, cairo,
#   pango, gdk-pixbuf-2.0, glib-2.0, gio-2.0 and gobject-2.0.
# - libwebkit2gtk-4.1-dev: webkit2gtk-sys (wry) probes webkit2gtk-4.1.
# - libjavascriptcoregtk-4.1-dev: javascriptcore-rs-sys probes
#   javascriptcoregtk-4.1.
# - libsoup-3.0-dev: soup3-sys probes libsoup-3.0.
# The other -sys crates in Cargo.lock build bundled C, load their library at
# run time, probe nothing at build, or are for other targets; none needs
# clang, bindgen or OpenSSL.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config git python3 perl ca-certificates curl \
      libasound2-dev libdbus-1-dev libgtk-3-dev libwebkit2gtk-4.1-dev \
      libjavascriptcoregtk-4.1-dev libsoup-3.0-dev \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp guest

# Rust under /opt, readable and runnable by any uid (an OCI guest runs as
# 10001, a native session's child as 65534). rustup-init 1.29.1 for the
# image's architecture, kept only once its SHA-256 is the release's, installs
# the toolchain under the name the seed plan selects (`RUSTUP_TOOLCHAIN=1.96`)
# with rust-toolchain.toml's profile and components.
ENV CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu sum=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 ;; \
      arm64) triple=aarch64-unknown-linux-gnu sum=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 ;; \
      *) echo "no rustup-init 1.29.1 pin for architecture '$TARGETARCH'" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/1.29.1/$triple/rustup-init" \
 && echo "$sum  /tmp/rustup-init" | sha256sum -c - \
 && chmod 0755 /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain 1.96 --component rustfmt,clippy \
 && rm /tmp/rustup-init \
 && chmod -R a+rX /opt/cargo /opt/rustup

# The dependency store: every registry crate and Git source the lockfile
# names, fetched against the checkout's own manifests, path crates and
# .cargo/config.toml (its vendored patch). The store's CARGO_HOME starts
# empty, so no host credentials or cargo config enter it, and the tree stays
# in this stage.
FROM base AS store
COPY tree /src
WORKDIR /src
RUN CARGO_HOME=/opt/queue-check/cargo-home cargo fetch --locked \
 && chmod -R a+rX /opt/queue-check

FROM base
COPY --from=store /opt/queue-check/cargo-home /opt/queue-check/cargo-home
COPY --chmod=0555 checker.py /usr/local/bin/oneiron-queue-check
COPY --chmod=0555 oneiron-fence /usr/local/bin/oneiron-fence
COPY --chmod=0555 oneiron-guest /usr/local/bin/oneiron-guest
RUN ln -s /usr/local/bin/oneiron-guest /sbin/oneiron-guest

USER 10001:10001
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/oneiron-queue-check"]

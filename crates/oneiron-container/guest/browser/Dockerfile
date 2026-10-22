# The browser guest: Lightpanda (the engine agents start on) or headless
# Chromium, each speaking CDP over the guest's stdio only (entrypoint.sh).
# Built on a Linux host by `build.sh --dockerfile`, which puts this checkout's builds
# of oneiron-fence, oneiron-browser-relay and oneiron-guest in the context
# beside this directory's files; deployments pin the built image's id
# (README.md). The runtime adds --network none, --read-only, a non-root
# user, --cap-drop ALL and tmpfs scratch (crates/oneiron-container/src/run.rs).
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation busybox \
      ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp guest

# Lightpanda 1.0.0 (lightpanda-io/browser at
# 588f6223b9cae8a2406aeef035ed9363a3e404fd): the release's Linux build for
# the image's architecture, kept only once its SHA-256 is the release's.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) arch=x86_64 sum=aa5a4b8ed53d1e38b3c73f5b2647d0a84a82e6744557f45f9a9c85858aa031c3 ;; \
      arm64) arch=aarch64 sum=69791924bcee43b13b224af4c845622c5fe66fdbc1b8143bfaa39ca8f85244f5 ;; \
      *) echo "no Lightpanda 1.0.0 build for architecture '$TARGETARCH'" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/lightpanda \
      "https://github.com/lightpanda-io/browser/releases/download/1.0.0/lightpanda-$arch-linux" \
 && echo "$sum  /tmp/lightpanda" | sha256sum -c - \
 && install -m 0555 /tmp/lightpanda /usr/local/bin/lightpanda \
 && rm /tmp/lightpanda

COPY --chmod=0555 oneiron-fence /usr/local/bin/oneiron-fence
COPY --chmod=0555 oneiron-browser-relay /usr/local/bin/oneiron-browser-relay
COPY --chmod=0555 oneiron-guest /sbin/oneiron-guest
COPY entrypoint.sh /usr/local/bin/oneiron-browser-guest
RUN chmod 0555 /usr/local/bin/oneiron-browser-guest

USER 10001:10001
ENV HOME=/tmp
# Lightpanda sends no usage telemetry. entrypoint.sh sets it again for a
# start that does not carry the image's environment (Firecracker's).
ENV LIGHTPANDA_DISABLE_TELEMETRY=true
ENTRYPOINT ["/usr/local/bin/oneiron-browser-guest"]

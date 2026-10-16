# The browser guest: headless Chromium that speaks CDP over its stdio only.
# Built on a Linux host (`docker build -t <tag> .`); deployments pin the built
# image by digest. The runtime adds --network none, --read-only, a non-root
# user, --cap-drop ALL and tmpfs scratch (crates/oneiron-container/src/run.rs).
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation busybox \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp guest

COPY --chmod=0555 oneiron-fence /usr/local/bin/oneiron-fence
COPY --chmod=0555 oneiron-guest /sbin/oneiron-guest
COPY entrypoint.sh /usr/local/bin/oneiron-browser-guest
RUN chmod 0555 /usr/local/bin/oneiron-browser-guest

USER 10001:10001
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/oneiron-browser-guest"]

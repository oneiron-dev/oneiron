# The desktop guest: a Linux desktop (Xvfb, its session and accessibility
# buses, Openbox and a fixed app set) that cua-driver serves as MCP over its
# stdio only. build.sh builds it on a Linux host (README.md): a `cua-driver`
# from trycua/cua at 6d6c734c127025fb39ad5d585a10382808b39dc1 (release
# 0.36.0, MIT), oneiron-fence and oneiron-guest go in the context, and the
# driver's sha256 is CUA_DRIVER_SHA256. Deployments pin the local image id it
# prints. The runtime adds --network none, --read-only, a non-root user,
# --cap-drop ALL and tmpfs scratch (crates/oneiron-container/src/lib.rs).
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ARG CUA_DRIVER_SHA256

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      xvfb xauth dbus dbus-x11 at-spi2-core libatk-adaptor openbox \
      libx11-6 libxi6 libxtst6 libxext6 libwayland-client0 libxkbcommon0 \
      mousepad gnumeric abiword galculator fonts-liberation \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp guest

COPY --chmod=0555 cua-driver /usr/local/bin/cua-driver
RUN test -n "$CUA_DRIVER_SHA256" \
 && echo "$CUA_DRIVER_SHA256  /usr/local/bin/cua-driver" | sha256sum -c -
COPY --chmod=0555 oneiron-fence /usr/local/bin/oneiron-fence
COPY --chmod=0555 oneiron-guest /sbin/oneiron-guest
COPY entrypoint.sh /usr/local/bin/oneiron-desktop-guest
RUN chmod 0555 /usr/local/bin/oneiron-desktop-guest

USER 10001:10001
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/oneiron-desktop-guest"]

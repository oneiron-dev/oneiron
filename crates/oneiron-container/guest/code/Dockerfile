# Build on Linux with the fleet-built oneiron-guest binary in the context.
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp guest
COPY --chmod=0555 oneiron-fence /usr/local/bin/oneiron-fence
COPY --chmod=0555 oneiron-guest /usr/local/bin/oneiron-guest
RUN ln -s /usr/local/bin/oneiron-guest /sbin/oneiron-guest
USER 10001:10001
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/oneiron-guest", "--container"]

# Linux Chromium guest recipe — S1

Run **only on an authorized Linux fleet host**, never on a developer laptop. This
recipe reuses `crates/oneiron-container/guest/browser/Dockerfile`
and its `entrypoint.sh chromium` path. It creates no second browser stack or
Dockerfile. The existing image contains Chromium and the engine's stdio CDP
transport; there is no debugging TCP port. No image change is needed.

Assumptions: a Linux checkout at `/srv/oneiron`, Docker, Python ≥3.11, curl,
sudo and Docker's iptables backend (with a `DOCKER-USER` chain). The subnet
172.30.91.0/24, ports 8765/8766, bridge `br-cua-s1` and names below must be unused.
Use an exclusive bench host/lane; don't join unrelated containers to this network.
IPv6 is not enabled on this bridge. If the host uses a different firewall backend,
stop and translate these rules deliberately; do not omit isolation.

## 1. Select the existing image

Use a previously built image on the Linux host:

```sh
export REPO=/srv/oneiron
export FIXTURE="$REPO/crates/oneiron-bench/fixtures/cua"
export RUN=/srv/cua-s1-run
export IMAGE="$(docker image inspect oneiron-browser-guest:local --format '{{.Id}}')"
```

If that image does not exist, the existing build recipe can build it on the Linux
build host (never here on the Mac):

```sh
cd /srv/oneiron
export IMAGE="$(crates/oneiron-container/guest/browser/build.sh)"
```

Record the resulting `sha256:...` local image id in the S2 run metadata. Use the
same id for every arm; do not use the floating tag as the run's pin.

## 2. Isolate guest traffic

```sh
docker network create --driver bridge --internal --subnet 172.30.91.0/24 --gateway 172.30.91.1 --opt com.docker.network.bridge.name=br-cua-s1 cua-s1
sudo iptables -N CUA_S1_INPUT
sudo iptables -A CUA_S1_INPUT -d 172.30.91.1 -p tcp --dport 8765 -j ACCEPT
sudo iptables -A CUA_S1_INPUT -j DROP
sudo iptables -I INPUT 1 -i br-cua-s1 -j CUA_S1_INPUT
sudo iptables -I DOCKER-USER 1 -i br-cua-s1 -j DROP
```

`--internal` removes external routing. The INPUT chain allows only the host's
PUBLIC HTTP endpoint, then drops every other guest-to-host packet. DOCKER-USER
blocks forwarding off this bridge, including other Docker networks. Host-local
responses to PUBLIC use OUTPUT, not FORWARD. Do not use `--network host`, `-p`, a
Docker socket mount, extra network attachments or privileged capabilities. The
private listener stays on host loopback and has an independent bearer token; the
guest gets neither a route to that listener nor its token/file/environment.

## 3. Start the one-process, two-listener server

```sh
umask 077
install -d -m 700 "$RUN"
python3 -I -c 'import secrets; print(secrets.token_hex(32))' > "$RUN/private-token"
python3 -I "$FIXTURE/state_server.py" --public-host 172.30.91.1 --public-port 8765 --private-port 8766 --token-file "$RUN/private-token" --event-log "$RUN/events.jsonl" > "$RUN/server.log" 2>&1 &
echo $! > "$RUN/server.pid"
curl --fail --silent --show-error --header "Authorization: Bearer $(cat "$RUN/private-token")" http://127.0.0.1:8766/health
```

Wait for health before reset; if the first curl races startup, inspect the log and
retry health, not server startup. Never start a second copy. For a later private
input variant, add `--external-data-dir /srv/private-cua-data` to that server
command and keep that directory/logs outside the repository. Don't mount it into
the guest. PUBLIC will render only the selected task's required inputs.

## 4. Reset privately, then create a fresh guest

Example F4 base run:

```sh
curl --fail --silent --show-error --header "Authorization: Bearer $(cat "$RUN/private-token")" --header 'Content-Type: application/json' --data '{"fixture":"F4","version":"v0","seed":20261021}' http://127.0.0.1:8766/reset > "$RUN/reset.json"
docker run --detach --interactive --name cua-s1-browser --network cua-s1 --ip 172.30.91.2 --dns 127.0.0.1 --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --tmpfs /tmp:rw,nosuid,nodev,size=1g "$IMAGE" chromium
```

The candidate entry URL is `http://172.30.91.1:8765/F4/v0/index.html`. Only pass that
PUBLIC origin/entry and task facts to the candidate. A host-side driver attaches
CDP stdin/stdout using this exact transport command (no TTY, no debug port):

```sh
docker attach --sig-proxy=false cua-s1-browser
```

That command is a binary/NUL-delimited CDP transport for the driver, **not** a
human terminal session or an instruction to type CDP by hand. It must be launched
by the host driver with pipes. Chromium stderr remains diagnostics. Use
`docker logs cua-s1-browser` only for diagnosis, never as checker state.

The guest image runs its normal Chromium entrypoint, nonroot and read-only; this
standalone network recipe does not claim to instantiate the production engine's
Landlock/seccomp launcher. Fixture effects remain isolated and have no outbound
mail/account integration. The driver must remain the engine browser surface in
benchmark runs, not an unrestricted alternative browser agent.

## 5. Read checker state, retain audit evidence, clean up

After all public writes report Saved and engine actions settle, from the host:

```sh
curl --fail --silent --show-error --header "Authorization: Bearer $(cat "$RUN/private-token")" http://127.0.0.1:8766/state/F4 > "$RUN/state-F4.json"
docker rm --force cua-s1-browser
kill "$(cat "$RUN/server.pid")"
sudo iptables -D INPUT -i br-cua-s1 -j CUA_S1_INPUT
sudo iptables -D DOCKER-USER -i br-cua-s1 -j DROP
sudo iptables -F CUA_S1_INPUT
sudo iptables -X CUA_S1_INPUT
docker network rm cua-s1
```

For another run keep the server/network but remove the previous guest, perform a
new PRIVATE reset and create a fresh guest before driving the entry URL. Partition
appended JSONL by the reset's `run_id`; never count only the last apparent Send.
Preserve reset response, state JSON, events, image id, seed and engine receipts in
host-private run artifacts. Token files and private state must not enter candidate
mounts or the public repository. The token should not be retained with shared
result artifacts.

## FIX / S2 handoff

- The existing engine launcher adds `--network none`. S2 must use its declared
  fixture HTTP door or add a bench-only isolated transport equivalent to the
  above network. This README is a runnable standalone guest recipe, not a claim
  that the future `oneiron-bench cua` CLI already supports this wiring. Do not
  change the engine Dockerfile or weaken production network policy for S1.
- No Linux/Docker/Chromium/firewall execution was performed during authoring.
  Verify PUBLIC reachability and PRIVATE/external unreachability on the booked
  Linux host before collecting results. On an nftables-only Docker backend, this
  iptables recipe needs an equivalent reviewed host-local ruleset before use.

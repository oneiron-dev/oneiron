#!/usr/bin/env sh
set -eu

ONEIRON_GIT_URL="${ONEIRON_GIT_URL:-https://github.com/oneiron-dev/oneiron}"

if [ -n "${ONEIRON_GIT_REV:-}" ]; then
  exec cargo install --git "$ONEIRON_GIT_URL" --rev "$ONEIRON_GIT_REV" "$@" oneiron-server
fi

if [ -n "${ONEIRON_GIT_TAG:-}" ]; then
  exec cargo install --git "$ONEIRON_GIT_URL" --tag "$ONEIRON_GIT_TAG" "$@" oneiron-server
fi

ONEIRON_GIT_BRANCH="${ONEIRON_GIT_BRANCH:-main}"
exec cargo install --git "$ONEIRON_GIT_URL" --branch "$ONEIRON_GIT_BRANCH" "$@" oneiron-server

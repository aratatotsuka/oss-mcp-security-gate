#!/bin/sh
set -eu

# Run only on a dedicated Linux CI worker. This script never runs target code;
# it probes the sandbox using a reviewed, digest-pinned test image supplied by CI.
: "${SECURITY_GATE_TEST_IMAGE:?set a reviewed image@sha256 digest}"
case "$SECURITY_GATE_TEST_IMAGE" in *@sha256:*) ;; *) echo "image is not digest-pinned" >&2; exit 1;; esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf 'unchanged' > "$tmp/sentinel"

docker run --rm --pull never --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 \
  --cpus 0.25 --memory 64m --memory-swap 64m \
  --mount "type=bind,src=$tmp,dst=/target,readonly" \
  "$SECURITY_GATE_TEST_IMAGE" sh -c '
    test ! -e /var/run/docker.sock
    test ! -e /run/containerd/containerd.sock
    ! printf changed > /target/sentinel
    ! wget -q -T 2 -O /dev/null http://169.254.169.254/latest/meta-data/
    ! wget -q -T 2 -O /dev/null https://example.com/
  '

test "$(cat "$tmp/sentinel")" = unchanged

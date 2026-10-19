#!/bin/sh
# Build with dependency access; execute without network or host directory mounts.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! docker info >/dev/null 2>&1; then
    echo 'Docker is unavailable. Start Docker Desktop or OrbStack and retry.' >&2
    exit 1
fi

docker build --tag sandbox-escape-finder-eval .
docker image inspect --format 'Evaluation image: {{.Id}}' sandbox-escape-finder-eval
docker run --rm --init \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges=true \
    --pids-limit 128 \
    --memory 512m --memory-swap 512m \
    --cpus 2 \
    sandbox-escape-finder-eval

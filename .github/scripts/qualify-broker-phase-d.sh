#!/usr/bin/env bash
# Explicit disposable lab only. Engineering smoke; never admission evidence.
set -euo pipefail
[[ $(id -u) == 0 && -f /etc/neticora-runnerd-lab && $# == 2 ]]
phase_d_binary=$1
phase_d_base_image=$2
phase_d_docker=/opt/neticora-runnerd-lab/docker-29.9.3/bin/docker
phase_d_endpoint=unix:///run/runnerd09-docker.sock
[[ -x $phase_d_binary && -S /run/runnerd09-docker.sock ]]
phase_d_name=phase-d-$(cat /proc/sys/kernel/random/uuid)
phase_d_stage=$(mktemp -d /var/tmp/runnerd-phase-d-image.XXXXXX)
chmod 0755 "$phase_d_stage"
cat > "$phase_d_stage/workload" <<'WORKLOAD'
#!/bin/sh
set -eu
umask 077
test -s /run/neticora-bootstrap/bootstrap.json
test "$(id -u)" = 10002
test ! -S /run/docker.sock
test ! -S /run/containerd/containerd.sock
# Real CPU/filesystem process with constrained work mount, no GitHub credentials.
awk 'BEGIN { for(i=1;i<=10000;i++) s+=i; if(s!=50005000) exit 1; print s }' > /runner/_work/fixture-result
test "$(cat /runner/_work/fixture-result)" = 50005000
rm /run/neticora-bootstrap/bootstrap.json
fixture_ticks=0
while ! test -f /run/neticora-bootstrap/fixture-finish; do
  fixture_ticks=$((fixture_ticks+1))
  test "$fixture_ticks" -lt 1200
  sleep 0.1
done
rm /run/neticora-bootstrap/fixture-finish
WORKLOAD
chmod 0755 "$phase_d_stage/workload"
cat > "$phase_d_stage/Dockerfile" <<DOCKERFILE
FROM $phase_d_base_image AS fixture
FROM scratch
COPY --from=fixture /bin /bin
COPY --from=fixture /lib /lib
COPY --from=fixture /usr/bin /usr/bin
ENV PATH=/usr/local/bin:/usr/bin:/bin HOME=/runner
WORKDIR /runner
LABEL org.neticora.qualification.controlled-workload=true
COPY workload /usr/local/bin/runnerd-github
LABEL com.neticora.runnerd.template=linux-github-process-v1 \
      com.neticora.runnerd.docker-build=false \
      com.neticora.runnerd.hard-storage-limit=false
ENTRYPOINT ["/usr/local/bin/runnerd-github"]
DOCKERFILE
"$phase_d_docker" -H "$phase_d_endpoint" image inspect "$phase_d_base_image" >/dev/null
"$phase_d_docker" -H "$phase_d_endpoint" image inspect registry:3 >/dev/null
# A separate loopback registry gives the local fixture an immutable RepoDigest.
phase_d_registry=$("$phase_d_docker" -H "$phase_d_endpoint" run -d --name "$phase_d_name-registry" --label com.neticora.runnerd.phase-d="$phase_d_name" -p 127.0.0.1::5000 registry:3)
phase_d_port=$("$phase_d_docker" -H "$phase_d_endpoint" port "$phase_d_registry" 5000/tcp | sed -n 's/^127\.0\.0\.1://p')
[[ $phase_d_port =~ ^[0-9]+$ ]]
phase_d_image=127.0.0.1:$phase_d_port/neticora/phase-d:$phase_d_name
"$phase_d_docker" -H "$phase_d_endpoint" build --pull=false --network=none -t "$phase_d_image" "$phase_d_stage"
"$phase_d_docker" -H "$phase_d_endpoint" push "$phase_d_image"
phase_d_digest=$("$phase_d_docker" -H "$phase_d_endpoint" image inspect "$phase_d_image" --format '{{index .RepoDigests 0}}')
phase_d_network=$("$phase_d_docker" -H "$phase_d_endpoint" network create --driver bridge --label com.neticora.runnerd.phase-d="$phase_d_name" "$phase_d_name")
RUNNERD_D2_CONTROLLED_WORKLOAD=1 RUNNERD_PHASE_D_ENDPOINT="$phase_d_endpoint" RUNNERD_PHASE_D_IMAGE="$phase_d_digest" RUNNERD_PHASE_D_NETWORK="$phase_d_network" TMPDIR=/var/tmp \
  "$phase_d_binary" -test.v -test.run '^TestPhaseDControllerRealDocker$' -test.timeout 3m
# Success cleanup affects only the script's exact fixture registry/network.
# Failures retain ownership and resources for diagnosis; no generic prune.
"$phase_d_docker" -H "$phase_d_endpoint" stop "$phase_d_registry" >/dev/null
"$phase_d_docker" -H "$phase_d_endpoint" rm -v "$phase_d_registry" >/dev/null
"$phase_d_docker" -H "$phase_d_endpoint" network rm "$phase_d_network" >/dev/null
printf '%s\n' 'Phase D engineering smoke passed. Production admission remains NO-GO.'

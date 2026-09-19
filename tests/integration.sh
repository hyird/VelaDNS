#!/bin/sh
set -eu

image=${1:-veladns:test}
alpine_mirror=${TEST_ALPINE_MIRROR:-}
network="veladns-test-$$"
mock_name="veladns-mock-$$"
dns_name="veladns-under-test-$$"
client_name="veladns-client-$$"
# An explicit template keeps TMPDIR authoritative. BSD mktemp otherwise ignores
# it, and the rule files then land outside the paths a macOS Docker VM shares.
rule_overrides=$(mktemp -d "${TMPDIR:-/tmp}/veladns-test.XXXXXXXX")

cleanup() {
  docker rm -f "$client_name" "$dns_name" "$mock_name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$rule_overrides"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  docker inspect -f '{{json .State}}' "$dns_name" >&2 2>/dev/null || true
  docker logs "$dns_name" >&2 || true
  docker exec "$dns_name" ps -ef >&2 2>/dev/null || true
  docker exec "$dns_name" /usr/local/bin/veladns-healthcheck >&2 2>/dev/null || true
  if [ -n "${dns_ip:-}" ]; then
    docker exec "$client_name" \
      dig +time=3 +tries=1 "@$dns_ip" dns.google A >&2 2>/dev/null || true
  fi
  exit 1
}

docker network create "$network" >/dev/null
printf 'full:dns.google\nfull:cloudflare-dns.com\n' >"$rule_overrides/proxy.txt"

# A classified-global name must reach Mihomo without an encrypted real lookup
# first, so the list is exercised with a name that has no real answer at all.
mkdir -p "$rule_overrides/data"
printf 'full:fakeip-first.test\nfull:www.wikipedia.org\n' \
  >"$rule_overrides/data/proxy.txt"

docker image inspect -f '{{json .Config.Healthcheck.Test}}' "$image" \
  | grep -q 'veladns-healthcheck' \
  || fail "image does not define the VelaDNS health check"

# Model a Mihomo DNS service on a custom port.
docker run -d \
  --name "$mock_name" \
  --network "$network" \
  -e "ALPINE_MIRROR=$alpine_mirror" \
  alpine:3.24 \
  sh -c 'set -eu
    if [ -n "$ALPINE_MIRROR" ]; then
      sed -i "s|https://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g" /etc/apk/repositories
    fi
    apk add --no-cache dnsmasq >/dev/null
    exec dnsmasq --keep-in-foreground --no-resolv --no-hosts \
      --port=5353 --log-facility=- --address=/#/198.18.0.42' >/dev/null

mock_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$mock_name")

docker run -d \
  --name "$dns_name" \
  --network "$network" \
  -v "$rule_overrides/proxy.txt:/usr/share/veladns/rules/proxy.txt:ro" \
  -v "$rule_overrides/data:/data" \
  -e "AUTO_FORWARD=$mock_ip:5353" \
  -e LOG_LEVEL=info \
  "$image" >/dev/null

dns_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dns_name")

docker run -d \
  --name "$client_name" \
  --network "$network" \
  -e "ALPINE_MIRROR=$alpine_mirror" \
  alpine:3.24 \
  sh -c 'if [ -n "$ALPINE_MIRROR" ]; then
      sed -i "s|https://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g" /etc/apk/repositories
    fi
    apk add --no-cache bind-tools >/dev/null && sleep 3600' >/dev/null

ready=0
i=0
while [ "$i" -lt 40 ]; do
  if docker exec "$client_name" dig +time=1 +tries=1 +short "@$dns_ip" doh.pub A \
      | grep -Eq '^[0-9]+\.'; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$ready" -eq 1 ] || fail "VelaDNS did not become ready"

# proxy.txt is deliberately empty in this container. This verifies the
# PaoPaoDNS-style final classifier rather than a domain-list fast path.
cn_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short "@$dns_ip" www.12306.cn A)
[ -n "$cn_answer" ] || fail "mainland domain returned no A record"
printf '%s\n' "$cn_answer" | grep -q '198\.18\.0\.42' \
  && fail "mainland domain was incorrectly sent to fake-IP"

global_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short "@$dns_ip" www.google.com A)
printf '%s\n' "$global_answer" | grep -qx '198.18.0.42' \
  || fail "global domain did not use validated Mihomo fake-IP"

# A name in proxy.txt goes straight to Mihomo. .test never resolves, so
# an answer here proves no encrypted real lookup gated the fake IP.
fakeip_first_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" fakeip-first.test A)
printf '%s\n' "$fakeip_first_answer" | grep -qx '198.18.0.42' \
  || fail "proxy domain did not reach Mihomo directly: $fakeip_first_answer"

# Rule files are watched in-process. A valid new proxy rule must take effect
# without restarting MosDNS, while malformed entries are removed from disk.
mosdns_pid_before_reload=$(docker exec "$dns_name" pidof mosdns)
docker exec "$dns_name" sh -c \
  'printf "full:fakeip-first.test\nfull:hot-reload.test\nfull:bad domain\n" > /data/proxy.txt'
hot_reload_answer=
i=0
while [ "$i" -lt 10 ]; do
  candidate=$(docker exec "$client_name" \
    dig +time=1 +tries=1 +short "@$dns_ip" hot-reload.test A || true)
  if printf '%s\n' "$candidate" | grep -qx '198.18.0.42'; then
    hot_reload_answer=$candidate
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$hot_reload_answer" = '198.18.0.42' ] \
  || fail "proxy rule was not hot-reloaded"
docker exec "$dns_name" sh -c \
  'grep -qx "full:hot-reload.test" /data/proxy.txt && ! grep -q "bad domain" /data/proxy.txt' \
  || fail "invalid proxy rule was not filtered"
mosdns_pid_after_reload=$(docker exec "$dns_name" pidof mosdns)
[ "$mosdns_pid_after_reload" = "$mosdns_pid_before_reload" ] \
  || fail "MosDNS restarted instead of hot-reloading rules"

for foreign_doh in dns.google cloudflare-dns.com; do
  proxy_answer=$(docker exec "$client_name" \
    dig +time=3 +tries=1 +short "@$dns_ip" "$foreign_doh" A)
  printf '%s\n' "$proxy_answer" | grep -qx '198.18.0.42' \
    || fail "foreign DoH domain did not use the proxy path: $foreign_doh"
done

direct_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short "@$dns_ip" doh.pub A)
[ -n "$direct_answer" ] || fail "direct domain returned no A record"
printf '%s\n' "$direct_answer" | grep -q '198\.18\.0\.42' \
  && fail "direct domain leaked into fake-IP mode"

secure_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short -p 5304 "@$dns_ip" www.google.com A)
[ -n "$secure_answer" ] || fail "secure listener returned no A record"
printf '%s\n' "$secure_answer" | grep -q '198\.18\.0\.42' \
  && fail "secure listener returned fake-IP"

dnssec_status=$(docker exec "$client_name" dig +time=4 +tries=1 "@$dns_ip" dnssec-failed.org A +noall +comments || true)
printf '%s\n' "$dnssec_status" | grep -q 'status: SERVFAIL' \
  || fail "DNSSEC failure was not preserved as SERVFAIL: $dnssec_status"
printf '%s\n' "$dnssec_status" | grep -q '198\.18\.0\.42' \
  && fail "DNSSEC failure was converted to fake-IP"

nxdomain_name="missing-$$.invalid"
nxdomain_status=$(docker exec "$client_name" dig +time=4 +tries=1 "@$dns_ip" "$nxdomain_name" A +noall +comments || true)
printf '%s\n' "$nxdomain_status" | grep -q 'status: NXDOMAIN' \
  || fail "NXDOMAIN was not preserved: $nxdomain_status"

nodata_status=$(docker exec "$client_name" dig +time=4 +tries=1 "@$dns_ip" _dmarc.example.com A +noall +comments +answer || true)
printf '%s\n' "$nodata_status" | grep -q 'status: NOERROR' \
  || fail "NODATA response did not remain NOERROR: $nodata_status"
printf '%s\n' "$nodata_status" | grep -q '198\.18\.0\.42' \
  && fail "NODATA response was converted to fake-IP"

aaaa_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short "@$dns_ip" cloudflare.com AAAA)
[ -z "$aaaa_answer" ] || fail "IPv6-disabled resolver returned an AAAA record"
secure_aaaa_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short -p 5304 "@$dns_ip" cloudflare.com AAAA)
[ -z "$secure_aaaa_answer" ] || fail "secure listener returned an AAAA record"

tcp_answer=$(docker exec "$client_name" dig +tcp +time=3 +tries=1 +short "@$dns_ip" doh.pub A)
[ -n "$tcp_answer" ] || fail "TCP listener returned no A record"

docker exec "$dns_name" /usr/local/bin/veladns-healthcheck \
  || fail "container health check failed"

metrics=$(docker exec "$dns_name" \
  wget -q -T 3 -O - http://127.0.0.1:5308/metrics)
printf '%s\n' "$metrics" | grep -q 'mosdns_metrics_collector_query_total{name="main"}' \
  || fail "main listener metrics were not exported"
printf '%s\n' "$metrics" | grep -q 'mosdns_metrics_collector_query_total{name="secure"}' \
  || fail "secure listener metrics were not exported"
printf '%s\n' "$metrics" | grep -q 'mosdns_veladns_component_up{component="unbound"} 1' \
  || fail "Unbound supervisor state was not exported"
printf '%s\n' "$metrics" | grep -q 'mosdns_veladns_component_up{component="doh_bridge"} 1' \
  || fail "encrypted bridge state was not exported"
printf '%s\n' "$metrics" | grep -q 'mosdns_veladns_circuit_state{name="auto_forward_circuit"}' \
  || fail "AUTO_FORWARD circuit state was not exported"
for decision in direct proxy classified_domestic classified_overseas; do
  printf '%s\n' "$metrics" \
    | grep -q "mosdns_veladns_decisions_total{decision=\"$decision\"}" \
    || fail "domain mapping decision $decision was not exported"
done

docker exec "$dns_name" sh -c \
  "grep -q 'forward-addr: 127.0.0.1@5307' /run/veladns/unbound.conf &&
   grep -q 'do-not-query-localhost: no' /run/veladns/unbound.conf &&
   ! grep -R -E 'addr: https://|dial_addr:|forward-addr: (223\\.5\\.5\\.5|119\\.29\\.29\\.29)' /run/veladns /etc/veladns"

# Stop the configured Mihomo DNS. Queries must seamlessly reuse their validated
# real responses; two consecutive failures open the exponential-backoff
# circuit.
docker stop "$mock_name" >/dev/null
cached_failover_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" www.google.com A)
[ -n "$cached_failover_answer" ] || fail "cached validation result was not reused"
printf '%s\n' "$cached_failover_answer" | grep -q '198\.18\.0\.42' \
  && fail "VelaDNS cached a fake-IP response after AUTO_FORWARD stopped"
# The proxy path has no pre-resolved answer to reuse, so it must fall
# back to encrypted real DNS on its own once Mihomo is gone.
fakeip_first_failover=$(docker exec "$client_name" \
  dig +time=5 +tries=1 +short "@$dns_ip" www.wikipedia.org A)
[ -n "$fakeip_first_failover" ] \
  || fail "proxy domain returned nothing after AUTO_FORWARD stopped"
printf '%s\n' "$fakeip_first_failover" | grep -q '198\.18\.0\.42' \
  && fail "proxy domain returned a stale fake-IP after AUTO_FORWARD stopped"

failover_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" www.youtube.com A)
[ -n "$failover_answer" ] || fail "AUTO_FORWARD failure returned no real answer"
printf '%s\n' "$failover_answer" | grep -q '198\.18\.0\.42' \
  && fail "AUTO_FORWARD failure returned fake-IP"
second_failover_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" github.com A)
[ -n "$second_failover_answer" ] || fail "second AUTO_FORWARD failure returned no real answer"
printf '%s\n' "$second_failover_answer" | grep -q '198\.18\.0\.42' \
  && fail "second AUTO_FORWARD failure returned fake-IP"
# How many consecutive failures should open the circuit is a tuning decision.
# The property under test is that a sustained outage eventually opens it rather
# than retrying every query forever, so drive failures until it trips.
circuit_opened=0
i=0
while [ "$i" -lt 12 ]; do
  docker exec "$client_name" \
    dig +time=4 +tries=1 +short "@$dns_ip" fakeip-first.test A >/dev/null 2>&1 || true
  if docker logs "$dns_name" 2>&1 | grep -q 'AUTO_FORWARD circuit opened'; then
    circuit_opened=1
    break
  fi
  i=$((i + 1))
done
[ "$circuit_opened" -eq 1 ] \
  || fail "AUTO_FORWARD circuit did not enter exponential backoff"

# After the backoff expires, one half-open probe should restore forwarding.
docker start "$mock_name" >/dev/null
sleep 2
recovered_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" www.twitter.com A)
printf '%s\n' "$recovered_answer" | grep -qx '198.18.0.42' \
  || fail "AUTO_FORWARD did not recover after the backoff probe"
docker logs "$dns_name" 2>&1 \
  | grep -q 'AUTO_FORWARD circuit recovered' \
  || fail "AUTO_FORWARD circuit did not report recovery"

# The Go entrypoint must recover each DNS child independently without exiting.
old_unbound_pid=$(docker exec "$dns_name" pidof unbound)
docker exec "$dns_name" kill -9 "$old_unbound_pid"
new_unbound_pid=
i=0
while [ "$i" -lt 20 ]; do
  candidate=$(docker exec "$dns_name" pidof unbound 2>/dev/null || true)
  if [ -n "$candidate" ] && [ "$candidate" != "$old_unbound_pid" ]; then
    new_unbound_pid=$candidate
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ -n "$new_unbound_pid" ] || fail "Unbound was not restarted"
docker inspect -f '{{.State.Running}}' "$dns_name" | grep -qx true \
  || fail "container exited when Unbound crashed"

old_mosdns_pid=$(docker exec "$dns_name" pidof mosdns)
docker exec "$dns_name" kill -9 "$old_mosdns_pid"
new_mosdns_pid=
i=0
while [ "$i" -lt 20 ]; do
  candidate=$(docker exec "$dns_name" pidof mosdns 2>/dev/null || true)
  if [ -n "$candidate" ] && [ "$candidate" != "$old_mosdns_pid" ]; then
    new_mosdns_pid=$candidate
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ -n "$new_mosdns_pid" ] || fail "MosDNS was not restarted"

healthy=0
i=0
while [ "$i" -lt 15 ]; do
  if docker exec "$dns_name" /usr/local/bin/veladns-healthcheck; then
    healthy=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$healthy" -eq 1 ] || fail "health endpoint did not recover after MosDNS restart"

metrics=$(docker exec "$dns_name" wget -q -T 3 -O - http://127.0.0.1:5308/metrics)
printf '%s\n' "$metrics" \
  | grep -Eq 'mosdns_veladns_component_restarts_total\{component="unbound"\} [1-9][0-9]*' \
  || fail "Unbound restart count was not exported"
printf '%s\n' "$metrics" \
  | grep -Eq 'mosdns_veladns_component_restarts_total\{component="mosdns"\} [1-9][0-9]*' \
  || fail "MosDNS restart count was not exported"

post_restart_answer=$(docker exec "$client_name" \
  dig +time=3 +tries=1 +short "@$dns_ip" www.google.com A)
[ -n "$post_restart_answer" ] || fail "DNS stopped serving after child recovery"

if docker run --rm -e 'AUTO_FORWARD=bad:notaport' "$image" >/dev/null 2>&1; then
  fail "AUTO_FORWARD with a non-numeric port was accepted"
fi

if docker run --rm -e 'AUTO_FORWARD=bad:65536' "$image" >/dev/null 2>&1; then
  fail "AUTO_FORWARD with an out-of-range port was accepted"
fi

if docker run --rm -e 'AUTO_FORWARD=:53' "$image" >/dev/null 2>&1; then
  fail "AUTO_FORWARD with an empty host was accepted"
fi

if docker run --rm -e 'LOG_LEVEL=verbose' "$image" >/dev/null 2>&1; then
  fail "invalid LOG_LEVEL was accepted"
fi

# Recreate the resolver without a Mihomo upstream and verify that the default
# secure real-IP mode starts and never returns the mock fake address.
docker rm -f "$dns_name" >/dev/null
docker run -d \
  --name "$dns_name" \
  --network "$network" \
  "$image" >/dev/null
dns_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dns_name")

ready=0
i=0
while [ "$i" -lt 40 ]; do
  if docker exec "$client_name" dig +time=1 +tries=1 +short "@$dns_ip" doh.pub A \
      | grep -Eq '^[0-9]+\.'; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$ready" -eq 1 ] || fail "secure real-IP mode did not become ready"

secure_mode_answer=$(docker exec "$client_name" dig +time=3 +tries=1 +short "@$dns_ip" www.google.com A)
[ -n "$secure_mode_answer" ] || fail "secure real-IP mode returned no A record"
printf '%s\n' "$secure_mode_answer" | grep -q '198\.18\.0\.42' \
  && fail "secure real-IP mode returned fake-IP"

printf '%s\n' "ALL TESTS PASSED"

# VelaDNS

English | [简体中文](README.zh-CN.md)

VelaDNS is a fail-closed split DNS container for RouterOS, Mihomo, and
ordinary Docker hosts. It combines:

- MosDNS 5.3.4 for request routing, caches, metrics, and DNS listeners.
- Two Unbound 1.25.2 instances: a local recursive CN classifier and a
  DNSSEC-validating encrypted resolver.
- An in-process DoH bridge with provider fallback and backoff.
- Optional Mihomo DNS integration for fake-IP.
- Independent child-process supervision and functional health checks.

IPv6 answers are disabled. Runtime policy is controlled by two environment
variables and two persistent domain lists. There is no Redis, and bundled rule
sources are not downloaded or refreshed at runtime.

## Request flow

```text
Client -> :53
  -> rule fast path
  -> otherwise :5305 recursive classification
       -> CN address: return it
       -> non-CN: discard it -> :5306 validation -> :5307 DoH
                                      -> optional Mihomo fake-IP

Mihomo real-DNS lookup -> :5304 -> :5306 -> :5307 -> DoH/443
```

Requests are evaluated in this order:

1. Reject AAAA and private names.
2. Apply the direct mapping.
3. Apply the proxy mapping.
4. Classify unknown names from their recursive A response using `cncidr.txt`.

| Decision | Result |
| --- | --- |
| Direct | Encrypted, DNSSEC-validated real address |
| Proxy | Mihomo fake-IP when enabled; encrypted real address on failure or in secure-only mode |
| Unknown name | Recursive CN answer, or a discarded and re-resolved encrypted non-CN answer |
| AAAA | Empty successful response |
| Private name | `NXDOMAIN` |

Fake-IP is never cached by VelaDNS. DNSSEC failures remain `SERVFAIL`;
`NXDOMAIN` and NODATA are not converted to fake-IP.

## Quick start

Secure real-IP mode:

```sh
docker run -d \
  --name veladns \
  --restart unless-stopped \
  -v ./data:/data \
  -p 53:53/udp -p 53:53/tcp \
  -p 5304:5304/udp -p 5304:5304/tcp \
  -p 127.0.0.1:5308:5308/tcp \
  ghcr.io/hyird/veladns:latest
```

Mihomo fake-IP mode:

```sh
docker run -d \
  --name veladns \
  --restart unless-stopped \
  -v ./data:/data \
  -e AUTO_FORWARD=172.16.0.101 \
  -p 53:53/udp -p 53:53/tcp \
  -p 5304:5304/udp -p 5304:5304/tcp \
  -p 127.0.0.1:5308:5308/tcp \
  ghcr.io/hyird/veladns:latest
```

Port `53` is the client-facing split DNS listener. Port `5304` always returns
an encrypted real address and is safe to use as Mihomo's real-DNS upstream.
Port `5308` should be restricted to trusted monitoring hosts.

The repository also provides [docker-compose.yml](docker-compose.yml) and a
reviewable [RouterOS template](routeros/install.rsc).

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LOG_LEVEL` | `warn` | `debug`, `info`, `warn`, or `error` |
| `AUTO_FORWARD` | `no` | `no` or Mihomo DNS `host[:port]`; the port defaults to `53` |

`AUTO_FORWARD` accepts a hostname or IPv4 endpoint; IPv6 literals are not
supported. VelaDNS uses TCP for this DNS hop.

When Mihomo is enabled:

- `proxy.txt`-mapped A queries go directly to Mihomo;
- `direct.txt`-mapped queries always use the encrypted, DNSSEC-validating real resolver;
- unknown names reach Mihomo only after their real response proves non-CN;
- a validated unknown-name response is reused for fallback with a five-second
  TTL;
- a `proxy.txt`-mapped name without a saved real response falls back to a new
  encrypted lookup;
- five consecutive failures open the circuit; each query has two 800 ms
  attempts, and jittered retry delay is capped at 30 seconds;
- a half-open probe restores forwarding automatically.

The encrypted path is `Unbound -> 127.0.0.1:5307 -> DoH/443`. Unbound performs
DNSSEC validation locally. With Mihomo enabled, the DoH bridge prefers NextDNS
and Quad9 through Mihomo, then falls back to direct Cloudflare and 360. Provider
hostname bootstrap uses TCP to Mihomo. A DoH provider enters backoff after two
consecutive failures, with a maximum delay of five minutes.

Logs go only to standard output/error. Expected downstream TCP disconnects are
counted separately and do not produce warning noise or increment DNS
`err_total`. At `warn`, Unbound emits only errors, recoverable DoH startup
probes remain available through provider metrics, and internal deadline
warnings are suppressed only after the same query was reported at the request
boundary.
Component exits, circuit changes, exhausted DNS providers, and client-visible
request failures remain actionable warnings.

## Ports

The non-standard ports are consecutive and ordered by request hierarchy:

| Port | Binding | Role |
| --- | --- | --- |
| `53` | `0.0.0.0`, UDP/TCP | Client-facing split DNS |
| `5304` | `0.0.0.0`, UDP/TCP | Encrypted real-IP listener for Mihomo |
| `5305` | `127.0.0.1` | Recursive CN classifier |
| `5306` | `127.0.0.1` | DNSSEC-validating Unbound |
| `5307` | `127.0.0.1` | In-process DoH bridge |
| `5308` | `0.0.0.0`, HTTP | Health, metrics, and profiling |

The image declares ports `53`, `5304`, and `5308`. Ports `5305`-`5307` remain
inside the container. The examples bind `5308` to host loopback.

## Health

The Go entrypoint supervises MosDNS and both Unbound processes independently.
A failed child restarts with a jittered delay capped at 30 seconds.

| Endpoint | Meaning |
| --- | --- |
| `/plugins/veladns/livez` | Supervisor state is fresh and MosDNS is running |
| `/plugins/veladns/readyz` | Adds the DoH bridge and resolver dependency state |
| `/plugins/veladns/healthz` | Compatibility alias for `readyz` |
| `/plugins/veladns/dependencies` | JSON snapshot of components and DoH providers |

A failed validating or recursive Unbound reports `degraded`; a stale supervisor,
stopped MosDNS, or unavailable DoH bridge reports unhealthy. The container
health check calls `readyz` and then performs a real A query through
`127.0.0.1:5304`, so HTTP state alone is not considered sufficient.

## Metrics

Prometheus metrics are available at:

```text
http://127.0.0.1:5308/metrics
```

Key metric families:

| Family | Purpose |
| --- | --- |
| `mosdns_metrics_collector_*` | Main/secure query totals, real errors, client cancellations, concurrency, and latency |
| `mosdns_veladns_decisions_total` | Ordered routing and classification decisions |
| `mosdns_veladns_doh_upstream_*` | Per-provider requests, successes, failures, duration, backoff, and timestamps |
| `mosdns_veladns_component_*` | Supervised process state, restarts, and restart backoff |
| `mosdns_veladns_circuit_*` | Mihomo circuit state, failures, bypasses, and retry delay |
| `mosdns_veladns_client_cancel_events_total` | Expected TCP entry/write cancellations suppressed from warning logs |

MosDNS also exports Go/process, cache, and tagged forward-upstream metrics.
Profiling handlers are available under `/debug/pprof` on the same listener.
Never expose port `5308` to an untrusted network.

## Custom rules

VelaDNS exposes two domain mappings:

| Mapping | User-maintained file | Built-in base | Result |
| --- | --- | --- | --- |
| Direct | `direct.txt` | None | Encrypted, DNSSEC-validated real address, bypassing fake-IP |
| Proxy | `proxy.txt` | Pinned proxy rules | Mihomo fake-IP with encrypted real fallback |

These two `/data` files contain domain rules only; IP addresses and CIDRs do
not belong in them. `real-ip.txt`, `overseas.txt`, and `domestic.txt` are not
migrated automatically; merge any rules you need into `direct.txt` or
`proxy.txt` before upgrading.

The bundled proxy rules and `cncidr.txt` are version-pinned internal data, not
operator-maintained lists. `cncidr.txt` is an IP range database used only to
classify unknown responses.

Rules use MosDNS domain syntax:

```text
domain:example.com
full:www.example.com
keyword:example
regexp:^api[0-9]+\.example\.com$
```

MosDNS continuously watches `direct.txt` and `proxy.txt`. Saved changes are
hot-reloaded after a roughly 200 ms debounce without restarting the container
or DNS listeners. An empty file clears its rules; comments, blank lines, and
invalid rules are removed. If an edit contains only invalid rules, the file is
restored to its previous valid content so active policy is not lost. The
writable DNSSEC trust anchor is stored under `/run/veladns/unbound`, not in
`/data`.

## RouterOS and Mihomo

The supplied RouterOS template assumes:

- VelaDNS: `172.16.0.100`
- Mihomo: `172.16.0.101`
- container bridge: `172.16.0.0/16`

Review interface names, paths, addresses, and firewall placement before
importing [routeros/install.rsc](routeros/install.rsc).

Mihomo should use VelaDNS port `5304` for real-address queries:

```yaml
dns:
  enable: true
  listen: :53
  enhanced-mode: fake-ip
  nameserver:
    - 172.16.0.100:5304
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - 114.114.114.114
```

Keep `proxy-server-nameserver` independent from VelaDNS so Mihomo can resolve
proxy node hostnames during bootstrap. Add subscription and control-plane names
to both `direct.txt` and Mihomo's `fake-ip-filter`.

## Validation and publishing

Run the integration suite with:

```sh
go test ./...
go vet ./...
docker build -t veladns:test .
sh tests/integration.sh veladns:test
```

The suite covers secure-only and Mihomo modes, UDP/TCP listeners, CN/non-CN
classification, direct fake-IP fast paths, DNSSEC/NXDOMAIN/NODATA behavior,
health, metrics, failover, circuit recovery, child restart, and environment
validation.

GitHub Actions tests `linux/amd64`, smoke-tests `linux/arm64` and
`linux/arm/v7`, and publishes a multi-architecture GHCR image with SBOM and
provenance after successful non-PR runs. Rule archives and the Go module graph
are checksum/version pinned. Release binaries are stripped and compressed with
UPX `--best --lzma`; the prepared Alpine filesystem is copied into a scratch
stage so each platform manifest contains exactly one filesystem layer. CI
checks that layer count and executes the compressed binaries on every published
architecture.

The CI jobs keep independent BuildKit caches for AMD64, ARM64, and ARMv7.
The publish job consumes all three tested caches instead of recompiling each
platform, while Go tests and vet run once before the integration image build.

Third-party components and data licenses are listed in
[THIRD_PARTY.md](THIRD_PARTY.md).

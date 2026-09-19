# syntax=docker/dockerfile:1.7

ARG ALPINE_VERSION=3.24
ARG ALPINE_MIRROR=

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS go-builder

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VELADNS_VERSION=v5.3.4-veladns

WORKDIR /src
RUN apk add --no-cache upx
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY config/ config/
COPY internal/ internal/

RUN set -eux; \
    target_goarm=""; \
    if [ "$TARGETARCH" = arm ]; then target_goarm="${TARGETVARIANT#v}"; fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="$target_goarm" \
      go build -trimpath -ldflags="-s -w -X main.version=${VELADNS_VERSION}" \
      -o /out/mosdns ./cmd/mosdns; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="$target_goarm" \
      go build -trimpath -ldflags="-s -w -X main.version=${VELADNS_VERSION}" \
      -o /out/veladns ./cmd/veladns
RUN upx --best --lzma /out/mosdns /out/veladns \
    && upx -t /out/mosdns /out/veladns

FROM alpine:${ALPINE_VERSION} AS rules-downloader

ARG ALPINE_MIRROR
ARG RULES_VERSION=202607232250
ARG RULES_SHA256=831c3105a7cf3fc7b03f155769a4a9d1627f05ebbda00ba0da15883540a16379
ARG CLASH_RULES_COMMIT=887d83dd2e6e261c8ee660842639839e52b3ccaa
ARG CNCIDR_SHA256=2971f17f525852241aa4d9e104c8cb414e23e2ac81ec01a7118e12ed5048cd13

RUN if [ -n "$ALPINE_MIRROR" ]; then \
      sed -i "s|https://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache ca-certificates curl unzip

COPY .test-assets/ /vendor/

RUN set -eux; \
    mkdir -p /out /tmp/rules; \
    if [ -s /vendor/rules.zip ]; then \
      cp /vendor/rules.zip /tmp/rules.zip; \
    else \
      curl -fsSL --retry 5 \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${RULES_VERSION}/rules.zip" \
        -o /tmp/rules.zip; \
    fi; \
    echo "${RULES_SHA256}  /tmp/rules.zip" | sha256sum -c -; \
    unzip -j /tmp/rules.zip proxy-list.txt -d /tmp/rules; \
    cp /tmp/rules/proxy-list.txt /out/proxy.txt; \
    printf '%s\n' \
      'full:dns.google' \
      'full:cloudflare-dns.com' >> /out/proxy.txt; \
    if [ -s /vendor/cncidr.txt ]; then \
      cp /vendor/cncidr.txt /tmp/cncidr.yaml; \
    else \
      curl -fsSL --retry 5 \
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/${CLASH_RULES_COMMIT}/cncidr.txt" \
        -o /tmp/cncidr.yaml; \
    fi; \
    echo "${CNCIDR_SHA256}  /tmp/cncidr.yaml" | sha256sum -c -; \
    sed \
      -e '/^payload:/d' \
      -e 's/^[[:space:]]*-[[:space:]]*//' \
      -e "s/^'//" \
      -e "s/'[[:space:]]*$//" \
      -e 's/\r$//' \
      /tmp/cncidr.yaml > /out/cncidr.txt; \
    test -s /out/proxy.txt; \
    test -s /out/cncidr.txt

FROM scratch AS runtime-assets

COPY --from=go-builder --chmod=0755 /out/mosdns /usr/local/bin/mosdns
COPY --from=go-builder --chmod=0755 /out/veladns /usr/local/bin/veladns
COPY --from=rules-downloader /out/ /usr/share/veladns/rules/
COPY config/ /etc/veladns/
COPY --chmod=0755 scripts/healthcheck.sh /usr/local/bin/veladns-healthcheck

FROM alpine:${ALPINE_VERSION} AS runtime-root

ARG UNBOUND_VERSION=1.25.2
ARG ALPINE_MIRROR

RUN if [ -n "$ALPINE_MIRROR" ]; then \
      sed -i "s|https://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache \
      ca-certificates \
      tini \
      tzdata \
      "unbound=1.25.2-r2" \
    && ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && printf '%s\n' 'Asia/Shanghai' > /etc/timezone \
    && mkdir -p /etc/veladns /usr/share/veladns/rules /run/veladns/unbound /data

COPY --from=runtime-assets / /

RUN unbound -V | grep -F "Version ${UNBOUND_VERSION}" \
    && cp /usr/share/dnssec-root/trusted-key.key /run/veladns/unbound/root.key \
    && chown -R unbound:unbound /run/veladns/unbound \
    && mkdir -p /run/veladns/unbound-recursive \
    && chown -R unbound:unbound /run/veladns/unbound-recursive \
    && sed 's/__UNBOUND_VERBOSITY__/1/' /etc/veladns/unbound.conf.tmpl > /tmp/unbound.conf \
    && unbound-checkconf /tmp/unbound.conf >/dev/null \
    && sed 's/__UNBOUND_VERBOSITY__/1/' /etc/veladns/unbound-recursive.conf.tmpl \
         > /tmp/unbound-recursive.conf \
    && unbound-checkconf /tmp/unbound-recursive.conf >/dev/null \
    && rm -f /tmp/unbound.conf /tmp/unbound-recursive.conf /run/veladns/unbound/root.key

FROM scratch

ARG MOSDNS_VERSION=5.3.4

LABEL org.opencontainers.image.title="VelaDNS" \
      org.opencontainers.image.description="Fail-closed anti-pollution split DNS for RouterOS and Mihomo" \
      org.opencontainers.image.source="https://github.com/hyird/VelaDNS" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${MOSDNS_VERSION}" \
      io.veladns.image.filesystem-layers="1" \
      io.veladns.image.upx="--best --lzma"

# Squash the prepared Alpine root into one final filesystem layer. Build-only
# package, validation, and asset layers stay out of the published manifest.
COPY --from=runtime-root / /

ENV AUTO_FORWARD=no \
    LOG_LEVEL=warn

VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 5304/udp 5304/tcp 5308/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/veladns-healthcheck"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/veladns"]

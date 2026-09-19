# Third-party components

[简体中文](THIRD_PARTY.zh-CN.md)

The VelaDNS image contains third-party programs, libraries, and data:

- [MosDNS](https://github.com/IrineSistiana/mosdns) v5.3.4, GPL-3.0. VelaDNS
  builds a custom entry binary that registers VelaDNS supervision,
  circuit-breaker, decision-metrics, request-metrics, and TCP-server plugins.
- [Unbound](https://github.com/NLnetLabs/unbound), BSD-3-Clause.
- [Loyalsoldier v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat),
  GPL-3.0.
- [Loyalsoldier clash-rules](https://github.com/Loyalsoldier/clash-rules),
  GPL-3.0.
- [UPX](https://github.com/upx/upx) compresses the Go executables during the
  image build. The standalone UPX program is not included in the runtime image.
- Alpine Linux packages, under their respective licenses.

The MosDNS source version and complete Go dependency graph are pinned by
`go.mod`/`go.sum`. Domain rules are verified against the upstream release
checksum; the CN CIDR snapshot is pinned by commit and verified against its
recorded checksum.
